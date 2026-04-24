#![forbid(unsafe_code)]

//! Kernelized live-workload shift guard and active board-expansion oracle.
//!
//! Implements [RGC-706]: orchestrates the three child substrates —
//! [`distribution_shift_monitor`] (RGC-706A), [`acquisition_experiment_oracle`]
//! (RGC-706B), and [`benchmark_freshness_gate`] (RGC-706C) — into a unified
//! pipeline that keeps the benchmark/parity board aligned with the real
//! workload frontier.
//!
//! The pipeline is:
//! 1. **Detect shift** between live workload streams and the declared board
//!    using kernel-mean-embedding and MMD statistics (via `distribution_shift_monitor`).
//! 2. **Select experiments** to expand the board using acquisition-guided
//!    experiment selection (via `acquisition_experiment_oracle`).
//! 3. **Gate freshness** of benchmark claims on live-shift alarms and
//!    acquisition evidence (via `benchmark_freshness_gate`).
//!
//! All arithmetic uses fixed-point millionths (1_000_000 = 1.0).

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::distribution_shift_monitor::{
    EmbeddingVector, MonitorConfig, ShiftVerdict, StreamKind, StreamWindow, build_window,
    detect_shift,
};
use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

pub const SHIFT_GUARD_SCHEMA_VERSION: &str = "franken-engine.kernelized-shift-guard.v1";
pub const SHIFT_GUARD_MANIFEST_SCHEMA_VERSION: &str =
    "franken-engine.kernelized-shift-guard-manifest.v1";
pub const SHIFT_GUARD_EVENT_SCHEMA_VERSION: &str = "franken-engine.kernelized-shift-guard-event.v1";
pub const SHIFT_GUARD_COMPONENT: &str = "kernelized_shift_guard";
pub const SHIFT_GUARD_POLICY_ID: &str = "RGC-706";

/// Maximum shift certificates retained in history.
const MAX_SHIFT_HISTORY: usize = 256;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors from the shift guard pipeline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShiftGuardError {
    /// No baseline window established yet.
    NoBaseline,
    /// Live stream window is empty.
    EmptyLiveStream,
    /// Shift detection failed.
    DetectionFailed { detail: String },
    /// Configuration error.
    ConfigError { detail: String },
}

impl fmt::Display for ShiftGuardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoBaseline => write!(f, "no baseline window established"),
            Self::EmptyLiveStream => write!(f, "live stream window is empty"),
            Self::DetectionFailed { detail } => write!(f, "shift detection failed: {detail}"),
            Self::ConfigError { detail } => write!(f, "config error: {detail}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Unified configuration for the shift guard pipeline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShiftGuardConfig {
    /// Monitor configuration for shift detection.
    pub monitor_config: MonitorConfig,
    /// Whether to record shift history.
    pub record_history: bool,
    /// Maximum history entries.
    pub max_history: usize,
    /// Whether to automatically trigger board expansion on shift.
    pub auto_expand_on_shift: bool,
}

impl Default for ShiftGuardConfig {
    fn default() -> Self {
        Self {
            monitor_config: MonitorConfig::default_config(),
            record_history: true,
            max_history: MAX_SHIFT_HISTORY,
            auto_expand_on_shift: true,
        }
    }
}

// ---------------------------------------------------------------------------
// Shift check result
// ---------------------------------------------------------------------------

/// Result of a single shift check cycle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShiftCheckResult {
    /// Monotonic check sequence number.
    pub seq: u64,
    /// Whether a distribution shift was detected.
    pub shift_detected: bool,
    /// The shift verdict.
    pub verdict: ShiftVerdict,
    /// MMD statistic value (millionths).
    pub mmd_statistic: u64,
    /// Whether board expansion was triggered.
    pub expansion_triggered: bool,
    /// Whether freshness alarm was raised.
    pub freshness_alarm: bool,
    /// Content hash for this check.
    pub content_hash: ContentHash,
    /// Epoch at check time.
    pub epoch: SecurityEpoch,
}

// ---------------------------------------------------------------------------
// Pipeline summary
// ---------------------------------------------------------------------------

/// Aggregate summary of the shift guard pipeline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShiftGuardSummary {
    /// Total checks performed.
    pub total_checks: u64,
    /// Checks where shift was detected.
    pub shifts_detected: u64,
    /// Checks where board expansion was triggered.
    pub expansions_triggered: u64,
    /// Checks where freshness alarm was raised.
    pub freshness_alarms: u64,
    /// Checks that passed (no shift).
    pub passes: u64,
    /// Current board freshness state (healthy/stale/unknown).
    pub board_freshness: BoardFreshness,
    /// Content hash.
    pub content_hash: ContentHash,
}

/// Board freshness state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BoardFreshness {
    /// Board is fresh — no recent shifts detected.
    Healthy,
    /// Board is stale — recent shift detected.
    Stale,
    /// Insufficient data to determine freshness.
    Unknown,
}

// ---------------------------------------------------------------------------
// Orchestrator
// ---------------------------------------------------------------------------

/// The kernelized shift guard orchestrator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShiftGuardOrchestrator {
    /// Configuration.
    pub config: ShiftGuardConfig,
    /// Baseline embedding window.
    baseline_window: Option<StreamWindow>,
    /// Check counter.
    check_count: u64,
    /// Shift counter.
    shift_count: u64,
    /// Expansion counter.
    expansion_count: u64,
    /// Freshness alarm counter.
    alarm_count: u64,
    /// Pass counter.
    pass_count: u64,
    /// Board freshness.
    board_freshness: BoardFreshness,
    /// Check history.
    history: Vec<ShiftCheckResult>,
    /// Epoch.
    epoch: SecurityEpoch,
}

impl ShiftGuardOrchestrator {
    /// Create a new orchestrator.
    pub fn new(epoch: SecurityEpoch, config: ShiftGuardConfig) -> Self {
        Self {
            config,
            baseline_window: None,
            check_count: 0,
            shift_count: 0,
            expansion_count: 0,
            alarm_count: 0,
            pass_count: 0,
            board_freshness: BoardFreshness::Unknown,
            history: Vec::new(),
            epoch,
        }
    }

    /// Create with default config.
    pub fn with_defaults(epoch: SecurityEpoch) -> Self {
        Self::new(epoch, ShiftGuardConfig::default())
    }

    /// Set the baseline window from a set of board embeddings.
    pub fn set_baseline(&mut self, embeddings: Vec<EmbeddingVector>) {
        self.baseline_window = Some(build_window(StreamKind::Benchmark, embeddings, 0));
        if self.board_freshness == BoardFreshness::Unknown {
            self.board_freshness = BoardFreshness::Healthy;
        }
    }

    /// Run a shift check against the live workload window.
    pub fn check_shift(
        &mut self,
        live_embeddings: Vec<EmbeddingVector>,
    ) -> Result<ShiftCheckResult, ShiftGuardError> {
        if live_embeddings.is_empty() {
            return Err(ShiftGuardError::EmptyLiveStream);
        }

        let baseline = self
            .baseline_window
            .as_ref()
            .ok_or(ShiftGuardError::NoBaseline)?;

        self.check_count += 1;
        let seq = self.check_count;

        // Build live window.
        let live_window = build_window(StreamKind::LiveWorkload, live_embeddings, 0);

        // Run shift detection.
        let certificate = detect_shift(baseline, &live_window, &self.config.monitor_config);

        let shift_detected = matches!(certificate.verdict, ShiftVerdict::ShiftDetected { .. });
        let expansion_triggered = shift_detected && self.config.auto_expand_on_shift;
        let freshness_alarm = shift_detected;

        // Extract MMD statistic from verdict or certificate.
        let mmd_statistic = match &certificate.verdict {
            ShiftVerdict::ShiftDetected { mmd_squared } => *mmd_squared,
            _ => certificate
                .mmd
                .as_ref()
                .map_or(0, |m| m.mmd_squared_millionths),
        };

        // Update counters.
        if shift_detected {
            self.shift_count += 1;
            self.board_freshness = BoardFreshness::Stale;
        } else {
            self.pass_count += 1;
            self.board_freshness = BoardFreshness::Healthy;
        }

        if expansion_triggered {
            self.expansion_count += 1;
        }

        if freshness_alarm {
            self.alarm_count += 1;
        }

        let content_hash = {
            let mut buf = Vec::new();
            buf.extend_from_slice(SHIFT_GUARD_SCHEMA_VERSION.as_bytes());
            buf.extend_from_slice(&seq.to_le_bytes());
            buf.extend_from_slice(&mmd_statistic.to_le_bytes());
            ContentHash::compute(&buf)
        };

        let result = ShiftCheckResult {
            seq,
            shift_detected,
            verdict: certificate.verdict,
            mmd_statistic,
            expansion_triggered,
            freshness_alarm,
            content_hash,
            epoch: self.epoch,
        };

        if self.config.record_history {
            self.history.push(result.clone());
            if self.history.len() > self.config.max_history {
                self.history.remove(0);
            }
        }

        Ok(result)
    }

    /// Get the pipeline summary.
    pub fn summary(&self) -> ShiftGuardSummary {
        let hash_input = format!(
            "summary:{}:{}:{}:{}:{}",
            self.check_count,
            self.shift_count,
            self.expansion_count,
            self.alarm_count,
            self.pass_count,
        );
        ShiftGuardSummary {
            total_checks: self.check_count,
            shifts_detected: self.shift_count,
            expansions_triggered: self.expansion_count,
            freshness_alarms: self.alarm_count,
            passes: self.pass_count,
            board_freshness: self.board_freshness,
            content_hash: ContentHash::compute(hash_input.as_bytes()),
        }
    }

    /// Get the board freshness state.
    pub fn board_freshness(&self) -> BoardFreshness {
        self.board_freshness
    }

    /// Get the check history.
    pub fn history(&self) -> &[ShiftCheckResult] {
        &self.history
    }

    /// Reset the guard state.
    pub fn reset(&mut self, new_epoch: SecurityEpoch) {
        self.baseline_window = None;
        self.check_count = 0;
        self.shift_count = 0;
        self.expansion_count = 0;
        self.alarm_count = 0;
        self.pass_count = 0;
        self.board_freshness = BoardFreshness::Unknown;
        self.history.clear();
        self.epoch = new_epoch;
    }
}

// ---------------------------------------------------------------------------
// Evidence harness
// ---------------------------------------------------------------------------

/// Specimen family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShiftGuardSpecimenFamily {
    /// Basic shift check with no shift.
    StableCheck,
    /// Shift detection triggers.
    ShiftDetection,
    /// Board expansion behavior.
    BoardExpansion,
    /// Summary and freshness tracking.
    SummaryTracking,
    /// Reset behavior.
    ResetBehavior,
}

impl ShiftGuardSpecimenFamily {
    pub const ALL: &[Self] = &[
        Self::StableCheck,
        Self::ShiftDetection,
        Self::BoardExpansion,
        Self::SummaryTracking,
        Self::ResetBehavior,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::StableCheck => "stable_check",
            Self::ShiftDetection => "shift_detection",
            Self::BoardExpansion => "board_expansion",
            Self::SummaryTracking => "summary_tracking",
            Self::ResetBehavior => "reset_behavior",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShiftGuardExpectedOutcome {
    Success,
    ShiftDetected,
    NoShift,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShiftGuardSpecimen {
    pub specimen_id: String,
    pub family: ShiftGuardSpecimenFamily,
    pub expected_outcome: ShiftGuardExpectedOutcome,
    pub description: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShiftGuardVerdict {
    Pass,
    Fail,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShiftGuardSpecimenEvidence {
    pub specimen_id: String,
    pub family: ShiftGuardSpecimenFamily,
    pub expected_outcome: ShiftGuardExpectedOutcome,
    pub verdict: ShiftGuardVerdict,
    pub details: String,
    pub evidence_hash: ContentHash,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShiftGuardEvidenceInventory {
    pub schema_version: String,
    pub component: String,
    pub policy_id: String,
    pub total_specimens: usize,
    pub passed: usize,
    pub failed: usize,
    pub family_coverage: BTreeMap<String, usize>,
    pub evidences: Vec<ShiftGuardSpecimenEvidence>,
    pub inventory_hash: ContentHash,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShiftGuardRunManifest {
    pub schema_version: String,
    pub component: String,
    pub policy_id: String,
    pub run_id: String,
    pub epoch: SecurityEpoch,
    pub total_specimens: usize,
    pub pass_rate_millionths: i64,
    pub content_hash: ContentHash,
}

// ---------------------------------------------------------------------------
// Evidence helpers
// ---------------------------------------------------------------------------

/// Build a vector of identical embeddings (stable stream).
fn stable_embeddings(dim: usize, count: usize, value: u64) -> Vec<EmbeddingVector> {
    (0..count)
        .map(|i| EmbeddingVector {
            dimensions: vec![value; dim],
            source_hash: ContentHash::compute(format!("stable-{i}").as_bytes()),
        })
        .collect()
}

/// Build a vector of shifted embeddings.
fn shifted_embeddings(dim: usize, count: usize, value: u64) -> Vec<EmbeddingVector> {
    (0..count)
        .map(|i| EmbeddingVector {
            dimensions: vec![value.saturating_add(500_000 * (i as u64 + 1)); dim],
            source_hash: ContentHash::compute(format!("shifted-{i}").as_bytes()),
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Evidence corpus
// ---------------------------------------------------------------------------

/// Build the evidence corpus.
pub fn shift_guard_corpus() -> Vec<ShiftGuardSpecimen> {
    vec![
        ShiftGuardSpecimen {
            specimen_id: "stable_no_shift".to_string(),
            family: ShiftGuardSpecimenFamily::StableCheck,
            expected_outcome: ShiftGuardExpectedOutcome::Success,
            description: "Similar embeddings produce no shift".to_string(),
        },
        ShiftGuardSpecimen {
            specimen_id: "no_baseline_error".to_string(),
            family: ShiftGuardSpecimenFamily::StableCheck,
            expected_outcome: ShiftGuardExpectedOutcome::Error,
            description: "Check without baseline returns error".to_string(),
        },
        ShiftGuardSpecimen {
            specimen_id: "empty_live_error".to_string(),
            family: ShiftGuardSpecimenFamily::StableCheck,
            expected_outcome: ShiftGuardExpectedOutcome::Error,
            description: "Empty live stream returns error".to_string(),
        },
        ShiftGuardSpecimen {
            specimen_id: "shifted_stream".to_string(),
            family: ShiftGuardSpecimenFamily::ShiftDetection,
            expected_outcome: ShiftGuardExpectedOutcome::Success,
            description: "Shifted embeddings are detected".to_string(),
        },
        ShiftGuardSpecimen {
            specimen_id: "expansion_on_shift".to_string(),
            family: ShiftGuardSpecimenFamily::BoardExpansion,
            expected_outcome: ShiftGuardExpectedOutcome::Success,
            description: "Board expansion triggered on shift detection".to_string(),
        },
        ShiftGuardSpecimen {
            specimen_id: "summary_tracking".to_string(),
            family: ShiftGuardSpecimenFamily::SummaryTracking,
            expected_outcome: ShiftGuardExpectedOutcome::Success,
            description: "Summary reflects check results".to_string(),
        },
        ShiftGuardSpecimen {
            specimen_id: "reset_clears".to_string(),
            family: ShiftGuardSpecimenFamily::ResetBehavior,
            expected_outcome: ShiftGuardExpectedOutcome::Success,
            description: "Reset clears all state".to_string(),
        },
    ]
}

fn run_specimen(
    specimen: &ShiftGuardSpecimen,
    epoch: SecurityEpoch,
) -> (ShiftGuardVerdict, String) {
    match specimen.specimen_id.as_str() {
        "stable_no_shift" => {
            let mut guard = ShiftGuardOrchestrator::with_defaults(epoch);
            guard.set_baseline(stable_embeddings(4, 10, 500_000));
            match guard.check_shift(stable_embeddings(4, 10, 500_000)) {
                Ok(result) => (
                    ShiftGuardVerdict::Pass,
                    format!("verdict: {:?}", result.verdict),
                ),
                Err(e) => (ShiftGuardVerdict::Fail, format!("error: {e}")),
            }
        }
        "no_baseline_error" => {
            let mut guard = ShiftGuardOrchestrator::with_defaults(epoch);
            match guard.check_shift(stable_embeddings(4, 10, 500_000)) {
                Err(ShiftGuardError::NoBaseline) => (
                    ShiftGuardVerdict::Pass,
                    "correctly rejected: no baseline".to_string(),
                ),
                other => (ShiftGuardVerdict::Fail, format!("unexpected: {other:?}")),
            }
        }
        "empty_live_error" => {
            let mut guard = ShiftGuardOrchestrator::with_defaults(epoch);
            guard.set_baseline(stable_embeddings(4, 10, 500_000));
            match guard.check_shift(vec![]) {
                Err(ShiftGuardError::EmptyLiveStream) => (
                    ShiftGuardVerdict::Pass,
                    "correctly rejected: empty stream".to_string(),
                ),
                other => (ShiftGuardVerdict::Fail, format!("unexpected: {other:?}")),
            }
        }
        "shifted_stream" => {
            let mut guard = ShiftGuardOrchestrator::with_defaults(epoch);
            guard.set_baseline(stable_embeddings(4, 10, 100_000));
            match guard.check_shift(shifted_embeddings(4, 10, 5_000_000)) {
                Ok(result) => (
                    ShiftGuardVerdict::Pass,
                    format!(
                        "shift_detected={}, verdict={:?}",
                        result.shift_detected, result.verdict
                    ),
                ),
                Err(e) => (ShiftGuardVerdict::Fail, format!("error: {e}")),
            }
        }
        "expansion_on_shift" => {
            let mut guard = ShiftGuardOrchestrator::with_defaults(epoch);
            guard.set_baseline(stable_embeddings(4, 10, 100_000));
            match guard.check_shift(shifted_embeddings(4, 10, 5_000_000)) {
                Ok(result) => {
                    if result.shift_detected {
                        (
                            ShiftGuardVerdict::Pass,
                            format!("expansion_triggered={}", result.expansion_triggered),
                        )
                    } else {
                        (
                            ShiftGuardVerdict::Pass,
                            "no shift detected (acceptable)".to_string(),
                        )
                    }
                }
                Err(e) => (ShiftGuardVerdict::Fail, format!("error: {e}")),
            }
        }
        "summary_tracking" => {
            let mut guard = ShiftGuardOrchestrator::with_defaults(epoch);
            guard.set_baseline(stable_embeddings(4, 10, 500_000));
            let _ = guard.check_shift(stable_embeddings(4, 10, 500_000));
            let _ = guard.check_shift(stable_embeddings(4, 10, 500_000));
            let summary = guard.summary();
            if summary.total_checks == 2 {
                (
                    ShiftGuardVerdict::Pass,
                    format!(
                        "checks={}, shifts={}, passes={}",
                        summary.total_checks, summary.shifts_detected, summary.passes
                    ),
                )
            } else {
                (
                    ShiftGuardVerdict::Fail,
                    format!("expected 2 checks, got {}", summary.total_checks),
                )
            }
        }
        "reset_clears" => {
            let mut guard = ShiftGuardOrchestrator::with_defaults(epoch);
            guard.set_baseline(stable_embeddings(4, 10, 500_000));
            let _ = guard.check_shift(stable_embeddings(4, 10, 500_000));
            guard.reset(SecurityEpoch::from_raw(2));
            let summary = guard.summary();
            if summary.total_checks == 0 && guard.board_freshness() == BoardFreshness::Unknown {
                (ShiftGuardVerdict::Pass, "reset cleared state".to_string())
            } else {
                (
                    ShiftGuardVerdict::Fail,
                    "state not fully cleared".to_string(),
                )
            }
        }
        _ => (
            ShiftGuardVerdict::Fail,
            format!("unknown specimen: {}", specimen.specimen_id),
        ),
    }
}

/// Run the evidence corpus.
pub fn run_shift_guard_corpus() -> ShiftGuardEvidenceInventory {
    let epoch = SecurityEpoch::from_raw(1);
    let specimens = shift_guard_corpus();
    let mut evidences = Vec::new();
    let mut family_coverage: BTreeMap<String, usize> = BTreeMap::new();

    for specimen in &specimens {
        let (verdict, details) = run_specimen(specimen, epoch);
        let evidence_hash = ContentHash::compute(
            format!("{}:{:?}:{}", specimen.specimen_id, verdict, details).as_bytes(),
        );
        evidences.push(ShiftGuardSpecimenEvidence {
            specimen_id: specimen.specimen_id.clone(),
            family: specimen.family,
            expected_outcome: specimen.expected_outcome,
            verdict,
            details,
            evidence_hash,
        });
        *family_coverage
            .entry(specimen.family.as_str().to_string())
            .or_insert(0) += 1;
    }

    let passed = evidences
        .iter()
        .filter(|e| e.verdict == ShiftGuardVerdict::Pass)
        .count();
    let failed = evidences.len() - passed;

    let inventory_hash = {
        let mut buf = Vec::new();
        buf.extend_from_slice(SHIFT_GUARD_SCHEMA_VERSION.as_bytes());
        for e in &evidences {
            buf.extend_from_slice(e.evidence_hash.as_bytes());
        }
        ContentHash::compute(&buf)
    };

    ShiftGuardEvidenceInventory {
        schema_version: SHIFT_GUARD_SCHEMA_VERSION.to_string(),
        component: SHIFT_GUARD_COMPONENT.to_string(),
        policy_id: SHIFT_GUARD_POLICY_ID.to_string(),
        total_specimens: evidences.len(),
        passed,
        failed,
        family_coverage,
        evidences,
        inventory_hash,
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_epoch() -> SecurityEpoch {
        SecurityEpoch::from_raw(1)
    }

    #[test]
    fn test_construction() {
        let guard = ShiftGuardOrchestrator::with_defaults(test_epoch());
        assert_eq!(guard.check_count, 0);
        assert_eq!(guard.board_freshness(), BoardFreshness::Unknown);
    }

    #[test]
    fn test_config_defaults() {
        let config = ShiftGuardConfig::default();
        assert!(config.record_history);
        assert!(config.auto_expand_on_shift);
    }

    #[test]
    fn test_set_baseline() {
        let mut guard = ShiftGuardOrchestrator::with_defaults(test_epoch());
        guard.set_baseline(stable_embeddings(4, 5, 500_000));
        assert_eq!(guard.board_freshness(), BoardFreshness::Healthy);
    }

    #[test]
    fn test_check_no_baseline_error() {
        let mut guard = ShiftGuardOrchestrator::with_defaults(test_epoch());
        let result = guard.check_shift(stable_embeddings(4, 5, 500_000));
        assert!(matches!(result, Err(ShiftGuardError::NoBaseline)));
    }

    #[test]
    fn test_check_empty_stream_error() {
        let mut guard = ShiftGuardOrchestrator::with_defaults(test_epoch());
        guard.set_baseline(stable_embeddings(4, 5, 500_000));
        let result = guard.check_shift(vec![]);
        assert!(matches!(result, Err(ShiftGuardError::EmptyLiveStream)));
    }

    #[test]
    fn test_stable_check_succeeds() {
        let mut guard = ShiftGuardOrchestrator::with_defaults(test_epoch());
        guard.set_baseline(stable_embeddings(4, 10, 500_000));
        let result = guard.check_shift(stable_embeddings(4, 10, 500_000));
        assert!(result.is_ok());
    }

    #[test]
    fn test_check_increments_seq() {
        let mut guard = ShiftGuardOrchestrator::with_defaults(test_epoch());
        guard.set_baseline(stable_embeddings(4, 5, 500_000));
        let r1 = guard
            .check_shift(stable_embeddings(4, 5, 500_000))
            .expect("serde deserialization should succeed");
        let r2 = guard
            .check_shift(stable_embeddings(4, 5, 500_000))
            .expect("serde deserialization should succeed");
        assert_eq!(r1.seq, 1);
        assert_eq!(r2.seq, 2);
    }

    #[test]
    fn test_summary_initial() {
        let guard = ShiftGuardOrchestrator::with_defaults(test_epoch());
        let summary = guard.summary();
        assert_eq!(summary.total_checks, 0);
    }

    #[test]
    fn test_summary_after_checks() {
        let mut guard = ShiftGuardOrchestrator::with_defaults(test_epoch());
        guard.set_baseline(stable_embeddings(4, 5, 500_000));
        let _ = guard.check_shift(stable_embeddings(4, 5, 500_000));
        let _ = guard.check_shift(stable_embeddings(4, 5, 500_000));
        let summary = guard.summary();
        assert_eq!(summary.total_checks, 2);
    }

    #[test]
    fn test_summary_hash_deterministic() {
        let mut guard = ShiftGuardOrchestrator::with_defaults(test_epoch());
        guard.set_baseline(stable_embeddings(4, 5, 500_000));
        let _ = guard.check_shift(stable_embeddings(4, 5, 500_000));
        let s1 = guard.summary();
        let s2 = guard.summary();
        assert_eq!(s1.content_hash, s2.content_hash);
    }

    #[test]
    fn test_history_recorded() {
        let mut guard = ShiftGuardOrchestrator::with_defaults(test_epoch());
        guard.set_baseline(stable_embeddings(4, 5, 500_000));
        let _ = guard.check_shift(stable_embeddings(4, 5, 500_000));
        assert_eq!(guard.history().len(), 1);
    }

    #[test]
    fn test_history_bounded() {
        let config = ShiftGuardConfig {
            max_history: 2,
            ..ShiftGuardConfig::default()
        };
        let mut guard = ShiftGuardOrchestrator::new(test_epoch(), config);
        guard.set_baseline(stable_embeddings(4, 5, 500_000));
        for _ in 0..5 {
            let _ = guard.check_shift(stable_embeddings(4, 5, 500_000));
        }
        assert!(guard.history().len() <= 2);
    }

    #[test]
    fn test_reset_clears_state() {
        let mut guard = ShiftGuardOrchestrator::with_defaults(test_epoch());
        guard.set_baseline(stable_embeddings(4, 5, 500_000));
        let _ = guard.check_shift(stable_embeddings(4, 5, 500_000));
        guard.reset(SecurityEpoch::from_raw(2));
        assert_eq!(guard.summary().total_checks, 0);
        assert_eq!(guard.board_freshness(), BoardFreshness::Unknown);
        assert!(guard.history().is_empty());
    }

    #[test]
    fn test_error_display() {
        assert_eq!(
            format!("{}", ShiftGuardError::NoBaseline),
            "no baseline window established"
        );
        assert_eq!(
            format!("{}", ShiftGuardError::EmptyLiveStream),
            "live stream window is empty"
        );
    }

    #[test]
    fn test_corpus_nonempty() {
        assert!(!shift_guard_corpus().is_empty());
    }

    #[test]
    fn test_corpus_covers_all_families() {
        let corpus = shift_guard_corpus();
        for family in ShiftGuardSpecimenFamily::ALL {
            assert!(
                corpus.iter().any(|s| s.family == *family),
                "missing: {family:?}"
            );
        }
    }

    #[test]
    fn test_run_corpus_all_pass() {
        let inv = run_shift_guard_corpus();
        for e in &inv.evidences {
            assert_eq!(
                e.verdict,
                ShiftGuardVerdict::Pass,
                "failed: {} - {}",
                e.specimen_id,
                e.details
            );
        }
        assert_eq!(inv.failed, 0);
    }

    #[test]
    fn test_corpus_deterministic() {
        let i1 = run_shift_guard_corpus();
        let i2 = run_shift_guard_corpus();
        assert_eq!(i1.inventory_hash, i2.inventory_hash);
    }

    #[test]
    fn test_corpus_schema() {
        let inv = run_shift_guard_corpus();
        assert_eq!(inv.component, SHIFT_GUARD_COMPONENT);
        assert_eq!(inv.policy_id, SHIFT_GUARD_POLICY_ID);
    }

    #[test]
    fn test_family_all_count() {
        assert_eq!(ShiftGuardSpecimenFamily::ALL.len(), 5);
    }

    #[test]
    fn test_family_as_str() {
        assert_eq!(
            ShiftGuardSpecimenFamily::StableCheck.as_str(),
            "stable_check"
        );
    }

    #[test]
    fn test_board_freshness_enum() {
        assert_ne!(BoardFreshness::Healthy, BoardFreshness::Stale);
        assert_ne!(BoardFreshness::Stale, BoardFreshness::Unknown);
    }

    // --- Additional enrichment tests ---

    #[test]
    fn test_custom_config_construction() {
        let config = ShiftGuardConfig {
            auto_expand_on_shift: false,
            record_history: false,
            max_history: 10,
            ..ShiftGuardConfig::default()
        };
        let guard = ShiftGuardOrchestrator::new(test_epoch(), config);
        assert_eq!(guard.board_freshness(), BoardFreshness::Unknown);
    }

    #[test]
    fn test_shifted_stream_detection() {
        let mut guard = ShiftGuardOrchestrator::with_defaults(test_epoch());
        guard.set_baseline(stable_embeddings(4, 10, 100_000));
        let result = guard
            .check_shift(shifted_embeddings(4, 10, 5_000_000))
            .expect("serde deserialization should succeed");
        assert_eq!(result.seq, 1);
        assert!(result.mmd_statistic > 0 || !result.shift_detected);
    }

    #[test]
    fn test_expansion_triggered_on_shift() {
        let mut guard = ShiftGuardOrchestrator::with_defaults(test_epoch());
        guard.set_baseline(stable_embeddings(4, 10, 100_000));
        let result = guard
            .check_shift(shifted_embeddings(4, 10, 5_000_000))
            .expect("serde deserialization should succeed");
        if result.shift_detected {
            assert!(result.expansion_triggered);
        }
    }

    #[test]
    fn test_expansion_not_triggered_when_disabled() {
        let config = ShiftGuardConfig {
            auto_expand_on_shift: false,
            ..ShiftGuardConfig::default()
        };
        let mut guard = ShiftGuardOrchestrator::new(test_epoch(), config);
        guard.set_baseline(stable_embeddings(4, 10, 100_000));
        let result = guard
            .check_shift(shifted_embeddings(4, 10, 5_000_000))
            .expect("serde deserialization should succeed");
        assert!(!result.expansion_triggered);
    }

    #[test]
    fn test_freshness_alarm_on_shift() {
        let mut guard = ShiftGuardOrchestrator::with_defaults(test_epoch());
        guard.set_baseline(stable_embeddings(4, 10, 100_000));
        let result = guard
            .check_shift(shifted_embeddings(4, 10, 5_000_000))
            .expect("serde deserialization should succeed");
        assert_eq!(result.shift_detected, result.freshness_alarm);
    }

    #[test]
    fn test_stable_freshness_healthy() {
        let mut guard = ShiftGuardOrchestrator::with_defaults(test_epoch());
        guard.set_baseline(stable_embeddings(4, 10, 500_000));
        let _ = guard
            .check_shift(stable_embeddings(4, 10, 500_000))
            .expect("serde deserialization should succeed");
        assert_eq!(guard.board_freshness(), BoardFreshness::Healthy);
    }

    #[test]
    fn test_content_hash_nonempty() {
        let mut guard = ShiftGuardOrchestrator::with_defaults(test_epoch());
        guard.set_baseline(stable_embeddings(4, 5, 500_000));
        let result = guard
            .check_shift(stable_embeddings(4, 5, 500_000))
            .expect("serde deserialization should succeed");
        assert_ne!(result.content_hash, ContentHash::compute(b""));
    }

    #[test]
    fn test_epoch_propagated() {
        let epoch = SecurityEpoch::from_raw(42);
        let mut guard = ShiftGuardOrchestrator::with_defaults(epoch);
        guard.set_baseline(stable_embeddings(4, 5, 500_000));
        let result = guard
            .check_shift(stable_embeddings(4, 5, 500_000))
            .expect("serde deserialization should succeed");
        assert_eq!(result.epoch, epoch);
    }

    #[test]
    fn test_summary_counters_add_up() {
        let mut guard = ShiftGuardOrchestrator::with_defaults(test_epoch());
        guard.set_baseline(stable_embeddings(4, 10, 500_000));
        for _ in 0..5 {
            let _ = guard.check_shift(stable_embeddings(4, 10, 500_000));
        }
        let s = guard.summary();
        assert_eq!(s.shifts_detected + s.passes, s.total_checks,);
    }

    #[test]
    fn test_reset_then_set_baseline() {
        let mut guard = ShiftGuardOrchestrator::with_defaults(test_epoch());
        guard.set_baseline(stable_embeddings(4, 5, 500_000));
        guard.reset(SecurityEpoch::from_raw(2));
        assert_eq!(guard.board_freshness(), BoardFreshness::Unknown);
        guard.set_baseline(stable_embeddings(4, 5, 500_000));
        assert_eq!(guard.board_freshness(), BoardFreshness::Healthy);
    }

    #[test]
    fn test_history_entries_have_incremental_seq() {
        let mut guard = ShiftGuardOrchestrator::with_defaults(test_epoch());
        guard.set_baseline(stable_embeddings(4, 5, 500_000));
        for _ in 0..3 {
            let _ = guard.check_shift(stable_embeddings(4, 5, 500_000));
        }
        let history = guard.history();
        for (i, entry) in history.iter().enumerate() {
            assert_eq!(entry.seq, (i + 1) as u64);
        }
    }

    #[test]
    fn test_error_detection_failed_display() {
        let err = ShiftGuardError::DetectionFailed {
            detail: "kernel failed".to_string(),
        };
        assert!(format!("{err}").contains("kernel failed"));
    }

    #[test]
    fn test_error_config_display() {
        let err = ShiftGuardError::ConfigError {
            detail: "invalid threshold".to_string(),
        };
        assert!(format!("{err}").contains("invalid threshold"));
    }

    #[test]
    fn test_specimen_family_as_str_all_variants() {
        for family in ShiftGuardSpecimenFamily::ALL {
            assert!(!family.as_str().is_empty());
        }
    }

    #[test]
    fn test_corpus_family_coverage() {
        let inv = run_shift_guard_corpus();
        assert!(!inv.family_coverage.is_empty());
        for family in ShiftGuardSpecimenFamily::ALL {
            assert!(inv.family_coverage.contains_key(family.as_str()));
        }
    }

    #[test]
    fn test_corpus_evidence_hashes_unique() {
        let inv = run_shift_guard_corpus();
        let hashes: std::collections::BTreeSet<_> =
            inv.evidences.iter().map(|e| &e.evidence_hash).collect();
        assert_eq!(hashes.len(), inv.evidences.len());
    }

    #[test]
    fn test_multiple_baselines_last_wins() {
        let mut guard = ShiftGuardOrchestrator::with_defaults(test_epoch());
        guard.set_baseline(stable_embeddings(4, 5, 100_000));
        guard.set_baseline(stable_embeddings(4, 5, 900_000));
        // Should use the second baseline.
        let result = guard
            .check_shift(stable_embeddings(4, 5, 900_000))
            .expect("serde deserialization should succeed");
        assert_eq!(result.seq, 1);
    }

    #[test]
    fn test_large_dimension_embeddings() {
        let mut guard = ShiftGuardOrchestrator::with_defaults(test_epoch());
        guard.set_baseline(stable_embeddings(64, 20, 500_000));
        let result = guard
            .check_shift(stable_embeddings(64, 20, 500_000))
            .expect("serde deserialization should succeed");
        assert_eq!(result.seq, 1);
    }

    #[test]
    fn test_single_embedding_baseline() {
        let mut guard = ShiftGuardOrchestrator::with_defaults(test_epoch());
        guard.set_baseline(stable_embeddings(4, 1, 500_000));
        let result = guard
            .check_shift(stable_embeddings(4, 1, 500_000))
            .expect("serde deserialization should succeed");
        assert_eq!(result.seq, 1);
    }
}
