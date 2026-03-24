#![forbid(unsafe_code)]

//! Calibration sentinels, observability-on supremacy cells, and fail-closed
//! promotion rules for approximate observability.
//!
//! This module turns approximate telemetry into a benchmark/promotion
//! obligation.  Every observability cell aggregates calibration sentinels
//! that measure error bounds, coverage, freshness, drift, and completeness
//! of telemetry streams.  Promotion decisions are fail-closed: unless every
//! sentinel in a cell is green (or the promotion rule explicitly allows
//! degraded states), the cell blocks promotion.
//!
//! Bead: bd-1lsy.11.20.3 [RGC-066C]
//!
//! Key invariants:
//! - Sentinel state is derived deterministically from `(value, threshold)`.
//! - FailClosed rule rejects promotion unless all sentinels are Green.
//! - RequireCalibration allows Yellow but rejects Red.
//! - AllowWithWarning always allows but records suppression reasons.
//! - SuppressClaim always blocks regardless of sentinel state.
//! - Content hashes provide tamper-evident binding of report data.
//!
//! Plan reference: Section 10.11, observability-on supremacy cells.

use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Component name for structured events.
const COMPONENT: &str = "calibration_sentinel";

/// Schema version for calibration sentinel artifacts.
pub const CALIBRATION_SENTINEL_SCHEMA_VERSION: &str = "franken-engine.calibration-sentinel.v1";

/// Bead identifier for this module.
pub const CALIBRATION_SENTINEL_BEAD_ID: &str = "bd-1lsy.11.20.3";

/// Fixed-point scale: 1_000_000 = 1.0.
const MILLIONTHS: u64 = 1_000_000;

/// Yellow threshold fraction: value within 80%-100% of threshold is Yellow.
/// Expressed as millionths: 800_000 = 0.8.
const YELLOW_FRACTION_MILLIONTHS: u64 = 800_000;

/// Maximum sentinels per cell (budget guard).
const MAX_SENTINELS_PER_CELL: usize = 10_000;

/// Maximum cells per report (budget guard).
const MAX_CELLS_PER_REPORT: usize = 50_000;

/// Maximum suppression reasons per decision.
const MAX_SUPPRESSION_REASONS: usize = 1_000;

// ---------------------------------------------------------------------------
// SentinelKind
// ---------------------------------------------------------------------------

/// Category of calibration sentinel.
///
/// Each kind measures a different dimension of telemetry quality.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SentinelKind {
    /// Maximum acceptable error bound (millionths).  A value exceeding the
    /// threshold means the telemetry error is too large.
    ErrorBound,
    /// Minimum required coverage fraction (millionths).  A value below the
    /// threshold means insufficient coverage.
    Coverage,
    /// Maximum acceptable staleness (millionths of an epoch).  Exceeding
    /// the threshold means the data is too old.
    Freshness,
    /// Maximum acceptable metric drift (millionths).  Exceeding means the
    /// metric has drifted beyond tolerance.
    Drift,
    /// Minimum required completeness fraction (millionths).  Below the
    /// threshold means too many gaps.
    Completeness,
}

impl SentinelKind {
    /// Return a static string label.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ErrorBound => "error_bound",
            Self::Coverage => "coverage",
            Self::Freshness => "freshness",
            Self::Drift => "drift",
            Self::Completeness => "completeness",
        }
    }

    /// All sentinel kinds in canonical order.
    pub fn all() -> &'static [SentinelKind] {
        &[
            Self::ErrorBound,
            Self::Coverage,
            Self::Freshness,
            Self::Drift,
            Self::Completeness,
        ]
    }

    /// Whether this kind uses an upper-bound check (value must stay below
    /// threshold) vs a lower-bound check (value must stay above threshold).
    ///
    /// Upper-bound: ErrorBound, Freshness, Drift.
    /// Lower-bound: Coverage, Completeness.
    pub fn is_upper_bound(self) -> bool {
        matches!(self, Self::ErrorBound | Self::Freshness | Self::Drift)
    }
}

impl fmt::Display for SentinelKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// PromotionRule
// ---------------------------------------------------------------------------

/// Rule governing how sentinel state maps to a promotion decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PromotionRule {
    /// All sentinels must be Green; any Yellow or Red blocks promotion.
    FailClosed,
    /// Yellow sentinels are tolerated (with warnings); Red blocks.
    RequireCalibration,
    /// All sentinels must be Green or Yellow; Red blocks.
    RequireObservability,
    /// Promotion is always blocked regardless of sentinel state.
    SuppressClaim,
    /// Promotion is always allowed; degraded sentinels produce warnings.
    AllowWithWarning,
}

impl PromotionRule {
    /// Return a static string label.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FailClosed => "fail_closed",
            Self::RequireCalibration => "require_calibration",
            Self::RequireObservability => "require_observability",
            Self::SuppressClaim => "suppress_claim",
            Self::AllowWithWarning => "allow_with_warning",
        }
    }
}

impl fmt::Display for PromotionRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// SentinelState
// ---------------------------------------------------------------------------

/// Traffic-light state of a calibration sentinel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SentinelState {
    /// All metrics within tolerance.
    Green,
    /// Metrics approaching threshold; calibration recommended.
    Yellow,
    /// Threshold violated; promotion must be blocked under strict rules.
    Red,
    /// State could not be determined (e.g., no data available).
    Unknown,
}

impl SentinelState {
    /// Return a static string label.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Green => "green",
            Self::Yellow => "yellow",
            Self::Red => "red",
            Self::Unknown => "unknown",
        }
    }

    /// Whether this state is considered healthy (Green only).
    pub fn is_healthy(self) -> bool {
        self == Self::Green
    }

    /// Whether this state is considered degraded (Yellow or Red).
    pub fn is_degraded(self) -> bool {
        matches!(self, Self::Yellow | Self::Red)
    }
}

impl fmt::Display for SentinelState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// SentinelError
// ---------------------------------------------------------------------------

/// Errors produced by the calibration sentinel subsystem.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SentinelError {
    /// A sentinel threshold was violated.
    ThresholdViolation,
    /// A required sentinel was not found in the cell.
    MissingSentinel,
    /// Calibration data is stale beyond acceptable freshness.
    CalibrationStale,
    /// An internal error occurred.
    InternalError(String),
}

impl fmt::Display for SentinelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ThresholdViolation => write!(f, "sentinel threshold violated"),
            Self::MissingSentinel => write!(f, "required sentinel missing from cell"),
            Self::CalibrationStale => write!(f, "calibration data is stale"),
            Self::InternalError(msg) => write!(f, "internal error: {msg}"),
        }
    }
}

// ---------------------------------------------------------------------------
// CalibrationSentinel
// ---------------------------------------------------------------------------

/// A single calibration sentinel measuring one dimension of telemetry quality.
///
/// The sentinel compares `current_value_millionths` against
/// `threshold_millionths` using direction-aware comparison (upper-bound for
/// ErrorBound/Freshness/Drift, lower-bound for Coverage/Completeness).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CalibrationSentinel {
    /// Unique sentinel identifier.
    pub sentinel_id: String,
    /// What dimension of telemetry this sentinel tracks.
    pub kind: SentinelKind,
    /// The threshold value in millionths.
    pub threshold_millionths: u64,
    /// The current observed value in millionths.
    pub current_value_millionths: u64,
    /// Derived traffic-light state.
    pub state: SentinelState,
    /// Content-addressable hash binding sentinel data.
    pub content_hash: ContentHash,
}

impl CalibrationSentinel {
    /// Compute a deterministic content hash for this sentinel.
    pub fn compute_hash(&self) -> ContentHash {
        let mut hasher = Sha256::new();
        hasher.update(COMPONENT.as_bytes());
        hasher.update(b":sentinel:");
        hasher.update(self.sentinel_id.as_bytes());
        hasher.update(b":");
        hasher.update(self.kind.as_str().as_bytes());
        hasher.update(self.threshold_millionths.to_le_bytes());
        hasher.update(self.current_value_millionths.to_le_bytes());
        hasher.update(self.state.as_str().as_bytes());
        let result = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&result);
        ContentHash(out)
    }
}

impl fmt::Display for CalibrationSentinel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "sentinel[{}] kind={} value={} threshold={} state={}",
            self.sentinel_id,
            self.kind,
            self.current_value_millionths,
            self.threshold_millionths,
            self.state,
        )
    }
}

// ---------------------------------------------------------------------------
// ObservabilityCell
// ---------------------------------------------------------------------------

/// An observability cell grouping sentinels under a supremacy domain.
///
/// The cell aggregates sentinel states and applies a promotion rule to
/// determine whether the domain's claims may proceed to promotion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservabilityCell {
    /// Unique cell identifier.
    pub cell_id: String,
    /// The supremacy domain this cell covers (e.g., "latency", "throughput").
    pub supremacy_domain: String,
    /// The sentinels attached to this cell.
    pub sentinels: Vec<CalibrationSentinel>,
    /// The promotion rule applied to this cell.
    pub promotion_rule: PromotionRule,
    /// Aggregate state across all sentinels.
    pub overall_state: SentinelState,
}

impl ObservabilityCell {
    /// Compute the aggregate state from the sentinels.
    ///
    /// - If any sentinel is Red, overall is Red.
    /// - If any sentinel is Unknown, overall is Unknown (unless Red exists).
    /// - If any sentinel is Yellow, overall is Yellow.
    /// - Otherwise, overall is Green.
    pub fn compute_overall_state(&self) -> SentinelState {
        aggregate_states(&self.sentinels)
    }

    /// Count sentinels in a given state.
    pub fn count_in_state(&self, state: SentinelState) -> usize {
        self.sentinels.iter().filter(|s| s.state == state).count()
    }

    /// Compute a deterministic content hash for this cell.
    pub fn compute_hash(&self) -> ContentHash {
        let mut hasher = Sha256::new();
        hasher.update(COMPONENT.as_bytes());
        hasher.update(b":cell:");
        hasher.update(self.cell_id.as_bytes());
        hasher.update(b":");
        hasher.update(self.supremacy_domain.as_bytes());
        hasher.update(b":");
        hasher.update(self.promotion_rule.as_str().as_bytes());
        hasher.update(b":");
        hasher.update(self.overall_state.as_str().as_bytes());
        {
            let mut sorted_hashes: Vec<[u8; 32]> = self
                .sentinels
                .iter()
                .map(|s| *s.content_hash.as_bytes())
                .collect();
            sorted_hashes.sort();
            for h in &sorted_hashes {
                hasher.update(h);
            }
        }
        let result = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&result);
        ContentHash(out)
    }
}

impl fmt::Display for ObservabilityCell {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "cell[{}] domain={} rule={} state={} sentinels={}",
            self.cell_id,
            self.supremacy_domain,
            self.promotion_rule,
            self.overall_state,
            self.sentinels.len(),
        )
    }
}

// ---------------------------------------------------------------------------
// PromotionDecision
// ---------------------------------------------------------------------------

/// The outcome of evaluating a promotion rule against an observability cell.
///
/// Contains the decision (allowed/blocked), any suppression reasons, and a
/// content hash for evidence binding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromotionDecision {
    /// Unique decision identifier.
    pub decision_id: String,
    /// Cell that was evaluated.
    pub cell_id: String,
    /// The promotion rule that was applied.
    pub rule: PromotionRule,
    /// Whether promotion is allowed.
    pub allowed: bool,
    /// Reasons for suppression (populated when blocked or warned).
    pub suppression_reasons: Vec<String>,
    /// Content-addressable hash binding decision data.
    pub content_hash: ContentHash,
}

impl PromotionDecision {
    /// Compute a deterministic content hash for this decision.
    pub fn compute_hash(&self) -> ContentHash {
        let mut hasher = Sha256::new();
        hasher.update(COMPONENT.as_bytes());
        hasher.update(b":decision:");
        hasher.update(self.decision_id.as_bytes());
        hasher.update(b":");
        hasher.update(self.cell_id.as_bytes());
        hasher.update(b":");
        hasher.update(self.rule.as_str().as_bytes());
        hasher.update(if self.allowed { b"allowed" } else { b"blocked" });
        for reason in &self.suppression_reasons {
            hasher.update(b"|");
            hasher.update(reason.as_bytes());
        }
        let result = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&result);
        ContentHash(out)
    }
}

impl fmt::Display for PromotionDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let status = if self.allowed { "ALLOWED" } else { "BLOCKED" };
        write!(
            f,
            "decision[{}] cell={} rule={} status={} reasons={}",
            self.decision_id,
            self.cell_id,
            self.rule,
            status,
            self.suppression_reasons.len(),
        )
    }
}

// ---------------------------------------------------------------------------
// SentinelReport
// ---------------------------------------------------------------------------

/// Aggregated report across all observability cells for a given epoch.
///
/// Contains promotion decisions, cell snapshots, and summary counters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SentinelReport {
    /// Unique report identifier.
    pub report_id: String,
    /// Security epoch for this report.
    pub epoch: SecurityEpoch,
    /// All observability cells included in the report.
    pub cells: Vec<ObservabilityCell>,
    /// Promotion decisions for each cell.
    pub decisions: Vec<PromotionDecision>,
    /// Number of cells with Green overall state.
    pub green_count: u64,
    /// Number of cells with Red overall state.
    pub red_count: u64,
    /// Content-addressable hash binding report data.
    pub content_hash: ContentHash,
}

impl SentinelReport {
    /// Compute a deterministic content hash for this report.
    pub fn compute_hash(&self) -> ContentHash {
        let mut hasher = Sha256::new();
        hasher.update(COMPONENT.as_bytes());
        hasher.update(b":report:");
        hasher.update(self.report_id.as_bytes());
        hasher.update(b":");
        hasher.update(self.epoch.as_u64().to_le_bytes());
        hasher.update(self.green_count.to_le_bytes());
        hasher.update(self.red_count.to_le_bytes());
        hasher.update((self.cells.len() as u64).to_le_bytes());
        {
            let mut cell_hashes: Vec<ContentHash> =
                self.cells.iter().map(|c| c.compute_hash()).collect();
            cell_hashes.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
            for h in &cell_hashes {
                hasher.update(h.as_bytes());
            }
        }
        {
            let mut decision_hashes: Vec<[u8; 32]> = self
                .decisions
                .iter()
                .map(|d| *d.content_hash.as_bytes())
                .collect();
            decision_hashes.sort();
            for h in &decision_hashes {
                hasher.update(h);
            }
        }
        let result = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&result);
        ContentHash(out)
    }

    /// Return the fraction of cells that are green, in millionths.
    pub fn green_fraction_millionths(&self) -> u64 {
        let total = self.cells.len() as u64;
        if total == 0 {
            return 0;
        }
        self.green_count.saturating_mul(MILLIONTHS) / total
    }

    /// Return the fraction of decisions that allowed promotion, in millionths.
    pub fn allowed_fraction_millionths(&self) -> u64 {
        let total = self.decisions.len() as u64;
        if total == 0 {
            return 0;
        }
        let allowed = self.decisions.iter().filter(|d| d.allowed).count() as u64;
        allowed.saturating_mul(MILLIONTHS) / total
    }
}

impl fmt::Display for SentinelReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "report[{}] epoch={} cells={} green={} red={} decisions={}",
            self.report_id,
            self.epoch,
            self.cells.len(),
            self.green_count,
            self.red_count,
            self.decisions.len(),
        )
    }
}

// ---------------------------------------------------------------------------
// Core functions
// ---------------------------------------------------------------------------

/// Classify a sentinel state from a value and threshold.
///
/// For upper-bound sentinels (ErrorBound, Freshness, Drift):
/// - Green: value <= yellow_threshold (80% of threshold)
/// - Yellow: yellow_threshold < value <= threshold
/// - Red: value > threshold
///
/// For lower-bound sentinels (Coverage, Completeness) the comparison is
/// inverted: the value should be *above* the threshold, not below.
///
/// When threshold is zero, state is Green if value is zero, Red otherwise
/// (for upper-bound) or Green if value is non-zero (for lower-bound).
pub fn classify_state(value: u64, threshold: u64) -> SentinelState {
    classify_state_directed(value, threshold, true)
}

/// Classify state with explicit directionality.
///
/// `upper_bound = true` means value must stay below threshold (ErrorBound,
/// Freshness, Drift).  `upper_bound = false` means value must stay above
/// threshold (Coverage, Completeness).
fn classify_state_directed(value: u64, threshold: u64, upper_bound: bool) -> SentinelState {
    if threshold == 0 {
        if upper_bound {
            return if value == 0 {
                SentinelState::Green
            } else {
                SentinelState::Red
            };
        } else {
            // Lower-bound with threshold 0: any value passes.
            return SentinelState::Green;
        }
    }

    if upper_bound {
        // Upper-bound: value should be below threshold.
        // Yellow zone: value > 80% of threshold but <= threshold.
        let yellow_boundary = threshold.saturating_mul(YELLOW_FRACTION_MILLIONTHS) / MILLIONTHS;

        if value > threshold {
            SentinelState::Red
        } else if value > yellow_boundary {
            SentinelState::Yellow
        } else {
            SentinelState::Green
        }
    } else {
        // Lower-bound: value should be above threshold.
        // Yellow zone: value >= threshold but < 125% of threshold (approaching from above).
        // Actually, for lower-bound let's define:
        // - Red: value < threshold
        // - Yellow: threshold <= value < threshold + 20% of threshold
        // - Green: value >= threshold + 20% of threshold
        let green_boundary = threshold.saturating_add(
            threshold.saturating_mul(MILLIONTHS - YELLOW_FRACTION_MILLIONTHS) / MILLIONTHS,
        );

        if value < threshold {
            SentinelState::Red
        } else if value < green_boundary {
            SentinelState::Yellow
        } else {
            SentinelState::Green
        }
    }
}

/// Create a new calibration sentinel with the given parameters.
///
/// The sentinel's state is initialized to Unknown and its content hash is
/// computed.  Call `update_sentinel` to set the initial value and derive the
/// proper state.
pub fn create_sentinel(id: &str, kind: SentinelKind, threshold: u64) -> CalibrationSentinel {
    let mut sentinel = CalibrationSentinel {
        sentinel_id: id.to_string(),
        kind,
        threshold_millionths: threshold,
        current_value_millionths: 0,
        state: SentinelState::Unknown,
        content_hash: ContentHash::compute(&[]),
    };
    sentinel.content_hash = sentinel.compute_hash();
    sentinel
}

/// Update a sentinel's current value and re-derive its state.
///
/// Returns the new state.
pub fn update_sentinel(sentinel: &mut CalibrationSentinel, value: u64) -> SentinelState {
    sentinel.current_value_millionths = value;
    let upper_bound = sentinel.kind.is_upper_bound();
    sentinel.state = classify_state_directed(value, sentinel.threshold_millionths, upper_bound);
    sentinel.content_hash = sentinel.compute_hash();
    sentinel.state
}

/// Build an observability cell from sentinels and a promotion rule.
///
/// The overall state is computed from the aggregate of sentinel states.
/// Sentinels are capped at `MAX_SENTINELS_PER_CELL`.
pub fn build_cell(
    cell_id: &str,
    domain: &str,
    sentinels: Vec<CalibrationSentinel>,
    rule: PromotionRule,
) -> ObservabilityCell {
    let capped = if sentinels.len() > MAX_SENTINELS_PER_CELL {
        sentinels[..MAX_SENTINELS_PER_CELL].to_vec()
    } else {
        sentinels
    };

    let overall_state = aggregate_states(&capped);

    ObservabilityCell {
        cell_id: cell_id.to_string(),
        supremacy_domain: domain.to_string(),
        sentinels: capped,
        promotion_rule: rule,
        overall_state,
    }
}

/// Evaluate a promotion decision for an observability cell.
///
/// Applies the cell's promotion rule to its overall state to determine
/// whether promotion is allowed.
pub fn evaluate_promotion(cell: &ObservabilityCell) -> PromotionDecision {
    let decision_id = generate_decision_id(cell);
    let mut suppression_reasons = Vec::new();

    let allowed = match cell.promotion_rule {
        PromotionRule::FailClosed => {
            // All sentinels must be Green.
            if cell.overall_state != SentinelState::Green {
                collect_non_green_reasons(cell, &mut suppression_reasons);
                false
            } else {
                true
            }
        }
        PromotionRule::RequireCalibration => {
            // Yellow is tolerated, Red blocks.
            match cell.overall_state {
                SentinelState::Green => true,
                SentinelState::Yellow => {
                    collect_yellow_warnings(cell, &mut suppression_reasons);
                    true
                }
                SentinelState::Red | SentinelState::Unknown => {
                    collect_non_green_reasons(cell, &mut suppression_reasons);
                    false
                }
            }
        }
        PromotionRule::RequireObservability => {
            // Green and Yellow pass; Red blocks.
            match cell.overall_state {
                SentinelState::Green | SentinelState::Yellow => {
                    if cell.overall_state == SentinelState::Yellow {
                        collect_yellow_warnings(cell, &mut suppression_reasons);
                    }
                    true
                }
                SentinelState::Red | SentinelState::Unknown => {
                    collect_non_green_reasons(cell, &mut suppression_reasons);
                    false
                }
            }
        }
        PromotionRule::SuppressClaim => {
            // Always blocked.
            suppression_reasons.push(format!(
                "cell {} has SuppressClaim rule; promotion unconditionally blocked",
                cell.cell_id,
            ));
            false
        }
        PromotionRule::AllowWithWarning => {
            // Always allowed, but with warnings for non-green sentinels.
            if cell.overall_state != SentinelState::Green {
                collect_non_green_reasons(cell, &mut suppression_reasons);
            }
            true
        }
    };

    // Cap suppression reasons.
    if suppression_reasons.len() > MAX_SUPPRESSION_REASONS {
        suppression_reasons.truncate(MAX_SUPPRESSION_REASONS);
    }

    let mut decision = PromotionDecision {
        decision_id,
        cell_id: cell.cell_id.clone(),
        rule: cell.promotion_rule,
        allowed,
        suppression_reasons,
        content_hash: ContentHash::compute(&[]),
    };
    decision.content_hash = decision.compute_hash();
    decision
}

/// Build a sentinel report from an epoch and a set of observability cells.
///
/// Evaluates promotion for each cell and aggregates green/red counts.
pub fn build_report(epoch: SecurityEpoch, cells: Vec<ObservabilityCell>) -> SentinelReport {
    let capped = if cells.len() > MAX_CELLS_PER_REPORT {
        cells[..MAX_CELLS_PER_REPORT].to_vec()
    } else {
        cells
    };

    let mut decisions = Vec::with_capacity(capped.len());
    let mut green_count: u64 = 0;
    let mut red_count: u64 = 0;

    for cell in &capped {
        let decision = evaluate_promotion(cell);
        decisions.push(decision);

        match cell.overall_state {
            SentinelState::Green => green_count += 1,
            SentinelState::Red => red_count += 1,
            _ => {}
        }
    }

    let report_id = generate_report_id(&epoch, &capped, &decisions);

    let mut report = SentinelReport {
        report_id,
        epoch,
        cells: capped,
        decisions,
        green_count,
        red_count,
        content_hash: ContentHash::compute(&[]),
    };
    report.content_hash = report.compute_hash();
    report
}

/// Generate a canonical reference manifest demonstrating calibration sentinel
/// capabilities.
///
/// Returns a self-consistent `SentinelReport` with representative cells and
/// sentinels across all sentinel kinds and promotion rules.
pub fn franken_engine_sentinel_manifest() -> SentinelReport {
    let epoch = SecurityEpoch::from_raw(1);

    // Cell 1: FailClosed, all green sentinels.
    let mut s1 = create_sentinel("manifest-s1-error", SentinelKind::ErrorBound, 500_000);
    update_sentinel(&mut s1, 100_000);

    let mut s2 = create_sentinel("manifest-s2-coverage", SentinelKind::Coverage, 800_000);
    update_sentinel(&mut s2, MILLIONTHS);

    let cell1 = build_cell(
        "manifest-cell-strict",
        "latency",
        vec![s1, s2],
        PromotionRule::FailClosed,
    );

    // Cell 2: RequireCalibration, one yellow sentinel.
    let mut s3 = create_sentinel("manifest-s3-freshness", SentinelKind::Freshness, MILLIONTHS);
    update_sentinel(&mut s3, 850_000); // Yellow: > 800_000 but <= 1_000_000

    let mut s4 = create_sentinel("manifest-s4-drift", SentinelKind::Drift, 200_000);
    update_sentinel(&mut s4, 50_000); // Green: well below threshold

    let cell2 = build_cell(
        "manifest-cell-calibrated",
        "throughput",
        vec![s3, s4],
        PromotionRule::RequireCalibration,
    );

    // Cell 3: SuppressClaim, one red sentinel.
    let mut s5 = create_sentinel(
        "manifest-s5-completeness",
        SentinelKind::Completeness,
        900_000,
    );
    update_sentinel(&mut s5, 400_000); // Red: below threshold

    let cell3 = build_cell(
        "manifest-cell-suppressed",
        "memory",
        vec![s5],
        PromotionRule::SuppressClaim,
    );

    // Cell 4: AllowWithWarning, red sentinel but still allowed.
    let mut s6 = create_sentinel("manifest-s6-error", SentinelKind::ErrorBound, 100_000);
    update_sentinel(&mut s6, 200_000); // Red: above threshold

    let cell4 = build_cell(
        "manifest-cell-warned",
        "tail_latency",
        vec![s6],
        PromotionRule::AllowWithWarning,
    );

    // Cell 5: RequireObservability, all green.
    let mut s7 = create_sentinel("manifest-s7-drift", SentinelKind::Drift, 300_000);
    update_sentinel(&mut s7, 100_000);

    let mut s8 = create_sentinel("manifest-s8-coverage", SentinelKind::Coverage, 700_000);
    update_sentinel(&mut s8, 900_000);

    let cell5 = build_cell(
        "manifest-cell-observable",
        "compilation",
        vec![s7, s8],
        PromotionRule::RequireObservability,
    );

    build_report(epoch, vec![cell1, cell2, cell3, cell4, cell5])
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Aggregate sentinel states into a single overall state.
///
/// Priority: Red > Unknown > Yellow > Green.
fn aggregate_states(sentinels: &[CalibrationSentinel]) -> SentinelState {
    if sentinels.is_empty() {
        return SentinelState::Unknown;
    }

    let mut has_red = false;
    let mut has_unknown = false;
    let mut has_yellow = false;

    for s in sentinels {
        match s.state {
            SentinelState::Red => has_red = true,
            SentinelState::Unknown => has_unknown = true,
            SentinelState::Yellow => has_yellow = true,
            SentinelState::Green => {}
        }
    }

    if has_red {
        SentinelState::Red
    } else if has_unknown {
        SentinelState::Unknown
    } else if has_yellow {
        SentinelState::Yellow
    } else {
        SentinelState::Green
    }
}

/// Collect suppression reasons for non-green sentinels in a cell.
fn collect_non_green_reasons(cell: &ObservabilityCell, reasons: &mut Vec<String>) {
    for s in &cell.sentinels {
        if s.state != SentinelState::Green {
            reasons.push(format!(
                "sentinel {} ({}) is {} (value={}, threshold={})",
                s.sentinel_id, s.kind, s.state, s.current_value_millionths, s.threshold_millionths,
            ));
        }
    }
}

/// Collect warning reasons for yellow sentinels in a cell.
fn collect_yellow_warnings(cell: &ObservabilityCell, reasons: &mut Vec<String>) {
    for s in &cell.sentinels {
        if s.state == SentinelState::Yellow {
            reasons.push(format!(
                "sentinel {} ({}) is yellow (value={}, threshold={})",
                s.sentinel_id, s.kind, s.current_value_millionths, s.threshold_millionths,
            ));
        }
    }
}

/// Generate a deterministic decision ID from cell data.
fn generate_decision_id(cell: &ObservabilityCell) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"decision:");
    hasher.update(cell.cell_id.as_bytes());
    hasher.update(b":");
    hasher.update(cell.promotion_rule.as_str().as_bytes());
    hasher.update(b":");
    hasher.update(cell.overall_state.as_str().as_bytes());
    for s in &cell.sentinels {
        hasher.update(s.sentinel_id.as_bytes());
        hasher.update(s.current_value_millionths.to_le_bytes());
    }
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    format!("dec-{}", hex_encode_prefix(&out, 16))
}

/// Generate a deterministic report ID from epoch, cells, and decisions.
fn generate_report_id(
    epoch: &SecurityEpoch,
    cells: &[ObservabilityCell],
    decisions: &[PromotionDecision],
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"report:");
    hasher.update(epoch.as_u64().to_le_bytes());
    hasher.update((cells.len() as u64).to_le_bytes());
    for c in cells {
        hasher.update(c.cell_id.as_bytes());
    }
    for d in decisions {
        hasher.update(d.decision_id.as_bytes());
    }
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    format!("rpt-{}", hex_encode_prefix(&out, 16))
}

/// Hex-encode the first `n` hex chars (n/2 bytes) of a byte slice.
fn hex_encode_prefix(bytes: &[u8], hex_chars: usize) -> String {
    let byte_count = hex_chars.div_ceil(2);
    let mut s = String::with_capacity(hex_chars);
    for &b in bytes.iter().take(byte_count) {
        s.push_str(&format!("{b:02x}"));
    }
    s.truncate(hex_chars);
    s
}

/// Full hex encoding of a byte slice.
#[cfg(test)]
fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Compute a SHA-256 digest and return raw bytes.
#[cfg(test)]
fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Helper functions ---------------------------------------------------

    fn make_sentinel(
        id: &str,
        kind: SentinelKind,
        threshold: u64,
        value: u64,
    ) -> CalibrationSentinel {
        let mut s = create_sentinel(id, kind, threshold);
        update_sentinel(&mut s, value);
        s
    }

    fn make_green_cell(cell_id: &str, domain: &str, rule: PromotionRule) -> ObservabilityCell {
        let s1 = make_sentinel("g1", SentinelKind::ErrorBound, 500_000, 100_000);
        let s2 = make_sentinel("g2", SentinelKind::Coverage, 800_000, MILLIONTHS);
        build_cell(cell_id, domain, vec![s1, s2], rule)
    }

    fn make_yellow_cell(cell_id: &str, domain: &str, rule: PromotionRule) -> ObservabilityCell {
        let s1 = make_sentinel("y1", SentinelKind::ErrorBound, MILLIONTHS, 850_000);
        let s2 = make_sentinel("y2", SentinelKind::Coverage, 800_000, MILLIONTHS);
        build_cell(cell_id, domain, vec![s1, s2], rule)
    }

    fn make_red_cell(cell_id: &str, domain: &str, rule: PromotionRule) -> ObservabilityCell {
        let s1 = make_sentinel("r1", SentinelKind::ErrorBound, 100_000, 200_000);
        let s2 = make_sentinel("r2", SentinelKind::Coverage, 800_000, MILLIONTHS);
        build_cell(cell_id, domain, vec![s1, s2], rule)
    }

    // -- SentinelKind tests -------------------------------------------------

    #[test]
    fn test_sentinel_kind_as_str() {
        assert_eq!(SentinelKind::ErrorBound.as_str(), "error_bound");
        assert_eq!(SentinelKind::Coverage.as_str(), "coverage");
        assert_eq!(SentinelKind::Freshness.as_str(), "freshness");
        assert_eq!(SentinelKind::Drift.as_str(), "drift");
        assert_eq!(SentinelKind::Completeness.as_str(), "completeness");
    }

    #[test]
    fn test_sentinel_kind_all() {
        let all = SentinelKind::all();
        assert_eq!(all.len(), 5);
        assert_eq!(all[0], SentinelKind::ErrorBound);
        assert_eq!(all[4], SentinelKind::Completeness);
    }

    #[test]
    fn test_sentinel_kind_is_upper_bound() {
        assert!(SentinelKind::ErrorBound.is_upper_bound());
        assert!(SentinelKind::Freshness.is_upper_bound());
        assert!(SentinelKind::Drift.is_upper_bound());
        assert!(!SentinelKind::Coverage.is_upper_bound());
        assert!(!SentinelKind::Completeness.is_upper_bound());
    }

    #[test]
    fn test_sentinel_kind_display() {
        assert_eq!(format!("{}", SentinelKind::ErrorBound), "error_bound");
        assert_eq!(format!("{}", SentinelKind::Completeness), "completeness");
    }

    // -- PromotionRule tests ------------------------------------------------

    #[test]
    fn test_promotion_rule_as_str() {
        assert_eq!(PromotionRule::FailClosed.as_str(), "fail_closed");
        assert_eq!(
            PromotionRule::RequireCalibration.as_str(),
            "require_calibration"
        );
        assert_eq!(
            PromotionRule::RequireObservability.as_str(),
            "require_observability"
        );
        assert_eq!(PromotionRule::SuppressClaim.as_str(), "suppress_claim");
        assert_eq!(
            PromotionRule::AllowWithWarning.as_str(),
            "allow_with_warning"
        );
    }

    #[test]
    fn test_promotion_rule_display() {
        assert_eq!(format!("{}", PromotionRule::FailClosed), "fail_closed");
        assert_eq!(
            format!("{}", PromotionRule::AllowWithWarning),
            "allow_with_warning"
        );
    }

    // -- SentinelState tests ------------------------------------------------

    #[test]
    fn test_sentinel_state_as_str() {
        assert_eq!(SentinelState::Green.as_str(), "green");
        assert_eq!(SentinelState::Yellow.as_str(), "yellow");
        assert_eq!(SentinelState::Red.as_str(), "red");
        assert_eq!(SentinelState::Unknown.as_str(), "unknown");
    }

    #[test]
    fn test_sentinel_state_is_healthy() {
        assert!(SentinelState::Green.is_healthy());
        assert!(!SentinelState::Yellow.is_healthy());
        assert!(!SentinelState::Red.is_healthy());
        assert!(!SentinelState::Unknown.is_healthy());
    }

    #[test]
    fn test_sentinel_state_is_degraded() {
        assert!(!SentinelState::Green.is_degraded());
        assert!(SentinelState::Yellow.is_degraded());
        assert!(SentinelState::Red.is_degraded());
        assert!(!SentinelState::Unknown.is_degraded());
    }

    #[test]
    fn test_sentinel_state_display() {
        assert_eq!(format!("{}", SentinelState::Green), "green");
        assert_eq!(format!("{}", SentinelState::Red), "red");
    }

    // -- SentinelError tests ------------------------------------------------

    #[test]
    fn test_sentinel_error_display() {
        assert_eq!(
            format!("{}", SentinelError::ThresholdViolation),
            "sentinel threshold violated",
        );
        assert_eq!(
            format!("{}", SentinelError::MissingSentinel),
            "required sentinel missing from cell",
        );
        assert_eq!(
            format!("{}", SentinelError::CalibrationStale),
            "calibration data is stale",
        );
        assert_eq!(
            format!("{}", SentinelError::InternalError("oops".into())),
            "internal error: oops",
        );
    }

    #[test]
    fn test_sentinel_error_serde_roundtrip() {
        let err = SentinelError::InternalError("test msg".into());
        let json = serde_json::to_string(&err).unwrap();
        let back: SentinelError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, back);
    }

    // -- classify_state tests -----------------------------------------------

    #[test]
    fn test_classify_state_upper_bound_green() {
        // value=100k, threshold=500k, yellow_boundary=400k => Green
        let state = classify_state(100_000, 500_000);
        assert_eq!(state, SentinelState::Green);
    }

    #[test]
    fn test_classify_state_upper_bound_yellow() {
        // value=450k, threshold=500k, yellow_boundary=400k => Yellow
        let state = classify_state(450_000, 500_000);
        assert_eq!(state, SentinelState::Yellow);
    }

    #[test]
    fn test_classify_state_upper_bound_red() {
        // value=600k, threshold=500k => Red
        let state = classify_state(600_000, 500_000);
        assert_eq!(state, SentinelState::Red);
    }

    #[test]
    fn test_classify_state_upper_bound_exact_threshold() {
        // value == threshold => Yellow (not Red, since <=)
        let state = classify_state(500_000, 500_000);
        assert_eq!(state, SentinelState::Yellow);
    }

    #[test]
    fn test_classify_state_upper_bound_at_yellow_boundary() {
        // value == yellow_boundary (80% of threshold) => Green (<=)
        // 80% of 500_000 = 400_000
        let state = classify_state(400_000, 500_000);
        assert_eq!(state, SentinelState::Green);
    }

    #[test]
    fn test_classify_state_upper_bound_just_above_yellow_boundary() {
        let state = classify_state(400_001, 500_000);
        assert_eq!(state, SentinelState::Yellow);
    }

    #[test]
    fn test_classify_state_zero_threshold_zero_value() {
        let state = classify_state(0, 0);
        assert_eq!(state, SentinelState::Green);
    }

    #[test]
    fn test_classify_state_zero_threshold_nonzero_value() {
        let state = classify_state(1, 0);
        assert_eq!(state, SentinelState::Red);
    }

    #[test]
    fn test_classify_state_lower_bound_green() {
        // Coverage: value=1M, threshold=800k.
        // green_boundary = 800k + 200k * 800k / 1M = 800k + 160k = 960k
        // value=1M > 960k => Green
        let state = classify_state_directed(MILLIONTHS, 800_000, false);
        assert_eq!(state, SentinelState::Green);
    }

    #[test]
    fn test_classify_state_lower_bound_yellow() {
        // Coverage: value=850k, threshold=800k.
        // green_boundary = 800k + 160k = 960k
        // 850k >= 800k but < 960k => Yellow
        let state = classify_state_directed(850_000, 800_000, false);
        assert_eq!(state, SentinelState::Yellow);
    }

    #[test]
    fn test_classify_state_lower_bound_red() {
        // Coverage: value=700k, threshold=800k.
        // 700k < 800k => Red
        let state = classify_state_directed(700_000, 800_000, false);
        assert_eq!(state, SentinelState::Red);
    }

    #[test]
    fn test_classify_state_lower_bound_zero_threshold() {
        // Lower-bound with threshold 0: any value is Green.
        let state = classify_state_directed(0, 0, false);
        assert_eq!(state, SentinelState::Green);
        let state2 = classify_state_directed(500_000, 0, false);
        assert_eq!(state2, SentinelState::Green);
    }

    // -- create_sentinel tests ----------------------------------------------

    #[test]
    fn test_create_sentinel_initial_state_unknown() {
        let s = create_sentinel("test", SentinelKind::ErrorBound, 500_000);
        assert_eq!(s.state, SentinelState::Unknown);
        assert_eq!(s.current_value_millionths, 0);
        assert_eq!(s.threshold_millionths, 500_000);
        assert_eq!(s.kind, SentinelKind::ErrorBound);
        assert_eq!(s.sentinel_id, "test");
    }

    #[test]
    fn test_create_sentinel_has_content_hash() {
        let s = create_sentinel("test", SentinelKind::Coverage, 800_000);
        assert_ne!(s.content_hash, ContentHash::compute(&[]));
    }

    // -- update_sentinel tests ----------------------------------------------

    #[test]
    fn test_update_sentinel_upper_bound_to_green() {
        let mut s = create_sentinel("s1", SentinelKind::ErrorBound, 500_000);
        let state = update_sentinel(&mut s, 100_000);
        assert_eq!(state, SentinelState::Green);
        assert_eq!(s.current_value_millionths, 100_000);
        assert_eq!(s.state, SentinelState::Green);
    }

    #[test]
    fn test_update_sentinel_upper_bound_to_red() {
        let mut s = create_sentinel("s1", SentinelKind::Drift, 200_000);
        let state = update_sentinel(&mut s, 300_000);
        assert_eq!(state, SentinelState::Red);
    }

    #[test]
    fn test_update_sentinel_lower_bound_coverage_green() {
        let mut s = create_sentinel("s1", SentinelKind::Coverage, 800_000);
        let state = update_sentinel(&mut s, MILLIONTHS);
        assert_eq!(state, SentinelState::Green);
    }

    #[test]
    fn test_update_sentinel_lower_bound_coverage_red() {
        let mut s = create_sentinel("s1", SentinelKind::Coverage, 800_000);
        let state = update_sentinel(&mut s, 500_000);
        assert_eq!(state, SentinelState::Red);
    }

    #[test]
    fn test_update_sentinel_refreshes_hash() {
        let mut s = create_sentinel("s1", SentinelKind::ErrorBound, 500_000);
        let hash_before = s.content_hash;
        update_sentinel(&mut s, 100_000);
        assert_ne!(s.content_hash, hash_before);
    }

    // -- aggregate_states tests ---------------------------------------------

    #[test]
    fn test_aggregate_empty_is_unknown() {
        let state = aggregate_states(&[]);
        assert_eq!(state, SentinelState::Unknown);
    }

    #[test]
    fn test_aggregate_all_green() {
        let s1 = make_sentinel("a", SentinelKind::ErrorBound, 500_000, 100_000);
        let s2 = make_sentinel("b", SentinelKind::Drift, 300_000, 50_000);
        let state = aggregate_states(&[s1, s2]);
        assert_eq!(state, SentinelState::Green);
    }

    #[test]
    fn test_aggregate_one_yellow() {
        let s1 = make_sentinel("a", SentinelKind::ErrorBound, 500_000, 100_000);
        let s2 = make_sentinel("b", SentinelKind::ErrorBound, MILLIONTHS, 850_000);
        let state = aggregate_states(&[s1, s2]);
        assert_eq!(state, SentinelState::Yellow);
    }

    #[test]
    fn test_aggregate_red_overrides_yellow() {
        let s1 = make_sentinel("a", SentinelKind::ErrorBound, MILLIONTHS, 850_000); // Yellow
        let s2 = make_sentinel("b", SentinelKind::ErrorBound, 100_000, 200_000); // Red
        let state = aggregate_states(&[s1, s2]);
        assert_eq!(state, SentinelState::Red);
    }

    #[test]
    fn test_aggregate_unknown_without_red() {
        let s1 = make_sentinel("a", SentinelKind::ErrorBound, 500_000, 100_000); // Green
        let s2 = create_sentinel("b", SentinelKind::Coverage, 800_000); // Unknown (not updated)
        let state = aggregate_states(&[s1, s2]);
        assert_eq!(state, SentinelState::Unknown);
    }

    #[test]
    fn test_aggregate_red_overrides_unknown() {
        let s1 = create_sentinel("a", SentinelKind::Coverage, 800_000); // Unknown
        let s2 = make_sentinel("b", SentinelKind::ErrorBound, 100_000, 200_000); // Red
        let state = aggregate_states(&[s1, s2]);
        assert_eq!(state, SentinelState::Red);
    }

    // -- build_cell tests ---------------------------------------------------

    #[test]
    fn test_build_cell_computes_overall_state() {
        let cell = make_green_cell("c1", "latency", PromotionRule::FailClosed);
        assert_eq!(cell.overall_state, SentinelState::Green);
        assert_eq!(cell.cell_id, "c1");
        assert_eq!(cell.supremacy_domain, "latency");
    }

    #[test]
    fn test_build_cell_with_red_sentinel() {
        let cell = make_red_cell("c2", "throughput", PromotionRule::FailClosed);
        assert_eq!(cell.overall_state, SentinelState::Red);
    }

    #[test]
    fn test_build_cell_count_in_state() {
        let cell = make_green_cell("c3", "memory", PromotionRule::FailClosed);
        assert_eq!(cell.count_in_state(SentinelState::Green), 2);
        assert_eq!(cell.count_in_state(SentinelState::Red), 0);
    }

    #[test]
    fn test_build_cell_display() {
        let cell = make_green_cell("c4", "latency", PromotionRule::FailClosed);
        let display = format!("{cell}");
        assert!(display.contains("c4"));
        assert!(display.contains("latency"));
        assert!(display.contains("green"));
    }

    #[test]
    fn test_build_cell_hash_deterministic() {
        let cell1 = make_green_cell("c5", "latency", PromotionRule::FailClosed);
        let cell2 = make_green_cell("c5", "latency", PromotionRule::FailClosed);
        assert_eq!(cell1.compute_hash(), cell2.compute_hash());
    }

    // -- evaluate_promotion tests -------------------------------------------

    #[test]
    fn test_evaluate_fail_closed_green_allows() {
        let cell = make_green_cell("fc-green", "latency", PromotionRule::FailClosed);
        let decision = evaluate_promotion(&cell);
        assert!(decision.allowed);
        assert!(decision.suppression_reasons.is_empty());
        assert_eq!(decision.rule, PromotionRule::FailClosed);
    }

    #[test]
    fn test_evaluate_fail_closed_yellow_blocks() {
        let cell = make_yellow_cell("fc-yellow", "latency", PromotionRule::FailClosed);
        let decision = evaluate_promotion(&cell);
        assert!(!decision.allowed);
        assert!(!decision.suppression_reasons.is_empty());
    }

    #[test]
    fn test_evaluate_fail_closed_red_blocks() {
        let cell = make_red_cell("fc-red", "latency", PromotionRule::FailClosed);
        let decision = evaluate_promotion(&cell);
        assert!(!decision.allowed);
        assert!(!decision.suppression_reasons.is_empty());
    }

    #[test]
    fn test_evaluate_require_calibration_green_allows() {
        let cell = make_green_cell("rc-green", "latency", PromotionRule::RequireCalibration);
        let decision = evaluate_promotion(&cell);
        assert!(decision.allowed);
        assert!(decision.suppression_reasons.is_empty());
    }

    #[test]
    fn test_evaluate_require_calibration_yellow_allows_with_warnings() {
        let cell = make_yellow_cell("rc-yellow", "latency", PromotionRule::RequireCalibration);
        let decision = evaluate_promotion(&cell);
        assert!(decision.allowed);
        assert!(!decision.suppression_reasons.is_empty());
    }

    #[test]
    fn test_evaluate_require_calibration_red_blocks() {
        let cell = make_red_cell("rc-red", "latency", PromotionRule::RequireCalibration);
        let decision = evaluate_promotion(&cell);
        assert!(!decision.allowed);
    }

    #[test]
    fn test_evaluate_require_observability_green_allows() {
        let cell = make_green_cell("ro-green", "latency", PromotionRule::RequireObservability);
        let decision = evaluate_promotion(&cell);
        assert!(decision.allowed);
    }

    #[test]
    fn test_evaluate_require_observability_yellow_allows() {
        let cell = make_yellow_cell("ro-yellow", "latency", PromotionRule::RequireObservability);
        let decision = evaluate_promotion(&cell);
        assert!(decision.allowed);
    }

    #[test]
    fn test_evaluate_require_observability_red_blocks() {
        let cell = make_red_cell("ro-red", "latency", PromotionRule::RequireObservability);
        let decision = evaluate_promotion(&cell);
        assert!(!decision.allowed);
    }

    #[test]
    fn test_evaluate_suppress_claim_always_blocks() {
        let cell = make_green_cell("sc-green", "latency", PromotionRule::SuppressClaim);
        let decision = evaluate_promotion(&cell);
        assert!(!decision.allowed);
        assert!(!decision.suppression_reasons.is_empty());
    }

    #[test]
    fn test_evaluate_suppress_claim_blocks_even_green() {
        let cell = make_green_cell("sc-green2", "throughput", PromotionRule::SuppressClaim);
        let decision = evaluate_promotion(&cell);
        assert!(!decision.allowed);
        assert!(decision.suppression_reasons[0].contains("SuppressClaim"));
    }

    #[test]
    fn test_evaluate_allow_with_warning_green_allows() {
        let cell = make_green_cell("aw-green", "latency", PromotionRule::AllowWithWarning);
        let decision = evaluate_promotion(&cell);
        assert!(decision.allowed);
        assert!(decision.suppression_reasons.is_empty());
    }

    #[test]
    fn test_evaluate_allow_with_warning_red_allows_with_reasons() {
        let cell = make_red_cell("aw-red", "latency", PromotionRule::AllowWithWarning);
        let decision = evaluate_promotion(&cell);
        assert!(decision.allowed);
        assert!(!decision.suppression_reasons.is_empty());
    }

    #[test]
    fn test_evaluate_decision_has_cell_id() {
        let cell = make_green_cell("test-cell", "domain", PromotionRule::FailClosed);
        let decision = evaluate_promotion(&cell);
        assert_eq!(decision.cell_id, "test-cell");
    }

    #[test]
    fn test_evaluate_decision_hash_is_deterministic() {
        let cell = make_green_cell("det-cell", "domain", PromotionRule::FailClosed);
        let d1 = evaluate_promotion(&cell);
        let d2 = evaluate_promotion(&cell);
        assert_eq!(d1.content_hash, d2.content_hash);
        assert_eq!(d1.decision_id, d2.decision_id);
    }

    // -- build_report tests -------------------------------------------------

    #[test]
    fn test_build_report_counts_green_and_red() {
        let c1 = make_green_cell("r1", "latency", PromotionRule::FailClosed);
        let c2 = make_red_cell("r2", "throughput", PromotionRule::FailClosed);
        let c3 = make_green_cell("r3", "memory", PromotionRule::FailClosed);
        let report = build_report(SecurityEpoch::from_raw(1), vec![c1, c2, c3]);
        assert_eq!(report.green_count, 2);
        assert_eq!(report.red_count, 1);
        assert_eq!(report.cells.len(), 3);
        assert_eq!(report.decisions.len(), 3);
    }

    #[test]
    fn test_build_report_epoch() {
        let epoch = SecurityEpoch::from_raw(42);
        let c1 = make_green_cell("e1", "latency", PromotionRule::FailClosed);
        let report = build_report(epoch, vec![c1]);
        assert_eq!(report.epoch, epoch);
    }

    #[test]
    fn test_build_report_empty_cells() {
        let report = build_report(SecurityEpoch::from_raw(0), vec![]);
        assert_eq!(report.green_count, 0);
        assert_eq!(report.red_count, 0);
        assert!(report.decisions.is_empty());
        assert!(report.cells.is_empty());
    }

    #[test]
    fn test_build_report_hash_deterministic() {
        let c1 = make_green_cell("h1", "latency", PromotionRule::FailClosed);
        let c2 = make_green_cell("h1", "latency", PromotionRule::FailClosed);
        let r1 = build_report(SecurityEpoch::from_raw(1), vec![c1]);
        let r2 = build_report(SecurityEpoch::from_raw(1), vec![c2]);
        assert_eq!(r1.content_hash, r2.content_hash);
    }

    #[test]
    fn test_build_report_green_fraction() {
        let c1 = make_green_cell("f1", "a", PromotionRule::FailClosed);
        let c2 = make_red_cell("f2", "b", PromotionRule::FailClosed);
        let report = build_report(SecurityEpoch::from_raw(1), vec![c1, c2]);
        // 1 green out of 2 = 500_000 millionths
        assert_eq!(report.green_fraction_millionths(), 500_000);
    }

    #[test]
    fn test_build_report_allowed_fraction() {
        let c1 = make_green_cell("a1", "x", PromotionRule::FailClosed);
        let c2 = make_red_cell("a2", "y", PromotionRule::FailClosed);
        let c3 = make_green_cell("a3", "z", PromotionRule::FailClosed);
        let report = build_report(SecurityEpoch::from_raw(1), vec![c1, c2, c3]);
        // 2 allowed out of 3 = 666_666 millionths
        assert_eq!(report.allowed_fraction_millionths(), 666_666);
    }

    #[test]
    fn test_build_report_empty_green_fraction_is_zero() {
        let report = build_report(SecurityEpoch::from_raw(1), vec![]);
        assert_eq!(report.green_fraction_millionths(), 0);
    }

    #[test]
    fn test_build_report_display() {
        let c1 = make_green_cell("d1", "latency", PromotionRule::FailClosed);
        let report = build_report(SecurityEpoch::from_raw(5), vec![c1]);
        let display = format!("{report}");
        assert!(display.contains("epoch:5"));
        assert!(display.contains("green=1"));
        assert!(display.contains("red=0"));
    }

    // -- sentinel manifest tests --------------------------------------------

    #[test]
    fn test_manifest_returns_valid_report() {
        let report = franken_engine_sentinel_manifest();
        assert_eq!(report.epoch, SecurityEpoch::from_raw(1));
        assert_eq!(report.cells.len(), 5);
        assert_eq!(report.decisions.len(), 5);
    }

    #[test]
    fn test_manifest_has_all_promotion_rules() {
        let report = franken_engine_sentinel_manifest();
        let rules: Vec<PromotionRule> = report.decisions.iter().map(|d| d.rule).collect();
        assert!(rules.contains(&PromotionRule::FailClosed));
        assert!(rules.contains(&PromotionRule::RequireCalibration));
        assert!(rules.contains(&PromotionRule::SuppressClaim));
        assert!(rules.contains(&PromotionRule::AllowWithWarning));
        assert!(rules.contains(&PromotionRule::RequireObservability));
    }

    #[test]
    fn test_manifest_suppress_claim_blocks() {
        let report = franken_engine_sentinel_manifest();
        let suppress_decision = report
            .decisions
            .iter()
            .find(|d| d.rule == PromotionRule::SuppressClaim)
            .unwrap();
        assert!(!suppress_decision.allowed);
    }

    #[test]
    fn test_manifest_fail_closed_allows_green() {
        let report = franken_engine_sentinel_manifest();
        let fc_decision = report
            .decisions
            .iter()
            .find(|d| d.rule == PromotionRule::FailClosed)
            .unwrap();
        assert!(fc_decision.allowed);
    }

    #[test]
    fn test_manifest_allow_with_warning_allows() {
        let report = franken_engine_sentinel_manifest();
        let aw_decision = report
            .decisions
            .iter()
            .find(|d| d.rule == PromotionRule::AllowWithWarning)
            .unwrap();
        assert!(aw_decision.allowed);
        // The cell has a red sentinel, so there should be warnings.
        assert!(!aw_decision.suppression_reasons.is_empty());
    }

    #[test]
    fn test_manifest_is_deterministic() {
        let r1 = franken_engine_sentinel_manifest();
        let r2 = franken_engine_sentinel_manifest();
        assert_eq!(r1.content_hash, r2.content_hash);
        assert_eq!(r1.report_id, r2.report_id);
    }

    #[test]
    fn test_manifest_green_and_red_counts() {
        let report = franken_engine_sentinel_manifest();
        // Cell 1: green, Cell 2: yellow, Cell 3: red, Cell 4: red, Cell 5: green
        assert!(report.green_count >= 1);
        assert!(report.red_count >= 1);
    }

    // -- serde roundtrip tests ----------------------------------------------

    #[test]
    fn test_sentinel_kind_serde_roundtrip() {
        for kind in SentinelKind::all() {
            let json = serde_json::to_string(kind).unwrap();
            let back: SentinelKind = serde_json::from_str(&json).unwrap();
            assert_eq!(*kind, back);
        }
    }

    #[test]
    fn test_promotion_rule_serde_roundtrip() {
        let rules = [
            PromotionRule::FailClosed,
            PromotionRule::RequireCalibration,
            PromotionRule::RequireObservability,
            PromotionRule::SuppressClaim,
            PromotionRule::AllowWithWarning,
        ];
        for rule in &rules {
            let json = serde_json::to_string(rule).unwrap();
            let back: PromotionRule = serde_json::from_str(&json).unwrap();
            assert_eq!(*rule, back);
        }
    }

    #[test]
    fn test_sentinel_state_serde_roundtrip() {
        let states = [
            SentinelState::Green,
            SentinelState::Yellow,
            SentinelState::Red,
            SentinelState::Unknown,
        ];
        for state in &states {
            let json = serde_json::to_string(state).unwrap();
            let back: SentinelState = serde_json::from_str(&json).unwrap();
            assert_eq!(*state, back);
        }
    }

    #[test]
    fn test_calibration_sentinel_serde_roundtrip() {
        let s = make_sentinel("rt", SentinelKind::ErrorBound, 500_000, 100_000);
        let json = serde_json::to_string(&s).unwrap();
        let back: CalibrationSentinel = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }

    #[test]
    fn test_observability_cell_serde_roundtrip() {
        let cell = make_green_cell("serde-cell", "latency", PromotionRule::FailClosed);
        let json = serde_json::to_string(&cell).unwrap();
        let back: ObservabilityCell = serde_json::from_str(&json).unwrap();
        assert_eq!(cell, back);
    }

    #[test]
    fn test_promotion_decision_serde_roundtrip() {
        let cell = make_green_cell("sd-cell", "latency", PromotionRule::FailClosed);
        let decision = evaluate_promotion(&cell);
        let json = serde_json::to_string(&decision).unwrap();
        let back: PromotionDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(decision, back);
    }

    #[test]
    fn test_sentinel_report_serde_roundtrip() {
        let c1 = make_green_cell("sr1", "a", PromotionRule::FailClosed);
        let report = build_report(SecurityEpoch::from_raw(1), vec![c1]);
        let json = serde_json::to_string(&report).unwrap();
        let back: SentinelReport = serde_json::from_str(&json).unwrap();
        assert_eq!(report, back);
    }

    // -- Display and formatting tests ---------------------------------------

    #[test]
    fn test_calibration_sentinel_display() {
        let s = make_sentinel("ds", SentinelKind::Drift, 300_000, 50_000);
        let display = format!("{s}");
        assert!(display.contains("ds"));
        assert!(display.contains("drift"));
        assert!(display.contains("50000"));
        assert!(display.contains("300000"));
        assert!(display.contains("green"));
    }

    #[test]
    fn test_promotion_decision_display() {
        let cell = make_green_cell("pd-cell", "latency", PromotionRule::FailClosed);
        let decision = evaluate_promotion(&cell);
        let display = format!("{decision}");
        assert!(display.contains("pd-cell"));
        assert!(display.contains("ALLOWED"));
        assert!(display.contains("fail_closed"));
    }

    #[test]
    fn test_promotion_decision_display_blocked() {
        let cell = make_red_cell("pd-red", "latency", PromotionRule::FailClosed);
        let decision = evaluate_promotion(&cell);
        let display = format!("{decision}");
        assert!(display.contains("BLOCKED"));
    }

    // -- Content hash tests -------------------------------------------------

    #[test]
    fn test_sentinel_hash_changes_with_value() {
        let s1 = make_sentinel("h1", SentinelKind::ErrorBound, 500_000, 100_000);
        let s2 = make_sentinel("h1", SentinelKind::ErrorBound, 500_000, 200_000);
        assert_ne!(s1.content_hash, s2.content_hash);
    }

    #[test]
    fn test_sentinel_hash_changes_with_kind() {
        let s1 = make_sentinel("h2", SentinelKind::ErrorBound, 500_000, 100_000);
        let s2 = make_sentinel("h2", SentinelKind::Drift, 500_000, 100_000);
        assert_ne!(s1.content_hash, s2.content_hash);
    }

    #[test]
    fn test_cell_hash_changes_with_domain() {
        let s1 = make_sentinel("ch1", SentinelKind::ErrorBound, 500_000, 100_000);
        let s2 = make_sentinel("ch1", SentinelKind::ErrorBound, 500_000, 100_000);
        let c1 = build_cell("same", "domain_a", vec![s1], PromotionRule::FailClosed);
        let c2 = build_cell("same", "domain_b", vec![s2], PromotionRule::FailClosed);
        assert_ne!(c1.compute_hash(), c2.compute_hash());
    }

    // -- Helper function tests ----------------------------------------------

    #[test]
    fn test_hex_encode_prefix() {
        let bytes = [0xAB, 0xCD, 0xEF, 0x12];
        assert_eq!(hex_encode_prefix(&bytes, 4), "abcd");
        assert_eq!(hex_encode_prefix(&bytes, 6), "abcdef");
        assert_eq!(hex_encode_prefix(&bytes, 8), "abcdef12");
    }

    #[test]
    fn test_hex_encode() {
        let bytes = [0x00, 0xFF, 0x42];
        assert_eq!(hex_encode(&bytes), "00ff42");
    }

    #[test]
    fn test_sha256_bytes_deterministic() {
        let h1 = sha256_bytes(b"hello");
        let h2 = sha256_bytes(b"hello");
        assert_eq!(h1, h2);
        let h3 = sha256_bytes(b"world");
        assert_ne!(h1, h3);
    }

    // -- Edge case tests ----------------------------------------------------

    #[test]
    fn test_require_calibration_unknown_blocks() {
        // Unknown state should block under RequireCalibration.
        let s = create_sentinel("unk", SentinelKind::Coverage, 800_000);
        let cell = build_cell(
            "unk-cell",
            "test",
            vec![s],
            PromotionRule::RequireCalibration,
        );
        assert_eq!(cell.overall_state, SentinelState::Unknown);
        let decision = evaluate_promotion(&cell);
        assert!(!decision.allowed);
    }

    #[test]
    fn test_require_observability_unknown_blocks() {
        let s = create_sentinel("unk2", SentinelKind::ErrorBound, 500_000);
        let cell = build_cell(
            "unk2-cell",
            "test",
            vec![s],
            PromotionRule::RequireObservability,
        );
        let decision = evaluate_promotion(&cell);
        assert!(!decision.allowed);
    }

    #[test]
    fn test_allow_with_warning_unknown_allows() {
        let s = create_sentinel("unk3", SentinelKind::Freshness, MILLIONTHS);
        let cell = build_cell(
            "unk3-cell",
            "test",
            vec![s],
            PromotionRule::AllowWithWarning,
        );
        let decision = evaluate_promotion(&cell);
        assert!(decision.allowed);
    }

    #[test]
    fn test_large_threshold_no_overflow() {
        let threshold = u64::MAX / 2;
        let value = threshold - 1;
        let state = classify_state(value, threshold);
        // Should not panic from overflow.
        assert!(
            state == SentinelState::Green
                || state == SentinelState::Yellow
                || state == SentinelState::Red
        );
    }

    #[test]
    fn test_sentinel_with_max_threshold() {
        let mut s = create_sentinel("max", SentinelKind::ErrorBound, u64::MAX);
        let state = update_sentinel(&mut s, 0);
        assert_eq!(state, SentinelState::Green);
    }

    #[test]
    fn test_multiple_cells_mixed_states() {
        let c1 = make_green_cell("m1", "a", PromotionRule::FailClosed);
        let c2 = make_yellow_cell("m2", "b", PromotionRule::RequireCalibration);
        let c3 = make_red_cell("m3", "c", PromotionRule::AllowWithWarning);
        let report = build_report(SecurityEpoch::from_raw(10), vec![c1, c2, c3]);
        // c1: green+FailClosed => allowed
        // c2: yellow+RequireCalibration => allowed
        // c3: red+AllowWithWarning => allowed
        assert_eq!(report.decisions.iter().filter(|d| d.allowed).count(), 3);
    }

    #[test]
    fn test_constants_are_correct() {
        assert_eq!(MILLIONTHS, 1_000_000);
        assert_eq!(YELLOW_FRACTION_MILLIONTHS, 800_000);
        assert_eq!(COMPONENT, "calibration_sentinel");
        assert_eq!(CALIBRATION_SENTINEL_BEAD_ID, "bd-1lsy.11.20.3");
    }

    #[test]
    fn test_schema_version_format() {
        assert!(CALIBRATION_SENTINEL_SCHEMA_VERSION.starts_with("franken-engine."));
        assert!(CALIBRATION_SENTINEL_SCHEMA_VERSION.ends_with(".v1"));
    }
}
