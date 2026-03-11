#![forbid(unsafe_code)]

//! Statistical verdict engine for supremacy claims.
//!
//! Bead: bd-1lsy.8.5.2 [RGC-705B]
//!
//! Emits supremacy verdicts with sequential statistics and side-constraint
//! disqualifiers.  A claimed performance win only stands if it survives
//! sequential testing, meets effect-size floors, passes all side-constraint
//! checks, and was captured under an observability mode that the evidence
//! actually supports.
//!
//! # Design
//!
//! - `CellMeasurement` records a single performance observation for one
//!   supremacy cell (family × environment × entry-mode).
//! - `SequentialTestState` tracks the running Wald SPRT for a one-sided
//!   superiority hypothesis.
//! - `EffectSizeFloor` gates claims on a minimum practical improvement
//!   (Cohen's d in millionths).
//! - `SideConstraint` disqualifies a claim when an auxiliary metric breaches
//!   a bound (memory, tail, crash rate, etc.).
//! - `ObservabilityMode` records the telemetry/capture regime under which
//!   measurements were collected; claims are only valid under the declared mode.
//! - `SupremacyVerdict` is the final three-valued outcome: Confirmed, Rejected,
//!   or Inconclusive.
//! - `VerdictReport` bundles the per-cell verdicts, disqualifiers, and an
//!   auditable `DecisionReceipt`.
//!
//! All arithmetic uses fixed-point millionths (1_000_000 = 1.0).
//!
//! Reference: [RGC-705B]

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version.
pub const SCHEMA_VERSION: &str = "franken-engine.supremacy-verdict-engine.v1";

/// Component name.
pub const COMPONENT: &str = "supremacy_verdict_engine";

/// Bead reference.
pub const BEAD_ID: &str = "bd-1lsy.8.5.2";

/// Policy reference.
pub const POLICY_ID: &str = "RGC-705B";

/// One in fixed-point millionths.
const MILLIONTHS: u64 = 1_000_000;

/// Default minimum observations per cell before verdict.
pub const DEFAULT_MIN_OBSERVATIONS: u64 = 30;

/// Default alpha (Type-I error) in millionths.  0.05 = 50_000.
pub const DEFAULT_ALPHA: u64 = 50_000;

/// Default beta (Type-II error) in millionths.  0.20 = 200_000.
pub const DEFAULT_BETA: u64 = 200_000;

/// Default minimum effect-size (Cohen's d) in millionths.  0.20 = 200_000.
pub const DEFAULT_MIN_EFFECT_SIZE: u64 = 200_000;

/// Default maximum coefficient of variation (millionths).  0.15 = 150_000.
pub const DEFAULT_MAX_CV: u64 = 150_000;

/// Default maximum memory regression fraction (millionths).  0.05 = 50_000.
pub const DEFAULT_MAX_MEMORY_REGRESSION: u64 = 50_000;

/// Default maximum tail-latency regression fraction (millionths).  0.10 = 100_000.
pub const DEFAULT_MAX_TAIL_REGRESSION: u64 = 100_000;

/// Default maximum crash-rate (millionths).  0.001 = 1_000.
pub const DEFAULT_MAX_CRASH_RATE: u64 = 1_000;

/// Maximum number of side constraints per verdict config.
pub const MAX_SIDE_CONSTRAINTS: usize = 32;

/// Maximum number of cells per verdict run.
pub const MAX_CELLS: usize = 256;

// ---------------------------------------------------------------------------
// ObservabilityMode
// ---------------------------------------------------------------------------

/// Telemetry/capture regime under which evidence was collected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservabilityMode {
    /// Production-budgeted probabilistic telemetry.
    BudgetedCapture,
    /// Full exact counting — not production-safe but used for validation.
    ExactShadow,
    /// Degraded-mode capture with sampling.
    DegradedCapture,
    /// Incident / full-capture mode — temporarily unbounded.
    IncidentCapture,
}

impl ObservabilityMode {
    /// All variants in canonical order.
    pub const ALL: &[Self] = &[
        Self::BudgetedCapture,
        Self::ExactShadow,
        Self::DegradedCapture,
        Self::IncidentCapture,
    ];

    /// Stable string representation.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BudgetedCapture => "budgeted_capture",
            Self::ExactShadow => "exact_shadow",
            Self::DegradedCapture => "degraded_capture",
            Self::IncidentCapture => "incident_capture",
        }
    }

    /// Whether this mode provides statistically rigorous measurements.
    pub const fn is_rigorous(self) -> bool {
        matches!(self, Self::BudgetedCapture | Self::ExactShadow)
    }
}

impl fmt::Display for ObservabilityMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// SideConstraintKind
// ---------------------------------------------------------------------------

/// Kind of auxiliary side constraint that can disqualify a supremacy claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SideConstraintKind {
    /// Resident-memory regression.
    MemoryRegression,
    /// Tail-latency (p99) regression.
    TailLatencyRegression,
    /// Crash / panic rate.
    CrashRate,
    /// Coefficient of variation too high (noisy measurements).
    ExcessiveVariance,
    /// Missing coverage — too few workload families observed.
    InsufficientCoverage,
    /// Environment drift — hardware or config changed between runs.
    EnvironmentDrift,
    /// Observability mode mismatch — claim captured under wrong mode.
    ObservabilityMismatch,
    /// Cold-start regression while warm throughput improved.
    ColdStartRegression,
}

impl SideConstraintKind {
    /// All variants in canonical order.
    pub const ALL: &[Self] = &[
        Self::MemoryRegression,
        Self::TailLatencyRegression,
        Self::CrashRate,
        Self::ExcessiveVariance,
        Self::InsufficientCoverage,
        Self::EnvironmentDrift,
        Self::ObservabilityMismatch,
        Self::ColdStartRegression,
    ];

    /// Stable string representation.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MemoryRegression => "memory_regression",
            Self::TailLatencyRegression => "tail_latency_regression",
            Self::CrashRate => "crash_rate",
            Self::ExcessiveVariance => "excessive_variance",
            Self::InsufficientCoverage => "insufficient_coverage",
            Self::EnvironmentDrift => "environment_drift",
            Self::ObservabilityMismatch => "observability_mismatch",
            Self::ColdStartRegression => "cold_start_regression",
        }
    }
}

impl fmt::Display for SideConstraintKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// SupremacyVerdict
// ---------------------------------------------------------------------------

/// Final three-valued verdict for a supremacy claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SupremacyVerdict {
    /// Claim confirmed: statistically significant with sufficient effect size
    /// and no side-constraint violations.
    Confirmed,
    /// Claim rejected: either not significant, below effect-size floor, or
    /// disqualified by side constraints.
    Rejected,
    /// Inconclusive: insufficient observations to decide.
    Inconclusive,
}

impl SupremacyVerdict {
    /// All variants in canonical order.
    pub const ALL: &[Self] = &[Self::Confirmed, Self::Rejected, Self::Inconclusive];

    /// Stable string representation.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Confirmed => "confirmed",
            Self::Rejected => "rejected",
            Self::Inconclusive => "inconclusive",
        }
    }

    /// Whether the verdict allows the claim to stand.
    pub const fn is_positive(self) -> bool {
        matches!(self, Self::Confirmed)
    }
}

impl fmt::Display for SupremacyVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// RejectionReason
// ---------------------------------------------------------------------------

/// Reason a supremacy claim was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RejectionReason {
    /// Sequential test rejected the superiority hypothesis.
    StatisticallyInsignificant,
    /// Effect size below the configured floor.
    BelowEffectSizeFloor,
    /// Side constraint breached.
    SideConstraintViolation,
    /// Observability mode not rigorous enough for the claim.
    ObservabilityInsufficient,
    /// Too few observations to reach a conclusion (but trend is negative).
    InsufficientDataNegativeTrend,
    /// Multiple cells failed — aggregate board failure.
    BoardLevelFailure,
}

impl RejectionReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::StatisticallyInsignificant => "statistically_insignificant",
            Self::BelowEffectSizeFloor => "below_effect_size_floor",
            Self::SideConstraintViolation => "side_constraint_violation",
            Self::ObservabilityInsufficient => "observability_insufficient",
            Self::InsufficientDataNegativeTrend => "insufficient_data_negative_trend",
            Self::BoardLevelFailure => "board_level_failure",
        }
    }
}

impl fmt::Display for RejectionReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// CellMeasurement
// ---------------------------------------------------------------------------

/// A single performance observation for one supremacy cell.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CellMeasurement {
    /// Cell identifier (family × environment × entry-mode composite key).
    pub cell_id: String,
    /// Observed value for the treatment (FrankenEngine) in nanoseconds.
    pub treatment_ns: u64,
    /// Observed value for the baseline (V8/Node/Bun) in nanoseconds.
    pub baseline_ns: u64,
    /// Observability mode under which the measurement was captured.
    pub observability_mode: ObservabilityMode,
    /// Epoch at which the measurement was taken.
    pub epoch: u64,
    /// Memory usage delta in bytes (treatment − baseline). Negative = regression.
    pub memory_delta_bytes: i64,
    /// Tail-latency (p99) in nanoseconds for the treatment.
    pub tail_p99_ns: u64,
    /// Tail-latency (p99) in nanoseconds for the baseline.
    pub baseline_tail_p99_ns: u64,
    /// Whether a crash or panic occurred during this observation.
    pub crash_observed: bool,
}

// ---------------------------------------------------------------------------
// SequentialTestState
// ---------------------------------------------------------------------------

/// Running state for a Wald Sequential Probability Ratio Test (SPRT).
///
/// The SPRT lets us reach a verdict as soon as the evidence is strong enough,
/// rather than waiting for a fixed sample size.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SequentialTestState {
    /// Cumulative log-likelihood ratio (millionths of ln-scale).
    pub cumulative_llr: i64,
    /// Upper boundary — accept H1 (superiority) when LLR exceeds this.
    pub upper_boundary: i64,
    /// Lower boundary — accept H0 (no superiority) when LLR is below this.
    pub lower_boundary: i64,
    /// Number of observations ingested.
    pub n_observations: u64,
    /// Running sum of treatment values.
    pub sum_treatment: u64,
    /// Running sum of baseline values.
    pub sum_baseline: u64,
    /// Running sum of squared treatment values (for variance).
    pub sum_sq_treatment: u128,
    /// Running sum of squared baseline values (for variance).
    pub sum_sq_baseline: u128,
}

impl SequentialTestState {
    /// Create a new SPRT state from alpha and beta error bounds.
    pub fn new(alpha_millionths: u64, beta_millionths: u64) -> Self {
        // Upper boundary ≈ ln((1-β)/α) in millionths
        // Lower boundary ≈ ln(β/(1-α)) in millionths
        // We use simplified integer approximations:
        //   ln((1-β)/α) ≈ (MILLIONTHS - β) * MILLIONTHS / α  (scaled)
        //   but keep it in a practical integer range.
        let upper = if alpha_millionths > 0 {
            let numerator = MILLIONTHS.saturating_sub(beta_millionths);
            // ln(x) ≈ (x-1) for small values; use ratio as proxy
            (numerator as i64) * (MILLIONTHS as i64) / (alpha_millionths as i64)
        } else {
            i64::MAX
        };
        let lower = if (MILLIONTHS - alpha_millionths) > 0 {
            let numerator = beta_millionths;
            -((numerator as i64) * (MILLIONTHS as i64) / ((MILLIONTHS - alpha_millionths) as i64))
        } else {
            i64::MIN
        };

        Self {
            cumulative_llr: 0,
            upper_boundary: upper,
            lower_boundary: lower,
            n_observations: 0,
            sum_treatment: 0,
            sum_baseline: 0,
            sum_sq_treatment: 0,
            sum_sq_baseline: 0,
        }
    }

    /// Ingest a new observation and update the running LLR.
    pub fn update(&mut self, treatment_ns: u64, baseline_ns: u64) {
        self.n_observations += 1;
        self.sum_treatment += treatment_ns;
        self.sum_baseline += baseline_ns;
        self.sum_sq_treatment += (treatment_ns as u128) * (treatment_ns as u128);
        self.sum_sq_baseline += (baseline_ns as u128) * (baseline_ns as u128);

        // Increment to LLR: if treatment < baseline, that's evidence of superiority.
        // Use the ratio (baseline - treatment) / max(baseline, 1) as a proxy.
        if baseline_ns > 0 {
            let diff = baseline_ns as i64 - treatment_ns as i64;
            let increment = diff * (MILLIONTHS as i64) / (baseline_ns as i64);
            self.cumulative_llr += increment;
        }
    }

    /// Whether the test has reached a conclusion.
    pub fn is_decided(&self) -> bool {
        self.cumulative_llr >= self.upper_boundary || self.cumulative_llr <= self.lower_boundary
    }

    /// Whether the superiority hypothesis is accepted.
    pub fn accepts_superiority(&self) -> bool {
        self.cumulative_llr >= self.upper_boundary
    }

    /// Whether the null (no superiority) is accepted.
    pub fn accepts_null(&self) -> bool {
        self.cumulative_llr <= self.lower_boundary
    }

    /// Mean treatment value (millionths).
    pub fn mean_treatment_millionths(&self) -> u64 {
        if self.n_observations == 0 {
            return 0;
        }
        self.sum_treatment * MILLIONTHS / self.n_observations
    }

    /// Mean baseline value (millionths).
    pub fn mean_baseline_millionths(&self) -> u64 {
        if self.n_observations == 0 {
            return 0;
        }
        self.sum_baseline * MILLIONTHS / self.n_observations
    }

    /// Estimated effect size (Cohen's d) in millionths.
    ///
    /// d = (mean_baseline - mean_treatment) / pooled_std_dev
    pub fn effect_size_millionths(&self) -> u64 {
        if self.n_observations < 2 {
            return 0;
        }
        let n = self.n_observations as u128;
        let mean_t = self.sum_treatment as u128 / n;
        let mean_b = self.sum_baseline as u128 / n;

        // Variance = E[X²] - (E[X])²
        let var_t = self.sum_sq_treatment / n - mean_t * mean_t;
        let var_b = self.sum_sq_baseline / n - mean_b * mean_b;
        let pooled_var = (var_t + var_b) / 2;

        if pooled_var == 0 {
            return if mean_b > mean_t { MILLIONTHS } else { 0 };
        }

        let pooled_sd = isqrt(pooled_var);
        if pooled_sd == 0 {
            return if mean_b > mean_t { MILLIONTHS } else { 0 };
        }

        let diff = if mean_b >= mean_t {
            mean_b - mean_t
        } else {
            return 0; // Treatment is worse — no positive effect
        };

        let d = diff * (MILLIONTHS as u128) / pooled_sd;
        // Cap at a reasonable maximum
        if d > (10 * MILLIONTHS as u128) {
            10 * MILLIONTHS
        } else {
            d as u64
        }
    }

    /// Coefficient of variation for treatment (millionths).
    pub fn cv_treatment_millionths(&self) -> u64 {
        if self.n_observations < 2 {
            return 0;
        }
        let n = self.n_observations as u128;
        let mean = self.sum_treatment as u128 / n;
        if mean == 0 {
            return 0;
        }
        let var = self.sum_sq_treatment / n - mean * mean;
        let sd = isqrt(var);
        (sd * (MILLIONTHS as u128) / mean) as u64
    }
}

// ---------------------------------------------------------------------------
// SideConstraint
// ---------------------------------------------------------------------------

/// A side-constraint violation that disqualifies a supremacy claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SideConstraintViolation {
    /// Which constraint was breached.
    pub kind: SideConstraintKind,
    /// Cell that triggered the violation (if cell-specific).
    pub cell_id: String,
    /// Observed value (millionths).
    pub observed: u64,
    /// Threshold that was breached (millionths).
    pub threshold: u64,
    /// Human-readable detail.
    pub detail: String,
}

// ---------------------------------------------------------------------------
// VerdictConfig
// ---------------------------------------------------------------------------

/// Configuration for the supremacy verdict engine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerdictConfig {
    /// Minimum observations per cell before rendering a verdict.
    pub min_observations: u64,
    /// Alpha (Type-I error) in millionths.
    pub alpha: u64,
    /// Beta (Type-II error) in millionths.
    pub beta: u64,
    /// Minimum effect-size (Cohen's d) in millionths.
    pub min_effect_size: u64,
    /// Maximum coefficient of variation in millionths.
    pub max_cv: u64,
    /// Maximum memory regression fraction (millionths).
    pub max_memory_regression: u64,
    /// Maximum tail-latency regression fraction (millionths).
    pub max_tail_regression: u64,
    /// Maximum crash rate (millionths).
    pub max_crash_rate: u64,
    /// Required observability modes for valid evidence.
    pub required_observability_modes: Vec<ObservabilityMode>,
    /// Minimum fraction of cells that must be Confirmed for board-level pass (millionths).
    pub board_pass_threshold: u64,
}

impl Default for VerdictConfig {
    fn default() -> Self {
        Self {
            min_observations: DEFAULT_MIN_OBSERVATIONS,
            alpha: DEFAULT_ALPHA,
            beta: DEFAULT_BETA,
            min_effect_size: DEFAULT_MIN_EFFECT_SIZE,
            max_cv: DEFAULT_MAX_CV,
            max_memory_regression: DEFAULT_MAX_MEMORY_REGRESSION,
            max_tail_regression: DEFAULT_MAX_TAIL_REGRESSION,
            max_crash_rate: DEFAULT_MAX_CRASH_RATE,
            required_observability_modes: vec![
                ObservabilityMode::BudgetedCapture,
                ObservabilityMode::ExactShadow,
            ],
            board_pass_threshold: 800_000, // 80%
        }
    }
}

// ---------------------------------------------------------------------------
// CellVerdict
// ---------------------------------------------------------------------------

/// Per-cell verdict with supporting statistics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CellVerdict {
    /// Cell identifier.
    pub cell_id: String,
    /// Final verdict for this cell.
    pub verdict: SupremacyVerdict,
    /// Rejection reasons (empty if Confirmed or Inconclusive).
    pub rejection_reasons: Vec<RejectionReason>,
    /// Number of observations.
    pub n_observations: u64,
    /// Effect size in millionths.
    pub effect_size: u64,
    /// CV of treatment in millionths.
    pub cv_treatment: u64,
    /// Side-constraint violations.
    pub violations: Vec<SideConstraintViolation>,
    /// Sequential test LLR at verdict time.
    pub final_llr: i64,
    /// Mean improvement ratio (treatment vs baseline) in millionths.
    pub mean_improvement_ratio: u64,
}

// ---------------------------------------------------------------------------
// VerdictReport
// ---------------------------------------------------------------------------

/// Full verdict report for a supremacy claim across all cells.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerdictReport {
    /// Per-cell verdicts.
    pub cell_verdicts: Vec<CellVerdict>,
    /// Board-level verdict.
    pub board_verdict: SupremacyVerdict,
    /// Board-level rejection reasons (if rejected).
    pub board_rejection_reasons: Vec<RejectionReason>,
    /// Fraction of cells confirmed (millionths).
    pub confirmed_fraction: u64,
    /// Total side-constraint violations across all cells.
    pub total_violations: usize,
    /// Decision receipt.
    pub receipt: DecisionReceipt,
}

// ---------------------------------------------------------------------------
// DecisionReceipt
// ---------------------------------------------------------------------------

/// Auditable receipt for a supremacy verdict decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionReceipt {
    /// Schema version.
    pub schema_version: String,
    /// Component.
    pub component: String,
    /// Bead reference.
    pub bead_id: String,
    /// Policy reference.
    pub policy_id: String,
    /// Security epoch.
    pub epoch: u64,
    /// Hash of all inputs (measurements + config).
    pub input_hash: ContentHash,
    /// Hash of the rendered verdict.
    pub verdict_hash: ContentHash,
    /// Timestamp in microseconds.
    pub timestamp_micros: u64,
}

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

/// Errors from the supremacy verdict engine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerdictError {
    /// No measurements provided.
    NoMeasurements,
    /// Too many cells (exceeds MAX_CELLS).
    TooManyCells { count: usize },
    /// Too many side constraints (exceeds MAX_SIDE_CONSTRAINTS).
    TooManySideConstraints { count: usize },
    /// Invalid config value.
    InvalidConfig { field: String, detail: String },
    /// Cell referenced in measurements not found in matrix.
    UnknownCell { cell_id: String },
}

impl fmt::Display for VerdictError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoMeasurements => write!(f, "no measurements provided"),
            Self::TooManyCells { count } => {
                write!(f, "too many cells: {count} exceeds limit {MAX_CELLS}")
            }
            Self::TooManySideConstraints { count } => {
                write!(
                    f,
                    "too many side constraints: {count} exceeds limit {MAX_SIDE_CONSTRAINTS}"
                )
            }
            Self::InvalidConfig { field, detail } => {
                write!(f, "invalid config field `{field}`: {detail}")
            }
            Self::UnknownCell { cell_id } => {
                write!(f, "unknown cell: {cell_id}")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Core logic
// ---------------------------------------------------------------------------

/// Validate verdict configuration.
pub fn validate_config(config: &VerdictConfig) -> Result<(), VerdictError> {
    if config.alpha == 0 || config.alpha >= MILLIONTHS {
        return Err(VerdictError::InvalidConfig {
            field: "alpha".into(),
            detail: "must be in (0, 1_000_000)".into(),
        });
    }
    if config.beta == 0 || config.beta >= MILLIONTHS {
        return Err(VerdictError::InvalidConfig {
            field: "beta".into(),
            detail: "must be in (0, 1_000_000)".into(),
        });
    }
    if config.min_observations == 0 {
        return Err(VerdictError::InvalidConfig {
            field: "min_observations".into(),
            detail: "must be > 0".into(),
        });
    }
    if config.board_pass_threshold == 0 || config.board_pass_threshold > MILLIONTHS {
        return Err(VerdictError::InvalidConfig {
            field: "board_pass_threshold".into(),
            detail: "must be in (0, 1_000_000]".into(),
        });
    }
    Ok(())
}

/// Run the supremacy verdict engine over a batch of measurements.
///
/// Groups measurements by cell ID, runs a sequential test per cell, checks
/// side constraints, and aggregates into a board-level verdict.
pub fn evaluate_supremacy(
    measurements: &[CellMeasurement],
    config: &VerdictConfig,
    epoch: &SecurityEpoch,
    timestamp_micros: u64,
) -> Result<VerdictReport, VerdictError> {
    validate_config(config)?;

    if measurements.is_empty() {
        return Err(VerdictError::NoMeasurements);
    }

    // Group measurements by cell_id.
    let mut cells: BTreeMap<&str, Vec<&CellMeasurement>> = BTreeMap::new();
    for m in measurements {
        cells.entry(m.cell_id.as_str()).or_default().push(m);
    }

    if cells.len() > MAX_CELLS {
        return Err(VerdictError::TooManyCells { count: cells.len() });
    }

    let mut cell_verdicts = Vec::new();

    for (cell_id, obs) in &cells {
        let cv = evaluate_cell(cell_id, obs, config);
        cell_verdicts.push(cv);
    }

    // Board-level aggregation.
    let confirmed_count = cell_verdicts
        .iter()
        .filter(|cv| cv.verdict == SupremacyVerdict::Confirmed)
        .count() as u64;
    let total_cells = cell_verdicts.len() as u64;
    let confirmed_fraction = (confirmed_count * MILLIONTHS)
        .checked_div(total_cells)
        .unwrap_or(0);

    let total_violations: usize = cell_verdicts.iter().map(|cv| cv.violations.len()).sum();

    let mut board_rejection_reasons = Vec::new();

    let board_verdict = if confirmed_fraction >= config.board_pass_threshold {
        SupremacyVerdict::Confirmed
    } else if cell_verdicts
        .iter()
        .all(|cv| cv.verdict == SupremacyVerdict::Inconclusive)
    {
        SupremacyVerdict::Inconclusive
    } else {
        // Check specific board-level failure reasons
        if total_violations > 0 {
            board_rejection_reasons.push(RejectionReason::SideConstraintViolation);
        }
        let rejected_count = cell_verdicts
            .iter()
            .filter(|cv| cv.verdict == SupremacyVerdict::Rejected)
            .count();
        if rejected_count > 0 {
            board_rejection_reasons.push(RejectionReason::BoardLevelFailure);
        }
        SupremacyVerdict::Rejected
    };

    // Build receipt.
    let input_hash = compute_input_hash(measurements, config);
    let verdict_hash = compute_verdict_hash(&cell_verdicts, board_verdict);

    let receipt = DecisionReceipt {
        schema_version: SCHEMA_VERSION.into(),
        component: COMPONENT.into(),
        bead_id: BEAD_ID.into(),
        policy_id: POLICY_ID.into(),
        epoch: epoch.as_u64(),
        input_hash,
        verdict_hash,
        timestamp_micros,
    };

    Ok(VerdictReport {
        cell_verdicts,
        board_verdict,
        board_rejection_reasons,
        confirmed_fraction,
        total_violations,
        receipt,
    })
}

/// Evaluate a single cell.
fn evaluate_cell(
    cell_id: &str,
    observations: &[&CellMeasurement],
    config: &VerdictConfig,
) -> CellVerdict {
    let n = observations.len() as u64;
    let mut sprt = SequentialTestState::new(config.alpha, config.beta);
    let mut violations = Vec::new();
    let mut crash_count = 0u64;
    let mut memory_regressions = 0u64;
    let mut tail_regressions = 0u64;
    let mut has_invalid_observability = false;

    for obs in observations {
        sprt.update(obs.treatment_ns, obs.baseline_ns);

        if obs.crash_observed {
            crash_count += 1;
        }

        // Memory regression check
        if obs.memory_delta_bytes > 0 && obs.baseline_ns > 0 {
            let regression_frac =
                (obs.memory_delta_bytes as u64) * MILLIONTHS / obs.baseline_ns.max(1);
            if regression_frac > config.max_memory_regression {
                memory_regressions += 1;
            }
        }

        // Tail-latency regression check
        if obs.tail_p99_ns > obs.baseline_tail_p99_ns && obs.baseline_tail_p99_ns > 0 {
            let regression_frac = (obs.tail_p99_ns - obs.baseline_tail_p99_ns) * MILLIONTHS
                / obs.baseline_tail_p99_ns;
            if regression_frac > config.max_tail_regression {
                tail_regressions += 1;
            }
        }

        // Observability mode check
        if !config.required_observability_modes.is_empty()
            && !config
                .required_observability_modes
                .contains(&obs.observability_mode)
        {
            has_invalid_observability = true;
        }
    }

    // Build side-constraint violations
    let crash_rate = (crash_count * MILLIONTHS).checked_div(n).unwrap_or(0);
    if crash_rate > config.max_crash_rate {
        violations.push(SideConstraintViolation {
            kind: SideConstraintKind::CrashRate,
            cell_id: cell_id.into(),
            observed: crash_rate,
            threshold: config.max_crash_rate,
            detail: format!(
                "crash rate {crash_rate} exceeds threshold {}",
                config.max_crash_rate
            ),
        });
    }

    if memory_regressions > 0 {
        let frac = memory_regressions * MILLIONTHS / n.max(1);
        if frac > config.max_memory_regression {
            violations.push(SideConstraintViolation {
                kind: SideConstraintKind::MemoryRegression,
                cell_id: cell_id.into(),
                observed: frac,
                threshold: config.max_memory_regression,
                detail: format!("{memory_regressions}/{n} observations show memory regression"),
            });
        }
    }

    if tail_regressions > 0 {
        let frac = tail_regressions * MILLIONTHS / n.max(1);
        if frac > config.max_tail_regression {
            violations.push(SideConstraintViolation {
                kind: SideConstraintKind::TailLatencyRegression,
                cell_id: cell_id.into(),
                observed: frac,
                threshold: config.max_tail_regression,
                detail: format!("{tail_regressions}/{n} observations show tail-latency regression"),
            });
        }
    }

    let cv = sprt.cv_treatment_millionths();
    if cv > config.max_cv {
        violations.push(SideConstraintViolation {
            kind: SideConstraintKind::ExcessiveVariance,
            cell_id: cell_id.into(),
            observed: cv,
            threshold: config.max_cv,
            detail: format!("CV {cv} exceeds threshold {}", config.max_cv),
        });
    }

    if has_invalid_observability {
        violations.push(SideConstraintViolation {
            kind: SideConstraintKind::ObservabilityMismatch,
            cell_id: cell_id.into(),
            observed: 0,
            threshold: 0,
            detail: "observations captured under non-rigorous observability mode".into(),
        });
    }

    let effect_size = sprt.effect_size_millionths();
    let mean_improvement_ratio = if sprt.mean_baseline_millionths() > 0 {
        let mean_t = sprt.mean_treatment_millionths();
        let mean_b = sprt.mean_baseline_millionths();
        if mean_b > mean_t {
            (mean_b - mean_t) * MILLIONTHS / mean_b
        } else {
            0
        }
    } else {
        0
    };

    // Render verdict
    let mut rejection_reasons = Vec::new();

    if n < config.min_observations {
        return CellVerdict {
            cell_id: cell_id.into(),
            verdict: SupremacyVerdict::Inconclusive,
            rejection_reasons: Vec::new(),
            n_observations: n,
            effect_size,
            cv_treatment: cv,
            violations,
            final_llr: sprt.cumulative_llr,
            mean_improvement_ratio,
        };
    }

    // Check side constraints first — any violation disqualifies
    if !violations.is_empty() {
        rejection_reasons.push(RejectionReason::SideConstraintViolation);
    }

    if has_invalid_observability {
        rejection_reasons.push(RejectionReason::ObservabilityInsufficient);
    }

    if effect_size < config.min_effect_size {
        rejection_reasons.push(RejectionReason::BelowEffectSizeFloor);
    }

    if sprt.accepts_null() {
        rejection_reasons.push(RejectionReason::StatisticallyInsignificant);
    }

    let verdict = if !rejection_reasons.is_empty() {
        SupremacyVerdict::Rejected
    } else if sprt.accepts_superiority() && effect_size >= config.min_effect_size {
        SupremacyVerdict::Confirmed
    } else {
        SupremacyVerdict::Inconclusive
    };

    CellVerdict {
        cell_id: cell_id.into(),
        verdict,
        rejection_reasons,
        n_observations: n,
        effect_size,
        cv_treatment: cv,
        violations,
        final_llr: sprt.cumulative_llr,
        mean_improvement_ratio,
    }
}

/// Compute a content hash of all input measurements and config.
fn compute_input_hash(measurements: &[CellMeasurement], config: &VerdictConfig) -> ContentHash {
    let mut hasher = Sha256::new();
    hasher.update(SCHEMA_VERSION.as_bytes());
    for m in measurements {
        hasher.update(m.cell_id.as_bytes());
        hasher.update(m.treatment_ns.to_le_bytes());
        hasher.update(m.baseline_ns.to_le_bytes());
        hasher.update(m.epoch.to_le_bytes());
    }
    hasher.update(config.min_observations.to_le_bytes());
    hasher.update(config.alpha.to_le_bytes());
    hasher.update(config.beta.to_le_bytes());
    hasher.update(config.min_effect_size.to_le_bytes());
    ContentHash::compute(&hasher.finalize())
}

/// Compute a content hash of all verdicts.
fn compute_verdict_hash(
    cell_verdicts: &[CellVerdict],
    board_verdict: SupremacyVerdict,
) -> ContentHash {
    let mut hasher = Sha256::new();
    hasher.update(SCHEMA_VERSION.as_bytes());
    hasher.update(board_verdict.as_str().as_bytes());
    for cv in cell_verdicts {
        hasher.update(cv.cell_id.as_bytes());
        hasher.update(cv.verdict.as_str().as_bytes());
        hasher.update(cv.n_observations.to_le_bytes());
        hasher.update(cv.effect_size.to_le_bytes());
    }
    ContentHash::compute(&hasher.finalize())
}

/// Integer square root for `u128`.
fn isqrt(n: u128) -> u128 {
    if n == 0 {
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

/// Generate a human-readable summary of a verdict report.
pub fn summarize_report(report: &VerdictReport) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "Board verdict: {} ({}/{} cells confirmed, {:.1}%)\n",
        report.board_verdict,
        report
            .cell_verdicts
            .iter()
            .filter(|cv| cv.verdict == SupremacyVerdict::Confirmed)
            .count(),
        report.cell_verdicts.len(),
        report.confirmed_fraction as f64 / (MILLIONTHS as f64) * 100.0,
    ));
    if !report.board_rejection_reasons.is_empty() {
        out.push_str("Board rejections:");
        for r in &report.board_rejection_reasons {
            out.push_str(&format!(" {r}"));
        }
        out.push('\n');
    }
    if report.total_violations > 0 {
        out.push_str(&format!(
            "Total side-constraint violations: {}\n",
            report.total_violations
        ));
    }
    for cv in &report.cell_verdicts {
        out.push_str(&format!(
            "  Cell {}: {} (n={}, d={}, cv={}, llr={})\n",
            cv.cell_id,
            cv.verdict,
            cv.n_observations,
            cv.effect_size,
            cv.cv_treatment,
            cv.final_llr,
        ));
    }
    out
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_measurement(cell_id: &str, treatment_ns: u64, baseline_ns: u64) -> CellMeasurement {
        CellMeasurement {
            cell_id: cell_id.into(),
            treatment_ns,
            baseline_ns,
            observability_mode: ObservabilityMode::BudgetedCapture,
            epoch: 1,
            memory_delta_bytes: 0,
            tail_p99_ns: treatment_ns + 100,
            baseline_tail_p99_ns: baseline_ns + 100,
            crash_observed: false,
        }
    }

    fn make_config() -> VerdictConfig {
        VerdictConfig::default()
    }

    fn epoch() -> SecurityEpoch {
        SecurityEpoch::from_raw(42)
    }

    #[test]
    fn test_observability_mode_variants() {
        assert_eq!(ObservabilityMode::ALL.len(), 4);
        assert_eq!(
            ObservabilityMode::BudgetedCapture.as_str(),
            "budgeted_capture"
        );
        assert_eq!(ObservabilityMode::ExactShadow.as_str(), "exact_shadow");
        assert_eq!(
            ObservabilityMode::DegradedCapture.as_str(),
            "degraded_capture"
        );
        assert_eq!(
            ObservabilityMode::IncidentCapture.as_str(),
            "incident_capture"
        );
    }

    #[test]
    fn test_observability_mode_is_rigorous() {
        assert!(ObservabilityMode::BudgetedCapture.is_rigorous());
        assert!(ObservabilityMode::ExactShadow.is_rigorous());
        assert!(!ObservabilityMode::DegradedCapture.is_rigorous());
        assert!(!ObservabilityMode::IncidentCapture.is_rigorous());
    }

    #[test]
    fn test_observability_mode_display() {
        let mode = ObservabilityMode::ExactShadow;
        assert_eq!(format!("{mode}"), "exact_shadow");
    }

    #[test]
    fn test_side_constraint_kind_variants() {
        assert_eq!(SideConstraintKind::ALL.len(), 8);
        assert_eq!(
            SideConstraintKind::MemoryRegression.as_str(),
            "memory_regression"
        );
        assert_eq!(SideConstraintKind::CrashRate.as_str(), "crash_rate");
        assert_eq!(
            SideConstraintKind::ObservabilityMismatch.as_str(),
            "observability_mismatch"
        );
    }

    #[test]
    fn test_side_constraint_kind_display() {
        let kind = SideConstraintKind::TailLatencyRegression;
        assert_eq!(format!("{kind}"), "tail_latency_regression");
    }

    #[test]
    fn test_supremacy_verdict_variants() {
        assert_eq!(SupremacyVerdict::ALL.len(), 3);
        assert!(SupremacyVerdict::Confirmed.is_positive());
        assert!(!SupremacyVerdict::Rejected.is_positive());
        assert!(!SupremacyVerdict::Inconclusive.is_positive());
    }

    #[test]
    fn test_supremacy_verdict_display() {
        assert_eq!(format!("{}", SupremacyVerdict::Confirmed), "confirmed");
        assert_eq!(format!("{}", SupremacyVerdict::Rejected), "rejected");
        assert_eq!(
            format!("{}", SupremacyVerdict::Inconclusive),
            "inconclusive"
        );
    }

    #[test]
    fn test_rejection_reason_display() {
        assert_eq!(
            format!("{}", RejectionReason::StatisticallyInsignificant),
            "statistically_insignificant"
        );
        assert_eq!(
            format!("{}", RejectionReason::BoardLevelFailure),
            "board_level_failure"
        );
    }

    #[test]
    fn test_sequential_test_new() {
        let state = SequentialTestState::new(DEFAULT_ALPHA, DEFAULT_BETA);
        assert_eq!(state.n_observations, 0);
        assert_eq!(state.cumulative_llr, 0);
        assert!(state.upper_boundary > 0);
        assert!(state.lower_boundary < 0);
    }

    #[test]
    fn test_sequential_test_update_superiority() {
        let mut state = SequentialTestState::new(DEFAULT_ALPHA, DEFAULT_BETA);
        // Treatment consistently faster than baseline
        for _ in 0..50 {
            state.update(500, 1000);
        }
        assert_eq!(state.n_observations, 50);
        assert!(
            state.cumulative_llr > 0,
            "LLR should be positive for superiority"
        );
    }

    #[test]
    fn test_sequential_test_update_null() {
        let mut state = SequentialTestState::new(DEFAULT_ALPHA, DEFAULT_BETA);
        // Treatment consistently slower
        for _ in 0..50 {
            state.update(1000, 500);
        }
        assert!(state.cumulative_llr < 0, "LLR should be negative for null");
    }

    #[test]
    fn test_sequential_test_mean_treatment() {
        let mut state = SequentialTestState::new(DEFAULT_ALPHA, DEFAULT_BETA);
        state.update(100, 200);
        state.update(300, 400);
        // mean = 200
        let mean = state.mean_treatment_millionths();
        assert_eq!(mean, 200 * MILLIONTHS / 2);
    }

    #[test]
    fn test_sequential_test_mean_baseline() {
        let mut state = SequentialTestState::new(DEFAULT_ALPHA, DEFAULT_BETA);
        state.update(100, 200);
        state.update(300, 400);
        let mean = state.mean_baseline_millionths();
        assert_eq!(mean, 300 * MILLIONTHS / 2);
    }

    #[test]
    fn test_sequential_test_effect_size_positive() {
        let mut state = SequentialTestState::new(DEFAULT_ALPHA, DEFAULT_BETA);
        for _ in 0..30 {
            state.update(500, 1000);
        }
        let d = state.effect_size_millionths();
        assert!(d > 0, "effect size should be positive for superiority");
    }

    #[test]
    fn test_sequential_test_effect_size_zero_when_worse() {
        let mut state = SequentialTestState::new(DEFAULT_ALPHA, DEFAULT_BETA);
        for _ in 0..30 {
            state.update(1000, 500);
        }
        let d = state.effect_size_millionths();
        assert_eq!(d, 0, "effect size should be 0 when treatment is worse");
    }

    #[test]
    fn test_sequential_test_cv_zero_with_single() {
        let mut state = SequentialTestState::new(DEFAULT_ALPHA, DEFAULT_BETA);
        state.update(100, 200);
        assert_eq!(state.cv_treatment_millionths(), 0);
    }

    #[test]
    fn test_sequential_test_cv_with_variance() {
        let mut state = SequentialTestState::new(DEFAULT_ALPHA, DEFAULT_BETA);
        state.update(100, 200);
        state.update(200, 300);
        state.update(300, 400);
        let cv = state.cv_treatment_millionths();
        assert!(cv > 0);
    }

    #[test]
    fn test_sequential_test_is_decided() {
        let mut state = SequentialTestState::new(DEFAULT_ALPHA, DEFAULT_BETA);
        assert!(!state.is_decided());
        // Feed overwhelming evidence
        for _ in 0..1000 {
            state.update(100, 10000);
        }
        assert!(state.is_decided());
        assert!(state.accepts_superiority());
    }

    #[test]
    fn test_sequential_test_empty() {
        let state = SequentialTestState::new(DEFAULT_ALPHA, DEFAULT_BETA);
        assert_eq!(state.mean_treatment_millionths(), 0);
        assert_eq!(state.mean_baseline_millionths(), 0);
        assert_eq!(state.effect_size_millionths(), 0);
        assert_eq!(state.cv_treatment_millionths(), 0);
    }

    #[test]
    fn test_validate_config_ok() {
        let config = make_config();
        assert!(validate_config(&config).is_ok());
    }

    #[test]
    fn test_validate_config_alpha_zero() {
        let mut config = make_config();
        config.alpha = 0;
        assert!(matches!(
            validate_config(&config),
            Err(VerdictError::InvalidConfig { field, .. }) if field == "alpha"
        ));
    }

    #[test]
    fn test_validate_config_beta_too_large() {
        let mut config = make_config();
        config.beta = MILLIONTHS;
        assert!(matches!(
            validate_config(&config),
            Err(VerdictError::InvalidConfig { field, .. }) if field == "beta"
        ));
    }

    #[test]
    fn test_validate_config_min_observations_zero() {
        let mut config = make_config();
        config.min_observations = 0;
        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn test_validate_config_board_threshold_zero() {
        let mut config = make_config();
        config.board_pass_threshold = 0;
        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn test_evaluate_no_measurements() {
        let config = make_config();
        let result = evaluate_supremacy(&[], &config, &epoch(), 1000);
        assert!(matches!(result, Err(VerdictError::NoMeasurements)));
    }

    #[test]
    fn test_evaluate_single_cell_inconclusive() {
        let config = make_config();
        // Only 5 observations, below min_observations=30
        let measurements: Vec<_> = (0..5)
            .map(|_| make_measurement("cell_a", 500, 1000))
            .collect();
        let report = evaluate_supremacy(&measurements, &config, &epoch(), 1000).unwrap();
        assert_eq!(report.cell_verdicts.len(), 1);
        assert_eq!(
            report.cell_verdicts[0].verdict,
            SupremacyVerdict::Inconclusive
        );
        assert_eq!(report.board_verdict, SupremacyVerdict::Inconclusive);
    }

    #[test]
    fn test_evaluate_single_cell_confirmed() {
        let mut config = make_config();
        config.min_observations = 5;
        config.min_effect_size = 10_000; // very low bar
        config.max_cv = MILLIONTHS; // disable CV constraint
        // Strong superiority: treatment 500ns vs baseline 1000ns
        let measurements: Vec<_> = (0..50)
            .map(|_| make_measurement("cell_a", 500, 1000))
            .collect();
        let report = evaluate_supremacy(&measurements, &config, &epoch(), 1000).unwrap();
        let cv = &report.cell_verdicts[0];
        assert_eq!(cv.verdict, SupremacyVerdict::Confirmed);
        assert!(cv.effect_size > 0);
        assert_eq!(report.board_verdict, SupremacyVerdict::Confirmed);
    }

    #[test]
    fn test_evaluate_cell_rejected_for_insignificance() {
        let mut config = make_config();
        config.min_observations = 5;
        // Treatment worse than baseline
        let measurements: Vec<_> = (0..50)
            .map(|_| make_measurement("cell_a", 1000, 500))
            .collect();
        let report = evaluate_supremacy(&measurements, &config, &epoch(), 1000).unwrap();
        let cv = &report.cell_verdicts[0];
        assert_eq!(cv.verdict, SupremacyVerdict::Rejected);
        assert!(
            cv.rejection_reasons
                .contains(&RejectionReason::BelowEffectSizeFloor)
        );
    }

    #[test]
    fn test_evaluate_crash_rate_violation() {
        let mut config = make_config();
        config.min_observations = 5;
        config.max_crash_rate = 50_000; // 5%
        let mut measurements: Vec<_> = (0..10)
            .map(|_| make_measurement("cell_a", 500, 1000))
            .collect();
        // 3 out of 10 crash — 30% crash rate
        for m in measurements.iter_mut().take(3) {
            m.crash_observed = true;
        }
        let report = evaluate_supremacy(&measurements, &config, &epoch(), 1000).unwrap();
        let cv = &report.cell_verdicts[0];
        assert!(!cv.violations.is_empty());
        assert!(
            cv.violations
                .iter()
                .any(|v| v.kind == SideConstraintKind::CrashRate)
        );
    }

    #[test]
    fn test_evaluate_observability_mismatch() {
        let mut config = make_config();
        config.min_observations = 5;
        config.required_observability_modes = vec![ObservabilityMode::ExactShadow];
        // Measurements under BudgetedCapture (not ExactShadow)
        let measurements: Vec<_> = (0..30)
            .map(|_| make_measurement("cell_a", 500, 1000))
            .collect();
        let report = evaluate_supremacy(&measurements, &config, &epoch(), 1000).unwrap();
        let cv = &report.cell_verdicts[0];
        assert!(
            cv.violations
                .iter()
                .any(|v| v.kind == SideConstraintKind::ObservabilityMismatch)
        );
    }

    #[test]
    fn test_evaluate_multi_cell() {
        let mut config = make_config();
        config.min_observations = 5;
        config.min_effect_size = 10_000;
        config.max_cv = MILLIONTHS;
        let mut measurements = Vec::new();
        for _ in 0..30 {
            measurements.push(make_measurement("cell_a", 500, 1000));
            measurements.push(make_measurement("cell_b", 500, 1000));
        }
        let report = evaluate_supremacy(&measurements, &config, &epoch(), 1000).unwrap();
        assert_eq!(report.cell_verdicts.len(), 2);
        assert_eq!(report.board_verdict, SupremacyVerdict::Confirmed);
        assert_eq!(report.confirmed_fraction, MILLIONTHS);
    }

    #[test]
    fn test_evaluate_board_level_failure() {
        let mut config = make_config();
        config.min_observations = 5;
        config.board_pass_threshold = 800_000; // 80%
        config.max_cv = MILLIONTHS;
        let mut measurements = Vec::new();
        // cell_a: confirmed
        for _ in 0..30 {
            measurements.push(make_measurement("cell_a", 200, 1000));
        }
        // cell_b: rejected (treatment worse)
        for _ in 0..30 {
            measurements.push(make_measurement("cell_b", 2000, 1000));
        }
        // cell_c: rejected (treatment worse)
        for _ in 0..30 {
            measurements.push(make_measurement("cell_c", 2000, 1000));
        }
        let report = evaluate_supremacy(&measurements, &config, &epoch(), 1000).unwrap();
        // Only 1/3 confirmed = 33%, below 80%
        assert_eq!(report.board_verdict, SupremacyVerdict::Rejected);
        assert!(
            report
                .board_rejection_reasons
                .contains(&RejectionReason::BoardLevelFailure)
        );
    }

    #[test]
    fn test_evaluate_receipt_populated() {
        let config = make_config();
        let measurements: Vec<_> = (0..5)
            .map(|_| make_measurement("cell_a", 500, 1000))
            .collect();
        let report = evaluate_supremacy(&measurements, &config, &epoch(), 12345).unwrap();
        assert_eq!(report.receipt.schema_version, SCHEMA_VERSION);
        assert_eq!(report.receipt.component, COMPONENT);
        assert_eq!(report.receipt.bead_id, BEAD_ID);
        assert_eq!(report.receipt.policy_id, POLICY_ID);
        assert_eq!(report.receipt.epoch, 42);
        assert_eq!(report.receipt.timestamp_micros, 12345);
    }

    #[test]
    fn test_evaluate_deterministic_receipt() {
        let config = make_config();
        let measurements: Vec<_> = (0..10)
            .map(|_| make_measurement("cell_a", 500, 1000))
            .collect();
        let r1 = evaluate_supremacy(&measurements, &config, &epoch(), 1000).unwrap();
        let r2 = evaluate_supremacy(&measurements, &config, &epoch(), 1000).unwrap();
        assert_eq!(r1.receipt.input_hash, r2.receipt.input_hash);
        assert_eq!(r1.receipt.verdict_hash, r2.receipt.verdict_hash);
    }

    #[test]
    fn test_isqrt_values() {
        assert_eq!(isqrt(0), 0);
        assert_eq!(isqrt(1), 1);
        assert_eq!(isqrt(4), 2);
        assert_eq!(isqrt(9), 3);
        assert_eq!(isqrt(100), 10);
        assert_eq!(isqrt(10000), 100);
    }

    #[test]
    fn test_isqrt_non_perfect_square() {
        assert_eq!(isqrt(2), 1);
        assert_eq!(isqrt(3), 1);
        assert_eq!(isqrt(5), 2);
        assert_eq!(isqrt(8), 2);
    }

    #[test]
    fn test_summarize_report_basic() {
        let config = make_config();
        let measurements: Vec<_> = (0..5)
            .map(|_| make_measurement("cell_a", 500, 1000))
            .collect();
        let report = evaluate_supremacy(&measurements, &config, &epoch(), 1000).unwrap();
        let summary = summarize_report(&report);
        assert!(summary.contains("Board verdict:"));
        assert!(summary.contains("cell_a"));
    }

    #[test]
    fn test_error_display() {
        let err = VerdictError::NoMeasurements;
        assert_eq!(format!("{err}"), "no measurements provided");

        let err = VerdictError::TooManyCells { count: 300 };
        assert!(format!("{err}").contains("300"));

        let err = VerdictError::UnknownCell {
            cell_id: "c1".into(),
        };
        assert!(format!("{err}").contains("c1"));
    }

    #[test]
    fn test_verdict_config_default() {
        let config = VerdictConfig::default();
        assert_eq!(config.min_observations, DEFAULT_MIN_OBSERVATIONS);
        assert_eq!(config.alpha, DEFAULT_ALPHA);
        assert_eq!(config.beta, DEFAULT_BETA);
        assert_eq!(config.min_effect_size, DEFAULT_MIN_EFFECT_SIZE);
    }

    #[test]
    fn test_cell_measurement_serde_roundtrip() {
        let m = make_measurement("cell_a", 500, 1000);
        let json = serde_json::to_string(&m).unwrap();
        let m2: CellMeasurement = serde_json::from_str(&json).unwrap();
        assert_eq!(m, m2);
    }

    #[test]
    fn test_verdict_report_serde_roundtrip() {
        let mut config = make_config();
        config.min_observations = 3;
        config.max_cv = MILLIONTHS;
        let measurements: Vec<_> = (0..10)
            .map(|_| make_measurement("cell_a", 500, 1000))
            .collect();
        let report = evaluate_supremacy(&measurements, &config, &epoch(), 1000).unwrap();
        let json = serde_json::to_string(&report).unwrap();
        let report2: VerdictReport = serde_json::from_str(&json).unwrap();
        assert_eq!(report, report2);
    }

    #[test]
    fn test_constants() {
        assert_eq!(SCHEMA_VERSION, "franken-engine.supremacy-verdict-engine.v1");
        assert_eq!(COMPONENT, "supremacy_verdict_engine");
        assert_eq!(BEAD_ID, "bd-1lsy.8.5.2");
        assert_eq!(POLICY_ID, "RGC-705B");
    }

    #[test]
    fn test_side_constraint_violation_serde() {
        let v = SideConstraintViolation {
            kind: SideConstraintKind::CrashRate,
            cell_id: "cell_x".into(),
            observed: 50_000,
            threshold: 1_000,
            detail: "crash rate too high".into(),
        };
        let json = serde_json::to_string(&v).unwrap();
        let v2: SideConstraintViolation = serde_json::from_str(&json).unwrap();
        assert_eq!(v, v2);
    }

    #[test]
    fn test_cell_verdict_serde() {
        let cv = CellVerdict {
            cell_id: "c1".into(),
            verdict: SupremacyVerdict::Confirmed,
            rejection_reasons: Vec::new(),
            n_observations: 50,
            effect_size: 500_000,
            cv_treatment: 100_000,
            violations: Vec::new(),
            final_llr: 12345,
            mean_improvement_ratio: 400_000,
        };
        let json = serde_json::to_string(&cv).unwrap();
        let cv2: CellVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(cv, cv2);
    }

    #[test]
    fn test_tail_regression_violation() {
        let mut config = make_config();
        config.min_observations = 5;
        config.max_tail_regression = 50_000; // 5%
        config.max_cv = MILLIONTHS;
        let mut measurements = Vec::new();
        for _ in 0..30 {
            let mut m = make_measurement("cell_a", 500, 1000);
            // Tail p99 significantly worse for treatment
            m.tail_p99_ns = 2000;
            m.baseline_tail_p99_ns = 1000;
            measurements.push(m);
        }
        let report = evaluate_supremacy(&measurements, &config, &epoch(), 1000).unwrap();
        let cv = &report.cell_verdicts[0];
        assert!(
            cv.violations
                .iter()
                .any(|v| v.kind == SideConstraintKind::TailLatencyRegression)
        );
    }

    #[test]
    fn test_equal_performance_below_effect_floor() {
        let mut config = make_config();
        config.min_observations = 5;
        config.max_cv = MILLIONTHS;
        // Equal performance — no effect
        let measurements: Vec<_> = (0..50)
            .map(|_| make_measurement("cell_a", 1000, 1000))
            .collect();
        let report = evaluate_supremacy(&measurements, &config, &epoch(), 1000).unwrap();
        let cv = &report.cell_verdicts[0];
        assert!(
            cv.rejection_reasons
                .contains(&RejectionReason::BelowEffectSizeFloor)
        );
    }

    #[test]
    fn test_validate_config_board_threshold_too_high() {
        let mut config = make_config();
        config.board_pass_threshold = MILLIONTHS + 1;
        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn test_verdict_error_invalid_config() {
        let err = VerdictError::InvalidConfig {
            field: "alpha".into(),
            detail: "too large".into(),
        };
        assert!(format!("{err}").contains("alpha"));
        assert!(format!("{err}").contains("too large"));
    }
}
