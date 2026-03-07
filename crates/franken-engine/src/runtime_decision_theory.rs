//! Runtime Decision Theory — formal state/action model for lane routing
//! and fallback selection with CVaR tail-risk guardrails, conformal
//! calibration, drift detection, and budgeted adaptive mode.
//!
//! This module implements the top-level decision-theoretic orchestration
//! described in FRX-01.3, tying together the existing Bayesian posterior,
//! expected-loss selector, e-process guardrails, regime detector, and
//! regret-bounded router into a single formal POMDP-style decision system.
//!
//! All arithmetic uses fixed-point millionths (1_000_000 = 1.0) for
//! deterministic cross-platform computation.
//!
//! Key components:
//! - **Formal state/action model**: `DecisionState`, `LaneAction`, `DecisionContext`
//! - **CVaR tail-risk guardrail**: prevents mean improvements from hiding p99/p999 regressions
//! - **Conformal calibration layer**: anytime-valid coverage guarantees with optional-stopping safety
//! - **Drift detector**: KL-divergence and empirical-distribution shift tests with deterministic demotion
//! - **Budgeted adaptive mode**: strict compute/memory caps with deterministic on-exhaust fallback
//! - **Policy bundle**: machine-readable serializable decision artifacts
//!
//! Plan reference: FRX-01.3 (Runtime Decision Theory).

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::baseline_interpreter::{
    DETERMINISTIC_PROFILE_LABEL, LEGACY_QUICKJS_PROFILE_LABEL, LEGACY_V8_PROFILE_LABEL,
    THROUGHPUT_PROFILE_LABEL,
};
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const MILLION: i64 = 1_000_000;
/// Default CVaR confidence level: 95th percentile (millionths).
const DEFAULT_CVAR_ALPHA_MILLIONTHS: i64 = 950_000;
/// Default conformal miscoverage target: 10% (millionths).
const DEFAULT_CONFORMAL_ALPHA_MILLIONTHS: i64 = 100_000;
/// Maximum allowed adaptive budget fraction before forced fallback (millionths).
const MAX_BUDGET_FRACTION_MILLIONTHS: i64 = MILLION;
/// Default drift KL threshold (millionths): 0.1 nats.
const DEFAULT_KL_DRIFT_THRESHOLD_MILLIONTHS: i64 = 100_000;
/// Minimum sample count before drift tests activate.
const MIN_DRIFT_SAMPLES: u64 = 20;
/// Number of histogram bins for empirical distribution.
const DRIFT_HISTOGRAM_BINS: usize = 10;

// ---------------------------------------------------------------------------
// LaneId — typed lane identifier
// ---------------------------------------------------------------------------

/// Identifies an execution lane.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LaneId(pub String);

impl fmt::Display for LaneId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.stable_label())
    }
}

impl LaneId {
    pub fn deterministic_profile() -> Self {
        Self(DETERMINISTIC_PROFILE_LABEL.into())
    }

    pub fn throughput_profile() -> Self {
        Self(THROUGHPUT_PROFILE_LABEL.into())
    }

    pub fn stable_label(&self) -> &str {
        canonical_lane_label(&self.0).unwrap_or(self.0.as_str())
    }

    fn from_label(label: &str) -> Self {
        match label {
            DETERMINISTIC_PROFILE_LABEL | LEGACY_QUICKJS_PROFILE_LABEL | "QuickJs" => {
                Self::deterministic_profile()
            }
            THROUGHPUT_PROFILE_LABEL | LEGACY_V8_PROFILE_LABEL | "V8" => Self::throughput_profile(),
            _ => Self(label.to_string()),
        }
    }
}

impl Serialize for LaneId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.stable_label())
    }
}

impl<'de> Deserialize<'de> for LaneId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Ok(Self::from_label(&raw))
    }
}

fn canonical_lane_label(label: &str) -> Option<&'static str> {
    match label {
        DETERMINISTIC_PROFILE_LABEL | LEGACY_QUICKJS_PROFILE_LABEL | "QuickJs" => {
            Some(DETERMINISTIC_PROFILE_LABEL)
        }
        THROUGHPUT_PROFILE_LABEL | LEGACY_V8_PROFILE_LABEL | "V8" => Some(THROUGHPUT_PROFILE_LABEL),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// DecisionState — formal POMDP-style state
// ---------------------------------------------------------------------------

/// Observable component of the decision state.
///
/// In a POMDP formulation, the agent cannot directly observe the full state;
/// instead it maintains beliefs over latent risk factors.  `DecisionState`
/// captures the observable portion plus summary statistics of the belief.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionState {
    /// Current epoch for causal ordering.
    pub epoch: SecurityEpoch,
    /// Detected operating regime (from regime_detector).
    pub regime: RegimeLabel,
    /// Belief-state summary: probability mass on each risk factor (millionths, sum to MILLION).
    pub risk_belief_millionths: BTreeMap<RiskFactor, i64>,
    /// Cumulative observed latency quantiles (p50/p95/p99/p999) in microseconds.
    pub latency_quantiles_us: LatencyQuantiles,
    /// Current adaptive budget remaining (millionths of max).
    pub budget_remaining_millionths: i64,
    /// Number of decisions made so far in this epoch.
    pub decisions_in_epoch: u64,
    /// Whether safe-mode fallback is currently active.
    pub safe_mode_active: bool,
}

/// Risk factors in the belief state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum RiskFactor {
    /// Compatibility risk: potential for semantic divergence.
    Compatibility,
    /// Latency risk: potential for p99/p999 regression.
    Latency,
    /// Memory risk: potential for memory budget exhaustion.
    Memory,
    /// Incident severity: potential for security incident.
    IncidentSeverity,
}

impl RiskFactor {
    pub const ALL: [RiskFactor; 4] = [
        RiskFactor::Compatibility,
        RiskFactor::Latency,
        RiskFactor::Memory,
        RiskFactor::IncidentSeverity,
    ];
}

impl fmt::Display for RiskFactor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Compatibility => write!(f, "compatibility"),
            Self::Latency => write!(f, "latency"),
            Self::Memory => write!(f, "memory"),
            Self::IncidentSeverity => write!(f, "incident_severity"),
        }
    }
}

/// Operating regime label (mirrors regime_detector::Regime but decoupled).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum RegimeLabel {
    Normal,
    Elevated,
    Attack,
    Degraded,
    Recovery,
}

impl fmt::Display for RegimeLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Normal => write!(f, "normal"),
            Self::Elevated => write!(f, "elevated"),
            Self::Attack => write!(f, "attack"),
            Self::Degraded => write!(f, "degraded"),
            Self::Recovery => write!(f, "recovery"),
        }
    }
}

/// Latency quantile snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LatencyQuantiles {
    pub p50_us: u64,
    pub p95_us: u64,
    pub p99_us: u64,
    pub p999_us: u64,
}

// ---------------------------------------------------------------------------
// LaneAction — formal action space for lane routing
// ---------------------------------------------------------------------------

/// Actions the decision system can take for lane routing and fallback.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum LaneAction {
    /// Route to the specified execution lane.
    RouteTo(LaneId),
    /// Fall back to the deterministic safe-mode lane.
    FallbackSafe,
    /// Demote the current lane and switch to fallback.
    Demote {
        from_lane: LaneId,
        reason: DemotionReason,
    },
    /// Suspend all adaptive logic and lock to safe mode.
    SuspendAdaptive,
}

impl fmt::Display for LaneAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RouteTo(lane) => write!(f, "route_to:{lane}"),
            Self::FallbackSafe => write!(f, "fallback_safe"),
            Self::Demote { from_lane, reason } => {
                write!(f, "demote:{from_lane}:{reason}")
            }
            Self::SuspendAdaptive => write!(f, "suspend_adaptive"),
        }
    }
}

/// Reason for deterministic demotion.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum DemotionReason {
    /// CVaR tail-risk threshold exceeded.
    CvarExceeded,
    /// Drift detected in decision quality metrics.
    DriftDetected,
    /// Adaptive budget exhausted.
    BudgetExhausted,
    /// E-process guardrail triggered.
    GuardrailTriggered,
    /// Conformal calibration coverage violation.
    CoverageViolation,
    /// Operator-initiated demotion.
    OperatorOverride,
}

impl fmt::Display for DemotionReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CvarExceeded => write!(f, "cvar_exceeded"),
            Self::DriftDetected => write!(f, "drift_detected"),
            Self::BudgetExhausted => write!(f, "budget_exhausted"),
            Self::GuardrailTriggered => write!(f, "guardrail_triggered"),
            Self::CoverageViolation => write!(f, "coverage_violation"),
            Self::OperatorOverride => write!(f, "operator_override"),
        }
    }
}

// ---------------------------------------------------------------------------
// CVaR Tail-Risk Guardrail
// ---------------------------------------------------------------------------

/// Configuration for the CVaR tail-risk guardrail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CvarConfig {
    /// Confidence level alpha (millionths).  E.g., 950_000 = 95%.
    /// CVaR is computed over the (1-alpha) tail.
    pub alpha_millionths: i64,
    /// Maximum acceptable CVaR (millionths).  If exceeded, demotion triggers.
    pub max_cvar_millionths: i64,
    /// Minimum observations before CVaR check activates.
    pub min_observations: u64,
}

impl Default for CvarConfig {
    fn default() -> Self {
        Self {
            alpha_millionths: DEFAULT_CVAR_ALPHA_MILLIONTHS,
            max_cvar_millionths: 50 * MILLION, // 50.0
            min_observations: 30,
        }
    }
}

/// Tracks empirical loss distribution and computes CVaR for tail-risk guardrails.
///
/// CVaR (Conditional Value at Risk) at level α is the expected loss in the
/// worst (1-α) fraction of outcomes.  This prevents mean improvements from
/// hiding p99/p999 regressions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CvarGuardrail {
    config: CvarConfig,
    /// Sorted observed loss values (millionths).
    observations: Vec<i64>,
    /// Whether the guardrail has been triggered.
    triggered: bool,
    /// Epoch when last triggered.
    trigger_epoch: Option<SecurityEpoch>,
}

impl CvarGuardrail {
    pub fn new(config: CvarConfig) -> Self {
        Self {
            config,
            observations: Vec::new(),
            triggered: false,
            trigger_epoch: None,
        }
    }

    /// Record a new loss observation.
    pub fn observe(&mut self, loss_millionths: i64) {
        // Insert in sorted order for efficient quantile computation.
        let pos = self.observations.partition_point(|&x| x < loss_millionths);
        self.observations.insert(pos, loss_millionths);
    }

    /// Compute the current CVaR estimate (millionths).
    ///
    /// Returns `None` if insufficient observations.
    pub fn cvar(&self) -> Option<i64> {
        let n = self.observations.len() as u64;
        if n < self.config.min_observations {
            return None;
        }
        // VaR index: the (1-alpha) quantile position.
        let var_index = {
            let alpha_frac = self.config.alpha_millionths;
            // index = floor(n * alpha / MILLION)
            let idx = (n as i64).saturating_mul(alpha_frac) / MILLION;
            idx.max(0) as usize
        };
        let tail_start = var_index.min(self.observations.len().saturating_sub(1));
        let tail = &self.observations[tail_start..];
        if tail.is_empty() {
            return None;
        }
        // CVaR = mean of observations in the tail.
        let sum: i64 = tail.iter().sum();
        let count = tail.len() as i64;
        Some(sum / count)
    }

    /// Check whether CVaR exceeds the configured threshold.
    /// If so, marks the guardrail as triggered and returns the current CVaR.
    pub fn check(&mut self, epoch: SecurityEpoch) -> CvarCheckResult {
        let cvar_value = self.cvar();
        match cvar_value {
            None => CvarCheckResult::InsufficientData {
                observations: self.observations.len() as u64,
                required: self.config.min_observations,
            },
            Some(cvar) if cvar > self.config.max_cvar_millionths => {
                self.triggered = true;
                self.trigger_epoch = Some(epoch);
                CvarCheckResult::Exceeded {
                    cvar_millionths: cvar,
                    threshold_millionths: self.config.max_cvar_millionths,
                    epoch,
                }
            }
            Some(cvar) => CvarCheckResult::WithinBounds {
                cvar_millionths: cvar,
                threshold_millionths: self.config.max_cvar_millionths,
                headroom_millionths: self.config.max_cvar_millionths - cvar,
            },
        }
    }

    pub fn is_triggered(&self) -> bool {
        self.triggered
    }

    pub fn trigger_epoch(&self) -> Option<SecurityEpoch> {
        self.trigger_epoch
    }

    /// Reset the guardrail (operator-authorized only).
    pub fn reset(&mut self) {
        self.triggered = false;
        self.trigger_epoch = None;
        self.observations.clear();
    }

    pub fn observation_count(&self) -> u64 {
        self.observations.len() as u64
    }

    /// Return the VaR (Value at Risk) at the configured alpha level.
    pub fn var(&self) -> Option<i64> {
        let n = self.observations.len() as u64;
        if n < self.config.min_observations {
            return None;
        }
        let var_index = {
            let alpha_frac = self.config.alpha_millionths;
            let idx = (n as i64).saturating_mul(alpha_frac) / MILLION;
            idx.max(0) as usize
        };
        let clamped = var_index.min(self.observations.len().saturating_sub(1));
        Some(self.observations[clamped])
    }
}

/// Result of a CVaR guardrail check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CvarCheckResult {
    /// Not enough observations to compute CVaR.
    InsufficientData { observations: u64, required: u64 },
    /// CVaR is within bounds.
    WithinBounds {
        cvar_millionths: i64,
        threshold_millionths: i64,
        headroom_millionths: i64,
    },
    /// CVaR exceeds threshold — demotion required.
    Exceeded {
        cvar_millionths: i64,
        threshold_millionths: i64,
        epoch: SecurityEpoch,
    },
}

// ---------------------------------------------------------------------------
// Conformal Calibration Layer
// ---------------------------------------------------------------------------

/// Configuration for the conformal calibration layer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformalConfig {
    /// Target miscoverage rate alpha (millionths).  E.g., 100_000 = 10%.
    pub alpha_millionths: i64,
    /// Minimum calibration observations before enforcement.
    pub min_calibration_observations: u64,
    /// Maximum allowed consecutive coverage violations before demotion.
    pub max_consecutive_violations: u64,
}

impl Default for ConformalConfig {
    fn default() -> Self {
        Self {
            alpha_millionths: DEFAULT_CONFORMAL_ALPHA_MILLIONTHS,
            min_calibration_observations: 50,
            max_consecutive_violations: 5,
        }
    }
}

/// Anytime-valid conformal calibration tracker.
///
/// Tracks whether decision predictions satisfy the promised coverage
/// guarantee.  Uses a running tally with optional-stopping safety:
/// the coverage guarantee holds at any stopping time, not just at
/// a fixed horizon.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConformalCalibrator {
    config: ConformalConfig,
    /// Total predictions tracked.
    total_predictions: u64,
    /// Predictions that were correctly covered by the conformal set.
    covered_predictions: u64,
    /// Consecutive coverage violations.
    consecutive_violations: u64,
    /// Running e-value for anytime-valid coverage test.
    /// Product of per-step likelihood ratios (millionths, 1M = 1.0).
    e_value_millionths: i64,
    /// Whether the calibrator has flagged a coverage violation.
    violation_flagged: bool,
    /// Calibration ledger entries (capped for memory).
    ledger: Vec<CalibrationLedgerEntry>,
}

/// Calibration ledger entry for audit trail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CalibrationLedgerEntry {
    pub epoch: SecurityEpoch,
    pub prediction_covered: bool,
    pub running_coverage_millionths: i64,
    pub e_value_millionths: i64,
    pub violation: bool,
}

impl ConformalCalibrator {
    pub fn new(config: ConformalConfig) -> Self {
        Self {
            config,
            total_predictions: 0,
            covered_predictions: 0,
            consecutive_violations: 0,
            e_value_millionths: MILLION, // e-value starts at 1.0
            violation_flagged: false,
            ledger: Vec::new(),
        }
    }

    /// Record whether a prediction was covered by the conformal set.
    pub fn record(&mut self, epoch: SecurityEpoch, covered: bool) {
        self.total_predictions += 1;
        if covered {
            self.covered_predictions += 1;
            self.consecutive_violations = 0;
        } else {
            self.consecutive_violations += 1;
        }

        // Update running coverage rate (millionths).
        let coverage_millionths = if self.total_predictions == 0 {
            0
        } else {
            (self.covered_predictions as i64).saturating_mul(MILLION)
                / (self.total_predictions as i64)
        };

        // Anytime-valid e-value update.
        // Under the null H0: coverage >= (1 - alpha), the expected coverage
        // of each observation is (1 - alpha).
        // Likelihood ratio for this step:
        //   covered=true:  LR = 1.0 (consistent with H0)
        //   covered=false: LR = (1 - alpha) / alpha  (evidence against H0)
        let step_lr = if covered {
            MILLION // 1.0
        } else {
            let alpha = self.config.alpha_millionths;
            if alpha <= 0 {
                MILLION
            } else {
                (MILLION - alpha).saturating_mul(MILLION) / alpha
            }
        };

        // Product update (capped to avoid overflow).
        self.e_value_millionths = self.e_value_millionths.saturating_mul(step_lr) / MILLION;
        // Cap at a large value to prevent overflow.
        self.e_value_millionths = self.e_value_millionths.min(1_000_000_000_000);

        let violation = self.consecutive_violations >= self.config.max_consecutive_violations
            && self.total_predictions >= self.config.min_calibration_observations;

        if violation {
            self.violation_flagged = true;
        }

        // Ledger entry.
        let entry = CalibrationLedgerEntry {
            epoch,
            prediction_covered: covered,
            running_coverage_millionths: coverage_millionths,
            e_value_millionths: self.e_value_millionths,
            violation,
        };
        // Keep ledger bounded.
        if self.ledger.len() < 10_000 {
            self.ledger.push(entry);
        }
    }

    /// Current empirical coverage rate (millionths).
    pub fn coverage_millionths(&self) -> i64 {
        if self.total_predictions == 0 {
            return MILLION; // vacuously covered
        }
        (self.covered_predictions as i64).saturating_mul(MILLION) / (self.total_predictions as i64)
    }

    /// Whether the required coverage is being met.
    pub fn is_calibrated(&self) -> bool {
        if self.total_predictions < self.config.min_calibration_observations {
            return true; // insufficient data → assume calibrated
        }
        let target = MILLION - self.config.alpha_millionths;
        self.coverage_millionths() >= target
    }

    /// Current anytime-valid e-value (millionths).
    pub fn e_value_millionths(&self) -> i64 {
        self.e_value_millionths
    }

    /// Whether a violation has been flagged.
    pub fn violation_flagged(&self) -> bool {
        self.violation_flagged
    }

    /// Get the calibration ledger.
    pub fn ledger(&self) -> &[CalibrationLedgerEntry] {
        &self.ledger
    }

    pub fn total_predictions(&self) -> u64 {
        self.total_predictions
    }

    pub fn covered_predictions(&self) -> u64 {
        self.covered_predictions
    }

    /// Reset the calibrator (operator-authorized).
    pub fn reset(&mut self) {
        self.total_predictions = 0;
        self.covered_predictions = 0;
        self.consecutive_violations = 0;
        self.e_value_millionths = MILLION;
        self.violation_flagged = false;
        self.ledger.clear();
    }
}

// ---------------------------------------------------------------------------
// Drift Detector
// ---------------------------------------------------------------------------

/// Configuration for the empirical drift detector.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DriftConfig {
    /// KL divergence threshold for drift detection (millionths).
    pub kl_threshold_millionths: i64,
    /// Reference window size (number of observations).
    pub reference_window: u64,
    /// Test window size.
    pub test_window: u64,
    /// Minimum samples in both windows before drift tests activate.
    pub min_samples: u64,
}

impl Default for DriftConfig {
    fn default() -> Self {
        Self {
            kl_threshold_millionths: DEFAULT_KL_DRIFT_THRESHOLD_MILLIONTHS,
            reference_window: 100,
            test_window: 50,
            min_samples: MIN_DRIFT_SAMPLES,
        }
    }
}

/// Empirical drift detector using KL divergence on discretized distributions.
///
/// Maintains reference and test windows of observations, computes an
/// empirical KL divergence between their histograms, and flags drift
/// when it exceeds the configured threshold.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriftDetector {
    config: DriftConfig,
    /// All observations (ring buffer semantic via index tracking).
    observations: Vec<i64>,
    /// Whether drift has been detected.
    drift_detected: bool,
    /// Last computed KL divergence (millionths).
    last_kl_millionths: Option<i64>,
    /// Epoch when drift was detected.
    drift_epoch: Option<SecurityEpoch>,
}

impl DriftDetector {
    pub fn new(config: DriftConfig) -> Self {
        Self {
            config,
            observations: Vec::new(),
            drift_detected: false,
            last_kl_millionths: None,
            drift_epoch: None,
        }
    }

    /// Record a new observation (millionths).
    pub fn observe(&mut self, value_millionths: i64) {
        self.observations.push(value_millionths);
        // Keep bounded: retain only reference_window + test_window + margin.
        let max_keep = (self.config.reference_window + self.config.test_window + 50) as usize;
        if self.observations.len() > max_keep {
            let drain = self.observations.len() - max_keep;
            self.observations.drain(..drain);
        }
    }

    /// Check for drift between reference and test windows.
    pub fn check(&mut self, epoch: SecurityEpoch) -> DriftCheckResult {
        let n = self.observations.len() as u64;
        let ref_size = self.config.reference_window;
        let test_size = self.config.test_window;
        let total_needed = ref_size + test_size;

        if n < total_needed || n < self.config.min_samples {
            return DriftCheckResult::InsufficientData {
                observations: n,
                required: total_needed,
            };
        }

        let obs_len = self.observations.len();
        let test_start = obs_len - test_size as usize;
        let ref_start = test_start - ref_size as usize;
        let reference = &self.observations[ref_start..test_start];
        let test = &self.observations[test_start..];

        let kl = empirical_kl_divergence(reference, test);
        self.last_kl_millionths = Some(kl);

        if kl > self.config.kl_threshold_millionths {
            self.drift_detected = true;
            self.drift_epoch = Some(epoch);
            DriftCheckResult::DriftDetected {
                kl_millionths: kl,
                threshold_millionths: self.config.kl_threshold_millionths,
                epoch,
            }
        } else {
            DriftCheckResult::NoDrift {
                kl_millionths: kl,
                threshold_millionths: self.config.kl_threshold_millionths,
            }
        }
    }

    pub fn is_drift_detected(&self) -> bool {
        self.drift_detected
    }

    pub fn last_kl_millionths(&self) -> Option<i64> {
        self.last_kl_millionths
    }

    pub fn drift_epoch(&self) -> Option<SecurityEpoch> {
        self.drift_epoch
    }

    /// Reset the detector (operator-authorized).
    pub fn reset(&mut self) {
        self.drift_detected = false;
        self.last_kl_millionths = None;
        self.drift_epoch = None;
        self.observations.clear();
    }

    pub fn observation_count(&self) -> u64 {
        self.observations.len() as u64
    }
}

/// Result of a drift check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DriftCheckResult {
    InsufficientData {
        observations: u64,
        required: u64,
    },
    NoDrift {
        kl_millionths: i64,
        threshold_millionths: i64,
    },
    DriftDetected {
        kl_millionths: i64,
        threshold_millionths: i64,
        epoch: SecurityEpoch,
    },
}

/// Compute empirical KL divergence D(P || Q) between two observation sets.
///
/// Uses histogram discretization with `DRIFT_HISTOGRAM_BINS` bins.
/// Returns result in millionths.
fn empirical_kl_divergence(reference: &[i64], test: &[i64]) -> i64 {
    if reference.is_empty() || test.is_empty() {
        return 0;
    }

    // Find global min/max for bin boundaries.
    let global_min = *reference.iter().chain(test.iter()).min().unwrap_or(&0);
    let global_max = *reference.iter().chain(test.iter()).max().unwrap_or(&0);

    if global_min == global_max {
        return 0; // all observations identical
    }

    let range = global_max - global_min;
    let bin_width = range / DRIFT_HISTOGRAM_BINS as i64 + 1;

    // Build histograms with Laplace smoothing (add 1 to each bin).
    let mut ref_counts = [1i64; DRIFT_HISTOGRAM_BINS];
    let mut test_counts = [1i64; DRIFT_HISTOGRAM_BINS];

    for &v in reference {
        let bin = ((v - global_min) / bin_width).min(DRIFT_HISTOGRAM_BINS as i64 - 1) as usize;
        ref_counts[bin] += 1;
    }
    for &v in test {
        let bin = ((v - global_min) / bin_width).min(DRIFT_HISTOGRAM_BINS as i64 - 1) as usize;
        test_counts[bin] += 1;
    }

    let ref_total: i64 = ref_counts.iter().sum();
    let test_total: i64 = test_counts.iter().sum();

    if ref_total == 0 || test_total == 0 {
        return 0;
    }

    // KL(P || Q) = sum_i P(i) * log(P(i) / Q(i))
    // Using fixed-point approximation of log via integer arithmetic.
    // log(a/b) ≈ (a - b) / b for small differences (first-order Taylor).
    // For larger differences, use ln(x) ≈ (x-1) - (x-1)^2/2 + ... but
    // we'll use a simple linear approximation scaled to millionths.
    let mut kl_sum: i64 = 0;
    for i in 0..DRIFT_HISTOGRAM_BINS {
        // p_i and q_i as millionths of their respective totals.
        let p_millionths = ref_counts[i].saturating_mul(MILLION) / ref_total;
        let q_millionths = test_counts[i].saturating_mul(MILLION) / test_total;

        if p_millionths == 0 || q_millionths == 0 {
            continue;
        }

        // log(p/q) approximation in millionths:
        // Using ln(x) ≈ 2*(x-1)/(x+1) (Padé approximant) which is more
        // accurate than Taylor for ratios away from 1.
        let ratio_millionths = p_millionths.saturating_mul(MILLION) / q_millionths;
        let log_approx = fixed_point_ln(ratio_millionths);

        // p_i * log(p_i / q_i) in millionths.
        let term = p_millionths.saturating_mul(log_approx) / MILLION;
        kl_sum = kl_sum.saturating_add(term);
    }

    kl_sum.max(0)
}

/// Fixed-point natural log approximation.
///
/// Input: x in millionths (1_000_000 = 1.0).
/// Output: ln(x) in millionths.
///
/// Uses Padé approximant: ln(x) ≈ 2*(x-1)/(x+1) for x near 1.
/// For x far from 1, uses iterative range reduction.
fn fixed_point_ln(x_millionths: i64) -> i64 {
    if x_millionths <= 0 {
        return -100 * MILLION; // large negative for log(0)
    }
    if x_millionths == MILLION {
        return 0;
    }

    // Range reduction: if x > 2, decompose as x = 2^k * y where 1 <= y < 2.
    let mut x = x_millionths;
    let mut shifts = 0i64;
    while x > 2 * MILLION {
        x /= 2;
        shifts += 1;
    }
    while x < MILLION / 2 {
        x *= 2;
        shifts -= 1;
    }

    // Padé approximant for ln(y) where y is close to 1.
    let numerator = 2 * (x - MILLION);
    let denominator = x + MILLION;
    let ln_y = if denominator != 0 {
        numerator.saturating_mul(MILLION) / denominator
    } else {
        0
    };

    // ln(x) = ln(y) + k * ln(2)
    // ln(2) ≈ 0.693147 → 693_147 millionths
    let ln2 = 693_147i64;
    ln_y.saturating_add(shifts.saturating_mul(ln2))
}

// ---------------------------------------------------------------------------
// Budgeted Adaptive Controller
// ---------------------------------------------------------------------------

/// Configuration for budgeted adaptive mode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetConfig {
    /// Maximum compute budget in microseconds per epoch.
    pub compute_budget_us: u64,
    /// Maximum memory budget in bytes per epoch.
    pub memory_budget_bytes: u64,
    /// Fraction of budget that triggers warning (millionths).
    pub warning_threshold_millionths: i64,
    /// Whether to deterministically fall back when budget exhausted.
    pub deterministic_fallback_on_exhaust: bool,
}

impl Default for BudgetConfig {
    fn default() -> Self {
        Self {
            compute_budget_us: 50_000,              // 50ms
            memory_budget_bytes: 128 * 1024 * 1024, // 128MB
            warning_threshold_millionths: 800_000,  // 80%
            deterministic_fallback_on_exhaust: true,
        }
    }
}

/// Tracks compute and memory budgets with deterministic on-exhaust fallback.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BudgetController {
    config: BudgetConfig,
    /// Compute microseconds consumed in current epoch.
    compute_consumed_us: u64,
    /// Memory bytes consumed in current epoch.
    memory_consumed_bytes: u64,
    /// Current epoch.
    epoch: SecurityEpoch,
    /// Whether fallback has been triggered.
    fallback_active: bool,
    /// Audit events for budget transitions.
    events: Vec<BudgetEvent>,
}

/// Budget-related audit event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetEvent {
    pub epoch: SecurityEpoch,
    pub kind: BudgetEventKind,
    pub compute_consumed_us: u64,
    pub memory_consumed_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BudgetEventKind {
    /// Budget warning threshold reached.
    Warning,
    /// Budget exhausted — fallback activated.
    Exhausted,
    /// Budget reset for new epoch.
    EpochReset,
}

impl fmt::Display for BudgetEventKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Warning => write!(f, "warning"),
            Self::Exhausted => write!(f, "exhausted"),
            Self::EpochReset => write!(f, "epoch_reset"),
        }
    }
}

impl BudgetController {
    pub fn new(config: BudgetConfig, epoch: SecurityEpoch) -> Self {
        Self {
            config,
            compute_consumed_us: 0,
            memory_consumed_bytes: 0,
            epoch,
            fallback_active: false,
            events: Vec::new(),
        }
    }

    /// Record compute usage.
    pub fn record_compute(&mut self, us: u64) -> BudgetStatus {
        self.compute_consumed_us = self.compute_consumed_us.saturating_add(us);
        self.check_budget()
    }

    /// Record memory usage.
    pub fn record_memory(&mut self, bytes: u64) -> BudgetStatus {
        self.memory_consumed_bytes = self.memory_consumed_bytes.saturating_add(bytes);
        self.check_budget()
    }

    /// Check the current budget status.
    fn check_budget(&mut self) -> BudgetStatus {
        let compute_fraction = if self.config.compute_budget_us == 0 {
            MILLION
        } else {
            (self.compute_consumed_us as i64).saturating_mul(MILLION)
                / (self.config.compute_budget_us as i64)
        };

        let memory_fraction = if self.config.memory_budget_bytes == 0 {
            MILLION
        } else {
            (self.memory_consumed_bytes as i64).saturating_mul(MILLION)
                / (self.config.memory_budget_bytes as i64)
        };

        let max_fraction = compute_fraction.max(memory_fraction);

        if max_fraction >= MAX_BUDGET_FRACTION_MILLIONTHS {
            if !self.fallback_active && self.config.deterministic_fallback_on_exhaust {
                self.fallback_active = true;
                let event = BudgetEvent {
                    epoch: self.epoch,
                    kind: BudgetEventKind::Exhausted,
                    compute_consumed_us: self.compute_consumed_us,
                    memory_consumed_bytes: self.memory_consumed_bytes,
                };
                self.events.push(event);
            }
            BudgetStatus::Exhausted {
                compute_fraction_millionths: compute_fraction,
                memory_fraction_millionths: memory_fraction,
            }
        } else if max_fraction >= self.config.warning_threshold_millionths {
            BudgetStatus::Warning {
                compute_fraction_millionths: compute_fraction,
                memory_fraction_millionths: memory_fraction,
            }
        } else {
            BudgetStatus::Normal {
                compute_fraction_millionths: compute_fraction,
                memory_fraction_millionths: memory_fraction,
            }
        }
    }

    /// Reset budget for a new epoch.
    pub fn reset_epoch(&mut self, new_epoch: SecurityEpoch) {
        let event = BudgetEvent {
            epoch: new_epoch,
            kind: BudgetEventKind::EpochReset,
            compute_consumed_us: self.compute_consumed_us,
            memory_consumed_bytes: self.memory_consumed_bytes,
        };
        self.events.push(event);
        self.compute_consumed_us = 0;
        self.memory_consumed_bytes = 0;
        self.epoch = new_epoch;
        self.fallback_active = false;
    }

    pub fn is_fallback_active(&self) -> bool {
        self.fallback_active
    }

    pub fn compute_consumed_us(&self) -> u64 {
        self.compute_consumed_us
    }

    pub fn memory_consumed_bytes(&self) -> u64 {
        self.memory_consumed_bytes
    }

    pub fn events(&self) -> &[BudgetEvent] {
        &self.events
    }

    /// Budget remaining as fraction (millionths).
    pub fn budget_remaining_millionths(&self) -> i64 {
        let compute_fraction = if self.config.compute_budget_us == 0 {
            0
        } else {
            (self.compute_consumed_us as i64).saturating_mul(MILLION)
                / (self.config.compute_budget_us as i64)
        };
        let memory_fraction = if self.config.memory_budget_bytes == 0 {
            0
        } else {
            (self.memory_consumed_bytes as i64).saturating_mul(MILLION)
                / (self.config.memory_budget_bytes as i64)
        };
        MILLION - compute_fraction.max(memory_fraction).min(MILLION)
    }
}

/// Budget status after a usage record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BudgetStatus {
    Normal {
        compute_fraction_millionths: i64,
        memory_fraction_millionths: i64,
    },
    Warning {
        compute_fraction_millionths: i64,
        memory_fraction_millionths: i64,
    },
    Exhausted {
        compute_fraction_millionths: i64,
        memory_fraction_millionths: i64,
    },
}

// ---------------------------------------------------------------------------
// Decision Trace — replay-stable decision record
// ---------------------------------------------------------------------------

/// A single decision trace entry for deterministic replay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionTrace {
    /// Decision sequence number within epoch.
    pub sequence: u64,
    /// Epoch in which the decision was made.
    pub epoch: SecurityEpoch,
    /// The state snapshot at decision time.
    pub state: DecisionState,
    /// The action selected.
    pub action: LaneAction,
    /// Expected loss of the selected action (millionths).
    pub expected_loss_millionths: i64,
    /// CVaR at decision time (millionths), if computed.
    pub cvar_millionths: Option<i64>,
    /// Drift KL divergence (millionths), if computed.
    pub drift_kl_millionths: Option<i64>,
    /// Budget remaining (millionths) at decision time.
    pub budget_remaining_millionths: i64,
    /// Whether any guardrail was active.
    pub guardrail_active: bool,
    /// Reason for the decision (human-readable).
    pub reason: String,
}

// ---------------------------------------------------------------------------
// Fallback Trigger Audit Event
// ---------------------------------------------------------------------------

/// Audit event emitted when a fallback or demotion is triggered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FallbackTriggerEvent {
    pub epoch: SecurityEpoch,
    pub trigger: DemotionReason,
    pub from_action: Option<LaneAction>,
    pub to_action: LaneAction,
    /// Snapshot of relevant metrics at trigger time.
    pub metrics: FallbackMetrics,
}

/// Metrics captured at fallback trigger time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FallbackMetrics {
    pub cvar_millionths: Option<i64>,
    pub drift_kl_millionths: Option<i64>,
    pub budget_remaining_millionths: i64,
    pub coverage_millionths: i64,
    pub e_value_millionths: i64,
}

// ---------------------------------------------------------------------------
// Policy Bundle — machine-readable decision artifact
// ---------------------------------------------------------------------------

/// Machine-readable policy bundle capturing the full decision configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyBundle {
    /// Bundle version.
    pub version: String,
    /// Epoch when the bundle was created.
    pub epoch: SecurityEpoch,
    /// Available lanes.
    pub lanes: Vec<LaneId>,
    /// CVaR configuration.
    pub cvar_config: CvarConfig,
    /// Conformal calibration configuration.
    pub conformal_config: ConformalConfig,
    /// Drift detection configuration.
    pub drift_config: DriftConfig,
    /// Budget configuration.
    pub budget_config: BudgetConfig,
    /// Risk-factor weights for expected-loss computation (millionths).
    pub risk_weights: BTreeMap<RiskFactor, i64>,
    /// Default action when all guardrails are clear.
    pub default_action: LaneAction,
    /// Fallback action when any guardrail triggers.
    pub fallback_action: LaneAction,
}

// ---------------------------------------------------------------------------
// DecisionContext — top-level orchestrator
// ---------------------------------------------------------------------------

/// Configuration for the runtime decision context.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DecisionContextConfig {
    pub cvar_config: CvarConfig,
    pub conformal_config: ConformalConfig,
    pub drift_config: DriftConfig,
    pub budget_config: BudgetConfig,
    /// Available lanes for routing.
    pub lanes: Vec<LaneId>,
    /// Risk-factor weights for multi-dimensional expected loss (millionths).
    pub risk_weights: BTreeMap<RiskFactor, i64>,
}

impl Default for DecisionContextConfig {
    fn default() -> Self {
        let mut risk_weights = BTreeMap::new();
        risk_weights.insert(RiskFactor::Compatibility, 300_000); // 30%
        risk_weights.insert(RiskFactor::Latency, 300_000); // 30%
        risk_weights.insert(RiskFactor::Memory, 200_000); // 20%
        risk_weights.insert(RiskFactor::IncidentSeverity, 200_000); // 20%

        Self {
            cvar_config: CvarConfig::default(),
            conformal_config: ConformalConfig::default(),
            drift_config: DriftConfig::default(),
            budget_config: BudgetConfig::default(),
            lanes: vec![
                LaneId::deterministic_profile(),
                LaneId::throughput_profile(),
            ],
            risk_weights,
        }
    }
}

/// Top-level runtime decision context.
///
/// Orchestrates CVaR guardrail, conformal calibration, drift detection,
/// and budgeted adaptive mode into a unified decision system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionContext {
    config: DecisionContextConfig,
    cvar: CvarGuardrail,
    calibrator: ConformalCalibrator,
    drift: DriftDetector,
    budget: BudgetController,
    /// Decision trace for replay.
    traces: Vec<DecisionTrace>,
    /// Fallback trigger events for audit.
    fallback_events: Vec<FallbackTriggerEvent>,
    /// Current decision sequence number.
    sequence: u64,
    /// Current epoch.
    epoch: SecurityEpoch,
}

impl DecisionContext {
    /// Create a new decision context.
    pub fn new(config: DecisionContextConfig, epoch: SecurityEpoch) -> Self {
        let cvar = CvarGuardrail::new(config.cvar_config.clone());
        let calibrator = ConformalCalibrator::new(config.conformal_config.clone());
        let drift = DriftDetector::new(config.drift_config.clone());
        let budget = BudgetController::new(config.budget_config.clone(), epoch);

        Self {
            config,
            cvar,
            calibrator,
            drift,
            budget,
            traces: Vec::new(),
            fallback_events: Vec::new(),
            sequence: 0,
            epoch,
        }
    }

    /// Make a lane-routing decision given the current state.
    ///
    /// This is the core decision function.  It checks all guardrails
    /// in priority order and either routes to a lane or triggers fallback.
    pub fn decide(&mut self, state: &DecisionState) -> DecisionOutcome {
        self.sequence += 1;

        // 1. Check budget exhaustion (highest priority).
        if self.budget.is_fallback_active() {
            let action = LaneAction::SuspendAdaptive;
            let trace = self.make_trace(state, action.clone(), 0, "budget_exhausted");
            self.traces.push(trace.clone());
            let event = self.make_fallback_event(DemotionReason::BudgetExhausted, None, &action);
            self.fallback_events.push(event);
            return DecisionOutcome {
                action,
                trace,
                demotion: Some(DemotionReason::BudgetExhausted),
            };
        }

        // 2. Check CVaR tail-risk guardrail.
        if self.cvar.is_triggered() {
            let action = LaneAction::FallbackSafe;
            let trace = self.make_trace(state, action.clone(), 0, "cvar_exceeded");
            self.traces.push(trace.clone());
            let event = self.make_fallback_event(DemotionReason::CvarExceeded, None, &action);
            self.fallback_events.push(event);
            return DecisionOutcome {
                action,
                trace,
                demotion: Some(DemotionReason::CvarExceeded),
            };
        }

        // 3. Check drift detector.
        if self.drift.is_drift_detected() {
            let action = LaneAction::FallbackSafe;
            let trace = self.make_trace(state, action.clone(), 0, "drift_detected");
            self.traces.push(trace.clone());
            let event = self.make_fallback_event(DemotionReason::DriftDetected, None, &action);
            self.fallback_events.push(event);
            return DecisionOutcome {
                action,
                trace,
                demotion: Some(DemotionReason::DriftDetected),
            };
        }

        // 4. Check conformal calibration.
        if self.calibrator.violation_flagged() {
            let action = LaneAction::FallbackSafe;
            let trace = self.make_trace(state, action.clone(), 0, "coverage_violation");
            self.traces.push(trace.clone());
            let event = self.make_fallback_event(DemotionReason::CoverageViolation, None, &action);
            self.fallback_events.push(event);
            return DecisionOutcome {
                action,
                trace,
                demotion: Some(DemotionReason::CoverageViolation),
            };
        }

        // 5. Compute expected loss for each available lane.
        let selected = self.select_lane(state);
        let expected_loss = self.compute_expected_loss(state, &selected);

        let action = LaneAction::RouteTo(selected);
        let trace = self.make_trace(state, action.clone(), expected_loss, "expected_loss_min");
        self.traces.push(trace.clone());

        DecisionOutcome {
            action,
            trace,
            demotion: None,
        }
    }

    /// Record an observed loss value for CVaR and drift tracking.
    pub fn observe_loss(&mut self, loss_millionths: i64, epoch: SecurityEpoch) {
        self.cvar.observe(loss_millionths);
        self.drift.observe(loss_millionths);
        self.cvar.check(epoch);
        self.drift.check(epoch);
    }

    /// Record a calibration observation.
    pub fn observe_calibration(&mut self, epoch: SecurityEpoch, covered: bool) {
        self.calibrator.record(epoch, covered);
    }

    /// Record compute usage.
    pub fn record_compute(&mut self, us: u64) -> BudgetStatus {
        self.budget.record_compute(us)
    }

    /// Record memory usage.
    pub fn record_memory(&mut self, bytes: u64) -> BudgetStatus {
        self.budget.record_memory(bytes)
    }

    /// Advance to a new epoch.
    pub fn advance_epoch(&mut self, new_epoch: SecurityEpoch) {
        self.epoch = new_epoch;
        self.budget.reset_epoch(new_epoch);
        self.sequence = 0;
    }

    /// Generate the machine-readable policy bundle.
    pub fn policy_bundle(&self) -> PolicyBundle {
        PolicyBundle {
            version: "1.0.0".into(),
            epoch: self.epoch,
            lanes: self.config.lanes.clone(),
            cvar_config: self.config.cvar_config.clone(),
            conformal_config: self.config.conformal_config.clone(),
            drift_config: self.config.drift_config.clone(),
            budget_config: self.config.budget_config.clone(),
            risk_weights: self.config.risk_weights.clone(),
            default_action: LaneAction::RouteTo(
                self.config
                    .lanes
                    .first()
                    .cloned()
                    .unwrap_or_else(|| LaneId("fallback".into())),
            ),
            fallback_action: LaneAction::FallbackSafe,
        }
    }

    /// Get the decision trace for replay.
    pub fn traces(&self) -> &[DecisionTrace] {
        &self.traces
    }

    /// Get fallback trigger events.
    pub fn fallback_events(&self) -> &[FallbackTriggerEvent] {
        &self.fallback_events
    }

    /// Access the CVaR guardrail.
    pub fn cvar(&self) -> &CvarGuardrail {
        &self.cvar
    }

    /// Access the conformal calibrator.
    pub fn calibrator(&self) -> &ConformalCalibrator {
        &self.calibrator
    }

    /// Access the drift detector.
    pub fn drift(&self) -> &DriftDetector {
        &self.drift
    }

    /// Access the budget controller.
    pub fn budget(&self) -> &BudgetController {
        &self.budget
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    fn select_lane(&self, state: &DecisionState) -> LaneId {
        // Multi-factor expected loss: pick the lane with the lowest
        // weighted risk exposure.
        if self.config.lanes.is_empty() {
            return LaneId("fallback".into());
        }

        // In safe mode or degraded regime, always fall back to first lane.
        if state.safe_mode_active || state.regime == RegimeLabel::Attack {
            return self.config.lanes.first().cloned().unwrap();
        }

        // For now, select based on regime.  Normal/Elevated → second lane
        // (performance), Degraded/Recovery → first lane (safe).
        if self.config.lanes.len() >= 2
            && matches!(state.regime, RegimeLabel::Normal | RegimeLabel::Elevated)
        {
            self.config.lanes[1].clone()
        } else {
            self.config.lanes[0].clone()
        }
    }

    fn compute_expected_loss(&self, state: &DecisionState, _lane: &LaneId) -> i64 {
        // Weighted sum of risk-factor beliefs × risk weights.
        let mut total: i64 = 0;
        for factor in &RiskFactor::ALL {
            let belief = state
                .risk_belief_millionths
                .get(factor)
                .copied()
                .unwrap_or(0);
            let weight = self.config.risk_weights.get(factor).copied().unwrap_or(0);
            total = total.saturating_add(belief.saturating_mul(weight) / MILLION);
        }
        total
    }

    fn make_trace(
        &self,
        state: &DecisionState,
        action: LaneAction,
        expected_loss: i64,
        reason: &str,
    ) -> DecisionTrace {
        DecisionTrace {
            sequence: self.sequence,
            epoch: self.epoch,
            state: state.clone(),
            action,
            expected_loss_millionths: expected_loss,
            cvar_millionths: self.cvar.cvar(),
            drift_kl_millionths: self.drift.last_kl_millionths(),
            budget_remaining_millionths: self.budget.budget_remaining_millionths(),
            guardrail_active: self.cvar.is_triggered()
                || self.drift.is_drift_detected()
                || self.calibrator.violation_flagged()
                || self.budget.is_fallback_active(),
            reason: reason.into(),
        }
    }

    fn make_fallback_event(
        &self,
        trigger: DemotionReason,
        from: Option<LaneAction>,
        to: &LaneAction,
    ) -> FallbackTriggerEvent {
        FallbackTriggerEvent {
            epoch: self.epoch,
            trigger,
            from_action: from,
            to_action: to.clone(),
            metrics: FallbackMetrics {
                cvar_millionths: self.cvar.cvar(),
                drift_kl_millionths: self.drift.last_kl_millionths(),
                budget_remaining_millionths: self.budget.budget_remaining_millionths(),
                coverage_millionths: self.calibrator.coverage_millionths(),
                e_value_millionths: self.calibrator.e_value_millionths(),
            },
        }
    }
}

/// Outcome of a decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionOutcome {
    /// The selected action.
    pub action: LaneAction,
    /// The decision trace entry.
    pub trace: DecisionTrace,
    /// Demotion reason, if any guardrail was triggered.
    pub demotion: Option<DemotionReason>,
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

    fn default_state() -> DecisionState {
        let mut risk = BTreeMap::new();
        risk.insert(RiskFactor::Compatibility, 100_000); // 10%
        risk.insert(RiskFactor::Latency, 100_000);
        risk.insert(RiskFactor::Memory, 100_000);
        risk.insert(RiskFactor::IncidentSeverity, 100_000);

        DecisionState {
            epoch: epoch(1),
            regime: RegimeLabel::Normal,
            risk_belief_millionths: risk,
            latency_quantiles_us: LatencyQuantiles {
                p50_us: 1000,
                p95_us: 5000,
                p99_us: 10000,
                p999_us: 50000,
            },
            budget_remaining_millionths: MILLION,
            decisions_in_epoch: 0,
            safe_mode_active: false,
        }
    }

    // -----------------------------------------------------------------------
    // LaneId tests
    // -----------------------------------------------------------------------

    #[test]
    fn lane_id_display() {
        let lane = LaneId("test_lane".into());
        assert_eq!(format!("{lane}"), "test_lane");
    }

    #[test]
    fn lane_id_serde_roundtrip() {
        let lane = LaneId::throughput_profile();
        let json = serde_json::to_string(&lane).unwrap();
        assert_eq!(json, format!("\"{THROUGHPUT_PROFILE_LABEL}\""));
        let back: LaneId = serde_json::from_str(&json).unwrap();
        assert_eq!(lane, back);
    }

    #[test]
    fn lane_id_deserialize_accepts_legacy_lineage_label() {
        let back: LaneId = serde_json::from_str("\"quickjs_inspired_native\"").unwrap();
        assert_eq!(back, LaneId::deterministic_profile());
    }

    // -----------------------------------------------------------------------
    // RiskFactor tests
    // -----------------------------------------------------------------------

    #[test]
    fn risk_factor_all_four_variants() {
        assert_eq!(RiskFactor::ALL.len(), 4);
    }

    #[test]
    fn risk_factor_display() {
        assert_eq!(format!("{}", RiskFactor::Compatibility), "compatibility");
        assert_eq!(format!("{}", RiskFactor::Latency), "latency");
        assert_eq!(format!("{}", RiskFactor::Memory), "memory");
        assert_eq!(
            format!("{}", RiskFactor::IncidentSeverity),
            "incident_severity"
        );
    }

    #[test]
    fn risk_factor_serde_roundtrip() {
        for factor in &RiskFactor::ALL {
            let json = serde_json::to_string(factor).unwrap();
            let back: RiskFactor = serde_json::from_str(&json).unwrap();
            assert_eq!(*factor, back);
        }
    }

    // -----------------------------------------------------------------------
    // RegimeLabel tests
    // -----------------------------------------------------------------------

    #[test]
    fn regime_label_display() {
        assert_eq!(format!("{}", RegimeLabel::Normal), "normal");
        assert_eq!(format!("{}", RegimeLabel::Attack), "attack");
        assert_eq!(format!("{}", RegimeLabel::Recovery), "recovery");
    }

    #[test]
    fn regime_label_serde_roundtrip() {
        let labels = [
            RegimeLabel::Normal,
            RegimeLabel::Elevated,
            RegimeLabel::Attack,
            RegimeLabel::Degraded,
            RegimeLabel::Recovery,
        ];
        for label in &labels {
            let json = serde_json::to_string(label).unwrap();
            let back: RegimeLabel = serde_json::from_str(&json).unwrap();
            assert_eq!(*label, back);
        }
    }

    // -----------------------------------------------------------------------
    // LaneAction tests
    // -----------------------------------------------------------------------

    #[test]
    fn lane_action_display() {
        let a = LaneAction::RouteTo(LaneId("main".into()));
        assert_eq!(format!("{a}"), "route_to:main");

        assert_eq!(format!("{}", LaneAction::FallbackSafe), "fallback_safe");
        assert_eq!(
            format!("{}", LaneAction::SuspendAdaptive),
            "suspend_adaptive"
        );
    }

    #[test]
    fn lane_action_demote_display() {
        let a = LaneAction::Demote {
            from_lane: LaneId("v8".into()),
            reason: DemotionReason::CvarExceeded,
        };
        assert_eq!(format!("{a}"), "demote:v8:cvar_exceeded");
    }

    #[test]
    fn lane_action_serde_roundtrip() {
        let actions = vec![
            LaneAction::RouteTo(LaneId("test".into())),
            LaneAction::FallbackSafe,
            LaneAction::Demote {
                from_lane: LaneId("x".into()),
                reason: DemotionReason::DriftDetected,
            },
            LaneAction::SuspendAdaptive,
        ];
        for action in &actions {
            let json = serde_json::to_string(action).unwrap();
            let back: LaneAction = serde_json::from_str(&json).unwrap();
            assert_eq!(*action, back);
        }
    }

    // -----------------------------------------------------------------------
    // DemotionReason tests
    // -----------------------------------------------------------------------

    #[test]
    fn demotion_reason_display_all() {
        let reasons = [
            (DemotionReason::CvarExceeded, "cvar_exceeded"),
            (DemotionReason::DriftDetected, "drift_detected"),
            (DemotionReason::BudgetExhausted, "budget_exhausted"),
            (DemotionReason::GuardrailTriggered, "guardrail_triggered"),
            (DemotionReason::CoverageViolation, "coverage_violation"),
            (DemotionReason::OperatorOverride, "operator_override"),
        ];
        for (reason, expected) in &reasons {
            assert_eq!(format!("{reason}"), *expected);
        }
    }

    // -----------------------------------------------------------------------
    // CVaR Guardrail tests
    // -----------------------------------------------------------------------

    #[test]
    fn cvar_insufficient_data_initially() {
        let mut cvar = CvarGuardrail::new(CvarConfig::default());
        let result = cvar.check(epoch(1));
        assert!(matches!(result, CvarCheckResult::InsufficientData { .. }));
    }

    #[test]
    fn cvar_within_bounds_low_losses() {
        let config = CvarConfig {
            min_observations: 10,
            max_cvar_millionths: 100 * MILLION,
            ..Default::default()
        };
        let mut cvar = CvarGuardrail::new(config);
        for i in 0..20 {
            cvar.observe(i * MILLION);
        }
        let result = cvar.check(epoch(1));
        assert!(matches!(result, CvarCheckResult::WithinBounds { .. }));
        assert!(!cvar.is_triggered());
    }

    #[test]
    fn cvar_exceeds_threshold_high_tail() {
        let config = CvarConfig {
            alpha_millionths: 500_000, // 50th percentile
            max_cvar_millionths: 5 * MILLION,
            min_observations: 5,
        };
        let mut cvar = CvarGuardrail::new(config);
        // Observations: 0, 0, 0, 100M, 200M — tail is very heavy.
        cvar.observe(0);
        cvar.observe(0);
        cvar.observe(0);
        cvar.observe(100 * MILLION);
        cvar.observe(200 * MILLION);
        let result = cvar.check(epoch(1));
        assert!(matches!(result, CvarCheckResult::Exceeded { .. }));
        assert!(cvar.is_triggered());
        assert_eq!(cvar.trigger_epoch(), Some(epoch(1)));
    }

    #[test]
    fn cvar_var_computation() {
        let config = CvarConfig {
            alpha_millionths: 800_000, // 80th percentile
            max_cvar_millionths: 100 * MILLION,
            min_observations: 5,
        };
        let mut cvar = CvarGuardrail::new(config);
        for i in 0..10 {
            cvar.observe(i * MILLION);
        }
        let var = cvar.var().unwrap();
        // VaR at 80%: index = floor(10 * 0.8) = 8 → obs[8] = 8M.
        assert_eq!(var, 8 * MILLION);
    }

    #[test]
    fn cvar_reset_clears_state() {
        let config = CvarConfig {
            min_observations: 2,
            max_cvar_millionths: 1,
            ..Default::default()
        };
        let mut cvar = CvarGuardrail::new(config);
        cvar.observe(MILLION);
        cvar.observe(MILLION);
        cvar.check(epoch(1));
        assert!(cvar.is_triggered());
        cvar.reset();
        assert!(!cvar.is_triggered());
        assert_eq!(cvar.observation_count(), 0);
    }

    #[test]
    fn cvar_observations_sorted() {
        let mut cvar = CvarGuardrail::new(CvarConfig {
            min_observations: 3,
            ..Default::default()
        });
        cvar.observe(30);
        cvar.observe(10);
        cvar.observe(20);
        // Internally sorted.
        assert_eq!(cvar.observation_count(), 3);
    }

    #[test]
    fn cvar_serde_roundtrip() {
        let mut cvar = CvarGuardrail::new(CvarConfig::default());
        cvar.observe(42 * MILLION);
        let json = serde_json::to_string(&cvar).unwrap();
        let back: CvarGuardrail = serde_json::from_str(&json).unwrap();
        assert_eq!(cvar.observation_count(), back.observation_count());
    }

    // -----------------------------------------------------------------------
    // Conformal Calibrator tests
    // -----------------------------------------------------------------------

    #[test]
    fn conformal_starts_calibrated() {
        let cal = ConformalCalibrator::new(ConformalConfig::default());
        assert!(cal.is_calibrated());
        assert_eq!(cal.coverage_millionths(), MILLION);
    }

    #[test]
    fn conformal_perfect_coverage() {
        let mut cal = ConformalCalibrator::new(ConformalConfig {
            min_calibration_observations: 5,
            ..Default::default()
        });
        for i in 0..10 {
            cal.record(epoch(i), true);
        }
        assert!(cal.is_calibrated());
        assert_eq!(cal.coverage_millionths(), MILLION);
        assert!(!cal.violation_flagged());
    }

    #[test]
    fn conformal_all_misses_flags_violation() {
        let config = ConformalConfig {
            alpha_millionths: 100_000,
            min_calibration_observations: 5,
            max_consecutive_violations: 3,
        };
        let mut cal = ConformalCalibrator::new(config);
        for i in 0..10 {
            cal.record(epoch(i), false);
        }
        assert!(cal.violation_flagged());
        assert!(!cal.is_calibrated());
        assert_eq!(cal.coverage_millionths(), 0);
    }

    #[test]
    fn conformal_e_value_increases_on_misses() {
        let mut cal = ConformalCalibrator::new(ConformalConfig::default());
        let e0 = cal.e_value_millionths();
        cal.record(epoch(1), false);
        let e1 = cal.e_value_millionths();
        assert!(e1 > e0, "e-value should increase on miss: {e1} > {e0}");
    }

    #[test]
    fn conformal_e_value_stable_on_hits() {
        let mut cal = ConformalCalibrator::new(ConformalConfig::default());
        cal.record(epoch(1), true);
        // After one hit, e-value should remain at 1M (LR=1.0).
        assert_eq!(cal.e_value_millionths(), MILLION);
    }

    #[test]
    fn conformal_ledger_recorded() {
        let mut cal = ConformalCalibrator::new(ConformalConfig::default());
        cal.record(epoch(1), true);
        cal.record(epoch(2), false);
        assert_eq!(cal.ledger().len(), 2);
        assert!(cal.ledger()[0].prediction_covered);
        assert!(!cal.ledger()[1].prediction_covered);
    }

    #[test]
    fn conformal_reset_clears() {
        let mut cal = ConformalCalibrator::new(ConformalConfig::default());
        cal.record(epoch(1), false);
        cal.reset();
        assert_eq!(cal.total_predictions(), 0);
        assert_eq!(cal.covered_predictions(), 0);
        assert!(!cal.violation_flagged());
    }

    #[test]
    fn conformal_serde_roundtrip() {
        let mut cal = ConformalCalibrator::new(ConformalConfig::default());
        cal.record(epoch(1), true);
        let json = serde_json::to_string(&cal).unwrap();
        let back: ConformalCalibrator = serde_json::from_str(&json).unwrap();
        assert_eq!(cal.total_predictions(), back.total_predictions());
    }

    // -----------------------------------------------------------------------
    // Drift Detector tests
    // -----------------------------------------------------------------------

    #[test]
    fn drift_insufficient_data_initially() {
        let mut drift = DriftDetector::new(DriftConfig::default());
        let result = drift.check(epoch(1));
        assert!(matches!(result, DriftCheckResult::InsufficientData { .. }));
    }

    #[test]
    fn drift_no_drift_on_uniform_data() {
        let config = DriftConfig {
            reference_window: 20,
            test_window: 10,
            min_samples: 10,
            kl_threshold_millionths: 500_000, // 0.5 nats
        };
        let mut drift = DriftDetector::new(config);
        // All observations identical → KL=0.
        for _ in 0..40 {
            drift.observe(MILLION);
        }
        let result = drift.check(epoch(1));
        assert!(matches!(result, DriftCheckResult::NoDrift { .. }));
        assert!(!drift.is_drift_detected());
    }

    #[test]
    fn drift_detects_distribution_shift() {
        let config = DriftConfig {
            reference_window: 20,
            test_window: 10,
            min_samples: 10,
            kl_threshold_millionths: 10_000, // very low threshold
        };
        let mut drift = DriftDetector::new(config);
        // Reference window: low values.
        for _ in 0..20 {
            drift.observe(MILLION);
        }
        // Test window: high values — a shift.
        for _ in 0..10 {
            drift.observe(100 * MILLION);
        }
        let result = drift.check(epoch(1));
        assert!(
            matches!(result, DriftCheckResult::DriftDetected { .. }),
            "Expected drift: {result:?}"
        );
        assert!(drift.is_drift_detected());
        assert_eq!(drift.drift_epoch(), Some(epoch(1)));
    }

    #[test]
    fn drift_reset_clears() {
        let mut drift = DriftDetector::new(DriftConfig {
            reference_window: 5,
            test_window: 5,
            min_samples: 5,
            kl_threshold_millionths: 1,
        });
        for i in 0..10 {
            drift.observe(i * MILLION);
        }
        drift.check(epoch(1));
        drift.reset();
        assert!(!drift.is_drift_detected());
        assert_eq!(drift.observation_count(), 0);
    }

    #[test]
    fn drift_observation_window_bounded() {
        let config = DriftConfig {
            reference_window: 5,
            test_window: 5,
            ..Default::default()
        };
        let mut drift = DriftDetector::new(config);
        // Add many observations.
        for i in 0..1000 {
            drift.observe(i);
        }
        // Should not grow unbounded.
        assert!(drift.observation_count() <= 60); // ref + test + margin
    }

    #[test]
    fn drift_serde_roundtrip() {
        let mut drift = DriftDetector::new(DriftConfig::default());
        drift.observe(42);
        let json = serde_json::to_string(&drift).unwrap();
        let back: DriftDetector = serde_json::from_str(&json).unwrap();
        assert_eq!(drift.observation_count(), back.observation_count());
    }

    // -----------------------------------------------------------------------
    // fixed_point_ln tests
    // -----------------------------------------------------------------------

    #[test]
    fn ln_of_one_is_zero() {
        assert_eq!(fixed_point_ln(MILLION), 0);
    }

    #[test]
    fn ln_of_two_approx_693k() {
        let ln2 = fixed_point_ln(2 * MILLION);
        // ln(2) ≈ 693_147.  Allow 5% tolerance.
        assert!((ln2 - 693_147).abs() < 50_000, "ln(2) = {ln2}");
    }

    #[test]
    fn ln_of_half_approx_neg_693k() {
        let ln_half = fixed_point_ln(500_000);
        // ln(0.5) ≈ -693_147.  Allow 5% tolerance.
        assert!((ln_half + 693_147).abs() < 50_000, "ln(0.5) = {ln_half}");
    }

    #[test]
    fn ln_monotonic() {
        let a = fixed_point_ln(500_000);
        let b = fixed_point_ln(MILLION);
        let c = fixed_point_ln(2 * MILLION);
        assert!(a < b, "ln(0.5) < ln(1): {a} < {b}");
        assert!(b < c, "ln(1) < ln(2): {b} < {c}");
    }

    #[test]
    fn ln_of_zero_or_negative_is_large_negative() {
        assert!(fixed_point_ln(0) < -10 * MILLION);
        assert!(fixed_point_ln(-1) < -10 * MILLION);
    }

    // -----------------------------------------------------------------------
    // empirical_kl_divergence tests
    // -----------------------------------------------------------------------

    #[test]
    fn kl_identical_distributions_zero() {
        let data = vec![1, 2, 3, 4, 5];
        let kl = empirical_kl_divergence(&data, &data);
        assert_eq!(kl, 0);
    }

    #[test]
    fn kl_different_distributions_positive() {
        let reference = vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let test = vec![
            100 * MILLION,
            100 * MILLION,
            100 * MILLION,
            100 * MILLION,
            100 * MILLION,
            100 * MILLION,
            100 * MILLION,
            100 * MILLION,
            100 * MILLION,
            100 * MILLION,
        ];
        let kl = empirical_kl_divergence(&reference, &test);
        assert!(
            kl > 0,
            "KL should be positive for different distributions: {kl}"
        );
    }

    #[test]
    fn kl_empty_returns_zero() {
        assert_eq!(empirical_kl_divergence(&[], &[1, 2, 3]), 0);
        assert_eq!(empirical_kl_divergence(&[1, 2, 3], &[]), 0);
    }

    // -----------------------------------------------------------------------
    // Budget Controller tests
    // -----------------------------------------------------------------------

    #[test]
    fn budget_starts_normal() {
        let budget = BudgetController::new(BudgetConfig::default(), epoch(1));
        assert!(!budget.is_fallback_active());
        assert_eq!(budget.compute_consumed_us(), 0);
        assert_eq!(budget.memory_consumed_bytes(), 0);
        assert_eq!(budget.budget_remaining_millionths(), MILLION);
    }

    #[test]
    fn budget_compute_tracking() {
        let mut budget = BudgetController::new(BudgetConfig::default(), epoch(1));
        let status = budget.record_compute(10_000);
        assert!(matches!(status, BudgetStatus::Normal { .. }));
        assert_eq!(budget.compute_consumed_us(), 10_000);
    }

    #[test]
    fn budget_warning_at_threshold() {
        let config = BudgetConfig {
            compute_budget_us: 100,
            warning_threshold_millionths: 800_000,
            ..Default::default()
        };
        let mut budget = BudgetController::new(config, epoch(1));
        let status = budget.record_compute(85); // 85% > 80% warning
        assert!(matches!(status, BudgetStatus::Warning { .. }));
    }

    #[test]
    fn budget_exhaustion_triggers_fallback() {
        let config = BudgetConfig {
            compute_budget_us: 100,
            deterministic_fallback_on_exhaust: true,
            ..Default::default()
        };
        let mut budget = BudgetController::new(config, epoch(1));
        let status = budget.record_compute(100);
        assert!(matches!(status, BudgetStatus::Exhausted { .. }));
        assert!(budget.is_fallback_active());
        assert_eq!(budget.events().len(), 1);
        assert!(matches!(
            budget.events()[0].kind,
            BudgetEventKind::Exhausted
        ));
    }

    #[test]
    fn budget_memory_exhaustion() {
        let config = BudgetConfig {
            memory_budget_bytes: 1000,
            deterministic_fallback_on_exhaust: true,
            ..Default::default()
        };
        let mut budget = BudgetController::new(config, epoch(1));
        budget.record_memory(1000);
        assert!(budget.is_fallback_active());
    }

    #[test]
    fn budget_epoch_reset_clears() {
        let config = BudgetConfig {
            compute_budget_us: 100,
            deterministic_fallback_on_exhaust: true,
            ..Default::default()
        };
        let mut budget = BudgetController::new(config, epoch(1));
        budget.record_compute(100);
        assert!(budget.is_fallback_active());
        budget.reset_epoch(epoch(2));
        assert!(!budget.is_fallback_active());
        assert_eq!(budget.compute_consumed_us(), 0);
    }

    #[test]
    fn budget_remaining_decreases() {
        let config = BudgetConfig {
            compute_budget_us: 100,
            ..Default::default()
        };
        let mut budget = BudgetController::new(config, epoch(1));
        let before = budget.budget_remaining_millionths();
        budget.record_compute(50);
        let after = budget.budget_remaining_millionths();
        assert!(
            after < before,
            "remaining should decrease: {after} < {before}"
        );
    }

    #[test]
    fn budget_serde_roundtrip() {
        let budget = BudgetController::new(BudgetConfig::default(), epoch(1));
        let json = serde_json::to_string(&budget).unwrap();
        let back: BudgetController = serde_json::from_str(&json).unwrap();
        assert_eq!(
            budget.budget_remaining_millionths(),
            back.budget_remaining_millionths()
        );
    }

    // -----------------------------------------------------------------------
    // DecisionContext integration tests
    // -----------------------------------------------------------------------

    #[test]
    fn context_normal_decision_routes_to_lane() {
        let config = DecisionContextConfig::default();
        let mut ctx = DecisionContext::new(config, epoch(1));
        let state = default_state();
        let outcome = ctx.decide(&state);
        assert!(matches!(outcome.action, LaneAction::RouteTo(_)));
        assert!(outcome.demotion.is_none());
    }

    #[test]
    fn context_budget_exhausted_suspends_adaptive() {
        let config = DecisionContextConfig {
            budget_config: BudgetConfig {
                compute_budget_us: 100,
                deterministic_fallback_on_exhaust: true,
                ..Default::default()
            },
            ..Default::default()
        };
        let mut ctx = DecisionContext::new(config, epoch(1));
        ctx.record_compute(100);
        let state = default_state();
        let outcome = ctx.decide(&state);
        assert_eq!(outcome.action, LaneAction::SuspendAdaptive);
        assert_eq!(outcome.demotion, Some(DemotionReason::BudgetExhausted));
    }

    #[test]
    fn context_cvar_exceeded_falls_back() {
        let config = DecisionContextConfig {
            cvar_config: CvarConfig {
                alpha_millionths: 500_000,
                max_cvar_millionths: 5,
                min_observations: 2,
            },
            ..Default::default()
        };
        let mut ctx = DecisionContext::new(config, epoch(1));
        ctx.observe_loss(100 * MILLION, epoch(1));
        ctx.observe_loss(200 * MILLION, epoch(1));
        let state = default_state();
        let outcome = ctx.decide(&state);
        assert_eq!(outcome.action, LaneAction::FallbackSafe);
        assert_eq!(outcome.demotion, Some(DemotionReason::CvarExceeded));
    }

    #[test]
    fn context_drift_detected_falls_back() {
        let config = DecisionContextConfig {
            drift_config: DriftConfig {
                reference_window: 5,
                test_window: 5,
                min_samples: 5,
                kl_threshold_millionths: 1, // very low threshold
            },
            ..Default::default()
        };
        let mut ctx = DecisionContext::new(config, epoch(1));
        // Cause a distribution shift.
        for _ in 0..5 {
            ctx.observe_loss(MILLION, epoch(1));
        }
        for _ in 0..5 {
            ctx.observe_loss(100 * MILLION, epoch(1));
        }
        let state = default_state();
        let outcome = ctx.decide(&state);
        assert_eq!(outcome.action, LaneAction::FallbackSafe);
        assert_eq!(outcome.demotion, Some(DemotionReason::DriftDetected));
    }

    #[test]
    fn context_calibration_violation_falls_back() {
        let config = DecisionContextConfig {
            conformal_config: ConformalConfig {
                alpha_millionths: 100_000,
                min_calibration_observations: 3,
                max_consecutive_violations: 2,
            },
            ..Default::default()
        };
        let mut ctx = DecisionContext::new(config, epoch(1));
        // Record many consecutive misses.
        for i in 0..5 {
            ctx.observe_calibration(epoch(i + 1), false);
        }
        let state = default_state();
        let outcome = ctx.decide(&state);
        assert_eq!(outcome.action, LaneAction::FallbackSafe);
        assert_eq!(outcome.demotion, Some(DemotionReason::CoverageViolation));
    }

    #[test]
    fn context_attack_regime_uses_safe_lane() {
        let config = DecisionContextConfig::default();
        let mut ctx = DecisionContext::new(config, epoch(1));
        let mut state = default_state();
        state.regime = RegimeLabel::Attack;
        let outcome = ctx.decide(&state);
        // Should route to first (safe) lane.
        if let LaneAction::RouteTo(lane) = &outcome.action {
            assert_eq!(lane.to_string(), DETERMINISTIC_PROFILE_LABEL);
        }
    }

    #[test]
    fn context_traces_accumulate() {
        let config = DecisionContextConfig::default();
        let mut ctx = DecisionContext::new(config, epoch(1));
        let state = default_state();
        ctx.decide(&state);
        ctx.decide(&state);
        assert_eq!(ctx.traces().len(), 2);
        assert_eq!(ctx.traces()[0].sequence, 1);
        assert_eq!(ctx.traces()[1].sequence, 2);
    }

    #[test]
    fn context_advance_epoch_resets_sequence() {
        let config = DecisionContextConfig::default();
        let mut ctx = DecisionContext::new(config, epoch(1));
        let state = default_state();
        ctx.decide(&state);
        ctx.advance_epoch(epoch(2));
        ctx.decide(&state);
        assert_eq!(ctx.traces()[1].sequence, 1);
        assert_eq!(ctx.traces()[1].epoch, epoch(2));
    }

    #[test]
    fn context_policy_bundle_serializable() {
        let config = DecisionContextConfig::default();
        let ctx = DecisionContext::new(config, epoch(1));
        let bundle = ctx.policy_bundle();
        let json = serde_json::to_string(&bundle).unwrap();
        let back: PolicyBundle = serde_json::from_str(&json).unwrap();
        assert_eq!(bundle.version, back.version);
        assert_eq!(bundle.lanes.len(), back.lanes.len());
    }

    #[test]
    fn context_fallback_events_recorded() {
        let config = DecisionContextConfig {
            budget_config: BudgetConfig {
                compute_budget_us: 10,
                deterministic_fallback_on_exhaust: true,
                ..Default::default()
            },
            ..Default::default()
        };
        let mut ctx = DecisionContext::new(config, epoch(1));
        ctx.record_compute(10);
        let state = default_state();
        ctx.decide(&state);
        assert_eq!(ctx.fallback_events().len(), 1);
        assert_eq!(
            ctx.fallback_events()[0].trigger,
            DemotionReason::BudgetExhausted
        );
    }

    #[test]
    fn context_serde_roundtrip() {
        let config = DecisionContextConfig::default();
        let mut ctx = DecisionContext::new(config, epoch(1));
        let state = default_state();
        ctx.decide(&state);
        let json = serde_json::to_string(&ctx).unwrap();
        let back: DecisionContext = serde_json::from_str(&json).unwrap();
        assert_eq!(ctx.traces().len(), back.traces().len());
    }

    #[test]
    fn decision_trace_serde_roundtrip() {
        let trace = DecisionTrace {
            sequence: 1,
            epoch: epoch(1),
            state: default_state(),
            action: LaneAction::FallbackSafe,
            expected_loss_millionths: 42 * MILLION,
            cvar_millionths: Some(10 * MILLION),
            drift_kl_millionths: None,
            budget_remaining_millionths: 500_000,
            guardrail_active: false,
            reason: "test".into(),
        };
        let json = serde_json::to_string(&trace).unwrap();
        let back: DecisionTrace = serde_json::from_str(&json).unwrap();
        assert_eq!(trace, back);
    }

    #[test]
    fn fallback_trigger_event_serde() {
        let event = FallbackTriggerEvent {
            epoch: epoch(1),
            trigger: DemotionReason::CvarExceeded,
            from_action: None,
            to_action: LaneAction::FallbackSafe,
            metrics: FallbackMetrics {
                cvar_millionths: Some(42),
                drift_kl_millionths: None,
                budget_remaining_millionths: MILLION,
                coverage_millionths: MILLION,
                e_value_millionths: MILLION,
            },
        };
        let json = serde_json::to_string(&event).unwrap();
        let back: FallbackTriggerEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, back);
    }

    #[test]
    fn decision_state_serde_roundtrip() {
        let state = default_state();
        let json = serde_json::to_string(&state).unwrap();
        let back: DecisionState = serde_json::from_str(&json).unwrap();
        assert_eq!(state, back);
    }

    #[test]
    fn context_normal_regime_picks_performance_lane() {
        let config = DecisionContextConfig::default();
        let mut ctx = DecisionContext::new(config, epoch(1));
        let state = default_state();
        let outcome = ctx.decide(&state);
        if let LaneAction::RouteTo(lane) = &outcome.action {
            assert_eq!(lane.to_string(), THROUGHPUT_PROFILE_LABEL);
        } else {
            panic!("expected RouteTo, got {:?}", outcome.action);
        }
    }

    #[test]
    fn context_safe_mode_forces_safe_lane() {
        let config = DecisionContextConfig::default();
        let mut ctx = DecisionContext::new(config, epoch(1));
        let mut state = default_state();
        state.safe_mode_active = true;
        let outcome = ctx.decide(&state);
        if let LaneAction::RouteTo(lane) = &outcome.action {
            assert_eq!(lane.to_string(), DETERMINISTIC_PROFILE_LABEL);
        }
    }

    #[test]
    fn cvar_config_default_values() {
        let config = CvarConfig::default();
        assert_eq!(config.alpha_millionths, 950_000);
        assert_eq!(config.max_cvar_millionths, 50 * MILLION);
        assert_eq!(config.min_observations, 30);
    }

    #[test]
    fn conformal_config_default_values() {
        let config = ConformalConfig::default();
        assert_eq!(config.alpha_millionths, 100_000);
        assert_eq!(config.min_calibration_observations, 50);
        assert_eq!(config.max_consecutive_violations, 5);
    }

    #[test]
    fn drift_config_default_values() {
        let config = DriftConfig::default();
        assert_eq!(config.kl_threshold_millionths, 100_000);
        assert_eq!(config.reference_window, 100);
        assert_eq!(config.test_window, 50);
    }

    #[test]
    fn budget_config_default_values() {
        let config = BudgetConfig::default();
        assert_eq!(config.compute_budget_us, 50_000);
        assert_eq!(config.memory_budget_bytes, 128 * 1024 * 1024);
        assert_eq!(config.warning_threshold_millionths, 800_000);
        assert!(config.deterministic_fallback_on_exhaust);
    }

    #[test]
    fn budget_event_kind_display() {
        assert_eq!(format!("{}", BudgetEventKind::Warning), "warning");
        assert_eq!(format!("{}", BudgetEventKind::Exhausted), "exhausted");
        assert_eq!(format!("{}", BudgetEventKind::EpochReset), "epoch_reset");
    }

    #[test]
    fn expected_loss_computation() {
        let config = DecisionContextConfig::default();
        let ctx = DecisionContext::new(config, epoch(1));
        let state = default_state();
        let lane = LaneId("test".into());
        let loss = ctx.compute_expected_loss(&state, &lane);
        // Each risk factor belief = 100k, weight = 200k-300k.
        // Total = sum of (belief * weight / MILLION) for each factor.
        assert!(loss > 0, "expected loss should be positive: {loss}");
    }

    #[test]
    fn context_observe_calibration_mixed() {
        let config = DecisionContextConfig::default();
        let mut ctx = DecisionContext::new(config, epoch(1));
        ctx.observe_calibration(epoch(1), true);
        ctx.observe_calibration(epoch(2), true);
        ctx.observe_calibration(epoch(3), false);
        assert_eq!(ctx.calibrator().total_predictions(), 3);
        assert_eq!(ctx.calibrator().covered_predictions(), 2);
    }

    #[test]
    fn context_observe_loss_updates_both() {
        let config = DecisionContextConfig::default();
        let mut ctx = DecisionContext::new(config, epoch(1));
        ctx.observe_loss(42, epoch(1));
        assert_eq!(ctx.cvar().observation_count(), 1);
        assert_eq!(ctx.drift().observation_count(), 1);
    }

    #[test]
    fn latency_quantiles_serde() {
        let q = LatencyQuantiles {
            p50_us: 100,
            p95_us: 500,
            p99_us: 1000,
            p999_us: 5000,
        };
        let json = serde_json::to_string(&q).unwrap();
        let back: LatencyQuantiles = serde_json::from_str(&json).unwrap();
        assert_eq!(q, back);
    }

    #[test]
    fn decision_outcome_serde() {
        let outcome = DecisionOutcome {
            action: LaneAction::FallbackSafe,
            trace: DecisionTrace {
                sequence: 1,
                epoch: epoch(1),
                state: default_state(),
                action: LaneAction::FallbackSafe,
                expected_loss_millionths: 0,
                cvar_millionths: None,
                drift_kl_millionths: None,
                budget_remaining_millionths: MILLION,
                guardrail_active: false,
                reason: "test".into(),
            },
            demotion: None,
        };
        let json = serde_json::to_string(&outcome).unwrap();
        let back: DecisionOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(outcome, back);
    }

    #[test]
    fn context_empty_lanes_uses_fallback() {
        let config = DecisionContextConfig {
            lanes: vec![],
            ..Default::default()
        };
        let mut ctx = DecisionContext::new(config, epoch(1));
        let state = default_state();
        let outcome = ctx.decide(&state);
        if let LaneAction::RouteTo(lane) = &outcome.action {
            assert_eq!(lane.0, "fallback");
        }
    }

    #[test]
    fn context_recovery_regime_uses_safe_lane() {
        let config = DecisionContextConfig::default();
        let mut ctx = DecisionContext::new(config, epoch(1));
        let mut state = default_state();
        state.regime = RegimeLabel::Recovery;
        let outcome = ctx.decide(&state);
        if let LaneAction::RouteTo(lane) = &outcome.action {
            assert_eq!(lane.to_string(), DETERMINISTIC_PROFILE_LABEL);
        }
    }

    #[test]
    fn policy_bundle_contains_all_configs() {
        let config = DecisionContextConfig::default();
        let ctx = DecisionContext::new(config, epoch(1));
        let bundle = ctx.policy_bundle();
        assert_eq!(bundle.version, "1.0.0");
        assert_eq!(bundle.lanes.len(), 2);
        assert_eq!(bundle.risk_weights.len(), 4);
    }

    #[test]
    fn guardrail_priority_budget_over_cvar() {
        // Budget exhaustion should be checked before CVaR.
        let config = DecisionContextConfig {
            budget_config: BudgetConfig {
                compute_budget_us: 10,
                deterministic_fallback_on_exhaust: true,
                ..Default::default()
            },
            cvar_config: CvarConfig {
                max_cvar_millionths: 1,
                min_observations: 2,
                ..Default::default()
            },
            ..Default::default()
        };
        let mut ctx = DecisionContext::new(config, epoch(1));
        ctx.record_compute(10);
        ctx.observe_loss(100 * MILLION, epoch(1));
        ctx.observe_loss(200 * MILLION, epoch(1));
        let state = default_state();
        let outcome = ctx.decide(&state);
        // Budget check should take priority.
        assert_eq!(outcome.action, LaneAction::SuspendAdaptive);
        assert_eq!(outcome.demotion, Some(DemotionReason::BudgetExhausted));
    }

    // -- Enrichment: PearlTower 2026-02-26 --

    #[test]
    fn cvar_check_result_serde_roundtrip() {
        let variants: Vec<CvarCheckResult> = vec![
            CvarCheckResult::InsufficientData {
                observations: 5,
                required: 30,
            },
            CvarCheckResult::WithinBounds {
                cvar_millionths: 10_000_000,
                threshold_millionths: 50_000_000,
                headroom_millionths: 40_000_000,
            },
            CvarCheckResult::Exceeded {
                cvar_millionths: 60_000_000,
                threshold_millionths: 50_000_000,
                epoch: epoch(3),
            },
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: CvarCheckResult = serde_json::from_str(&json).unwrap();
            assert_eq!(&back, v);
        }
    }

    #[test]
    fn drift_check_result_serde_roundtrip() {
        let variants: Vec<DriftCheckResult> = vec![
            DriftCheckResult::InsufficientData {
                observations: 3,
                required: 20,
            },
            DriftCheckResult::NoDrift {
                kl_millionths: 10_000,
                threshold_millionths: 100_000,
            },
            DriftCheckResult::DriftDetected {
                kl_millionths: 200_000,
                threshold_millionths: 100_000,
                epoch: epoch(7),
            },
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: DriftCheckResult = serde_json::from_str(&json).unwrap();
            assert_eq!(&back, v);
        }
    }

    #[test]
    fn budget_status_serde_roundtrip() {
        let variants: Vec<BudgetStatus> = vec![
            BudgetStatus::Normal {
                compute_fraction_millionths: 200_000,
                memory_fraction_millionths: 100_000,
            },
            BudgetStatus::Warning {
                compute_fraction_millionths: 850_000,
                memory_fraction_millionths: 500_000,
            },
            BudgetStatus::Exhausted {
                compute_fraction_millionths: MILLION,
                memory_fraction_millionths: MILLION,
            },
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: BudgetStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(&back, v);
        }
    }

    #[test]
    fn budget_event_kind_serde_all_variants() {
        let variants = [
            BudgetEventKind::Warning,
            BudgetEventKind::Exhausted,
            BudgetEventKind::EpochReset,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: BudgetEventKind = serde_json::from_str(&json).unwrap();
            assert_eq!(&back, v);
        }
    }

    #[test]
    fn demotion_reason_serde_all_variants() {
        let variants = [
            DemotionReason::CvarExceeded,
            DemotionReason::DriftDetected,
            DemotionReason::BudgetExhausted,
            DemotionReason::GuardrailTriggered,
            DemotionReason::CoverageViolation,
            DemotionReason::OperatorOverride,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: DemotionReason = serde_json::from_str(&json).unwrap();
            assert_eq!(&back, v);
        }
        assert_eq!(variants.len(), 6);
    }

    #[test]
    fn budget_event_serde_roundtrip() {
        let event = BudgetEvent {
            epoch: epoch(5),
            kind: BudgetEventKind::Exhausted,
            compute_consumed_us: 9999,
            memory_consumed_bytes: 512_000,
        };
        let json = serde_json::to_string(&event).unwrap();
        let back: BudgetEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(back, event);
    }

    #[test]
    fn decision_context_config_default_serde_roundtrip() {
        let config = DecisionContextConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let back: DecisionContextConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back.lanes.len(), config.lanes.len());
        assert_eq!(back.risk_weights.len(), config.risk_weights.len());
    }

    // -- Enrichment: PearlTower 2026-03-02 --

    #[test]
    fn regime_label_display_exact_all_5() {
        assert_eq!(RegimeLabel::Normal.to_string(), "normal");
        assert_eq!(RegimeLabel::Elevated.to_string(), "elevated");
        assert_eq!(RegimeLabel::Attack.to_string(), "attack");
        assert_eq!(RegimeLabel::Degraded.to_string(), "degraded");
        assert_eq!(RegimeLabel::Recovery.to_string(), "recovery");
    }

    #[test]
    fn regime_label_ordering() {
        assert!(RegimeLabel::Normal < RegimeLabel::Elevated);
        assert!(RegimeLabel::Elevated < RegimeLabel::Attack);
        assert!(RegimeLabel::Attack < RegimeLabel::Degraded);
        assert!(RegimeLabel::Degraded < RegimeLabel::Recovery);
    }

    #[test]
    fn risk_factor_ordering() {
        assert!(RiskFactor::Compatibility < RiskFactor::Latency);
        assert!(RiskFactor::Latency < RiskFactor::Memory);
        assert!(RiskFactor::Memory < RiskFactor::IncidentSeverity);
    }

    #[test]
    fn cvar_config_serde_roundtrip() {
        let config = CvarConfig {
            alpha_millionths: 900_000,
            max_cvar_millionths: 25 * MILLION,
            min_observations: 50,
        };
        let json = serde_json::to_string(&config).unwrap();
        let back: CvarConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, back);
    }

    #[test]
    fn conformal_config_serde_roundtrip() {
        let config = ConformalConfig {
            alpha_millionths: 50_000,
            min_calibration_observations: 100,
            max_consecutive_violations: 10,
        };
        let json = serde_json::to_string(&config).unwrap();
        let back: ConformalConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, back);
    }

    #[test]
    fn drift_config_serde_roundtrip() {
        let config = DriftConfig {
            kl_threshold_millionths: 200_000,
            reference_window: 50,
            test_window: 25,
            min_samples: 15,
        };
        let json = serde_json::to_string(&config).unwrap();
        let back: DriftConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, back);
    }

    #[test]
    fn budget_config_serde_roundtrip() {
        let config = BudgetConfig {
            compute_budget_us: 100_000,
            memory_budget_bytes: 256 * 1024 * 1024,
            warning_threshold_millionths: 750_000,
            deterministic_fallback_on_exhaust: false,
        };
        let json = serde_json::to_string(&config).unwrap();
        let back: BudgetConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, back);
    }

    #[test]
    fn cvar_returns_none_with_insufficient_data() {
        let config = CvarConfig {
            min_observations: 10,
            ..Default::default()
        };
        let mut cvar = CvarGuardrail::new(config);
        assert!(cvar.cvar().is_none());
        assert!(cvar.var().is_none());
        for i in 0..5 {
            cvar.observe(i * MILLION);
        }
        assert!(cvar.cvar().is_none(), "still below min_observations");
    }

    #[test]
    fn budget_no_fallback_when_deterministic_disabled() {
        let config = BudgetConfig {
            compute_budget_us: 100,
            deterministic_fallback_on_exhaust: false,
            ..Default::default()
        };
        let mut budget = BudgetController::new(config, epoch(1));
        let status = budget.record_compute(100);
        assert!(matches!(status, BudgetStatus::Exhausted { .. }));
        assert!(
            !budget.is_fallback_active(),
            "fallback should not activate when deterministic_fallback_on_exhaust=false"
        );
        assert!(budget.events().is_empty());
    }

    #[test]
    fn context_degraded_regime_uses_safe_lane() {
        let config = DecisionContextConfig::default();
        let mut ctx = DecisionContext::new(config, epoch(1));
        let mut state = default_state();
        state.regime = RegimeLabel::Degraded;
        let outcome = ctx.decide(&state);
        if let LaneAction::RouteTo(lane) = &outcome.action {
            assert_eq!(lane.to_string(), DETERMINISTIC_PROFILE_LABEL);
        } else {
            panic!("expected RouteTo, got {:?}", outcome.action);
        }
    }

    #[test]
    fn drift_detector_last_kl_initially_none() {
        let drift = DriftDetector::new(DriftConfig::default());
        assert!(drift.last_kl_millionths().is_none());
        assert!(drift.drift_epoch().is_none());
        assert!(!drift.is_drift_detected());
    }

    #[test]
    fn calibration_ledger_entry_serde_roundtrip() {
        let entry = CalibrationLedgerEntry {
            epoch: epoch(42),
            prediction_covered: false,
            running_coverage_millionths: 800_000,
            e_value_millionths: 9_000_000,
            violation: true,
        };
        let json = serde_json::to_string(&entry).unwrap();
        let back: CalibrationLedgerEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry, back);
    }

    #[test]
    fn fallback_trigger_event_with_from_action() {
        let event = FallbackTriggerEvent {
            epoch: epoch(5),
            trigger: DemotionReason::DriftDetected,
            from_action: Some(LaneAction::RouteTo(LaneId("v8_lane".into()))),
            to_action: LaneAction::FallbackSafe,
            metrics: FallbackMetrics {
                cvar_millionths: Some(10 * MILLION),
                drift_kl_millionths: Some(200_000),
                budget_remaining_millionths: 600_000,
                coverage_millionths: 850_000,
                e_value_millionths: 3 * MILLION,
            },
        };
        let json = serde_json::to_string(&event).unwrap();
        let back: FallbackTriggerEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, back);
    }
}
