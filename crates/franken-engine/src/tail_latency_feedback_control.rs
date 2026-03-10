#![forbid(unsafe_code)]

//! Bounded feedback control and policy-as-data for tail-latency preservation.
//!
//! Bead: bd-1lsy.7.11.3 [RGC-611C]
//!
//! Implements a PID feedback controller that maps observed latency percentiles
//! to discrete control actions (hold, scale-up, scale-down, shed, emergency
//! brake). Sits above the queueing admission control layer ([RGC-611B]) and
//! provides the closed-loop signal that drives admission policy adjustments.
//!
//! Key design:
//! - PID controller with anti-windup for latency error signals
//! - Discrete control actions mapped from continuous PID output
//! - Content-addressed audit trail for every decision
//! - Policy overrides with epoch-bounded expiration
//! - Deterministic percentile estimation from sample windows
//!
//! All latencies are in nanoseconds, ratios in millionths (1_000_000 = 1.0).

use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Schema constants
// ---------------------------------------------------------------------------

/// Schema version.
pub const FEEDBACK_CONTROL_SCHEMA_VERSION: &str = "franken-engine.tail-latency-feedback-control.v1";

/// Bead reference.
pub const FEEDBACK_CONTROL_BEAD_ID: &str = "bd-1lsy.7.11.3";

/// Policy reference.
pub const FEEDBACK_CONTROL_POLICY_ID: &str = "RGC-611C";

/// Component name.
pub const COMPONENT: &str = "tail_latency_feedback_control";

/// Fixed-point millionths unit.
const MILLIONTHS: u64 = 1_000_000;

// ---------------------------------------------------------------------------
// ControlAction
// ---------------------------------------------------------------------------

/// Discrete control action emitted by the PID controller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlAction {
    /// No change required — system is within target.
    Hold,
    /// Scale up resources by the given magnitude (millionths).
    ScaleUp(u64),
    /// Scale down resources by the given magnitude (millionths).
    ScaleDown(u64),
    /// Shed load by the given magnitude (millionths).
    Shed(u64),
    /// Emergency brake — immediately halt non-critical work.
    EmergencyBrake,
}

impl fmt::Display for ControlAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Hold => write!(f, "hold"),
            Self::ScaleUp(mag) => write!(f, "scale_up({mag})"),
            Self::ScaleDown(mag) => write!(f, "scale_down({mag})"),
            Self::Shed(mag) => write!(f, "shed({mag})"),
            Self::EmergencyBrake => write!(f, "emergency_brake"),
        }
    }
}

// ---------------------------------------------------------------------------
// LatencyTarget
// ---------------------------------------------------------------------------

/// A latency SLO target at a given percentile.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct LatencyTarget {
    /// Percentile in millionths (e.g. p99 = 990_000).
    pub percentile_millionths: u64,
    /// Target latency budget in nanoseconds.
    pub budget_nanos: u64,
    /// Tolerance band in millionths (e.g. 50_000 = 5% tolerance).
    pub tolerance_millionths: u64,
}

impl LatencyTarget {
    /// Create a new latency target.
    pub fn new(percentile_millionths: u64, budget_nanos: u64, tolerance_millionths: u64) -> Self {
        Self {
            percentile_millionths,
            budget_nanos,
            tolerance_millionths,
        }
    }

    /// Effective upper bound including tolerance.
    pub fn upper_bound_nanos(&self) -> u64 {
        let tolerance_nanos =
            self.budget_nanos.saturating_mul(self.tolerance_millionths) / MILLIONTHS;
        self.budget_nanos.saturating_add(tolerance_nanos)
    }
}

impl fmt::Display for LatencyTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "p{}@{}ns(±{}‰)",
            self.percentile_millionths, self.budget_nanos, self.tolerance_millionths
        )
    }
}

// ---------------------------------------------------------------------------
// ControllerConfig
// ---------------------------------------------------------------------------

/// PID controller configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControllerConfig {
    /// Proportional gain (millionths).
    pub proportional_gain_millionths: u64,
    /// Integral gain (millionths).
    pub integral_gain_millionths: u64,
    /// Derivative gain (millionths).
    pub derivative_gain_millionths: u64,
    /// Maximum absolute value of the error integral (anti-windup).
    pub max_integral_windup: i64,
    /// Minimum controller output (clamp floor).
    pub min_control_output: i64,
    /// Maximum controller output (clamp ceiling).
    pub max_control_output: i64,
    /// Number of samples in the sliding window.
    pub sample_window_size: usize,
}

impl ControllerConfig {
    /// Balanced defaults suitable for most tail-latency controllers.
    pub fn default_config() -> Self {
        Self {
            proportional_gain_millionths: 500_000, // 0.5
            integral_gain_millionths: 100_000,     // 0.1
            derivative_gain_millionths: 200_000,   // 0.2
            max_integral_windup: 5_000_000,
            min_control_output: -3_000_000,
            max_control_output: 3_000_000,
            sample_window_size: 100,
        }
    }
}

impl Default for ControllerConfig {
    fn default() -> Self {
        Self::default_config()
    }
}

impl fmt::Display for ControllerConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PID(P={},I={},D={},windup={},range=[{},{}],window={})",
            self.proportional_gain_millionths,
            self.integral_gain_millionths,
            self.derivative_gain_millionths,
            self.max_integral_windup,
            self.min_control_output,
            self.max_control_output,
            self.sample_window_size,
        )
    }
}

// ---------------------------------------------------------------------------
// ControllerState
// ---------------------------------------------------------------------------

/// Mutable state of the PID controller.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControllerState {
    /// Unique state identifier.
    pub state_id: String,
    /// Current security epoch.
    pub epoch: SecurityEpoch,
    /// Accumulated error integral.
    pub error_integral: i64,
    /// Previous error value for derivative computation.
    pub previous_error: i64,
    /// Total samples processed.
    pub sample_count: u64,
    /// Current control action.
    pub current_action: ControlAction,
    /// Last observed latency in nanoseconds.
    pub last_latency_nanos: u64,
    /// Content hash of this state snapshot.
    pub content_hash: ContentHash,
}

impl ControllerState {
    /// Create initial controller state.
    pub fn new(state_id: impl Into<String>, epoch: SecurityEpoch) -> Self {
        let state_id = state_id.into();
        let hash = Self::compute_hash(&state_id, &epoch, 0, 0, 0, &ControlAction::Hold, 0);
        Self {
            state_id,
            epoch,
            error_integral: 0,
            previous_error: 0,
            sample_count: 0,
            current_action: ControlAction::Hold,
            last_latency_nanos: 0,
            content_hash: hash,
        }
    }

    /// Recompute and update the content hash.
    pub fn rehash(&mut self) {
        self.content_hash = Self::compute_hash(
            &self.state_id,
            &self.epoch,
            self.error_integral,
            self.previous_error,
            self.sample_count,
            &self.current_action,
            self.last_latency_nanos,
        );
    }

    fn compute_hash(
        state_id: &str,
        epoch: &SecurityEpoch,
        error_integral: i64,
        previous_error: i64,
        sample_count: u64,
        action: &ControlAction,
        last_latency_nanos: u64,
    ) -> ContentHash {
        let mut hasher = Sha256::new();
        hasher.update(FEEDBACK_CONTROL_SCHEMA_VERSION.as_bytes());
        hasher.update(state_id.as_bytes());
        hasher.update(epoch.as_u64().to_le_bytes());
        hasher.update(error_integral.to_le_bytes());
        hasher.update(previous_error.to_le_bytes());
        hasher.update(sample_count.to_le_bytes());
        hasher.update(format!("{action}").as_bytes());
        hasher.update(last_latency_nanos.to_le_bytes());
        let result = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&result);
        ContentHash(bytes)
    }
}

impl fmt::Display for ControllerState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ControllerState({}, epoch={}, samples={}, action={}, integral={})",
            self.state_id,
            self.epoch.as_u64(),
            self.sample_count,
            self.current_action,
            self.error_integral,
        )
    }
}

// ---------------------------------------------------------------------------
// LatencySample
// ---------------------------------------------------------------------------

/// A single latency observation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct LatencySample {
    /// Unique sample identifier.
    pub sample_id: String,
    /// Timestamp in nanoseconds (monotonic).
    pub timestamp_nanos: u64,
    /// Observed latency in nanoseconds.
    pub latency_nanos: u64,
    /// Percentile bucket this sample belongs to (millionths).
    pub percentile_millionths: u64,
    /// Execution stage label.
    pub stage: String,
}

impl LatencySample {
    /// Create a new sample.
    pub fn new(
        sample_id: impl Into<String>,
        timestamp_nanos: u64,
        latency_nanos: u64,
        percentile_millionths: u64,
        stage: impl Into<String>,
    ) -> Self {
        Self {
            sample_id: sample_id.into(),
            timestamp_nanos,
            latency_nanos,
            percentile_millionths,
            stage: stage.into(),
        }
    }
}

impl fmt::Display for LatencySample {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Sample({}, {}ns, stage={})",
            self.sample_id, self.latency_nanos, self.stage,
        )
    }
}

// ---------------------------------------------------------------------------
// ControlDecision
// ---------------------------------------------------------------------------

/// A single PID controller decision with full audit trail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlDecision {
    /// Unique decision identifier.
    pub decision_id: String,
    /// Security epoch at decision time.
    pub epoch: SecurityEpoch,
    /// Computed error signal (millionths).
    pub error_millionths: i64,
    /// Proportional term.
    pub proportional: i64,
    /// Integral term.
    pub integral: i64,
    /// Derivative term.
    pub derivative: i64,
    /// Raw (unclamped) PID output.
    pub raw_output: i64,
    /// Clamped PID output.
    pub clamped_output: i64,
    /// Resulting control action.
    pub action: ControlAction,
    /// Human-readable rationale.
    pub rationale: String,
    /// Content hash for audit.
    pub content_hash: ContentHash,
}

impl ControlDecision {
    /// Compute content hash for this decision.
    fn compute_hash(
        decision_id: &str,
        epoch: &SecurityEpoch,
        error: i64,
        raw_output: i64,
        clamped_output: i64,
        action: &ControlAction,
    ) -> ContentHash {
        let mut hasher = Sha256::new();
        hasher.update(FEEDBACK_CONTROL_SCHEMA_VERSION.as_bytes());
        hasher.update(b"decision:");
        hasher.update(decision_id.as_bytes());
        hasher.update(epoch.as_u64().to_le_bytes());
        hasher.update(error.to_le_bytes());
        hasher.update(raw_output.to_le_bytes());
        hasher.update(clamped_output.to_le_bytes());
        hasher.update(format!("{action}").as_bytes());
        let result = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&result);
        ContentHash(bytes)
    }
}

impl fmt::Display for ControlDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Decision({}, err={}, P={}, I={}, D={}, out={}, action={})",
            self.decision_id,
            self.error_millionths,
            self.proportional,
            self.integral,
            self.derivative,
            self.clamped_output,
            self.action,
        )
    }
}

// ---------------------------------------------------------------------------
// FeedbackControlReport
// ---------------------------------------------------------------------------

/// Full feedback control report encompassing all targets and decisions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeedbackControlReport {
    /// Unique report identifier.
    pub report_id: String,
    /// Security epoch of the report.
    pub epoch: SecurityEpoch,
    /// Latency targets being tracked.
    pub targets: Vec<LatencyTarget>,
    /// Decisions produced this cycle.
    pub decisions: Vec<ControlDecision>,
    /// Current controller state snapshot.
    pub current_state: ControllerState,
    /// Number of targets currently in violation.
    pub violations_count: u64,
    /// Overall compliance rate in millionths (targets met / total targets).
    pub compliance_rate_millionths: u64,
    /// Content hash for audit.
    pub content_hash: ContentHash,
}

impl FeedbackControlReport {
    /// Compute content hash for this report.
    fn compute_hash(
        report_id: &str,
        epoch: &SecurityEpoch,
        violations_count: u64,
        compliance_rate: u64,
        decision_hashes: &[ContentHash],
    ) -> ContentHash {
        let mut hasher = Sha256::new();
        hasher.update(FEEDBACK_CONTROL_SCHEMA_VERSION.as_bytes());
        hasher.update(b"report:");
        hasher.update(report_id.as_bytes());
        hasher.update(epoch.as_u64().to_le_bytes());
        hasher.update(violations_count.to_le_bytes());
        hasher.update(compliance_rate.to_le_bytes());
        for h in decision_hashes {
            hasher.update(h.as_bytes());
        }
        let result = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&result);
        ContentHash(bytes)
    }
}

impl fmt::Display for FeedbackControlReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "FeedbackControlReport({}, epoch={}, targets={}, decisions={}, violations={}, compliance={}‰)",
            self.report_id,
            self.epoch.as_u64(),
            self.targets.len(),
            self.decisions.len(),
            self.violations_count,
            self.compliance_rate_millionths,
        )
    }
}

// ---------------------------------------------------------------------------
// PolicyOverride
// ---------------------------------------------------------------------------

/// Manual policy override that forces a specific action until expiry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyOverride {
    /// Unique override identifier.
    pub override_id: String,
    /// Forced action.
    pub action: ControlAction,
    /// Human-readable reason.
    pub reason: String,
    /// Epoch after which this override expires.
    pub expires_epoch: SecurityEpoch,
    /// Content hash for audit.
    pub content_hash: ContentHash,
}

impl PolicyOverride {
    /// Create a new policy override with content hash.
    pub fn new(
        override_id: impl Into<String>,
        action: ControlAction,
        reason: impl Into<String>,
        expires_epoch: SecurityEpoch,
    ) -> Self {
        let override_id = override_id.into();
        let reason = reason.into();
        let hash = Self::compute_hash(&override_id, &action, &reason, &expires_epoch);
        Self {
            override_id,
            action,
            reason,
            expires_epoch,
            content_hash: hash,
        }
    }

    fn compute_hash(
        override_id: &str,
        action: &ControlAction,
        reason: &str,
        expires_epoch: &SecurityEpoch,
    ) -> ContentHash {
        let mut hasher = Sha256::new();
        hasher.update(FEEDBACK_CONTROL_SCHEMA_VERSION.as_bytes());
        hasher.update(b"override:");
        hasher.update(override_id.as_bytes());
        hasher.update(format!("{action}").as_bytes());
        hasher.update(reason.as_bytes());
        hasher.update(expires_epoch.as_u64().to_le_bytes());
        let result = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&result);
        ContentHash(bytes)
    }
}

impl fmt::Display for PolicyOverride {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Override({}, action={}, expires=epoch-{})",
            self.override_id,
            self.action,
            self.expires_epoch.as_u64(),
        )
    }
}

// ---------------------------------------------------------------------------
// Core functions
// ---------------------------------------------------------------------------

/// Compute the error signal between observed latency and target budget.
///
/// Returns (observed - budget) * MILLIONTHS / budget, i.e. a signed value
/// in millionths representing the relative overshoot (positive) or
/// undershoot (negative).
pub fn compute_error(target: &LatencyTarget, observed_nanos: u64) -> i64 {
    if target.budget_nanos == 0 {
        // Avoid division by zero — treat as maximum overshoot.
        if observed_nanos > 0 {
            return i64::MAX;
        }
        return 0;
    }
    let observed = observed_nanos as i64;
    let budget = target.budget_nanos as i64;
    let diff = observed.saturating_sub(budget);
    // (diff * MILLIONTHS) / budget, using saturating arithmetic.
    diff.saturating_mul(MILLIONTHS as i64)
        .checked_div(budget)
        .unwrap_or(0)
}

/// Execute a single PID controller step.
///
/// Updates `state` in-place (integral accumulator, previous error, sample
/// count) and returns the control decision.
pub fn pid_step(
    config: &ControllerConfig,
    state: &mut ControllerState,
    error: i64,
) -> ControlDecision {
    // Proportional term: P * error / MILLIONTHS
    let proportional =
        error.saturating_mul(config.proportional_gain_millionths as i64) / MILLIONTHS as i64;

    // Integral term: accumulate then clamp (anti-windup)
    state.error_integral = state.error_integral.saturating_add(error);
    // Anti-windup: clamp integral to [-max_windup, +max_windup]
    state.error_integral = state
        .error_integral
        .clamp(-config.max_integral_windup, config.max_integral_windup);
    let integral = state
        .error_integral
        .saturating_mul(config.integral_gain_millionths as i64)
        / MILLIONTHS as i64;

    // Derivative term: D * (error - previous_error) / MILLIONTHS
    let delta_error = error.saturating_sub(state.previous_error);
    let derivative =
        delta_error.saturating_mul(config.derivative_gain_millionths as i64) / MILLIONTHS as i64;

    // Raw output
    let raw_output = proportional
        .saturating_add(integral)
        .saturating_add(derivative);

    // Clamp to configured range
    let clamped_output = raw_output.clamp(config.min_control_output, config.max_control_output);

    // Map to discrete action
    let action = action_from_output(clamped_output);

    // Update state
    state.previous_error = error;
    state.sample_count = state.sample_count.saturating_add(1);
    state.current_action = action;
    state.rehash();

    // Build decision ID
    let decision_id = format!("decision-{}-{}", state.epoch.as_u64(), state.sample_count);

    // Build rationale
    let rationale = format!(
        "PID step: error={error}, P={proportional}, I={integral}, D={derivative}, raw={raw_output}, clamped={clamped_output} -> {action}"
    );

    let content_hash = ControlDecision::compute_hash(
        &decision_id,
        &state.epoch,
        error,
        raw_output,
        clamped_output,
        &action,
    );

    ControlDecision {
        decision_id,
        epoch: state.epoch,
        error_millionths: error,
        proportional,
        integral,
        derivative,
        raw_output,
        clamped_output,
        action,
        rationale,
        content_hash,
    }
}

/// Map a continuous PID output (in millionths) to a discrete control action.
///
/// Thresholds:
/// - output >= 2_000_000 => EmergencyBrake
/// - output >= 1_000_000 => Shed(magnitude)
/// - output >= 100_000   => ScaleUp(magnitude)
/// - output <= -100_000  => ScaleDown(magnitude)
/// - otherwise           => Hold
pub fn action_from_output(output: i64) -> ControlAction {
    if output >= 2_000_000 {
        ControlAction::EmergencyBrake
    } else if output >= 1_000_000 {
        ControlAction::Shed(output as u64)
    } else if output >= 100_000 {
        ControlAction::ScaleUp(output as u64)
    } else if output <= -100_000 {
        ControlAction::ScaleDown(output.unsigned_abs())
    } else {
        ControlAction::Hold
    }
}

/// Check whether the observed latency exceeds the target plus tolerance.
pub fn is_in_violation(target: &LatencyTarget, observed_nanos: u64) -> bool {
    observed_nanos > target.upper_bound_nanos()
}

/// Deterministic percentile estimation using nearest-rank method.
///
/// `percentile_millionths` is in millionths (e.g. 990_000 = p99).
/// Returns latency in nanoseconds. Returns 0 for empty input.
pub fn estimate_percentile(samples: &[LatencySample], percentile_millionths: u64) -> u64 {
    if samples.is_empty() {
        return 0;
    }

    // Collect and sort latencies
    let mut latencies: Vec<u64> = samples.iter().map(|s| s.latency_nanos).collect();
    latencies.sort_unstable();

    // Nearest-rank: rank = ceil(percentile * N)
    // percentile is in millionths, so rank = ceil(percentile * N / MILLIONTHS)
    let n = latencies.len() as u64;
    let rank_millionths = percentile_millionths.saturating_mul(n);
    // Ceiling division
    let rank = rank_millionths
        .saturating_add(MILLIONTHS - 1)
        .checked_div(MILLIONTHS)
        .unwrap_or(1);
    // Clamp to [1, N]
    let rank = rank.max(1).min(n);

    latencies[(rank - 1) as usize]
}

/// Build a complete feedback control report for all targets.
///
/// For each target, estimates the corresponding percentile from samples,
/// computes the error, runs a PID step, and checks for violation.
pub fn build_feedback_report(
    targets: &[LatencyTarget],
    samples: &[LatencySample],
    config: &ControllerConfig,
    state: &mut ControllerState,
    epoch: &SecurityEpoch,
) -> FeedbackControlReport {
    let report_id = format!("report-{}-{}", epoch.as_u64(), state.sample_count);

    let mut decisions = Vec::new();
    let mut violations_count: u64 = 0;

    for target in targets {
        let observed = estimate_percentile(samples, target.percentile_millionths);
        state.last_latency_nanos = observed;

        let error = compute_error(target, observed);
        let decision = pid_step(config, state, error);
        decisions.push(decision);

        if is_in_violation(target, observed) {
            violations_count = violations_count.saturating_add(1);
        }
    }

    let total_targets = targets.len() as u64;
    let compliance_rate_millionths = if total_targets == 0 {
        MILLIONTHS // 100% compliance when there are no targets
    } else {
        let compliant = total_targets.saturating_sub(violations_count);
        compliant.saturating_mul(MILLIONTHS) / total_targets
    };

    let decision_hashes: Vec<ContentHash> =
        decisions.iter().map(|d| d.content_hash.clone()).collect();
    let content_hash = FeedbackControlReport::compute_hash(
        &report_id,
        epoch,
        violations_count,
        compliance_rate_millionths,
        &decision_hashes,
    );

    state.epoch = *epoch;
    state.rehash();

    FeedbackControlReport {
        report_id,
        epoch: *epoch,
        targets: targets.to_vec(),
        decisions,
        current_state: state.clone(),
        violations_count,
        compliance_rate_millionths,
        content_hash,
    }
}

/// Apply a manual policy override to the controller state.
///
/// Forces the controller action to the override's action if the current
/// epoch has not yet passed the override's expiry.
pub fn apply_override(state: &mut ControllerState, over: &PolicyOverride) {
    if state.epoch <= over.expires_epoch {
        state.current_action = over.action;
        state.rehash();
    }
}

/// Reset the PID controller's integral and derivative state.
///
/// Preserves the state_id, epoch, sample_count, and action. Useful after
/// a configuration change or manual override to avoid integral windup
/// carryover.
pub fn reset_controller(state: &mut ControllerState) {
    state.error_integral = 0;
    state.previous_error = 0;
    state.rehash();
}

/// Canonical empty manifest for the feedback control module.
pub fn franken_engine_feedback_control_manifest() -> FeedbackControlReport {
    let epoch = SecurityEpoch::GENESIS;
    let state = ControllerState::new("manifest-genesis", epoch);
    let content_hash =
        FeedbackControlReport::compute_hash("manifest-empty", &epoch, 0, MILLIONTHS, &[]);
    FeedbackControlReport {
        report_id: "manifest-empty".to_string(),
        epoch,
        targets: Vec::new(),
        decisions: Vec::new(),
        current_state: state,
        violations_count: 0,
        compliance_rate_millionths: MILLIONTHS,
        content_hash,
    }
}

// ===========================================================================
// Unit tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_target(percentile: u64, budget_nanos: u64, tolerance: u64) -> LatencyTarget {
        LatencyTarget::new(percentile, budget_nanos, tolerance)
    }

    fn make_sample(id: &str, latency_nanos: u64) -> LatencySample {
        LatencySample::new(id, 1000, latency_nanos, 990_000, "test")
    }

    // --- compute_error ---

    #[test]
    fn test_compute_error_positive_overshoot() {
        let target = make_target(990_000, 1_000_000, 0);
        // Observed 1.5x the budget => 500_000 millionths overshoot
        let err = compute_error(&target, 1_500_000);
        assert_eq!(err, 500_000);
    }

    #[test]
    fn test_compute_error_negative_undershoot() {
        let target = make_target(990_000, 1_000_000, 0);
        // Observed 0.5x the budget => -500_000 millionths undershoot
        let err = compute_error(&target, 500_000);
        assert_eq!(err, -500_000);
    }

    #[test]
    fn test_compute_error_exact_match() {
        let target = make_target(990_000, 1_000_000, 0);
        let err = compute_error(&target, 1_000_000);
        assert_eq!(err, 0);
    }

    #[test]
    fn test_compute_error_zero_budget_nonzero_observed() {
        let target = make_target(990_000, 0, 0);
        let err = compute_error(&target, 100);
        assert_eq!(err, i64::MAX);
    }

    #[test]
    fn test_compute_error_zero_budget_zero_observed() {
        let target = make_target(990_000, 0, 0);
        let err = compute_error(&target, 0);
        assert_eq!(err, 0);
    }

    // --- pid_step ---

    #[test]
    fn test_pid_step_proportional_only() {
        let config = ControllerConfig {
            proportional_gain_millionths: MILLIONTHS, // gain = 1.0
            integral_gain_millionths: 0,
            derivative_gain_millionths: 0,
            max_integral_windup: 10_000_000,
            min_control_output: -10_000_000,
            max_control_output: 10_000_000,
            sample_window_size: 100,
        };
        let epoch = SecurityEpoch::from_raw(1);
        let mut state = ControllerState::new("test-p", epoch);

        let decision = pid_step(&config, &mut state, 500_000);
        assert_eq!(decision.proportional, 500_000);
        assert_eq!(decision.integral, 0);
        assert_eq!(decision.derivative, 0);
        assert_eq!(decision.raw_output, 500_000);
    }

    #[test]
    fn test_pid_step_with_integral() {
        let config = ControllerConfig {
            proportional_gain_millionths: 0,
            integral_gain_millionths: MILLIONTHS,
            derivative_gain_millionths: 0,
            max_integral_windup: 10_000_000,
            min_control_output: -10_000_000,
            max_control_output: 10_000_000,
            sample_window_size: 100,
        };
        let epoch = SecurityEpoch::from_raw(1);
        let mut state = ControllerState::new("test-i", epoch);

        // First step: integral = error (500_000)
        let d1 = pid_step(&config, &mut state, 500_000);
        assert_eq!(d1.integral, 500_000);

        // Second step: integral = 500_000 + 300_000 = 800_000
        let d2 = pid_step(&config, &mut state, 300_000);
        assert_eq!(d2.integral, 800_000);
    }

    #[test]
    fn test_pid_step_with_derivative() {
        let config = ControllerConfig {
            proportional_gain_millionths: 0,
            integral_gain_millionths: 0,
            derivative_gain_millionths: MILLIONTHS,
            max_integral_windup: 10_000_000,
            min_control_output: -10_000_000,
            max_control_output: 10_000_000,
            sample_window_size: 100,
        };
        let epoch = SecurityEpoch::from_raw(1);
        let mut state = ControllerState::new("test-d", epoch);

        // First step: derivative = (500_000 - 0) = 500_000
        let d1 = pid_step(&config, &mut state, 500_000);
        assert_eq!(d1.derivative, 500_000);

        // Second step: derivative = (300_000 - 500_000) = -200_000
        let d2 = pid_step(&config, &mut state, 300_000);
        assert_eq!(d2.derivative, -200_000);
    }

    #[test]
    fn test_pid_step_anti_windup() {
        let config = ControllerConfig {
            proportional_gain_millionths: 0,
            integral_gain_millionths: MILLIONTHS,
            derivative_gain_millionths: 0,
            max_integral_windup: 1_000_000, // Clamp integral at 1M
            min_control_output: -10_000_000,
            max_control_output: 10_000_000,
            sample_window_size: 100,
        };
        let epoch = SecurityEpoch::from_raw(1);
        let mut state = ControllerState::new("test-windup", epoch);

        // Push integral way past windup limit
        pid_step(&config, &mut state, 5_000_000);
        assert_eq!(state.error_integral, 1_000_000); // Clamped

        pid_step(&config, &mut state, 5_000_000);
        assert_eq!(state.error_integral, 1_000_000); // Still clamped
    }

    #[test]
    fn test_pid_step_output_clamping() {
        let config = ControllerConfig {
            proportional_gain_millionths: MILLIONTHS,
            integral_gain_millionths: 0,
            derivative_gain_millionths: 0,
            max_integral_windup: 10_000_000,
            min_control_output: -500_000,
            max_control_output: 500_000,
            sample_window_size: 100,
        };
        let epoch = SecurityEpoch::from_raw(1);
        let mut state = ControllerState::new("test-clamp", epoch);

        let d = pid_step(&config, &mut state, 2_000_000);
        // Raw = 2M, clamped to 500K
        assert_eq!(d.raw_output, 2_000_000);
        assert_eq!(d.clamped_output, 500_000);
    }

    // --- action_from_output ---

    #[test]
    fn test_action_from_output_hold() {
        assert_eq!(action_from_output(0), ControlAction::Hold);
        assert_eq!(action_from_output(99_999), ControlAction::Hold);
        assert_eq!(action_from_output(-99_999), ControlAction::Hold);
    }

    #[test]
    fn test_action_from_output_scale_up() {
        assert_eq!(action_from_output(100_000), ControlAction::ScaleUp(100_000));
        assert_eq!(action_from_output(999_999), ControlAction::ScaleUp(999_999));
    }

    #[test]
    fn test_action_from_output_scale_down() {
        assert_eq!(
            action_from_output(-100_000),
            ControlAction::ScaleDown(100_000)
        );
        assert_eq!(
            action_from_output(-500_000),
            ControlAction::ScaleDown(500_000)
        );
    }

    #[test]
    fn test_action_from_output_shed() {
        assert_eq!(
            action_from_output(1_000_000),
            ControlAction::Shed(1_000_000)
        );
        assert_eq!(
            action_from_output(1_999_999),
            ControlAction::Shed(1_999_999)
        );
    }

    #[test]
    fn test_action_from_output_emergency_brake() {
        assert_eq!(action_from_output(2_000_000), ControlAction::EmergencyBrake);
        assert_eq!(action_from_output(5_000_000), ControlAction::EmergencyBrake);
    }

    // --- is_in_violation ---

    #[test]
    fn test_is_in_violation_within_budget() {
        let target = make_target(990_000, 1_000_000, 50_000);
        assert!(!is_in_violation(&target, 1_000_000));
    }

    #[test]
    fn test_is_in_violation_within_tolerance() {
        let target = make_target(990_000, 1_000_000, 50_000);
        // upper bound = 1_000_000 + 50_000 = 1_050_000
        assert!(!is_in_violation(&target, 1_050_000));
    }

    #[test]
    fn test_is_in_violation_exceeds_tolerance() {
        let target = make_target(990_000, 1_000_000, 50_000);
        assert!(is_in_violation(&target, 1_050_001));
    }

    #[test]
    fn test_is_in_violation_zero_tolerance() {
        let target = make_target(990_000, 1_000_000, 0);
        assert!(!is_in_violation(&target, 1_000_000));
        assert!(is_in_violation(&target, 1_000_001));
    }

    // --- estimate_percentile ---

    #[test]
    fn test_estimate_percentile_empty() {
        assert_eq!(estimate_percentile(&[], 990_000), 0);
    }

    #[test]
    fn test_estimate_percentile_single_sample() {
        let samples = vec![make_sample("s1", 42_000)];
        assert_eq!(estimate_percentile(&samples, 990_000), 42_000);
    }

    #[test]
    fn test_estimate_percentile_p50() {
        let samples: Vec<LatencySample> = (1..=100)
            .map(|i| make_sample(&format!("s{i}"), i * 1000))
            .collect();
        // p50 = 500_000 millionths => rank = ceil(0.5 * 100) = 50 => value = 50_000
        assert_eq!(estimate_percentile(&samples, 500_000), 50_000);
    }

    #[test]
    fn test_estimate_percentile_p99() {
        let samples: Vec<LatencySample> = (1..=100)
            .map(|i| make_sample(&format!("s{i}"), i * 1000))
            .collect();
        // p99 = 990_000 millionths => rank = ceil(0.99 * 100) = 99 => value = 99_000
        assert_eq!(estimate_percentile(&samples, 990_000), 99_000);
    }

    #[test]
    fn test_estimate_percentile_p100() {
        let samples: Vec<LatencySample> = (1..=100)
            .map(|i| make_sample(&format!("s{i}"), i * 1000))
            .collect();
        assert_eq!(estimate_percentile(&samples, MILLIONTHS), 100_000);
    }

    #[test]
    fn test_estimate_percentile_unsorted_input() {
        // Samples out of order — should still produce correct result
        let samples = vec![
            make_sample("s1", 50_000),
            make_sample("s2", 10_000),
            make_sample("s3", 90_000),
            make_sample("s4", 30_000),
            make_sample("s5", 70_000),
        ];
        // p50 => rank = ceil(0.5 * 5) = 3 => sorted: [10K, 30K, 50K, 70K, 90K] => 50_000
        assert_eq!(estimate_percentile(&samples, 500_000), 50_000);
    }

    // --- build_feedback_report ---

    #[test]
    fn test_build_feedback_report_no_targets() {
        let config = ControllerConfig::default();
        let epoch = SecurityEpoch::from_raw(1);
        let mut state = ControllerState::new("test", epoch);

        let report = build_feedback_report(&[], &[], &config, &mut state, &epoch);
        assert_eq!(report.violations_count, 0);
        assert_eq!(report.compliance_rate_millionths, MILLIONTHS);
        assert!(report.decisions.is_empty());
    }

    #[test]
    fn test_build_feedback_report_with_violation() {
        let config = ControllerConfig::default();
        let epoch = SecurityEpoch::from_raw(1);
        let mut state = ControllerState::new("test", epoch);
        let targets = vec![make_target(990_000, 100_000, 0)];
        let samples: Vec<LatencySample> = (1..=100)
            .map(|i| make_sample(&format!("s{i}"), 200_000)) // all at 200K, target 100K
            .collect();

        let report = build_feedback_report(&targets, &samples, &config, &mut state, &epoch);
        assert_eq!(report.violations_count, 1);
        assert_eq!(report.decisions.len(), 1);
        // Error should be positive (overshoot)
        assert!(report.decisions[0].error_millionths > 0);
    }

    #[test]
    fn test_build_feedback_report_full_compliance() {
        let config = ControllerConfig::default();
        let epoch = SecurityEpoch::from_raw(1);
        let mut state = ControllerState::new("test", epoch);
        let targets = vec![make_target(990_000, 1_000_000, 50_000)];
        let samples: Vec<LatencySample> = (1..=100)
            .map(|i| make_sample(&format!("s{i}"), 500_000)) // well under budget
            .collect();

        let report = build_feedback_report(&targets, &samples, &config, &mut state, &epoch);
        assert_eq!(report.violations_count, 0);
        assert_eq!(report.compliance_rate_millionths, MILLIONTHS);
    }

    #[test]
    fn test_build_feedback_report_multiple_targets() {
        let config = ControllerConfig::default();
        let epoch = SecurityEpoch::from_raw(1);
        let mut state = ControllerState::new("test", epoch);
        let targets = vec![
            make_target(500_000, 100_000, 0), // p50 target
            make_target(990_000, 200_000, 0), // p99 target
        ];
        let samples: Vec<LatencySample> = (1..=100)
            .map(|i| make_sample(&format!("s{i}"), i * 1000))
            .collect();

        let report = build_feedback_report(&targets, &samples, &config, &mut state, &epoch);
        assert_eq!(report.decisions.len(), 2);
        assert_eq!(report.targets.len(), 2);
    }

    // --- apply_override ---

    #[test]
    fn test_apply_override_within_epoch() {
        let epoch = SecurityEpoch::from_raw(5);
        let mut state = ControllerState::new("test", epoch);
        let over = PolicyOverride::new(
            "ov-1",
            ControlAction::EmergencyBrake,
            "manual intervention",
            SecurityEpoch::from_raw(10),
        );

        apply_override(&mut state, &over);
        assert_eq!(state.current_action, ControlAction::EmergencyBrake);
    }

    #[test]
    fn test_apply_override_expired() {
        let epoch = SecurityEpoch::from_raw(15);
        let mut state = ControllerState::new("test", epoch);
        let original_action = state.current_action;
        let over = PolicyOverride::new(
            "ov-1",
            ControlAction::EmergencyBrake,
            "manual intervention",
            SecurityEpoch::from_raw(10), // expired
        );

        apply_override(&mut state, &over);
        // Action should NOT change
        assert_eq!(state.current_action, original_action);
    }

    // --- reset_controller ---

    #[test]
    fn test_reset_controller() {
        let config = ControllerConfig::default();
        let epoch = SecurityEpoch::from_raw(1);
        let mut state = ControllerState::new("test", epoch);

        // Accumulate some state
        pid_step(&config, &mut state, 500_000);
        pid_step(&config, &mut state, 300_000);
        assert_ne!(state.error_integral, 0);
        assert_ne!(state.previous_error, 0);

        reset_controller(&mut state);
        assert_eq!(state.error_integral, 0);
        assert_eq!(state.previous_error, 0);
        // sample_count preserved
        assert_eq!(state.sample_count, 2);
    }

    // --- serde roundtrips ---

    #[test]
    fn test_serde_control_action() {
        let actions = vec![
            ControlAction::Hold,
            ControlAction::ScaleUp(100),
            ControlAction::ScaleDown(200),
            ControlAction::Shed(300),
            ControlAction::EmergencyBrake,
        ];
        for action in &actions {
            let json = serde_json::to_string(action).unwrap();
            let decoded: ControlAction = serde_json::from_str(&json).unwrap();
            assert_eq!(*action, decoded);
        }
    }

    #[test]
    fn test_serde_latency_target() {
        let target = make_target(990_000, 1_000_000, 50_000);
        let json = serde_json::to_string(&target).unwrap();
        let decoded: LatencyTarget = serde_json::from_str(&json).unwrap();
        assert_eq!(target, decoded);
    }

    #[test]
    fn test_serde_controller_state() {
        let state = ControllerState::new("test", SecurityEpoch::from_raw(1));
        let json = serde_json::to_string(&state).unwrap();
        let decoded: ControllerState = serde_json::from_str(&json).unwrap();
        assert_eq!(state, decoded);
    }

    #[test]
    fn test_serde_feedback_report() {
        let report = franken_engine_feedback_control_manifest();
        let json = serde_json::to_string(&report).unwrap();
        let decoded: FeedbackControlReport = serde_json::from_str(&json).unwrap();
        assert_eq!(report, decoded);
    }

    #[test]
    fn test_serde_policy_override() {
        let over = PolicyOverride::new(
            "ov-1",
            ControlAction::Shed(500),
            "test reason",
            SecurityEpoch::from_raw(10),
        );
        let json = serde_json::to_string(&over).unwrap();
        let decoded: PolicyOverride = serde_json::from_str(&json).unwrap();
        assert_eq!(over, decoded);
    }

    // --- Display impls ---

    #[test]
    fn test_display_control_action() {
        assert_eq!(format!("{}", ControlAction::Hold), "hold");
        assert_eq!(format!("{}", ControlAction::ScaleUp(100)), "scale_up(100)");
        assert_eq!(
            format!("{}", ControlAction::EmergencyBrake),
            "emergency_brake"
        );
    }

    #[test]
    fn test_display_controller_state() {
        let state = ControllerState::new("s1", SecurityEpoch::from_raw(3));
        let display = format!("{state}");
        assert!(display.contains("s1"));
        assert!(display.contains("epoch=3"));
    }

    #[test]
    fn test_display_control_decision() {
        let config = ControllerConfig::default();
        let epoch = SecurityEpoch::from_raw(1);
        let mut state = ControllerState::new("test", epoch);
        let decision = pid_step(&config, &mut state, 500_000);
        let display = format!("{decision}");
        assert!(display.contains("Decision("));
        assert!(display.contains("err="));
    }

    #[test]
    fn test_display_feedback_report() {
        let report = franken_engine_feedback_control_manifest();
        let display = format!("{report}");
        assert!(display.contains("FeedbackControlReport("));
    }

    // --- content hash determinism ---

    #[test]
    fn test_content_hash_determinism_controller_state() {
        let s1 = ControllerState::new("det-test", SecurityEpoch::from_raw(42));
        let s2 = ControllerState::new("det-test", SecurityEpoch::from_raw(42));
        assert_eq!(s1.content_hash, s2.content_hash);
    }

    #[test]
    fn test_content_hash_changes_with_input() {
        let s1 = ControllerState::new("a", SecurityEpoch::from_raw(1));
        let s2 = ControllerState::new("b", SecurityEpoch::from_raw(1));
        assert_ne!(s1.content_hash, s2.content_hash);
    }

    #[test]
    fn test_content_hash_determinism_report() {
        let r1 = franken_engine_feedback_control_manifest();
        let r2 = franken_engine_feedback_control_manifest();
        assert_eq!(r1.content_hash, r2.content_hash);
    }

    // --- empty samples ---

    #[test]
    fn test_build_report_empty_samples() {
        let config = ControllerConfig::default();
        let epoch = SecurityEpoch::from_raw(1);
        let mut state = ControllerState::new("test", epoch);
        let targets = vec![make_target(990_000, 100_000, 0)];

        let report = build_feedback_report(&targets, &[], &config, &mut state, &epoch);
        // With empty samples, percentile estimate = 0, which is under budget
        assert_eq!(report.violations_count, 0);
    }

    // --- convergence behavior ---

    #[test]
    fn test_controller_convergence() {
        // Simulate repeated positive errors decreasing over time.
        // The controller should trend toward ScaleUp then Hold.
        let config = ControllerConfig {
            proportional_gain_millionths: 500_000,
            integral_gain_millionths: 100_000,
            derivative_gain_millionths: 200_000,
            max_integral_windup: 5_000_000,
            min_control_output: -3_000_000,
            max_control_output: 3_000_000,
            sample_window_size: 100,
        };
        let epoch = SecurityEpoch::from_raw(1);
        let mut state = ControllerState::new("conv", epoch);

        // Decreasing error sequence
        let errors = [800_000i64, 400_000, 200_000, 50_000, 10_000, 0];
        let mut last_output = i64::MAX;
        for &err in &errors {
            let d = pid_step(&config, &mut state, err);
            // Overall output should generally decrease as error decreases
            // (not strictly monotone due to integral, but trend should hold)
            if err <= 50_000 {
                // Once error is small enough, output should be modest
                assert!(d.clamped_output < 1_000_000);
            }
            last_output = d.clamped_output;
        }
        // Final output at zero error should be small
        assert!(last_output.abs() < 500_000);
    }

    // --- manifest ---

    #[test]
    fn test_manifest_is_empty() {
        let manifest = franken_engine_feedback_control_manifest();
        assert!(manifest.targets.is_empty());
        assert!(manifest.decisions.is_empty());
        assert_eq!(manifest.violations_count, 0);
        assert_eq!(manifest.compliance_rate_millionths, MILLIONTHS);
        assert_eq!(manifest.epoch, SecurityEpoch::GENESIS);
    }

    // --- upper_bound_nanos ---

    #[test]
    fn test_upper_bound_nanos() {
        let target = make_target(990_000, 1_000_000, 100_000);
        // 1_000_000 * 100_000 / 1_000_000 = 100_000 tolerance
        assert_eq!(target.upper_bound_nanos(), 1_100_000);
    }

    #[test]
    fn test_upper_bound_nanos_zero_tolerance() {
        let target = make_target(990_000, 1_000_000, 0);
        assert_eq!(target.upper_bound_nanos(), 1_000_000);
    }

    // --- pid_step state updates ---

    #[test]
    fn test_pid_step_updates_sample_count() {
        let config = ControllerConfig::default();
        let epoch = SecurityEpoch::from_raw(1);
        let mut state = ControllerState::new("test", epoch);
        assert_eq!(state.sample_count, 0);

        pid_step(&config, &mut state, 100_000);
        assert_eq!(state.sample_count, 1);

        pid_step(&config, &mut state, 100_000);
        assert_eq!(state.sample_count, 2);
    }

    #[test]
    fn test_pid_step_updates_previous_error() {
        let config = ControllerConfig::default();
        let epoch = SecurityEpoch::from_raw(1);
        let mut state = ControllerState::new("test", epoch);

        pid_step(&config, &mut state, 123_456);
        assert_eq!(state.previous_error, 123_456);
    }

    // --- policy override content hash ---

    #[test]
    fn test_policy_override_deterministic_hash() {
        let o1 = PolicyOverride::new(
            "ov-1",
            ControlAction::Hold,
            "reason",
            SecurityEpoch::from_raw(5),
        );
        let o2 = PolicyOverride::new(
            "ov-1",
            ControlAction::Hold,
            "reason",
            SecurityEpoch::from_raw(5),
        );
        assert_eq!(o1.content_hash, o2.content_hash);
    }

    #[test]
    fn test_policy_override_different_action_different_hash() {
        let o1 = PolicyOverride::new(
            "ov-1",
            ControlAction::Hold,
            "reason",
            SecurityEpoch::from_raw(5),
        );
        let o2 = PolicyOverride::new(
            "ov-1",
            ControlAction::EmergencyBrake,
            "reason",
            SecurityEpoch::from_raw(5),
        );
        assert_ne!(o1.content_hash, o2.content_hash);
    }
}
