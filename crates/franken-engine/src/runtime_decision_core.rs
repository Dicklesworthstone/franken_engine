//! Runtime Decision Core — unified orchestration of lane routing, loss-optimal
//! action selection, sequential calibration, tail-risk guardrails, regime
//! detection, and budgeted adaptive mode.
//!
//! This module ties together the existing decision-theory building blocks
//! ([`regret_bounded_router`], [`bayesian_posterior`], [`expected_loss_selector`],
//! [`eprocess_guardrail`], [`regime_detector`], [`policy_controller`],
//! [`trust_economics`]) into a single coherent decision system for the
//! FrankenEngine runtime.
//!
//! Design requirements (FRX-01.3):
//! - Formal state/action model for lane routing and fallback selection
//! - Expected-loss policy with action costs tied to compatibility risk,
//!   latency risk, memory risk, and incident severity
//! - Conformal and anytime-valid sequential calibration layer
//! - CVaR tail-risk guardrail (mean improvements cannot hide p99/p999 regressions)
//! - Drift/regime detector with deterministic demotion policy
//! - Budgeted adaptive mode (strict compute/memory caps + deterministic fallback)
//!
//! Operational outputs:
//! - Machine-readable policy bundle
//! - Calibration ledger entries
//! - Fallback-trigger audit events
//! - Replay-stable decision traces
//!
//! All arithmetic uses fixed-point millionths (1_000_000 = 1.0) for
//! deterministic replay.  No floating point.
//!
//! Plan references: FRX-01.3, Section 10.11, 9G.5, Top-10 #2 (guardplane).

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

/// Fixed-point scale: 1_000_000 millionths = 1.0.
const MILLION: i64 = 1_000_000;

/// Schema version for serialized decision-core artifacts.
pub const DECISION_CORE_SCHEMA_VERSION: &str = "franken-engine.runtime-decision-core.v1";

/// Default CVaR quantile level: 99th percentile (990_000 millionths = 0.99).
const DEFAULT_CVAR_QUANTILE_MILLIONTHS: i64 = 990_000;

/// Default adaptive budget: 50ms compute cap.
const DEFAULT_COMPUTE_BUDGET_MS: u64 = 50;

/// Default adaptive budget: 128 MB memory cap.
const DEFAULT_MEMORY_BUDGET_MB: u64 = 128;

/// Maximum number of latency samples retained for CVaR estimation.
const MAX_LATENCY_SAMPLES: usize = 10_000;

/// Maximum number of decision trace entries retained.
const MAX_TRACE_ENTRIES: usize = 50_000;
/// Stable safe-mode lane label.
const SAFE_MODE_LANE_LABEL: &str = "safe_mode";

// ---------------------------------------------------------------------------
// LaneId — typed lane identifier
// ---------------------------------------------------------------------------

/// Typed lane identifier for routing decisions.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LaneId(pub String);

impl fmt::Display for LaneId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.stable_label())
    }
}

impl LaneId {
    /// Canonical deterministic execution profile.
    pub fn deterministic_profile() -> Self {
        Self(DETERMINISTIC_PROFILE_LABEL.into())
    }

    /// Canonical throughput-oriented execution profile.
    pub fn throughput_profile() -> Self {
        Self(THROUGHPUT_PROFILE_LABEL.into())
    }

    /// Legacy constructor retained for compatibility with existing call sites.
    pub fn quickjs_native() -> Self {
        Self::deterministic_profile()
    }

    /// Legacy constructor retained for compatibility with existing call sites.
    pub fn v8_native() -> Self {
        Self::throughput_profile()
    }

    /// Safe-mode fallback lane (deterministic, no adaptive logic).
    pub fn safe_mode() -> Self {
        Self(SAFE_MODE_LANE_LABEL.into())
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
            SAFE_MODE_LANE_LABEL => Self::safe_mode(),
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
        SAFE_MODE_LANE_LABEL => Some(SAFE_MODE_LANE_LABEL),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// RiskDimension — multi-dimensional risk decomposition
// ---------------------------------------------------------------------------

/// Risk dimensions for expected-loss decomposition.
///
/// Each routing decision's cost is decomposed across these orthogonal
/// dimensions so operators can inspect which risk drove the action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum RiskDimension {
    /// Compatibility risk: behavior drift from Node/Bun reference.
    Compatibility,
    /// Latency risk: p50/p99/p999 regression.
    Latency,
    /// Memory risk: heap/RSS budget violation.
    Memory,
    /// Incident severity: containment failure or evidence-chain break.
    IncidentSeverity,
}

impl RiskDimension {
    /// All variants in deterministic order.
    pub const ALL: [Self; 4] = [
        Self::Compatibility,
        Self::Latency,
        Self::Memory,
        Self::IncidentSeverity,
    ];
}

impl fmt::Display for RiskDimension {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Compatibility => write!(f, "compatibility"),
            Self::Latency => write!(f, "latency"),
            Self::Memory => write!(f, "memory"),
            Self::IncidentSeverity => write!(f, "incident_severity"),
        }
    }
}

// ---------------------------------------------------------------------------
// RoutingAction — formal action space
// ---------------------------------------------------------------------------

/// Formal action space for lane routing decisions.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum RoutingAction {
    /// Select a specific lane for execution.
    SelectLane(LaneId),
    /// Fall back to safe-mode lane unconditionally.
    FallbackSafeMode,
    /// Escalate decision to operator (human-in-the-loop).
    EscalateToOperator,
    /// Hold current lane assignment (no change).
    Hold,
}

impl fmt::Display for RoutingAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SelectLane(id) => write!(f, "select:{id}"),
            Self::FallbackSafeMode => write!(f, "fallback:safe_mode"),
            Self::EscalateToOperator => write!(f, "escalate:operator"),
            Self::Hold => write!(f, "hold"),
        }
    }
}

// ---------------------------------------------------------------------------
// LaneRoutingState — formal state for routing decisions
// ---------------------------------------------------------------------------

/// Formal state representation for lane routing decisions.
///
/// Captures the current lane assignment, confidence, regime estimate,
/// posterior over risk dimensions, and resource utilization snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaneRoutingState {
    /// Currently active lane.
    pub active_lane: LaneId,
    /// Confidence in current lane assignment (millionths, [0, MILLION]).
    pub confidence_millionths: i64,
    /// Current regime estimate.
    pub regime: RegimeEstimate,
    /// Per-dimension risk posterior (millionths).
    pub risk_posteriors: BTreeMap<String, i64>,
    /// Cumulative latency samples for CVaR estimation (microseconds).
    pub recent_latencies_us: Vec<u64>,
    /// Total routing decisions made.
    pub decision_count: u64,
    /// Current epoch.
    pub epoch: SecurityEpoch,
    /// Whether safe-mode fallback is currently active.
    pub safe_mode_active: bool,
}

impl LaneRoutingState {
    /// Create initial state with the given default lane.
    pub fn initial(default_lane: LaneId, epoch: SecurityEpoch) -> Self {
        let mut risk_posteriors = BTreeMap::new();
        for dim in RiskDimension::ALL {
            // Start with low risk across all dimensions.
            risk_posteriors.insert(dim.to_string(), 100_000); // 10%
        }
        Self {
            active_lane: default_lane,
            confidence_millionths: 500_000, // 50% — uninformative
            regime: RegimeEstimate::Normal,
            risk_posteriors,
            recent_latencies_us: Vec::new(),
            decision_count: 0,
            epoch,
            safe_mode_active: false,
        }
    }
}

// ---------------------------------------------------------------------------
// RegimeEstimate — operating regime
// ---------------------------------------------------------------------------

/// Estimated operating regime from BOCPD.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum RegimeEstimate {
    /// Normal operation.
    Normal,
    /// Elevated activity — heightened monitoring.
    Elevated,
    /// Active attack or severe anomaly.
    Attack,
    /// Degraded system state.
    Degraded,
    /// Recovering from incident.
    Recovery,
}

impl fmt::Display for RegimeEstimate {
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

// ---------------------------------------------------------------------------
// AsymmetricLossPolicy — multi-dimensional loss decomposition
// ---------------------------------------------------------------------------

/// Asymmetric loss policy mapping (action, risk_dimension) to cost.
///
/// The loss is asymmetric: false-allowing a risky action has much higher
/// cost than false-restricting a benign one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AsymmetricLossPolicy {
    /// Policy identifier.
    pub policy_id: String,
    /// Per-(action_label, dimension) loss entries (millionths).
    pub entries: Vec<LossPolicyEntry>,
    /// Regime-specific multipliers: regime_name -> multiplier_millionths.
    /// Under Attack regime, losses from IncidentSeverity are amplified.
    pub regime_multipliers: BTreeMap<String, i64>,
}

/// Single entry in the asymmetric loss policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LossPolicyEntry {
    /// Action label (for example, `select:baseline_throughput_profile`).
    pub action_label: String,
    /// Risk dimension.
    pub dimension: String,
    /// Loss in millionths (higher = worse).
    pub loss_millionths: i64,
}

impl AsymmetricLossPolicy {
    /// Create a new empty policy.
    pub fn new(policy_id: impl Into<String>) -> Self {
        Self {
            policy_id: policy_id.into(),
            entries: Vec::new(),
            regime_multipliers: BTreeMap::new(),
        }
    }

    /// Add a loss entry.
    pub fn add_entry(
        &mut self,
        action_label: impl Into<String>,
        dimension: RiskDimension,
        loss_millionths: i64,
    ) {
        let action_label = action_label.into();
        self.entries.push(LossPolicyEntry {
            action_label: canonical_action_label(&action_label),
            dimension: dimension.to_string(),
            loss_millionths,
        });
    }

    /// Set a regime multiplier (applied to matching-dimension losses).
    pub fn set_regime_multiplier(&mut self, regime: RegimeEstimate, multiplier_millionths: i64) {
        self.regime_multipliers
            .insert(regime.to_string(), multiplier_millionths);
    }

    /// Compute expected loss for an action given current risk posteriors
    /// and active regime.
    pub fn expected_loss(
        &self,
        action_label: &str,
        risk_posteriors: &BTreeMap<String, i64>,
        regime: RegimeEstimate,
    ) -> i64 {
        let normalized_action_label = canonical_action_label(action_label);
        let regime_mult = self
            .regime_multipliers
            .get(&regime.to_string())
            .copied()
            .unwrap_or(MILLION);

        let mut total_loss: i64 = 0;
        for entry in &self.entries {
            if canonical_action_label(&entry.action_label) == normalized_action_label {
                let posterior = risk_posteriors.get(&entry.dimension).copied().unwrap_or(0);
                // E[loss] = loss * P(risk) * regime_multiplier
                // All in millionths, so divide by MILLION twice.
                let raw = entry.loss_millionths.saturating_mul(posterior) / MILLION;
                let adjusted = raw.saturating_mul(regime_mult) / MILLION;
                total_loss = total_loss.saturating_add(adjusted);
            }
        }
        total_loss
    }

    /// Select the minimum-expected-loss action from a set of candidates.
    pub fn select_min_loss_action(
        &self,
        candidates: &[String],
        risk_posteriors: &BTreeMap<String, i64>,
        regime: RegimeEstimate,
    ) -> Option<(String, i64)> {
        if candidates.is_empty() {
            return None;
        }
        let mut best_action: Option<(String, i64)> = None;
        for candidate in candidates {
            let loss = self.expected_loss(candidate, risk_posteriors, regime);
            if best_action
                .as_ref()
                .is_none_or(|(_, best_loss)| loss < *best_loss)
            {
                best_action = Some((candidate.clone(), loss));
            }
        }
        best_action
    }
}

fn canonical_action_label(action_label: &str) -> String {
    match action_label {
        "select:quickjs_inspired_native" | "select:QuickJs" => {
            format!("select:{DETERMINISTIC_PROFILE_LABEL}")
        }
        "select:v8_inspired_native" | "select:V8" => {
            format!("select:{THROUGHPUT_PROFILE_LABEL}")
        }
        _ => action_label.to_string(),
    }
}

/// Build a default asymmetric loss policy for the current dual-profile router.
pub fn default_routing_loss_policy() -> AsymmetricLossPolicy {
    let mut policy = AsymmetricLossPolicy::new("default-routing-v1");

    // SelectLane(throughput_profile): high throughput but higher compatibility risk.
    policy.add_entry(
        format!("select:{THROUGHPUT_PROFILE_LABEL}"),
        RiskDimension::Compatibility,
        400_000,
    );
    policy.add_entry(
        format!("select:{THROUGHPUT_PROFILE_LABEL}"),
        RiskDimension::Latency,
        100_000,
    );
    policy.add_entry(
        format!("select:{THROUGHPUT_PROFILE_LABEL}"),
        RiskDimension::Memory,
        300_000,
    );
    policy.add_entry(
        format!("select:{THROUGHPUT_PROFILE_LABEL}"),
        RiskDimension::IncidentSeverity,
        200_000,
    );

    // SelectLane(deterministic_profile): lower compatibility risk, stricter budgets.
    policy.add_entry(
        format!("select:{DETERMINISTIC_PROFILE_LABEL}"),
        RiskDimension::Compatibility,
        100_000,
    );
    policy.add_entry(
        format!("select:{DETERMINISTIC_PROFILE_LABEL}"),
        RiskDimension::Latency,
        400_000,
    );
    policy.add_entry(
        format!("select:{DETERMINISTIC_PROFILE_LABEL}"),
        RiskDimension::Memory,
        100_000,
    );
    policy.add_entry(
        format!("select:{DETERMINISTIC_PROFILE_LABEL}"),
        RiskDimension::IncidentSeverity,
        100_000,
    );

    // FallbackSafeMode: safest but highest latency cost.
    policy.add_entry("fallback:safe_mode", RiskDimension::Compatibility, 50_000);
    policy.add_entry("fallback:safe_mode", RiskDimension::Latency, 800_000);
    policy.add_entry("fallback:safe_mode", RiskDimension::Memory, 50_000);
    policy.add_entry(
        "fallback:safe_mode",
        RiskDimension::IncidentSeverity,
        10_000,
    );

    // Hold: no change — moderate across dimensions.
    policy.add_entry("hold", RiskDimension::Compatibility, 200_000);
    policy.add_entry("hold", RiskDimension::Latency, 200_000);
    policy.add_entry("hold", RiskDimension::Memory, 200_000);
    policy.add_entry("hold", RiskDimension::IncidentSeverity, 200_000);

    // Regime multipliers: amplify losses under adverse regimes.
    policy.set_regime_multiplier(RegimeEstimate::Normal, MILLION); // 1.0x
    policy.set_regime_multiplier(RegimeEstimate::Elevated, 1_500_000); // 1.5x
    policy.set_regime_multiplier(RegimeEstimate::Attack, 3_000_000); // 3.0x
    policy.set_regime_multiplier(RegimeEstimate::Degraded, 2_000_000); // 2.0x
    policy.set_regime_multiplier(RegimeEstimate::Recovery, 1_200_000); // 1.2x

    policy
}

// ---------------------------------------------------------------------------
// CVaRConstraint — tail-risk guardrail
// ---------------------------------------------------------------------------

/// Conditional Value-at-Risk (CVaR) constraint for tail-risk protection.
///
/// Ensures that mean improvements in routing decisions cannot hide
/// p99/p999 latency regressions.  Maintains a rolling window of
/// latency observations and computes CVaR at a configurable quantile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CVaRConstraint {
    /// Constraint identifier.
    pub constraint_id: String,
    /// Quantile level (millionths): 990_000 = 99th percentile.
    pub quantile_millionths: i64,
    /// Maximum acceptable CVaR (microseconds).
    pub max_cvar_us: u64,
    /// Rolling latency samples (microseconds).
    pub samples: Vec<u64>,
    /// Maximum sample window size.
    pub max_samples: usize,
}

/// Result of a CVaR evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CVaRResult {
    /// Computed CVaR value (microseconds).
    pub cvar_us: u64,
    /// Whether the constraint is satisfied.
    pub satisfied: bool,
    /// The VaR (quantile) value (microseconds).
    pub var_us: u64,
    /// Number of samples used.
    pub sample_count: usize,
}

impl CVaRConstraint {
    /// Create a new CVaR constraint.
    pub fn new(
        constraint_id: impl Into<String>,
        quantile_millionths: i64,
        max_cvar_us: u64,
    ) -> Self {
        Self {
            constraint_id: constraint_id.into(),
            quantile_millionths: quantile_millionths.clamp(0, MILLION),
            max_cvar_us,
            samples: Vec::new(),
            max_samples: MAX_LATENCY_SAMPLES,
        }
    }

    /// Create a default p99 constraint with a 10ms cap.
    pub fn default_p99() -> Self {
        Self::new("cvar-p99-default", DEFAULT_CVAR_QUANTILE_MILLIONTHS, 10_000)
    }

    /// Record a new latency observation.
    pub fn observe(&mut self, latency_us: u64) {
        self.samples.push(latency_us);
        if self.samples.len() > self.max_samples {
            self.samples.remove(0);
        }
    }

    /// Evaluate the CVaR constraint.
    ///
    /// CVaR(alpha) = E[X | X >= VaR(alpha)], i.e., the expected value of
    /// the tail beyond the quantile.  All arithmetic is integer-safe.
    pub fn evaluate(&self) -> CVaRResult {
        if self.samples.is_empty() {
            return CVaRResult {
                cvar_us: 0,
                satisfied: true,
                var_us: 0,
                sample_count: 0,
            };
        }

        let mut sorted = self.samples.clone();
        sorted.sort_unstable();

        let n = sorted.len();
        // VaR index: quantile * n / MILLION, clamped.
        let var_index = ((self.quantile_millionths as u64).saturating_mul(n as u64)
            / (MILLION as u64))
            .min((n as u64).saturating_sub(1)) as usize;

        let var_us = sorted[var_index];

        // CVaR: mean of all samples >= VaR.
        let tail: Vec<u64> = sorted[var_index..].to_vec();
        let tail_sum: u64 = tail.iter().sum();
        let cvar_us = if tail.is_empty() {
            var_us
        } else {
            tail_sum / tail.len() as u64
        };

        CVaRResult {
            cvar_us,
            satisfied: cvar_us <= self.max_cvar_us,
            var_us,
            sample_count: n,
        }
    }

    /// Check if the constraint is currently violated.
    pub fn is_violated(&self) -> bool {
        !self.evaluate().satisfied
    }
}

// ---------------------------------------------------------------------------
// ConformalCalibrationLayer — coverage guarantees
// ---------------------------------------------------------------------------

/// Conformal calibration layer for anytime-valid coverage guarantees.
///
/// Tracks empirical coverage of prediction intervals and triggers
/// recalibration when coverage drops below the target.  Integrates
/// with e-process guardrails for optional-stopping safety.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformalCalibrationLayer {
    /// Layer identifier.
    pub layer_id: String,
    /// Target coverage level (millionths): 950_000 = 95%.
    pub target_coverage_millionths: i64,
    /// Number of observations that fell within the prediction interval.
    pub covered_count: u64,
    /// Total observations evaluated.
    pub total_count: u64,
    /// Current nonconformity threshold (millionths).
    pub threshold_millionths: i64,
    /// Sequence of recent nonconformity scores (millionths).
    pub recent_scores: Vec<i64>,
    /// Maximum retained scores for adaptive threshold.
    pub max_scores: usize,
    /// Whether recalibration was triggered.
    pub recalibration_triggered: bool,
    /// E-value accumulator for optional-stopping safety.
    pub e_value_millionths: i64,
}

impl ConformalCalibrationLayer {
    /// Create a new calibration layer with target coverage.
    pub fn new(layer_id: impl Into<String>, target_coverage_millionths: i64) -> Self {
        Self {
            layer_id: layer_id.into(),
            target_coverage_millionths: target_coverage_millionths.clamp(0, MILLION),
            covered_count: 0,
            total_count: 0,
            threshold_millionths: 500_000, // initial threshold
            recent_scores: Vec::new(),
            max_scores: 1_000,
            recalibration_triggered: false,
            e_value_millionths: MILLION, // start at 1.0
        }
    }

    /// Observe a new nonconformity score and whether the true outcome
    /// was covered by the prediction interval.
    pub fn observe(&mut self, nonconformity_score_millionths: i64, covered: bool) {
        self.total_count += 1;
        if covered {
            self.covered_count += 1;
        }

        self.recent_scores.push(nonconformity_score_millionths);
        if self.recent_scores.len() > self.max_scores {
            self.recent_scores.remove(0);
        }

        // Update e-value: e_t = e_{t-1} * (coverage_indicator / target_coverage)
        // If covered: multiply by 1/target ≈ 1.05 for 95% target
        // If not covered: multiply by (1 - 1/target) ≈ 0 for 95% target
        let update_ratio = if covered {
            // 1 / target_coverage = MILLION / target
            MILLION.saturating_mul(MILLION) / self.target_coverage_millionths.max(1)
        } else {
            // (1 - 1/(1-target)) ... simplified: use 0 to strongly penalize
            0
        };
        self.e_value_millionths = self.e_value_millionths.saturating_mul(update_ratio) / MILLION;

        // Clamp to prevent overflow.
        self.e_value_millionths = self.e_value_millionths.clamp(0, 100 * MILLION);

        // Adaptive recalibration: update threshold from recent scores.
        self.recalibrate_threshold();
    }

    /// Current empirical coverage (millionths).
    pub fn empirical_coverage_millionths(&self) -> i64 {
        if self.total_count == 0 {
            return MILLION;
        }
        (self.covered_count as i64).saturating_mul(MILLION) / (self.total_count as i64)
    }

    /// Whether coverage is below target.
    pub fn is_undercovering(&self) -> bool {
        self.empirical_coverage_millionths() < self.target_coverage_millionths
    }

    /// Recalibrate the nonconformity threshold from recent scores.
    fn recalibrate_threshold(&mut self) {
        if self.recent_scores.is_empty() {
            return;
        }

        let mut sorted = self.recent_scores.clone();
        sorted.sort_unstable();

        let n = sorted.len();
        // Set threshold at the (1-alpha) quantile of nonconformity scores.
        let quantile_index = ((self.target_coverage_millionths as u64).saturating_mul(n as u64)
            / (MILLION as u64))
            .min((n as u64).saturating_sub(1)) as usize;

        let new_threshold = sorted[quantile_index];
        if new_threshold != self.threshold_millionths {
            self.threshold_millionths = new_threshold;
            self.recalibration_triggered = true;
        }
    }
}

// ---------------------------------------------------------------------------
// DemotionPolicy — deterministic demotion on regime change
// ---------------------------------------------------------------------------

/// Deterministic demotion policy triggered by regime changes.
///
/// When the regime detector signals a shift to an adverse regime, this
/// policy deterministically demotes the lane assignment to a safer option.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DemotionPolicy {
    /// Policy identifier.
    pub policy_id: String,
    /// Mapping from regime -> mandatory lane demotion target.
    /// If absent for a regime, no mandatory demotion occurs.
    pub regime_demotions: BTreeMap<String, LaneId>,
    /// Minimum confidence (millionths) required to stay on current lane.
    /// Below this, demotion is triggered regardless of regime.
    pub min_confidence_millionths: i64,
    /// Number of consecutive adverse observations before demotion.
    pub demotion_threshold: u64,
    /// Current consecutive adverse count.
    pub consecutive_adverse: u64,
}

impl DemotionPolicy {
    /// Create a new demotion policy.
    pub fn new(policy_id: impl Into<String>) -> Self {
        let mut regime_demotions = BTreeMap::new();
        // Attack regime always demotes to safe mode.
        regime_demotions.insert(RegimeEstimate::Attack.to_string(), LaneId::safe_mode());
        // Degraded regime demotes to quickjs (deterministic).
        regime_demotions.insert(
            RegimeEstimate::Degraded.to_string(),
            LaneId::quickjs_native(),
        );

        Self {
            policy_id: policy_id.into(),
            regime_demotions,
            min_confidence_millionths: 200_000, // 20%
            demotion_threshold: 3,
            consecutive_adverse: 0,
        }
    }

    /// Evaluate demotion given current state.
    ///
    /// Returns `Some(target_lane)` if demotion should occur, `None` otherwise.
    pub fn evaluate(
        &mut self,
        regime: RegimeEstimate,
        confidence_millionths: i64,
        is_adverse_observation: bool,
    ) -> Option<LaneId> {
        // Mandatory regime-based demotion.
        if let Some(target) = self.regime_demotions.get(&regime.to_string()) {
            self.consecutive_adverse = 0;
            return Some(target.clone());
        }

        // Confidence-based demotion.
        if confidence_millionths < self.min_confidence_millionths {
            self.consecutive_adverse = 0;
            return Some(LaneId::safe_mode());
        }

        // Consecutive-adverse demotion.
        if is_adverse_observation {
            self.consecutive_adverse += 1;
            if self.consecutive_adverse >= self.demotion_threshold {
                self.consecutive_adverse = 0;
                return Some(LaneId::quickjs_native());
            }
        } else {
            self.consecutive_adverse = 0;
        }

        None
    }

    /// Reset the consecutive adverse counter.
    pub fn reset(&mut self) {
        self.consecutive_adverse = 0;
    }
}

// ---------------------------------------------------------------------------
// AdaptiveBudget — compute/memory caps with deterministic fallback
// ---------------------------------------------------------------------------

/// Budgeted mode for adaptive logic with strict caps and deterministic
/// on-exhaust fallback.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdaptiveBudget {
    /// Budget identifier.
    pub budget_id: String,
    /// Compute budget (milliseconds per decision cycle).
    pub compute_budget_ms: u64,
    /// Memory budget (megabytes for working set).
    pub memory_budget_mb: u64,
    /// Cumulative compute consumed this epoch (milliseconds).
    pub compute_consumed_ms: u64,
    /// Peak memory observed this epoch (megabytes).
    pub peak_memory_mb: u64,
    /// Whether the budget has been exhausted.
    pub exhausted: bool,
    /// Epoch at which budget was last reset.
    pub reset_epoch: SecurityEpoch,
}

impl AdaptiveBudget {
    /// Create a new budget with defaults.
    pub fn new(budget_id: impl Into<String>, epoch: SecurityEpoch) -> Self {
        Self {
            budget_id: budget_id.into(),
            compute_budget_ms: DEFAULT_COMPUTE_BUDGET_MS,
            memory_budget_mb: DEFAULT_MEMORY_BUDGET_MB,
            compute_consumed_ms: 0,
            peak_memory_mb: 0,
            exhausted: false,
            reset_epoch: epoch,
        }
    }

    /// Record resource consumption for a decision cycle.
    pub fn record(&mut self, compute_ms: u64, memory_mb: u64) {
        self.compute_consumed_ms = self.compute_consumed_ms.saturating_add(compute_ms);
        if memory_mb > self.peak_memory_mb {
            self.peak_memory_mb = memory_mb;
        }
        self.exhausted = self.compute_consumed_ms >= self.compute_budget_ms
            || self.peak_memory_mb >= self.memory_budget_mb;
    }

    /// Check if the budget is exhausted.
    pub fn is_exhausted(&self) -> bool {
        self.exhausted
    }

    /// Remaining compute budget (milliseconds).
    pub fn remaining_compute_ms(&self) -> u64 {
        self.compute_budget_ms
            .saturating_sub(self.compute_consumed_ms)
    }

    /// Reset budget for a new epoch.
    pub fn reset(&mut self, epoch: SecurityEpoch) {
        self.compute_consumed_ms = 0;
        self.peak_memory_mb = 0;
        self.exhausted = false;
        self.reset_epoch = epoch;
    }
}

// ---------------------------------------------------------------------------
// PolicyBundle — machine-readable policy snapshot
// ---------------------------------------------------------------------------

/// Machine-readable policy bundle capturing all active policy parameters.
///
/// Serialized to JSON for audit, replay, and operator inspection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyBundle {
    /// Schema version.
    pub schema_version: String,
    /// Bundle identifier.
    pub bundle_id: String,
    /// Loss policy snapshot.
    pub loss_policy: AsymmetricLossPolicy,
    /// CVaR constraint configuration.
    pub cvar_quantile_millionths: i64,
    /// CVaR max acceptable value (microseconds).
    pub cvar_max_us: u64,
    /// Demotion policy: regime -> target lane.
    pub regime_demotions: BTreeMap<String, String>,
    /// Adaptive budget limits.
    pub compute_budget_ms: u64,
    /// Memory budget limit.
    pub memory_budget_mb: u64,
    /// Calibration target coverage.
    pub calibration_target_coverage_millionths: i64,
    /// Active epoch.
    pub epoch: SecurityEpoch,
    /// Timestamp (logical tick).
    pub timestamp_ns: u64,
}

// ---------------------------------------------------------------------------
// CalibrationLedgerEntry — calibration audit trail
// ---------------------------------------------------------------------------

/// Entry in the calibration ledger recording coverage state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CalibrationLedgerEntry {
    /// Entry sequence number.
    pub seq: u64,
    /// Empirical coverage at this point (millionths).
    pub empirical_coverage_millionths: i64,
    /// Target coverage (millionths).
    pub target_coverage_millionths: i64,
    /// Current nonconformity threshold (millionths).
    pub threshold_millionths: i64,
    /// E-value for optional-stopping safety.
    pub e_value_millionths: i64,
    /// Whether recalibration was triggered.
    pub recalibration_triggered: bool,
    /// Epoch.
    pub epoch: SecurityEpoch,
    /// Timestamp (logical tick).
    pub timestamp_ns: u64,
}

// ---------------------------------------------------------------------------
// FallbackTriggerEvent — fallback audit trail
// ---------------------------------------------------------------------------

/// Audit event recording a fallback trigger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FallbackTriggerEvent {
    /// Event sequence number.
    pub seq: u64,
    /// Reason for fallback.
    pub reason: FallbackReason,
    /// Source lane before fallback.
    pub from_lane: LaneId,
    /// Target lane after fallback.
    pub to_lane: LaneId,
    /// Regime at time of trigger.
    pub regime: RegimeEstimate,
    /// Confidence at time of trigger (millionths).
    pub confidence_millionths: i64,
    /// Epoch.
    pub epoch: SecurityEpoch,
    /// Timestamp (logical tick).
    pub timestamp_ns: u64,
}

/// Reason for a fallback trigger.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum FallbackReason {
    /// Regime change triggered demotion.
    RegimeChange(String),
    /// CVaR constraint violated.
    CVaRViolation { cvar_us: u64, max_us: u64 },
    /// Calibration coverage below target.
    CalibrationUndercoverage { coverage_millionths: i64 },
    /// Adaptive budget exhausted.
    BudgetExhausted { compute_ms: u64, memory_mb: u64 },
    /// Confidence below minimum threshold.
    LowConfidence { confidence_millionths: i64 },
    /// E-process guardrail triggered.
    EProcessTriggered { guardrail_id: String },
    /// Consecutive adverse observations exceeded threshold.
    ConsecutiveAdverse { count: u64 },
}

impl fmt::Display for FallbackReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RegimeChange(regime) => write!(f, "regime_change:{regime}"),
            Self::CVaRViolation { cvar_us, max_us } => {
                write!(f, "cvar_violation:{cvar_us}us>{max_us}us")
            }
            Self::CalibrationUndercoverage {
                coverage_millionths,
            } => {
                write!(f, "undercoverage:{coverage_millionths}")
            }
            Self::BudgetExhausted {
                compute_ms,
                memory_mb,
            } => write!(
                f,
                "budget_exhausted:compute={compute_ms}ms,mem={memory_mb}mb"
            ),
            Self::LowConfidence {
                confidence_millionths,
            } => write!(f, "low_confidence:{confidence_millionths}"),
            Self::EProcessTriggered { guardrail_id } => {
                write!(f, "eprocess_triggered:{guardrail_id}")
            }
            Self::ConsecutiveAdverse { count } => write!(f, "consecutive_adverse:{count}"),
        }
    }
}

// ---------------------------------------------------------------------------
// DecisionTrace — replay-stable decision record
// ---------------------------------------------------------------------------

/// A single replay-stable decision trace entry.
///
/// Contains all inputs and outputs for a routing decision, enabling
/// bit-exact replay from fixed artifacts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionTraceEntry {
    /// Decision sequence number.
    pub seq: u64,
    /// Routing state snapshot before decision.
    pub state_before: LaneRoutingState,
    /// Action selected.
    pub action: RoutingAction,
    /// Expected loss of selected action (millionths).
    pub expected_loss_millionths: i64,
    /// CVaR at time of decision (microseconds).
    pub cvar_us: u64,
    /// Whether a fallback was triggered.
    pub fallback_triggered: bool,
    /// Fallback reason, if any.
    pub fallback_reason: Option<FallbackReason>,
    /// Epoch.
    pub epoch: SecurityEpoch,
    /// Timestamp (logical tick).
    pub timestamp_ns: u64,
}

// ---------------------------------------------------------------------------
// DecisionCoreError — error types
// ---------------------------------------------------------------------------

/// Errors from the runtime decision core.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DecisionCoreError {
    /// No available lanes configured.
    NoLanesConfigured,
    /// No candidates in the action set.
    EmptyActionSet,
    /// Budget exhausted and no fallback lane available.
    BudgetExhaustedNoFallback,
    /// Epoch regression detected.
    EpochRegression { current: u64, received: u64 },
    /// Invalid configuration parameter.
    InvalidConfig(String),
}

impl fmt::Display for DecisionCoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoLanesConfigured => write!(f, "no lanes configured"),
            Self::EmptyActionSet => write!(f, "empty action set"),
            Self::BudgetExhaustedNoFallback => {
                write!(f, "budget exhausted with no fallback lane")
            }
            Self::EpochRegression { current, received } => {
                write!(
                    f,
                    "epoch regression: current={current}, received={received}"
                )
            }
            Self::InvalidConfig(msg) => write!(f, "invalid config: {msg}"),
        }
    }
}

impl std::error::Error for DecisionCoreError {}

// ---------------------------------------------------------------------------
// RuntimeDecisionCore — unified orchestrator
// ---------------------------------------------------------------------------

/// Unified runtime decision core orchestrating lane routing, loss-optimal
/// action selection, calibration, tail-risk guardrails, regime detection,
/// and budgeted adaptive mode.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeDecisionCore {
    /// Core identifier.
    pub core_id: String,
    /// Current routing state.
    pub state: LaneRoutingState,
    /// Asymmetric loss policy.
    pub loss_policy: AsymmetricLossPolicy,
    /// CVaR tail-risk constraint.
    pub cvar_constraint: CVaRConstraint,
    /// Conformal calibration layer.
    pub calibration: ConformalCalibrationLayer,
    /// Demotion policy.
    pub demotion_policy: DemotionPolicy,
    /// Adaptive budget.
    pub budget: AdaptiveBudget,
    /// Available lane identifiers.
    pub available_lanes: Vec<LaneId>,
    /// Decision trace log.
    pub trace: Vec<DecisionTraceEntry>,
    /// Calibration ledger.
    pub calibration_ledger: Vec<CalibrationLedgerEntry>,
    /// Fallback trigger events.
    pub fallback_events: Vec<FallbackTriggerEvent>,
    /// Decision sequence counter.
    pub decision_seq: u64,
    /// Calibration ledger sequence counter.
    pub calibration_seq: u64,
    /// Fallback event sequence counter.
    pub fallback_seq: u64,
}

/// Input for a routing decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoutingDecisionInput {
    /// Observed latency from last execution (microseconds).
    pub observed_latency_us: u64,
    /// Updated risk posteriors (dimension_name -> millionths).
    pub risk_posteriors: BTreeMap<String, i64>,
    /// Current regime estimate.
    pub regime: RegimeEstimate,
    /// Confidence in current assignment (millionths).
    pub confidence_millionths: i64,
    /// Whether the last observation was adverse.
    pub is_adverse: bool,
    /// Nonconformity score for calibration (millionths).
    pub nonconformity_score_millionths: i64,
    /// Whether the calibration prediction interval covered the true outcome.
    pub calibration_covered: bool,
    /// Compute time consumed this cycle (milliseconds).
    pub compute_ms: u64,
    /// Memory used this cycle (megabytes).
    pub memory_mb: u64,
    /// Current epoch.
    pub epoch: SecurityEpoch,
    /// Current logical timestamp.
    pub timestamp_ns: u64,
}

/// Output from a routing decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoutingDecisionOutput {
    /// Selected action.
    pub action: RoutingAction,
    /// Expected loss of selected action (millionths).
    pub expected_loss_millionths: i64,
    /// Whether a fallback was triggered.
    pub fallback_triggered: bool,
    /// Fallback reason, if any.
    pub fallback_reason: Option<FallbackReason>,
    /// CVaR at time of decision.
    pub cvar_result: CVaRResult,
    /// Decision sequence number.
    pub decision_seq: u64,
}

impl RuntimeDecisionCore {
    /// Create a new decision core with the given lanes and default configuration.
    pub fn new(
        core_id: impl Into<String>,
        available_lanes: Vec<LaneId>,
        default_lane: LaneId,
        epoch: SecurityEpoch,
    ) -> Result<Self, DecisionCoreError> {
        if available_lanes.is_empty() {
            return Err(DecisionCoreError::NoLanesConfigured);
        }

        let core_id = core_id.into();
        Ok(Self {
            core_id: core_id.clone(),
            state: LaneRoutingState::initial(default_lane, epoch),
            loss_policy: default_routing_loss_policy(),
            cvar_constraint: CVaRConstraint::default_p99(),
            calibration: ConformalCalibrationLayer::new(
                format!("{core_id}-calibration"),
                950_000, // 95% coverage target
            ),
            demotion_policy: DemotionPolicy::new(format!("{core_id}-demotion")),
            budget: AdaptiveBudget::new(format!("{core_id}-budget"), epoch),
            available_lanes,
            trace: Vec::new(),
            calibration_ledger: Vec::new(),
            fallback_events: Vec::new(),
            decision_seq: 0,
            calibration_seq: 0,
            fallback_seq: 0,
        })
    }

    /// Process a routing decision given new observations.
    ///
    /// This is the main entry point: it integrates all subsystems
    /// (loss policy, CVaR, calibration, demotion, budget) and returns
    /// the optimal action with full audit trail.
    pub fn decide(
        &mut self,
        input: &RoutingDecisionInput,
    ) -> Result<RoutingDecisionOutput, DecisionCoreError> {
        // 1. Epoch check.
        if input.epoch.as_u64() < self.state.epoch.as_u64() {
            return Err(DecisionCoreError::EpochRegression {
                current: self.state.epoch.as_u64(),
                received: input.epoch.as_u64(),
            });
        }

        // 2. Update state.
        self.state.epoch = input.epoch;
        self.state.confidence_millionths = input.confidence_millionths;
        self.state.regime = input.regime;
        self.state.risk_posteriors = input.risk_posteriors.clone();
        self.state.decision_count += 1;

        // 3. Record latency and update CVaR.
        self.cvar_constraint.observe(input.observed_latency_us);
        self.state
            .recent_latencies_us
            .push(input.observed_latency_us);
        if self.state.recent_latencies_us.len() > MAX_LATENCY_SAMPLES {
            self.state.recent_latencies_us.remove(0);
        }

        // 4. Update calibration.
        self.calibration.observe(
            input.nonconformity_score_millionths,
            input.calibration_covered,
        );

        // 5. Record budget consumption.
        self.budget.record(input.compute_ms, input.memory_mb);

        // 6. Emit calibration ledger entry.
        let cal_entry = CalibrationLedgerEntry {
            seq: self.calibration_seq,
            empirical_coverage_millionths: self.calibration.empirical_coverage_millionths(),
            target_coverage_millionths: self.calibration.target_coverage_millionths,
            threshold_millionths: self.calibration.threshold_millionths,
            e_value_millionths: self.calibration.e_value_millionths,
            recalibration_triggered: self.calibration.recalibration_triggered,
            epoch: input.epoch,
            timestamp_ns: input.timestamp_ns,
        };
        self.calibration_seq += 1;
        self.calibration_ledger.push(cal_entry);
        // Trim ledger.
        if self.calibration_ledger.len() > MAX_TRACE_ENTRIES {
            self.calibration_ledger.remove(0);
        }

        // 7. Check fallback triggers (priority order: budget -> CVaR -> regime -> confidence -> calibration).
        let mut fallback_reason: Option<FallbackReason> = None;

        // 7a. Budget exhausted.
        if self.budget.is_exhausted() {
            fallback_reason = Some(FallbackReason::BudgetExhausted {
                compute_ms: self.budget.compute_consumed_ms,
                memory_mb: self.budget.peak_memory_mb,
            });
        }

        // 7b. CVaR violated.
        let cvar_result = self.cvar_constraint.evaluate();
        if fallback_reason.is_none() && !cvar_result.satisfied {
            fallback_reason = Some(FallbackReason::CVaRViolation {
                cvar_us: cvar_result.cvar_us,
                max_us: self.cvar_constraint.max_cvar_us,
            });
        }

        // 7c. Demotion policy (regime change or confidence).
        if fallback_reason.is_none()
            && let Some(target) = self.demotion_policy.evaluate(
                input.regime,
                input.confidence_millionths,
                input.is_adverse,
            )
        {
            let reason = if self
                .demotion_policy
                .regime_demotions
                .contains_key(&input.regime.to_string())
            {
                FallbackReason::RegimeChange(input.regime.to_string())
            } else if input.confidence_millionths < self.demotion_policy.min_confidence_millionths {
                FallbackReason::LowConfidence {
                    confidence_millionths: input.confidence_millionths,
                }
            } else {
                FallbackReason::ConsecutiveAdverse {
                    count: self.demotion_policy.demotion_threshold,
                }
            };
            fallback_reason = Some(reason);
            // Override target lane.
            self.state.active_lane = target;
        }

        // 7d. Calibration undercoverage.
        if fallback_reason.is_none()
            && self.calibration.is_undercovering()
            && self.calibration.total_count >= 20
        {
            fallback_reason = Some(FallbackReason::CalibrationUndercoverage {
                coverage_millionths: self.calibration.empirical_coverage_millionths(),
            });
        }

        // 8. Select action.
        let (action, expected_loss) = if let Some(ref reason) = fallback_reason {
            // Fallback: select safe mode or demotion target.
            let target_lane = match reason {
                FallbackReason::RegimeChange(_) | FallbackReason::ConsecutiveAdverse { .. } => {
                    // Demotion policy already set state.active_lane.
                    self.state.active_lane.clone()
                }
                _ => LaneId::safe_mode(),
            };

            // Emit fallback event.
            let event = FallbackTriggerEvent {
                seq: self.fallback_seq,
                reason: reason.clone(),
                from_lane: self.state.active_lane.clone(),
                to_lane: target_lane.clone(),
                regime: input.regime,
                confidence_millionths: input.confidence_millionths,
                epoch: input.epoch,
                timestamp_ns: input.timestamp_ns,
            };
            self.fallback_seq += 1;
            self.fallback_events.push(event);
            if self.fallback_events.len() > MAX_TRACE_ENTRIES {
                self.fallback_events.remove(0);
            }

            self.state.safe_mode_active = true;
            let action = RoutingAction::SelectLane(target_lane.clone());
            let loss = self.loss_policy.expected_loss(
                &action.to_string(),
                &self.state.risk_posteriors,
                input.regime,
            );
            self.state.active_lane = target_lane;
            (action, loss)
        } else {
            // Normal: select min-loss action.
            self.state.safe_mode_active = false;
            let candidates: Vec<String> = self
                .available_lanes
                .iter()
                .map(|l| format!("select:{l}"))
                .chain(std::iter::once("hold".to_string()))
                .collect();

            if let Some((best_label, best_loss)) = self.loss_policy.select_min_loss_action(
                &candidates,
                &self.state.risk_posteriors,
                input.regime,
            ) {
                let action = if best_label == "hold" {
                    RoutingAction::Hold
                } else if let Some(lane_str) = best_label.strip_prefix("select:") {
                    let lane = LaneId::from_label(lane_str);
                    self.state.active_lane = lane.clone();
                    RoutingAction::SelectLane(lane)
                } else {
                    RoutingAction::Hold
                };
                (action, best_loss)
            } else {
                (RoutingAction::Hold, 0)
            }
        };

        // 9. Record decision trace.
        let trace_entry = DecisionTraceEntry {
            seq: self.decision_seq,
            state_before: self.state.clone(),
            action: action.clone(),
            expected_loss_millionths: expected_loss,
            cvar_us: cvar_result.cvar_us,
            fallback_triggered: fallback_reason.is_some(),
            fallback_reason: fallback_reason.clone(),
            epoch: input.epoch,
            timestamp_ns: input.timestamp_ns,
        };
        self.decision_seq += 1;
        self.trace.push(trace_entry);
        if self.trace.len() > MAX_TRACE_ENTRIES {
            self.trace.remove(0);
        }

        Ok(RoutingDecisionOutput {
            action,
            expected_loss_millionths: expected_loss,
            fallback_triggered: fallback_reason.is_some(),
            fallback_reason,
            cvar_result,
            decision_seq: self.decision_seq - 1,
        })
    }

    /// Export current policy bundle for audit/replay.
    pub fn export_policy_bundle(&self, timestamp_ns: u64) -> PolicyBundle {
        PolicyBundle {
            schema_version: DECISION_CORE_SCHEMA_VERSION.to_string(),
            bundle_id: format!("{}-bundle-{}", self.core_id, self.decision_seq),
            loss_policy: self.loss_policy.clone(),
            cvar_quantile_millionths: self.cvar_constraint.quantile_millionths,
            cvar_max_us: self.cvar_constraint.max_cvar_us,
            regime_demotions: self
                .demotion_policy
                .regime_demotions
                .iter()
                .map(|(k, v)| (k.clone(), v.0.clone()))
                .collect(),
            compute_budget_ms: self.budget.compute_budget_ms,
            memory_budget_mb: self.budget.memory_budget_mb,
            calibration_target_coverage_millionths: self.calibration.target_coverage_millionths,
            epoch: self.state.epoch,
            timestamp_ns,
        }
    }

    /// Reset budget for a new epoch.
    pub fn reset_budget(&mut self, epoch: SecurityEpoch) {
        self.budget.reset(epoch);
    }

    /// Get the current decision count.
    pub fn decision_count(&self) -> u64 {
        self.decision_seq
    }

    /// Get the current CVaR result.
    pub fn current_cvar(&self) -> CVaRResult {
        self.cvar_constraint.evaluate()
    }

    /// Get the current empirical coverage.
    pub fn current_coverage_millionths(&self) -> i64 {
        self.calibration.empirical_coverage_millionths()
    }

    /// Check if any fallback is currently active.
    pub fn is_fallback_active(&self) -> bool {
        self.state.safe_mode_active
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- helpers --

    fn epoch(n: u64) -> SecurityEpoch {
        SecurityEpoch::from_raw(n)
    }

    fn default_risk_posteriors() -> BTreeMap<String, i64> {
        let mut m = BTreeMap::new();
        for dim in RiskDimension::ALL {
            m.insert(dim.to_string(), 100_000); // 10%
        }
        m
    }

    fn high_risk_posteriors() -> BTreeMap<String, i64> {
        let mut m = BTreeMap::new();
        m.insert(RiskDimension::Compatibility.to_string(), 800_000);
        m.insert(RiskDimension::Latency.to_string(), 600_000);
        m.insert(RiskDimension::Memory.to_string(), 700_000);
        m.insert(RiskDimension::IncidentSeverity.to_string(), 900_000);
        m
    }

    fn make_input(
        latency_us: u64,
        regime: RegimeEstimate,
        confidence: i64,
        is_adverse: bool,
        epoch_val: u64,
    ) -> RoutingDecisionInput {
        RoutingDecisionInput {
            observed_latency_us: latency_us,
            risk_posteriors: default_risk_posteriors(),
            regime,
            confidence_millionths: confidence,
            is_adverse,
            nonconformity_score_millionths: 300_000,
            calibration_covered: true,
            compute_ms: 5,
            memory_mb: 32,
            epoch: epoch(epoch_val),
            timestamp_ns: epoch_val * 1_000_000,
        }
    }

    fn make_core() -> RuntimeDecisionCore {
        RuntimeDecisionCore::new(
            "test-core",
            vec![LaneId::quickjs_native(), LaneId::v8_native()],
            LaneId::quickjs_native(),
            epoch(1),
        )
        .unwrap()
    }

    // -- LaneId tests --

    #[test]
    fn lane_id_display() {
        assert_eq!(
            LaneId::quickjs_native().to_string(),
            DETERMINISTIC_PROFILE_LABEL
        );
        assert_eq!(LaneId::v8_native().to_string(), THROUGHPUT_PROFILE_LABEL);
        assert_eq!(LaneId::safe_mode().to_string(), "safe_mode");
    }

    #[test]
    fn lane_id_ordering() {
        let q = LaneId::quickjs_native();
        let v = LaneId::v8_native();
        let s = LaneId::safe_mode();
        let mut lanes = vec![v.clone(), s.clone(), q.clone()];
        lanes.sort();
        assert_eq!(lanes, vec![q, v, s]);
    }

    #[test]
    fn lane_id_serde_roundtrip() {
        let lane = LaneId::v8_native();
        let json = serde_json::to_string(&lane).unwrap();
        assert_eq!(json, format!("\"{THROUGHPUT_PROFILE_LABEL}\""));
        let back: LaneId = serde_json::from_str(&json).unwrap();
        assert_eq!(lane, back);
    }

    #[test]
    fn lane_id_deserialize_accepts_legacy_lineage_labels() {
        let back: LaneId = serde_json::from_str("\"v8_inspired_native\"").unwrap();
        assert_eq!(back, LaneId::v8_native());
        assert_eq!(back.to_string(), THROUGHPUT_PROFILE_LABEL);
    }

    // -- RiskDimension tests --

    #[test]
    fn risk_dimension_all_has_four_variants() {
        assert_eq!(RiskDimension::ALL.len(), 4);
    }

    #[test]
    fn risk_dimension_display() {
        assert_eq!(RiskDimension::Compatibility.to_string(), "compatibility");
        assert_eq!(RiskDimension::Latency.to_string(), "latency");
        assert_eq!(RiskDimension::Memory.to_string(), "memory");
        assert_eq!(
            RiskDimension::IncidentSeverity.to_string(),
            "incident_severity"
        );
    }

    // -- RoutingAction tests --

    #[test]
    fn routing_action_display() {
        assert_eq!(
            RoutingAction::SelectLane(LaneId::v8_native()).to_string(),
            format!("select:{THROUGHPUT_PROFILE_LABEL}")
        );
        assert_eq!(
            RoutingAction::FallbackSafeMode.to_string(),
            "fallback:safe_mode"
        );
        assert_eq!(
            RoutingAction::EscalateToOperator.to_string(),
            "escalate:operator"
        );
        assert_eq!(RoutingAction::Hold.to_string(), "hold");
    }

    #[test]
    fn routing_action_serde_roundtrip() {
        let action = RoutingAction::SelectLane(LaneId::quickjs_native());
        let json = serde_json::to_string(&action).unwrap();
        let back: RoutingAction = serde_json::from_str(&json).unwrap();
        assert_eq!(action, back);
    }

    // -- RegimeEstimate tests --

    #[test]
    fn regime_estimate_display() {
        assert_eq!(RegimeEstimate::Normal.to_string(), "normal");
        assert_eq!(RegimeEstimate::Attack.to_string(), "attack");
        assert_eq!(RegimeEstimate::Degraded.to_string(), "degraded");
        assert_eq!(RegimeEstimate::Recovery.to_string(), "recovery");
        assert_eq!(RegimeEstimate::Elevated.to_string(), "elevated");
    }

    // -- AsymmetricLossPolicy tests --

    #[test]
    fn default_loss_policy_has_all_dimensions() {
        let policy = default_routing_loss_policy();
        assert!(!policy.entries.is_empty());
        // Should have entries for all 4 actions * 4 dimensions = 16.
        assert_eq!(policy.entries.len(), 16);
    }

    #[test]
    fn default_loss_policy_has_regime_multipliers() {
        let policy = default_routing_loss_policy();
        assert_eq!(policy.regime_multipliers.len(), 5);
        assert_eq!(
            policy.regime_multipliers.get("normal").copied(),
            Some(MILLION)
        );
        assert_eq!(
            policy.regime_multipliers.get("attack").copied(),
            Some(3_000_000)
        );
    }

    #[test]
    fn expected_loss_zero_posteriors_returns_zero() {
        let policy = default_routing_loss_policy();
        let posteriors = BTreeMap::new();
        let loss = policy.expected_loss("hold", &posteriors, RegimeEstimate::Normal);
        assert_eq!(loss, 0);
    }

    #[test]
    fn expected_loss_increases_under_attack_regime() {
        let policy = default_routing_loss_policy();
        let posteriors = default_risk_posteriors();
        let normal_loss = policy.expected_loss(
            &format!("select:{THROUGHPUT_PROFILE_LABEL}"),
            &posteriors,
            RegimeEstimate::Normal,
        );
        let attack_loss = policy.expected_loss(
            &format!("select:{THROUGHPUT_PROFILE_LABEL}"),
            &posteriors,
            RegimeEstimate::Attack,
        );
        assert!(
            attack_loss > normal_loss,
            "attack loss {attack_loss} should exceed normal loss {normal_loss}"
        );
    }

    #[test]
    fn expected_loss_higher_posteriors_increase_loss() {
        let policy = default_routing_loss_policy();
        let low = default_risk_posteriors();
        let high = high_risk_posteriors();
        let low_loss = policy.expected_loss(
            &format!("select:{THROUGHPUT_PROFILE_LABEL}"),
            &low,
            RegimeEstimate::Normal,
        );
        let high_loss = policy.expected_loss(
            &format!("select:{THROUGHPUT_PROFILE_LABEL}"),
            &high,
            RegimeEstimate::Normal,
        );
        assert!(
            high_loss > low_loss,
            "high-risk loss {high_loss} should exceed low-risk loss {low_loss}"
        );
    }

    #[test]
    fn select_min_loss_action_empty_candidates_returns_none() {
        let policy = default_routing_loss_policy();
        assert!(
            policy
                .select_min_loss_action(&[], &default_risk_posteriors(), RegimeEstimate::Normal)
                .is_none()
        );
    }

    #[test]
    fn select_min_loss_action_picks_lowest() {
        let policy = default_routing_loss_policy();
        let posteriors = default_risk_posteriors();
        let candidates = vec![
            format!("select:{THROUGHPUT_PROFILE_LABEL}"),
            format!("select:{DETERMINISTIC_PROFILE_LABEL}"),
            "hold".to_string(),
        ];
        let (best, _loss) = policy
            .select_min_loss_action(&candidates, &posteriors, RegimeEstimate::Normal)
            .unwrap();
        // deterministic profile should be cheapest under low risk.
        assert_eq!(best, format!("select:{DETERMINISTIC_PROFILE_LABEL}"));
    }

    #[test]
    fn loss_policy_serde_roundtrip() {
        let policy = default_routing_loss_policy();
        let json = serde_json::to_string(&policy).unwrap();
        let back: AsymmetricLossPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(policy, back);
    }

    // -- CVaRConstraint tests --

    #[test]
    fn cvar_empty_samples_satisfied() {
        let cvar = CVaRConstraint::default_p99();
        let result = cvar.evaluate();
        assert!(result.satisfied);
        assert_eq!(result.sample_count, 0);
    }

    #[test]
    fn cvar_single_sample_below_max() {
        let mut cvar = CVaRConstraint::default_p99();
        cvar.observe(5_000); // 5ms
        let result = cvar.evaluate();
        assert!(result.satisfied);
        assert_eq!(result.cvar_us, 5_000);
    }

    #[test]
    fn cvar_single_sample_above_max() {
        let mut cvar = CVaRConstraint::new("test", 990_000, 1_000);
        cvar.observe(5_000); // 5ms > 1ms max
        let result = cvar.evaluate();
        assert!(!result.satisfied);
    }

    #[test]
    fn cvar_tail_captures_worst_samples() {
        let mut cvar = CVaRConstraint::new("test", 900_000, 100_000);
        // 100 samples: 90 at 1ms, 10 at 50ms.
        for _ in 0..90 {
            cvar.observe(1_000);
        }
        for _ in 0..10 {
            cvar.observe(50_000);
        }
        let result = cvar.evaluate();
        // p90 tail is the top 10%, which is exactly the 50ms samples.
        assert_eq!(result.var_us, 50_000);
        assert_eq!(result.cvar_us, 50_000);
    }

    #[test]
    fn cvar_is_violated_helper() {
        let mut cvar = CVaRConstraint::new("test", 990_000, 1_000);
        assert!(!cvar.is_violated()); // empty
        cvar.observe(5_000);
        assert!(cvar.is_violated()); // 5ms > 1ms
    }

    #[test]
    fn cvar_respects_max_samples() {
        let mut cvar = CVaRConstraint::new("test", 990_000, 100_000);
        cvar.max_samples = 100;
        for i in 0..200 {
            cvar.observe(i);
        }
        assert_eq!(cvar.samples.len(), 100);
    }

    #[test]
    fn cvar_serde_roundtrip() {
        let mut cvar = CVaRConstraint::default_p99();
        cvar.observe(1_000);
        cvar.observe(2_000);
        let json = serde_json::to_string(&cvar).unwrap();
        let back: CVaRConstraint = serde_json::from_str(&json).unwrap();
        assert_eq!(cvar.samples, back.samples);
    }

    // -- ConformalCalibrationLayer tests --

    #[test]
    fn calibration_initial_coverage_is_full() {
        let cal = ConformalCalibrationLayer::new("test", 950_000);
        assert_eq!(cal.empirical_coverage_millionths(), MILLION);
        assert!(!cal.is_undercovering());
    }

    #[test]
    fn calibration_perfect_coverage() {
        let mut cal = ConformalCalibrationLayer::new("test", 950_000);
        for _ in 0..100 {
            cal.observe(100_000, true);
        }
        assert_eq!(cal.empirical_coverage_millionths(), MILLION);
        assert!(!cal.is_undercovering());
    }

    #[test]
    fn calibration_undercoverage_detected() {
        let mut cal = ConformalCalibrationLayer::new("test", 950_000);
        // 80 covered, 20 not covered => 80% < 95% target.
        for _ in 0..80 {
            cal.observe(100_000, true);
        }
        for _ in 0..20 {
            cal.observe(900_000, false);
        }
        assert!(cal.is_undercovering());
        let coverage = cal.empirical_coverage_millionths();
        assert_eq!(coverage, 800_000); // 80%
    }

    #[test]
    fn calibration_threshold_adapts() {
        let mut cal = ConformalCalibrationLayer::new("test", 950_000);
        let initial_threshold = cal.threshold_millionths;
        for i in 0..100 {
            cal.observe(i * 10_000, true);
        }
        // Threshold should have changed from initial.
        assert_ne!(cal.threshold_millionths, initial_threshold);
    }

    #[test]
    fn calibration_serde_roundtrip() {
        let mut cal = ConformalCalibrationLayer::new("test", 950_000);
        cal.observe(100_000, true);
        let json = serde_json::to_string(&cal).unwrap();
        let back: ConformalCalibrationLayer = serde_json::from_str(&json).unwrap();
        assert_eq!(cal.total_count, back.total_count);
    }

    // -- DemotionPolicy tests --

    #[test]
    fn demotion_attack_regime_triggers_safe_mode() {
        let mut policy = DemotionPolicy::new("test");
        let result = policy.evaluate(RegimeEstimate::Attack, 900_000, false);
        assert_eq!(result, Some(LaneId::safe_mode()));
    }

    #[test]
    fn demotion_degraded_regime_triggers_quickjs() {
        let mut policy = DemotionPolicy::new("test");
        let result = policy.evaluate(RegimeEstimate::Degraded, 900_000, false);
        assert_eq!(result, Some(LaneId::quickjs_native()));
    }

    #[test]
    fn demotion_normal_regime_no_demotion() {
        let mut policy = DemotionPolicy::new("test");
        let result = policy.evaluate(RegimeEstimate::Normal, 900_000, false);
        assert!(result.is_none());
    }

    #[test]
    fn demotion_low_confidence_triggers() {
        let mut policy = DemotionPolicy::new("test");
        let result = policy.evaluate(RegimeEstimate::Normal, 100_000, false);
        assert_eq!(result, Some(LaneId::safe_mode()));
    }

    #[test]
    fn demotion_consecutive_adverse_triggers() {
        let mut policy = DemotionPolicy::new("test");
        policy.demotion_threshold = 3;
        assert!(
            policy
                .evaluate(RegimeEstimate::Normal, 900_000, true)
                .is_none()
        );
        assert!(
            policy
                .evaluate(RegimeEstimate::Normal, 900_000, true)
                .is_none()
        );
        let result = policy.evaluate(RegimeEstimate::Normal, 900_000, true);
        assert_eq!(result, Some(LaneId::quickjs_native()));
    }

    #[test]
    fn demotion_adverse_resets_on_good_observation() {
        let mut policy = DemotionPolicy::new("test");
        policy.demotion_threshold = 3;
        assert!(
            policy
                .evaluate(RegimeEstimate::Normal, 900_000, true)
                .is_none()
        );
        assert!(
            policy
                .evaluate(RegimeEstimate::Normal, 900_000, true)
                .is_none()
        );
        // Good observation resets counter.
        assert!(
            policy
                .evaluate(RegimeEstimate::Normal, 900_000, false)
                .is_none()
        );
        // Need 3 more consecutive.
        assert!(
            policy
                .evaluate(RegimeEstimate::Normal, 900_000, true)
                .is_none()
        );
        assert!(
            policy
                .evaluate(RegimeEstimate::Normal, 900_000, true)
                .is_none()
        );
        let result = policy.evaluate(RegimeEstimate::Normal, 900_000, true);
        assert_eq!(result, Some(LaneId::quickjs_native()));
    }

    #[test]
    fn demotion_reset_clears_counter() {
        let mut policy = DemotionPolicy::new("test");
        policy.evaluate(RegimeEstimate::Normal, 900_000, true);
        policy.evaluate(RegimeEstimate::Normal, 900_000, true);
        assert_eq!(policy.consecutive_adverse, 2);
        policy.reset();
        assert_eq!(policy.consecutive_adverse, 0);
    }

    // -- AdaptiveBudget tests --

    #[test]
    fn budget_initial_not_exhausted() {
        let budget = AdaptiveBudget::new("test", epoch(1));
        assert!(!budget.is_exhausted());
        assert_eq!(budget.remaining_compute_ms(), DEFAULT_COMPUTE_BUDGET_MS);
    }

    #[test]
    fn budget_compute_exhaustion() {
        let mut budget = AdaptiveBudget::new("test", epoch(1));
        budget.record(25, 10);
        assert!(!budget.is_exhausted());
        budget.record(30, 10);
        assert!(budget.is_exhausted());
    }

    #[test]
    fn budget_memory_exhaustion() {
        let mut budget = AdaptiveBudget::new("test", epoch(1));
        budget.record(1, 200); // 200 MB > 128 MB default
        assert!(budget.is_exhausted());
    }

    #[test]
    fn budget_reset() {
        let mut budget = AdaptiveBudget::new("test", epoch(1));
        budget.record(60, 200);
        assert!(budget.is_exhausted());
        budget.reset(epoch(2));
        assert!(!budget.is_exhausted());
        assert_eq!(budget.remaining_compute_ms(), DEFAULT_COMPUTE_BUDGET_MS);
    }

    #[test]
    fn budget_remaining_decreases() {
        let mut budget = AdaptiveBudget::new("test", epoch(1));
        budget.record(10, 0);
        assert_eq!(
            budget.remaining_compute_ms(),
            DEFAULT_COMPUTE_BUDGET_MS - 10
        );
    }

    #[test]
    fn budget_serde_roundtrip() {
        let budget = AdaptiveBudget::new("test", epoch(1));
        let json = serde_json::to_string(&budget).unwrap();
        let back: AdaptiveBudget = serde_json::from_str(&json).unwrap();
        assert_eq!(budget.budget_id, back.budget_id);
    }

    // -- RuntimeDecisionCore tests --

    #[test]
    fn core_creation_succeeds() {
        let core = make_core();
        assert_eq!(core.decision_count(), 0);
        assert!(!core.is_fallback_active());
    }

    #[test]
    fn core_creation_empty_lanes_fails() {
        let result = RuntimeDecisionCore::new("test", vec![], LaneId::quickjs_native(), epoch(1));
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), DecisionCoreError::NoLanesConfigured);
    }

    #[test]
    fn core_normal_decision() {
        let mut core = make_core();
        let input = make_input(1_000, RegimeEstimate::Normal, 800_000, false, 1);
        let output = core.decide(&input).unwrap();
        assert!(!output.fallback_triggered);
        assert_eq!(core.decision_count(), 1);
    }

    #[test]
    fn core_epoch_regression_rejected() {
        let mut core = make_core();
        let input1 = make_input(1_000, RegimeEstimate::Normal, 800_000, false, 5);
        core.decide(&input1).unwrap();
        let input2 = make_input(1_000, RegimeEstimate::Normal, 800_000, false, 3);
        let result = core.decide(&input2);
        assert!(result.is_err());
    }

    #[test]
    fn core_attack_regime_triggers_fallback() {
        let mut core = make_core();
        let input = make_input(1_000, RegimeEstimate::Attack, 800_000, false, 1);
        let output = core.decide(&input).unwrap();
        assert!(output.fallback_triggered);
        assert!(matches!(
            output.fallback_reason,
            Some(FallbackReason::RegimeChange(_))
        ));
    }

    #[test]
    fn core_degraded_regime_triggers_fallback() {
        let mut core = make_core();
        let input = make_input(1_000, RegimeEstimate::Degraded, 800_000, false, 1);
        let output = core.decide(&input).unwrap();
        assert!(output.fallback_triggered);
    }

    #[test]
    fn core_low_confidence_triggers_fallback() {
        let mut core = make_core();
        let input = make_input(1_000, RegimeEstimate::Normal, 100_000, false, 1);
        let output = core.decide(&input).unwrap();
        assert!(output.fallback_triggered);
        assert!(matches!(
            output.fallback_reason,
            Some(FallbackReason::LowConfidence { .. })
        ));
    }

    #[test]
    fn core_budget_exhaustion_triggers_fallback() {
        let mut core = make_core();
        // First consume most of budget.
        let input1 = make_input(1_000, RegimeEstimate::Normal, 800_000, false, 1);
        core.decide(&input1).unwrap();

        // Force budget exhaustion.
        core.budget.record(100, 0);

        let input2 = make_input(1_000, RegimeEstimate::Normal, 800_000, false, 2);
        let output = core.decide(&input2).unwrap();
        assert!(output.fallback_triggered);
        assert!(matches!(
            output.fallback_reason,
            Some(FallbackReason::BudgetExhausted { .. })
        ));
    }

    #[test]
    fn core_cvar_violation_triggers_fallback() {
        let mut core = make_core();
        core.cvar_constraint.max_cvar_us = 1_000; // 1ms cap
        // Raise budget so it doesn't exhaust before CVaR triggers.
        core.budget.compute_budget_ms = 10_000;

        // Feed high-latency samples.
        for _ in 0..10 {
            let input = make_input(50_000, RegimeEstimate::Normal, 800_000, false, 1);
            let _ = core.decide(&input);
        }

        let input = make_input(50_000, RegimeEstimate::Normal, 800_000, false, 1);
        let output = core.decide(&input).unwrap();
        assert!(output.fallback_triggered);
        assert!(matches!(
            output.fallback_reason,
            Some(FallbackReason::CVaRViolation { .. })
        ));
    }

    #[test]
    fn core_consecutive_adverse_triggers_fallback() {
        let mut core = make_core();
        core.demotion_policy.demotion_threshold = 3;

        for i in 0..3 {
            let input = make_input(1_000, RegimeEstimate::Normal, 800_000, true, i + 1);
            let output = core.decide(&input).unwrap();
            if i < 2 {
                assert!(!output.fallback_triggered, "should not trigger at step {i}");
            } else {
                assert!(output.fallback_triggered, "should trigger at step {i}");
                assert!(matches!(
                    output.fallback_reason,
                    Some(FallbackReason::ConsecutiveAdverse { .. })
                ));
            }
        }
    }

    #[test]
    fn core_trace_grows() {
        let mut core = make_core();
        for i in 0..5 {
            let input = make_input(1_000, RegimeEstimate::Normal, 800_000, false, i + 1);
            core.decide(&input).unwrap();
        }
        assert_eq!(core.trace.len(), 5);
    }

    #[test]
    fn core_calibration_ledger_grows() {
        let mut core = make_core();
        for i in 0..5 {
            let input = make_input(1_000, RegimeEstimate::Normal, 800_000, false, i + 1);
            core.decide(&input).unwrap();
        }
        assert_eq!(core.calibration_ledger.len(), 5);
    }

    #[test]
    fn core_fallback_events_recorded() {
        let mut core = make_core();
        let input = make_input(1_000, RegimeEstimate::Attack, 800_000, false, 1);
        core.decide(&input).unwrap();
        assert_eq!(core.fallback_events.len(), 1);
        assert_eq!(core.fallback_events[0].regime, RegimeEstimate::Attack);
    }

    #[test]
    fn core_export_policy_bundle() {
        let core = make_core();
        let bundle = core.export_policy_bundle(12345);
        assert_eq!(bundle.schema_version, DECISION_CORE_SCHEMA_VERSION);
        assert!(!bundle.loss_policy.entries.is_empty());
        assert_eq!(bundle.timestamp_ns, 12345);
    }

    #[test]
    fn core_reset_budget_clears_exhaustion() {
        let mut core = make_core();
        core.budget.record(100, 200);
        assert!(core.budget.is_exhausted());
        core.reset_budget(epoch(2));
        assert!(!core.budget.is_exhausted());
    }

    #[test]
    fn core_serde_roundtrip() {
        let mut core = make_core();
        let input = make_input(1_000, RegimeEstimate::Normal, 800_000, false, 1);
        core.decide(&input).unwrap();
        let json = serde_json::to_string(&core).unwrap();
        let back: RuntimeDecisionCore = serde_json::from_str(&json).unwrap();
        assert_eq!(core.decision_seq, back.decision_seq);
    }

    #[test]
    fn core_multiple_epochs() {
        let mut core = make_core();
        // Raise budget so 10 rounds of 5ms don't exhaust the 50ms default.
        core.budget.compute_budget_ms = 10_000;
        for i in 1..=10 {
            let input = make_input(1_000, RegimeEstimate::Normal, 800_000, false, i);
            let output = core.decide(&input).unwrap();
            assert!(!output.fallback_triggered);
        }
        assert_eq!(core.decision_count(), 10);
    }

    #[test]
    fn core_regime_transition_normal_to_attack_to_recovery() {
        let mut core = make_core();

        // Normal phase.
        let input = make_input(1_000, RegimeEstimate::Normal, 800_000, false, 1);
        let out = core.decide(&input).unwrap();
        assert!(!out.fallback_triggered);

        // Attack phase: triggers fallback.
        let input = make_input(1_000, RegimeEstimate::Attack, 800_000, false, 2);
        let out = core.decide(&input).unwrap();
        assert!(out.fallback_triggered);

        // Recovery phase: no mandatory demotion.
        let input = make_input(1_000, RegimeEstimate::Recovery, 800_000, false, 3);
        let out = core.decide(&input).unwrap();
        assert!(!out.fallback_triggered);
    }

    #[test]
    fn policy_bundle_serde_roundtrip() {
        let core = make_core();
        let bundle = core.export_policy_bundle(999);
        let json = serde_json::to_string(&bundle).unwrap();
        let back: PolicyBundle = serde_json::from_str(&json).unwrap();
        assert_eq!(bundle.bundle_id, back.bundle_id);
    }

    #[test]
    fn decision_core_error_display() {
        assert_eq!(
            DecisionCoreError::NoLanesConfigured.to_string(),
            "no lanes configured"
        );
        assert_eq!(
            DecisionCoreError::EmptyActionSet.to_string(),
            "empty action set"
        );
        assert_eq!(
            DecisionCoreError::EpochRegression {
                current: 5,
                received: 3
            }
            .to_string(),
            "epoch regression: current=5, received=3"
        );
    }

    #[test]
    fn fallback_reason_display() {
        assert_eq!(
            FallbackReason::RegimeChange("attack".into()).to_string(),
            "regime_change:attack"
        );
        assert_eq!(
            FallbackReason::CVaRViolation {
                cvar_us: 5000,
                max_us: 1000
            }
            .to_string(),
            "cvar_violation:5000us>1000us"
        );
    }

    #[test]
    fn decision_trace_entry_serde_roundtrip() {
        let entry = DecisionTraceEntry {
            seq: 0,
            state_before: LaneRoutingState::initial(LaneId::quickjs_native(), epoch(1)),
            action: RoutingAction::Hold,
            expected_loss_millionths: 42_000,
            cvar_us: 1_000,
            fallback_triggered: false,
            fallback_reason: None,
            epoch: epoch(1),
            timestamp_ns: 1_000_000,
        };
        let json = serde_json::to_string(&entry).unwrap();
        let back: DecisionTraceEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry.seq, back.seq);
    }

    #[test]
    fn calibration_ledger_entry_serde() {
        let entry = CalibrationLedgerEntry {
            seq: 0,
            empirical_coverage_millionths: 960_000,
            target_coverage_millionths: 950_000,
            threshold_millionths: 400_000,
            e_value_millionths: MILLION,
            recalibration_triggered: false,
            epoch: epoch(1),
            timestamp_ns: 100,
        };
        let json = serde_json::to_string(&entry).unwrap();
        let back: CalibrationLedgerEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(
            entry.empirical_coverage_millionths,
            back.empirical_coverage_millionths
        );
    }

    #[test]
    fn fallback_trigger_event_serde() {
        let event = FallbackTriggerEvent {
            seq: 0,
            reason: FallbackReason::BudgetExhausted {
                compute_ms: 60,
                memory_mb: 200,
            },
            from_lane: LaneId::v8_native(),
            to_lane: LaneId::safe_mode(),
            regime: RegimeEstimate::Normal,
            confidence_millionths: 500_000,
            epoch: epoch(1),
            timestamp_ns: 100,
        };
        let json = serde_json::to_string(&event).unwrap();
        let back: FallbackTriggerEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event.seq, back.seq);
    }

    #[test]
    fn lane_routing_state_initial() {
        let state = LaneRoutingState::initial(LaneId::quickjs_native(), epoch(1));
        assert_eq!(state.confidence_millionths, 500_000);
        assert_eq!(state.regime, RegimeEstimate::Normal);
        assert!(!state.safe_mode_active);
        assert_eq!(state.risk_posteriors.len(), 4);
    }

    #[test]
    fn asymmetric_loss_policy_custom() {
        let mut policy = AsymmetricLossPolicy::new("custom");
        policy.add_entry("action_a", RiskDimension::Latency, 500_000);
        let mut posteriors = BTreeMap::new();
        posteriors.insert("latency".to_string(), 500_000); // 50%
        let loss = policy.expected_loss("action_a", &posteriors, RegimeEstimate::Normal);
        // 500_000 * 500_000 / 1_000_000 = 250_000, then * 1.0 (no regime mult)
        assert_eq!(loss, 250_000);
    }

    #[test]
    fn cvar_mixed_latencies() {
        let mut cvar = CVaRConstraint::new("test", 500_000, 100_000); // p50 constraint
        cvar.observe(100);
        cvar.observe(200);
        cvar.observe(300);
        cvar.observe(400);
        let result = cvar.evaluate();
        // p50: median is at index 2 (300), tail = [300, 400], CVaR = 350
        assert_eq!(result.var_us, 300);
        assert_eq!(result.cvar_us, 350);
        assert!(result.satisfied); // 350 < 100_000
    }

    #[test]
    fn core_current_cvar_initially_zero() {
        let core = make_core();
        let result = core.current_cvar();
        assert_eq!(result.cvar_us, 0);
        assert!(result.satisfied);
    }

    #[test]
    fn core_current_coverage_initially_full() {
        let core = make_core();
        assert_eq!(core.current_coverage_millionths(), MILLION);
    }

    // -- Enrichment: PearlTower 2026-02-26 --

    #[test]
    fn risk_dimension_serde_roundtrip() {
        for v in &RiskDimension::ALL {
            let json = serde_json::to_string(v).unwrap();
            let back: RiskDimension = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    #[test]
    fn regime_estimate_serde_roundtrip() {
        let variants = [
            RegimeEstimate::Normal,
            RegimeEstimate::Elevated,
            RegimeEstimate::Attack,
            RegimeEstimate::Degraded,
            RegimeEstimate::Recovery,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: RegimeEstimate = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    #[test]
    fn risk_dimension_display_all_distinct() {
        let mut set = std::collections::BTreeSet::new();
        for v in &RiskDimension::ALL {
            set.insert(v.to_string());
        }
        assert_eq!(set.len(), RiskDimension::ALL.len());
    }

    #[test]
    fn regime_estimate_display_all_distinct() {
        let variants = [
            RegimeEstimate::Normal,
            RegimeEstimate::Elevated,
            RegimeEstimate::Attack,
            RegimeEstimate::Degraded,
            RegimeEstimate::Recovery,
        ];
        let mut set = std::collections::BTreeSet::new();
        for v in &variants {
            set.insert(v.to_string());
        }
        assert_eq!(set.len(), variants.len());
    }

    #[test]
    fn fallback_reason_serde_roundtrip() {
        let variants = vec![
            FallbackReason::RegimeChange("attack detected".into()),
            FallbackReason::CVaRViolation {
                cvar_us: 1000,
                max_us: 500,
            },
            FallbackReason::CalibrationUndercoverage {
                coverage_millionths: 300_000,
            },
            FallbackReason::BudgetExhausted {
                compute_ms: 100,
                memory_mb: 256,
            },
            FallbackReason::LowConfidence {
                confidence_millionths: 200_000,
            },
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: FallbackReason = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    #[test]
    fn decision_core_error_serde_roundtrip() {
        let variants = vec![
            DecisionCoreError::NoLanesConfigured,
            DecisionCoreError::EmptyActionSet,
            DecisionCoreError::BudgetExhaustedNoFallback,
            DecisionCoreError::EpochRegression {
                current: 5,
                received: 3,
            },
            DecisionCoreError::InvalidConfig("bad".into()),
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: DecisionCoreError = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    #[test]
    fn fallback_reason_display_all_distinct() {
        let variants = vec![
            FallbackReason::RegimeChange("x".into()),
            FallbackReason::CVaRViolation {
                cvar_us: 1,
                max_us: 2,
            },
            FallbackReason::CalibrationUndercoverage {
                coverage_millionths: 1,
            },
            FallbackReason::BudgetExhausted {
                compute_ms: 1,
                memory_mb: 1,
            },
            FallbackReason::LowConfidence {
                confidence_millionths: 1,
            },
        ];
        let mut set = std::collections::BTreeSet::new();
        for v in &variants {
            set.insert(v.to_string());
        }
        assert_eq!(set.len(), variants.len());
    }

    // -- Enrichment: PearlTower 2026-03-02 --

    #[test]
    fn decision_core_error_display_exact_all_5() {
        assert_eq!(
            DecisionCoreError::NoLanesConfigured.to_string(),
            "no lanes configured"
        );
        assert_eq!(
            DecisionCoreError::EmptyActionSet.to_string(),
            "empty action set"
        );
        assert_eq!(
            DecisionCoreError::BudgetExhaustedNoFallback.to_string(),
            "budget exhausted with no fallback lane"
        );
        assert_eq!(
            DecisionCoreError::EpochRegression {
                current: 10,
                received: 3
            }
            .to_string(),
            "epoch regression: current=10, received=3"
        );
        assert_eq!(
            DecisionCoreError::InvalidConfig("bad param".into()).to_string(),
            "invalid config: bad param"
        );
    }

    #[test]
    fn decision_core_error_source_returns_none_all() {
        use std::error::Error;
        let variants: Vec<DecisionCoreError> = vec![
            DecisionCoreError::NoLanesConfigured,
            DecisionCoreError::EmptyActionSet,
            DecisionCoreError::BudgetExhaustedNoFallback,
            DecisionCoreError::EpochRegression {
                current: 5,
                received: 3,
            },
            DecisionCoreError::InvalidConfig("x".into()),
        ];
        for err in &variants {
            assert!(err.source().is_none(), "source() should be None for {err}");
        }
    }

    #[test]
    fn fallback_reason_serde_eprocess_and_consecutive() {
        let variants = vec![
            FallbackReason::EProcessTriggered {
                guardrail_id: "ep-1".into(),
            },
            FallbackReason::ConsecutiveAdverse { count: 5 },
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: FallbackReason = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    #[test]
    fn fallback_reason_display_exact_all_7() {
        assert_eq!(
            FallbackReason::RegimeChange("attack".into()).to_string(),
            "regime_change:attack"
        );
        assert_eq!(
            FallbackReason::CVaRViolation {
                cvar_us: 5000,
                max_us: 1000
            }
            .to_string(),
            "cvar_violation:5000us>1000us"
        );
        assert_eq!(
            FallbackReason::CalibrationUndercoverage {
                coverage_millionths: 800_000
            }
            .to_string(),
            "undercoverage:800000"
        );
        assert_eq!(
            FallbackReason::BudgetExhausted {
                compute_ms: 60,
                memory_mb: 200
            }
            .to_string(),
            "budget_exhausted:compute=60ms,mem=200mb"
        );
        assert_eq!(
            FallbackReason::LowConfidence {
                confidence_millionths: 100_000
            }
            .to_string(),
            "low_confidence:100000"
        );
        assert_eq!(
            FallbackReason::EProcessTriggered {
                guardrail_id: "g1".into()
            }
            .to_string(),
            "eprocess_triggered:g1"
        );
        assert_eq!(
            FallbackReason::ConsecutiveAdverse { count: 3 }.to_string(),
            "consecutive_adverse:3"
        );
    }

    #[test]
    fn routing_action_serde_all_variants() {
        let variants = vec![
            RoutingAction::SelectLane(LaneId::v8_native()),
            RoutingAction::FallbackSafeMode,
            RoutingAction::EscalateToOperator,
            RoutingAction::Hold,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: RoutingAction = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    #[test]
    fn lane_routing_state_serde_roundtrip() {
        let state = LaneRoutingState::initial(LaneId::quickjs_native(), epoch(1));
        let json = serde_json::to_string(&state).unwrap();
        let back: LaneRoutingState = serde_json::from_str(&json).unwrap();
        assert_eq!(state, back);
    }

    #[test]
    fn routing_decision_output_serde_roundtrip() {
        let output = RoutingDecisionOutput {
            action: RoutingAction::Hold,
            expected_loss_millionths: 42_000,
            fallback_triggered: false,
            fallback_reason: None,
            cvar_result: CVaRResult {
                cvar_us: 0,
                satisfied: true,
                var_us: 0,
                sample_count: 0,
            },
            decision_seq: 0,
        };
        let json = serde_json::to_string(&output).unwrap();
        let back: RoutingDecisionOutput = serde_json::from_str(&json).unwrap();
        assert_eq!(output, back);
    }

    #[test]
    fn demotion_policy_serde_roundtrip() {
        let policy = DemotionPolicy::new("test-demotion");
        let json = serde_json::to_string(&policy).unwrap();
        let back: DemotionPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(policy, back);
    }

    #[test]
    fn cvar_result_serde_roundtrip() {
        let result = CVaRResult {
            cvar_us: 5000,
            satisfied: false,
            var_us: 4000,
            sample_count: 100,
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: CVaRResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, back);
    }

    #[test]
    fn regime_estimate_ordering() {
        assert!(RegimeEstimate::Normal < RegimeEstimate::Elevated);
        assert!(RegimeEstimate::Elevated < RegimeEstimate::Attack);
        assert!(RegimeEstimate::Attack < RegimeEstimate::Degraded);
        assert!(RegimeEstimate::Degraded < RegimeEstimate::Recovery);
    }

    #[test]
    fn calibration_e_value_decays_on_miss() {
        let mut cal = ConformalCalibrationLayer::new("test", 950_000);
        let initial_e = cal.e_value_millionths;
        assert_eq!(initial_e, MILLION);
        cal.observe(100_000, false);
        assert_eq!(
            cal.e_value_millionths, 0,
            "e-value should decay to 0 on miss"
        );
    }

    #[test]
    fn core_is_fallback_active_tracks_state() {
        let mut core = make_core();
        assert!(!core.is_fallback_active());
        // Attack triggers fallback.
        let input = make_input(1_000, RegimeEstimate::Attack, 800_000, false, 1);
        core.decide(&input).unwrap();
        assert!(core.is_fallback_active());
        // Recovery returns to normal.
        let input2 = make_input(1_000, RegimeEstimate::Recovery, 800_000, false, 2);
        core.decide(&input2).unwrap();
        assert!(!core.is_fallback_active());
    }

    #[test]
    fn loss_policy_entry_serde_roundtrip() {
        let entry = LossPolicyEntry {
            action_label: format!("select:{THROUGHPUT_PROFILE_LABEL}"),
            dimension: "compatibility".into(),
            loss_millionths: 400_000,
        };
        let json = serde_json::to_string(&entry).unwrap();
        let back: LossPolicyEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry, back);
    }
}
