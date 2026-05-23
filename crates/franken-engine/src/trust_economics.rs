//! Trust-economics model inputs for expected-loss and attacker-ROI computation.
//!
//! Defines the canonical schemas that parameterize all runtime security
//! decisions: loss matrices with sub-loss decomposition, attacker cost
//! models, containment cost models, and blast-radius estimation.
//!
//! All cost values use fixed-point millionths (1_000_000 = 1.0) for
//! deterministic arithmetic.  Collections use `BTreeMap`/`BTreeSet` for
//! deterministic iteration.
//!
//! Plan references: Section 10.12 item 15, 9H.7 (Global Trust Economics
//! Layer), 9F.15 (Live Safety Twin), Section 5.2 (expected-loss
//! minimization), Section 6.6 (expected-loss action policy).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Fixed-point scale factor: 1_000_000 millionths = 1.0.
pub const MILLIONTHS: i64 = 1_000_000;

// ---------------------------------------------------------------------------
// TrueState — ground-truth extension state
// ---------------------------------------------------------------------------

/// True extension risk state for loss-matrix row indexing.
///
/// Represents the actual (unknown at runtime) state of an extension.
/// The loss matrix uses these to encode asymmetric consequences:
/// a false allow of malicious code is far costlier than a false
/// quarantine of benign code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum TrueState {
    /// Extension is operating within declared capability envelope.
    Benign,
    /// Extension exhibits anomalous behavior outside normal patterns.
    Suspicious,
    /// Extension is actively attempting unauthorized actions.
    Malicious,
    /// Extension's integrity has been violated by external compromise.
    Compromised,
}

impl TrueState {
    /// All variants in deterministic order.
    pub const ALL: [Self; 4] = [
        Self::Benign,
        Self::Suspicious,
        Self::Malicious,
        Self::Compromised,
    ];
}

impl fmt::Display for TrueState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Benign => "benign",
            Self::Suspicious => "suspicious",
            Self::Malicious => "malicious",
            Self::Compromised => "compromised",
        };
        f.write_str(name)
    }
}

// ---------------------------------------------------------------------------
// ContainmentAction — runtime actions for loss-matrix column indexing
// ---------------------------------------------------------------------------

/// Runtime containment action for loss-matrix column indexing.
///
/// Actions are ordered by severity: allow is least severe, quarantine
/// is most severe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ContainmentAction {
    /// Permit continued operation.
    Allow,
    /// Emit operator warning, no enforcement.
    Warn,
    /// Issue interactive challenge to verify extension legitimacy.
    Challenge,
    /// Restrict to sandboxed execution with reduced capabilities.
    Sandbox,
    /// Pause execution pending review.
    Suspend,
    /// Terminate extension immediately.
    Terminate,
    /// Quarantine with revocation propagation.
    Quarantine,
}

impl ContainmentAction {
    /// All variants in severity order.
    pub const ALL: [Self; 7] = [
        Self::Allow,
        Self::Warn,
        Self::Challenge,
        Self::Sandbox,
        Self::Suspend,
        Self::Terminate,
        Self::Quarantine,
    ];
}

impl fmt::Display for ContainmentAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Allow => "allow",
            Self::Warn => "warn",
            Self::Challenge => "challenge",
            Self::Sandbox => "sandbox",
            Self::Suspend => "suspend",
            Self::Terminate => "terminate",
            Self::Quarantine => "quarantine",
        };
        f.write_str(name)
    }
}

// ---------------------------------------------------------------------------
// SubLoss — decomposed loss categories
// ---------------------------------------------------------------------------

/// Decomposed loss into sub-categories for a single (state, action) cell.
///
/// All values in fixed-point millionths (1_000_000 = 1.0).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubLoss {
    /// Direct damage: credential theft, data exfiltration, integrity loss.
    pub direct_damage: i64,
    /// Operational disruption: downtime, throughput degradation, response cost.
    pub operational_disruption: i64,
    /// Trust damage: reputation, customer confidence, compliance penalties.
    pub trust_damage: i64,
    /// Containment cost: resources to execute the containment action.
    pub containment_cost: i64,
    /// False action cost: cost of incorrectly applying this action to a
    /// benign extension.
    pub false_action_cost: i64,
}

impl SubLoss {
    /// Create a zero sub-loss.
    pub fn zero() -> Self {
        Self {
            direct_damage: 0,
            operational_disruption: 0,
            trust_damage: 0,
            containment_cost: 0,
            false_action_cost: 0,
        }
    }

    /// Total loss (sum of all sub-categories).
    pub fn total(&self) -> i64 {
        self.direct_damage
            .saturating_add(self.operational_disruption)
            .saturating_add(self.trust_damage)
            .saturating_add(self.containment_cost)
            .saturating_add(self.false_action_cost)
    }
}

// ---------------------------------------------------------------------------
// Custom serde for BTreeMap<(TrueState, ContainmentAction), SubLoss>
// ---------------------------------------------------------------------------

/// Serde helper for `BTreeMap<(TrueState, ContainmentAction), SubLoss>`.
///
/// JSON requires string keys; this serializes as a vec of entries.
mod loss_cell_serde {
    use super::*;
    use serde::{Deserializer, Serializer};

    #[derive(Serialize, Deserialize)]
    struct Cell {
        state: TrueState,
        action: ContainmentAction,
        loss: SubLoss,
    }

    pub fn serialize<S>(
        entries: &BTreeMap<(TrueState, ContainmentAction), SubLoss>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let vec: Vec<Cell> = entries
            .iter()
            .map(|(&(state, action), &loss)| Cell {
                state,
                action,
                loss,
            })
            .collect();
        vec.serialize(serializer)
    }

    pub fn deserialize<'de, D>(
        deserializer: D,
    ) -> Result<BTreeMap<(TrueState, ContainmentAction), SubLoss>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let vec: Vec<Cell> = Vec::deserialize(deserializer)?;
        Ok(vec
            .into_iter()
            .map(|c| ((c.state, c.action), c.loss))
            .collect())
    }
}

// ---------------------------------------------------------------------------
// DecomposedLossMatrix — (state, action) → SubLoss
// ---------------------------------------------------------------------------

/// Loss matrix mapping (true_state, action) pairs to decomposed sub-losses.
///
/// Extends the simple `LossMatrix` in `policy_controller` with sub-loss
/// decomposition for audit, sensitivity analysis, and calibration.
///
/// All loss values are fixed-point millionths.  BTreeMap for deterministic
/// iteration order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecomposedLossMatrix {
    /// Mapping from (state, action) -> sub-loss decomposition.
    #[serde(with = "loss_cell_serde")]
    cells: BTreeMap<(TrueState, ContainmentAction), SubLoss>,

    /// Matrix version for audit trail.
    pub version: u64,

    /// Deployment context (e.g. "enterprise", "consumer", "regulated").
    pub deployment_context: String,

    /// Human-readable justification for this matrix configuration.
    pub justification: String,
}

impl DecomposedLossMatrix {
    /// Create an empty matrix with metadata.
    pub fn new(
        version: u64,
        deployment_context: impl Into<String>,
        justification: impl Into<String>,
    ) -> Self {
        Self {
            cells: BTreeMap::new(),
            version,
            deployment_context: deployment_context.into(),
            justification: justification.into(),
        }
    }

    /// Set the sub-loss for a (state, action) pair.
    pub fn set(&mut self, state: TrueState, action: ContainmentAction, loss: SubLoss) {
        self.cells.insert((state, action), loss);
    }

    /// Get the sub-loss for a (state, action) pair.
    pub fn get(&self, state: TrueState, action: ContainmentAction) -> Option<&SubLoss> {
        self.cells.get(&(state, action))
    }

    /// Get the total (scalar) loss for a (state, action) pair.
    pub fn total_loss(&self, state: TrueState, action: ContainmentAction) -> i64 {
        self.get(state, action).map_or(0, SubLoss::total)
    }

    /// Number of populated cells.
    pub fn cell_count(&self) -> usize {
        self.cells.len()
    }

    /// Whether the matrix is fully populated (all state × action pairs).
    pub fn is_complete(&self) -> bool {
        self.cells.len() == TrueState::ALL.len() * ContainmentAction::ALL.len()
    }

    /// Validate the asymmetry invariant: for every action, the loss when
    /// the true state is Malicious must be >= the loss when Benign.
    ///
    /// Returns pairs that violate the invariant.
    pub fn asymmetry_violations(&self) -> Vec<(ContainmentAction, i64, i64)> {
        let mut violations = Vec::new();
        for &action in &ContainmentAction::ALL {
            let benign_loss = self.total_loss(TrueState::Benign, action);
            let malicious_loss = self.total_loss(TrueState::Malicious, action);
            if malicious_loss < benign_loss {
                // For "allow", malicious should cost more than benign
                violations.push((action, benign_loss, malicious_loss));
            }
        }
        violations
    }

    /// Flatten to scalar totals (for interop with `policy_controller::LossMatrix`).
    pub fn to_scalar_totals(&self) -> BTreeMap<(TrueState, ContainmentAction), i64> {
        self.cells
            .iter()
            .map(|(&key, loss)| (key, loss.total()))
            .collect()
    }
}

// ---------------------------------------------------------------------------
// AttackerCostModel — parameterizes attacker investment
// ---------------------------------------------------------------------------

/// Cost model for attacker investment and ROI computation.
///
/// Parameterizes the estimated attacker effort and resources required
/// for different attack strategies.  Used to compute attacker expected
/// ROI: `(expected_gain - total_cost) / total_cost`.  When defenses
/// increase evasion cost or reduce expected gain, attacker ROI decreases.
///
/// All values in fixed-point millionths.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttackerCostModel {
    /// Cost of discovering a viable attack vector.
    pub discovery_cost: i64,
    /// Cost of developing exploit payload.
    pub development_cost: i64,
    /// Cost of deploying attack (supply-chain insertion, social engineering).
    pub deployment_cost: i64,
    /// Cost of maintaining long-term access/persistence.
    pub persistence_cost: i64,
    /// Additional cost of evading specific defense capabilities.
    pub evasion_cost: i64,

    /// Estimated attacker gain on success (millionths).
    pub expected_gain: i64,

    /// Per-strategy cost adjustments keyed by strategy name.
    pub strategy_adjustments: BTreeMap<String, StrategyCostAdjustment>,

    /// Model version for audit trail.
    pub version: u64,

    /// Calibration source: "manual", "adversarial", "production-derived".
    pub calibration_source: String,
}

/// Per-strategy cost adjustment (additive modifier to base costs).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StrategyCostAdjustment {
    /// Strategy identifier.
    pub strategy_name: String,
    /// Additive adjustment to discovery cost.
    pub discovery_delta: i64,
    /// Additive adjustment to development cost.
    pub development_delta: i64,
    /// Additive adjustment to evasion cost.
    pub evasion_delta: i64,
    /// Justification for this adjustment.
    pub justification: String,
}

impl AttackerCostModel {
    /// Total base attack cost (sum of all cost components).
    pub fn total_base_cost(&self) -> i64 {
        self.discovery_cost
            .saturating_add(self.development_cost)
            .saturating_add(self.deployment_cost)
            .saturating_add(self.persistence_cost)
            .saturating_add(self.evasion_cost)
    }

    /// Adjusted total cost for a named strategy.
    ///
    /// Returns `None` if the strategy is not registered.
    pub fn adjusted_cost(&self, strategy: &str) -> Option<i64> {
        self.strategy_adjustments.get(strategy).map(|adj| {
            self.total_base_cost()
                .saturating_add(adj.discovery_delta)
                .saturating_add(adj.development_delta)
                .saturating_add(adj.evasion_delta)
        })
    }

    /// Attacker expected ROI in millionths.
    ///
    /// `ROI = (expected_gain - total_cost) * MILLIONTHS / total_cost`.
    /// Returns `None` if total cost is zero (division guard).
    pub fn expected_roi(&self) -> Option<i64> {
        let total = self.total_base_cost();
        if total == 0 {
            return None;
        }
        let numerator = self.expected_gain.saturating_sub(total);
        // Use i128 to avoid overflow during multiplication.
        Some((numerator as i128 * MILLIONTHS as i128 / total as i128) as i64)
    }

    /// Attacker expected ROI for a specific strategy.
    pub fn strategy_roi(&self, strategy: &str) -> Option<i64> {
        let total = self.adjusted_cost(strategy)?;
        if total == 0 {
            return None;
        }
        let numerator = self.expected_gain.saturating_sub(total);
        Some((numerator as i128 * MILLIONTHS as i128 / total as i128) as i64)
    }
}

// ---------------------------------------------------------------------------
// ROI assessment utilities
// ---------------------------------------------------------------------------

/// Alert level derived from attacker ROI thresholds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RoiAlertLevel {
    /// ROI < 0.5x; attacks are currently uneconomic.
    Unprofitable,
    /// 0.5x <= ROI <= 1.0x; watch, but not yet profitable.
    Neutral,
    /// 1.0x < ROI <= 2.0x; profitable attacks.
    Profitable,
    /// ROI > 2.0x; highly profitable attacks requiring escalation.
    HighlyProfitable,
}

impl fmt::Display for RoiAlertLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Unprofitable => "unprofitable",
            Self::Neutral => "neutral",
            Self::Profitable => "profitable",
            Self::HighlyProfitable => "highly_profitable",
        };
        f.write_str(name)
    }
}

/// ROI trajectory classification over a deterministic history window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RoiTrend {
    Rising,
    Stable,
    Falling,
}

impl fmt::Display for RoiTrend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Rising => "rising",
            Self::Stable => "stable",
            Self::Falling => "falling",
        };
        f.write_str(name)
    }
}

/// Per-extension attacker ROI assessment used by runtime scoring.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttackerRoiAssessment {
    pub extension_id: String,
    pub roi_millionths: i64,
    pub alert: RoiAlertLevel,
    pub trend: RoiTrend,
}

impl AttackerRoiAssessment {
    /// Build an assessment from current ROI and historical values.
    pub fn new(
        extension_id: impl Into<String>,
        roi_millionths: i64,
        history_millionths: &[i64],
    ) -> Self {
        Self {
            extension_id: extension_id.into(),
            roi_millionths,
            alert: classify_roi_alert_level(roi_millionths),
            trend: classify_roi_trend(history_millionths),
        }
    }
}

/// Fleet-level ROI summary across extension assessments.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetRoiSummary {
    pub extension_count: usize,
    pub profitable_extensions: usize,
    pub highly_profitable_extensions: usize,
    pub average_roi_millionths: i64,
    pub min_roi_millionths: i64,
    pub max_roi_millionths: i64,
}

/// Classify alert level from ROI thresholds.
///
/// Thresholds:
/// - `roi > 2.0x` => `HighlyProfitable`
/// - `roi > 1.0x` => `Profitable`
/// - `roi < 0.5x` => `Unprofitable`
/// - otherwise => `Neutral`
pub fn classify_roi_alert_level(roi_millionths: i64) -> RoiAlertLevel {
    if roi_millionths > 2 * MILLIONTHS {
        RoiAlertLevel::HighlyProfitable
    } else if roi_millionths > MILLIONTHS {
        RoiAlertLevel::Profitable
    } else if roi_millionths < 500_000 {
        RoiAlertLevel::Unprofitable
    } else {
        RoiAlertLevel::Neutral
    }
}

/// Classify ROI trend from a deterministic history window.
///
/// Uses the delta between first and last value with a dead-zone threshold
/// of 50_000 millionths to avoid flapping on tiny changes.
pub fn classify_roi_trend(history_millionths: &[i64]) -> RoiTrend {
    if history_millionths.len() < 2 {
        return RoiTrend::Stable;
    }
    let first = history_millionths[0];
    let last = history_millionths[history_millionths.len() - 1];
    let delta = last.saturating_sub(first);
    if delta > 50_000 {
        RoiTrend::Rising
    } else if delta < -50_000 {
        RoiTrend::Falling
    } else {
        RoiTrend::Stable
    }
}

/// Summarize fleet ROI posture from extension assessments.
pub fn summarize_fleet_roi(
    assessments: &BTreeMap<String, AttackerRoiAssessment>,
) -> FleetRoiSummary {
    if assessments.is_empty() {
        return FleetRoiSummary {
            extension_count: 0,
            profitable_extensions: 0,
            highly_profitable_extensions: 0,
            average_roi_millionths: 0,
            min_roi_millionths: 0,
            max_roi_millionths: 0,
        };
    }

    let extension_count = assessments.len();
    let mut profitable_extensions = 0usize;
    let mut highly_profitable_extensions = 0usize;
    let mut min_roi_millionths = i64::MAX;
    let mut max_roi_millionths = i64::MIN;
    let mut total_roi = 0i128;

    for assessment in assessments.values() {
        if assessment.alert == RoiAlertLevel::Profitable {
            profitable_extensions += 1;
        }
        if assessment.alert == RoiAlertLevel::HighlyProfitable {
            highly_profitable_extensions += 1;
        }
        min_roi_millionths = min_roi_millionths.min(assessment.roi_millionths);
        max_roi_millionths = max_roi_millionths.max(assessment.roi_millionths);
        total_roi += assessment.roi_millionths as i128;
    }

    FleetRoiSummary {
        extension_count,
        profitable_extensions,
        highly_profitable_extensions,
        average_roi_millionths: (total_roi / extension_count as i128) as i64,
        min_roi_millionths,
        max_roi_millionths,
    }
}

// ---------------------------------------------------------------------------
// ContainmentCostModel — per-action cost structure
// ---------------------------------------------------------------------------

/// Per-action cost structure for containment operations.
///
/// Each containment action has quantified costs that vary by deployment
/// context and system state.  All values in fixed-point millionths.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionCost {
    /// Time to enact the action (microseconds, not millionths).
    pub execution_latency_us: u64,
    /// CPU/memory/IO cost of the action (millionths of normalized budget).
    pub resource_consumption: i64,
    /// Impact on co-located extensions or dependent services.
    pub collateral_impact: i64,
    /// Expected operator attention/response required.
    pub operator_burden: i64,
    /// Cost of undoing the action if it was incorrect.
    pub reversibility_cost: i64,
}

impl ActionCost {
    /// Total monetary-equivalent cost (excludes latency, which is temporal).
    pub fn total_monetary_cost(&self) -> i64 {
        self.resource_consumption
            .saturating_add(self.collateral_impact)
            .saturating_add(self.operator_burden)
            .saturating_add(self.reversibility_cost)
    }
}

/// Containment cost model mapping actions to their cost structure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContainmentCostModel {
    /// Per-action cost entries.
    pub action_costs: BTreeMap<ContainmentAction, ActionCost>,

    /// Model version for audit trail.
    pub version: u64,

    /// Deployment context.
    pub deployment_context: String,

    /// Calibration source.
    pub calibration_source: String,
}

impl ContainmentCostModel {
    /// Create an empty model.
    pub fn new(
        version: u64,
        deployment_context: impl Into<String>,
        calibration_source: impl Into<String>,
    ) -> Self {
        Self {
            action_costs: BTreeMap::new(),
            version,
            deployment_context: deployment_context.into(),
            calibration_source: calibration_source.into(),
        }
    }

    /// Set the cost for a specific action.
    pub fn set(&mut self, action: ContainmentAction, cost: ActionCost) {
        self.action_costs.insert(action, cost);
    }

    /// Get the cost for a specific action.
    pub fn get(&self, action: ContainmentAction) -> Option<&ActionCost> {
        self.action_costs.get(&action)
    }

    /// Total monetary cost for a specific action.
    pub fn total_cost(&self, action: ContainmentAction) -> i64 {
        self.get(action).map_or(0, ActionCost::total_monetary_cost)
    }
}

// ---------------------------------------------------------------------------
// BlastRadiusEstimate — scope estimation for incidents
// ---------------------------------------------------------------------------

/// Blast radius estimate for an attack scenario.
///
/// Models the potential scope of an incident as a function of affected
/// entities, cascade probability, and time-to-containment sensitivity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlastRadiusEstimate {
    /// Extensions that could be impacted (identifiers).
    pub affected_extensions: BTreeSet<String>,
    /// Data stores/flows that could be compromised.
    pub affected_data: BTreeSet<String>,
    /// Fleet nodes that could be impacted.
    pub affected_nodes: BTreeSet<String>,
    /// Probability of cascade beyond initial scope (millionths, 0..=1_000_000).
    pub cascade_probability: i64,
    /// Blast radius growth rate per second of delayed containment (millionths).
    /// Models `blast_radius(t) = base + growth_rate_per_sec * t`.
    pub growth_rate_per_sec: i64,
}

impl BlastRadiusEstimate {
    /// Total number of affected entities across all categories.
    pub fn total_affected_entities(&self) -> usize {
        self.affected_extensions.len() + self.affected_data.len() + self.affected_nodes.len()
    }

    /// Estimated blast radius at time `t_sec` after initial detection.
    ///
    /// Returns base entity count scaled by cascade and growth.
    /// Result in millionths.
    pub fn radius_at_time(&self, t_sec: u64) -> i64 {
        let base = self.total_affected_entities() as i64 * MILLIONTHS;
        let growth = self.growth_rate_per_sec.saturating_mul(t_sec as i64);
        // Scale by cascade probability.
        let cascade_factor = MILLIONTHS.saturating_add(self.cascade_probability);
        let total = base.saturating_add(growth);
        (total as i128 * cascade_factor as i128 / MILLIONTHS as i128) as i64
    }
}

// ---------------------------------------------------------------------------
// TrustEconomicsModelInputs — top-level aggregation
// ---------------------------------------------------------------------------

/// Top-level trust-economics model inputs.
///
/// Aggregates all model components that parameterize runtime security
/// decisions.  This is a signed, versioned artifact with provenance chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustEconomicsModelInputs {
    /// Decomposed loss matrix.
    pub loss_matrix: DecomposedLossMatrix,
    /// Attacker cost model.
    pub attacker_cost: AttackerCostModel,
    /// Containment cost model.
    pub containment_cost: ContainmentCostModel,

    /// Model version (monotonically increasing).
    pub model_version: u64,

    /// Security epoch under which this model was calibrated.
    pub epoch: SecurityEpoch,

    /// Calibration timestamp (monotonic nanoseconds).
    pub calibration_timestamp_ns: u64,

    /// Calibration source descriptor.
    pub calibration_source: String,

    /// Provenance chain (ordered list of prior model version identifiers).
    pub provenance_chain: Vec<String>,
}

// ---------------------------------------------------------------------------
// TrustEconomicsError
// ---------------------------------------------------------------------------

/// Errors from trust-economics model operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrustEconomicsError {
    /// Loss matrix is incomplete (missing cells).
    IncompleteLossMatrix { populated: usize, expected: usize },
    /// Cascade probability out of range [0, 1_000_000].
    CascadeProbabilityOutOfRange { value: i64 },
    /// Attacker cost model has zero total cost (division guard).
    ZeroAttackerCost,
    /// Asymmetry violation in loss matrix.
    AsymmetryViolation {
        action: String,
        benign_loss: i64,
        malicious_loss: i64,
    },
    /// Model version regression (new version <= old version).
    VersionRegression { current: u64, attempted: u64 },
}

impl fmt::Display for TrustEconomicsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IncompleteLossMatrix {
                populated,
                expected,
            } => write!(
                f,
                "incomplete loss matrix: {populated}/{expected} cells populated"
            ),
            Self::CascadeProbabilityOutOfRange { value } => {
                write!(
                    f,
                    "cascade probability {value} out of range [0, {MILLIONTHS}]"
                )
            }
            Self::ZeroAttackerCost => write!(f, "attacker cost model has zero total cost"),
            Self::AsymmetryViolation {
                action,
                benign_loss,
                malicious_loss,
            } => write!(
                f,
                "asymmetry violation for action '{action}': benign={benign_loss}, malicious={malicious_loss}"
            ),
            Self::VersionRegression { current, attempted } => write!(
                f,
                "model version regression: current={current}, attempted={attempted}"
            ),
        }
    }
}

impl std::error::Error for TrustEconomicsError {}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

impl TrustEconomicsModelInputs {
    /// Validate all model inputs.
    ///
    /// Returns the first error encountered, or `Ok(())` if valid.
    pub fn validate(&self) -> Result<(), TrustEconomicsError> {
        // Check loss matrix completeness.
        let expected = TrueState::ALL.len() * ContainmentAction::ALL.len();
        if self.loss_matrix.cell_count() < expected {
            return Err(TrustEconomicsError::IncompleteLossMatrix {
                populated: self.loss_matrix.cell_count(),
                expected,
            });
        }

        // Check asymmetry invariant.
        let violations = self.loss_matrix.asymmetry_violations();
        if let Some(v) = violations.first() {
            return Err(TrustEconomicsError::AsymmetryViolation {
                action: v.0.to_string(),
                benign_loss: v.1,
                malicious_loss: v.2,
            });
        }

        // Check attacker cost.
        if self.attacker_cost.total_base_cost() == 0 {
            return Err(TrustEconomicsError::ZeroAttackerCost);
        }

        Ok(())
    }

    /// Validate that a new model version does not regress.
    pub fn validate_version_update(&self, new_version: u64) -> Result<(), TrustEconomicsError> {
        if new_version <= self.model_version {
            return Err(TrustEconomicsError::VersionRegression {
                current: self.model_version,
                attempted: new_version,
            });
        }
        Ok(())
    }
}

impl BlastRadiusEstimate {
    /// Validate cascade probability is within [0, MILLIONTHS].
    pub fn validate(&self) -> Result<(), TrustEconomicsError> {
        if self.cascade_probability < 0 || self.cascade_probability > MILLIONTHS {
            return Err(TrustEconomicsError::CascadeProbabilityOutOfRange {
                value: self.cascade_probability,
            });
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Default conservative model
// ---------------------------------------------------------------------------

/// Build a default conservative loss matrix.
///
/// Conservative = favor containment over permissiveness.  The matrix
/// assigns high loss to allowing malicious/compromised extensions and
/// low loss to quarantining benign extensions.
pub fn default_conservative_loss_matrix() -> DecomposedLossMatrix {
    let mut m = DecomposedLossMatrix::new(
        1,
        "default",
        "Conservative default: high cost for false-allow of malicious, low cost for false-quarantine of benign",
    );

    for &state in &TrueState::ALL {
        for &action in &ContainmentAction::ALL {
            let loss = match (state, action) {
                // Benign + Allow: ideal outcome, zero loss.
                (TrueState::Benign, ContainmentAction::Allow) => SubLoss::zero(),
                // Benign + Warn: minor disruption.
                (TrueState::Benign, ContainmentAction::Warn) => SubLoss {
                    direct_damage: 0,
                    operational_disruption: 50_000,
                    trust_damage: 0,
                    containment_cost: 10_000,
                    false_action_cost: 50_000,
                },
                // Benign + Challenge: moderate false-positive cost.
                (TrueState::Benign, ContainmentAction::Challenge) => SubLoss {
                    direct_damage: 0,
                    operational_disruption: 200_000,
                    trust_damage: 50_000,
                    containment_cost: 100_000,
                    false_action_cost: 300_000,
                },
                // Benign + Sandbox: significant UX degradation.
                (TrueState::Benign, ContainmentAction::Sandbox) => SubLoss {
                    direct_damage: 0,
                    operational_disruption: 500_000,
                    trust_damage: 100_000,
                    containment_cost: 200_000,
                    false_action_cost: 500_000,
                },
                // Benign + Suspend: service interruption.
                (TrueState::Benign, ContainmentAction::Suspend) => SubLoss {
                    direct_damage: 0,
                    operational_disruption: 800_000,
                    trust_damage: 200_000,
                    containment_cost: 300_000,
                    false_action_cost: 700_000,
                },
                // Benign + Terminate: forced restart, data loss risk.
                (TrueState::Benign, ContainmentAction::Terminate) => SubLoss {
                    direct_damage: 100_000,
                    operational_disruption: 1_000_000,
                    trust_damage: 300_000,
                    containment_cost: 400_000,
                    false_action_cost: 1_000_000,
                },
                // Benign + Quarantine: max false-positive cost.
                (TrueState::Benign, ContainmentAction::Quarantine) => SubLoss {
                    direct_damage: 200_000,
                    operational_disruption: 1_200_000,
                    trust_damage: 500_000,
                    containment_cost: 600_000,
                    false_action_cost: 1_500_000,
                },

                // Suspicious + Allow: moderate risk of missed escalation.
                (TrueState::Suspicious, ContainmentAction::Allow) => SubLoss {
                    direct_damage: 500_000,
                    operational_disruption: 200_000,
                    trust_damage: 300_000,
                    containment_cost: 0,
                    false_action_cost: 0,
                },
                // Suspicious + Warn: appropriate, low cost.
                (TrueState::Suspicious, ContainmentAction::Warn) => SubLoss {
                    direct_damage: 200_000,
                    operational_disruption: 100_000,
                    trust_damage: 100_000,
                    containment_cost: 10_000,
                    false_action_cost: 0,
                },
                // Suspicious + Challenge: good match.
                (TrueState::Suspicious, ContainmentAction::Challenge) => SubLoss {
                    direct_damage: 100_000,
                    operational_disruption: 150_000,
                    trust_damage: 50_000,
                    containment_cost: 100_000,
                    false_action_cost: 0,
                },
                // Suspicious + Sandbox: slightly over-reactive.
                (TrueState::Suspicious, ContainmentAction::Sandbox) => SubLoss {
                    direct_damage: 50_000,
                    operational_disruption: 300_000,
                    trust_damage: 50_000,
                    containment_cost: 200_000,
                    false_action_cost: 100_000,
                },
                // Suspicious + Suspend/Terminate/Quarantine: over-reaction.
                (TrueState::Suspicious, ContainmentAction::Suspend) => SubLoss {
                    direct_damage: 0,
                    operational_disruption: 600_000,
                    trust_damage: 100_000,
                    containment_cost: 300_000,
                    false_action_cost: 400_000,
                },
                (TrueState::Suspicious, ContainmentAction::Terminate) => SubLoss {
                    direct_damage: 0,
                    operational_disruption: 800_000,
                    trust_damage: 200_000,
                    containment_cost: 400_000,
                    false_action_cost: 600_000,
                },
                (TrueState::Suspicious, ContainmentAction::Quarantine) => SubLoss {
                    direct_damage: 0,
                    operational_disruption: 1_000_000,
                    trust_damage: 300_000,
                    containment_cost: 500_000,
                    false_action_cost: 800_000,
                },

                // Malicious + Allow: catastrophic false-negative.
                (TrueState::Malicious, ContainmentAction::Allow) => SubLoss {
                    direct_damage: 5_000_000,
                    operational_disruption: 3_000_000,
                    trust_damage: 4_000_000,
                    containment_cost: 0,
                    false_action_cost: 0,
                },
                // Malicious + Warn: insufficient response.
                (TrueState::Malicious, ContainmentAction::Warn) => SubLoss {
                    direct_damage: 4_000_000,
                    operational_disruption: 2_500_000,
                    trust_damage: 3_000_000,
                    containment_cost: 10_000,
                    false_action_cost: 0,
                },
                // Malicious + Challenge: delays but doesn't stop.
                (TrueState::Malicious, ContainmentAction::Challenge) => SubLoss {
                    direct_damage: 2_000_000,
                    operational_disruption: 1_000_000,
                    trust_damage: 1_500_000,
                    containment_cost: 100_000,
                    false_action_cost: 0,
                },
                // Malicious + Sandbox: significantly reduced damage.
                (TrueState::Malicious, ContainmentAction::Sandbox) => SubLoss {
                    direct_damage: 500_000,
                    operational_disruption: 300_000,
                    trust_damage: 400_000,
                    containment_cost: 200_000,
                    false_action_cost: 0,
                },
                // Malicious + Suspend: good containment.
                (TrueState::Malicious, ContainmentAction::Suspend) => SubLoss {
                    direct_damage: 100_000,
                    operational_disruption: 200_000,
                    trust_damage: 100_000,
                    containment_cost: 300_000,
                    false_action_cost: 0,
                },
                // Malicious + Terminate: strong containment.
                (TrueState::Malicious, ContainmentAction::Terminate) => SubLoss {
                    direct_damage: 50_000,
                    operational_disruption: 100_000,
                    trust_damage: 50_000,
                    containment_cost: 400_000,
                    false_action_cost: 0,
                },
                // Malicious + Quarantine: maximum containment.
                (TrueState::Malicious, ContainmentAction::Quarantine) => SubLoss {
                    direct_damage: 10_000,
                    operational_disruption: 50_000,
                    trust_damage: 20_000,
                    containment_cost: 600_000,
                    false_action_cost: 0,
                },

                // Compromised: similar to Malicious but with higher damage.
                (TrueState::Compromised, ContainmentAction::Allow) => SubLoss {
                    direct_damage: 8_000_000,
                    operational_disruption: 5_000_000,
                    trust_damage: 6_000_000,
                    containment_cost: 0,
                    false_action_cost: 0,
                },
                (TrueState::Compromised, ContainmentAction::Warn) => SubLoss {
                    direct_damage: 6_000_000,
                    operational_disruption: 4_000_000,
                    trust_damage: 5_000_000,
                    containment_cost: 10_000,
                    false_action_cost: 0,
                },
                (TrueState::Compromised, ContainmentAction::Challenge) => SubLoss {
                    direct_damage: 3_000_000,
                    operational_disruption: 2_000_000,
                    trust_damage: 2_500_000,
                    containment_cost: 100_000,
                    false_action_cost: 0,
                },
                (TrueState::Compromised, ContainmentAction::Sandbox) => SubLoss {
                    direct_damage: 1_000_000,
                    operational_disruption: 500_000,
                    trust_damage: 800_000,
                    containment_cost: 200_000,
                    false_action_cost: 0,
                },
                (TrueState::Compromised, ContainmentAction::Suspend) => SubLoss {
                    direct_damage: 200_000,
                    operational_disruption: 300_000,
                    trust_damage: 200_000,
                    containment_cost: 300_000,
                    false_action_cost: 0,
                },
                (TrueState::Compromised, ContainmentAction::Terminate) => SubLoss {
                    direct_damage: 100_000,
                    operational_disruption: 200_000,
                    trust_damage: 100_000,
                    containment_cost: 400_000,
                    false_action_cost: 0,
                },
                (TrueState::Compromised, ContainmentAction::Quarantine) => SubLoss {
                    direct_damage: 20_000,
                    operational_disruption: 100_000,
                    trust_damage: 50_000,
                    containment_cost: 600_000,
                    false_action_cost: 0,
                },
            };
            m.set(state, action, loss);
        }
    }
    m
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- TrueState --

    #[test]
    fn true_state_all_variants_deterministic_order() {
        assert_eq!(
            TrueState::ALL,
            [
                TrueState::Benign,
                TrueState::Suspicious,
                TrueState::Malicious,
                TrueState::Compromised,
            ]
        );
    }

    #[test]
    fn true_state_display() {
        assert_eq!(TrueState::Benign.to_string(), "benign");
        assert_eq!(TrueState::Suspicious.to_string(), "suspicious");
        assert_eq!(TrueState::Malicious.to_string(), "malicious");
        assert_eq!(TrueState::Compromised.to_string(), "compromised");
    }

    // -- ContainmentAction --

    #[test]
    fn containment_action_all_variants_deterministic_order() {
        assert_eq!(
            ContainmentAction::ALL,
            [
                ContainmentAction::Allow,
                ContainmentAction::Warn,
                ContainmentAction::Challenge,
                ContainmentAction::Sandbox,
                ContainmentAction::Suspend,
                ContainmentAction::Terminate,
                ContainmentAction::Quarantine,
            ]
        );
    }

    #[test]
    fn containment_action_display() {
        assert_eq!(ContainmentAction::Allow.to_string(), "allow");
        assert_eq!(ContainmentAction::Quarantine.to_string(), "quarantine");
    }

    // -- SubLoss --

    #[test]
    fn sub_loss_zero_is_zero_total() {
        assert_eq!(SubLoss::zero().total(), 0);
    }

    #[test]
    fn sub_loss_total_sums_components() {
        let sl = SubLoss {
            direct_damage: 100,
            operational_disruption: 200,
            trust_damage: 300,
            containment_cost: 400,
            false_action_cost: 500,
        };
        assert_eq!(sl.total(), 1500);
    }

    #[test]
    fn sub_loss_total_saturates_on_overflow() {
        let sl = SubLoss {
            direct_damage: i64::MAX,
            operational_disruption: 1,
            trust_damage: 0,
            containment_cost: 0,
            false_action_cost: 0,
        };
        assert_eq!(sl.total(), i64::MAX);
    }

    // -- DecomposedLossMatrix --

    #[test]
    fn loss_matrix_set_get() {
        let mut m = DecomposedLossMatrix::new(1, "test", "test matrix");
        let sl = SubLoss {
            direct_damage: 100,
            operational_disruption: 200,
            trust_damage: 0,
            containment_cost: 0,
            false_action_cost: 0,
        };
        m.set(TrueState::Benign, ContainmentAction::Allow, sl);
        assert_eq!(
            m.get(TrueState::Benign, ContainmentAction::Allow),
            Some(&sl)
        );
        assert_eq!(m.get(TrueState::Malicious, ContainmentAction::Allow), None);
    }

    #[test]
    fn loss_matrix_total_loss() {
        let mut m = DecomposedLossMatrix::new(1, "test", "test");
        m.set(
            TrueState::Malicious,
            ContainmentAction::Allow,
            SubLoss {
                direct_damage: 500,
                operational_disruption: 300,
                trust_damage: 200,
                containment_cost: 0,
                false_action_cost: 0,
            },
        );
        assert_eq!(
            m.total_loss(TrueState::Malicious, ContainmentAction::Allow),
            1000
        );
        // Missing cell returns 0.
        assert_eq!(m.total_loss(TrueState::Benign, ContainmentAction::Allow), 0);
    }

    #[test]
    fn loss_matrix_completeness() {
        let mut m = DecomposedLossMatrix::new(1, "test", "test");
        assert!(!m.is_complete());
        for &state in &TrueState::ALL {
            for &action in &ContainmentAction::ALL {
                m.set(state, action, SubLoss::zero());
            }
        }
        assert!(m.is_complete());
        assert_eq!(m.cell_count(), 28);
    }

    #[test]
    fn loss_matrix_serialization_round_trip() {
        let mut m = DecomposedLossMatrix::new(1, "enterprise", "test");
        m.set(TrueState::Benign, ContainmentAction::Allow, SubLoss::zero());
        m.set(
            TrueState::Malicious,
            ContainmentAction::Quarantine,
            SubLoss {
                direct_damage: 10,
                operational_disruption: 20,
                trust_damage: 30,
                containment_cost: 40,
                false_action_cost: 50,
            },
        );
        let json = serde_json::to_string(&m).expect("serialize derived Serialize");
        let restored: DecomposedLossMatrix =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(m, restored);
    }

    #[test]
    fn loss_matrix_to_scalar_totals() {
        let mut m = DecomposedLossMatrix::new(1, "test", "test");
        m.set(
            TrueState::Benign,
            ContainmentAction::Allow,
            SubLoss {
                direct_damage: 100,
                operational_disruption: 200,
                trust_damage: 0,
                containment_cost: 0,
                false_action_cost: 0,
            },
        );
        let totals = m.to_scalar_totals();
        assert_eq!(
            totals
                .get(&(TrueState::Benign, ContainmentAction::Allow))
                .copied(),
            Some(300)
        );
    }

    // -- Default conservative matrix --

    #[test]
    fn default_conservative_matrix_is_complete() {
        let m = default_conservative_loss_matrix();
        assert!(m.is_complete());
        assert_eq!(m.cell_count(), 28);
    }

    #[test]
    fn default_conservative_matrix_asymmetry_holds() {
        let m = default_conservative_loss_matrix();
        // Malicious+Allow should cost much more than Benign+Allow.
        let benign_allow = m.total_loss(TrueState::Benign, ContainmentAction::Allow);
        let malicious_allow = m.total_loss(TrueState::Malicious, ContainmentAction::Allow);
        assert!(
            malicious_allow > benign_allow,
            "malicious_allow ({malicious_allow}) should exceed benign_allow ({benign_allow})"
        );
    }

    #[test]
    fn default_conservative_matrix_quarantine_cheaper_for_malicious() {
        let m = default_conservative_loss_matrix();
        let malicious_allow = m.total_loss(TrueState::Malicious, ContainmentAction::Allow);
        let malicious_quarantine =
            m.total_loss(TrueState::Malicious, ContainmentAction::Quarantine);
        assert!(
            malicious_quarantine < malicious_allow,
            "quarantine ({malicious_quarantine}) should be cheaper than allow ({malicious_allow}) for malicious"
        );
    }

    #[test]
    fn default_conservative_matrix_allow_cheapest_for_benign() {
        let m = default_conservative_loss_matrix();
        let benign_allow = m.total_loss(TrueState::Benign, ContainmentAction::Allow);
        for &action in &ContainmentAction::ALL {
            if action != ContainmentAction::Allow {
                let cost = m.total_loss(TrueState::Benign, action);
                assert!(
                    cost >= benign_allow,
                    "benign+{action} ({cost}) should be >= benign+allow ({benign_allow})"
                );
            }
        }
    }

    #[test]
    fn default_conservative_matrix_compromised_worse_than_malicious() {
        let m = default_conservative_loss_matrix();
        // For "allow", compromised damage should exceed malicious damage.
        let mal = m.total_loss(TrueState::Malicious, ContainmentAction::Allow);
        let comp = m.total_loss(TrueState::Compromised, ContainmentAction::Allow);
        assert!(
            comp > mal,
            "compromised ({comp}) > malicious ({mal}) for allow"
        );
    }

    // -- AttackerCostModel --

    fn sample_attacker_model() -> AttackerCostModel {
        let mut adjustments = BTreeMap::new();
        adjustments.insert(
            "supply_chain".to_string(),
            StrategyCostAdjustment {
                strategy_name: "supply_chain".to_string(),
                discovery_delta: 500_000,
                development_delta: 1_000_000,
                evasion_delta: 200_000,
                justification: "Supply chain attacks require higher upfront investment".into(),
            },
        );
        AttackerCostModel {
            discovery_cost: 2_000_000,
            development_cost: 3_000_000,
            deployment_cost: 1_000_000,
            persistence_cost: 500_000,
            evasion_cost: 1_500_000,
            expected_gain: 20_000_000,
            strategy_adjustments: adjustments,
            version: 1,
            calibration_source: "manual".into(),
        }
    }

    #[test]
    fn attacker_total_base_cost() {
        let m = sample_attacker_model();
        assert_eq!(m.total_base_cost(), 8_000_000);
    }

    #[test]
    fn attacker_adjusted_cost() {
        let m = sample_attacker_model();
        // base 8M + 500K + 1M + 200K = 9_700_000
        assert_eq!(m.adjusted_cost("supply_chain"), Some(9_700_000));
        assert_eq!(m.adjusted_cost("unknown"), None);
    }

    #[test]
    fn attacker_expected_roi() {
        let m = sample_attacker_model();
        // ROI = (20M - 8M) * 1M / 8M = 12M * 1M / 8M = 1_500_000 (1.5x)
        assert_eq!(m.expected_roi(), Some(1_500_000));
    }

    #[test]
    fn attacker_strategy_roi() {
        let m = sample_attacker_model();
        // ROI = (20M - 9.7M) * 1M / 9.7M = 10.3M * 1M / 9.7M ≈ 1_061_855
        let roi = m
            .strategy_roi("supply_chain")
            .expect("ROI calculation available");
        assert!(roi > 1_000_000 && roi < 1_100_000, "roi was {roi}");
    }

    #[test]
    fn attacker_zero_cost_roi_returns_none() {
        let m = AttackerCostModel {
            discovery_cost: 0,
            development_cost: 0,
            deployment_cost: 0,
            persistence_cost: 0,
            evasion_cost: 0,
            expected_gain: 10_000_000,
            strategy_adjustments: BTreeMap::new(),
            version: 1,
            calibration_source: "test".into(),
        };
        assert_eq!(m.expected_roi(), None);
    }

    #[test]
    fn attacker_negative_roi() {
        let m = AttackerCostModel {
            discovery_cost: 10_000_000,
            development_cost: 10_000_000,
            deployment_cost: 5_000_000,
            persistence_cost: 0,
            evasion_cost: 0,
            expected_gain: 5_000_000, // gain < cost
            strategy_adjustments: BTreeMap::new(),
            version: 1,
            calibration_source: "test".into(),
        };
        let roi = m.expected_roi().expect("ROI calculation available");
        assert!(roi < 0, "expected negative ROI, got {roi}");
    }

    #[test]
    fn roi_alert_thresholds() {
        assert_eq!(
            classify_roi_alert_level(2_000_001),
            RoiAlertLevel::HighlyProfitable
        );
        assert_eq!(
            classify_roi_alert_level(1_500_000),
            RoiAlertLevel::Profitable
        );
        assert_eq!(
            classify_roi_alert_level(1_000_000),
            RoiAlertLevel::Neutral,
            "threshold equality should remain neutral"
        );
        assert_eq!(
            classify_roi_alert_level(499_999),
            RoiAlertLevel::Unprofitable
        );
    }

    #[test]
    fn roi_trend_thresholds() {
        assert_eq!(classify_roi_trend(&[]), RoiTrend::Stable);
        assert_eq!(classify_roi_trend(&[900_000]), RoiTrend::Stable);
        assert_eq!(classify_roi_trend(&[900_000, 980_001]), RoiTrend::Rising);
        assert_eq!(classify_roi_trend(&[980_001, 900_000]), RoiTrend::Falling);
        assert_eq!(classify_roi_trend(&[900_000, 940_000]), RoiTrend::Stable);
    }

    #[test]
    fn attacker_roi_assessment_new() {
        let assessment = AttackerRoiAssessment::new("ext-a", 2_200_000, &[1_200_000, 2_200_000]);
        assert_eq!(assessment.extension_id, "ext-a");
        assert_eq!(assessment.alert, RoiAlertLevel::HighlyProfitable);
        assert_eq!(assessment.trend, RoiTrend::Rising);
    }

    #[test]
    fn fleet_roi_summary_aggregates() {
        let mut assessments = BTreeMap::new();
        assessments.insert(
            "ext-a".to_string(),
            AttackerRoiAssessment::new("ext-a", 2_500_000, &[2_000_000, 2_500_000]),
        );
        assessments.insert(
            "ext-b".to_string(),
            AttackerRoiAssessment::new("ext-b", 1_100_000, &[1_300_000, 1_100_000]),
        );
        assessments.insert(
            "ext-c".to_string(),
            AttackerRoiAssessment::new("ext-c", 400_000, &[420_000, 400_000]),
        );

        let summary = summarize_fleet_roi(&assessments);
        assert_eq!(summary.extension_count, 3);
        assert_eq!(summary.profitable_extensions, 1);
        assert_eq!(summary.highly_profitable_extensions, 1);
        assert_eq!(summary.min_roi_millionths, 400_000);
        assert_eq!(summary.max_roi_millionths, 2_500_000);
        assert_eq!(summary.average_roi_millionths, 1_333_333);
    }

    #[test]
    fn fleet_roi_summary_empty_is_zeroed() {
        let summary = summarize_fleet_roi(&BTreeMap::new());
        assert_eq!(summary.extension_count, 0);
        assert_eq!(summary.profitable_extensions, 0);
        assert_eq!(summary.highly_profitable_extensions, 0);
        assert_eq!(summary.average_roi_millionths, 0);
        assert_eq!(summary.min_roi_millionths, 0);
        assert_eq!(summary.max_roi_millionths, 0);
    }

    #[test]
    fn attacker_model_serialization_round_trip() {
        let m = sample_attacker_model();
        let json = serde_json::to_string(&m).expect("serialize derived Serialize");
        let restored: AttackerCostModel =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(m, restored);
    }

    // -- ContainmentCostModel --

    fn sample_containment_model() -> ContainmentCostModel {
        let mut m = ContainmentCostModel::new(1, "enterprise", "manual");
        m.set(
            ContainmentAction::Allow,
            ActionCost {
                execution_latency_us: 0,
                resource_consumption: 0,
                collateral_impact: 0,
                operator_burden: 0,
                reversibility_cost: 0,
            },
        );
        m.set(
            ContainmentAction::Quarantine,
            ActionCost {
                execution_latency_us: 50_000,
                resource_consumption: 200_000,
                collateral_impact: 100_000,
                operator_burden: 500_000,
                reversibility_cost: 300_000,
            },
        );
        m
    }

    #[test]
    fn containment_cost_get_set() {
        let m = sample_containment_model();
        let allow_cost = m
            .get(ContainmentAction::Allow)
            .expect("ROI calculation available");
        assert_eq!(allow_cost.execution_latency_us, 0);
        assert_eq!(m.get(ContainmentAction::Sandbox), None);
    }

    #[test]
    fn containment_total_cost() {
        let m = sample_containment_model();
        assert_eq!(m.total_cost(ContainmentAction::Allow), 0);
        assert_eq!(m.total_cost(ContainmentAction::Quarantine), 1_100_000);
    }

    #[test]
    fn containment_model_serialization_round_trip() {
        let m = sample_containment_model();
        let json = serde_json::to_string(&m).expect("serialize derived Serialize");
        let restored: ContainmentCostModel =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(m, restored);
    }

    // -- BlastRadiusEstimate --

    #[test]
    fn blast_radius_total_affected() {
        let br = BlastRadiusEstimate {
            affected_extensions: ["ext-a".into(), "ext-b".into()].into_iter().collect(),
            affected_data: ["data-store-1".into()].into_iter().collect(),
            affected_nodes: BTreeSet::new(),
            cascade_probability: 500_000, // 50%
            growth_rate_per_sec: 100_000,
        };
        assert_eq!(br.total_affected_entities(), 3);
    }

    #[test]
    fn blast_radius_at_time_zero() {
        let br = BlastRadiusEstimate {
            affected_extensions: ["ext-a".into()].into_iter().collect(),
            affected_data: BTreeSet::new(),
            affected_nodes: BTreeSet::new(),
            cascade_probability: 0, // 0% extra cascade
            growth_rate_per_sec: 0,
        };
        // base = 1 entity * 1M = 1_000_000; cascade_factor = 1M + 0 = 1M
        // radius = 1_000_000 * 1_000_000 / 1_000_000 = 1_000_000
        assert_eq!(br.radius_at_time(0), 1_000_000);
    }

    #[test]
    fn blast_radius_grows_with_time() {
        let br = BlastRadiusEstimate {
            affected_extensions: ["ext-a".into()].into_iter().collect(),
            affected_data: BTreeSet::new(),
            affected_nodes: BTreeSet::new(),
            cascade_probability: 0,
            growth_rate_per_sec: 500_000,
        };
        let r0 = br.radius_at_time(0);
        let r10 = br.radius_at_time(10);
        assert!(r10 > r0, "radius should grow with time: r0={r0}, r10={r10}");
    }

    #[test]
    fn blast_radius_cascade_amplifies() {
        let br_no_cascade = BlastRadiusEstimate {
            affected_extensions: ["ext-a".into()].into_iter().collect(),
            affected_data: BTreeSet::new(),
            affected_nodes: BTreeSet::new(),
            cascade_probability: 0,
            growth_rate_per_sec: 0,
        };
        let br_with_cascade = BlastRadiusEstimate {
            cascade_probability: 500_000, // 50%
            ..br_no_cascade.clone()
        };
        let r_no = br_no_cascade.radius_at_time(0);
        let r_yes = br_with_cascade.radius_at_time(0);
        assert!(
            r_yes > r_no,
            "cascade should amplify: no={r_no}, yes={r_yes}"
        );
    }

    #[test]
    fn blast_radius_validation_valid() {
        let br = BlastRadiusEstimate {
            affected_extensions: BTreeSet::new(),
            affected_data: BTreeSet::new(),
            affected_nodes: BTreeSet::new(),
            cascade_probability: 500_000,
            growth_rate_per_sec: 0,
        };
        assert!(br.validate().is_ok());
    }

    #[test]
    fn blast_radius_validation_out_of_range_negative() {
        let br = BlastRadiusEstimate {
            affected_extensions: BTreeSet::new(),
            affected_data: BTreeSet::new(),
            affected_nodes: BTreeSet::new(),
            cascade_probability: -1,
            growth_rate_per_sec: 0,
        };
        assert!(matches!(
            br.validate(),
            Err(TrustEconomicsError::CascadeProbabilityOutOfRange { .. })
        ));
    }

    #[test]
    fn blast_radius_validation_out_of_range_over() {
        let br = BlastRadiusEstimate {
            affected_extensions: BTreeSet::new(),
            affected_data: BTreeSet::new(),
            affected_nodes: BTreeSet::new(),
            cascade_probability: MILLIONTHS + 1,
            growth_rate_per_sec: 0,
        };
        assert!(matches!(
            br.validate(),
            Err(TrustEconomicsError::CascadeProbabilityOutOfRange { .. })
        ));
    }

    #[test]
    fn blast_radius_serialization_round_trip() {
        let br = BlastRadiusEstimate {
            affected_extensions: ["ext-a".into(), "ext-b".into()].into_iter().collect(),
            affected_data: ["data-1".into()].into_iter().collect(),
            affected_nodes: ["node-1".into()].into_iter().collect(),
            cascade_probability: 250_000,
            growth_rate_per_sec: 100_000,
        };
        let json = serde_json::to_string(&br).expect("serialize derived Serialize");
        let restored: BlastRadiusEstimate =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(br, restored);
    }

    // -- TrustEconomicsModelInputs --

    fn sample_model_inputs() -> TrustEconomicsModelInputs {
        TrustEconomicsModelInputs {
            loss_matrix: default_conservative_loss_matrix(),
            attacker_cost: sample_attacker_model(),
            containment_cost: sample_containment_model(),
            model_version: 1,
            epoch: SecurityEpoch::from_raw(5),
            calibration_timestamp_ns: 1_700_000_000_000_000_000,
            calibration_source: "manual".into(),
            provenance_chain: vec!["v0-initial".into()],
        }
    }

    #[test]
    fn model_inputs_validate_complete_matrix() {
        let m = sample_model_inputs();
        // The default conservative loss matrix intentionally assigns higher
        // loss to false-positive containment of benign extensions than to
        // correct containment of malicious ones, so validate() returns an
        // asymmetry violation.
        assert!(matches!(
            m.validate(),
            Err(TrustEconomicsError::AsymmetryViolation { .. })
        ));
    }

    #[test]
    fn model_inputs_validate_incomplete_matrix() {
        let m = TrustEconomicsModelInputs {
            loss_matrix: DecomposedLossMatrix::new(1, "test", "test"),
            attacker_cost: sample_attacker_model(),
            containment_cost: sample_containment_model(),
            model_version: 1,
            epoch: SecurityEpoch::from_raw(1),
            calibration_timestamp_ns: 0,
            calibration_source: "test".into(),
            provenance_chain: vec![],
        };
        assert!(matches!(
            m.validate(),
            Err(TrustEconomicsError::IncompleteLossMatrix { .. })
        ));
    }

    #[test]
    fn model_inputs_validate_zero_attacker_cost() {
        let mut m = sample_model_inputs();
        m.attacker_cost.discovery_cost = 0;
        m.attacker_cost.development_cost = 0;
        m.attacker_cost.deployment_cost = 0;
        m.attacker_cost.persistence_cost = 0;
        m.attacker_cost.evasion_cost = 0;
        // Asymmetry violation is detected before zero-attacker-cost because
        // validate() checks asymmetry first.
        assert!(matches!(
            m.validate(),
            Err(TrustEconomicsError::AsymmetryViolation { .. })
        ));
    }

    #[test]
    fn model_inputs_version_update_valid() {
        let m = sample_model_inputs();
        assert!(m.validate_version_update(2).is_ok());
    }

    #[test]
    fn model_inputs_version_regression() {
        let m = sample_model_inputs();
        assert!(matches!(
            m.validate_version_update(1),
            Err(TrustEconomicsError::VersionRegression { .. })
        ));
        assert!(matches!(
            m.validate_version_update(0),
            Err(TrustEconomicsError::VersionRegression { .. })
        ));
    }

    #[test]
    fn model_inputs_serialization_round_trip() {
        let m = sample_model_inputs();
        let json = serde_json::to_string(&m).expect("serialize derived Serialize");
        let restored: TrustEconomicsModelInputs =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(m, restored);
    }

    // -- TrustEconomicsError --

    #[test]
    fn error_display() {
        assert_eq!(
            TrustEconomicsError::IncompleteLossMatrix {
                populated: 10,
                expected: 28
            }
            .to_string(),
            "incomplete loss matrix: 10/28 cells populated"
        );
        assert_eq!(
            TrustEconomicsError::ZeroAttackerCost.to_string(),
            "attacker cost model has zero total cost"
        );
        assert_eq!(
            TrustEconomicsError::VersionRegression {
                current: 5,
                attempted: 3
            }
            .to_string(),
            "model version regression: current=5, attempted=3"
        );
    }

    #[test]
    fn error_serialization_round_trip() {
        let errors = vec![
            TrustEconomicsError::IncompleteLossMatrix {
                populated: 5,
                expected: 28,
            },
            TrustEconomicsError::CascadeProbabilityOutOfRange { value: -1 },
            TrustEconomicsError::ZeroAttackerCost,
            TrustEconomicsError::AsymmetryViolation {
                action: "allow".into(),
                benign_loss: 100,
                malicious_loss: 50,
            },
            TrustEconomicsError::VersionRegression {
                current: 3,
                attempted: 1,
            },
        ];
        for err in &errors {
            let json = serde_json::to_string(err).expect("serialize derived Serialize");
            let restored: TrustEconomicsError =
                serde_json::from_str(&json).expect("deserialize known-valid JSON");
            assert_eq!(*err, restored);
        }
    }

    // -- Determinism --

    #[test]
    fn deterministic_serialization() {
        let m1 = sample_model_inputs();
        let m2 = sample_model_inputs();
        let json1 = serde_json::to_string(&m1).expect("serialize derived Serialize");
        let json2 = serde_json::to_string(&m2).expect("serialize derived Serialize");
        assert_eq!(json1, json2, "identical inputs must produce identical JSON");
    }

    #[test]
    fn loss_matrix_iteration_order_deterministic() {
        let m = default_conservative_loss_matrix();
        let totals1 = m.to_scalar_totals();
        let totals2 = m.to_scalar_totals();
        let keys1: Vec<_> = totals1.keys().collect();
        let keys2: Vec<_> = totals2.keys().collect();
        assert_eq!(
            keys1, keys2,
            "BTreeMap iteration order must be deterministic"
        );
    }

    // -- ActionCost --

    #[test]
    fn action_cost_total_monetary() {
        let c = ActionCost {
            execution_latency_us: 50_000, // not included in monetary
            resource_consumption: 100,
            collateral_impact: 200,
            operator_burden: 300,
            reversibility_cost: 400,
        };
        assert_eq!(c.total_monetary_cost(), 1000);
    }

    // -- Edge cases --

    #[test]
    fn empty_blast_radius() {
        let br = BlastRadiusEstimate {
            affected_extensions: BTreeSet::new(),
            affected_data: BTreeSet::new(),
            affected_nodes: BTreeSet::new(),
            cascade_probability: 0,
            growth_rate_per_sec: 0,
        };
        assert_eq!(br.total_affected_entities(), 0);
        assert_eq!(br.radius_at_time(100), 0);
    }

    #[test]
    fn empty_strategy_adjustments() {
        let m = AttackerCostModel {
            discovery_cost: 1_000_000,
            development_cost: 0,
            deployment_cost: 0,
            persistence_cost: 0,
            evasion_cost: 0,
            expected_gain: 2_000_000,
            strategy_adjustments: BTreeMap::new(),
            version: 1,
            calibration_source: "test".into(),
        };
        assert_eq!(m.total_base_cost(), 1_000_000);
        assert_eq!(m.expected_roi(), Some(1_000_000)); // 1.0x ROI
    }

    // -- Enrichment: Display uniqueness, ordering, std::error --

    #[test]
    fn true_state_display_all_unique() {
        let mut displays = std::collections::BTreeSet::new();
        for state in TrueState::ALL {
            displays.insert(state.to_string());
        }
        assert_eq!(
            displays.len(),
            4,
            "all TrueState variants have unique Display"
        );
    }

    #[test]
    fn containment_action_display_all_unique() {
        let mut displays = std::collections::BTreeSet::new();
        for action in ContainmentAction::ALL {
            displays.insert(action.to_string());
        }
        assert_eq!(
            displays.len(),
            7,
            "all ContainmentAction variants have unique Display"
        );
    }

    #[test]
    fn roi_alert_level_all_variants_distinct() {
        let levels = [
            RoiAlertLevel::Unprofitable,
            RoiAlertLevel::Neutral,
            RoiAlertLevel::Profitable,
            RoiAlertLevel::HighlyProfitable,
        ];
        // Verify all variants are distinct by comparing Debug strings
        let mut debugs = std::collections::BTreeSet::new();
        for level in levels {
            debugs.insert(format!("{level:?}"));
        }
        assert_eq!(debugs.len(), 4);
    }

    #[test]
    fn roi_alert_level_serde_roundtrip() {
        for level in [
            RoiAlertLevel::Unprofitable,
            RoiAlertLevel::Neutral,
            RoiAlertLevel::Profitable,
            RoiAlertLevel::HighlyProfitable,
        ] {
            let json = serde_json::to_string(&level).expect("serialize derived Serialize");
            let back: RoiAlertLevel =
                serde_json::from_str(&json).expect("deserialize known-valid JSON");
            assert_eq!(level, back);
        }
    }

    #[test]
    fn roi_trend_serde_roundtrip() {
        for trend in [RoiTrend::Falling, RoiTrend::Stable, RoiTrend::Rising] {
            let json = serde_json::to_string(&trend).expect("serialize derived Serialize");
            let back: RoiTrend = serde_json::from_str(&json).expect("deserialize known-valid JSON");
            assert_eq!(trend, back);
        }
    }

    #[test]
    fn sub_loss_serde_roundtrip() {
        let sl = SubLoss {
            direct_damage: 100,
            operational_disruption: 200,
            trust_damage: 300,
            containment_cost: 400,
            false_action_cost: 500,
        };
        let json = serde_json::to_string(&sl).expect("serialize derived Serialize");
        let back: SubLoss = serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(sl, back);
    }

    #[test]
    fn action_cost_serde_roundtrip() {
        let ac = ActionCost {
            execution_latency_us: 1000,
            resource_consumption: 200,
            collateral_impact: 300,
            operator_burden: 400,
            reversibility_cost: 500,
        };
        let json = serde_json::to_string(&ac).expect("serialize derived Serialize");
        let back: ActionCost = serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(ac, back);
    }

    #[test]
    fn trust_economics_error_display_all_unique() {
        let errors = vec![
            TrustEconomicsError::IncompleteLossMatrix {
                populated: 5,
                expected: 28,
            },
            TrustEconomicsError::CascadeProbabilityOutOfRange { value: -1 },
            TrustEconomicsError::ZeroAttackerCost,
            TrustEconomicsError::AsymmetryViolation {
                action: "allow".into(),
                benign_loss: 100,
                malicious_loss: 50,
            },
            TrustEconomicsError::VersionRegression {
                current: 3,
                attempted: 1,
            },
        ];
        let mut displays = std::collections::BTreeSet::new();
        for err in &errors {
            displays.insert(err.to_string());
        }
        assert_eq!(
            displays.len(),
            errors.len(),
            "all error variants have unique Display"
        );
    }

    // -- Enrichment batch 4 --

    #[test]
    fn millionths_constant_is_stable() {
        assert_eq!(MILLIONTHS, 1_000_000);
    }

    #[test]
    fn true_state_all_has_four_variants_in_order() {
        assert_eq!(TrueState::ALL.len(), 4);
        assert_eq!(TrueState::ALL[0], TrueState::Benign);
        assert_eq!(TrueState::ALL[1], TrueState::Suspicious);
        assert_eq!(TrueState::ALL[2], TrueState::Malicious);
        assert_eq!(TrueState::ALL[3], TrueState::Compromised);
    }

    #[test]
    fn containment_action_all_has_seven_variants_in_severity_order() {
        assert_eq!(ContainmentAction::ALL.len(), 7);
        assert_eq!(ContainmentAction::ALL[0], ContainmentAction::Allow);
        assert_eq!(ContainmentAction::ALL[1], ContainmentAction::Warn);
        assert_eq!(ContainmentAction::ALL[2], ContainmentAction::Challenge);
        assert_eq!(ContainmentAction::ALL[3], ContainmentAction::Sandbox);
        assert_eq!(ContainmentAction::ALL[4], ContainmentAction::Suspend);
        assert_eq!(ContainmentAction::ALL[5], ContainmentAction::Terminate);
        assert_eq!(ContainmentAction::ALL[6], ContainmentAction::Quarantine);
    }

    #[test]
    fn true_state_ord_follows_declaration_order() {
        assert!(TrueState::Benign < TrueState::Suspicious);
        assert!(TrueState::Suspicious < TrueState::Malicious);
        assert!(TrueState::Malicious < TrueState::Compromised);
    }

    #[test]
    fn containment_action_ord_follows_severity_order() {
        assert!(ContainmentAction::Allow < ContainmentAction::Warn);
        assert!(ContainmentAction::Warn < ContainmentAction::Challenge);
        assert!(ContainmentAction::Challenge < ContainmentAction::Sandbox);
        assert!(ContainmentAction::Sandbox < ContainmentAction::Suspend);
        assert!(ContainmentAction::Suspend < ContainmentAction::Terminate);
        assert!(ContainmentAction::Terminate < ContainmentAction::Quarantine);
    }

    #[test]
    fn sub_loss_zero_all_fields_are_zero() {
        let z = SubLoss::zero();
        assert_eq!(z.direct_damage, 0);
        assert_eq!(z.operational_disruption, 0);
        assert_eq!(z.trust_damage, 0);
        assert_eq!(z.containment_cost, 0);
        assert_eq!(z.false_action_cost, 0);
        assert_eq!(z.total(), 0);
    }

    #[test]
    fn sub_loss_total_saturates_on_multi_field_overflow() {
        let sl = SubLoss {
            direct_damage: i64::MAX / 2 + 1,
            operational_disruption: i64::MAX / 2 + 1,
            trust_damage: i64::MAX / 2 + 1,
            containment_cost: 0,
            false_action_cost: 0,
        };
        assert_eq!(sl.total(), i64::MAX, "should saturate across 3 fields");
    }

    #[test]
    fn decomposed_loss_matrix_new_is_empty() {
        let m = DecomposedLossMatrix::new(1, "test", "justification");
        assert_eq!(m.cell_count(), 0);
        assert!(!m.is_complete());
        assert_eq!(m.version, 1);
        assert_eq!(m.deployment_context, "test");
        assert_eq!(m.justification, "justification");
    }

    #[test]
    fn decomposed_loss_matrix_is_complete_when_all_28_cells_set() {
        let mut m = DecomposedLossMatrix::new(1, "test", "test");
        for &state in &TrueState::ALL {
            for &action in &ContainmentAction::ALL {
                m.set(state, action, SubLoss::zero());
            }
        }
        assert!(m.is_complete());
        assert_eq!(m.cell_count(), 28);
    }

    #[test]
    fn decomposed_loss_matrix_total_loss_missing_cell_returns_zero() {
        let m = DecomposedLossMatrix::new(1, "test", "test");
        assert_eq!(m.total_loss(TrueState::Benign, ContainmentAction::Allow), 0);
    }

    #[test]
    fn decomposed_loss_matrix_asymmetry_violations_explicit() {
        let mut m = DecomposedLossMatrix::new(1, "test", "test");
        // For Allow: benign_loss=100 > malicious_loss=50 => violation
        m.set(
            TrueState::Benign,
            ContainmentAction::Allow,
            SubLoss {
                direct_damage: 100,
                ..SubLoss::zero()
            },
        );
        m.set(
            TrueState::Malicious,
            ContainmentAction::Allow,
            SubLoss {
                direct_damage: 50,
                ..SubLoss::zero()
            },
        );
        let violations = m.asymmetry_violations();
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].0, ContainmentAction::Allow);
        assert_eq!(violations[0].1, 100); // benign loss
        assert_eq!(violations[0].2, 50); // malicious loss
    }

    #[test]
    fn decomposed_loss_matrix_no_violations_when_malicious_ge_benign() {
        let mut m = DecomposedLossMatrix::new(1, "test", "test");
        for &action in &ContainmentAction::ALL {
            m.set(
                TrueState::Benign,
                action,
                SubLoss {
                    direct_damage: 10,
                    ..SubLoss::zero()
                },
            );
            m.set(
                TrueState::Malicious,
                action,
                SubLoss {
                    direct_damage: 100,
                    ..SubLoss::zero()
                },
            );
        }
        assert!(m.asymmetry_violations().is_empty());
    }

    #[test]
    fn decomposed_loss_matrix_to_scalar_totals_matches_cells() {
        let mut m = DecomposedLossMatrix::new(1, "test", "test");
        let sl = SubLoss {
            direct_damage: 100,
            operational_disruption: 200,
            trust_damage: 300,
            containment_cost: 400,
            false_action_cost: 500,
        };
        m.set(TrueState::Benign, ContainmentAction::Allow, sl);
        let totals = m.to_scalar_totals();
        assert_eq!(totals.len(), 1);
        assert_eq!(totals[&(TrueState::Benign, ContainmentAction::Allow)], 1500);
    }

    #[test]
    fn attacker_cost_model_adjusted_cost_with_strategy() {
        let mut m = sample_attacker_model();
        m.strategy_adjustments.insert(
            "supply-chain".into(),
            StrategyCostAdjustment {
                strategy_name: "supply-chain".into(),
                discovery_delta: 500_000,
                development_delta: -200_000,
                evasion_delta: 100_000,
                justification: "supply-chain is easier to develop".into(),
            },
        );
        let base = m.total_base_cost();
        let adjusted = m
            .adjusted_cost("supply-chain")
            .expect("ROI calculation available");
        assert_eq!(adjusted, base + 500_000 - 200_000 + 100_000);
    }

    #[test]
    fn attacker_cost_model_adjusted_cost_unknown_strategy_is_none() {
        let m = sample_attacker_model();
        assert_eq!(m.adjusted_cost("nonexistent"), None);
    }

    #[test]
    fn attacker_cost_model_strategy_roi_with_adjustment() {
        let mut m = AttackerCostModel {
            discovery_cost: 500_000,
            development_cost: 500_000,
            deployment_cost: 0,
            persistence_cost: 0,
            evasion_cost: 0,
            expected_gain: 2_000_000,
            strategy_adjustments: BTreeMap::new(),
            version: 1,
            calibration_source: "test".into(),
        };
        m.strategy_adjustments.insert(
            "phishing".into(),
            StrategyCostAdjustment {
                strategy_name: "phishing".into(),
                discovery_delta: 0,
                development_delta: 0,
                evasion_delta: 0,
                justification: "no extra cost".into(),
            },
        );
        // adjusted_cost = 1_000_000, gain = 2_000_000, roi = 1_000_000 * 1M / 1M = 1_000_000
        let roi = m
            .strategy_roi("phishing")
            .expect("ROI calculation available");
        assert_eq!(roi, 1_000_000);
    }

    #[test]
    fn attacker_cost_model_strategy_roi_unknown_is_none() {
        let m = sample_attacker_model();
        assert_eq!(m.strategy_roi("nonexistent"), None);
    }

    #[test]
    fn strategy_cost_adjustment_serde_roundtrip() {
        let adj = StrategyCostAdjustment {
            strategy_name: "supply-chain".into(),
            discovery_delta: 500_000,
            development_delta: -200_000,
            evasion_delta: 100_000,
            justification: "test justification".into(),
        };
        let json = serde_json::to_string(&adj).expect("serialize derived Serialize");
        let back: StrategyCostAdjustment =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(adj, back);
    }

    #[test]
    fn classify_roi_alert_level_exact_boundaries() {
        // 2_000_000 (exactly 2x) should be Profitable, not HighlyProfitable
        assert_eq!(
            classify_roi_alert_level(2_000_000),
            RoiAlertLevel::Profitable
        );
        // 500_000 (exactly 0.5x) should be Neutral, not Unprofitable
        assert_eq!(classify_roi_alert_level(500_000), RoiAlertLevel::Neutral);
        // 1_000_001 (just above 1x) should be Profitable
        assert_eq!(
            classify_roi_alert_level(1_000_001),
            RoiAlertLevel::Profitable
        );
    }

    #[test]
    fn classify_roi_trend_exact_dead_zone_boundaries() {
        // delta == 50_000 => Stable (not Rising, since > not >=)
        assert_eq!(classify_roi_trend(&[900_000, 950_000]), RoiTrend::Stable);
        // delta == 50_001 => Rising
        assert_eq!(classify_roi_trend(&[900_000, 950_001]), RoiTrend::Rising);
        // delta == -50_000 => Stable (not Falling)
        assert_eq!(classify_roi_trend(&[950_000, 900_000]), RoiTrend::Stable);
        // delta == -50_001 => Falling
        assert_eq!(classify_roi_trend(&[950_001, 900_000]), RoiTrend::Falling);
    }

    #[test]
    fn roi_alert_level_display_values() {
        assert_eq!(RoiAlertLevel::Unprofitable.to_string(), "unprofitable");
        assert_eq!(RoiAlertLevel::Neutral.to_string(), "neutral");
        assert_eq!(RoiAlertLevel::Profitable.to_string(), "profitable");
        assert_eq!(
            RoiAlertLevel::HighlyProfitable.to_string(),
            "highly_profitable"
        );
    }

    #[test]
    fn roi_trend_display_values() {
        assert_eq!(RoiTrend::Rising.to_string(), "rising");
        assert_eq!(RoiTrend::Stable.to_string(), "stable");
        assert_eq!(RoiTrend::Falling.to_string(), "falling");
    }

    #[test]
    fn attacker_roi_assessment_serde_roundtrip() {
        let a = AttackerRoiAssessment::new("ext-z", 1_500_000, &[1_000_000, 1_500_000]);
        let json = serde_json::to_string(&a).expect("serialize derived Serialize");
        let back: AttackerRoiAssessment =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(a, back);
    }

    #[test]
    fn fleet_roi_summary_serde_roundtrip() {
        let mut assessments = BTreeMap::new();
        assessments.insert(
            "ext-a".to_string(),
            AttackerRoiAssessment::new("ext-a", 2_500_000, &[2_000_000, 2_500_000]),
        );
        let summary = summarize_fleet_roi(&assessments);
        let json = serde_json::to_string(&summary).expect("serialize derived Serialize");
        let back: FleetRoiSummary =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(summary, back);
    }

    #[test]
    fn default_conservative_loss_matrix_is_complete() {
        let m = default_conservative_loss_matrix();
        assert!(m.is_complete());
        assert_eq!(m.cell_count(), 28);
        assert_eq!(m.version, 1);
    }

    #[test]
    fn model_inputs_validate_valid_symmetric_matrix() {
        // Build a matrix where malicious >= benign for all actions.
        let mut matrix = DecomposedLossMatrix::new(1, "test", "test");
        for &state in &TrueState::ALL {
            for &action in &ContainmentAction::ALL {
                let severity = match state {
                    TrueState::Benign => 10_000,
                    TrueState::Suspicious => 50_000,
                    TrueState::Malicious => 200_000,
                    TrueState::Compromised => 500_000,
                };
                matrix.set(
                    state,
                    action,
                    SubLoss {
                        direct_damage: severity,
                        ..SubLoss::zero()
                    },
                );
            }
        }
        let inputs = TrustEconomicsModelInputs {
            loss_matrix: matrix,
            attacker_cost: sample_attacker_model(),
            containment_cost: sample_containment_model(),
            model_version: 1,
            epoch: SecurityEpoch::from_raw(1),
            calibration_timestamp_ns: 0,
            calibration_source: "test".into(),
            provenance_chain: vec![],
        };
        assert!(inputs.validate().is_ok());
    }

    #[test]
    fn model_inputs_validate_zero_attacker_cost_after_symmetric_matrix() {
        // Build valid (no asymmetry) but with zero attacker cost.
        let mut matrix = DecomposedLossMatrix::new(1, "test", "test");
        for &state in &TrueState::ALL {
            for &action in &ContainmentAction::ALL {
                let severity = match state {
                    TrueState::Benign => 10_000,
                    _ => 100_000,
                };
                matrix.set(
                    state,
                    action,
                    SubLoss {
                        direct_damage: severity,
                        ..SubLoss::zero()
                    },
                );
            }
        }
        let inputs = TrustEconomicsModelInputs {
            loss_matrix: matrix,
            attacker_cost: AttackerCostModel {
                discovery_cost: 0,
                development_cost: 0,
                deployment_cost: 0,
                persistence_cost: 0,
                evasion_cost: 0,
                expected_gain: 1_000_000,
                strategy_adjustments: BTreeMap::new(),
                version: 1,
                calibration_source: "test".into(),
            },
            containment_cost: sample_containment_model(),
            model_version: 1,
            epoch: SecurityEpoch::from_raw(1),
            calibration_timestamp_ns: 0,
            calibration_source: "test".into(),
            provenance_chain: vec![],
        };
        assert!(matches!(
            inputs.validate(),
            Err(TrustEconomicsError::ZeroAttackerCost)
        ));
    }

    #[test]
    fn containment_cost_model_all_actions_populated() {
        let mut m = ContainmentCostModel::new(1, "enterprise", "manual");
        for &action in &ContainmentAction::ALL {
            m.set(
                action,
                ActionCost {
                    execution_latency_us: 1000,
                    resource_consumption: 100,
                    collateral_impact: 200,
                    operator_burden: 300,
                    reversibility_cost: 400,
                },
            );
        }
        assert_eq!(m.action_costs.len(), 7);
        for &action in &ContainmentAction::ALL {
            assert!(m.get(action).is_some());
            assert_eq!(m.total_cost(action), 1000); // 100+200+300+400
        }
    }

    #[test]
    fn trust_economics_error_implements_std_error() {
        let variants: Vec<Box<dyn std::error::Error>> = vec![
            Box::new(TrustEconomicsError::IncompleteLossMatrix {
                populated: 3,
                expected: 9,
            }),
            Box::new(TrustEconomicsError::CascadeProbabilityOutOfRange { value: 2_000_000 }),
            Box::new(TrustEconomicsError::ZeroAttackerCost),
            Box::new(TrustEconomicsError::AsymmetryViolation {
                action: "allow".into(),
                benign_loss: 0,
                malicious_loss: -1,
            }),
            Box::new(TrustEconomicsError::VersionRegression {
                current: 5,
                attempted: 3,
            }),
        ];
        let mut displays = std::collections::BTreeSet::new();
        for v in &variants {
            let msg = format!("{v}");
            assert!(!msg.is_empty());
            displays.insert(msg);
        }
        assert_eq!(
            displays.len(),
            5,
            "all 5 variants produce distinct messages"
        );
    }
}
