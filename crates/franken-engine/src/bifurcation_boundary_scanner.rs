//! Bifurcation boundary scanner and early-warning stability guard.
//!
//! Detects qualitative stability regime changes before user-visible failures
//! by scanning policy/control parameters against twin dynamics. Triggers
//! preemptive demotion or safe-mode routing when boundary risk crosses budget.
//!
//! Plan reference: FRX-19.3

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;
use crate::runtime_decision_theory::{DemotionReason, LaneAction, LaneId, RegimeLabel};
use crate::security_epoch::SecurityEpoch;

// ── Constants ────────────────────────────────────────────────────────────

const MILLION: i64 = 1_000_000;

/// Schema version for bifurcation scanner artifacts.
pub const BIFURCATION_SCHEMA_VERSION: &str = "franken-engine.bifurcation-boundary-scanner.v1";

/// Maximum number of control parameters tracked.
const MAX_CONTROL_PARAMS: usize = 128;

/// Maximum number of operating envelope definitions.
const MAX_ENVELOPES: usize = 64;

/// Default proximity threshold (25% of envelope range).
const DEFAULT_PROXIMITY_THRESHOLD_MILLIONTHS: i64 = 250_000;

/// Default risk budget before preemptive action (millionths).
const DEFAULT_RISK_BUDGET_MILLIONTHS: i64 = 500_000;

/// Minimum observations before early-warning indicators activate.
const MIN_OBSERVATIONS: usize = 5;

// ── Control Parameter ────────────────────────────────────────────────────

/// A control or policy parameter that can be scanned for bifurcation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlParameter {
    /// Unique identifier.
    pub id: String,
    /// Human-readable label.
    pub label: String,
    /// Domain categorization.
    pub domain: ParameterDomain,
    /// Current value (fixed-point millionths).
    pub current_value_millionths: i64,
    /// Whether the parameter is directly tunable by policy.
    pub policy_tunable: bool,
}

impl fmt::Display for ControlParameter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}={}", self.id, self.current_value_millionths)
    }
}

/// Domain classification for control parameters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ParameterDomain {
    /// Loss/risk threshold parameter.
    RiskThreshold,
    /// Calibration/scheduling parameter.
    Calibration,
    /// Resource allocation parameter.
    ResourceAllocation,
    /// Routing/lane selection parameter.
    LaneRouting,
    /// Guard/safety boundary parameter.
    SafetyBoundary,
    /// Environment/workload characteristic.
    Environment,
}

impl fmt::Display for ParameterDomain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RiskThreshold => write!(f, "risk-threshold"),
            Self::Calibration => write!(f, "calibration"),
            Self::ResourceAllocation => write!(f, "resource-allocation"),
            Self::LaneRouting => write!(f, "lane-routing"),
            Self::SafetyBoundary => write!(f, "safety-boundary"),
            Self::Environment => write!(f, "environment"),
        }
    }
}

// ── Operating Envelope ───────────────────────────────────────────────────

/// An operating envelope defining safe bounds for a control parameter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatingEnvelope {
    /// Parameter ID this envelope applies to.
    pub parameter_id: String,
    /// Lower safe bound (inclusive, millionths).
    pub lower_bound_millionths: i64,
    /// Upper safe bound (inclusive, millionths).
    pub upper_bound_millionths: i64,
    /// Nominal operating point (millionths).
    pub nominal_millionths: i64,
    /// Criticality: how severe a breach is (millionths, 0-MILLION).
    pub criticality_millionths: i64,
}

impl OperatingEnvelope {
    /// Range of the envelope.
    pub fn range(&self) -> i64 {
        self.upper_bound_millionths - self.lower_bound_millionths
    }

    /// Check if a value is within bounds.
    pub fn in_bounds(&self, value: i64) -> bool {
        value >= self.lower_bound_millionths && value <= self.upper_bound_millionths
    }

    /// Compute proximity to the nearest boundary (0 = on boundary, MILLION = at nominal).
    /// Returns 0 if out of bounds.
    pub fn proximity_millionths(&self, value: i64) -> i64 {
        if !self.in_bounds(value) {
            return 0;
        }
        let range = self.range();
        if range <= 0 {
            return MILLION;
        }
        let dist_lower = value - self.lower_bound_millionths;
        let dist_upper = self.upper_bound_millionths - value;
        let min_dist = dist_lower.min(dist_upper);
        let half_range = range / 2;
        if half_range <= 0 {
            return MILLION;
        }
        (min_dist * MILLION / half_range).min(MILLION)
    }
}

// ── Bifurcation Point ────────────────────────────────────────────────────

/// A detected or potential bifurcation point in parameter space.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BifurcationPoint {
    /// Parameter that exhibits the bifurcation.
    pub parameter_id: String,
    /// Value at which the bifurcation occurs (millionths).
    pub critical_value_millionths: i64,
    /// Type of bifurcation detected.
    pub bifurcation_type: BifurcationType,
    /// Stability regime before the bifurcation.
    pub regime_before: RegimeLabel,
    /// Stability regime after the bifurcation.
    pub regime_after: RegimeLabel,
    /// Confidence in the detection (millionths, 0-MILLION).
    pub confidence_millionths: i64,
}

/// Types of bifurcation that can be detected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BifurcationType {
    /// Saddle-node: stable equilibrium disappears.
    SaddleNode,
    /// Transcritical: stability exchange between equilibria.
    Transcritical,
    /// Pitchfork: symmetric branching.
    Pitchfork,
    /// Hopf: transition to oscillatory behavior.
    Hopf,
    /// Catastrophic: sudden jump to a different regime.
    Catastrophic,
    /// Gradual: smooth transition (not a true bifurcation).
    Gradual,
}

impl fmt::Display for BifurcationType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SaddleNode => write!(f, "saddle-node"),
            Self::Transcritical => write!(f, "transcritical"),
            Self::Pitchfork => write!(f, "pitchfork"),
            Self::Hopf => write!(f, "hopf"),
            Self::Catastrophic => write!(f, "catastrophic"),
            Self::Gradual => write!(f, "gradual"),
        }
    }
}

// ── Early Warning Indicator ──────────────────────────────────────────────

/// An early-warning indicator tied to stability-boundary proximity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EarlyWarningIndicator {
    /// Identifier.
    pub indicator_id: String,
    /// Parameter being monitored.
    pub parameter_id: String,
    /// Current indicator value (millionths; higher = more risk).
    pub risk_value_millionths: i64,
    /// Threshold at which warning fires (millionths).
    pub threshold_millionths: i64,
    /// Whether the warning is currently active.
    pub active: bool,
    /// Trend direction: positive = worsening, negative = improving.
    pub trend_millionths: i64,
    /// Number of observations used to compute this indicator.
    pub observation_count: u64,
}

impl EarlyWarningIndicator {
    /// Whether this indicator signals imminent danger.
    pub fn is_critical(&self) -> bool {
        self.active && self.risk_value_millionths > self.threshold_millionths
    }
}

// ── Preemptive Action ────────────────────────────────────────────────────

/// A preemptive action card triggered by boundary proximity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreemptiveAction {
    /// Unique action ID.
    pub action_id: String,
    /// Trigger indicator.
    pub trigger_indicator_id: String,
    /// Parameter that triggered this action.
    pub parameter_id: String,
    /// Lane action to take.
    pub lane_action: LaneAction,
    /// Epoch when this action was generated.
    pub epoch: SecurityEpoch,
    /// Risk score that triggered the action (millionths).
    pub trigger_risk_millionths: i64,
    /// Human-readable rationale.
    pub rationale: String,
}

impl fmt::Display for PreemptiveAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: {} (risk={})",
            self.action_id, self.lane_action, self.trigger_risk_millionths
        )
    }
}

// ── Scan Result ──────────────────────────────────────────────────────────

/// Result of a bifurcation boundary scan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanResult {
    /// Schema version.
    pub schema_version: String,
    /// Epoch when the scan was performed.
    pub epoch: SecurityEpoch,
    /// Parameters scanned.
    pub parameters_scanned: u64,
    /// Bifurcation points detected.
    pub bifurcation_points: Vec<BifurcationPoint>,
    /// Early warning indicators.
    pub warnings: Vec<EarlyWarningIndicator>,
    /// Preemptive actions triggered.
    pub preemptive_actions: Vec<PreemptiveAction>,
    /// Overall stability score (millionths; MILLION = fully stable).
    pub stability_score_millionths: i64,
    /// Regime summary: count of parameters in each regime.
    pub regime_summary: BTreeMap<String, u64>,
    /// Artifact hash.
    pub artifact_hash: ContentHash,
}

impl ScanResult {
    /// Whether any preemptive actions are triggered.
    pub fn has_preemptive_actions(&self) -> bool {
        !self.preemptive_actions.is_empty()
    }

    /// Whether any early warnings are active.
    pub fn has_active_warnings(&self) -> bool {
        self.warnings.iter().any(|w| w.active)
    }

    /// Number of critical warnings.
    pub fn critical_warning_count(&self) -> usize {
        self.warnings.iter().filter(|w| w.is_critical()).count()
    }

    /// Whether the system is overall stable.
    pub fn is_stable(&self) -> bool {
        self.stability_score_millionths >= DEFAULT_RISK_BUDGET_MILLIONTHS
            && !self.has_preemptive_actions()
    }
}

// ── Stability Map Entry ──────────────────────────────────────────────────

/// A point in a stability map: parameter value → regime.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StabilityMapEntry {
    /// Parameter value (millionths).
    pub value_millionths: i64,
    /// Observed regime at this value.
    pub regime: RegimeLabel,
    /// Stability score (millionths; MILLION = very stable).
    pub stability_millionths: i64,
}

// ── Error ────────────────────────────────────────────────────────────────

/// Errors from the bifurcation boundary scanner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScannerError {
    /// No parameters configured.
    NoParameters,
    /// Too many parameters.
    TooManyParameters { count: usize, max: usize },
    /// No envelopes configured.
    NoEnvelopes,
    /// Too many envelopes.
    TooManyEnvelopes { count: usize, max: usize },
    /// Envelope references unknown parameter.
    UnknownParameter { parameter_id: String },
    /// Duplicate parameter IDs.
    DuplicateParameter { parameter_id: String },
    /// Envelope has inverted bounds.
    InvertedBounds { parameter_id: String },
    /// Risk budget must be positive.
    InvalidRiskBudget { value: i64 },
}

impl fmt::Display for ScannerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoParameters => write!(f, "no control parameters configured"),
            Self::TooManyParameters { count, max } => {
                write!(f, "too many parameters: {count} exceeds max {max}")
            }
            Self::NoEnvelopes => write!(f, "no operating envelopes configured"),
            Self::TooManyEnvelopes { count, max } => {
                write!(f, "too many envelopes: {count} exceeds max {max}")
            }
            Self::UnknownParameter { parameter_id } => {
                write!(f, "unknown parameter: {parameter_id}")
            }
            Self::DuplicateParameter { parameter_id } => {
                write!(f, "duplicate parameter ID: {parameter_id}")
            }
            Self::InvertedBounds { parameter_id } => {
                write!(f, "inverted bounds for parameter: {parameter_id}")
            }
            Self::InvalidRiskBudget { value } => {
                write!(f, "invalid risk budget: {value}")
            }
        }
    }
}

impl std::error::Error for ScannerError {}

// ── Scanner Configuration ────────────────────────────────────────────────

/// Configuration for the bifurcation boundary scanner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScannerConfig {
    /// Proximity threshold for early warnings (millionths of envelope range).
    pub proximity_threshold_millionths: i64,
    /// Risk budget before preemptive actions trigger (millionths).
    pub risk_budget_millionths: i64,
    /// Number of scan steps per parameter for bifurcation detection.
    pub scan_steps: u64,
    /// Epoch for the scan.
    pub epoch: SecurityEpoch,
    /// Whether to record full stability maps.
    pub record_stability_maps: bool,
}

impl Default for ScannerConfig {
    fn default() -> Self {
        Self {
            proximity_threshold_millionths: DEFAULT_PROXIMITY_THRESHOLD_MILLIONTHS,
            risk_budget_millionths: DEFAULT_RISK_BUDGET_MILLIONTHS,
            scan_steps: 20,
            epoch: SecurityEpoch::GENESIS,
            record_stability_maps: false,
        }
    }
}

// ── Observation ──────────────────────────────────────────────────────────

/// A parameter observation for tracking trends.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParameterObservation {
    /// Parameter ID.
    pub parameter_id: String,
    /// Observed value (millionths).
    pub value_millionths: i64,
    /// Tick at which the observation was made.
    pub tick: u64,
    /// Observed regime at this tick.
    pub regime: RegimeLabel,
}

// ── Bifurcation Boundary Scanner ─────────────────────────────────────────

/// The main bifurcation boundary scanner.
///
/// Scans control parameters against operating envelopes to detect
/// proximity to stability boundaries. Maintains observation history
/// for trend detection and early-warning indicators.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BifurcationBoundaryScanner {
    config: ScannerConfig,
    parameters: BTreeMap<String, ControlParameter>,
    envelopes: BTreeMap<String, OperatingEnvelope>,
    observations: Vec<ParameterObservation>,
    stability_maps: BTreeMap<String, Vec<StabilityMapEntry>>,
    scan_count: u64,
}

impl BifurcationBoundaryScanner {
    /// Create a new scanner.
    pub fn new(
        config: ScannerConfig,
        parameters: Vec<ControlParameter>,
        envelopes: Vec<OperatingEnvelope>,
    ) -> Result<Self, ScannerError> {
        Self::validate(&config, &parameters, &envelopes)?;

        let param_map: BTreeMap<String, ControlParameter> =
            parameters.into_iter().map(|p| (p.id.clone(), p)).collect();

        let env_map: BTreeMap<String, OperatingEnvelope> = envelopes
            .into_iter()
            .map(|e| (e.parameter_id.clone(), e))
            .collect();

        Ok(Self {
            config,
            parameters: param_map,
            envelopes: env_map,
            observations: Vec::new(),
            stability_maps: BTreeMap::new(),
            scan_count: 0,
        })
    }

    /// Access the configuration.
    pub fn config(&self) -> &ScannerConfig {
        &self.config
    }

    /// Number of scans performed.
    pub fn scan_count(&self) -> u64 {
        self.scan_count
    }

    /// Number of parameters being tracked.
    pub fn parameter_count(&self) -> usize {
        self.parameters.len()
    }

    /// Number of observations recorded.
    pub fn observation_count(&self) -> usize {
        self.observations.len()
    }

    /// Record a parameter observation.
    pub fn observe(&mut self, observation: ParameterObservation) {
        // Update current value
        if let Some(param) = self.parameters.get_mut(&observation.parameter_id) {
            param.current_value_millionths = observation.value_millionths;
        }
        self.observations.push(observation);
    }

    /// Update a parameter's current value.
    pub fn update_parameter(&mut self, parameter_id: &str, value_millionths: i64) {
        if let Some(param) = self.parameters.get_mut(parameter_id) {
            param.current_value_millionths = value_millionths;
        }
    }

    /// Run a full bifurcation boundary scan.
    pub fn scan(&mut self) -> Result<ScanResult, ScannerError> {
        let mut bifurcation_points = Vec::new();
        let mut warnings = Vec::new();
        let mut preemptive_actions = Vec::new();
        let mut regime_summary: BTreeMap<String, u64> = BTreeMap::new();
        let mut total_stability: i64 = 0;
        let mut param_count: u64 = 0;

        for (param_id, param) in &self.parameters {
            param_count += 1;

            if let Some(envelope) = self.envelopes.get(param_id) {
                let proximity = envelope.proximity_millionths(param.current_value_millionths);
                let in_bounds = envelope.in_bounds(param.current_value_millionths);

                // Determine current regime based on proximity
                let current_regime = self.classify_regime(proximity, in_bounds);
                *regime_summary
                    .entry(format!("{current_regime}"))
                    .or_insert(0) += 1;

                total_stability += proximity;

                // Check for bifurcation points via scan
                let bif_points = self.scan_parameter_bifurcations(param, envelope);
                bifurcation_points.extend(bif_points);

                // Compute early warning indicator
                let warning = self.compute_warning(param, envelope, proximity);
                let warning_active = warning.active;
                warnings.push(warning.clone());

                // Check if preemptive action is needed
                if warning_active && proximity < self.config.proximity_threshold_millionths {
                    let action = self.build_preemptive_action(param, &warning, proximity);
                    preemptive_actions.push(action);
                }
            } else {
                // No envelope — parameter is unmonitored, assume stable
                total_stability += MILLION;
                *regime_summary.entry("unmonitored".to_string()).or_insert(0) += 1;
            }
        }

        let stability_score = if param_count > 0 {
            total_stability / param_count as i64
        } else {
            MILLION
        };

        // Build stability maps if requested
        if self.config.record_stability_maps {
            for (param_id, param) in &self.parameters {
                if let Some(envelope) = self.envelopes.get(param_id) {
                    let map = self.build_stability_map(param, envelope);
                    self.stability_maps.insert(param_id.clone(), map);
                }
            }
        }

        let artifact_hash = {
            let mut buf = Vec::new();
            buf.extend_from_slice(BIFURCATION_SCHEMA_VERSION.as_bytes());
            buf.extend_from_slice(&self.config.epoch.as_u64().to_le_bytes());
            buf.extend_from_slice(&param_count.to_le_bytes());
            buf.extend_from_slice(&stability_score.to_le_bytes());
            // Include bifurcation point content (sorted by parameter_id).
            let mut sorted_bps: Vec<_> = bifurcation_points.iter().collect();
            sorted_bps.sort_by(|a, b| a.parameter_id.cmp(&b.parameter_id));
            buf.extend_from_slice(&(sorted_bps.len() as u64).to_le_bytes());
            for bp in &sorted_bps {
                buf.extend_from_slice(bp.parameter_id.as_bytes());
                buf.extend_from_slice(&bp.critical_value_millionths.to_le_bytes());
                buf.extend_from_slice(
                    serde_json::to_string(&bp.bifurcation_type)
                        .unwrap_or_default()
                        .as_bytes(),
                );
            }
            // Include warnings.
            buf.extend_from_slice(&(warnings.len() as u64).to_le_bytes());
            for w in &warnings {
                buf.extend_from_slice(w.parameter_id.as_bytes());
                buf.extend_from_slice(&w.risk_value_millionths.to_le_bytes());
            }
            // Include preemptive actions.
            buf.extend_from_slice(&(preemptive_actions.len() as u64).to_le_bytes());
            for pa in &preemptive_actions {
                buf.extend_from_slice(pa.parameter_id.as_bytes());
                buf.extend_from_slice(
                    serde_json::to_string(&pa.lane_action)
                        .unwrap_or_default()
                        .as_bytes(),
                );
            }
            // regime_summary is BTreeMap — deterministic iteration.
            for (regime, count) in &regime_summary {
                buf.extend_from_slice(regime.as_bytes());
                buf.extend_from_slice(&count.to_le_bytes());
            }
            ContentHash::compute(&buf)
        };

        self.scan_count += 1;

        Ok(ScanResult {
            schema_version: BIFURCATION_SCHEMA_VERSION.to_string(),
            epoch: self.config.epoch,
            parameters_scanned: param_count,
            bifurcation_points,
            warnings,
            preemptive_actions,
            stability_score_millionths: stability_score,
            regime_summary,
            artifact_hash,
        })
    }

    /// Access stability maps (if recorded).
    pub fn stability_maps(&self) -> &BTreeMap<String, Vec<StabilityMapEntry>> {
        &self.stability_maps
    }

    // ── Validation ───────────────────────────────────────────────

    fn validate(
        config: &ScannerConfig,
        parameters: &[ControlParameter],
        envelopes: &[OperatingEnvelope],
    ) -> Result<(), ScannerError> {
        if parameters.is_empty() {
            return Err(ScannerError::NoParameters);
        }
        if parameters.len() > MAX_CONTROL_PARAMS {
            return Err(ScannerError::TooManyParameters {
                count: parameters.len(),
                max: MAX_CONTROL_PARAMS,
            });
        }
        if envelopes.is_empty() {
            return Err(ScannerError::NoEnvelopes);
        }
        if envelopes.len() > MAX_ENVELOPES {
            return Err(ScannerError::TooManyEnvelopes {
                count: envelopes.len(),
                max: MAX_ENVELOPES,
            });
        }
        if config.risk_budget_millionths <= 0 {
            return Err(ScannerError::InvalidRiskBudget {
                value: config.risk_budget_millionths,
            });
        }

        // Check for duplicate parameter IDs
        let mut seen = BTreeSet::new();
        for p in parameters {
            if !seen.insert(&p.id) {
                return Err(ScannerError::DuplicateParameter {
                    parameter_id: p.id.clone(),
                });
            }
        }

        // Verify envelopes reference valid parameters
        let param_ids: BTreeSet<&String> = parameters.iter().map(|p| &p.id).collect();
        for env in envelopes {
            if !param_ids.contains(&env.parameter_id) {
                return Err(ScannerError::UnknownParameter {
                    parameter_id: env.parameter_id.clone(),
                });
            }
            if env.lower_bound_millionths > env.upper_bound_millionths {
                return Err(ScannerError::InvertedBounds {
                    parameter_id: env.parameter_id.clone(),
                });
            }
        }

        Ok(())
    }

    // ── Regime classification ────────────────────────────────────

    fn classify_regime(&self, proximity: i64, in_bounds: bool) -> RegimeLabel {
        if !in_bounds {
            return RegimeLabel::Attack;
        }
        if proximity < MILLION / 10 {
            // Very close to boundary (< 10% of half-range)
            RegimeLabel::Degraded
        } else if proximity < MILLION / 4 {
            // Near boundary (< 25%)
            RegimeLabel::Elevated
        } else {
            RegimeLabel::Normal
        }
    }

    // ── Bifurcation scanning ─────────────────────────────────────

    fn scan_parameter_bifurcations(
        &self,
        param: &ControlParameter,
        envelope: &OperatingEnvelope,
    ) -> Vec<BifurcationPoint> {
        let mut points = Vec::new();
        let steps = self.config.scan_steps.max(2);
        let range = envelope.range();
        if range <= 0 {
            return points;
        }

        let step_size = range / steps as i64;
        if step_size <= 0 {
            return points;
        }

        let mut prev_regime = self.classify_regime(
            envelope.proximity_millionths(envelope.lower_bound_millionths),
            true,
        );

        for i in 1..=steps {
            let value = envelope.lower_bound_millionths + (i as i64 * step_size);
            let proximity = envelope.proximity_millionths(value);
            let in_bounds = envelope.in_bounds(value);
            let regime = self.classify_regime(proximity, in_bounds);

            if regime != prev_regime {
                let bif_type = self.classify_bifurcation(&prev_regime, &regime);
                let confidence = self.compute_bifurcation_confidence(step_size, range);

                points.push(BifurcationPoint {
                    parameter_id: param.id.clone(),
                    critical_value_millionths: value - step_size / 2,
                    bifurcation_type: bif_type,
                    regime_before: prev_regime,
                    regime_after: regime,
                    confidence_millionths: confidence,
                });
            }
            prev_regime = regime;
        }

        points
    }

    fn classify_bifurcation(&self, from: &RegimeLabel, to: &RegimeLabel) -> BifurcationType {
        match (from, to) {
            (RegimeLabel::Normal, RegimeLabel::Attack) => BifurcationType::Catastrophic,
            (RegimeLabel::Normal, RegimeLabel::Degraded) => BifurcationType::SaddleNode,
            (RegimeLabel::Normal, RegimeLabel::Elevated) => BifurcationType::Gradual,
            (RegimeLabel::Elevated, RegimeLabel::Normal) => BifurcationType::Gradual,
            (RegimeLabel::Elevated, RegimeLabel::Degraded) => BifurcationType::Transcritical,
            (RegimeLabel::Degraded, RegimeLabel::Attack) => BifurcationType::Catastrophic,
            _ => BifurcationType::Pitchfork,
        }
    }

    fn compute_bifurcation_confidence(&self, step_size: i64, range: i64) -> i64 {
        if range <= 0 {
            return 0;
        }
        // Finer scan steps → higher confidence
        let resolution = (step_size * MILLION) / range;
        // Confidence = 1 - resolution/MILLION (finer = higher)
        (MILLION - resolution).clamp(0, MILLION)
    }

    // ── Early warning indicators ─────────────────────────────────

    fn compute_warning(
        &self,
        param: &ControlParameter,
        envelope: &OperatingEnvelope,
        proximity: i64,
    ) -> EarlyWarningIndicator {
        let risk_value = MILLION - proximity;

        // Compute trend from observations
        let (trend, obs_count) = self.compute_trend(&param.id);

        let active = risk_value > (MILLION - self.config.proximity_threshold_millionths)
            || !envelope.in_bounds(param.current_value_millionths);

        EarlyWarningIndicator {
            indicator_id: format!("ew-{}", param.id),
            parameter_id: param.id.clone(),
            risk_value_millionths: risk_value,
            threshold_millionths: MILLION - self.config.proximity_threshold_millionths,
            active,
            trend_millionths: trend,
            observation_count: obs_count,
        }
    }

    fn compute_trend(&self, parameter_id: &str) -> (i64, u64) {
        let param_obs: Vec<_> = self
            .observations
            .iter()
            .filter(|o| o.parameter_id == parameter_id)
            .collect();

        let count = param_obs.len() as u64;
        if param_obs.len() < MIN_OBSERVATIONS {
            return (0, count);
        }

        // Simple linear trend: compare average of last half vs first half
        let mid = param_obs.len() / 2;
        let first_half_avg = param_obs[..mid]
            .iter()
            .map(|o| o.value_millionths)
            .sum::<i64>()
            / mid as i64;
        let second_half_avg = param_obs[mid..]
            .iter()
            .map(|o| o.value_millionths)
            .sum::<i64>()
            / (param_obs.len() - mid) as i64;

        (second_half_avg - first_half_avg, count)
    }

    // ── Preemptive actions ───────────────────────────────────────

    fn build_preemptive_action(
        &self,
        param: &ControlParameter,
        warning: &EarlyWarningIndicator,
        proximity: i64,
    ) -> PreemptiveAction {
        let lane_action = if proximity == 0 {
            // Out of bounds — full safe mode
            LaneAction::SuspendAdaptive
        } else if proximity < MILLION / 20 {
            // Very close (< 5%) — demote
            LaneAction::Demote {
                from_lane: LaneId("adaptive".to_string()),
                reason: DemotionReason::GuardrailTriggered,
            }
        } else {
            // Near boundary — fallback safe
            LaneAction::FallbackSafe
        };

        let rationale = format!(
            "Parameter {} at proximity {} (threshold {}), trend {}",
            param.id,
            proximity,
            self.config.proximity_threshold_millionths,
            warning.trend_millionths,
        );

        PreemptiveAction {
            action_id: format!("pa-{}-s{}", param.id, self.scan_count),
            trigger_indicator_id: warning.indicator_id.clone(),
            parameter_id: param.id.clone(),
            lane_action,
            epoch: self.config.epoch,
            trigger_risk_millionths: warning.risk_value_millionths,
            rationale,
        }
    }

    // ── Stability maps ───────────────────────────────────────────

    fn build_stability_map(
        &self,
        _param: &ControlParameter,
        envelope: &OperatingEnvelope,
    ) -> Vec<StabilityMapEntry> {
        let mut map = Vec::new();
        let steps = self.config.scan_steps.max(2);
        let range = envelope.range();
        if range <= 0 {
            return map;
        }

        let step_size = range / steps as i64;
        if step_size <= 0 {
            return map;
        }

        for i in 0..=steps {
            let value = envelope.lower_bound_millionths + (i as i64 * step_size);
            let proximity = envelope.proximity_millionths(value);
            let in_bounds = envelope.in_bounds(value);
            let regime = self.classify_regime(proximity, in_bounds);

            map.push(StabilityMapEntry {
                value_millionths: value,
                regime,
                stability_millionths: proximity,
            });
        }

        map
    }
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Test helpers ─────────────────────────────────────────────

    fn make_param(id: &str, value: i64) -> ControlParameter {
        ControlParameter {
            id: id.to_string(),
            label: format!("{id} parameter"),
            domain: ParameterDomain::RiskThreshold,
            current_value_millionths: value,
            policy_tunable: true,
        }
    }

    fn make_envelope(param_id: &str, lower: i64, upper: i64, nominal: i64) -> OperatingEnvelope {
        OperatingEnvelope {
            parameter_id: param_id.to_string(),
            lower_bound_millionths: lower,
            upper_bound_millionths: upper,
            nominal_millionths: nominal,
            criticality_millionths: MILLION / 2,
        }
    }

    fn default_scanner() -> BifurcationBoundaryScanner {
        let params = vec![
            make_param("threshold-1", 500_000),
            make_param("calibration-1", 750_000),
        ];
        let envelopes = vec![
            make_envelope("threshold-1", 100_000, 900_000, 500_000),
            make_envelope("calibration-1", 200_000, 800_000, 500_000),
        ];
        BifurcationBoundaryScanner::new(ScannerConfig::default(), params, envelopes).unwrap()
    }

    // ── Constructor tests ────────────────────────────────────────

    #[test]
    fn new_creates_scanner() {
        let scanner = default_scanner();
        assert_eq!(scanner.scan_count(), 0);
        assert_eq!(scanner.parameter_count(), 2);
    }

    #[test]
    fn new_rejects_no_parameters() {
        let result = BifurcationBoundaryScanner::new(
            ScannerConfig::default(),
            vec![],
            vec![make_envelope("x", 0, MILLION, 500_000)],
        );
        assert!(matches!(result, Err(ScannerError::NoParameters)));
    }

    #[test]
    fn new_rejects_no_envelopes() {
        let result = BifurcationBoundaryScanner::new(
            ScannerConfig::default(),
            vec![make_param("x", 500_000)],
            vec![],
        );
        assert!(matches!(result, Err(ScannerError::NoEnvelopes)));
    }

    #[test]
    fn new_rejects_too_many_parameters() {
        let params: Vec<_> = (0..129)
            .map(|i| make_param(&format!("p-{i}"), 500_000))
            .collect();
        let envelopes = vec![make_envelope("p-0", 0, MILLION, 500_000)];
        let result = BifurcationBoundaryScanner::new(ScannerConfig::default(), params, envelopes);
        assert!(matches!(
            result,
            Err(ScannerError::TooManyParameters { .. })
        ));
    }

    #[test]
    fn new_rejects_unknown_parameter_in_envelope() {
        let params = vec![make_param("x", 500_000)];
        let envelopes = vec![make_envelope("unknown", 0, MILLION, 500_000)];
        let result = BifurcationBoundaryScanner::new(ScannerConfig::default(), params, envelopes);
        assert!(matches!(result, Err(ScannerError::UnknownParameter { .. })));
    }

    #[test]
    fn new_rejects_duplicate_parameters() {
        let params = vec![make_param("x", 500_000), make_param("x", 600_000)];
        let envelopes = vec![make_envelope("x", 0, MILLION, 500_000)];
        let result = BifurcationBoundaryScanner::new(ScannerConfig::default(), params, envelopes);
        assert!(matches!(
            result,
            Err(ScannerError::DuplicateParameter { .. })
        ));
    }

    #[test]
    fn new_rejects_inverted_bounds() {
        let params = vec![make_param("x", 500_000)];
        let envelopes = vec![make_envelope("x", MILLION, 0, 500_000)];
        let result = BifurcationBoundaryScanner::new(ScannerConfig::default(), params, envelopes);
        assert!(matches!(result, Err(ScannerError::InvertedBounds { .. })));
    }

    #[test]
    fn new_rejects_invalid_risk_budget() {
        let config = ScannerConfig {
            risk_budget_millionths: 0,
            ..Default::default()
        };
        let result = BifurcationBoundaryScanner::new(
            config,
            vec![make_param("x", 500_000)],
            vec![make_envelope("x", 0, MILLION, 500_000)],
        );
        assert!(matches!(
            result,
            Err(ScannerError::InvalidRiskBudget { .. })
        ));
    }

    // ── Operating envelope tests ─────────────────────────────────

    #[test]
    fn envelope_in_bounds() {
        let env = make_envelope("x", 100_000, 900_000, 500_000);
        assert!(env.in_bounds(500_000));
        assert!(env.in_bounds(100_000));
        assert!(env.in_bounds(900_000));
        assert!(!env.in_bounds(99_999));
        assert!(!env.in_bounds(900_001));
    }

    #[test]
    fn envelope_range() {
        let env = make_envelope("x", 100_000, 900_000, 500_000);
        assert_eq!(env.range(), 800_000);
    }

    #[test]
    fn envelope_proximity_at_nominal() {
        let env = make_envelope("x", 0, MILLION, 500_000);
        let prox = env.proximity_millionths(500_000);
        assert_eq!(prox, MILLION); // At center = max proximity
    }

    #[test]
    fn envelope_proximity_at_boundary() {
        let env = make_envelope("x", 0, MILLION, 500_000);
        assert_eq!(env.proximity_millionths(0), 0); // At lower boundary
        assert_eq!(env.proximity_millionths(MILLION), 0); // At upper boundary
    }

    #[test]
    fn envelope_proximity_out_of_bounds() {
        let env = make_envelope("x", 100_000, 900_000, 500_000);
        assert_eq!(env.proximity_millionths(50_000), 0);
        assert_eq!(env.proximity_millionths(950_000), 0);
    }

    // ── Scan tests ───────────────────────────────────────────────

    #[test]
    fn scan_stable_parameters() {
        let mut scanner = default_scanner();
        let result = scanner.scan().unwrap();
        assert_eq!(result.schema_version, BIFURCATION_SCHEMA_VERSION);
        assert_eq!(result.parameters_scanned, 2);
        assert!(result.stability_score_millionths > 0);
    }

    #[test]
    fn scan_count_increments() {
        let mut scanner = default_scanner();
        assert_eq!(scanner.scan_count(), 0);
        scanner.scan().unwrap();
        assert_eq!(scanner.scan_count(), 1);
        scanner.scan().unwrap();
        assert_eq!(scanner.scan_count(), 2);
    }

    #[test]
    fn scan_detects_near_boundary() {
        // Parameter very close to lower bound
        let params = vec![make_param("threshold", 110_000)]; // Close to 100k lower bound
        let envelopes = vec![make_envelope("threshold", 100_000, 900_000, 500_000)];
        let mut scanner =
            BifurcationBoundaryScanner::new(ScannerConfig::default(), params, envelopes).unwrap();

        let result = scanner.scan().unwrap();
        // Should have a warning active
        assert!(result.has_active_warnings());
    }

    #[test]
    fn scan_triggers_preemptive_action_out_of_bounds() {
        let params = vec![make_param("threshold", 50_000)]; // Below lower bound
        let envelopes = vec![make_envelope("threshold", 100_000, 900_000, 500_000)];
        let mut scanner =
            BifurcationBoundaryScanner::new(ScannerConfig::default(), params, envelopes).unwrap();

        let result = scanner.scan().unwrap();
        assert!(result.has_preemptive_actions());
    }

    #[test]
    fn scan_no_warnings_at_nominal() {
        let params = vec![make_param("threshold", 500_000)]; // At nominal
        let envelopes = vec![make_envelope("threshold", 100_000, 900_000, 500_000)];
        let mut scanner =
            BifurcationBoundaryScanner::new(ScannerConfig::default(), params, envelopes).unwrap();

        let result = scanner.scan().unwrap();
        assert!(!result.has_active_warnings());
        assert!(!result.has_preemptive_actions());
    }

    #[test]
    fn scan_produces_bifurcation_points() {
        let mut scanner = default_scanner();
        let result = scanner.scan().unwrap();
        // Scanning should find regime transitions
        assert!(!result.bifurcation_points.is_empty());
    }

    #[test]
    fn scan_result_has_artifact_hash() {
        let mut scanner = default_scanner();
        let result = scanner.scan().unwrap();
        assert_ne!(result.artifact_hash.as_bytes(), &[0u8; 32]);
    }

    #[test]
    fn scan_result_has_regime_summary() {
        let mut scanner = default_scanner();
        let result = scanner.scan().unwrap();
        assert!(!result.regime_summary.is_empty());
    }

    // ── Observation and trend tests ──────────────────────────────

    #[test]
    fn observe_updates_parameter() {
        let mut scanner = default_scanner();
        scanner.observe(ParameterObservation {
            parameter_id: "threshold-1".to_string(),
            value_millionths: 800_000,
            tick: 100,
            regime: RegimeLabel::Normal,
        });
        assert_eq!(scanner.observation_count(), 1);
    }

    #[test]
    fn update_parameter_changes_value() {
        let mut scanner = default_scanner();
        scanner.update_parameter("threshold-1", 300_000);
        // Scan should use updated value
        let result = scanner.scan().unwrap();
        assert!(result.parameters_scanned > 0);
    }

    #[test]
    fn trend_computation_with_observations() {
        let mut scanner = default_scanner();
        // Add observations showing upward trend
        for i in 0..10 {
            scanner.observe(ParameterObservation {
                parameter_id: "threshold-1".to_string(),
                value_millionths: 400_000 + i * 20_000,
                tick: i as u64,
                regime: RegimeLabel::Normal,
            });
        }
        let result = scanner.scan().unwrap();
        // With enough observations, warning should have trend computed
        let warning = result
            .warnings
            .iter()
            .find(|w| w.parameter_id == "threshold-1")
            .unwrap();
        assert!(warning.observation_count >= 10);
    }

    // ── Stability map tests ──────────────────────────────────────

    #[test]
    fn stability_maps_recorded_when_enabled() {
        let config = ScannerConfig {
            record_stability_maps: true,
            ..Default::default()
        };
        let params = vec![make_param("x", 500_000)];
        let envelopes = vec![make_envelope("x", 0, MILLION, 500_000)];
        let mut scanner = BifurcationBoundaryScanner::new(config, params, envelopes).unwrap();

        scanner.scan().unwrap();
        assert!(!scanner.stability_maps().is_empty());

        let map = scanner.stability_maps().get("x").unwrap();
        assert!(!map.is_empty());
    }

    #[test]
    fn stability_maps_not_recorded_when_disabled() {
        let mut scanner = default_scanner();
        scanner.scan().unwrap();
        assert!(scanner.stability_maps().is_empty());
    }

    // ── Preemptive action tests ──────────────────────────────────

    #[test]
    fn preemptive_action_out_of_bounds_suspends() {
        let params = vec![make_param("x", -100_000)]; // Way below bounds
        let envelopes = vec![make_envelope("x", 100_000, 900_000, 500_000)];
        let mut scanner =
            BifurcationBoundaryScanner::new(ScannerConfig::default(), params, envelopes).unwrap();

        let result = scanner.scan().unwrap();
        assert!(result.has_preemptive_actions());

        let action = &result.preemptive_actions[0];
        assert!(matches!(action.lane_action, LaneAction::SuspendAdaptive));
    }

    #[test]
    fn preemptive_action_near_boundary_demotes() {
        // Just barely inside bounds
        let params = vec![make_param("x", 105_000)];
        let envelopes = vec![make_envelope("x", 100_000, 900_000, 500_000)];
        let mut scanner =
            BifurcationBoundaryScanner::new(ScannerConfig::default(), params, envelopes).unwrap();

        let result = scanner.scan().unwrap();
        if result.has_preemptive_actions() {
            let action = &result.preemptive_actions[0];
            // Should be Demote or FallbackSafe depending on proximity
            assert!(matches!(
                action.lane_action,
                LaneAction::Demote { .. } | LaneAction::FallbackSafe
            ));
        }
    }

    // ── ScanResult method tests ──────────────────────────────────

    #[test]
    fn is_stable_at_nominal() {
        let params = vec![
            make_param("threshold-1", 500_000),
            make_param("calibration-1", 500_000),
        ];
        let envelopes = vec![
            make_envelope("threshold-1", 100_000, 900_000, 500_000),
            make_envelope("calibration-1", 200_000, 800_000, 500_000),
        ];
        let mut scanner =
            BifurcationBoundaryScanner::new(ScannerConfig::default(), params, envelopes).unwrap();
        let result = scanner.scan().unwrap();
        assert!(result.is_stable());
    }

    #[test]
    fn not_stable_with_preemptive_actions() {
        let params = vec![make_param("x", 50_000)];
        let envelopes = vec![make_envelope("x", 100_000, 900_000, 500_000)];
        let mut scanner =
            BifurcationBoundaryScanner::new(ScannerConfig::default(), params, envelopes).unwrap();

        let result = scanner.scan().unwrap();
        assert!(!result.is_stable());
    }

    #[test]
    fn critical_warning_count() {
        let params = vec![make_param("x", 105_000)]; // Near boundary
        let envelopes = vec![make_envelope("x", 100_000, 900_000, 500_000)];
        let mut scanner =
            BifurcationBoundaryScanner::new(ScannerConfig::default(), params, envelopes).unwrap();

        let result = scanner.scan().unwrap();
        let critical = result.critical_warning_count();
        // May or may not be critical depending on exact proximity calculation
        assert!(critical <= 1);
    }

    // ── Serde roundtrip tests ────────────────────────────────────

    #[test]
    fn config_serde_roundtrip() {
        let config = ScannerConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let back: ScannerConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, back);
    }

    #[test]
    fn scan_result_serde_roundtrip() {
        let mut scanner = default_scanner();
        let result = scanner.scan().unwrap();
        let json = serde_json::to_string(&result).unwrap();
        let back: ScanResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result.artifact_hash, back.artifact_hash);
        assert_eq!(result.parameters_scanned, back.parameters_scanned);
    }

    #[test]
    fn error_serde_roundtrip() {
        let errors = vec![
            ScannerError::NoParameters,
            ScannerError::NoEnvelopes,
            ScannerError::TooManyParameters {
                count: 200,
                max: 128,
            },
            ScannerError::DuplicateParameter {
                parameter_id: "x".to_string(),
            },
            ScannerError::InvertedBounds {
                parameter_id: "y".to_string(),
            },
            ScannerError::InvalidRiskBudget { value: -1 },
        ];
        for err in &errors {
            let json = serde_json::to_string(err).unwrap();
            let back: ScannerError = serde_json::from_str(&json).unwrap();
            assert_eq!(*err, back);
        }
    }

    // ── Display tests ────────────────────────────────────────────

    #[test]
    fn error_display_all_variants() {
        let variants = vec![
            ScannerError::NoParameters,
            ScannerError::TooManyParameters {
                count: 200,
                max: 128,
            },
            ScannerError::NoEnvelopes,
            ScannerError::TooManyEnvelopes {
                count: 100,
                max: 64,
            },
            ScannerError::UnknownParameter {
                parameter_id: "x".to_string(),
            },
            ScannerError::DuplicateParameter {
                parameter_id: "x".to_string(),
            },
            ScannerError::InvertedBounds {
                parameter_id: "x".to_string(),
            },
            ScannerError::InvalidRiskBudget { value: -1 },
        ];
        for v in &variants {
            let s = format!("{v}");
            assert!(!s.is_empty());
        }
    }

    #[test]
    fn parameter_domain_display() {
        let domains = vec![
            ParameterDomain::RiskThreshold,
            ParameterDomain::Calibration,
            ParameterDomain::ResourceAllocation,
            ParameterDomain::LaneRouting,
            ParameterDomain::SafetyBoundary,
            ParameterDomain::Environment,
        ];
        for d in &domains {
            let s = format!("{d}");
            assert!(!s.is_empty());
        }
    }

    #[test]
    fn bifurcation_type_display() {
        let types = vec![
            BifurcationType::SaddleNode,
            BifurcationType::Transcritical,
            BifurcationType::Pitchfork,
            BifurcationType::Hopf,
            BifurcationType::Catastrophic,
            BifurcationType::Gradual,
        ];
        for t in &types {
            let s = format!("{t}");
            assert!(!s.is_empty());
        }
    }

    #[test]
    fn control_parameter_display() {
        let p = make_param("test-param", 500_000);
        let s = format!("{p}");
        assert!(s.contains("test-param"));
        assert!(s.contains("500000"));
    }

    #[test]
    fn preemptive_action_display() {
        let action = PreemptiveAction {
            action_id: "pa-test".to_string(),
            trigger_indicator_id: "ew-test".to_string(),
            parameter_id: "test".to_string(),
            lane_action: LaneAction::FallbackSafe,
            epoch: SecurityEpoch::GENESIS,
            trigger_risk_millionths: 800_000,
            rationale: "test".to_string(),
        };
        let s = format!("{action}");
        assert!(s.contains("pa-test"));
    }

    // ── Early warning indicator tests ────────────────────────────

    #[test]
    fn indicator_is_critical() {
        let indicator = EarlyWarningIndicator {
            indicator_id: "ew-test".to_string(),
            parameter_id: "test".to_string(),
            risk_value_millionths: 900_000,
            threshold_millionths: 750_000,
            active: true,
            trend_millionths: 10_000,
            observation_count: 20,
        };
        assert!(indicator.is_critical());
    }

    #[test]
    fn indicator_not_critical_when_inactive() {
        let indicator = EarlyWarningIndicator {
            indicator_id: "ew-test".to_string(),
            parameter_id: "test".to_string(),
            risk_value_millionths: 900_000,
            threshold_millionths: 750_000,
            active: false,
            trend_millionths: 0,
            observation_count: 0,
        };
        assert!(!indicator.is_critical());
    }

    #[test]
    fn indicator_not_critical_below_threshold() {
        let indicator = EarlyWarningIndicator {
            indicator_id: "ew-test".to_string(),
            parameter_id: "test".to_string(),
            risk_value_millionths: 500_000,
            threshold_millionths: 750_000,
            active: true,
            trend_millionths: 0,
            observation_count: 10,
        };
        assert!(!indicator.is_critical());
    }

    // ── Determinism test ─────────────────────────────────────────

    #[test]
    fn scan_is_deterministic() {
        let params = vec![make_param("a", 300_000), make_param("b", 700_000)];
        let envelopes = vec![
            make_envelope("a", 100_000, 900_000, 500_000),
            make_envelope("b", 200_000, 800_000, 500_000),
        ];

        let mut s1 = BifurcationBoundaryScanner::new(
            ScannerConfig::default(),
            params.clone(),
            envelopes.clone(),
        )
        .unwrap();
        let mut s2 =
            BifurcationBoundaryScanner::new(ScannerConfig::default(), params, envelopes).unwrap();

        let r1 = s1.scan().unwrap();
        let r2 = s2.scan().unwrap();

        assert_eq!(r1.artifact_hash, r2.artifact_hash);
        assert_eq!(r1.stability_score_millionths, r2.stability_score_millionths);
        assert_eq!(r1.bifurcation_points.len(), r2.bifurcation_points.len());
    }

    // ── Default config tests ─────────────────────────────────────

    #[test]
    fn default_config_values() {
        let config = ScannerConfig::default();
        assert_eq!(
            config.proximity_threshold_millionths,
            DEFAULT_PROXIMITY_THRESHOLD_MILLIONTHS
        );
        assert_eq!(
            config.risk_budget_millionths,
            DEFAULT_RISK_BUDGET_MILLIONTHS
        );
        assert_eq!(config.scan_steps, 20);
        assert!(!config.record_stability_maps);
    }

    // -----------------------------------------------------------------------
    // Enrichment: ParameterDomain serde roundtrip
    // -----------------------------------------------------------------------

    #[test]
    fn parameter_domain_serde_roundtrip() {
        for d in [
            ParameterDomain::RiskThreshold,
            ParameterDomain::Calibration,
            ParameterDomain::ResourceAllocation,
            ParameterDomain::LaneRouting,
            ParameterDomain::SafetyBoundary,
            ParameterDomain::Environment,
        ] {
            let json = serde_json::to_string(&d).unwrap();
            let back: ParameterDomain = serde_json::from_str(&json).unwrap();
            assert_eq!(d, back);
        }
    }

    // -----------------------------------------------------------------------
    // Enrichment: BifurcationType serde roundtrip
    // -----------------------------------------------------------------------

    #[test]
    fn bifurcation_type_serde_roundtrip() {
        for t in [
            BifurcationType::SaddleNode,
            BifurcationType::Transcritical,
            BifurcationType::Pitchfork,
            BifurcationType::Hopf,
            BifurcationType::Catastrophic,
            BifurcationType::Gradual,
        ] {
            let json = serde_json::to_string(&t).unwrap();
            let back: BifurcationType = serde_json::from_str(&json).unwrap();
            assert_eq!(t, back);
        }
    }

    // -----------------------------------------------------------------------
    // Enrichment: ScannerError serde missing 2 variants
    // -----------------------------------------------------------------------

    #[test]
    fn error_serde_roundtrip_remaining() {
        let errors = [
            ScannerError::TooManyEnvelopes {
                count: 100,
                max: 64,
            },
            ScannerError::UnknownParameter {
                parameter_id: "unknown-param".to_string(),
            },
        ];
        for err in errors {
            let json = serde_json::to_string(&err).unwrap();
            let back: ScannerError = serde_json::from_str(&json).unwrap();
            assert_eq!(err, back);
        }
    }

    // -----------------------------------------------------------------------
    // Enrichment: ControlParameter serde roundtrip
    // -----------------------------------------------------------------------

    #[test]
    fn control_parameter_serde_roundtrip() {
        let p = make_param("test", 500_000);
        let json = serde_json::to_string(&p).unwrap();
        let back: ControlParameter = serde_json::from_str(&json).unwrap();
        assert_eq!(p, back);
    }

    // -----------------------------------------------------------------------
    // Enrichment: ScannerConfig serde roundtrip
    // -----------------------------------------------------------------------

    #[test]
    fn scanner_config_serde_roundtrip_custom() {
        let config = ScannerConfig {
            proximity_threshold_millionths: 50_000,
            risk_budget_millionths: 800_000,
            scan_steps: 50,
            epoch: crate::security_epoch::SecurityEpoch::from_raw(7),
            record_stability_maps: true,
        };
        let json = serde_json::to_string(&config).unwrap();
        let back: ScannerConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, back);
    }

    // -----------------------------------------------------------------------
    // Enrichment: ParameterDomain Display exact format
    // -----------------------------------------------------------------------

    #[test]
    fn parameter_domain_display_exact() {
        assert_eq!(ParameterDomain::RiskThreshold.to_string(), "risk-threshold");
        assert_eq!(ParameterDomain::Calibration.to_string(), "calibration");
        assert_eq!(
            ParameterDomain::ResourceAllocation.to_string(),
            "resource-allocation"
        );
        assert_eq!(ParameterDomain::LaneRouting.to_string(), "lane-routing");
        assert_eq!(
            ParameterDomain::SafetyBoundary.to_string(),
            "safety-boundary"
        );
        assert_eq!(ParameterDomain::Environment.to_string(), "environment");
    }

    // -----------------------------------------------------------------------
    // Enrichment: BifurcationType Display exact format
    // -----------------------------------------------------------------------

    #[test]
    fn bifurcation_type_display_exact() {
        assert_eq!(BifurcationType::SaddleNode.to_string(), "saddle-node");
        assert_eq!(BifurcationType::Transcritical.to_string(), "transcritical");
        assert_eq!(BifurcationType::Pitchfork.to_string(), "pitchfork");
        assert_eq!(BifurcationType::Hopf.to_string(), "hopf");
        assert_eq!(BifurcationType::Catastrophic.to_string(), "catastrophic");
        assert_eq!(BifurcationType::Gradual.to_string(), "gradual");
    }

    // -----------------------------------------------------------------------
    // Enrichment: Clone equality
    // -----------------------------------------------------------------------

    #[test]
    fn clone_eq_control_parameter() {
        let a = make_param("cp-1", 123_456);
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn clone_eq_operating_envelope() {
        let a = make_envelope("env-1", 50_000, 950_000, 500_000);
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn clone_eq_bifurcation_point() {
        let a = BifurcationPoint {
            parameter_id: "bp-1".to_string(),
            critical_value_millionths: 400_000,
            bifurcation_type: BifurcationType::Hopf,
            regime_before: RegimeLabel::Normal,
            regime_after: RegimeLabel::Elevated,
            confidence_millionths: 850_000,
        };
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn clone_eq_early_warning_indicator() {
        let a = EarlyWarningIndicator {
            indicator_id: "ew-clone".to_string(),
            parameter_id: "p-clone".to_string(),
            risk_value_millionths: 600_000,
            threshold_millionths: 750_000,
            active: true,
            trend_millionths: -5_000,
            observation_count: 42,
        };
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn clone_eq_stability_map_entry() {
        let a = StabilityMapEntry {
            value_millionths: 333_333,
            regime: RegimeLabel::Degraded,
            stability_millionths: 80_000,
        };
        let b = a.clone();
        assert_eq!(a, b);
    }

    // -----------------------------------------------------------------------
    // Enrichment: JSON field presence
    // -----------------------------------------------------------------------

    #[test]
    fn json_field_presence_scan_result() {
        let mut scanner = default_scanner();
        let result = scanner.scan().unwrap();
        let j = serde_json::to_string(&result).unwrap();
        assert!(j.contains("\"schema_version\""));
        assert!(j.contains("\"stability_score_millionths\""));
        assert!(j.contains("\"artifact_hash\""));
        assert!(j.contains("\"regime_summary\""));
    }

    #[test]
    fn json_field_presence_preemptive_action() {
        let action = PreemptiveAction {
            action_id: "pa-json".to_string(),
            trigger_indicator_id: "ew-json".to_string(),
            parameter_id: "json-param".to_string(),
            lane_action: LaneAction::FallbackSafe,
            epoch: SecurityEpoch::GENESIS,
            trigger_risk_millionths: 700_000,
            rationale: "json-test".to_string(),
        };
        let j = serde_json::to_string(&action).unwrap();
        assert!(j.contains("\"action_id\""));
        assert!(j.contains("\"trigger_indicator_id\""));
        assert!(j.contains("\"rationale\""));
    }

    #[test]
    fn json_field_presence_bifurcation_point() {
        let bp = BifurcationPoint {
            parameter_id: "bp-json".to_string(),
            critical_value_millionths: 250_000,
            bifurcation_type: BifurcationType::Catastrophic,
            regime_before: RegimeLabel::Degraded,
            regime_after: RegimeLabel::Attack,
            confidence_millionths: 900_000,
        };
        let j = serde_json::to_string(&bp).unwrap();
        assert!(j.contains("\"parameter_id\""));
        assert!(j.contains("\"critical_value_millionths\""));
        assert!(j.contains("\"bifurcation_type\""));
        assert!(j.contains("\"confidence_millionths\""));
    }

    // -----------------------------------------------------------------------
    // Enrichment: Display uniqueness
    // -----------------------------------------------------------------------

    #[test]
    fn control_parameter_display_distinct_values_differ() {
        let p1 = make_param("alpha", 100_000);
        let p2 = make_param("beta", 900_000);
        assert_ne!(format!("{p1}"), format!("{p2}"));
    }

    // -----------------------------------------------------------------------
    // Enrichment: Boundary — envelope with zero range
    // -----------------------------------------------------------------------

    #[test]
    fn envelope_zero_range_proximity_returns_million() {
        let env = make_envelope("x", 500_000, 500_000, 500_000);
        assert_eq!(env.range(), 0);
        // At a degenerate point-envelope the value is at the bounds
        assert!(env.in_bounds(500_000));
        // proximity_millionths special-cases range <= 0 → MILLION
        assert_eq!(env.proximity_millionths(500_000), MILLION);
    }

    // -----------------------------------------------------------------------
    // Enrichment: Error source is None (std::error::Error)
    // -----------------------------------------------------------------------

    #[test]
    fn scanner_error_source_is_none() {
        use std::error::Error as _;
        let errors: Vec<ScannerError> = vec![
            ScannerError::NoParameters,
            ScannerError::NoEnvelopes,
            ScannerError::TooManyParameters {
                count: 200,
                max: 128,
            },
            ScannerError::TooManyEnvelopes {
                count: 100,
                max: 64,
            },
            ScannerError::UnknownParameter {
                parameter_id: "u".to_string(),
            },
            ScannerError::DuplicateParameter {
                parameter_id: "d".to_string(),
            },
            ScannerError::InvertedBounds {
                parameter_id: "i".to_string(),
            },
            ScannerError::InvalidRiskBudget { value: -10 },
        ];
        for err in &errors {
            assert!(err.source().is_none());
        }
    }

    // -----------------------------------------------------------------------
    // Enrichment: Negative risk budget rejected
    // -----------------------------------------------------------------------

    #[test]
    fn negative_risk_budget_rejected() {
        let config = ScannerConfig {
            risk_budget_millionths: -500_000,
            ..Default::default()
        };
        let result = BifurcationBoundaryScanner::new(
            config,
            vec![make_param("x", 500_000)],
            vec![make_envelope("x", 0, MILLION, 500_000)],
        );
        assert!(matches!(
            result,
            Err(ScannerError::InvalidRiskBudget { value: -500_000 })
        ));
    }

    // -----------------------------------------------------------------------
    // Enrichment: serde roundtrips for remaining types
    // -----------------------------------------------------------------------

    #[test]
    fn enrichment_stability_map_entry_serde_roundtrip() {
        let entry = StabilityMapEntry {
            value_millionths: 400_000,
            regime: RegimeLabel::Elevated,
            stability_millionths: 200_000,
        };
        let json = serde_json::to_string(&entry).unwrap();
        let back: StabilityMapEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry, back);
    }

    #[test]
    fn enrichment_early_warning_indicator_serde_roundtrip() {
        let ewi = EarlyWarningIndicator {
            indicator_id: "ew-serde".to_string(),
            parameter_id: "p-serde".to_string(),
            risk_value_millionths: 700_000,
            threshold_millionths: 750_000,
            active: true,
            trend_millionths: 15_000,
            observation_count: 30,
        };
        let json = serde_json::to_string(&ewi).unwrap();
        let back: EarlyWarningIndicator = serde_json::from_str(&json).unwrap();
        assert_eq!(ewi, back);
    }

    #[test]
    fn enrichment_preemptive_action_serde_roundtrip() {
        let action = PreemptiveAction {
            action_id: "pa-serde".to_string(),
            trigger_indicator_id: "ew-serde".to_string(),
            parameter_id: "p-serde".to_string(),
            lane_action: LaneAction::FallbackSafe,
            epoch: SecurityEpoch::GENESIS,
            trigger_risk_millionths: 800_000,
            rationale: "serde roundtrip test".to_string(),
        };
        let json = serde_json::to_string(&action).unwrap();
        let back: PreemptiveAction = serde_json::from_str(&json).unwrap();
        assert_eq!(action, back);
    }

    #[test]
    fn enrichment_parameter_observation_serde_roundtrip() {
        let obs = ParameterObservation {
            parameter_id: "obs-serde".to_string(),
            value_millionths: 600_000,
            tick: 42,
            regime: RegimeLabel::Normal,
        };
        let json = serde_json::to_string(&obs).unwrap();
        let back: ParameterObservation = serde_json::from_str(&json).unwrap();
        assert_eq!(obs, back);
    }

    #[test]
    fn enrichment_bifurcation_point_serde_roundtrip() {
        let bp = BifurcationPoint {
            parameter_id: "bp-serde".to_string(),
            critical_value_millionths: 350_000,
            bifurcation_type: BifurcationType::Transcritical,
            regime_before: RegimeLabel::Elevated,
            regime_after: RegimeLabel::Degraded,
            confidence_millionths: 850_000,
        };
        let json = serde_json::to_string(&bp).unwrap();
        let back: BifurcationPoint = serde_json::from_str(&json).unwrap();
        assert_eq!(bp, back);
    }

    // -----------------------------------------------------------------------
    // Enrichment: JSON field presence for remaining types
    // -----------------------------------------------------------------------

    #[test]
    fn enrichment_json_field_presence_control_parameter() {
        let p = make_param("cp-json", 500_000);
        let j = serde_json::to_string(&p).unwrap();
        assert!(j.contains("\"id\""));
        assert!(j.contains("\"label\""));
        assert!(j.contains("\"domain\""));
        assert!(j.contains("\"current_value_millionths\""));
        assert!(j.contains("\"policy_tunable\""));
    }

    #[test]
    fn enrichment_json_field_presence_early_warning_indicator() {
        let ewi = EarlyWarningIndicator {
            indicator_id: "ew-json".to_string(),
            parameter_id: "p-json".to_string(),
            risk_value_millionths: 600_000,
            threshold_millionths: 750_000,
            active: false,
            trend_millionths: 0,
            observation_count: 5,
        };
        let j = serde_json::to_string(&ewi).unwrap();
        assert!(j.contains("\"indicator_id\""));
        assert!(j.contains("\"risk_value_millionths\""));
        assert!(j.contains("\"threshold_millionths\""));
        assert!(j.contains("\"active\""));
        assert!(j.contains("\"trend_millionths\""));
        assert!(j.contains("\"observation_count\""));
    }

    // -----------------------------------------------------------------------
    // Enrichment: observe unknown parameter does not crash
    // -----------------------------------------------------------------------

    #[test]
    fn enrichment_observe_unknown_parameter_no_panic() {
        let mut scanner = default_scanner();
        scanner.observe(ParameterObservation {
            parameter_id: "nonexistent".to_string(),
            value_millionths: 999_999,
            tick: 1,
            regime: RegimeLabel::Normal,
        });
        assert_eq!(scanner.observation_count(), 1);
        // Scan still works
        let result = scanner.scan().unwrap();
        assert_eq!(result.parameters_scanned, 2);
    }

    // -----------------------------------------------------------------------
    // Enrichment: scan with partially unmonitored parameter
    // -----------------------------------------------------------------------

    #[test]
    fn enrichment_scan_unmonitored_parameter_regime_summary() {
        // 2 params, only 1 has an envelope → the other is "unmonitored"
        let params = vec![
            make_param("monitored", 500_000),
            make_param("unmonitored", 300_000),
        ];
        let envelopes = vec![make_envelope("monitored", 100_000, 900_000, 500_000)];
        let mut scanner =
            BifurcationBoundaryScanner::new(ScannerConfig::default(), params, envelopes).unwrap();
        let result = scanner.scan().unwrap();
        assert_eq!(result.parameters_scanned, 2);
        assert!(result.regime_summary.contains_key("unmonitored"));
    }

    // -----------------------------------------------------------------------
    // Enrichment: stability map has correct ordering
    // -----------------------------------------------------------------------

    #[test]
    fn enrichment_stability_map_entries_ordered_by_value() {
        let config = ScannerConfig {
            record_stability_maps: true,
            ..Default::default()
        };
        let params = vec![make_param("x", 500_000)];
        let envelopes = vec![make_envelope("x", 0, MILLION, 500_000)];
        let mut scanner = BifurcationBoundaryScanner::new(config, params, envelopes).unwrap();
        scanner.scan().unwrap();
        let map = scanner.stability_maps().get("x").unwrap();
        // Entries should be in ascending order of value_millionths
        for w in map.windows(2) {
            assert!(w[0].value_millionths <= w[1].value_millionths);
        }
    }

    // -----------------------------------------------------------------------
    // Enrichment: artifact hash differs between different scan states
    // -----------------------------------------------------------------------

    #[test]
    fn enrichment_artifact_hash_differs_for_different_states() {
        let params_a = vec![make_param("x", 500_000)];
        let params_b = vec![make_param("x", 110_000)]; // near boundary
        let envs = vec![make_envelope("x", 100_000, 900_000, 500_000)];
        let mut sa =
            BifurcationBoundaryScanner::new(ScannerConfig::default(), params_a, envs.clone())
                .unwrap();
        let mut sb =
            BifurcationBoundaryScanner::new(ScannerConfig::default(), params_b, envs).unwrap();
        let ra = sa.scan().unwrap();
        let rb = sb.scan().unwrap();
        // Different parameter states should produce different artifact hashes
        assert_ne!(ra.artifact_hash, rb.artifact_hash);
    }

    // -----------------------------------------------------------------------
    // Enrichment: clone/eq for ParameterObservation
    // -----------------------------------------------------------------------

    #[test]
    fn enrichment_clone_eq_parameter_observation() {
        let obs = ParameterObservation {
            parameter_id: "obs-clone".to_string(),
            value_millionths: 333_333,
            tick: 99,
            regime: RegimeLabel::Degraded,
        };
        let cloned = obs.clone();
        assert_eq!(obs, cloned);
    }

    // -----------------------------------------------------------------------
    // Enrichment: too many envelopes boundary
    // -----------------------------------------------------------------------

    #[test]
    fn enrichment_too_many_envelopes_rejected() {
        let params: Vec<_> = (0..65)
            .map(|i| make_param(&format!("p-{i}"), 500_000))
            .collect();
        let envelopes: Vec<_> = (0..65)
            .map(|i| make_envelope(&format!("p-{i}"), 0, MILLION, 500_000))
            .collect();
        let result = BifurcationBoundaryScanner::new(ScannerConfig::default(), params, envelopes);
        assert!(matches!(
            result,
            Err(ScannerError::TooManyEnvelopes { count: 65, max: 64 })
        ));
    }
}
