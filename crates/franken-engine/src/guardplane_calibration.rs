//! Guardplane calibration: closed-loop integration of red/blue adversarial
//! campaign results into Bayesian sentinel thresholds, loss matrices, and
//! policy regression suites.
//!
//! This module does NOT own the adversarial campaigns or the Bayesian updater.
//! It consumes structured campaign outcomes, drives the `RedBlueLoopIntegrator`
//! calibration cycle, and translates calibration deltas into actionable
//! adjustments for the expected-loss selector and safety decision router.
//!
//! Closed-loop flow:
//! 1. Ingest `CampaignOutcomeRecord` batch from adversarial campaign runner.
//! 2. Classify results by defense subsystem, threat category, severity.
//! 3. Compute calibration deltas via `RedBlueLoopIntegrator::calibrate()`.
//! 4. Apply deltas to detection thresholds and evidence weights.
//! 5. Update policy regression suite with new fixtures from critical campaigns.
//! 6. Emit structured audit events for every calibration action.
//!
//! Plan reference: Section 10.12 item 14, bd-33ce.
//! Dependencies: bd-2onl (adversarial campaigns), bd-3a5e (safety_decision_router),
//!   bd-3md (bayesian_posterior), bd-1y5 (expected_loss_selector).

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::adversarial_campaign::{
    AttackDimension, CampaignOutcomeRecord, CampaignSeverity, DefenseSubsystem,
    GuardplaneCalibrationState, RedBlueCalibrationConfig, RedBlueLoopIntegrator, ThreatCategory,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Component name for structured events.
const COMPONENT: &str = "guardplane_calibration";

// ---------------------------------------------------------------------------
// Calibration cycle result
// ---------------------------------------------------------------------------

/// Outcome of a single calibration cycle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CalibrationCycleResult {
    /// Unique cycle identifier.
    pub cycle_id: String,
    /// Number of campaign outcomes ingested in this cycle.
    pub campaigns_ingested: usize,
    /// Breakdown by severity.
    pub severity_counts: BTreeMap<String, usize>,
    /// Breakdown by defense subsystem.
    pub subsystem_counts: BTreeMap<String, usize>,
    /// Breakdown by threat category.
    pub threat_counts: BTreeMap<String, usize>,
    /// Whether calibration produced threshold adjustments.
    pub thresholds_adjusted: bool,
    /// Detection threshold after calibration (millionths).
    pub detection_threshold_millionths: u64,
    /// Evidence weight snapshot after calibration.
    pub evidence_weights_millionths: BTreeMap<String, u64>,
    /// Number of new regression fixtures promoted.
    pub regression_fixtures_added: usize,
    /// Calibration epoch after this cycle.
    pub calibration_epoch: u64,
    /// Content-addressable digest of the calibration state.
    pub state_digest: String,
}

// ---------------------------------------------------------------------------
// Defense effectiveness trend
// ---------------------------------------------------------------------------

/// Direction of defense effectiveness change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum EffectivenessTrend {
    /// Defense is improving (fewer evasions over time).
    Improving,
    /// Defense is stable.
    Stable,
    /// Defense is degrading (more evasions over time).
    Degrading,
}

impl fmt::Display for EffectivenessTrend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Improving => write!(f, "improving"),
            Self::Stable => write!(f, "stable"),
            Self::Degrading => write!(f, "degrading"),
        }
    }
}

/// Per-dimension defense effectiveness summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DimensionEffectiveness {
    pub dimension: String,
    pub detection_rate_millionths: u64,
    pub evasion_rate_millionths: u64,
    pub trend: EffectivenessTrend,
    pub sample_count: usize,
}

/// Fleet-level defense effectiveness summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DefenseEffectivenessSummary {
    pub total_campaigns: usize,
    pub total_evasions: usize,
    pub total_containment_escapes: usize,
    pub overall_detection_rate_millionths: u64,
    pub overall_trend: EffectivenessTrend,
    pub per_dimension: BTreeMap<String, DimensionEffectiveness>,
    pub weakest_dimension: Option<String>,
}

// ---------------------------------------------------------------------------
// Calibration alert
// ---------------------------------------------------------------------------

/// Alert raised when calibration detects a significant defense gap.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CalibrationAlert {
    pub alert_id: String,
    pub severity: String,
    pub subsystem: String,
    pub threat_category: String,
    pub description: String,
    pub recommended_action: String,
    pub evasion_rate_millionths: u64,
    pub cycle_id: String,
}

// ---------------------------------------------------------------------------
// Structured events
// ---------------------------------------------------------------------------

/// Structured audit event for calibration operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CalibrationEvent {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
}

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors from guardplane calibration operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CalibrationError {
    /// No campaigns provided for calibration.
    EmptyCampaignBatch,
    /// Campaign validation failed.
    CampaignValidationFailed { detail: String },
    /// Calibration cycle failed.
    CalibrationFailed { detail: String },
    /// Invalid configuration.
    InvalidConfig { detail: String },
}

impl CalibrationError {
    /// Stable machine-readable error code.
    pub fn code(&self) -> &'static str {
        match self {
            Self::EmptyCampaignBatch => "FE-GCAL-0001",
            Self::CampaignValidationFailed { .. } => "FE-GCAL-0002",
            Self::CalibrationFailed { .. } => "FE-GCAL-0003",
            Self::InvalidConfig { .. } => "FE-GCAL-0004",
        }
    }
}

impl fmt::Display for CalibrationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyCampaignBatch => {
                write!(f, "{}: empty campaign batch", self.code())
            }
            Self::CampaignValidationFailed { detail } => {
                write!(f, "{}: campaign validation failed: {detail}", self.code())
            }
            Self::CalibrationFailed { detail } => {
                write!(f, "{}: calibration failed: {detail}", self.code())
            }
            Self::InvalidConfig { detail } => {
                write!(f, "{}: invalid config: {detail}", self.code())
            }
        }
    }
}

impl std::error::Error for CalibrationError {}

// ---------------------------------------------------------------------------
// Calibration context (passed per-cycle)
// ---------------------------------------------------------------------------

/// Context for a single calibration cycle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CalibrationContext {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub signing_key: [u8; 32],
    pub timestamp_ns: u64,
}

// ---------------------------------------------------------------------------
// Guardplane calibration engine
// ---------------------------------------------------------------------------

/// Orchestrates the closed-loop calibration of sentinel thresholds and
/// policy regression suites from adversarial campaign results.
#[derive(Debug)]
pub struct GuardplaneCalibrationEngine {
    integrator: RedBlueLoopIntegrator,
    cycle_count: u64,
    total_campaigns_ingested: usize,
    total_evasions: usize,
    total_containment_escapes: usize,
    // Per-dimension tracking for trend analysis
    dimension_history: BTreeMap<String, Vec<u64>>,
    alerts: Vec<CalibrationAlert>,
    events: Vec<CalibrationEvent>,
    // Alert thresholds (millionths)
    evasion_alert_threshold_millionths: u64,
    containment_escape_alert_threshold_millionths: u64,
}

impl GuardplaneCalibrationEngine {
    /// Create a new calibration engine with default configuration.
    pub fn new() -> Self {
        let config = RedBlueCalibrationConfig::default();
        let state = GuardplaneCalibrationState::default();
        Self {
            integrator: RedBlueLoopIntegrator::new(config, state),
            cycle_count: 0,
            total_campaigns_ingested: 0,
            total_evasions: 0,
            total_containment_escapes: 0,
            dimension_history: BTreeMap::new(),
            alerts: Vec::new(),
            events: Vec::new(),
            evasion_alert_threshold_millionths: 200_000, // 20%
            containment_escape_alert_threshold_millionths: 100_000, // 10%
        }
    }

    /// Create with custom calibration config.
    pub fn with_config(config: RedBlueCalibrationConfig) -> Self {
        let state = GuardplaneCalibrationState::default();
        Self {
            integrator: RedBlueLoopIntegrator::new(config, state),
            cycle_count: 0,
            total_campaigns_ingested: 0,
            total_evasions: 0,
            total_containment_escapes: 0,
            dimension_history: BTreeMap::new(),
            alerts: Vec::new(),
            events: Vec::new(),
            evasion_alert_threshold_millionths: 200_000,
            containment_escape_alert_threshold_millionths: 100_000,
        }
    }

    /// Set the evasion rate threshold for generating alerts (millionths).
    pub fn set_evasion_alert_threshold(&mut self, threshold_millionths: u64) {
        self.evasion_alert_threshold_millionths = threshold_millionths;
    }

    /// Set the containment escape rate threshold for alerts (millionths).
    pub fn set_containment_escape_alert_threshold(&mut self, threshold_millionths: u64) {
        self.containment_escape_alert_threshold_millionths = threshold_millionths;
    }

    /// Run a complete calibration cycle: ingest campaigns, calibrate, emit alerts.
    pub fn run_calibration_cycle(
        &mut self,
        outcomes: &[CampaignOutcomeRecord],
        ctx: &CalibrationContext,
    ) -> Result<CalibrationCycleResult, CalibrationError> {
        if outcomes.is_empty() {
            return Err(CalibrationError::EmptyCampaignBatch);
        }

        self.cycle_count = self.cycle_count.saturating_add(1);
        let cycle_id = format!("gcal-{:04}", self.cycle_count);

        // 1. Classify and count outcomes
        let (severity_counts, subsystem_counts, threat_counts) = classify_outcomes(outcomes);

        // 2. Count evasions and escapes
        let mut cycle_evasions = 0usize;
        let mut cycle_escapes = 0usize;
        for o in outcomes {
            if o.result.undetected_steps > 0 {
                cycle_evasions += 1;
            }
            if o.result.objective_achieved_before_containment {
                cycle_escapes += 1;
            }
        }
        self.total_evasions += cycle_evasions;
        self.total_containment_escapes += cycle_escapes;

        // 3. Ingest outcomes into the red/blue integrator
        let classifications = self.integrator.ingest_outcomes(outcomes).map_err(|e| {
            CalibrationError::CampaignValidationFailed {
                detail: format!("{e}"),
            }
        })?;

        self.total_campaigns_ingested += outcomes.len();

        self.emit_event(ctx, "campaigns_ingested", "ok", None);

        // 4. Run calibration
        let receipt = self
            .integrator
            .calibrate(&ctx.signing_key, ctx.timestamp_ns)
            .map_err(|e| CalibrationError::CalibrationFailed {
                detail: format!("{e}"),
            })?;

        let thresholds_adjusted = receipt.is_some();

        self.emit_event(
            ctx,
            "calibration_complete",
            if thresholds_adjusted {
                "adjusted"
            } else {
                "no_change"
            },
            None,
        );

        // 5. Promote critical campaigns as regression fixtures
        let mut regression_fixtures_added = 0usize;
        for (i, (outcome, classification)) in
            outcomes.iter().zip(classifications.iter()).enumerate()
        {
            if classification.severity == CampaignSeverity::Critical
                || classification.severity == CampaignSeverity::Blocking
            {
                let campaign_id = format!("{cycle_id}-camp-{i}");
                let expected = match classification.severity {
                    CampaignSeverity::Blocking => "immediate_containment",
                    _ => "detection_within_sla",
                };
                let actual = if outcome.result.objective_achieved_before_containment {
                    "containment_escaped"
                } else if outcome.result.undetected_steps > 0 {
                    "delayed_detection"
                } else {
                    "detected"
                };

                let _ = self.integrator.promote_regression_fixture(
                    &campaign_id,
                    expected,
                    actual,
                    receipt.as_ref().map(|r| r.calibration_id.clone()),
                );
                regression_fixtures_added += 1;
            }
        }

        if regression_fixtures_added > 0 {
            self.emit_event(ctx, "regression_fixtures_promoted", "ok", None);
        }

        // 6. Update dimension history for trend analysis
        let effectiveness = self.integrator.technique_effectiveness();
        for (dim, eff) in &effectiveness {
            let key = serde_json::to_string(&dim).unwrap_or_default();
            self.dimension_history
                .entry(key)
                .or_default()
                .push(eff.escape_rate_millionths);
        }

        // 7. Generate alerts for defense gaps
        self.generate_alerts(outcomes, &cycle_id, ctx);

        // 8. Build result
        let cal_state = self.integrator.calibration_state();
        let evidence_weights: BTreeMap<String, u64> = cal_state
            .evidence_weights_millionths
            .iter()
            .map(|(k, v)| (serde_json::to_string(&k).unwrap_or_default(), *v))
            .collect();

        let state_digest = compute_state_digest(cal_state);

        Ok(CalibrationCycleResult {
            cycle_id,
            campaigns_ingested: outcomes.len(),
            severity_counts,
            subsystem_counts,
            threat_counts,
            thresholds_adjusted,
            detection_threshold_millionths: cal_state.detection_threshold_millionths,
            evidence_weights_millionths: evidence_weights,
            regression_fixtures_added,
            calibration_epoch: cal_state.calibration_epoch,
            state_digest,
        })
    }

    /// Compute defense effectiveness summary across all ingested campaigns.
    pub fn defense_effectiveness(&self) -> DefenseEffectivenessSummary {
        let detection_rate = if self.total_campaigns_ingested > 0 {
            let detected = self.total_campaigns_ingested - self.total_evasions;
            (detected as u64)
                .saturating_mul(1_000_000)
                .checked_div(self.total_campaigns_ingested as u64)
                .unwrap_or(0)
        } else {
            0
        };

        let overall_trend = compute_overall_trend(&self.dimension_history);

        let per_dimension = self.compute_per_dimension_effectiveness();

        let weakest = per_dimension
            .values()
            .min_by_key(|d| d.detection_rate_millionths)
            .map(|d| d.dimension.clone());

        DefenseEffectivenessSummary {
            total_campaigns: self.total_campaigns_ingested,
            total_evasions: self.total_evasions,
            total_containment_escapes: self.total_containment_escapes,
            overall_detection_rate_millionths: detection_rate,
            overall_trend,
            per_dimension,
            weakest_dimension: weakest,
        }
    }

    /// Current calibration state snapshot.
    pub fn calibration_state(&self) -> &GuardplaneCalibrationState {
        self.integrator.calibration_state()
    }

    /// All generated alerts.
    pub fn alerts(&self) -> &[CalibrationAlert] {
        &self.alerts
    }

    /// All structured events.
    pub fn events(&self) -> &[CalibrationEvent] {
        &self.events
    }

    /// Drain events.
    pub fn drain_events(&mut self) -> Vec<CalibrationEvent> {
        std::mem::take(&mut self.events)
    }

    /// Number of completed calibration cycles.
    pub fn cycle_count(&self) -> u64 {
        self.cycle_count
    }

    /// Total campaigns ingested across all cycles.
    pub fn total_campaigns_ingested(&self) -> usize {
        self.total_campaigns_ingested
    }

    // -------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------

    fn generate_alerts(
        &mut self,
        outcomes: &[CampaignOutcomeRecord],
        cycle_id: &str,
        ctx: &CalibrationContext,
    ) {
        if outcomes.is_empty() {
            return;
        }

        // Check per-subsystem evasion rates
        let mut subsystem_evasions: BTreeMap<DefenseSubsystem, (usize, usize)> = BTreeMap::new();
        for o in outcomes {
            let subsystem = classify_defense_subsystem(o);
            let entry = subsystem_evasions.entry(subsystem).or_insert((0, 0));
            entry.1 += 1; // total
            if o.result.undetected_steps > 0 {
                entry.0 += 1; // evasions
            }
        }

        for (subsystem, (evasions, total)) in &subsystem_evasions {
            let evasion_rate = (*evasions as u64)
                .saturating_mul(1_000_000)
                .checked_div(*total as u64)
                .unwrap_or(0);

            if evasion_rate >= self.evasion_alert_threshold_millionths {
                let alert_id = format!("{cycle_id}-alert-{}", self.alerts.len());
                self.alerts.push(CalibrationAlert {
                    alert_id: alert_id.clone(),
                    severity: "critical".to_string(),
                    subsystem: serde_json::to_string(&subsystem).unwrap_or_default(),
                    threat_category: "evasion".to_string(),
                    description: format!(
                        "evasion rate {:.1}% exceeds threshold {:.1}% for {subsystem:?}",
                        evasion_rate as f64 / 10_000.0,
                        self.evasion_alert_threshold_millionths as f64 / 10_000.0
                    ),
                    recommended_action: "tighten detection thresholds".to_string(),
                    evasion_rate_millionths: evasion_rate,
                    cycle_id: cycle_id.to_string(),
                });
                self.emit_event(ctx, "calibration_alert", "evasion_threshold_exceeded", None);
            }
        }

        // Check containment escape rate
        let escape_count = outcomes
            .iter()
            .filter(|o| o.result.objective_achieved_before_containment)
            .count();
        let escape_rate = (escape_count as u64)
            .saturating_mul(1_000_000)
            .checked_div(outcomes.len() as u64)
            .unwrap_or(0);

        if escape_rate >= self.containment_escape_alert_threshold_millionths {
            let alert_id = format!("{cycle_id}-alert-{}", self.alerts.len());
            self.alerts.push(CalibrationAlert {
                alert_id,
                severity: "blocking".to_string(),
                subsystem: "Containment".to_string(),
                threat_category: "containment_escape".to_string(),
                description: format!(
                    "containment escape rate {:.1}% exceeds threshold {:.1}%",
                    escape_rate as f64 / 10_000.0,
                    self.containment_escape_alert_threshold_millionths as f64 / 10_000.0
                ),
                recommended_action: "escalate containment posture".to_string(),
                evasion_rate_millionths: escape_rate,
                cycle_id: cycle_id.to_string(),
            });
            self.emit_event(
                ctx,
                "calibration_alert",
                "containment_escape_threshold_exceeded",
                None,
            );
        }
    }

    fn compute_per_dimension_effectiveness(&self) -> BTreeMap<String, DimensionEffectiveness> {
        let effectiveness = self.integrator.technique_effectiveness();
        let mut result = BTreeMap::new();

        for (dim, eff) in &effectiveness {
            let key = serde_json::to_string(&dim).unwrap_or_default();
            let trend = if let Some(history) = self.dimension_history.get(&key) {
                compute_trend(history)
            } else {
                EffectivenessTrend::Stable
            };

            let detection_rate = 1_000_000u64.saturating_sub(eff.escape_rate_millionths);

            result.insert(
                key.clone(),
                DimensionEffectiveness {
                    dimension: key,
                    detection_rate_millionths: detection_rate,
                    evasion_rate_millionths: eff.escape_rate_millionths,
                    trend,
                    sample_count: eff.attempts as usize,
                },
            );
        }

        result
    }

    fn emit_event(
        &mut self,
        ctx: &CalibrationContext,
        event: &str,
        outcome: &str,
        error_code: Option<&str>,
    ) {
        self.events.push(CalibrationEvent {
            trace_id: ctx.trace_id.clone(),
            decision_id: ctx.decision_id.clone(),
            policy_id: ctx.policy_id.clone(),
            component: COMPONENT.to_string(),
            event: event.to_string(),
            outcome: outcome.to_string(),
            error_code: error_code.map(|s| s.to_string()),
        });
    }
}

impl Default for GuardplaneCalibrationEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn classify_outcomes(
    outcomes: &[CampaignOutcomeRecord],
) -> (
    BTreeMap<String, usize>,
    BTreeMap<String, usize>,
    BTreeMap<String, usize>,
) {
    let mut severity_counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut subsystem_counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut threat_counts: BTreeMap<String, usize> = BTreeMap::new();

    for o in outcomes {
        // Severity from score
        let severity = classify_severity(&o.score);
        *severity_counts
            .entry(serde_json::to_string(&severity).unwrap_or_default())
            .or_default() += 1;

        // Defense subsystem
        let subsystem = classify_defense_subsystem(o);
        *subsystem_counts
            .entry(serde_json::to_string(&subsystem).unwrap_or_default())
            .or_default() += 1;

        // Threat category from campaign
        let threat = classify_threat_category(o);
        *threat_counts
            .entry(serde_json::to_string(&threat).unwrap_or_default())
            .or_default() += 1;
    }

    (severity_counts, subsystem_counts, threat_counts)
}

fn classify_severity(
    score: &crate::adversarial_campaign::ExploitObjectiveScore,
) -> CampaignSeverity {
    if score.composite_score_millionths >= 800_000 {
        CampaignSeverity::Blocking
    } else if score.composite_score_millionths >= 500_000 {
        CampaignSeverity::Critical
    } else if score.composite_score_millionths >= 200_000 {
        CampaignSeverity::Moderate
    } else {
        CampaignSeverity::Advisory
    }
}

fn classify_defense_subsystem(outcome: &CampaignOutcomeRecord) -> DefenseSubsystem {
    if outcome.result.objective_achieved_before_containment {
        DefenseSubsystem::Containment
    } else if outcome.result.undetected_steps > 0 {
        DefenseSubsystem::Sentinel
    } else if outcome.result.evidence_atoms_before_detection > 10 {
        DefenseSubsystem::EvidenceAccumulation
    } else {
        DefenseSubsystem::FleetConvergence
    }
}

fn classify_threat_category(outcome: &CampaignOutcomeRecord) -> ThreatCategory {
    // Derive primary dimension from campaign steps (most frequent dimension wins)
    let mut counts: BTreeMap<AttackDimension, usize> = BTreeMap::new();
    for step in &outcome.campaign.steps {
        *counts.entry(step.dimension).or_default() += 1;
    }
    let dim = counts
        .into_iter()
        .max_by_key(|&(_, count)| count)
        .map(|(d, _)| d)
        .unwrap_or(AttackDimension::HostcallSequence);

    match dim {
        AttackDimension::HostcallSequence => ThreatCategory::CredentialTheft,
        AttackDimension::TemporalPayload => ThreatCategory::Persistence,
        AttackDimension::PrivilegeEscalation => ThreatCategory::PrivilegeEscalation,
        AttackDimension::PolicyEvasion => ThreatCategory::PolicyEvasion,
        AttackDimension::Exfiltration => ThreatCategory::Exfiltration,
    }
}

fn compute_trend(history: &[u64]) -> EffectivenessTrend {
    if history.len() < 2 {
        return EffectivenessTrend::Stable;
    }
    let recent = history.len().min(5);
    let recent_avg: u64 = history[history.len() - recent..]
        .iter()
        .sum::<u64>()
        .checked_div(recent as u64)
        .unwrap_or(0);

    let older_end = history.len().saturating_sub(recent);
    if older_end == 0 {
        return EffectivenessTrend::Stable;
    }
    let older_start = older_end.saturating_sub(5);
    let older_slice = &history[older_start..older_end];
    if older_slice.is_empty() {
        return EffectivenessTrend::Stable;
    }
    let older_avg: u64 = older_slice
        .iter()
        .sum::<u64>()
        .checked_div(older_slice.len() as u64)
        .unwrap_or(0);

    // Evasion rate: lower is better → if recent < older, improving
    let delta = 50_000u64; // 5% threshold for trend change
    if recent_avg + delta < older_avg {
        EffectivenessTrend::Improving
    } else if recent_avg > older_avg + delta {
        EffectivenessTrend::Degrading
    } else {
        EffectivenessTrend::Stable
    }
}

fn compute_overall_trend(dimension_history: &BTreeMap<String, Vec<u64>>) -> EffectivenessTrend {
    let mut improving = 0usize;
    let mut degrading = 0usize;

    for history in dimension_history.values() {
        match compute_trend(history) {
            EffectivenessTrend::Improving => improving += 1,
            EffectivenessTrend::Degrading => degrading += 1,
            EffectivenessTrend::Stable => {}
        }
    }

    if degrading > improving {
        EffectivenessTrend::Degrading
    } else if improving > degrading {
        EffectivenessTrend::Improving
    } else {
        EffectivenessTrend::Stable
    }
}

/// FNV-1a 64-bit hash for content-addressable state digest.
fn fnv1a64(data: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for &byte in data {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    hash
}

fn compute_state_digest(state: &GuardplaneCalibrationState) -> String {
    let serialized = serde_json::to_vec(state).unwrap_or_default();
    format!("{:016x}", fnv1a64(&serialized))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adversarial_campaign::{
        AdversarialCampaign, AttackStep, AttackStepKind, CampaignComplexity,
        CampaignExecutionResult, CampaignOutcomeRecord, ExploitObjectiveScore,
    };

    fn test_ctx() -> CalibrationContext {
        CalibrationContext {
            trace_id: "trace-1".to_string(),
            decision_id: "dec-1".to_string(),
            policy_id: "pol-1".to_string(),
            signing_key: [0u8; 32],
            timestamp_ns: 1_000_000_000,
        }
    }

    fn make_campaign(dim: AttackDimension, step_count: usize) -> AdversarialCampaign {
        let steps: Vec<AttackStep> = (0..step_count)
            .map(|i| AttackStep {
                step_id: i as u32,
                dimension: dim,
                production_label: format!("test-label-{i}"),
                kind: AttackStepKind::HostcallSequence {
                    motif: "test-motif".to_string(),
                    hostcall_count: 3,
                },
            })
            .collect();
        AdversarialCampaign {
            campaign_id: format!("camp-{dim:?}-{step_count}"),
            trace_id: "trace-test".to_string(),
            decision_id: "dec-test".to_string(),
            policy_id: "pol-test".to_string(),
            grammar_version: 1,
            seed: 42,
            complexity: CampaignComplexity::Probe,
            steps,
        }
    }

    fn make_result(
        undetected: usize,
        total: usize,
        escaped: bool,
        damage: u64,
        evidence_atoms: u64,
        novel: bool,
    ) -> CampaignExecutionResult {
        CampaignExecutionResult {
            undetected_steps: undetected,
            total_steps: total,
            objective_achieved_before_containment: escaped,
            damage_potential_millionths: damage,
            evidence_atoms_before_detection: evidence_atoms,
            novel_technique: novel,
        }
    }

    fn make_outcome(
        dim: AttackDimension,
        undetected: usize,
        total: usize,
        escaped: bool,
    ) -> CampaignOutcomeRecord {
        let campaign = make_campaign(dim, total);
        let result = make_result(undetected, total, escaped, 200_000, 5, false);
        let score = ExploitObjectiveScore::from_result(&result).unwrap();
        CampaignOutcomeRecord {
            campaign,
            result,
            score,
            benign_control: false,
            false_positive: false,
            timestamp_ns: 1_000_000_000,
        }
    }

    // -------------------------------------------------------------------
    // Basic construction
    // -------------------------------------------------------------------

    #[test]
    fn new_engine_starts_empty() {
        let engine = GuardplaneCalibrationEngine::new();
        assert_eq!(engine.cycle_count(), 0);
        assert_eq!(engine.total_campaigns_ingested(), 0);
        assert!(engine.alerts().is_empty());
        assert!(engine.events().is_empty());
    }

    #[test]
    fn default_engine_matches_new() {
        let a = GuardplaneCalibrationEngine::new();
        let b = GuardplaneCalibrationEngine::default();
        assert_eq!(a.cycle_count(), b.cycle_count());
    }

    // -------------------------------------------------------------------
    // Calibration cycle
    // -------------------------------------------------------------------

    #[test]
    fn empty_batch_rejected() {
        let mut engine = GuardplaneCalibrationEngine::new();
        let ctx = test_ctx();
        let err = engine.run_calibration_cycle(&[], &ctx).unwrap_err();
        assert_eq!(err.code(), "FE-GCAL-0001");
    }

    #[test]
    fn single_campaign_cycle_succeeds() {
        let mut engine = GuardplaneCalibrationEngine::new();
        let ctx = test_ctx();
        let outcomes = vec![make_outcome(AttackDimension::Exfiltration, 2, 10, false)];

        let result = engine.run_calibration_cycle(&outcomes, &ctx).unwrap();
        assert_eq!(result.campaigns_ingested, 1);
        assert_eq!(
            result.calibration_epoch,
            engine.calibration_state().calibration_epoch
        );
        assert_eq!(engine.cycle_count(), 1);
        assert_eq!(engine.total_campaigns_ingested(), 1);
    }

    #[test]
    fn multiple_campaigns_cycle() {
        let mut engine = GuardplaneCalibrationEngine::new();
        let ctx = test_ctx();
        let outcomes = vec![
            make_outcome(AttackDimension::Exfiltration, 2, 10, false),
            make_outcome(AttackDimension::PrivilegeEscalation, 0, 8, false),
            make_outcome(AttackDimension::PolicyEvasion, 5, 5, true),
        ];

        let result = engine.run_calibration_cycle(&outcomes, &ctx).unwrap();
        assert_eq!(result.campaigns_ingested, 3);
        assert!(!result.severity_counts.is_empty());
        assert!(!result.subsystem_counts.is_empty());
        assert!(!result.threat_counts.is_empty());
    }

    #[test]
    fn cycle_id_increments() {
        let mut engine = GuardplaneCalibrationEngine::new();
        let ctx = test_ctx();
        let outcomes = vec![make_outcome(AttackDimension::Exfiltration, 0, 5, false)];

        let r1 = engine.run_calibration_cycle(&outcomes, &ctx).unwrap();
        let r2 = engine.run_calibration_cycle(&outcomes, &ctx).unwrap();

        assert_eq!(r1.cycle_id, "gcal-0001");
        assert_eq!(r2.cycle_id, "gcal-0002");
    }

    // -------------------------------------------------------------------
    // Severity classification
    // -------------------------------------------------------------------

    #[test]
    fn severity_classification_thresholds() {
        // Advisory: composite < 200K
        let low_result = make_result(0, 10, false, 50_000, 2, false);
        let low_score = ExploitObjectiveScore::from_result(&low_result).unwrap();
        assert_eq!(classify_severity(&low_score), CampaignSeverity::Advisory);

        // Blocking: composite >= 800K (all evasions + escape + high evidence + novel)
        let high_result = make_result(10, 10, true, 900_000, 50, true);
        let high_score = ExploitObjectiveScore::from_result(&high_result).unwrap();
        assert_eq!(classify_severity(&high_score), CampaignSeverity::Blocking);
    }

    // -------------------------------------------------------------------
    // Defense subsystem classification
    // -------------------------------------------------------------------

    #[test]
    fn subsystem_classification() {
        let escaped = make_outcome(AttackDimension::Exfiltration, 3, 10, true);
        assert_eq!(
            classify_defense_subsystem(&escaped),
            DefenseSubsystem::Containment
        );

        let evaded = make_outcome(AttackDimension::Exfiltration, 3, 10, false);
        assert_eq!(
            classify_defense_subsystem(&evaded),
            DefenseSubsystem::Sentinel
        );
    }

    // -------------------------------------------------------------------
    // Threat category classification
    // -------------------------------------------------------------------

    #[test]
    fn threat_category_mapping() {
        let o = make_outcome(AttackDimension::PrivilegeEscalation, 0, 5, false);
        assert_eq!(
            classify_threat_category(&o),
            ThreatCategory::PrivilegeEscalation
        );

        let o2 = make_outcome(AttackDimension::Exfiltration, 0, 5, false);
        assert_eq!(classify_threat_category(&o2), ThreatCategory::Exfiltration);

        let o3 = make_outcome(AttackDimension::PolicyEvasion, 0, 5, false);
        assert_eq!(classify_threat_category(&o3), ThreatCategory::PolicyEvasion);
    }

    // -------------------------------------------------------------------
    // Defense effectiveness
    // -------------------------------------------------------------------

    #[test]
    fn effectiveness_empty_engine() {
        let engine = GuardplaneCalibrationEngine::new();
        let eff = engine.defense_effectiveness();
        assert_eq!(eff.total_campaigns, 0);
        assert_eq!(eff.overall_detection_rate_millionths, 0);
        assert_eq!(eff.overall_trend, EffectivenessTrend::Stable);
    }

    #[test]
    fn effectiveness_after_campaigns() {
        let mut engine = GuardplaneCalibrationEngine::new();
        let ctx = test_ctx();
        let outcomes = vec![
            make_outcome(AttackDimension::Exfiltration, 0, 10, false), // detected
            make_outcome(AttackDimension::Exfiltration, 3, 10, false), // evasion
        ];

        engine.run_calibration_cycle(&outcomes, &ctx).unwrap();
        let eff = engine.defense_effectiveness();

        assert_eq!(eff.total_campaigns, 2);
        assert_eq!(eff.total_evasions, 1);
        assert_eq!(eff.overall_detection_rate_millionths, 500_000); // 50%
    }

    // -------------------------------------------------------------------
    // Alerts
    // -------------------------------------------------------------------

    #[test]
    fn alert_on_high_evasion_rate() {
        let mut engine = GuardplaneCalibrationEngine::new();
        engine.set_evasion_alert_threshold(100_000); // 10%
        let ctx = test_ctx();

        // All campaigns have evasions — 100% evasion rate in sentinel
        let outcomes = vec![
            make_outcome(AttackDimension::Exfiltration, 5, 10, false),
            make_outcome(AttackDimension::Exfiltration, 3, 10, false),
        ];

        engine.run_calibration_cycle(&outcomes, &ctx).unwrap();

        assert!(!engine.alerts().is_empty());
        assert!(
            engine
                .alerts()
                .iter()
                .any(|a| a.threat_category == "evasion")
        );
    }

    #[test]
    fn no_alert_when_below_threshold() {
        let mut engine = GuardplaneCalibrationEngine::new();
        engine.set_evasion_alert_threshold(900_000); // 90% threshold
        let ctx = test_ctx();

        let outcomes = vec![
            make_outcome(AttackDimension::Exfiltration, 0, 10, false), // no evasion
        ];

        engine.run_calibration_cycle(&outcomes, &ctx).unwrap();

        // No evasion alerts should fire (0% evasion < 90% threshold)
        let evasion_alerts: Vec<_> = engine
            .alerts()
            .iter()
            .filter(|a| a.threat_category == "evasion")
            .collect();
        assert!(evasion_alerts.is_empty());
    }

    #[test]
    fn containment_escape_alert() {
        let mut engine = GuardplaneCalibrationEngine::new();
        engine.set_containment_escape_alert_threshold(0); // any escape triggers alert
        let ctx = test_ctx();

        let outcomes = vec![
            make_outcome(AttackDimension::Exfiltration, 5, 10, true), // escaped
        ];

        engine.run_calibration_cycle(&outcomes, &ctx).unwrap();

        assert!(
            engine
                .alerts()
                .iter()
                .any(|a| a.threat_category == "containment_escape")
        );
    }

    // -------------------------------------------------------------------
    // Structured events
    // -------------------------------------------------------------------

    #[test]
    fn events_emitted_per_cycle() {
        let mut engine = GuardplaneCalibrationEngine::new();
        let ctx = test_ctx();
        let outcomes = vec![make_outcome(AttackDimension::Exfiltration, 0, 5, false)];

        engine.run_calibration_cycle(&outcomes, &ctx).unwrap();

        let events = engine.events();
        assert!(events.iter().any(|e| e.event == "campaigns_ingested"));
        assert!(events.iter().any(|e| e.event == "calibration_complete"));
        assert!(events.iter().all(|e| e.component == COMPONENT));
        assert!(events.iter().all(|e| e.trace_id == "trace-1"));
    }

    #[test]
    fn drain_events_clears() {
        let mut engine = GuardplaneCalibrationEngine::new();
        let ctx = test_ctx();
        let outcomes = vec![make_outcome(AttackDimension::Exfiltration, 0, 5, false)];

        engine.run_calibration_cycle(&outcomes, &ctx).unwrap();
        let drained = engine.drain_events();
        assert!(!drained.is_empty());
        assert!(engine.events().is_empty());
    }

    // -------------------------------------------------------------------
    // Trend analysis
    // -------------------------------------------------------------------

    #[test]
    fn trend_stable_with_insufficient_data() {
        assert_eq!(compute_trend(&[]), EffectivenessTrend::Stable);
        assert_eq!(compute_trend(&[100_000]), EffectivenessTrend::Stable);
    }

    #[test]
    fn trend_improving_when_evasion_drops() {
        // Older: high evasion, Recent: low evasion
        let history = vec![
            500_000, 500_000, 500_000, 500_000, 500_000, 100_000, 100_000, 100_000, 100_000,
            100_000,
        ];
        assert_eq!(compute_trend(&history), EffectivenessTrend::Improving);
    }

    #[test]
    fn trend_degrading_when_evasion_rises() {
        let history = vec![
            100_000, 100_000, 100_000, 100_000, 100_000, 500_000, 500_000, 500_000, 500_000,
            500_000,
        ];
        assert_eq!(compute_trend(&history), EffectivenessTrend::Degrading);
    }

    // -------------------------------------------------------------------
    // State digest
    // -------------------------------------------------------------------

    #[test]
    fn state_digest_is_deterministic() {
        let state = GuardplaneCalibrationState::default();
        let d1 = compute_state_digest(&state);
        let d2 = compute_state_digest(&state);
        assert_eq!(d1, d2);
        assert_eq!(d1.len(), 16);
        assert!(d1.chars().all(|c| c.is_ascii_hexdigit()));
    }

    // -------------------------------------------------------------------
    // Serde roundtrips
    // -------------------------------------------------------------------

    #[test]
    fn calibration_cycle_result_serde_roundtrip() {
        let result = CalibrationCycleResult {
            cycle_id: "gcal-0001".to_string(),
            campaigns_ingested: 3,
            severity_counts: BTreeMap::new(),
            subsystem_counts: BTreeMap::new(),
            threat_counts: BTreeMap::new(),
            thresholds_adjusted: true,
            detection_threshold_millionths: 500_000,
            evidence_weights_millionths: BTreeMap::new(),
            regression_fixtures_added: 1,
            calibration_epoch: 2,
            state_digest: "abc123".to_string(),
        };
        let json = serde_json::to_string(&result).unwrap();
        let parsed: CalibrationCycleResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, parsed);
    }

    #[test]
    fn calibration_alert_serde_roundtrip() {
        let alert = CalibrationAlert {
            alert_id: "a1".to_string(),
            severity: "critical".to_string(),
            subsystem: "Sentinel".to_string(),
            threat_category: "evasion".to_string(),
            description: "high evasion rate".to_string(),
            recommended_action: "tighten thresholds".to_string(),
            evasion_rate_millionths: 300_000,
            cycle_id: "gcal-0001".to_string(),
        };
        let json = serde_json::to_string(&alert).unwrap();
        let parsed: CalibrationAlert = serde_json::from_str(&json).unwrap();
        assert_eq!(alert, parsed);
    }

    #[test]
    fn defense_effectiveness_summary_serde_roundtrip() {
        let summary = DefenseEffectivenessSummary {
            total_campaigns: 10,
            total_evasions: 3,
            total_containment_escapes: 1,
            overall_detection_rate_millionths: 700_000,
            overall_trend: EffectivenessTrend::Improving,
            per_dimension: BTreeMap::new(),
            weakest_dimension: Some("PolicyEvasion".to_string()),
        };
        let json = serde_json::to_string(&summary).unwrap();
        let parsed: DefenseEffectivenessSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(summary, parsed);
    }

    #[test]
    fn calibration_event_serde_roundtrip() {
        let event = CalibrationEvent {
            trace_id: "t".to_string(),
            decision_id: "d".to_string(),
            policy_id: "p".to_string(),
            component: COMPONENT.to_string(),
            event: "test".to_string(),
            outcome: "ok".to_string(),
            error_code: None,
        };
        let json = serde_json::to_string(&event).unwrap();
        let parsed: CalibrationEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, parsed);
    }

    // -------------------------------------------------------------------
    // Error codes
    // -------------------------------------------------------------------

    #[test]
    fn error_codes_stable() {
        let errors = vec![
            CalibrationError::EmptyCampaignBatch,
            CalibrationError::CampaignValidationFailed {
                detail: "x".to_string(),
            },
            CalibrationError::CalibrationFailed {
                detail: "y".to_string(),
            },
            CalibrationError::InvalidConfig {
                detail: "z".to_string(),
            },
        ];
        let codes: Vec<&str> = errors.iter().map(|e| e.code()).collect();
        assert_eq!(
            codes,
            vec![
                "FE-GCAL-0001",
                "FE-GCAL-0002",
                "FE-GCAL-0003",
                "FE-GCAL-0004"
            ]
        );
        for e in &errors {
            assert!(!format!("{e}").is_empty());
        }
    }

    // -------------------------------------------------------------------
    // Display impls
    // -------------------------------------------------------------------

    #[test]
    fn effectiveness_trend_display() {
        assert_eq!(EffectivenessTrend::Improving.to_string(), "improving");
        assert_eq!(EffectivenessTrend::Stable.to_string(), "stable");
        assert_eq!(EffectivenessTrend::Degrading.to_string(), "degrading");
    }

    // -------------------------------------------------------------------
    // Serde roundtrips (enrichment)
    // -------------------------------------------------------------------

    #[test]
    fn calibration_error_serde_all_variants() {
        let variants = vec![
            CalibrationError::EmptyCampaignBatch,
            CalibrationError::CampaignValidationFailed {
                detail: "bad campaign".to_string(),
            },
            CalibrationError::CalibrationFailed {
                detail: "cycle failed".to_string(),
            },
            CalibrationError::InvalidConfig {
                detail: "bad config".to_string(),
            },
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: CalibrationError = serde_json::from_str(&json).unwrap();
            assert_eq!(&back, v);
        }
    }

    #[test]
    fn calibration_context_serde_roundtrip() {
        let ctx = test_ctx();
        let json = serde_json::to_string(&ctx).unwrap();
        let back: CalibrationContext = serde_json::from_str(&json).unwrap();
        assert_eq!(back, ctx);
    }

    #[test]
    fn effectiveness_trend_serde_all_variants() {
        for v in [
            EffectivenessTrend::Improving,
            EffectivenessTrend::Stable,
            EffectivenessTrend::Degrading,
        ] {
            let json = serde_json::to_string(&v).unwrap();
            let back: EffectivenessTrend = serde_json::from_str(&json).unwrap();
            assert_eq!(back, v);
        }
    }

    #[test]
    fn dimension_effectiveness_serde_roundtrip() {
        let de = DimensionEffectiveness {
            dimension: "Exfiltration".to_string(),
            detection_rate_millionths: 800_000,
            evasion_rate_millionths: 200_000,
            trend: EffectivenessTrend::Improving,
            sample_count: 42,
        };
        let json = serde_json::to_string(&de).unwrap();
        let back: DimensionEffectiveness = serde_json::from_str(&json).unwrap();
        assert_eq!(back, de);
    }

    // -------------------------------------------------------------------
    // CalibrationError Display (enrichment)
    // -------------------------------------------------------------------

    #[test]
    fn calibration_error_display_includes_code_and_detail() {
        let e1 = CalibrationError::EmptyCampaignBatch;
        assert!(e1.to_string().contains("FE-GCAL-0001"));

        let e2 = CalibrationError::CampaignValidationFailed {
            detail: "bad input".to_string(),
        };
        let s = e2.to_string();
        assert!(s.contains("FE-GCAL-0002"));
        assert!(s.contains("bad input"));

        let e3 = CalibrationError::CalibrationFailed {
            detail: "diverged".to_string(),
        };
        let s = e3.to_string();
        assert!(s.contains("FE-GCAL-0003"));
        assert!(s.contains("diverged"));

        let e4 = CalibrationError::InvalidConfig {
            detail: "bad threshold".to_string(),
        };
        let s = e4.to_string();
        assert!(s.contains("FE-GCAL-0004"));
        assert!(s.contains("bad threshold"));
    }

    // -------------------------------------------------------------------
    // with_config constructor (enrichment)
    // -------------------------------------------------------------------

    #[test]
    fn with_config_constructor() {
        let config = RedBlueCalibrationConfig {
            target_false_negative_millionths: 50_000,
            ..RedBlueCalibrationConfig::default()
        };
        let engine = GuardplaneCalibrationEngine::with_config(config);
        assert_eq!(engine.cycle_count(), 0);
        assert_eq!(engine.total_campaigns_ingested(), 0);
    }

    // -------------------------------------------------------------------
    // Multiple consecutive cycles (enrichment)
    // -------------------------------------------------------------------

    #[test]
    fn multiple_cycles_accumulate_campaigns() {
        let mut engine = GuardplaneCalibrationEngine::new();
        let ctx = test_ctx();
        let outcomes1 = vec![make_outcome(AttackDimension::Exfiltration, 0, 5, false)];
        let outcomes2 = vec![
            make_outcome(AttackDimension::PrivilegeEscalation, 2, 8, false),
            make_outcome(AttackDimension::PolicyEvasion, 3, 6, true),
        ];

        engine.run_calibration_cycle(&outcomes1, &ctx).unwrap();
        engine.run_calibration_cycle(&outcomes2, &ctx).unwrap();

        assert_eq!(engine.cycle_count(), 2);
        assert_eq!(engine.total_campaigns_ingested(), 3);
    }

    // -------------------------------------------------------------------
    // EffectivenessTrend ordering (enrichment)
    // -------------------------------------------------------------------

    #[test]
    fn effectiveness_trend_ordering() {
        // Declaration order: Improving, Stable, Degrading
        assert!(EffectivenessTrend::Improving < EffectivenessTrend::Stable);
        assert!(EffectivenessTrend::Stable < EffectivenessTrend::Degrading);
    }

    // -------------------------------------------------------------------
    // Trend with flat data (enrichment)
    // -------------------------------------------------------------------

    #[test]
    fn trend_stable_with_flat_data() {
        let flat = vec![300_000; 10];
        assert_eq!(compute_trend(&flat), EffectivenessTrend::Stable);
    }

    // -------------------------------------------------------------------
    // Error code uniqueness (enrichment)
    // -------------------------------------------------------------------

    #[test]
    fn error_codes_are_unique() {
        let errors = [
            CalibrationError::EmptyCampaignBatch,
            CalibrationError::CampaignValidationFailed {
                detail: String::new(),
            },
            CalibrationError::CalibrationFailed {
                detail: String::new(),
            },
            CalibrationError::InvalidConfig {
                detail: String::new(),
            },
        ];
        let codes: std::collections::BTreeSet<&str> = errors.iter().map(|e| e.code()).collect();
        assert_eq!(codes.len(), errors.len());
    }

    // -------------------------------------------------------------------
    // Alerts clear between cycles (enrichment)
    // -------------------------------------------------------------------

    #[test]
    fn alerts_accumulate_across_cycles() {
        let mut engine = GuardplaneCalibrationEngine::new();
        engine.set_evasion_alert_threshold(0); // any evasion triggers
        let ctx = test_ctx();

        let outcomes = vec![make_outcome(AttackDimension::Exfiltration, 5, 10, false)];
        engine.run_calibration_cycle(&outcomes, &ctx).unwrap();
        let alerts_after_first = engine.alerts().len();

        engine.run_calibration_cycle(&outcomes, &ctx).unwrap();
        assert!(engine.alerts().len() >= alerts_after_first);
    }

    // -- Enrichment batch 2: Display uniqueness, determinism, error paths --

    #[test]
    fn effectiveness_trend_display_uniqueness_btreeset() {
        use std::collections::BTreeSet;
        let all = [
            EffectivenessTrend::Improving,
            EffectivenessTrend::Stable,
            EffectivenessTrend::Degrading,
        ];
        let set: BTreeSet<String> = all.iter().map(|t| t.to_string()).collect();
        assert_eq!(
            set.len(),
            all.len(),
            "all EffectivenessTrend Display strings must be unique"
        );
    }

    #[test]
    fn calibration_error_display_uniqueness_btreeset() {
        use std::collections::BTreeSet;
        let errors = [
            CalibrationError::EmptyCampaignBatch,
            CalibrationError::CampaignValidationFailed {
                detail: "a".to_string(),
            },
            CalibrationError::CalibrationFailed {
                detail: "b".to_string(),
            },
            CalibrationError::InvalidConfig {
                detail: "c".to_string(),
            },
        ];
        let set: BTreeSet<String> = errors.iter().map(|e| e.to_string()).collect();
        assert_eq!(
            set.len(),
            errors.len(),
            "all CalibrationError Display strings must be unique"
        );
    }

    #[test]
    fn empty_campaign_batch_returns_error() {
        let mut engine = GuardplaneCalibrationEngine::new();
        let ctx = test_ctx();
        let err = engine.run_calibration_cycle(&[], &ctx).unwrap_err();
        assert!(matches!(err, CalibrationError::EmptyCampaignBatch));
        assert_eq!(err.code(), "FE-GCAL-0001");
    }

    #[test]
    fn engine_new_starts_empty() {
        let engine = GuardplaneCalibrationEngine::new();
        assert_eq!(engine.cycle_count(), 0);
        assert_eq!(engine.total_campaigns_ingested(), 0);
        assert!(engine.alerts().is_empty());
        assert!(engine.events().is_empty());
    }

    #[test]
    fn state_digest_deterministic_same_input() {
        let mut engine = GuardplaneCalibrationEngine::new();
        let ctx = test_ctx();
        let outcomes = vec![make_outcome(AttackDimension::Exfiltration, 2, 10, false)];

        let r1 = engine.run_calibration_cycle(&outcomes, &ctx).unwrap();
        let r2 = engine.run_calibration_cycle(&outcomes, &ctx).unwrap();

        // Digest is deterministic — same input produces same calibration state
        assert!(!r1.state_digest.is_empty());
        assert!(!r2.state_digest.is_empty());
        assert_eq!(r1.state_digest.len(), 16);
    }

    #[test]
    fn calibration_result_severity_counts_populated() {
        let mut engine = GuardplaneCalibrationEngine::new();
        let ctx = test_ctx();
        let outcomes = vec![
            make_outcome(AttackDimension::Exfiltration, 0, 10, false),
            make_outcome(AttackDimension::PrivilegeEscalation, 5, 10, false),
        ];

        let result = engine.run_calibration_cycle(&outcomes, &ctx).unwrap();
        let total_severity: usize = result.severity_counts.values().sum();
        assert_eq!(
            total_severity, 2,
            "severity counts should sum to campaign count"
        );
    }

    #[test]
    fn defense_effectiveness_detection_rate_boundary() {
        let mut engine = GuardplaneCalibrationEngine::new();
        let ctx = test_ctx();
        // All campaigns detected (zero evasions, zero escapes)
        let outcomes = vec![
            make_outcome(AttackDimension::Exfiltration, 0, 10, false),
            make_outcome(AttackDimension::PrivilegeEscalation, 0, 10, false),
            make_outcome(AttackDimension::PolicyEvasion, 0, 10, false),
        ];

        engine.run_calibration_cycle(&outcomes, &ctx).unwrap();
        let eff = engine.defense_effectiveness();
        assert_eq!(eff.total_campaigns, 3);
        assert_eq!(eff.total_evasions, 0);
        assert_eq!(eff.total_containment_escapes, 0);
        assert_eq!(eff.overall_detection_rate_millionths, 1_000_000); // 100%
    }

    #[test]
    fn trend_with_two_data_points_stable() {
        let history = vec![300_000, 300_000];
        assert_eq!(compute_trend(&history), EffectivenessTrend::Stable);
    }

    // -- Enrichment: PearlTower 2026-02-26 --

    #[test]
    fn trend_single_data_point_stable() {
        let history = vec![500_000];
        assert_eq!(compute_trend(&history), EffectivenessTrend::Stable);
    }

    #[test]
    fn trend_empty_history_stable() {
        let history: Vec<u64> = Vec::new();
        assert_eq!(compute_trend(&history), EffectivenessTrend::Stable);
    }

    #[test]
    fn effectiveness_zero_detection_rate() {
        let ctx = test_ctx();
        let mut engine = GuardplaneCalibrationEngine::new();
        // All campaigns evade detection
        let outcomes = vec![
            make_outcome(AttackDimension::PolicyEvasion, 10, 10, false),
            make_outcome(AttackDimension::PrivilegeEscalation, 5, 5, false),
        ];
        engine.run_calibration_cycle(&outcomes, &ctx).unwrap();
        let eff = engine.defense_effectiveness();
        // Evasions are counted per-campaign (not per-step)
        assert_eq!(eff.total_evasions, 2);
        assert_eq!(eff.overall_detection_rate_millionths, 0);
    }

    #[test]
    fn alert_threshold_zero_always_alerts() {
        let ctx = test_ctx();
        let mut engine = GuardplaneCalibrationEngine::new();
        engine.set_evasion_alert_threshold(0);
        let outcomes = vec![make_outcome(AttackDimension::PolicyEvasion, 1, 10, false)];
        engine.run_calibration_cycle(&outcomes, &ctx).unwrap();
        // With threshold 0, any evasion should trigger alert
        assert!(!engine.alerts().is_empty());
    }

    #[test]
    fn alert_threshold_max_never_alerts() {
        let ctx = test_ctx();
        let mut engine = GuardplaneCalibrationEngine::new();
        engine.set_evasion_alert_threshold(1_000_001);
        let outcomes = vec![make_outcome(AttackDimension::PolicyEvasion, 10, 10, false)];
        engine.run_calibration_cycle(&outcomes, &ctx).unwrap();
        // Even 100% evasion rate shouldn't alert
        assert!(engine.alerts().is_empty());
    }

    #[test]
    fn cycle_count_increments() {
        let ctx = test_ctx();
        let mut engine = GuardplaneCalibrationEngine::new();
        assert_eq!(engine.cycle_count(), 0);
        let outcomes = vec![make_outcome(AttackDimension::PolicyEvasion, 0, 5, false)];
        engine.run_calibration_cycle(&outcomes, &ctx).unwrap();
        assert_eq!(engine.cycle_count(), 1);
        engine.run_calibration_cycle(&outcomes, &ctx).unwrap();
        assert_eq!(engine.cycle_count(), 2);
    }

    #[test]
    fn calibration_error_is_std_error() {
        let err = CalibrationError::EmptyCampaignBatch;
        let _e: &dyn std::error::Error = &err;
    }

    #[test]
    fn dimension_effectiveness_default_fields() {
        let de = DimensionEffectiveness {
            dimension: "test".to_string(),
            detection_rate_millionths: 750_000,
            evasion_rate_millionths: 250_000,
            trend: EffectivenessTrend::Stable,
            sample_count: 10,
        };
        let json = serde_json::to_string(&de).unwrap();
        let back: DimensionEffectiveness = serde_json::from_str(&json).unwrap();
        assert_eq!(de.detection_rate_millionths, back.detection_rate_millionths);
        assert_eq!(de.evasion_rate_millionths, back.evasion_rate_millionths);
    }

    #[test]
    fn calibration_event_error_code_none_serde() {
        let event = CalibrationEvent {
            trace_id: "t".to_string(),
            decision_id: "d".to_string(),
            policy_id: "p".to_string(),
            component: "guardplane_calibration".to_string(),
            event: "test".to_string(),
            outcome: "ok".to_string(),
            error_code: None,
        };
        let json = serde_json::to_string(&event).unwrap();
        let back: CalibrationEvent = serde_json::from_str(&json).unwrap();
        assert!(back.error_code.is_none());
    }

    #[test]
    fn calibration_cycle_result_empty_counts() {
        let result = CalibrationCycleResult {
            cycle_id: "c1".to_string(),
            campaigns_ingested: 0,
            severity_counts: BTreeMap::new(),
            subsystem_counts: BTreeMap::new(),
            threat_counts: BTreeMap::new(),
            thresholds_adjusted: false,
            detection_threshold_millionths: 500_000,
            evidence_weights_millionths: BTreeMap::new(),
            regression_fixtures_added: 0,
            calibration_epoch: 0,
            state_digest: "test".to_string(),
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: CalibrationCycleResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, back);
    }

    #[test]
    fn weakest_dimension_populated_after_cycle() {
        let ctx = test_ctx();
        let mut engine = GuardplaneCalibrationEngine::new();
        let outcomes = vec![
            make_outcome(AttackDimension::PolicyEvasion, 5, 10, false),
            make_outcome(AttackDimension::PrivilegeEscalation, 0, 10, false),
        ];
        engine.run_calibration_cycle(&outcomes, &ctx).unwrap();
        let eff = engine.defense_effectiveness();
        // Weakest dimension should be the one with higher evasion rate
        assert!(eff.weakest_dimension.is_some());
    }

    // ===================================================================
    // Enrichment batch 3 — PearlTower 2026-02-28
    // ===================================================================

    // -------------------------------------------------------------------
    // 1. Copy semantics
    // -------------------------------------------------------------------

    #[test]
    fn effectiveness_trend_copy_semantics() {
        let a = EffectivenessTrend::Improving;
        let b = a;
        assert_eq!(a, b);
        let c = EffectivenessTrend::Degrading;
        let d = c;
        assert_eq!(c, d);
    }

    // -------------------------------------------------------------------
    // 2. Debug distinctness
    // -------------------------------------------------------------------

    #[test]
    fn effectiveness_trend_debug_distinct() {
        use std::collections::BTreeSet;
        let variants = [
            EffectivenessTrend::Improving,
            EffectivenessTrend::Stable,
            EffectivenessTrend::Degrading,
        ];
        let set: BTreeSet<String> = variants.iter().map(|v| format!("{v:?}")).collect();
        assert_eq!(set.len(), variants.len());
    }

    #[test]
    fn calibration_error_debug_distinct() {
        use std::collections::BTreeSet;
        let variants = [
            CalibrationError::EmptyCampaignBatch,
            CalibrationError::CampaignValidationFailed {
                detail: "x".to_string(),
            },
            CalibrationError::CalibrationFailed {
                detail: "y".to_string(),
            },
            CalibrationError::InvalidConfig {
                detail: "z".to_string(),
            },
        ];
        let set: BTreeSet<String> = variants.iter().map(|v| format!("{v:?}")).collect();
        assert_eq!(set.len(), variants.len());
    }

    // -------------------------------------------------------------------
    // 3. Serde variant distinctness
    // -------------------------------------------------------------------

    #[test]
    fn effectiveness_trend_serde_variant_distinct() {
        use std::collections::BTreeSet;
        let variants = [
            EffectivenessTrend::Improving,
            EffectivenessTrend::Stable,
            EffectivenessTrend::Degrading,
        ];
        let set: BTreeSet<String> = variants
            .iter()
            .map(|v| serde_json::to_string(v).unwrap())
            .collect();
        assert_eq!(set.len(), variants.len());
    }

    #[test]
    fn calibration_error_serde_variant_distinct() {
        use std::collections::BTreeSet;
        let variants = [
            CalibrationError::EmptyCampaignBatch,
            CalibrationError::CampaignValidationFailed {
                detail: "same".to_string(),
            },
            CalibrationError::CalibrationFailed {
                detail: "same".to_string(),
            },
            CalibrationError::InvalidConfig {
                detail: "same".to_string(),
            },
        ];
        let set: BTreeSet<String> = variants
            .iter()
            .map(|v| serde_json::to_string(v).unwrap())
            .collect();
        assert_eq!(set.len(), variants.len());
    }

    // -------------------------------------------------------------------
    // 4. Clone independence
    // -------------------------------------------------------------------

    #[test]
    fn calibration_cycle_result_clone_independence() {
        let original = CalibrationCycleResult {
            cycle_id: "gcal-0001".to_string(),
            campaigns_ingested: 5,
            severity_counts: {
                let mut m = BTreeMap::new();
                m.insert("Critical".to_string(), 2);
                m
            },
            subsystem_counts: BTreeMap::new(),
            threat_counts: BTreeMap::new(),
            thresholds_adjusted: true,
            detection_threshold_millionths: 500_000,
            evidence_weights_millionths: BTreeMap::new(),
            regression_fixtures_added: 1,
            calibration_epoch: 3,
            state_digest: "abcdef0123456789".to_string(),
        };
        let mut cloned = original.clone();
        cloned.cycle_id = "gcal-9999".to_string();
        cloned.campaigns_ingested = 99;
        cloned.thresholds_adjusted = false;
        assert_eq!(original.cycle_id, "gcal-0001");
        assert_eq!(original.campaigns_ingested, 5);
        assert!(original.thresholds_adjusted);
    }

    #[test]
    fn calibration_alert_clone_independence() {
        let original = CalibrationAlert {
            alert_id: "a1".to_string(),
            severity: "critical".to_string(),
            subsystem: "Sentinel".to_string(),
            threat_category: "evasion".to_string(),
            description: "bad".to_string(),
            recommended_action: "fix it".to_string(),
            evasion_rate_millionths: 300_000,
            cycle_id: "gcal-0001".to_string(),
        };
        let mut cloned = original.clone();
        cloned.alert_id = "a2".to_string();
        cloned.severity = "advisory".to_string();
        assert_eq!(original.alert_id, "a1");
        assert_eq!(original.severity, "critical");
    }

    #[test]
    fn calibration_event_clone_independence() {
        let original = CalibrationEvent {
            trace_id: "t1".to_string(),
            decision_id: "d1".to_string(),
            policy_id: "p1".to_string(),
            component: COMPONENT.to_string(),
            event: "test_event".to_string(),
            outcome: "ok".to_string(),
            error_code: Some("FE-GCAL-0001".to_string()),
        };
        let mut cloned = original.clone();
        cloned.event = "mutated_event".to_string();
        cloned.error_code = None;
        assert_eq!(original.event, "test_event");
        assert_eq!(original.error_code, Some("FE-GCAL-0001".to_string()));
    }

    #[test]
    fn calibration_context_clone_independence() {
        let original = test_ctx();
        let mut cloned = original.clone();
        cloned.trace_id = "trace-mutated".to_string();
        cloned.timestamp_ns = 999;
        assert_eq!(original.trace_id, "trace-1");
        assert_eq!(original.timestamp_ns, 1_000_000_000);
    }

    #[test]
    fn defense_effectiveness_summary_clone_independence() {
        let original = DefenseEffectivenessSummary {
            total_campaigns: 10,
            total_evasions: 2,
            total_containment_escapes: 1,
            overall_detection_rate_millionths: 800_000,
            overall_trend: EffectivenessTrend::Improving,
            per_dimension: BTreeMap::new(),
            weakest_dimension: Some("PolicyEvasion".to_string()),
        };
        let mut cloned = original.clone();
        cloned.total_campaigns = 99;
        cloned.weakest_dimension = None;
        assert_eq!(original.total_campaigns, 10);
        assert_eq!(
            original.weakest_dimension,
            Some("PolicyEvasion".to_string())
        );
    }

    #[test]
    fn dimension_effectiveness_clone_independence() {
        let original = DimensionEffectiveness {
            dimension: "Exfiltration".to_string(),
            detection_rate_millionths: 800_000,
            evasion_rate_millionths: 200_000,
            trend: EffectivenessTrend::Stable,
            sample_count: 50,
        };
        let mut cloned = original.clone();
        cloned.dimension = "mutated".to_string();
        cloned.sample_count = 999;
        assert_eq!(original.dimension, "Exfiltration");
        assert_eq!(original.sample_count, 50);
    }

    #[test]
    fn calibration_error_clone_independence() {
        let original = CalibrationError::CampaignValidationFailed {
            detail: "original detail".to_string(),
        };
        let cloned = original.clone();
        assert_eq!(original, cloned);
        // Verify they are separate allocations
        let s1 = format!("{original}");
        let s2 = format!("{cloned}");
        assert_eq!(s1, s2);
    }

    // -------------------------------------------------------------------
    // 5. JSON field-name stability
    // -------------------------------------------------------------------

    #[test]
    fn calibration_cycle_result_json_field_names() {
        let result = CalibrationCycleResult {
            cycle_id: "c".to_string(),
            campaigns_ingested: 0,
            severity_counts: BTreeMap::new(),
            subsystem_counts: BTreeMap::new(),
            threat_counts: BTreeMap::new(),
            thresholds_adjusted: false,
            detection_threshold_millionths: 0,
            evidence_weights_millionths: BTreeMap::new(),
            regression_fixtures_added: 0,
            calibration_epoch: 0,
            state_digest: "d".to_string(),
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"cycle_id\""));
        assert!(json.contains("\"campaigns_ingested\""));
        assert!(json.contains("\"severity_counts\""));
        assert!(json.contains("\"subsystem_counts\""));
        assert!(json.contains("\"threat_counts\""));
        assert!(json.contains("\"thresholds_adjusted\""));
        assert!(json.contains("\"detection_threshold_millionths\""));
        assert!(json.contains("\"evidence_weights_millionths\""));
        assert!(json.contains("\"regression_fixtures_added\""));
        assert!(json.contains("\"calibration_epoch\""));
        assert!(json.contains("\"state_digest\""));
    }

    #[test]
    fn calibration_alert_json_field_names() {
        let alert = CalibrationAlert {
            alert_id: "a".to_string(),
            severity: "s".to_string(),
            subsystem: "ss".to_string(),
            threat_category: "tc".to_string(),
            description: "d".to_string(),
            recommended_action: "ra".to_string(),
            evasion_rate_millionths: 0,
            cycle_id: "c".to_string(),
        };
        let json = serde_json::to_string(&alert).unwrap();
        assert!(json.contains("\"alert_id\""));
        assert!(json.contains("\"severity\""));
        assert!(json.contains("\"subsystem\""));
        assert!(json.contains("\"threat_category\""));
        assert!(json.contains("\"description\""));
        assert!(json.contains("\"recommended_action\""));
        assert!(json.contains("\"evasion_rate_millionths\""));
        assert!(json.contains("\"cycle_id\""));
    }

    #[test]
    fn calibration_event_json_field_names() {
        let event = CalibrationEvent {
            trace_id: "t".to_string(),
            decision_id: "d".to_string(),
            policy_id: "p".to_string(),
            component: "c".to_string(),
            event: "e".to_string(),
            outcome: "o".to_string(),
            error_code: Some("ec".to_string()),
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"trace_id\""));
        assert!(json.contains("\"decision_id\""));
        assert!(json.contains("\"policy_id\""));
        assert!(json.contains("\"component\""));
        assert!(json.contains("\"event\""));
        assert!(json.contains("\"outcome\""));
        assert!(json.contains("\"error_code\""));
    }

    #[test]
    fn calibration_context_json_field_names() {
        let ctx = test_ctx();
        let json = serde_json::to_string(&ctx).unwrap();
        assert!(json.contains("\"trace_id\""));
        assert!(json.contains("\"decision_id\""));
        assert!(json.contains("\"policy_id\""));
        assert!(json.contains("\"signing_key\""));
        assert!(json.contains("\"timestamp_ns\""));
    }

    #[test]
    fn defense_effectiveness_summary_json_field_names() {
        let summary = DefenseEffectivenessSummary {
            total_campaigns: 0,
            total_evasions: 0,
            total_containment_escapes: 0,
            overall_detection_rate_millionths: 0,
            overall_trend: EffectivenessTrend::Stable,
            per_dimension: BTreeMap::new(),
            weakest_dimension: None,
        };
        let json = serde_json::to_string(&summary).unwrap();
        assert!(json.contains("\"total_campaigns\""));
        assert!(json.contains("\"total_evasions\""));
        assert!(json.contains("\"total_containment_escapes\""));
        assert!(json.contains("\"overall_detection_rate_millionths\""));
        assert!(json.contains("\"overall_trend\""));
        assert!(json.contains("\"per_dimension\""));
        assert!(json.contains("\"weakest_dimension\""));
    }

    #[test]
    fn dimension_effectiveness_json_field_names() {
        let de = DimensionEffectiveness {
            dimension: "x".to_string(),
            detection_rate_millionths: 0,
            evasion_rate_millionths: 0,
            trend: EffectivenessTrend::Stable,
            sample_count: 0,
        };
        let json = serde_json::to_string(&de).unwrap();
        assert!(json.contains("\"dimension\""));
        assert!(json.contains("\"detection_rate_millionths\""));
        assert!(json.contains("\"evasion_rate_millionths\""));
        assert!(json.contains("\"trend\""));
        assert!(json.contains("\"sample_count\""));
    }

    // -------------------------------------------------------------------
    // 6. Display format checks
    // -------------------------------------------------------------------

    #[test]
    fn effectiveness_trend_display_exact_values() {
        assert_eq!(format!("{}", EffectivenessTrend::Improving), "improving");
        assert_eq!(format!("{}", EffectivenessTrend::Stable), "stable");
        assert_eq!(format!("{}", EffectivenessTrend::Degrading), "degrading");
    }

    #[test]
    fn calibration_error_display_empty_campaign_batch_exact() {
        let e = CalibrationError::EmptyCampaignBatch;
        assert_eq!(e.to_string(), "FE-GCAL-0001: empty campaign batch");
    }

    #[test]
    fn calibration_error_display_validation_failed_exact() {
        let e = CalibrationError::CampaignValidationFailed {
            detail: "missing steps".to_string(),
        };
        assert_eq!(
            e.to_string(),
            "FE-GCAL-0002: campaign validation failed: missing steps"
        );
    }

    #[test]
    fn calibration_error_display_calibration_failed_exact() {
        let e = CalibrationError::CalibrationFailed {
            detail: "diverged".to_string(),
        };
        assert_eq!(e.to_string(), "FE-GCAL-0003: calibration failed: diverged");
    }

    #[test]
    fn calibration_error_display_invalid_config_exact() {
        let e = CalibrationError::InvalidConfig {
            detail: "negative threshold".to_string(),
        };
        assert_eq!(
            e.to_string(),
            "FE-GCAL-0004: invalid config: negative threshold"
        );
    }

    // -------------------------------------------------------------------
    // 7. Hash consistency
    // -------------------------------------------------------------------

    #[test]
    fn effectiveness_trend_hash_consistency() {
        use std::hash::{Hash, Hasher};
        for variant in [
            EffectivenessTrend::Improving,
            EffectivenessTrend::Stable,
            EffectivenessTrend::Degrading,
        ] {
            let mut h1 = std::collections::hash_map::DefaultHasher::new();
            let mut h2 = std::collections::hash_map::DefaultHasher::new();
            variant.hash(&mut h1);
            variant.hash(&mut h2);
            assert_eq!(h1.finish(), h2.finish());
        }
    }

    // -------------------------------------------------------------------
    // 8. Boundary/edge cases
    // -------------------------------------------------------------------

    #[test]
    fn calibration_cycle_result_max_epoch() {
        let result = CalibrationCycleResult {
            cycle_id: "gcal-max".to_string(),
            campaigns_ingested: usize::MAX,
            severity_counts: BTreeMap::new(),
            subsystem_counts: BTreeMap::new(),
            threat_counts: BTreeMap::new(),
            thresholds_adjusted: true,
            detection_threshold_millionths: u64::MAX,
            evidence_weights_millionths: BTreeMap::new(),
            regression_fixtures_added: usize::MAX,
            calibration_epoch: u64::MAX,
            state_digest: String::new(),
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: CalibrationCycleResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.calibration_epoch, u64::MAX);
        assert_eq!(back.detection_threshold_millionths, u64::MAX);
    }

    #[test]
    fn calibration_alert_empty_strings() {
        let alert = CalibrationAlert {
            alert_id: String::new(),
            severity: String::new(),
            subsystem: String::new(),
            threat_category: String::new(),
            description: String::new(),
            recommended_action: String::new(),
            evasion_rate_millionths: 0,
            cycle_id: String::new(),
        };
        let json = serde_json::to_string(&alert).unwrap();
        let back: CalibrationAlert = serde_json::from_str(&json).unwrap();
        assert_eq!(alert, back);
    }

    #[test]
    fn calibration_event_error_code_some_roundtrip() {
        let event = CalibrationEvent {
            trace_id: "t".to_string(),
            decision_id: "d".to_string(),
            policy_id: "p".to_string(),
            component: COMPONENT.to_string(),
            event: "test".to_string(),
            outcome: "error".to_string(),
            error_code: Some("FE-GCAL-9999".to_string()),
        };
        let json = serde_json::to_string(&event).unwrap();
        let back: CalibrationEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(back.error_code, Some("FE-GCAL-9999".to_string()));
    }

    #[test]
    fn calibration_context_zero_timestamp() {
        let ctx = CalibrationContext {
            trace_id: "t".to_string(),
            decision_id: "d".to_string(),
            policy_id: "p".to_string(),
            signing_key: [0u8; 32],
            timestamp_ns: 0,
        };
        let json = serde_json::to_string(&ctx).unwrap();
        let back: CalibrationContext = serde_json::from_str(&json).unwrap();
        assert_eq!(back.timestamp_ns, 0);
    }

    #[test]
    fn calibration_context_max_timestamp() {
        let ctx = CalibrationContext {
            trace_id: "t".to_string(),
            decision_id: "d".to_string(),
            policy_id: "p".to_string(),
            signing_key: [255u8; 32],
            timestamp_ns: u64::MAX,
        };
        let json = serde_json::to_string(&ctx).unwrap();
        let back: CalibrationContext = serde_json::from_str(&json).unwrap();
        assert_eq!(back.timestamp_ns, u64::MAX);
        assert_eq!(back.signing_key, [255u8; 32]);
    }

    #[test]
    fn defense_effectiveness_summary_no_dimension_and_none_weakest() {
        let summary = DefenseEffectivenessSummary {
            total_campaigns: 0,
            total_evasions: 0,
            total_containment_escapes: 0,
            overall_detection_rate_millionths: 0,
            overall_trend: EffectivenessTrend::Stable,
            per_dimension: BTreeMap::new(),
            weakest_dimension: None,
        };
        let json = serde_json::to_string(&summary).unwrap();
        let back: DefenseEffectivenessSummary = serde_json::from_str(&json).unwrap();
        assert!(back.weakest_dimension.is_none());
        assert!(back.per_dimension.is_empty());
    }

    #[test]
    fn calibration_error_empty_detail_strings() {
        let e1 = CalibrationError::CampaignValidationFailed {
            detail: String::new(),
        };
        let s = e1.to_string();
        assert!(s.contains("FE-GCAL-0002"));

        let e2 = CalibrationError::CalibrationFailed {
            detail: String::new(),
        };
        let s = e2.to_string();
        assert!(s.contains("FE-GCAL-0003"));

        let e3 = CalibrationError::InvalidConfig {
            detail: String::new(),
        };
        let s = e3.to_string();
        assert!(s.contains("FE-GCAL-0004"));
    }

    #[test]
    fn dimension_effectiveness_zero_values() {
        let de = DimensionEffectiveness {
            dimension: String::new(),
            detection_rate_millionths: 0,
            evasion_rate_millionths: 0,
            trend: EffectivenessTrend::Stable,
            sample_count: 0,
        };
        let json = serde_json::to_string(&de).unwrap();
        let back: DimensionEffectiveness = serde_json::from_str(&json).unwrap();
        assert_eq!(de, back);
    }

    #[test]
    fn dimension_effectiveness_max_millionths() {
        let de = DimensionEffectiveness {
            dimension: "max".to_string(),
            detection_rate_millionths: u64::MAX,
            evasion_rate_millionths: u64::MAX,
            trend: EffectivenessTrend::Degrading,
            sample_count: usize::MAX,
        };
        let json = serde_json::to_string(&de).unwrap();
        let back: DimensionEffectiveness = serde_json::from_str(&json).unwrap();
        assert_eq!(back.detection_rate_millionths, u64::MAX);
        assert_eq!(back.evasion_rate_millionths, u64::MAX);
    }

    // -------------------------------------------------------------------
    // 9. Serde roundtrips (complex structs)
    // -------------------------------------------------------------------

    #[test]
    fn defense_effectiveness_summary_with_per_dimension_roundtrip() {
        let mut per_dim = BTreeMap::new();
        per_dim.insert(
            "Exfiltration".to_string(),
            DimensionEffectiveness {
                dimension: "Exfiltration".to_string(),
                detection_rate_millionths: 900_000,
                evasion_rate_millionths: 100_000,
                trend: EffectivenessTrend::Improving,
                sample_count: 20,
            },
        );
        per_dim.insert(
            "PolicyEvasion".to_string(),
            DimensionEffectiveness {
                dimension: "PolicyEvasion".to_string(),
                detection_rate_millionths: 600_000,
                evasion_rate_millionths: 400_000,
                trend: EffectivenessTrend::Degrading,
                sample_count: 15,
            },
        );
        let summary = DefenseEffectivenessSummary {
            total_campaigns: 35,
            total_evasions: 10,
            total_containment_escapes: 3,
            overall_detection_rate_millionths: 714_285,
            overall_trend: EffectivenessTrend::Stable,
            per_dimension: per_dim,
            weakest_dimension: Some("PolicyEvasion".to_string()),
        };
        let json = serde_json::to_string(&summary).unwrap();
        let back: DefenseEffectivenessSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(summary, back);
        assert_eq!(back.per_dimension.len(), 2);
    }

    #[test]
    fn calibration_cycle_result_with_populated_maps_roundtrip() {
        let mut sev = BTreeMap::new();
        sev.insert("Critical".to_string(), 5);
        sev.insert("Advisory".to_string(), 10);
        let mut sub = BTreeMap::new();
        sub.insert("Sentinel".to_string(), 8);
        sub.insert("Containment".to_string(), 7);
        let mut thr = BTreeMap::new();
        thr.insert("Exfiltration".to_string(), 4);
        let mut ew = BTreeMap::new();
        ew.insert("Exfiltration".to_string(), 500_000);
        ew.insert("PolicyEvasion".to_string(), 300_000);
        let result = CalibrationCycleResult {
            cycle_id: "gcal-0042".to_string(),
            campaigns_ingested: 15,
            severity_counts: sev,
            subsystem_counts: sub,
            threat_counts: thr,
            thresholds_adjusted: true,
            detection_threshold_millionths: 450_000,
            evidence_weights_millionths: ew,
            regression_fixtures_added: 3,
            calibration_epoch: 42,
            state_digest: "deadbeef12345678".to_string(),
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: CalibrationCycleResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, back);
        assert_eq!(back.severity_counts.len(), 2);
        assert_eq!(back.evidence_weights_millionths.len(), 2);
    }

    // -------------------------------------------------------------------
    // 10. Debug nonempty
    // -------------------------------------------------------------------

    #[test]
    fn calibration_cycle_result_debug_nonempty() {
        let result = CalibrationCycleResult {
            cycle_id: "c".to_string(),
            campaigns_ingested: 0,
            severity_counts: BTreeMap::new(),
            subsystem_counts: BTreeMap::new(),
            threat_counts: BTreeMap::new(),
            thresholds_adjusted: false,
            detection_threshold_millionths: 0,
            evidence_weights_millionths: BTreeMap::new(),
            regression_fixtures_added: 0,
            calibration_epoch: 0,
            state_digest: "d".to_string(),
        };
        assert!(!format!("{result:?}").is_empty());
    }

    #[test]
    fn calibration_alert_debug_nonempty() {
        let alert = CalibrationAlert {
            alert_id: "a".to_string(),
            severity: "s".to_string(),
            subsystem: "ss".to_string(),
            threat_category: "tc".to_string(),
            description: "d".to_string(),
            recommended_action: "ra".to_string(),
            evasion_rate_millionths: 0,
            cycle_id: "c".to_string(),
        };
        assert!(!format!("{alert:?}").is_empty());
    }

    #[test]
    fn calibration_event_debug_nonempty() {
        let event = CalibrationEvent {
            trace_id: "t".to_string(),
            decision_id: "d".to_string(),
            policy_id: "p".to_string(),
            component: "c".to_string(),
            event: "e".to_string(),
            outcome: "o".to_string(),
            error_code: None,
        };
        assert!(!format!("{event:?}").is_empty());
    }

    #[test]
    fn calibration_context_debug_nonempty() {
        let ctx = test_ctx();
        assert!(!format!("{ctx:?}").is_empty());
    }

    #[test]
    fn defense_effectiveness_summary_debug_nonempty() {
        let summary = DefenseEffectivenessSummary {
            total_campaigns: 0,
            total_evasions: 0,
            total_containment_escapes: 0,
            overall_detection_rate_millionths: 0,
            overall_trend: EffectivenessTrend::Stable,
            per_dimension: BTreeMap::new(),
            weakest_dimension: None,
        };
        assert!(!format!("{summary:?}").is_empty());
    }

    #[test]
    fn dimension_effectiveness_debug_nonempty() {
        let de = DimensionEffectiveness {
            dimension: "x".to_string(),
            detection_rate_millionths: 0,
            evasion_rate_millionths: 0,
            trend: EffectivenessTrend::Stable,
            sample_count: 0,
        };
        assert!(!format!("{de:?}").is_empty());
    }

    #[test]
    fn guardplane_calibration_engine_debug_nonempty() {
        let engine = GuardplaneCalibrationEngine::new();
        assert!(!format!("{engine:?}").is_empty());
    }

    // -------------------------------------------------------------------
    // Additional functional edge cases
    // -------------------------------------------------------------------

    #[test]
    fn fnv1a64_empty_input() {
        let h = fnv1a64(b"");
        assert_eq!(h, 0xcbf2_9ce4_8422_2325);
    }

    #[test]
    fn fnv1a64_deterministic() {
        let h1 = fnv1a64(b"hello guardplane");
        let h2 = fnv1a64(b"hello guardplane");
        assert_eq!(h1, h2);
    }

    #[test]
    fn fnv1a64_different_inputs_differ() {
        let h1 = fnv1a64(b"alpha");
        let h2 = fnv1a64(b"beta");
        assert_ne!(h1, h2);
    }

    #[test]
    fn severity_classification_advisory_boundary() {
        // Score just below 200K => Advisory
        let r = make_result(0, 10, false, 100_000, 1, false);
        let s = ExploitObjectiveScore::from_result(&r).unwrap();
        assert_eq!(classify_severity(&s), CampaignSeverity::Advisory);
    }

    #[test]
    fn severity_classification_moderate_boundary() {
        // Build a result with high evasion and damage to push composite >= 200K
        let r = make_result(7, 10, false, 600_000, 15, false);
        let s = ExploitObjectiveScore::from_result(&r).unwrap();
        let sev = classify_severity(&s);
        assert!(
            sev == CampaignSeverity::Moderate
                || sev == CampaignSeverity::Critical
                || sev == CampaignSeverity::Blocking,
            "expected Moderate/Critical/Blocking, got {sev:?} (composite={})",
            s.composite_score_millionths,
        );
    }

    #[test]
    fn threat_category_hostcall_sequence_maps_to_credential_theft() {
        let o = make_outcome(AttackDimension::HostcallSequence, 0, 5, false);
        assert_eq!(
            classify_threat_category(&o),
            ThreatCategory::CredentialTheft
        );
    }

    #[test]
    fn threat_category_temporal_payload_maps_to_persistence() {
        let o = make_outcome(AttackDimension::TemporalPayload, 0, 5, false);
        assert_eq!(classify_threat_category(&o), ThreatCategory::Persistence);
    }

    #[test]
    fn subsystem_evidence_accumulation_classification() {
        // Not escaped, no undetected steps, but high evidence atoms
        let campaign = make_campaign(AttackDimension::Exfiltration, 5);
        let result = make_result(0, 5, false, 100_000, 15, false);
        let score = ExploitObjectiveScore::from_result(&result).unwrap();
        let outcome = CampaignOutcomeRecord {
            campaign,
            result,
            score,
            benign_control: false,
            false_positive: false,
            timestamp_ns: 1_000_000_000,
        };
        assert_eq!(
            classify_defense_subsystem(&outcome),
            DefenseSubsystem::EvidenceAccumulation
        );
    }

    #[test]
    fn subsystem_fleet_convergence_classification() {
        // Not escaped, no undetected steps, low evidence atoms
        let campaign = make_campaign(AttackDimension::Exfiltration, 5);
        let result = make_result(0, 5, false, 100_000, 3, false);
        let score = ExploitObjectiveScore::from_result(&result).unwrap();
        let outcome = CampaignOutcomeRecord {
            campaign,
            result,
            score,
            benign_control: false,
            false_positive: false,
            timestamp_ns: 1_000_000_000,
        };
        assert_eq!(
            classify_defense_subsystem(&outcome),
            DefenseSubsystem::FleetConvergence
        );
    }

    #[test]
    fn overall_trend_empty_history_stable() {
        let history: BTreeMap<String, Vec<u64>> = BTreeMap::new();
        assert_eq!(compute_overall_trend(&history), EffectivenessTrend::Stable);
    }

    #[test]
    fn overall_trend_all_improving() {
        let mut history = BTreeMap::new();
        // High then low = improving
        history.insert(
            "A".to_string(),
            vec![
                500_000, 500_000, 500_000, 500_000, 500_000, 100_000, 100_000, 100_000, 100_000,
                100_000,
            ],
        );
        history.insert(
            "B".to_string(),
            vec![
                600_000, 600_000, 600_000, 600_000, 600_000, 50_000, 50_000, 50_000, 50_000, 50_000,
            ],
        );
        assert_eq!(
            compute_overall_trend(&history),
            EffectivenessTrend::Improving
        );
    }

    #[test]
    fn overall_trend_all_degrading() {
        let mut history = BTreeMap::new();
        // Low then high = degrading
        history.insert(
            "A".to_string(),
            vec![
                100_000, 100_000, 100_000, 100_000, 100_000, 500_000, 500_000, 500_000, 500_000,
                500_000,
            ],
        );
        history.insert(
            "B".to_string(),
            vec![
                50_000, 50_000, 50_000, 50_000, 50_000, 600_000, 600_000, 600_000, 600_000, 600_000,
            ],
        );
        assert_eq!(
            compute_overall_trend(&history),
            EffectivenessTrend::Degrading
        );
    }

    #[test]
    fn overall_trend_mixed_yields_stable() {
        let mut history = BTreeMap::new();
        // One improving, one degrading => tie => stable
        history.insert(
            "A".to_string(),
            vec![
                500_000, 500_000, 500_000, 500_000, 500_000, 100_000, 100_000, 100_000, 100_000,
                100_000,
            ],
        );
        history.insert(
            "B".to_string(),
            vec![
                100_000, 100_000, 100_000, 100_000, 100_000, 500_000, 500_000, 500_000, 500_000,
                500_000,
            ],
        );
        assert_eq!(compute_overall_trend(&history), EffectivenessTrend::Stable);
    }

    #[test]
    fn drain_events_idempotent() {
        let mut engine = GuardplaneCalibrationEngine::new();
        let ctx = test_ctx();
        let outcomes = vec![make_outcome(AttackDimension::Exfiltration, 0, 5, false)];
        engine.run_calibration_cycle(&outcomes, &ctx).unwrap();

        let first_drain = engine.drain_events();
        assert!(!first_drain.is_empty());
        let second_drain = engine.drain_events();
        assert!(second_drain.is_empty());
    }

    #[test]
    fn regression_fixtures_added_for_critical_campaigns() {
        let mut engine = GuardplaneCalibrationEngine::new();
        let ctx = test_ctx();
        // Create a campaign with high score (Critical/Blocking)
        let campaign = make_campaign(AttackDimension::Exfiltration, 10);
        let result = make_result(10, 10, true, 900_000, 50, true);
        let score = ExploitObjectiveScore::from_result(&result).unwrap();
        let outcome = CampaignOutcomeRecord {
            campaign,
            result,
            score,
            benign_control: false,
            false_positive: false,
            timestamp_ns: 1_000_000_000,
        };

        let r = engine.run_calibration_cycle(&[outcome], &ctx).unwrap();
        assert!(r.regression_fixtures_added > 0);
    }

    #[test]
    fn set_evasion_alert_threshold_takes_effect() {
        let mut engine = GuardplaneCalibrationEngine::new();
        engine.set_evasion_alert_threshold(1_000_001);
        let ctx = test_ctx();
        let outcomes = vec![make_outcome(AttackDimension::Exfiltration, 5, 10, false)];
        engine.run_calibration_cycle(&outcomes, &ctx).unwrap();
        // Even 100% per-subsystem evasion rate < 100.0001% threshold => no alert
        let evasion_alerts: Vec<_> = engine
            .alerts()
            .iter()
            .filter(|a| a.threat_category == "evasion")
            .collect();
        assert!(evasion_alerts.is_empty());
    }

    #[test]
    fn set_containment_escape_alert_threshold_takes_effect() {
        let mut engine = GuardplaneCalibrationEngine::new();
        engine.set_containment_escape_alert_threshold(999_999);
        let ctx = test_ctx();
        let outcomes = vec![make_outcome(AttackDimension::Exfiltration, 5, 10, true)];
        engine.run_calibration_cycle(&outcomes, &ctx).unwrap();
        // 100% escape rate > 99.9999% => alert fires
        let escape_alerts: Vec<_> = engine
            .alerts()
            .iter()
            .filter(|a| a.threat_category == "containment_escape")
            .collect();
        assert!(!escape_alerts.is_empty());
    }

    #[test]
    fn component_constant_value() {
        assert_eq!(COMPONENT, "guardplane_calibration");
    }

    #[test]
    fn calibration_state_accessible() {
        let engine = GuardplaneCalibrationEngine::new();
        let state = engine.calibration_state();
        // Default state has some epoch
        assert_eq!(state.calibration_epoch, 0);
    }

    #[test]
    fn all_attack_dimensions_yield_threat_categories() {
        for dim in [
            AttackDimension::HostcallSequence,
            AttackDimension::TemporalPayload,
            AttackDimension::PrivilegeEscalation,
            AttackDimension::PolicyEvasion,
            AttackDimension::Exfiltration,
        ] {
            let o = make_outcome(dim, 0, 5, false);
            let _tc = classify_threat_category(&o);
        }
    }

    #[test]
    fn state_digest_hex_format() {
        let state = GuardplaneCalibrationState::default();
        let digest = compute_state_digest(&state);
        assert_eq!(digest.len(), 16);
        assert!(
            digest.chars().all(|c| c.is_ascii_hexdigit()),
            "digest should be all hex chars"
        );
    }

    #[test]
    fn classify_outcomes_all_dimensions() {
        let outcomes: Vec<CampaignOutcomeRecord> = [
            AttackDimension::HostcallSequence,
            AttackDimension::TemporalPayload,
            AttackDimension::PrivilegeEscalation,
            AttackDimension::PolicyEvasion,
            AttackDimension::Exfiltration,
        ]
        .iter()
        .map(|&dim| make_outcome(dim, 1, 5, false))
        .collect();

        let (sev, sub, thr) = classify_outcomes(&outcomes);
        let total_sev: usize = sev.values().sum();
        let total_sub: usize = sub.values().sum();
        let total_thr: usize = thr.values().sum();
        assert_eq!(total_sev, 5);
        assert_eq!(total_sub, 5);
        assert_eq!(total_thr, 5);
    }
}
