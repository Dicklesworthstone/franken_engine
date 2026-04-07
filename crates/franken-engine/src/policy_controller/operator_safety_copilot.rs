//! Operator-facing safety copilot surfaces for policy-controller decisions.
//!
//! This module focuses on deterministic recommendation ranking, confidence
//! bands, rollback command generation, confirmation workflow, and audit-friendly
//! interaction contracts used by operator UI surfaces.
//!
//! Plan reference: Section 10.12 item 19 (`bd-1ddd`).

use std::cmp::Ordering;
use std::error::Error;
use std::fmt;

use serde::{Deserialize, Serialize};

const COPILOT_COMPONENT: &str = "operator_safety_copilot";
const MILLION: i64 = 1_000_000;
const FNV_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

/// Reversibility classification for an operator recommendation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecommendationReversibility {
    Reversible,
    LimitedWindow,
    Irreversible,
}

/// Time sensitivity for recommended actions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimeSensitivity {
    Immediate,
    NearTerm,
    Routine,
}

/// Operator role for access-control checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatorRole {
    Viewer,
    Operator,
    Administrator,
}

/// Direction for a decision-boundary trigger.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BoundaryTriggerDirection {
    AtOrAbove,
    AtOrBelow,
}

/// Severity class for fleet incidents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IncidentSeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// Extension trust level for fleet-health surfaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtensionTrustLevel {
    High,
    Guarded,
    Watch,
    Quarantined,
}

/// Candidate recommendation generated from runtime decision scoring.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionRecommendationCandidate {
    pub action_type: String,
    pub target_extension: String,
    pub expected_loss_reduction_millionths: i64,
    pub confidence_millionths: i64,
    pub side_effects: Vec<String>,
    pub collateral_extensions: u32,
    pub estimated_action_latency_ms: u64,
    pub reversibility: RecommendationReversibility,
    pub time_sensitivity: TimeSensitivity,
    pub rollback_window_ms: Option<u64>,
    pub snapshot_id: Option<String>,
}

/// Confidence interval for one metric.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidenceBand {
    pub metric: String,
    pub point_millionths: i64,
    pub lower_millionths: i64,
    pub upper_millionths: i64,
    pub confidence_level_bps: u16,
}

impl ConfidenceBand {
    fn validate(&self) -> Result<(), CopilotError> {
        validate_non_empty("confidence_band.metric", &self.metric)?;
        validate_probability("confidence_band.point_millionths", self.point_millionths)?;
        validate_probability("confidence_band.lower_millionths", self.lower_millionths)?;
        validate_probability("confidence_band.upper_millionths", self.upper_millionths)?;
        if self.lower_millionths > self.point_millionths
            || self.point_millionths > self.upper_millionths
        {
            return Err(CopilotError::InvalidConfidenceBand {
                metric: self.metric.clone(),
            });
        }
        if self.confidence_level_bps == 0 || self.confidence_level_bps > 10_000 {
            return Err(CopilotError::InvalidConfidenceBand {
                metric: self.metric.clone(),
            });
        }
        Ok(())
    }
}

/// Evidence strength summary shown to operators.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceStrength {
    pub evidence_atoms: u32,
    pub observation_window_seconds: u64,
}

/// Proximity hint for a decision boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionBoundaryHint {
    pub metric: String,
    pub current_millionths: i64,
    pub threshold_millionths: i64,
    pub additional_evidence_needed: u32,
    pub evidence_type: String,
    pub trigger_direction: BoundaryTriggerDirection,
}

impl DecisionBoundaryHint {
    fn validate(&self) -> Result<(), CopilotError> {
        validate_non_empty("decision_boundary.metric", &self.metric)?;
        validate_probability(
            "decision_boundary.current_millionths",
            self.current_millionths,
        )?;
        validate_probability(
            "decision_boundary.threshold_millionths",
            self.threshold_millionths,
        )?;
        validate_non_empty("decision_boundary.evidence_type", &self.evidence_type)?;
        if self.additional_evidence_needed == 0 {
            return Err(CopilotError::InvalidDecisionBoundaryHint {
                metric: self.metric.clone(),
            });
        }
        Ok(())
    }
}

/// Drill-down pointers associated with timeline events.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimelineDrilldownPointers {
    pub evidence_pointer: Option<String>,
    pub decision_receipt_pointer: Option<String>,
    pub replay_pointer: Option<String>,
    pub counterfactual_pointer: Option<String>,
}

/// One event in the incident timeline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncidentTimelineEvent {
    pub timestamp_ns: u64,
    pub event_id: String,
    pub event_type: String,
    pub detail: String,
    pub outcome: String,
    pub error_code: Option<String>,
    #[serde(default)]
    pub drilldown: TimelineDrilldownPointers,
}

/// Input envelope for building an operator safety copilot surface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorSafetyCopilotInput {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub incident_id: String,
    pub no_action_expected_loss_millionths: i64,
    pub recommendations: Vec<ActionRecommendationCandidate>,
    pub confidence_bands: Vec<ConfidenceBand>,
    pub evidence_strength: EvidenceStrength,
    pub decision_boundary_hints: Vec<DecisionBoundaryHint>,
    pub timeline: Vec<IncidentTimelineEvent>,
}

/// Deterministic rollback command emitted for every recommendation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollbackCommand {
    pub command: String,
    pub safety_summary: String,
}

/// Ranked recommendation for operator presentation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RankedRecommendation {
    pub rank: u32,
    pub action_type: String,
    pub target_extension: String,
    pub expected_loss_reduction_millionths: i64,
    pub confidence_millionths: i64,
    pub side_effects: Vec<String>,
    pub collateral_extensions: u32,
    pub estimated_action_latency_ms: u64,
    pub reversibility: RecommendationReversibility,
    pub time_sensitivity: TimeSensitivity,
    pub rollback_window_ms: Option<u64>,
    pub rollback_command: RollbackCommand,
    pub explanation: String,
}

/// Structured event emitted by copilot-surface operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CopilotStructuredLogEvent {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
}

/// Deterministic output for operator safety copilot surfaces.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorSafetyCopilotSurface {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub incident_id: String,
    pub read_only: bool,
    pub recommended_action: RankedRecommendation,
    pub alternatives: Vec<RankedRecommendation>,
    pub no_action_expected_loss_millionths: i64,
    pub confidence_bands: Vec<ConfidenceBand>,
    pub evidence_strength: EvidenceStrength,
    pub decision_boundary_hints: Vec<DecisionBoundaryHint>,
    pub timeline: Vec<IncidentTimelineEvent>,
    pub logs: Vec<CopilotStructuredLogEvent>,
}

/// Operator identity attached to action interactions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorIdentity {
    pub operator_id: String,
    pub role: OperatorRole,
}

/// Operator interaction audit record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorAuditEvent {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub operator_id: String,
    pub operator_role: OperatorRole,
    pub event: String,
    pub outcome: String,
    pub context: String,
    pub timestamp_ns: u64,
    pub error_code: Option<String>,
}

/// Impact summary shown before action confirmation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionImpactSummary {
    pub dependent_extensions_affected: u32,
    pub estimated_latency_ms: u64,
    pub reversible: bool,
    pub rollback_window_ms_remaining: Option<u64>,
}

/// Selection state for the action-confirmation workflow.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionSelectionReview {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub incident_id: String,
    pub selected_rank: u32,
    pub selected_recommendation: RankedRecommendation,
    pub impact_summary: ActionImpactSummary,
    pub selected_by: OperatorIdentity,
    pub selected_at_ns: u64,
    pub audit_event: OperatorAuditEvent,
}

/// Receipt proving an action execution decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionExecutionReceipt {
    pub receipt_id: String,
    pub signature: String,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub incident_id: String,
    pub action_type: String,
    pub target_extension: String,
    pub operator_id: String,
    pub confirmed_at_ns: u64,
    pub rollback_command: String,
}

/// Final action-confirmation output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfirmedActionExecution {
    pub execution_command: String,
    pub rollback_command: RollbackCommand,
    pub receipt: ActionExecutionReceipt,
    pub audit_event: OperatorAuditEvent,
    pub log_event: CopilotStructuredLogEvent,
}

/// Input for deterministic rollback receipt generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollbackReceiptInput {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub action_receipt_id: String,
    pub rollback_decision_id: String,
    pub evidence_pointer: String,
    pub restoration_verification: String,
    pub executed_at_ns: u64,
}

/// Receipt proving rollback execution and verification linkage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollbackExecutionReceipt {
    pub receipt_id: String,
    pub signature: String,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub action_receipt_id: String,
    pub rollback_decision_id: String,
    pub evidence_pointer: String,
    pub restoration_verification: String,
    pub executed_at_ns: u64,
}

/// Per-extension detail card used in dashboard surfaces.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtensionTrustCard {
    pub extension_id: String,
    pub trust_level: ExtensionTrustLevel,
    pub recent_evidence_atoms: u32,
    pub recent_decision_ids: Vec<String>,
    pub current_recommendation: Option<String>,
}

/// Active incident summary for fleet dashboards.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActiveIncidentSummary {
    pub incident_id: String,
    pub extension_id: String,
    pub severity: IncidentSeverity,
    pub started_at_ns: u64,
    pub status: String,
}

/// Recent containment action outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContainmentActionOutcome {
    pub incident_id: String,
    pub action_type: String,
    pub outcome: String,
    pub latency_ms: u64,
}

/// Distribution row for trust-level aggregates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustLevelDistributionEntry {
    pub trust_level: ExtensionTrustLevel,
    pub extensions: u32,
}

/// Fleet health aggregate view.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetHealthOverview {
    pub trust_level_distribution: Vec<TrustLevelDistributionEntry>,
    pub active_incidents: Vec<ActiveIncidentSummary>,
    pub active_incidents_count: u32,
    pub highest_severity: IncidentSeverity,
    pub attacker_roi_trend_millionths: Vec<i64>,
    pub recent_containment_actions: Vec<ContainmentActionOutcome>,
    pub extension_details: Vec<ExtensionTrustCard>,
}

/// Raw detection counts for policy effectiveness views.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CategoryDetectionCount {
    pub category: String,
    pub detected_events: u64,
    pub total_events: u64,
}

/// Detection-rate row (fixed-point millionths).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CategoryDetectionRate {
    pub category: String,
    pub detected_events: u64,
    pub total_events: u64,
    pub rate_millionths: i64,
}

/// Calibration point for reliability tracking.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CalibrationPoint {
    pub timestamp_ns: u64,
    pub expected_millionths: i64,
    pub observed_millionths: i64,
}

/// Input envelope for policy-effectiveness surface computation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyEffectivenessInput {
    pub detection_counts: Vec<CategoryDetectionCount>,
    pub false_positive_rate_trend_millionths: Vec<i64>,
    pub containment_latencies_ms: Vec<u64>,
    pub calibration_history: Vec<CalibrationPoint>,
}

/// Policy-effectiveness dashboard view.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyEffectivenessView {
    pub detection_rate_by_category: Vec<CategoryDetectionRate>,
    pub false_positive_rate_trend_millionths: Vec<i64>,
    pub containment_latency_p50_ms: u64,
    pub containment_latency_p95_ms: u64,
    pub calibration_history: Vec<CalibrationPoint>,
}

/// Copilot-surface construction and interaction errors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CopilotError {
    MissingRecommendations,
    InvalidProbability {
        field: String,
        value: i64,
    },
    InvalidField {
        field: String,
    },
    InvalidConfidenceBand {
        metric: String,
    },
    InvalidDecisionBoundaryHint {
        metric: String,
    },
    MissingSnapshotForRollback {
        action_type: String,
        target_extension: String,
    },
    InvalidRollbackWindow {
        action_type: String,
        target_extension: String,
    },
    UnauthorizedRole {
        role: OperatorRole,
        action: String,
    },
    RecommendationRankOutOfRange {
        requested_rank: u32,
        available: u32,
    },
    OperatorMismatch {
        selected_by: String,
        confirmed_by: String,
    },
    MissingConfirmationToken,
}

impl fmt::Display for CopilotError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingRecommendations => f.write_str("copilot input is missing recommendations"),
            Self::InvalidProbability { field, value } => {
                write!(
                    f,
                    "invalid probability for {field}: {value} (expected 0..=1_000_000)"
                )
            }
            Self::InvalidField { field } => write!(f, "invalid or empty field `{field}`"),
            Self::InvalidConfidenceBand { metric } => {
                write!(f, "invalid confidence band bounds for metric `{metric}`")
            }
            Self::InvalidDecisionBoundaryHint { metric } => {
                write!(f, "invalid decision boundary hint for metric `{metric}`")
            }
            Self::MissingSnapshotForRollback {
                action_type,
                target_extension,
            } => write!(
                f,
                "missing snapshot_id for rollback action `{action_type}` on extension `{target_extension}`"
            ),
            Self::InvalidRollbackWindow {
                action_type,
                target_extension,
            } => write!(
                f,
                "limited-window rollback requires rollback_window_ms for action `{action_type}` on extension `{target_extension}`"
            ),
            Self::UnauthorizedRole { role, action } => {
                write!(f, "role `{role:?}` is not authorized to `{action}`")
            }
            Self::RecommendationRankOutOfRange {
                requested_rank,
                available,
            } => write!(
                f,
                "requested recommendation rank {requested_rank} out of range (available={available})"
            ),
            Self::OperatorMismatch {
                selected_by,
                confirmed_by,
            } => write!(
                f,
                "operator mismatch between selection `{selected_by}` and confirmation `{confirmed_by}`"
            ),
            Self::MissingConfirmationToken => {
                f.write_str("confirmation token is required for action execution")
            }
        }
    }
}

impl Error for CopilotError {}

/// Build the deterministic operator safety copilot surface.
pub fn build_operator_safety_copilot_surface(
    input: &OperatorSafetyCopilotInput,
) -> Result<OperatorSafetyCopilotSurface, CopilotError> {
    validate_input(input)?;

    let mut ranked = input.recommendations.clone();
    ranked.sort_by(recommendation_sort);

    let ranked_recommendations = ranked
        .iter()
        .enumerate()
        .map(|(idx, candidate)| {
            let rank = u32::try_from(idx + 1).unwrap_or(u32::MAX);
            let rollback = build_rollback_command(
                &input.trace_id,
                &input.decision_id,
                &input.policy_id,
                candidate,
            );
            RankedRecommendation {
                rank,
                action_type: candidate.action_type.clone(),
                target_extension: candidate.target_extension.clone(),
                expected_loss_reduction_millionths: candidate.expected_loss_reduction_millionths,
                confidence_millionths: candidate.confidence_millionths,
                side_effects: candidate.side_effects.clone(),
                collateral_extensions: candidate.collateral_extensions,
                estimated_action_latency_ms: candidate.estimated_action_latency_ms,
                reversibility: candidate.reversibility,
                time_sensitivity: candidate.time_sensitivity,
                rollback_window_ms: candidate.rollback_window_ms,
                rollback_command: rollback,
                explanation: recommendation_explanation(candidate),
            }
        })
        .collect::<Vec<_>>();

    let mut timeline = input.timeline.clone();
    timeline.sort_by(|left, right| {
        left.timestamp_ns
            .cmp(&right.timestamp_ns)
            .then_with(|| left.event_id.cmp(&right.event_id))
            .then_with(|| left.event_type.cmp(&right.event_type))
    });

    let mut bands = input.confidence_bands.clone();
    bands.sort_by(|left, right| left.metric.cmp(&right.metric));

    let mut boundary_hints = input.decision_boundary_hints.clone();
    boundary_hints.sort_by(|left, right| {
        left.metric
            .cmp(&right.metric)
            .then_with(|| left.threshold_millionths.cmp(&right.threshold_millionths))
            .then_with(|| left.current_millionths.cmp(&right.current_millionths))
            .then_with(|| left.evidence_type.cmp(&right.evidence_type))
    });

    let recommended_action = ranked_recommendations[0].clone();
    let alternatives = ranked_recommendations[1..].to_vec();
    let logs = vec![CopilotStructuredLogEvent {
        trace_id: input.trace_id.clone(),
        decision_id: input.decision_id.clone(),
        policy_id: input.policy_id.clone(),
        component: COPILOT_COMPONENT.to_string(),
        event: "copilot_surface_built".to_string(),
        outcome: "pass".to_string(),
        error_code: None,
    }];

    Ok(OperatorSafetyCopilotSurface {
        trace_id: input.trace_id.clone(),
        decision_id: input.decision_id.clone(),
        policy_id: input.policy_id.clone(),
        incident_id: input.incident_id.clone(),
        read_only: true,
        recommended_action,
        alternatives,
        no_action_expected_loss_millionths: input.no_action_expected_loss_millionths,
        confidence_bands: bands,
        evidence_strength: input.evidence_strength.clone(),
        decision_boundary_hints: boundary_hints,
        timeline,
        logs,
    })
}

/// Step (a)+(b): select a recommendation and review deterministic impact summary.
pub fn select_recommendation_for_review(
    surface: &OperatorSafetyCopilotSurface,
    identity: &OperatorIdentity,
    requested_rank: u32,
    selected_at_ns: u64,
) -> Result<ActionSelectionReview, CopilotError> {
    validate_operator_identity(identity)?;
    if !role_can_execute_actions(identity.role) {
        return Err(CopilotError::UnauthorizedRole {
            role: identity.role,
            action: "select_recommendation".to_string(),
        });
    }

    let selected_recommendation = recommendation_by_rank(surface, requested_rank)?;
    let impact_summary = ActionImpactSummary {
        dependent_extensions_affected: selected_recommendation.collateral_extensions,
        estimated_latency_ms: selected_recommendation.estimated_action_latency_ms,
        reversible: selected_recommendation.reversibility
            != RecommendationReversibility::Irreversible,
        rollback_window_ms_remaining: selected_recommendation.rollback_window_ms,
    };

    let context = format!(
        "rank={} action={} target={} collateral={} latency_ms={}",
        selected_recommendation.rank,
        selected_recommendation.action_type,
        selected_recommendation.target_extension,
        impact_summary.dependent_extensions_affected,
        impact_summary.estimated_latency_ms
    );

    let audit_event = OperatorAuditEvent {
        trace_id: surface.trace_id.clone(),
        decision_id: surface.decision_id.clone(),
        policy_id: surface.policy_id.clone(),
        operator_id: identity.operator_id.clone(),
        operator_role: identity.role,
        event: "copilot_action_selected".to_string(),
        outcome: "pending_confirmation".to_string(),
        context,
        timestamp_ns: selected_at_ns,
        error_code: None,
    };

    Ok(ActionSelectionReview {
        trace_id: surface.trace_id.clone(),
        decision_id: surface.decision_id.clone(),
        policy_id: surface.policy_id.clone(),
        incident_id: surface.incident_id.clone(),
        selected_rank: selected_recommendation.rank,
        selected_recommendation,
        impact_summary,
        selected_by: identity.clone(),
        selected_at_ns,
        audit_event,
    })
}

/// Step (c): confirm action execution with operator identity and token.
pub fn confirm_selected_recommendation(
    review: &ActionSelectionReview,
    identity: &OperatorIdentity,
    confirmation_token: &str,
    confirmed_at_ns: u64,
) -> Result<ConfirmedActionExecution, CopilotError> {
    validate_operator_identity(identity)?;
    if !role_can_execute_actions(identity.role) {
        return Err(CopilotError::UnauthorizedRole {
            role: identity.role,
            action: "confirm_recommendation".to_string(),
        });
    }
    if identity.operator_id != review.selected_by.operator_id {
        return Err(CopilotError::OperatorMismatch {
            selected_by: review.selected_by.operator_id.clone(),
            confirmed_by: identity.operator_id.clone(),
        });
    }
    if confirmation_token.trim().is_empty() {
        return Err(CopilotError::MissingConfirmationToken);
    }

    let confirmation_token_hash = deterministic_signature(&[confirmation_token.trim()]);
    let execution_command = build_execute_command(review, identity, &confirmation_token_hash);

    let signature = deterministic_signature(&[
        &review.trace_id,
        &review.decision_id,
        &review.policy_id,
        &review.incident_id,
        &review.selected_recommendation.action_type,
        &review.selected_recommendation.target_extension,
        &identity.operator_id,
        &confirmed_at_ns.to_string(),
        &confirmation_token_hash,
    ]);
    let receipt_id = format!("action-receipt-{signature}");

    let receipt = ActionExecutionReceipt {
        receipt_id,
        signature,
        trace_id: review.trace_id.clone(),
        decision_id: review.decision_id.clone(),
        policy_id: review.policy_id.clone(),
        incident_id: review.incident_id.clone(),
        action_type: review.selected_recommendation.action_type.clone(),
        target_extension: review.selected_recommendation.target_extension.clone(),
        operator_id: identity.operator_id.clone(),
        confirmed_at_ns,
        rollback_command: review
            .selected_recommendation
            .rollback_command
            .command
            .clone(),
    };

    let audit_event = OperatorAuditEvent {
        trace_id: review.trace_id.clone(),
        decision_id: review.decision_id.clone(),
        policy_id: review.policy_id.clone(),
        operator_id: identity.operator_id.clone(),
        operator_role: identity.role,
        event: "copilot_action_confirmed".to_string(),
        outcome: "executed".to_string(),
        context: format!(
            "rank={} action={} target={} token_hash={}",
            review.selected_rank,
            review.selected_recommendation.action_type,
            review.selected_recommendation.target_extension,
            confirmation_token_hash
        ),
        timestamp_ns: confirmed_at_ns,
        error_code: None,
    };

    let log_event = CopilotStructuredLogEvent {
        trace_id: review.trace_id.clone(),
        decision_id: review.decision_id.clone(),
        policy_id: review.policy_id.clone(),
        component: COPILOT_COMPONENT.to_string(),
        event: "copilot_action_confirmed".to_string(),
        outcome: "pass".to_string(),
        error_code: None,
    };

    Ok(ConfirmedActionExecution {
        execution_command,
        rollback_command: review.selected_recommendation.rollback_command.clone(),
        receipt,
        audit_event,
        log_event,
    })
}

/// Build a deterministic rollback receipt linking rollback decision and evidence.
pub fn build_rollback_execution_receipt(
    input: &RollbackReceiptInput,
) -> Result<RollbackExecutionReceipt, CopilotError> {
    validate_non_empty("rollback.trace_id", &input.trace_id)?;
    validate_non_empty("rollback.decision_id", &input.decision_id)?;
    validate_non_empty("rollback.policy_id", &input.policy_id)?;
    validate_non_empty("rollback.action_receipt_id", &input.action_receipt_id)?;
    validate_non_empty("rollback.rollback_decision_id", &input.rollback_decision_id)?;
    validate_non_empty("rollback.evidence_pointer", &input.evidence_pointer)?;
    validate_non_empty(
        "rollback.restoration_verification",
        &input.restoration_verification,
    )?;

    let signature = deterministic_signature(&[
        &input.trace_id,
        &input.decision_id,
        &input.policy_id,
        &input.action_receipt_id,
        &input.rollback_decision_id,
        &input.evidence_pointer,
        &input.restoration_verification,
        &input.executed_at_ns.to_string(),
    ]);
    let receipt_id = format!("rollback-receipt-{signature}");

    Ok(RollbackExecutionReceipt {
        receipt_id,
        signature,
        trace_id: input.trace_id.clone(),
        decision_id: input.decision_id.clone(),
        policy_id: input.policy_id.clone(),
        action_receipt_id: input.action_receipt_id.clone(),
        rollback_decision_id: input.rollback_decision_id.clone(),
        evidence_pointer: input.evidence_pointer.clone(),
        restoration_verification: input.restoration_verification.clone(),
        executed_at_ns: input.executed_at_ns,
    })
}

/// Build deterministic fleet-health aggregates for dashboard surfaces.
pub fn build_fleet_health_overview(
    extension_cards: &[ExtensionTrustCard],
    active_incidents: &[ActiveIncidentSummary],
    attacker_roi_trend_millionths: &[i64],
    recent_containment_actions: &[ContainmentActionOutcome],
) -> FleetHealthOverview {
    let mut high = 0u32;
    let mut guarded = 0u32;
    let mut watch = 0u32;
    let mut quarantined = 0u32;

    for card in extension_cards {
        match card.trust_level {
            ExtensionTrustLevel::High => high += 1,
            ExtensionTrustLevel::Guarded => guarded += 1,
            ExtensionTrustLevel::Watch => watch += 1,
            ExtensionTrustLevel::Quarantined => quarantined += 1,
        }
    }

    let trust_level_distribution = vec![
        TrustLevelDistributionEntry {
            trust_level: ExtensionTrustLevel::High,
            extensions: high,
        },
        TrustLevelDistributionEntry {
            trust_level: ExtensionTrustLevel::Guarded,
            extensions: guarded,
        },
        TrustLevelDistributionEntry {
            trust_level: ExtensionTrustLevel::Watch,
            extensions: watch,
        },
        TrustLevelDistributionEntry {
            trust_level: ExtensionTrustLevel::Quarantined,
            extensions: quarantined,
        },
    ];

    let mut incidents = active_incidents.to_vec();
    incidents.sort_by(|left, right| {
        left.started_at_ns
            .cmp(&right.started_at_ns)
            .then_with(|| left.incident_id.cmp(&right.incident_id))
            .then_with(|| left.extension_id.cmp(&right.extension_id))
    });
    let highest_severity = incidents
        .iter()
        .map(|incident| incident.severity)
        .max()
        .unwrap_or(IncidentSeverity::Low);

    let mut extension_details = extension_cards.to_vec();
    extension_details.sort_by(|left, right| {
        left.extension_id
            .cmp(&right.extension_id)
            .then_with(|| left.trust_level.cmp(&right.trust_level))
    });

    let mut containment = recent_containment_actions.to_vec();
    containment.sort_by(|left, right| {
        left.incident_id
            .cmp(&right.incident_id)
            .then_with(|| left.action_type.cmp(&right.action_type))
            .then_with(|| left.outcome.cmp(&right.outcome))
            .then_with(|| left.latency_ms.cmp(&right.latency_ms))
    });

    let active_incidents_count = u32::try_from(incidents.len()).unwrap_or(u32::MAX);

    FleetHealthOverview {
        trust_level_distribution,
        active_incidents: incidents,
        active_incidents_count,
        highest_severity,
        attacker_roi_trend_millionths: attacker_roi_trend_millionths.to_vec(),
        recent_containment_actions: containment,
        extension_details,
    }
}

/// Build deterministic policy-effectiveness metrics for dashboard surfaces.
pub fn build_policy_effectiveness_view(
    input: &PolicyEffectivenessInput,
) -> Result<PolicyEffectivenessView, CopilotError> {
    for value in &input.false_positive_rate_trend_millionths {
        validate_probability("policy.false_positive_rate_trend", *value)?;
    }

    let mut detection_rate_by_category = input
        .detection_counts
        .iter()
        .map(|entry| {
            validate_non_empty("policy.detection.category", &entry.category)?;
            let rate_millionths = if entry.total_events == 0 {
                0
            } else {
                let numerator = u128::from(entry.detected_events) * u128::from(MILLION as u64);
                let denominator = u128::from(entry.total_events);
                let ratio = numerator / denominator;
                match i64::try_from(ratio) {
                    Ok(value) => value,
                    Err(_) => MILLION,
                }
            };
            Ok(CategoryDetectionRate {
                category: entry.category.clone(),
                detected_events: entry.detected_events,
                total_events: entry.total_events,
                rate_millionths,
            })
        })
        .collect::<Result<Vec<_>, CopilotError>>()?;
    detection_rate_by_category.sort_by(|left, right| left.category.cmp(&right.category));

    let mut calibration_history = input.calibration_history.clone();
    for point in &calibration_history {
        validate_probability(
            "policy.calibration.expected_millionths",
            point.expected_millionths,
        )?;
        validate_probability(
            "policy.calibration.observed_millionths",
            point.observed_millionths,
        )?;
    }
    calibration_history.sort_by(|left, right| {
        left.timestamp_ns
            .cmp(&right.timestamp_ns)
            .then_with(|| left.expected_millionths.cmp(&right.expected_millionths))
            .then_with(|| left.observed_millionths.cmp(&right.observed_millionths))
    });

    let mut latencies = input.containment_latencies_ms.clone();
    latencies.sort_unstable();
    let containment_latency_p50_ms = percentile_ms(&latencies, 5_000);
    let containment_latency_p95_ms = percentile_ms(&latencies, 9_500);

    Ok(PolicyEffectivenessView {
        detection_rate_by_category,
        false_positive_rate_trend_millionths: input.false_positive_rate_trend_millionths.clone(),
        containment_latency_p50_ms,
        containment_latency_p95_ms,
        calibration_history,
    })
}

/// Render a deterministic text summary for CLI/TUI fallback output.
pub fn render_copilot_summary(surface: &OperatorSafetyCopilotSurface) -> String {
    let mut lines = Vec::new();
    lines.push(format!("trace_id: {}", surface.trace_id));
    lines.push(format!("decision_id: {}", surface.decision_id));
    lines.push(format!("policy_id: {}", surface.policy_id));
    lines.push(format!("incident_id: {}", surface.incident_id));
    lines.push(format!("read_only: {}", surface.read_only));
    lines.push(format!(
        "recommended_action: {} {}",
        surface.recommended_action.action_type, surface.recommended_action.target_extension
    ));
    lines.push(format!(
        "recommended_el_reduction: {}",
        format_millionths(
            surface
                .recommended_action
                .expected_loss_reduction_millionths
        )
    ));
    lines.push(format!(
        "recommended_confidence: {}",
        format_millionths(surface.recommended_action.confidence_millionths)
    ));
    lines.push(format!(
        "no_action_expected_loss: {}",
        format_millionths(surface.no_action_expected_loss_millionths)
    ));
    lines.push(format!(
        "evidence_strength: {} atoms / {}s",
        surface.evidence_strength.evidence_atoms,
        surface.evidence_strength.observation_window_seconds
    ));

    for hint in &surface.decision_boundary_hints {
        lines.push(format!(
            "decision_boundary:{} current={} threshold={} direction={:?} additional_evidence={}({})",
            hint.metric,
            format_millionths(hint.current_millionths),
            format_millionths(hint.threshold_millionths),
            hint.trigger_direction,
            hint.additional_evidence_needed,
            hint.evidence_type
        ));
    }

    for (idx, alternative) in surface.alternatives.iter().enumerate() {
        lines.push(format!(
            "alternative_{}: {} {} (el_reduction={}, confidence={}, collateral={}, latency_ms={})",
            idx + 1,
            alternative.action_type,
            alternative.target_extension,
            format_millionths(alternative.expected_loss_reduction_millionths),
            format_millionths(alternative.confidence_millionths),
            alternative.collateral_extensions,
            alternative.estimated_action_latency_ms,
        ));
    }
    for band in &surface.confidence_bands {
        lines.push(format!(
            "confidence_band:{}={} [{}..{}] @{}bps",
            band.metric,
            format_millionths(band.point_millionths),
            format_millionths(band.lower_millionths),
            format_millionths(band.upper_millionths),
            band.confidence_level_bps
        ));
    }
    lines.join("\n")
}

fn validate_input(input: &OperatorSafetyCopilotInput) -> Result<(), CopilotError> {
    validate_non_empty("trace_id", &input.trace_id)?;
    validate_non_empty("decision_id", &input.decision_id)?;
    validate_non_empty("policy_id", &input.policy_id)?;
    validate_non_empty("incident_id", &input.incident_id)?;

    if input.recommendations.is_empty() {
        return Err(CopilotError::MissingRecommendations);
    }

    if input.no_action_expected_loss_millionths < 0 {
        return Err(CopilotError::InvalidField {
            field: "no_action_expected_loss_millionths".to_string(),
        });
    }

    for candidate in &input.recommendations {
        validate_non_empty("recommendation.action_type", &candidate.action_type)?;
        validate_non_empty(
            "recommendation.target_extension",
            &candidate.target_extension,
        )?;
        validate_probability(
            "recommendation.confidence_millionths",
            candidate.confidence_millionths,
        )?;
        if candidate.expected_loss_reduction_millionths < 0 {
            return Err(CopilotError::InvalidField {
                field: "recommendation.expected_loss_reduction_millionths".to_string(),
            });
        }
        match candidate.reversibility {
            RecommendationReversibility::Reversible => {
                if candidate
                    .snapshot_id
                    .as_deref()
                    .unwrap_or("")
                    .trim()
                    .is_empty()
                {
                    return Err(CopilotError::MissingSnapshotForRollback {
                        action_type: candidate.action_type.clone(),
                        target_extension: candidate.target_extension.clone(),
                    });
                }
            }
            RecommendationReversibility::LimitedWindow => {
                if candidate
                    .snapshot_id
                    .as_deref()
                    .unwrap_or("")
                    .trim()
                    .is_empty()
                {
                    return Err(CopilotError::MissingSnapshotForRollback {
                        action_type: candidate.action_type.clone(),
                        target_extension: candidate.target_extension.clone(),
                    });
                }
                if candidate.rollback_window_ms.unwrap_or(0) == 0 {
                    return Err(CopilotError::InvalidRollbackWindow {
                        action_type: candidate.action_type.clone(),
                        target_extension: candidate.target_extension.clone(),
                    });
                }
            }
            RecommendationReversibility::Irreversible => {}
        }
    }

    for band in &input.confidence_bands {
        band.validate()?;
    }

    for hint in &input.decision_boundary_hints {
        hint.validate()?;
    }

    for event in &input.timeline {
        validate_non_empty("timeline.event_id", &event.event_id)?;
        validate_non_empty("timeline.event_type", &event.event_type)?;
        validate_non_empty("timeline.detail", &event.detail)?;
        validate_non_empty("timeline.outcome", &event.outcome)?;
    }

    Ok(())
}

fn validate_operator_identity(identity: &OperatorIdentity) -> Result<(), CopilotError> {
    validate_non_empty("operator.operator_id", &identity.operator_id)
}

fn validate_non_empty(field: &str, value: &str) -> Result<(), CopilotError> {
    if value.trim().is_empty() {
        return Err(CopilotError::InvalidField {
            field: field.to_string(),
        });
    }
    Ok(())
}

fn validate_probability(field: &str, value: i64) -> Result<(), CopilotError> {
    if !(0..=MILLION).contains(&value) {
        return Err(CopilotError::InvalidProbability {
            field: field.to_string(),
            value,
        });
    }
    Ok(())
}

fn role_can_execute_actions(role: OperatorRole) -> bool {
    matches!(role, OperatorRole::Operator | OperatorRole::Administrator)
}

fn recommendation_by_rank(
    surface: &OperatorSafetyCopilotSurface,
    requested_rank: u32,
) -> Result<RankedRecommendation, CopilotError> {
    if requested_rank == 1 {
        return Ok(surface.recommended_action.clone());
    }

    let available = u32::try_from(surface.alternatives.len() + 1).unwrap_or(u32::MAX);

    let idx_u32 = requested_rank.saturating_sub(2);
    let idx = match usize::try_from(idx_u32) {
        Ok(value) => value,
        Err(_) => {
            return Err(CopilotError::RecommendationRankOutOfRange {
                requested_rank,
                available,
            });
        }
    };

    surface
        .alternatives
        .get(idx)
        .cloned()
        .ok_or(CopilotError::RecommendationRankOutOfRange {
            requested_rank,
            available,
        })
}

fn recommendation_sort(
    left: &ActionRecommendationCandidate,
    right: &ActionRecommendationCandidate,
) -> Ordering {
    right
        .expected_loss_reduction_millionths
        .cmp(&left.expected_loss_reduction_millionths)
        .then_with(|| right.confidence_millionths.cmp(&left.confidence_millionths))
        .then_with(|| left.action_type.cmp(&right.action_type))
        .then_with(|| left.target_extension.cmp(&right.target_extension))
}

fn build_rollback_command(
    trace_id: &str,
    decision_id: &str,
    policy_id: &str,
    candidate: &ActionRecommendationCandidate,
) -> RollbackCommand {
    let action_token = canonical_action_token(&candidate.action_type);
    let extension = candidate.target_extension.trim();
    match candidate.reversibility {
        RecommendationReversibility::Reversible => {
            let snapshot = candidate.snapshot_id.as_deref().unwrap_or("unknown");
            RollbackCommand {
                command: format!(
                    "rollback {action_token} --extension {extension} --snapshot-id {snapshot} --trace-id {trace_id} --decision-id {decision_id} --policy-id {policy_id} --verify"
                ),
                safety_summary: format!(
                    "snapshot={snapshot}; dependent_extensions={}; estimated_latency_ms={}",
                    candidate.collateral_extensions, candidate.estimated_action_latency_ms
                ),
            }
        }
        RecommendationReversibility::LimitedWindow => {
            let snapshot = candidate.snapshot_id.as_deref().unwrap_or("unknown");
            let window_ms = candidate.rollback_window_ms.unwrap_or(0);
            RollbackCommand {
                command: format!(
                    "rollback {action_token} --extension {extension} --snapshot-id {snapshot} --trace-id {trace_id} --decision-id {decision_id} --policy-id {policy_id} --window-ms {window_ms} --verify"
                ),
                safety_summary: format!(
                    "snapshot={snapshot}; dependent_extensions={}; estimated_latency_ms={}; window_ms_remaining={window_ms}",
                    candidate.collateral_extensions, candidate.estimated_action_latency_ms,
                ),
            }
        }
        RecommendationReversibility::Irreversible => RollbackCommand {
            command: format!(
                "rollback mark-irreversible --action {action_token} --extension {extension} --trace-id {trace_id} --decision-id {decision_id} --policy-id {policy_id} --acknowledge"
            ),
            safety_summary: format!(
                "irreversible action; dependent_extensions={}; estimated_latency_ms={}",
                candidate.collateral_extensions, candidate.estimated_action_latency_ms
            ),
        },
    }
}

fn build_execute_command(
    review: &ActionSelectionReview,
    identity: &OperatorIdentity,
    confirmation_token_hash: &str,
) -> String {
    let action_token = canonical_action_token(&review.selected_recommendation.action_type);
    format!(
        "execute {action_token} --extension {} --incident-id {} --trace-id {} --decision-id {} --policy-id {} --confirmed-by {} --confirmation-token-hash {}",
        review.selected_recommendation.target_extension,
        review.incident_id,
        review.trace_id,
        review.decision_id,
        review.policy_id,
        identity.operator_id,
        confirmation_token_hash
    )
}

fn deterministic_signature(parts: &[&str]) -> String {
    let mut hash = FNV_OFFSET_BASIS;
    for part in parts {
        for byte in part.as_bytes() {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(FNV_PRIME);
        }
        hash ^= 0xff;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    format!("{hash:016x}")
}

fn canonical_action_token(action: &str) -> String {
    let mut out = String::new();
    let mut previous_was_dash = false;
    for ch in action.trim().chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
            previous_was_dash = false;
        } else if !previous_was_dash {
            out.push('-');
            previous_was_dash = true;
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    if out.is_empty() {
        "unknown-action".to_string()
    } else {
        out
    }
}

fn recommendation_explanation(candidate: &ActionRecommendationCandidate) -> String {
    format!(
        "Recommended: {} {} because expected loss reduction={} and confidence={}",
        candidate.action_type,
        candidate.target_extension,
        format_millionths(candidate.expected_loss_reduction_millionths),
        format_millionths(candidate.confidence_millionths)
    )
}

fn percentile_ms(sorted_values: &[u64], percentile_bps: u16) -> u64 {
    if sorted_values.is_empty() {
        return 0;
    }
    let n_minus_one = sorted_values.len() - 1;
    let rank = (n_minus_one as u128 * u128::from(percentile_bps)).div_ceil(10_000);
    let index = match usize::try_from(rank) {
        Ok(value) => value,
        Err(_) => sorted_values.len() - 1,
    };
    sorted_values[index]
}

fn format_millionths(value: i64) -> String {
    let sign = if value < 0 { "-" } else { "" };
    let abs = value.unsigned_abs();
    let whole = abs / 1_000_000;
    let fractional = abs % 1_000_000;
    format!("{sign}{whole}.{fractional:06}")
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Helper constructors ───────────────────────────────────────
    fn test_candidate(
        action: &str,
        target: &str,
        loss_reduction: i64,
        confidence: i64,
    ) -> ActionRecommendationCandidate {
        ActionRecommendationCandidate {
            action_type: action.to_string(),
            target_extension: target.to_string(),
            expected_loss_reduction_millionths: loss_reduction,
            confidence_millionths: confidence,
            side_effects: vec!["side-effect-1".to_string()],
            collateral_extensions: 2,
            estimated_action_latency_ms: 100,
            reversibility: RecommendationReversibility::Reversible,
            time_sensitivity: TimeSensitivity::NearTerm,
            rollback_window_ms: Some(30_000),
            snapshot_id: Some("snap-1".to_string()),
        }
    }

    fn test_input() -> OperatorSafetyCopilotInput {
        OperatorSafetyCopilotInput {
            trace_id: "trace-1".to_string(),
            decision_id: "dec-1".to_string(),
            policy_id: "pol-1".to_string(),
            incident_id: "inc-1".to_string(),
            no_action_expected_loss_millionths: 500_000,
            recommendations: vec![
                test_candidate("throttle", "ext-a", 400_000, 800_000),
                test_candidate("isolate", "ext-b", 300_000, 700_000),
            ],
            confidence_bands: vec![ConfidenceBand {
                metric: "attack_probability".to_string(),
                point_millionths: 500_000,
                lower_millionths: 300_000,
                upper_millionths: 700_000,
                confidence_level_bps: 9500,
            }],
            evidence_strength: EvidenceStrength {
                evidence_atoms: 42,
                observation_window_seconds: 300,
            },
            decision_boundary_hints: vec![DecisionBoundaryHint {
                metric: "attacker_roi".to_string(),
                current_millionths: 400_000,
                threshold_millionths: 500_000,
                additional_evidence_needed: 5,
                evidence_type: "hostcall_anomaly".to_string(),
                trigger_direction: BoundaryTriggerDirection::AtOrAbove,
            }],
            timeline: vec![IncidentTimelineEvent {
                timestamp_ns: 1000,
                event_id: "evt-1".to_string(),
                event_type: "anomaly_detected".to_string(),
                detail: "budget spike".to_string(),
                outcome: "flagged".to_string(),
                error_code: None,
                drilldown: TimelineDrilldownPointers::default(),
            }],
        }
    }

    fn test_identity() -> OperatorIdentity {
        OperatorIdentity {
            operator_id: "op-1".to_string(),
            role: OperatorRole::Operator,
        }
    }

    fn build_test_surface() -> OperatorSafetyCopilotSurface {
        build_operator_safety_copilot_surface(&test_input()).unwrap()
    }

    // ── Enum serde round-trips ────────────────────────────────────
    #[test]
    fn recommendation_reversibility_serde() {
        for v in [
            RecommendationReversibility::Reversible,
            RecommendationReversibility::LimitedWindow,
            RecommendationReversibility::Irreversible,
        ] {
            let json = serde_json::to_string(&v).unwrap();
            let back: RecommendationReversibility = serde_json::from_str(&json).unwrap();
            assert_eq!(v, back);
        }
    }

    #[test]
    fn time_sensitivity_serde() {
        for v in [
            TimeSensitivity::Immediate,
            TimeSensitivity::NearTerm,
            TimeSensitivity::Routine,
        ] {
            let json = serde_json::to_string(&v).unwrap();
            let back: TimeSensitivity = serde_json::from_str(&json).unwrap();
            assert_eq!(v, back);
        }
    }

    #[test]
    fn operator_role_serde() {
        for v in [
            OperatorRole::Viewer,
            OperatorRole::Operator,
            OperatorRole::Administrator,
        ] {
            let json = serde_json::to_string(&v).unwrap();
            let back: OperatorRole = serde_json::from_str(&json).unwrap();
            assert_eq!(v, back);
        }
    }

    #[test]
    fn boundary_trigger_direction_serde() {
        for v in [
            BoundaryTriggerDirection::AtOrAbove,
            BoundaryTriggerDirection::AtOrBelow,
        ] {
            let json = serde_json::to_string(&v).unwrap();
            let back: BoundaryTriggerDirection = serde_json::from_str(&json).unwrap();
            assert_eq!(v, back);
        }
    }

    #[test]
    fn incident_severity_ordering() {
        assert!(IncidentSeverity::Low < IncidentSeverity::Medium);
        assert!(IncidentSeverity::Medium < IncidentSeverity::High);
        assert!(IncidentSeverity::High < IncidentSeverity::Critical);
    }

    #[test]
    fn incident_severity_serde() {
        for v in [
            IncidentSeverity::Low,
            IncidentSeverity::Medium,
            IncidentSeverity::High,
            IncidentSeverity::Critical,
        ] {
            let json = serde_json::to_string(&v).unwrap();
            let back: IncidentSeverity = serde_json::from_str(&json).unwrap();
            assert_eq!(v, back);
        }
    }

    #[test]
    fn extension_trust_level_ordering() {
        assert!(ExtensionTrustLevel::High < ExtensionTrustLevel::Guarded);
        assert!(ExtensionTrustLevel::Guarded < ExtensionTrustLevel::Watch);
        assert!(ExtensionTrustLevel::Watch < ExtensionTrustLevel::Quarantined);
    }

    // ── CopilotError Display ──────────────────────────────────────
    #[test]
    fn copilot_error_display_missing_recommendations() {
        let e = CopilotError::MissingRecommendations;
        assert!(format!("{e}").contains("missing recommendations"));
    }

    #[test]
    fn copilot_error_display_invalid_probability() {
        let e = CopilotError::InvalidProbability {
            field: "confidence".into(),
            value: -1,
        };
        let s = format!("{e}");
        assert!(s.contains("confidence"));
        assert!(s.contains("-1"));
    }

    #[test]
    fn copilot_error_display_invalid_field() {
        let e = CopilotError::InvalidField {
            field: "trace_id".into(),
        };
        assert!(format!("{e}").contains("trace_id"));
    }

    #[test]
    fn copilot_error_display_invalid_confidence_band() {
        let e = CopilotError::InvalidConfidenceBand {
            metric: "m1".into(),
        };
        assert!(format!("{e}").contains("m1"));
    }

    #[test]
    fn copilot_error_display_missing_snapshot() {
        let e = CopilotError::MissingSnapshotForRollback {
            action_type: "throttle".into(),
            target_extension: "ext-a".into(),
        };
        let s = format!("{e}");
        assert!(s.contains("throttle"));
        assert!(s.contains("ext-a"));
    }

    #[test]
    fn copilot_error_display_invalid_rollback_window() {
        let e = CopilotError::InvalidRollbackWindow {
            action_type: "isolate".into(),
            target_extension: "ext-b".into(),
        };
        let s = format!("{e}");
        assert!(s.contains("isolate"));
        assert!(s.contains("ext-b"));
    }

    #[test]
    fn copilot_error_display_unauthorized_role() {
        let e = CopilotError::UnauthorizedRole {
            role: OperatorRole::Viewer,
            action: "execute".into(),
        };
        let s = format!("{e}");
        assert!(s.contains("Viewer"));
        assert!(s.contains("execute"));
    }

    #[test]
    fn copilot_error_display_rank_out_of_range() {
        let e = CopilotError::RecommendationRankOutOfRange {
            requested_rank: 5,
            available: 2,
        };
        let s = format!("{e}");
        assert!(s.contains("5"));
        assert!(s.contains("2"));
    }

    #[test]
    fn copilot_error_display_operator_mismatch() {
        let e = CopilotError::OperatorMismatch {
            selected_by: "op-1".into(),
            confirmed_by: "op-2".into(),
        };
        let s = format!("{e}");
        assert!(s.contains("op-1"));
        assert!(s.contains("op-2"));
    }

    #[test]
    fn copilot_error_display_missing_confirmation_token() {
        let e = CopilotError::MissingConfirmationToken;
        assert!(format!("{e}").contains("confirmation token"));
    }

    #[test]
    fn copilot_error_is_std_error() {
        let e = CopilotError::MissingRecommendations;
        let _: &dyn Error = &e;
    }

    // ── validate_probability ──────────────────────────────────────
    #[test]
    fn validate_probability_valid_zero() {
        validate_probability("test", 0).unwrap();
    }

    #[test]
    fn validate_probability_valid_million() {
        validate_probability("test", MILLION).unwrap();
    }

    #[test]
    fn validate_probability_valid_mid() {
        validate_probability("test", 500_000).unwrap();
    }

    #[test]
    fn validate_probability_negative_fails() {
        assert!(validate_probability("test", -1).is_err());
    }

    #[test]
    fn validate_probability_above_million_fails() {
        assert!(validate_probability("test", MILLION + 1).is_err());
    }

    // ── validate_non_empty ────────────────────────────────────────
    #[test]
    fn validate_non_empty_valid() {
        validate_non_empty("f", "hello").unwrap();
    }

    #[test]
    fn validate_non_empty_empty_fails() {
        assert!(validate_non_empty("f", "").is_err());
    }

    #[test]
    fn validate_non_empty_whitespace_fails() {
        assert!(validate_non_empty("f", "  ").is_err());
    }

    // ── role_can_execute_actions ───────────────────────────────────
    #[test]
    fn role_can_execute() {
        assert!(!role_can_execute_actions(OperatorRole::Viewer));
        assert!(role_can_execute_actions(OperatorRole::Operator));
        assert!(role_can_execute_actions(OperatorRole::Administrator));
    }

    // ── canonical_action_token ────────────────────────────────────
    #[test]
    fn canonical_action_token_basic() {
        assert_eq!(canonical_action_token("Throttle CPU"), "throttle-cpu");
    }

    #[test]
    fn canonical_action_token_special_chars() {
        assert_eq!(canonical_action_token("a!!b@@c"), "a-b-c");
    }

    #[test]
    fn canonical_action_token_trailing_special() {
        assert_eq!(canonical_action_token("action!!"), "action");
    }

    #[test]
    fn canonical_action_token_empty() {
        assert_eq!(canonical_action_token(""), "unknown-action");
    }

    #[test]
    fn canonical_action_token_only_special() {
        assert_eq!(canonical_action_token("!!!"), "unknown-action");
    }

    // ── deterministic_signature ───────────────────────────────────
    #[test]
    fn deterministic_signature_same_inputs() {
        let a = deterministic_signature(&["hello", "world"]);
        let b = deterministic_signature(&["hello", "world"]);
        assert_eq!(a, b);
        assert_eq!(a.len(), 16); // 16 hex chars = 8 bytes
    }

    #[test]
    fn deterministic_signature_different_inputs() {
        let a = deterministic_signature(&["hello"]);
        let b = deterministic_signature(&["world"]);
        assert_ne!(a, b);
    }

    // ── format_millionths ─────────────────────────────────────────
    #[test]
    fn format_millionths_positive() {
        assert_eq!(format_millionths(1_500_000), "1.500000");
    }

    #[test]
    fn format_millionths_zero() {
        assert_eq!(format_millionths(0), "0.000000");
    }

    #[test]
    fn format_millionths_negative() {
        assert_eq!(format_millionths(-250_000), "-0.250000");
    }

    #[test]
    fn format_millionths_fraction_only() {
        assert_eq!(format_millionths(123), "0.000123");
    }

    // ── percentile_ms ─────────────────────────────────────────────
    #[test]
    fn percentile_ms_basic() {
        let sorted = vec![10, 20, 30, 40, 50, 60, 70, 80, 90, 100];
        let p50 = percentile_ms(&sorted, 5_000);
        let p95 = percentile_ms(&sorted, 9_500);
        assert!((40..=60).contains(&p50));
        assert!(p95 >= 90);
    }

    #[test]
    fn percentile_ms_empty() {
        assert_eq!(percentile_ms(&[], 5_000), 0);
    }

    #[test]
    fn percentile_ms_single() {
        assert_eq!(percentile_ms(&[42], 5_000), 42);
    }

    // ── recommendation_sort ───────────────────────────────────────
    #[test]
    fn recommendation_sort_by_loss_reduction() {
        let a = test_candidate("a", "ext-a", 500_000, 800_000);
        let b = test_candidate("b", "ext-b", 300_000, 800_000);
        let mut recs = [b.clone(), a.clone()];
        recs.sort_by(recommendation_sort);
        assert_eq!(recs[0].action_type, "a"); // higher loss reduction first
    }

    #[test]
    fn recommendation_sort_by_confidence_on_tie() {
        let a = test_candidate("a", "ext-a", 500_000, 900_000);
        let b = test_candidate("b", "ext-b", 500_000, 800_000);
        let mut recs = [b.clone(), a.clone()];
        recs.sort_by(recommendation_sort);
        assert_eq!(recs[0].action_type, "a"); // higher confidence first
    }

    #[test]
    fn recommendation_sort_by_action_type_on_tie() {
        let a = test_candidate("aaa", "ext-a", 500_000, 800_000);
        let b = test_candidate("bbb", "ext-a", 500_000, 800_000);
        let mut recs = [b.clone(), a.clone()];
        recs.sort_by(recommendation_sort);
        assert_eq!(recs[0].action_type, "aaa"); // alphabetical
    }

    // ── ConfidenceBand validate ───────────────────────────────────
    #[test]
    fn confidence_band_validate_valid() {
        let band = ConfidenceBand {
            metric: "m".to_string(),
            point_millionths: 500_000,
            lower_millionths: 300_000,
            upper_millionths: 700_000,
            confidence_level_bps: 9500,
        };
        band.validate().unwrap();
    }

    #[test]
    fn confidence_band_validate_inverted_bounds() {
        let band = ConfidenceBand {
            metric: "m".to_string(),
            point_millionths: 200_000,
            lower_millionths: 500_000,
            upper_millionths: 700_000,
            confidence_level_bps: 9500,
        };
        assert!(band.validate().is_err());
    }

    #[test]
    fn confidence_band_validate_zero_bps() {
        let band = ConfidenceBand {
            metric: "m".to_string(),
            point_millionths: 500_000,
            lower_millionths: 300_000,
            upper_millionths: 700_000,
            confidence_level_bps: 0,
        };
        assert!(band.validate().is_err());
    }

    #[test]
    fn confidence_band_validate_bps_over_10000() {
        let band = ConfidenceBand {
            metric: "m".to_string(),
            point_millionths: 500_000,
            lower_millionths: 300_000,
            upper_millionths: 700_000,
            confidence_level_bps: 10_001,
        };
        assert!(band.validate().is_err());
    }

    // ── DecisionBoundaryHint validate ─────────────────────────────
    #[test]
    fn decision_boundary_hint_validate_valid() {
        let hint = DecisionBoundaryHint {
            metric: "m".to_string(),
            current_millionths: 400_000,
            threshold_millionths: 500_000,
            additional_evidence_needed: 5,
            evidence_type: "hostcall".to_string(),
            trigger_direction: BoundaryTriggerDirection::AtOrAbove,
        };
        hint.validate().unwrap();
    }

    #[test]
    fn decision_boundary_hint_validate_zero_evidence() {
        let hint = DecisionBoundaryHint {
            metric: "m".to_string(),
            current_millionths: 400_000,
            threshold_millionths: 500_000,
            additional_evidence_needed: 0,
            evidence_type: "hostcall".to_string(),
            trigger_direction: BoundaryTriggerDirection::AtOrAbove,
        };
        assert!(hint.validate().is_err());
    }

    // ── build_operator_safety_copilot_surface ─────────────────────
    #[test]
    fn build_surface_basic() {
        let surface = build_test_surface();
        assert_eq!(surface.trace_id, "trace-1");
        assert_eq!(surface.decision_id, "dec-1");
        assert_eq!(surface.incident_id, "inc-1");
        assert!(surface.read_only);
        assert_eq!(surface.recommended_action.rank, 1);
        assert_eq!(surface.alternatives.len(), 1);
        assert!(!surface.logs.is_empty());
    }

    #[test]
    fn build_surface_ranks_by_loss_reduction() {
        let surface = build_test_surface();
        // throttle has 400k, isolate has 300k -> throttle should be rank 1
        assert_eq!(surface.recommended_action.action_type, "throttle");
        assert_eq!(surface.alternatives[0].action_type, "isolate");
    }

    #[test]
    fn build_surface_empty_recommendations_fails() {
        let mut input = test_input();
        input.recommendations.clear();
        assert!(build_operator_safety_copilot_surface(&input).is_err());
    }

    #[test]
    fn build_surface_empty_trace_id_fails() {
        let mut input = test_input();
        input.trace_id = "".to_string();
        assert!(build_operator_safety_copilot_surface(&input).is_err());
    }

    #[test]
    fn build_surface_negative_no_action_loss_fails() {
        let mut input = test_input();
        input.no_action_expected_loss_millionths = -1;
        assert!(build_operator_safety_copilot_surface(&input).is_err());
    }

    #[test]
    fn build_surface_invalid_confidence_probability_fails() {
        let mut input = test_input();
        input.recommendations[0].confidence_millionths = MILLION + 1;
        assert!(build_operator_safety_copilot_surface(&input).is_err());
    }

    #[test]
    fn build_surface_missing_snapshot_reversible_fails() {
        let mut input = test_input();
        input.recommendations[0].snapshot_id = None;
        assert!(build_operator_safety_copilot_surface(&input).is_err());
    }

    #[test]
    fn build_surface_missing_snapshot_limited_window_fails() {
        let mut input = test_input();
        input.recommendations[0].reversibility = RecommendationReversibility::LimitedWindow;
        input.recommendations[0].snapshot_id = None;
        assert!(build_operator_safety_copilot_surface(&input).is_err());
    }

    #[test]
    fn build_surface_missing_rollback_window_limited_fails() {
        let mut input = test_input();
        input.recommendations[0].reversibility = RecommendationReversibility::LimitedWindow;
        input.recommendations[0].rollback_window_ms = None;
        assert!(build_operator_safety_copilot_surface(&input).is_err());
    }

    #[test]
    fn build_surface_irreversible_no_snapshot_ok() {
        let mut input = test_input();
        input.recommendations[0].reversibility = RecommendationReversibility::Irreversible;
        input.recommendations[0].snapshot_id = None;
        input.recommendations[0].rollback_window_ms = None;
        build_operator_safety_copilot_surface(&input).unwrap();
    }

    #[test]
    fn build_surface_sorts_timeline_by_timestamp() {
        let mut input = test_input();
        input.timeline.push(IncidentTimelineEvent {
            timestamp_ns: 500,
            event_id: "evt-0".to_string(),
            event_type: "earlier".to_string(),
            detail: "first".to_string(),
            outcome: "ok".to_string(),
            error_code: None,
            drilldown: TimelineDrilldownPointers::default(),
        });
        let surface = build_operator_safety_copilot_surface(&input).unwrap();
        assert_eq!(surface.timeline[0].timestamp_ns, 500);
        assert_eq!(surface.timeline[1].timestamp_ns, 1000);
    }

    #[test]
    fn build_surface_sorts_confidence_bands() {
        let mut input = test_input();
        input.confidence_bands.push(ConfidenceBand {
            metric: "aaa_metric".to_string(),
            point_millionths: 100_000,
            lower_millionths: 50_000,
            upper_millionths: 200_000,
            confidence_level_bps: 9000,
        });
        let surface = build_operator_safety_copilot_surface(&input).unwrap();
        assert_eq!(surface.confidence_bands[0].metric, "aaa_metric");
    }

    // ── select_recommendation_for_review ──────────────────────────
    #[test]
    fn select_recommendation_rank_1() {
        let surface = build_test_surface();
        let identity = test_identity();
        let review = select_recommendation_for_review(&surface, &identity, 1, 999).unwrap();
        assert_eq!(review.selected_rank, 1);
        assert_eq!(review.selected_recommendation.action_type, "throttle");
        assert_eq!(review.audit_event.event, "copilot_action_selected");
    }

    #[test]
    fn select_recommendation_rank_2() {
        let surface = build_test_surface();
        let identity = test_identity();
        let review = select_recommendation_for_review(&surface, &identity, 2, 999).unwrap();
        assert_eq!(review.selected_rank, 2);
        assert_eq!(review.selected_recommendation.action_type, "isolate");
    }

    #[test]
    fn select_recommendation_rank_out_of_range() {
        let surface = build_test_surface();
        let identity = test_identity();
        let err = select_recommendation_for_review(&surface, &identity, 10, 999).unwrap_err();
        assert!(matches!(
            err,
            CopilotError::RecommendationRankOutOfRange { .. }
        ));
    }

    #[test]
    fn select_recommendation_viewer_unauthorized() {
        let surface = build_test_surface();
        let identity = OperatorIdentity {
            operator_id: "op-1".to_string(),
            role: OperatorRole::Viewer,
        };
        let err = select_recommendation_for_review(&surface, &identity, 1, 999).unwrap_err();
        assert!(matches!(err, CopilotError::UnauthorizedRole { .. }));
    }

    #[test]
    fn select_recommendation_empty_operator_id() {
        let surface = build_test_surface();
        let identity = OperatorIdentity {
            operator_id: "".to_string(),
            role: OperatorRole::Operator,
        };
        assert!(select_recommendation_for_review(&surface, &identity, 1, 999).is_err());
    }

    #[test]
    fn select_recommendation_administrator_allowed() {
        let surface = build_test_surface();
        let identity = OperatorIdentity {
            operator_id: "admin-1".to_string(),
            role: OperatorRole::Administrator,
        };
        select_recommendation_for_review(&surface, &identity, 1, 999).unwrap();
    }

    // ── confirm_selected_recommendation ───────────────────────────
    #[test]
    fn confirm_recommendation_basic() {
        let surface = build_test_surface();
        let identity = test_identity();
        let review = select_recommendation_for_review(&surface, &identity, 1, 999).unwrap();
        let confirmed =
            confirm_selected_recommendation(&review, &identity, "token-123", 1000).unwrap();
        assert!(!confirmed.execution_command.is_empty());
        assert!(confirmed.receipt.receipt_id.starts_with("action-receipt-"));
        assert_eq!(confirmed.audit_event.event, "copilot_action_confirmed");
        assert_eq!(confirmed.log_event.outcome, "pass");
    }

    #[test]
    fn confirm_recommendation_operator_mismatch() {
        let surface = build_test_surface();
        let identity = test_identity();
        let review = select_recommendation_for_review(&surface, &identity, 1, 999).unwrap();
        let other = OperatorIdentity {
            operator_id: "op-other".to_string(),
            role: OperatorRole::Operator,
        };
        let err = confirm_selected_recommendation(&review, &other, "token", 1000).unwrap_err();
        assert!(matches!(err, CopilotError::OperatorMismatch { .. }));
    }

    #[test]
    fn confirm_recommendation_empty_token() {
        let surface = build_test_surface();
        let identity = test_identity();
        let review = select_recommendation_for_review(&surface, &identity, 1, 999).unwrap();
        let err = confirm_selected_recommendation(&review, &identity, "  ", 1000).unwrap_err();
        assert!(matches!(err, CopilotError::MissingConfirmationToken));
    }

    #[test]
    fn confirm_recommendation_viewer_unauthorized() {
        let surface = build_test_surface();
        let identity = test_identity();
        let review = select_recommendation_for_review(&surface, &identity, 1, 999).unwrap();
        let viewer = OperatorIdentity {
            operator_id: "op-1".to_string(),
            role: OperatorRole::Viewer,
        };
        let err = confirm_selected_recommendation(&review, &viewer, "token", 1000).unwrap_err();
        assert!(matches!(err, CopilotError::UnauthorizedRole { .. }));
    }

    #[test]
    fn confirm_recommendation_receipt_deterministic() {
        let surface = build_test_surface();
        let identity = test_identity();
        let review = select_recommendation_for_review(&surface, &identity, 1, 999).unwrap();
        let c1 = confirm_selected_recommendation(&review, &identity, "token", 1000).unwrap();
        let c2 = confirm_selected_recommendation(&review, &identity, "token", 1000).unwrap();
        assert_eq!(c1.receipt.receipt_id, c2.receipt.receipt_id);
        assert_eq!(c1.receipt.signature, c2.receipt.signature);
    }

    // ── build_rollback_execution_receipt ───────────────────────────
    #[test]
    fn rollback_receipt_basic() {
        let input = RollbackReceiptInput {
            trace_id: "t1".to_string(),
            decision_id: "d1".to_string(),
            policy_id: "p1".to_string(),
            action_receipt_id: "ar-1".to_string(),
            rollback_decision_id: "rd-1".to_string(),
            evidence_pointer: "ep-1".to_string(),
            restoration_verification: "rv-1".to_string(),
            executed_at_ns: 5000,
        };
        let receipt = build_rollback_execution_receipt(&input).unwrap();
        assert!(receipt.receipt_id.starts_with("rollback-receipt-"));
        assert_eq!(receipt.action_receipt_id, "ar-1");
    }

    #[test]
    fn rollback_receipt_empty_field_fails() {
        let mut input = RollbackReceiptInput {
            trace_id: "t1".to_string(),
            decision_id: "d1".to_string(),
            policy_id: "p1".to_string(),
            action_receipt_id: "ar-1".to_string(),
            rollback_decision_id: "rd-1".to_string(),
            evidence_pointer: "ep-1".to_string(),
            restoration_verification: "rv-1".to_string(),
            executed_at_ns: 5000,
        };
        input.trace_id = "".to_string();
        assert!(build_rollback_execution_receipt(&input).is_err());
    }

    #[test]
    fn rollback_receipt_deterministic() {
        let input = RollbackReceiptInput {
            trace_id: "t1".to_string(),
            decision_id: "d1".to_string(),
            policy_id: "p1".to_string(),
            action_receipt_id: "ar-1".to_string(),
            rollback_decision_id: "rd-1".to_string(),
            evidence_pointer: "ep-1".to_string(),
            restoration_verification: "rv-1".to_string(),
            executed_at_ns: 5000,
        };
        let r1 = build_rollback_execution_receipt(&input).unwrap();
        let r2 = build_rollback_execution_receipt(&input).unwrap();
        assert_eq!(r1.receipt_id, r2.receipt_id);
        assert_eq!(r1.signature, r2.signature);
    }

    // ── build_fleet_health_overview ───────────────────────────────
    #[test]
    fn fleet_health_overview_basic() {
        let cards = vec![
            ExtensionTrustCard {
                extension_id: "ext-1".to_string(),
                trust_level: ExtensionTrustLevel::High,
                recent_evidence_atoms: 5,
                recent_decision_ids: vec!["d1".to_string()],
                current_recommendation: None,
            },
            ExtensionTrustCard {
                extension_id: "ext-2".to_string(),
                trust_level: ExtensionTrustLevel::Quarantined,
                recent_evidence_atoms: 10,
                recent_decision_ids: vec!["d2".to_string()],
                current_recommendation: Some("isolate".to_string()),
            },
        ];
        let incidents = vec![ActiveIncidentSummary {
            incident_id: "inc-1".to_string(),
            extension_id: "ext-2".to_string(),
            severity: IncidentSeverity::High,
            started_at_ns: 1000,
            status: "active".to_string(),
        }];
        let overview = build_fleet_health_overview(&cards, &incidents, &[100_000, 200_000], &[]);
        assert_eq!(overview.trust_level_distribution.len(), 4);
        assert_eq!(overview.active_incidents_count, 1);
        assert_eq!(overview.highest_severity, IncidentSeverity::High);
        assert_eq!(overview.extension_details.len(), 2);
    }

    #[test]
    fn fleet_health_overview_empty() {
        let overview = build_fleet_health_overview(&[], &[], &[], &[]);
        assert_eq!(overview.active_incidents_count, 0);
        assert_eq!(overview.highest_severity, IncidentSeverity::Low);
    }

    #[test]
    fn fleet_health_overview_sorts_extensions_by_id() {
        let cards = vec![
            ExtensionTrustCard {
                extension_id: "z-ext".to_string(),
                trust_level: ExtensionTrustLevel::High,
                recent_evidence_atoms: 0,
                recent_decision_ids: vec![],
                current_recommendation: None,
            },
            ExtensionTrustCard {
                extension_id: "a-ext".to_string(),
                trust_level: ExtensionTrustLevel::High,
                recent_evidence_atoms: 0,
                recent_decision_ids: vec![],
                current_recommendation: None,
            },
        ];
        let overview = build_fleet_health_overview(&cards, &[], &[], &[]);
        assert_eq!(overview.extension_details[0].extension_id, "a-ext");
        assert_eq!(overview.extension_details[1].extension_id, "z-ext");
    }

    // ── build_policy_effectiveness_view ───────────────────────────
    #[test]
    fn policy_effectiveness_view_basic() {
        let input = PolicyEffectivenessInput {
            detection_counts: vec![CategoryDetectionCount {
                category: "anomaly".to_string(),
                detected_events: 80,
                total_events: 100,
            }],
            false_positive_rate_trend_millionths: vec![50_000, 40_000],
            containment_latencies_ms: vec![10, 20, 30, 40, 50],
            calibration_history: vec![CalibrationPoint {
                timestamp_ns: 1000,
                expected_millionths: 800_000,
                observed_millionths: 750_000,
            }],
        };
        let view = build_policy_effectiveness_view(&input).unwrap();
        assert_eq!(view.detection_rate_by_category.len(), 1);
        assert_eq!(view.detection_rate_by_category[0].rate_millionths, 800_000);
        assert!(view.containment_latency_p50_ms > 0);
    }

    #[test]
    fn policy_effectiveness_view_zero_total_events() {
        let input = PolicyEffectivenessInput {
            detection_counts: vec![CategoryDetectionCount {
                category: "zero".to_string(),
                detected_events: 0,
                total_events: 0,
            }],
            false_positive_rate_trend_millionths: vec![],
            containment_latencies_ms: vec![],
            calibration_history: vec![],
        };
        let view = build_policy_effectiveness_view(&input).unwrap();
        assert_eq!(view.detection_rate_by_category[0].rate_millionths, 0);
    }

    #[test]
    fn policy_effectiveness_view_invalid_fp_rate_fails() {
        let input = PolicyEffectivenessInput {
            detection_counts: vec![],
            false_positive_rate_trend_millionths: vec![MILLION + 1],
            containment_latencies_ms: vec![],
            calibration_history: vec![],
        };
        assert!(build_policy_effectiveness_view(&input).is_err());
    }

    #[test]
    fn policy_effectiveness_view_sorts_categories() {
        let input = PolicyEffectivenessInput {
            detection_counts: vec![
                CategoryDetectionCount {
                    category: "zzz".to_string(),
                    detected_events: 10,
                    total_events: 100,
                },
                CategoryDetectionCount {
                    category: "aaa".to_string(),
                    detected_events: 20,
                    total_events: 100,
                },
            ],
            false_positive_rate_trend_millionths: vec![],
            containment_latencies_ms: vec![],
            calibration_history: vec![],
        };
        let view = build_policy_effectiveness_view(&input).unwrap();
        assert_eq!(view.detection_rate_by_category[0].category, "aaa");
    }

    // ── render_copilot_summary ────────────────────────────────────
    #[test]
    fn render_copilot_summary_basic() {
        let surface = build_test_surface();
        let summary = render_copilot_summary(&surface);
        assert!(summary.contains("trace_id: trace-1"));
        assert!(summary.contains("decision_id: dec-1"));
        assert!(summary.contains("incident_id: inc-1"));
        assert!(summary.contains("recommended_action: throttle ext-a"));
        assert!(summary.contains("read_only: true"));
    }

    #[test]
    fn render_copilot_summary_contains_alternatives() {
        let surface = build_test_surface();
        let summary = render_copilot_summary(&surface);
        assert!(summary.contains("alternative_1: isolate ext-b"));
    }

    #[test]
    fn render_copilot_summary_contains_confidence_bands() {
        let surface = build_test_surface();
        let summary = render_copilot_summary(&surface);
        assert!(summary.contains("confidence_band:attack_probability"));
    }

    #[test]
    fn render_copilot_summary_contains_decision_boundaries() {
        let surface = build_test_surface();
        let summary = render_copilot_summary(&surface);
        assert!(summary.contains("decision_boundary:attacker_roi"));
    }

    // ── build_rollback_command ─────────────────────────────────────
    #[test]
    fn rollback_command_reversible() {
        let candidate = test_candidate("throttle", "ext-a", 400_000, 800_000);
        let cmd = build_rollback_command("t1", "d1", "p1", &candidate);
        assert!(cmd.command.contains("rollback throttle"));
        assert!(cmd.command.contains("--snapshot-id snap-1"));
        assert!(cmd.command.contains("--verify"));
    }

    #[test]
    fn rollback_command_limited_window() {
        let mut candidate = test_candidate("isolate", "ext-b", 300_000, 700_000);
        candidate.reversibility = RecommendationReversibility::LimitedWindow;
        candidate.rollback_window_ms = Some(60_000);
        let cmd = build_rollback_command("t1", "d1", "p1", &candidate);
        assert!(cmd.command.contains("--window-ms 60000"));
    }

    #[test]
    fn rollback_command_irreversible() {
        let mut candidate = test_candidate("terminate", "ext-c", 200_000, 600_000);
        candidate.reversibility = RecommendationReversibility::Irreversible;
        let cmd = build_rollback_command("t1", "d1", "p1", &candidate);
        assert!(cmd.command.contains("mark-irreversible"));
        assert!(cmd.command.contains("--acknowledge"));
        assert!(cmd.safety_summary.contains("irreversible"));
    }

    // ── Serde round-trips for data types ──────────────────────────
    #[test]
    fn copilot_structured_log_event_serde() {
        let evt = CopilotStructuredLogEvent {
            trace_id: "t".to_string(),
            decision_id: "d".to_string(),
            policy_id: "p".to_string(),
            component: COPILOT_COMPONENT.to_string(),
            event: "test".to_string(),
            outcome: "pass".to_string(),
            error_code: None,
        };
        let json = serde_json::to_string(&evt).unwrap();
        let back: CopilotStructuredLogEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(evt, back);
    }

    #[test]
    fn operator_audit_event_serde() {
        let evt = OperatorAuditEvent {
            trace_id: "t".to_string(),
            decision_id: "d".to_string(),
            policy_id: "p".to_string(),
            operator_id: "op".to_string(),
            operator_role: OperatorRole::Operator,
            event: "test".to_string(),
            outcome: "pass".to_string(),
            context: "ctx".to_string(),
            timestamp_ns: 1234,
            error_code: None,
        };
        let json = serde_json::to_string(&evt).unwrap();
        let back: OperatorAuditEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(evt, back);
    }

    #[test]
    fn action_impact_summary_serde() {
        let s = ActionImpactSummary {
            dependent_extensions_affected: 3,
            estimated_latency_ms: 100,
            reversible: true,
            rollback_window_ms_remaining: Some(30_000),
        };
        let json = serde_json::to_string(&s).unwrap();
        let back: ActionImpactSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }

    #[test]
    fn timeline_drilldown_pointers_default() {
        let p = TimelineDrilldownPointers::default();
        assert!(p.evidence_pointer.is_none());
        assert!(p.decision_receipt_pointer.is_none());
        assert!(p.replay_pointer.is_none());
        assert!(p.counterfactual_pointer.is_none());
    }

    // -- Enrichment: serde roundtrips for untested types (PearlTower 2026-02-26) --

    #[test]
    fn extension_trust_level_serde_roundtrip_all() {
        let variants = [
            ExtensionTrustLevel::High,
            ExtensionTrustLevel::Guarded,
            ExtensionTrustLevel::Watch,
            ExtensionTrustLevel::Quarantined,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: ExtensionTrustLevel = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    #[test]
    fn confidence_band_serde_roundtrip() {
        let cb = ConfidenceBand {
            metric: "accuracy".into(),
            point_millionths: 500_000,
            lower_millionths: 400_000,
            upper_millionths: 600_000,
            confidence_level_bps: 9500,
        };
        let json = serde_json::to_string(&cb).unwrap();
        let back: ConfidenceBand = serde_json::from_str(&json).unwrap();
        assert_eq!(cb, back);
    }

    #[test]
    fn evidence_strength_serde_roundtrip() {
        let es = EvidenceStrength {
            evidence_atoms: 42,
            observation_window_seconds: 3600,
        };
        let json = serde_json::to_string(&es).unwrap();
        let back: EvidenceStrength = serde_json::from_str(&json).unwrap();
        assert_eq!(es, back);
    }

    #[test]
    fn decision_boundary_hint_serde_roundtrip() {
        let h = DecisionBoundaryHint {
            metric: "safety_score".into(),
            current_millionths: 700_000,
            threshold_millionths: 800_000,
            additional_evidence_needed: 5,
            evidence_type: "test_run".into(),
            trigger_direction: BoundaryTriggerDirection::AtOrAbove,
        };
        let json = serde_json::to_string(&h).unwrap();
        let back: DecisionBoundaryHint = serde_json::from_str(&json).unwrap();
        assert_eq!(h, back);
    }

    #[test]
    fn timeline_drilldown_pointers_serde_roundtrip() {
        let p = TimelineDrilldownPointers {
            evidence_pointer: Some("ev-1".into()),
            decision_receipt_pointer: None,
            replay_pointer: Some("rp-1".into()),
            counterfactual_pointer: None,
        };
        let json = serde_json::to_string(&p).unwrap();
        let back: TimelineDrilldownPointers = serde_json::from_str(&json).unwrap();
        assert_eq!(p, back);
    }

    #[test]
    fn incident_timeline_event_serde_roundtrip() {
        let e = IncidentTimelineEvent {
            timestamp_ns: 1_000_000,
            event_id: "evt-1".into(),
            event_type: "detection".into(),
            detail: "anomaly detected".into(),
            outcome: "flagged".into(),
            error_code: None,
            drilldown: TimelineDrilldownPointers::default(),
        };
        let json = serde_json::to_string(&e).unwrap();
        let back: IncidentTimelineEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(e, back);
    }

    #[test]
    fn rollback_command_serde_roundtrip() {
        let rc = RollbackCommand {
            command: "restore-snapshot ext-a snap-123".into(),
            safety_summary: "reverts to known-good state".into(),
        };
        let json = serde_json::to_string(&rc).unwrap();
        let back: RollbackCommand = serde_json::from_str(&json).unwrap();
        assert_eq!(rc, back);
    }

    #[test]
    fn operator_identity_serde_roundtrip() {
        let id = OperatorIdentity {
            operator_id: "op-1".into(),
            role: OperatorRole::Administrator,
        };
        let json = serde_json::to_string(&id).unwrap();
        let back: OperatorIdentity = serde_json::from_str(&json).unwrap();
        assert_eq!(id, back);
    }

    #[test]
    fn action_recommendation_candidate_serde_roundtrip() {
        let c = ActionRecommendationCandidate {
            action_type: "quarantine".into(),
            target_extension: "ext-a".into(),
            expected_loss_reduction_millionths: 500_000,
            confidence_millionths: 800_000,
            side_effects: vec!["downtime".into()],
            collateral_extensions: 2,
            estimated_action_latency_ms: 1000,
            reversibility: RecommendationReversibility::Reversible,
            time_sensitivity: TimeSensitivity::Immediate,
            rollback_window_ms: Some(60_000),
            snapshot_id: Some("snap-1".into()),
        };
        let json = serde_json::to_string(&c).unwrap();
        let back: ActionRecommendationCandidate = serde_json::from_str(&json).unwrap();
        assert_eq!(c, back);
    }

    #[test]
    fn action_execution_receipt_serde_roundtrip() {
        let r = ActionExecutionReceipt {
            receipt_id: "rcpt-1".into(),
            signature: "sig-abc".into(),
            trace_id: "t-1".into(),
            decision_id: "d-1".into(),
            policy_id: "p-1".into(),
            incident_id: "inc-1".into(),
            action_type: "quarantine".into(),
            target_extension: "ext-a".into(),
            operator_id: "op-1".into(),
            confirmed_at_ns: 999_000,
            rollback_command: "rollback ext-a".into(),
        };
        let json = serde_json::to_string(&r).unwrap();
        let back: ActionExecutionReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }

    // -- Enrichment: serde roundtrips for remaining types (PearlTower 2026-02-27) --

    fn make_rollback_cmd() -> RollbackCommand {
        RollbackCommand {
            command: "rollback ext-a".into(),
            safety_summary: "safe to rollback".into(),
        }
    }

    fn make_ranked_rec(rank: u32) -> RankedRecommendation {
        RankedRecommendation {
            rank,
            action_type: "quarantine".into(),
            target_extension: "ext-a".into(),
            expected_loss_reduction_millionths: 500_000,
            confidence_millionths: 900_000,
            side_effects: vec!["disable ext-b".into()],
            collateral_extensions: 1,
            estimated_action_latency_ms: 50,
            reversibility: RecommendationReversibility::Reversible,
            time_sensitivity: TimeSensitivity::Immediate,
            rollback_window_ms: Some(60_000),
            rollback_command: make_rollback_cmd(),
            explanation: "quarantine to stop exfil".into(),
        }
    }

    fn make_audit_event() -> OperatorAuditEvent {
        OperatorAuditEvent {
            trace_id: "t-1".into(),
            decision_id: "d-1".into(),
            policy_id: "p-1".into(),
            operator_id: "op-1".into(),
            operator_role: OperatorRole::Administrator,
            event: "confirm".into(),
            outcome: "ok".into(),
            context: "manual".into(),
            timestamp_ns: 1_000_000,
            error_code: None,
        }
    }

    fn make_log_event() -> CopilotStructuredLogEvent {
        CopilotStructuredLogEvent {
            trace_id: "t-1".into(),
            decision_id: "d-1".into(),
            policy_id: "p-1".into(),
            component: "copilot".into(),
            event: "surface_rendered".into(),
            outcome: "ok".into(),
            error_code: None,
        }
    }

    #[test]
    fn ranked_recommendation_serde_roundtrip() {
        let r = make_ranked_rec(1);
        let json = serde_json::to_string(&r).unwrap();
        let back: RankedRecommendation = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn copilot_structured_log_event_serde_roundtrip() {
        let e = make_log_event();
        let json = serde_json::to_string(&e).unwrap();
        let back: CopilotStructuredLogEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(e, back);
    }

    #[test]
    fn operator_audit_event_serde_roundtrip() {
        let e = make_audit_event();
        let json = serde_json::to_string(&e).unwrap();
        let back: OperatorAuditEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(e, back);
    }

    #[test]
    fn action_impact_summary_serde_roundtrip() {
        let s = ActionImpactSummary {
            dependent_extensions_affected: 3,
            estimated_latency_ms: 200,
            reversible: true,
            rollback_window_ms_remaining: Some(30_000),
        };
        let json = serde_json::to_string(&s).unwrap();
        let back: ActionImpactSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }

    #[test]
    fn action_selection_review_serde_roundtrip() {
        let r = ActionSelectionReview {
            trace_id: "t-1".into(),
            decision_id: "d-1".into(),
            policy_id: "p-1".into(),
            incident_id: "inc-1".into(),
            selected_rank: 1,
            selected_recommendation: make_ranked_rec(1),
            impact_summary: ActionImpactSummary {
                dependent_extensions_affected: 2,
                estimated_latency_ms: 100,
                reversible: true,
                rollback_window_ms_remaining: None,
            },
            selected_by: OperatorIdentity {
                operator_id: "op-1".into(),
                role: OperatorRole::Administrator,
            },
            selected_at_ns: 2_000_000,
            audit_event: make_audit_event(),
        };
        let json = serde_json::to_string(&r).unwrap();
        let back: ActionSelectionReview = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn confirmed_action_execution_serde_roundtrip() {
        let c = ConfirmedActionExecution {
            execution_command: "quarantine ext-a".into(),
            rollback_command: make_rollback_cmd(),
            receipt: ActionExecutionReceipt {
                receipt_id: "rcpt-1".into(),
                signature: "sig-1".into(),
                trace_id: "t-1".into(),
                decision_id: "d-1".into(),
                policy_id: "p-1".into(),
                incident_id: "inc-1".into(),
                action_type: "quarantine".into(),
                target_extension: "ext-a".into(),
                operator_id: "op-1".into(),
                confirmed_at_ns: 3_000_000,
                rollback_command: "rollback ext-a".into(),
            },
            audit_event: make_audit_event(),
            log_event: make_log_event(),
        };
        let json = serde_json::to_string(&c).unwrap();
        let back: ConfirmedActionExecution = serde_json::from_str(&json).unwrap();
        assert_eq!(c, back);
    }

    #[test]
    fn rollback_receipt_input_serde_roundtrip() {
        let r = RollbackReceiptInput {
            trace_id: "t-1".into(),
            decision_id: "d-1".into(),
            policy_id: "p-1".into(),
            action_receipt_id: "rcpt-1".into(),
            rollback_decision_id: "rd-1".into(),
            evidence_pointer: "ev-ptr".into(),
            restoration_verification: "verified".into(),
            executed_at_ns: 4_000_000,
        };
        let json = serde_json::to_string(&r).unwrap();
        let back: RollbackReceiptInput = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn rollback_execution_receipt_serde_roundtrip() {
        let r = RollbackExecutionReceipt {
            receipt_id: "rb-rcpt-1".into(),
            signature: "sig-rb".into(),
            trace_id: "t-1".into(),
            decision_id: "d-1".into(),
            policy_id: "p-1".into(),
            action_receipt_id: "rcpt-1".into(),
            rollback_decision_id: "rd-1".into(),
            evidence_pointer: "ev-ptr".into(),
            restoration_verification: "verified".into(),
            executed_at_ns: 5_000_000,
        };
        let json = serde_json::to_string(&r).unwrap();
        let back: RollbackExecutionReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn extension_trust_card_serde_roundtrip() {
        let c = ExtensionTrustCard {
            extension_id: "ext-a".into(),
            trust_level: ExtensionTrustLevel::High,
            recent_evidence_atoms: 12,
            recent_decision_ids: vec!["d-1".into(), "d-2".into()],
            current_recommendation: Some("monitor".into()),
        };
        let json = serde_json::to_string(&c).unwrap();
        let back: ExtensionTrustCard = serde_json::from_str(&json).unwrap();
        assert_eq!(c, back);
    }

    #[test]
    fn active_incident_summary_serde_roundtrip() {
        let s = ActiveIncidentSummary {
            incident_id: "inc-1".into(),
            extension_id: "ext-a".into(),
            severity: IncidentSeverity::High,
            started_at_ns: 100_000,
            status: "active".into(),
        };
        let json = serde_json::to_string(&s).unwrap();
        let back: ActiveIncidentSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }

    #[test]
    fn fleet_health_overview_serde_roundtrip() {
        let f = FleetHealthOverview {
            trust_level_distribution: vec![TrustLevelDistributionEntry {
                trust_level: ExtensionTrustLevel::High,
                extensions: 5,
            }],
            active_incidents: vec![],
            active_incidents_count: 0,
            highest_severity: IncidentSeverity::Low,
            attacker_roi_trend_millionths: vec![100_000, 90_000],
            recent_containment_actions: vec![ContainmentActionOutcome {
                incident_id: "inc-old".into(),
                action_type: "quarantine".into(),
                outcome: "success".into(),
                latency_ms: 45,
            }],
            extension_details: vec![],
        };
        let json = serde_json::to_string(&f).unwrap();
        let back: FleetHealthOverview = serde_json::from_str(&json).unwrap();
        assert_eq!(f, back);
    }

    #[test]
    fn policy_effectiveness_input_serde_roundtrip() {
        let p = PolicyEffectivenessInput {
            detection_counts: vec![CategoryDetectionCount {
                category: "exfil".into(),
                detected_events: 95,
                total_events: 100,
            }],
            false_positive_rate_trend_millionths: vec![50_000, 45_000],
            containment_latencies_ms: vec![10, 20, 30],
            calibration_history: vec![CalibrationPoint {
                timestamp_ns: 1_000,
                expected_millionths: 900_000,
                observed_millionths: 880_000,
            }],
        };
        let json = serde_json::to_string(&p).unwrap();
        let back: PolicyEffectivenessInput = serde_json::from_str(&json).unwrap();
        assert_eq!(p, back);
    }

    #[test]
    fn policy_effectiveness_view_serde_roundtrip() {
        let v = PolicyEffectivenessView {
            detection_rate_by_category: vec![CategoryDetectionRate {
                category: "exfil".into(),
                detected_events: 95,
                total_events: 100,
                rate_millionths: 950_000,
            }],
            false_positive_rate_trend_millionths: vec![50_000],
            containment_latency_p50_ms: 15,
            containment_latency_p95_ms: 45,
            calibration_history: vec![],
        };
        let json = serde_json::to_string(&v).unwrap();
        let back: PolicyEffectivenessView = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }

    #[test]
    fn copilot_error_serde_roundtrip_all_variants() {
        let variants: Vec<CopilotError> = vec![
            CopilotError::MissingRecommendations,
            CopilotError::InvalidProbability {
                field: "conf".into(),
                value: -1,
            },
            CopilotError::InvalidField {
                field: "name".into(),
            },
            CopilotError::InvalidConfidenceBand {
                metric: "loss".into(),
            },
            CopilotError::InvalidDecisionBoundaryHint {
                metric: "threshold".into(),
            },
            CopilotError::MissingSnapshotForRollback {
                action_type: "quarantine".into(),
                target_extension: "ext".into(),
            },
            CopilotError::InvalidRollbackWindow {
                action_type: "quarantine".into(),
                target_extension: "ext".into(),
            },
            CopilotError::UnauthorizedRole {
                role: OperatorRole::Viewer,
                action: "execute".into(),
            },
            CopilotError::RecommendationRankOutOfRange {
                requested_rank: 5,
                available: 3,
            },
            CopilotError::OperatorMismatch {
                selected_by: "a".into(),
                confirmed_by: "b".into(),
            },
            CopilotError::MissingConfirmationToken,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: CopilotError = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
        assert_eq!(variants.len(), 11);
    }

    #[test]
    fn copilot_error_display_all_unique() {
        let variants: Vec<CopilotError> = vec![
            CopilotError::MissingRecommendations,
            CopilotError::InvalidProbability {
                field: "a".into(),
                value: 0,
            },
            CopilotError::InvalidField { field: "a".into() },
            CopilotError::InvalidConfidenceBand { metric: "a".into() },
            CopilotError::InvalidDecisionBoundaryHint { metric: "a".into() },
            CopilotError::MissingSnapshotForRollback {
                action_type: "a".into(),
                target_extension: "b".into(),
            },
            CopilotError::InvalidRollbackWindow {
                action_type: "a".into(),
                target_extension: "b".into(),
            },
            CopilotError::UnauthorizedRole {
                role: OperatorRole::Viewer,
                action: "a".into(),
            },
            CopilotError::RecommendationRankOutOfRange {
                requested_rank: 1,
                available: 1,
            },
            CopilotError::OperatorMismatch {
                selected_by: "a".into(),
                confirmed_by: "b".into(),
            },
            CopilotError::MissingConfirmationToken,
        ];
        let displays: std::collections::BTreeSet<String> =
            variants.iter().map(|e| e.to_string()).collect();
        assert_eq!(displays.len(), 11);
    }
}
