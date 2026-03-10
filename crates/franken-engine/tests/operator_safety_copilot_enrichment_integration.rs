//! Enrichment integration tests for operator_safety_copilot module.
//!
//! Covers serde roundtrips for all public types, Display impls,
//! error variant coverage, validation edge cases, and cross-function
//! interaction patterns not exercised by the existing 14 integration tests.
//!
//! bd-1ddd: Section 10.12 item 19.

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op,
    clippy::manual_abs_diff
)]

use frankenengine_engine::policy_controller::operator_safety_copilot::{
    ActionExecutionReceipt, ActionImpactSummary, ActionRecommendationCandidate,
    ActiveIncidentSummary, BoundaryTriggerDirection, CalibrationPoint, CategoryDetectionCount,
    CategoryDetectionRate, ConfidenceBand, ConfirmedActionExecution, ContainmentActionOutcome,
    CopilotError, CopilotStructuredLogEvent, DecisionBoundaryHint, EvidenceStrength,
    ExtensionTrustCard, ExtensionTrustLevel, FleetHealthOverview, IncidentSeverity,
    IncidentTimelineEvent, OperatorAuditEvent, OperatorIdentity, OperatorRole,
    OperatorSafetyCopilotInput, OperatorSafetyCopilotSurface, PolicyEffectivenessInput,
    PolicyEffectivenessView, RecommendationReversibility, RollbackCommand,
    RollbackExecutionReceipt, RollbackReceiptInput, TimeSensitivity, TimelineDrilldownPointers,
    TrustLevelDistributionEntry, build_fleet_health_overview,
    build_operator_safety_copilot_surface, build_policy_effectiveness_view,
    build_rollback_execution_receipt, confirm_selected_recommendation, render_copilot_summary,
    select_recommendation_for_review,
};

// ===========================================================================
// Helpers
// ===========================================================================

fn sample_input() -> OperatorSafetyCopilotInput {
    OperatorSafetyCopilotInput {
        trace_id: "trace-enrich-1".to_string(),
        decision_id: "decision-enrich-1".to_string(),
        policy_id: "policy-enrich-1".to_string(),
        incident_id: "incident-enrich-1".to_string(),
        no_action_expected_loss_millionths: 5_000_000,
        recommendations: vec![
            ActionRecommendationCandidate {
                action_type: "sandbox".to_string(),
                target_extension: "ext-a".to_string(),
                expected_loss_reduction_millionths: 3_000_000,
                confidence_millionths: 800_000,
                side_effects: vec!["restricted fs".to_string()],
                collateral_extensions: 1,
                estimated_action_latency_ms: 100,
                reversibility: RecommendationReversibility::LimitedWindow,
                time_sensitivity: TimeSensitivity::Immediate,
                rollback_window_ms: Some(600_000),
                snapshot_id: Some("snap-a".to_string()),
            },
            ActionRecommendationCandidate {
                action_type: "terminate".to_string(),
                target_extension: "ext-a".to_string(),
                expected_loss_reduction_millionths: 4_500_000,
                confidence_millionths: 700_000,
                side_effects: vec!["connection drop".to_string()],
                collateral_extensions: 2,
                estimated_action_latency_ms: 50,
                reversibility: RecommendationReversibility::Irreversible,
                time_sensitivity: TimeSensitivity::Immediate,
                rollback_window_ms: None,
                snapshot_id: None,
            },
        ],
        confidence_bands: vec![ConfidenceBand {
            metric: "p_malicious".to_string(),
            point_millionths: 700_000,
            lower_millionths: 500_000,
            upper_millionths: 900_000,
            confidence_level_bps: 8_000,
        }],
        evidence_strength: EvidenceStrength {
            evidence_atoms: 20,
            observation_window_seconds: 300,
        },
        decision_boundary_hints: vec![DecisionBoundaryHint {
            metric: "auto_terminate".to_string(),
            current_millionths: 700_000,
            threshold_millionths: 900_000,
            additional_evidence_needed: 3,
            evidence_type: "hostcall_anomaly".to_string(),
            trigger_direction: BoundaryTriggerDirection::AtOrAbove,
        }],
        timeline: vec![IncidentTimelineEvent {
            timestamp_ns: 100,
            event_id: "ev-1".to_string(),
            event_type: "evidence".to_string(),
            detail: "hostcall burst".to_string(),
            outcome: "pass".to_string(),
            error_code: None,
            drilldown: TimelineDrilldownPointers::default(),
        }],
    }
}

fn op(id: &str, role: OperatorRole) -> OperatorIdentity {
    OperatorIdentity {
        operator_id: id.to_string(),
        role,
    }
}

// ===========================================================================
// Section 1: Enum serde roundtrips
// ===========================================================================

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
fn extension_trust_level_serde() {
    for v in [
        ExtensionTrustLevel::High,
        ExtensionTrustLevel::Guarded,
        ExtensionTrustLevel::Watch,
        ExtensionTrustLevel::Quarantined,
    ] {
        let json = serde_json::to_string(&v).unwrap();
        let back: ExtensionTrustLevel = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }
}

// ===========================================================================
// Section 2: Enum ordering
// ===========================================================================

#[test]
fn incident_severity_ordering() {
    assert!(IncidentSeverity::Low < IncidentSeverity::Medium);
    assert!(IncidentSeverity::Medium < IncidentSeverity::High);
    assert!(IncidentSeverity::High < IncidentSeverity::Critical);
}

#[test]
fn extension_trust_level_ordering() {
    assert!(ExtensionTrustLevel::High < ExtensionTrustLevel::Guarded);
    assert!(ExtensionTrustLevel::Guarded < ExtensionTrustLevel::Watch);
    assert!(ExtensionTrustLevel::Watch < ExtensionTrustLevel::Quarantined);
}

// ===========================================================================
// Section 3: Struct serde roundtrips
// ===========================================================================

#[test]
fn confidence_band_serde() {
    let cb = ConfidenceBand {
        metric: "test".to_string(),
        point_millionths: 500_000,
        lower_millionths: 300_000,
        upper_millionths: 700_000,
        confidence_level_bps: 9_500,
    };
    let json = serde_json::to_string(&cb).unwrap();
    let back: ConfidenceBand = serde_json::from_str(&json).unwrap();
    assert_eq!(cb, back);
}

#[test]
fn evidence_strength_serde() {
    let es = EvidenceStrength {
        evidence_atoms: 42,
        observation_window_seconds: 600,
    };
    let json = serde_json::to_string(&es).unwrap();
    let back: EvidenceStrength = serde_json::from_str(&json).unwrap();
    assert_eq!(es, back);
}

#[test]
fn decision_boundary_hint_serde() {
    let dbh = DecisionBoundaryHint {
        metric: "threshold".to_string(),
        current_millionths: 400_000,
        threshold_millionths: 600_000,
        additional_evidence_needed: 2,
        evidence_type: "probe".to_string(),
        trigger_direction: BoundaryTriggerDirection::AtOrAbove,
    };
    let json = serde_json::to_string(&dbh).unwrap();
    let back: DecisionBoundaryHint = serde_json::from_str(&json).unwrap();
    assert_eq!(dbh, back);
}

#[test]
fn timeline_drilldown_pointers_default_is_all_none() {
    let dd = TimelineDrilldownPointers::default();
    assert_eq!(dd.evidence_pointer, None);
    assert_eq!(dd.decision_receipt_pointer, None);
    assert_eq!(dd.replay_pointer, None);
    assert_eq!(dd.counterfactual_pointer, None);
}

#[test]
fn timeline_drilldown_pointers_serde() {
    let dd = TimelineDrilldownPointers {
        evidence_pointer: Some("ev://1".to_string()),
        decision_receipt_pointer: Some("receipt://2".to_string()),
        replay_pointer: None,
        counterfactual_pointer: Some("cf://3".to_string()),
    };
    let json = serde_json::to_string(&dd).unwrap();
    let back: TimelineDrilldownPointers = serde_json::from_str(&json).unwrap();
    assert_eq!(dd, back);
}

#[test]
fn incident_timeline_event_serde() {
    let ite = IncidentTimelineEvent {
        timestamp_ns: 999,
        event_id: "ev-x".to_string(),
        event_type: "alert".to_string(),
        detail: "anomaly detected".to_string(),
        outcome: "pass".to_string(),
        error_code: Some("E001".to_string()),
        drilldown: TimelineDrilldownPointers::default(),
    };
    let json = serde_json::to_string(&ite).unwrap();
    let back: IncidentTimelineEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(ite, back);
}

#[test]
fn rollback_command_serde() {
    let rc = RollbackCommand {
        command: "rollback sandbox --verify".to_string(),
        safety_summary: "reversible; latency=100ms".to_string(),
    };
    let json = serde_json::to_string(&rc).unwrap();
    let back: RollbackCommand = serde_json::from_str(&json).unwrap();
    assert_eq!(rc, back);
}

#[test]
fn operator_identity_serde() {
    let oi = op("op-1", OperatorRole::Administrator);
    let json = serde_json::to_string(&oi).unwrap();
    let back: OperatorIdentity = serde_json::from_str(&json).unwrap();
    assert_eq!(oi, back);
}

#[test]
fn action_impact_summary_serde() {
    let ais = ActionImpactSummary {
        dependent_extensions_affected: 3,
        estimated_latency_ms: 150,
        reversible: false,
        rollback_window_ms_remaining: Some(60_000),
    };
    let json = serde_json::to_string(&ais).unwrap();
    let back: ActionImpactSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(ais, back);
}

#[test]
fn action_execution_receipt_serde() {
    let aer = ActionExecutionReceipt {
        receipt_id: "rcpt-1".to_string(),
        signature: "sig-abc".to_string(),
        trace_id: "t-1".to_string(),
        decision_id: "d-1".to_string(),
        policy_id: "p-1".to_string(),
        incident_id: "i-1".to_string(),
        action_type: "sandbox".to_string(),
        target_extension: "ext-a".to_string(),
        operator_id: "op-1".to_string(),
        confirmed_at_ns: 12345,
        rollback_command: "rollback sandbox --verify".to_string(),
    };
    let json = serde_json::to_string(&aer).unwrap();
    let back: ActionExecutionReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(aer, back);
}

#[test]
fn rollback_receipt_input_serde() {
    let rri = RollbackReceiptInput {
        trace_id: "t-1".to_string(),
        decision_id: "d-1".to_string(),
        policy_id: "p-1".to_string(),
        action_receipt_id: "rcpt-1".to_string(),
        rollback_decision_id: "rd-1".to_string(),
        evidence_pointer: "ev://rollback".to_string(),
        restoration_verification: "restored snap-1".to_string(),
        executed_at_ns: 99999,
    };
    let json = serde_json::to_string(&rri).unwrap();
    let back: RollbackReceiptInput = serde_json::from_str(&json).unwrap();
    assert_eq!(rri, back);
}

#[test]
fn rollback_execution_receipt_serde() {
    let rer = RollbackExecutionReceipt {
        receipt_id: "rb-rcpt-1".to_string(),
        signature: "rb-sig".to_string(),
        trace_id: "t-1".to_string(),
        decision_id: "d-1".to_string(),
        policy_id: "p-1".to_string(),
        action_receipt_id: "rcpt-1".to_string(),
        rollback_decision_id: "rd-1".to_string(),
        evidence_pointer: "ev://rb".to_string(),
        restoration_verification: "restored".to_string(),
        executed_at_ns: 88888,
    };
    let json = serde_json::to_string(&rer).unwrap();
    let back: RollbackExecutionReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(rer, back);
}

#[test]
fn extension_trust_card_serde() {
    let etc = ExtensionTrustCard {
        extension_id: "ext-z".to_string(),
        trust_level: ExtensionTrustLevel::Watch,
        recent_evidence_atoms: 7,
        recent_decision_ids: vec!["d-1".to_string(), "d-2".to_string()],
        current_recommendation: None,
    };
    let json = serde_json::to_string(&etc).unwrap();
    let back: ExtensionTrustCard = serde_json::from_str(&json).unwrap();
    assert_eq!(etc, back);
}

#[test]
fn active_incident_summary_serde() {
    let ais = ActiveIncidentSummary {
        incident_id: "inc-1".to_string(),
        extension_id: "ext-a".to_string(),
        severity: IncidentSeverity::Critical,
        started_at_ns: 1000,
        status: "active".to_string(),
    };
    let json = serde_json::to_string(&ais).unwrap();
    let back: ActiveIncidentSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(ais, back);
}

#[test]
fn containment_action_outcome_serde() {
    let cao = ContainmentActionOutcome {
        incident_id: "inc-1".to_string(),
        action_type: "sandbox".to_string(),
        outcome: "pass".to_string(),
        latency_ms: 250,
    };
    let json = serde_json::to_string(&cao).unwrap();
    let back: ContainmentActionOutcome = serde_json::from_str(&json).unwrap();
    assert_eq!(cao, back);
}

#[test]
fn trust_level_distribution_entry_serde() {
    let tle = TrustLevelDistributionEntry {
        trust_level: ExtensionTrustLevel::Quarantined,
        extensions: 5,
    };
    let json = serde_json::to_string(&tle).unwrap();
    let back: TrustLevelDistributionEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(tle, back);
}

#[test]
fn category_detection_count_serde() {
    let cdc = CategoryDetectionCount {
        category: "malware".to_string(),
        detected_events: 10,
        total_events: 20,
    };
    let json = serde_json::to_string(&cdc).unwrap();
    let back: CategoryDetectionCount = serde_json::from_str(&json).unwrap();
    assert_eq!(cdc, back);
}

#[test]
fn category_detection_rate_serde() {
    let cdr = CategoryDetectionRate {
        category: "phishing".to_string(),
        detected_events: 5,
        total_events: 10,
        rate_millionths: 500_000,
    };
    let json = serde_json::to_string(&cdr).unwrap();
    let back: CategoryDetectionRate = serde_json::from_str(&json).unwrap();
    assert_eq!(cdr, back);
}

#[test]
fn calibration_point_serde() {
    let cp = CalibrationPoint {
        timestamp_ns: 42,
        expected_millionths: 600_000,
        observed_millionths: 590_000,
    };
    let json = serde_json::to_string(&cp).unwrap();
    let back: CalibrationPoint = serde_json::from_str(&json).unwrap();
    assert_eq!(cp, back);
}

#[test]
fn copilot_structured_log_event_serde() {
    let le = CopilotStructuredLogEvent {
        trace_id: "t-1".to_string(),
        decision_id: "d-1".to_string(),
        policy_id: "p-1".to_string(),
        component: "operator_safety_copilot".to_string(),
        event: "copilot_surface_built".to_string(),
        outcome: "pass".to_string(),
        error_code: None,
    };
    let json = serde_json::to_string(&le).unwrap();
    let back: CopilotStructuredLogEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(le, back);
}

#[test]
fn operator_audit_event_serde() {
    let oae = OperatorAuditEvent {
        trace_id: "t-1".to_string(),
        decision_id: "d-1".to_string(),
        policy_id: "p-1".to_string(),
        operator_id: "op-1".to_string(),
        operator_role: OperatorRole::Operator,
        event: "action_selected".to_string(),
        outcome: "pending".to_string(),
        context: "rank=1".to_string(),
        timestamp_ns: 99,
        error_code: Some("E001".to_string()),
    };
    let json = serde_json::to_string(&oae).unwrap();
    let back: OperatorAuditEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(oae, back);
}

// ===========================================================================
// Section 4: CopilotError — all variants serde + Display
// ===========================================================================

#[test]
fn copilot_error_missing_recommendations_serde_display() {
    let e = CopilotError::MissingRecommendations;
    let json = serde_json::to_string(&e).unwrap();
    let back: CopilotError = serde_json::from_str(&json).unwrap();
    assert_eq!(e, back);
    let display = format!("{e}");
    assert!(display.contains("missing recommendations"));
}

#[test]
fn copilot_error_invalid_probability_serde_display() {
    let e = CopilotError::InvalidProbability {
        field: "confidence".to_string(),
        value: -1,
    };
    let json = serde_json::to_string(&e).unwrap();
    let back: CopilotError = serde_json::from_str(&json).unwrap();
    assert_eq!(e, back);
    let display = format!("{e}");
    assert!(display.contains("invalid probability"));
    assert!(display.contains("-1"));
}

#[test]
fn copilot_error_invalid_field_serde_display() {
    let e = CopilotError::InvalidField {
        field: "trace_id".to_string(),
    };
    let json = serde_json::to_string(&e).unwrap();
    let back: CopilotError = serde_json::from_str(&json).unwrap();
    assert_eq!(e, back);
    assert!(format!("{e}").contains("trace_id"));
}

#[test]
fn copilot_error_invalid_confidence_band_serde_display() {
    let e = CopilotError::InvalidConfidenceBand {
        metric: "p_malicious".to_string(),
    };
    let json = serde_json::to_string(&e).unwrap();
    let back: CopilotError = serde_json::from_str(&json).unwrap();
    assert_eq!(e, back);
    assert!(format!("{e}").contains("confidence band"));
}

#[test]
fn copilot_error_invalid_decision_boundary_serde_display() {
    let e = CopilotError::InvalidDecisionBoundaryHint {
        metric: "auto_terminate".to_string(),
    };
    let json = serde_json::to_string(&e).unwrap();
    let back: CopilotError = serde_json::from_str(&json).unwrap();
    assert_eq!(e, back);
    assert!(format!("{e}").contains("decision boundary"));
}

#[test]
fn copilot_error_missing_snapshot_serde_display() {
    let e = CopilotError::MissingSnapshotForRollback {
        action_type: "sandbox".to_string(),
        target_extension: "ext-x".to_string(),
    };
    let json = serde_json::to_string(&e).unwrap();
    let back: CopilotError = serde_json::from_str(&json).unwrap();
    assert_eq!(e, back);
    assert!(format!("{e}").contains("snapshot_id"));
}

#[test]
fn copilot_error_invalid_rollback_window_serde_display() {
    let e = CopilotError::InvalidRollbackWindow {
        action_type: "sandbox".to_string(),
        target_extension: "ext-y".to_string(),
    };
    let json = serde_json::to_string(&e).unwrap();
    let back: CopilotError = serde_json::from_str(&json).unwrap();
    assert_eq!(e, back);
    assert!(format!("{e}").contains("rollback_window_ms"));
}

#[test]
fn copilot_error_unauthorized_role_serde_display() {
    let e = CopilotError::UnauthorizedRole {
        role: OperatorRole::Viewer,
        action: "execute".to_string(),
    };
    let json = serde_json::to_string(&e).unwrap();
    let back: CopilotError = serde_json::from_str(&json).unwrap();
    assert_eq!(e, back);
    assert!(format!("{e}").contains("Viewer"));
}

#[test]
fn copilot_error_rank_out_of_range_serde_display() {
    let e = CopilotError::RecommendationRankOutOfRange {
        requested_rank: 99,
        available: 3,
    };
    let json = serde_json::to_string(&e).unwrap();
    let back: CopilotError = serde_json::from_str(&json).unwrap();
    assert_eq!(e, back);
    assert!(format!("{e}").contains("99"));
}

#[test]
fn copilot_error_operator_mismatch_serde_display() {
    let e = CopilotError::OperatorMismatch {
        selected_by: "op-a".to_string(),
        confirmed_by: "op-b".to_string(),
    };
    let json = serde_json::to_string(&e).unwrap();
    let back: CopilotError = serde_json::from_str(&json).unwrap();
    assert_eq!(e, back);
    assert!(format!("{e}").contains("op-a"));
    assert!(format!("{e}").contains("op-b"));
}

#[test]
fn copilot_error_missing_confirmation_token_serde_display() {
    let e = CopilotError::MissingConfirmationToken;
    let json = serde_json::to_string(&e).unwrap();
    let back: CopilotError = serde_json::from_str(&json).unwrap();
    assert_eq!(e, back);
    assert!(format!("{e}").contains("confirmation token"));
}

#[test]
fn copilot_error_is_std_error() {
    let e = CopilotError::MissingRecommendations;
    let _: &dyn std::error::Error = &e;
}

// ===========================================================================
// Section 5: Validation edge cases
// ===========================================================================

#[test]
fn rejects_empty_trace_id() {
    let mut input = sample_input();
    input.trace_id = "".to_string();
    let err = build_operator_safety_copilot_surface(&input).unwrap_err();
    assert!(matches!(err, CopilotError::InvalidField { .. }));
}

#[test]
fn rejects_empty_decision_id() {
    let mut input = sample_input();
    input.decision_id = "".to_string();
    let err = build_operator_safety_copilot_surface(&input).unwrap_err();
    assert!(matches!(err, CopilotError::InvalidField { .. }));
}

#[test]
fn rejects_empty_policy_id() {
    let mut input = sample_input();
    input.policy_id = "".to_string();
    let err = build_operator_safety_copilot_surface(&input).unwrap_err();
    assert!(matches!(err, CopilotError::InvalidField { .. }));
}

#[test]
fn rejects_empty_incident_id() {
    let mut input = sample_input();
    input.incident_id = "".to_string();
    let err = build_operator_safety_copilot_surface(&input).unwrap_err();
    assert!(matches!(err, CopilotError::InvalidField { .. }));
}

#[test]
fn rejects_no_recommendations() {
    let mut input = sample_input();
    input.recommendations.clear();
    let err = build_operator_safety_copilot_surface(&input).unwrap_err();
    assert_eq!(err, CopilotError::MissingRecommendations);
}

#[test]
fn rejects_negative_no_action_loss() {
    let mut input = sample_input();
    input.no_action_expected_loss_millionths = -1;
    let err = build_operator_safety_copilot_surface(&input).unwrap_err();
    assert!(matches!(err, CopilotError::InvalidField { .. }));
}

#[test]
fn rejects_confidence_above_million() {
    let mut input = sample_input();
    input.recommendations[0].confidence_millionths = 1_000_001;
    let err = build_operator_safety_copilot_surface(&input).unwrap_err();
    assert!(matches!(err, CopilotError::InvalidProbability { .. }));
}

#[test]
fn rejects_limited_window_without_rollback_ms() {
    let mut input = sample_input();
    input.recommendations[0].rollback_window_ms = None;
    let err = build_operator_safety_copilot_surface(&input).unwrap_err();
    assert!(matches!(err, CopilotError::InvalidRollbackWindow { .. }));
}

#[test]
fn rejects_limited_window_with_zero_rollback_ms() {
    let mut input = sample_input();
    input.recommendations[0].rollback_window_ms = Some(0);
    let err = build_operator_safety_copilot_surface(&input).unwrap_err();
    assert!(matches!(err, CopilotError::InvalidRollbackWindow { .. }));
}

#[test]
fn rejects_confidence_band_zero_bps() {
    let mut input = sample_input();
    input.confidence_bands[0].confidence_level_bps = 0;
    let err = build_operator_safety_copilot_surface(&input).unwrap_err();
    assert!(matches!(err, CopilotError::InvalidConfidenceBand { .. }));
}

#[test]
fn rejects_confidence_band_above_10000_bps() {
    let mut input = sample_input();
    input.confidence_bands[0].confidence_level_bps = 10_001;
    let err = build_operator_safety_copilot_surface(&input).unwrap_err();
    assert!(matches!(err, CopilotError::InvalidConfidenceBand { .. }));
}

#[test]
fn rejects_empty_timeline_event_id() {
    let mut input = sample_input();
    input.timeline[0].event_id = "".to_string();
    let err = build_operator_safety_copilot_surface(&input).unwrap_err();
    assert!(matches!(err, CopilotError::InvalidField { .. }));
}

// ===========================================================================
// Section 6: Rank out of range
// ===========================================================================

#[test]
fn select_rank_zero_saturates_to_first_alternative() {
    // rank 0 -> saturating_sub(2) = 0 -> alternatives[0]
    let surface = build_operator_safety_copilot_surface(&sample_input()).unwrap();
    let operator = op("op-1", OperatorRole::Operator);
    let review = select_recommendation_for_review(&surface, &operator, 0, 100).unwrap();
    // Should get the first alternative (sandbox)
    assert_eq!(review.selected_recommendation.action_type, "sandbox");
}

#[test]
fn select_rank_too_high_is_out_of_range() {
    let surface = build_operator_safety_copilot_surface(&sample_input()).unwrap();
    let operator = op("op-1", OperatorRole::Operator);
    // 2 recommendations, so rank 3 is out of range
    let err = select_recommendation_for_review(&surface, &operator, 3, 100).unwrap_err();
    assert!(matches!(
        err,
        CopilotError::RecommendationRankOutOfRange { .. }
    ));
}

// ===========================================================================
// Section 7: Operator identity validation
// ===========================================================================

#[test]
fn empty_operator_id_rejected() {
    let surface = build_operator_safety_copilot_surface(&sample_input()).unwrap();
    let empty_op = op("", OperatorRole::Operator);
    let err = select_recommendation_for_review(&surface, &empty_op, 1, 100).unwrap_err();
    assert!(matches!(err, CopilotError::InvalidField { .. }));
}

#[test]
fn administrator_can_select_and_confirm() {
    let surface = build_operator_safety_copilot_surface(&sample_input()).unwrap();
    let admin = op("admin-1", OperatorRole::Administrator);
    let review = select_recommendation_for_review(&surface, &admin, 1, 100).unwrap();
    let confirmed = confirm_selected_recommendation(&review, &admin, "token-1", 200).unwrap();
    assert_eq!(
        confirmed.audit_event.operator_role,
        OperatorRole::Administrator
    );
}

// ===========================================================================
// Section 8: Rollback receipt validation
// ===========================================================================

#[test]
fn rollback_receipt_rejects_empty_fields() {
    let base = RollbackReceiptInput {
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        action_receipt_id: "a".to_string(),
        rollback_decision_id: "r".to_string(),
        evidence_pointer: "e".to_string(),
        restoration_verification: "v".to_string(),
        executed_at_ns: 1,
    };

    // Each field empty should cause InvalidField
    for field_name in [
        "trace_id",
        "decision_id",
        "policy_id",
        "action_receipt_id",
        "rollback_decision_id",
        "evidence_pointer",
        "restoration_verification",
    ] {
        let mut input = base.clone();
        match field_name {
            "trace_id" => input.trace_id = "".to_string(),
            "decision_id" => input.decision_id = "".to_string(),
            "policy_id" => input.policy_id = "".to_string(),
            "action_receipt_id" => input.action_receipt_id = "".to_string(),
            "rollback_decision_id" => input.rollback_decision_id = "".to_string(),
            "evidence_pointer" => input.evidence_pointer = "".to_string(),
            "restoration_verification" => input.restoration_verification = "".to_string(),
            _ => unreachable!(),
        }
        let err = build_rollback_execution_receipt(&input).unwrap_err();
        assert!(
            matches!(err, CopilotError::InvalidField { .. }),
            "expected InvalidField for empty {field_name}, got {err:?}"
        );
    }
}

// ===========================================================================
// Section 9: Fleet health overview edge cases
// ===========================================================================

#[test]
fn fleet_health_overview_empty_inputs() {
    let overview = build_fleet_health_overview(&[], &[], &[], &[]);
    assert_eq!(overview.active_incidents_count, 0);
    assert_eq!(overview.highest_severity, IncidentSeverity::Low);
    assert!(overview.extension_details.is_empty());
    assert!(overview.recent_containment_actions.is_empty());
    // Trust distribution still has 4 entries (all zeros)
    assert_eq!(overview.trust_level_distribution.len(), 4);
    for entry in &overview.trust_level_distribution {
        assert_eq!(entry.extensions, 0);
    }
}

#[test]
fn fleet_health_overview_serde_roundtrip() {
    let cards = vec![ExtensionTrustCard {
        extension_id: "ext-a".to_string(),
        trust_level: ExtensionTrustLevel::High,
        recent_evidence_atoms: 5,
        recent_decision_ids: vec![],
        current_recommendation: None,
    }];
    let incidents = vec![ActiveIncidentSummary {
        incident_id: "inc-1".to_string(),
        extension_id: "ext-a".to_string(),
        severity: IncidentSeverity::Medium,
        started_at_ns: 1000,
        status: "active".to_string(),
    }];
    let overview = build_fleet_health_overview(&cards, &incidents, &[100_000], &[]);
    let json = serde_json::to_string(&overview).unwrap();
    let back: FleetHealthOverview = serde_json::from_str(&json).unwrap();
    assert_eq!(overview, back);
}

// ===========================================================================
// Section 10: Policy effectiveness edge cases
// ===========================================================================

#[test]
fn policy_effectiveness_empty_latencies() {
    let input = PolicyEffectivenessInput {
        detection_counts: vec![],
        false_positive_rate_trend_millionths: vec![],
        containment_latencies_ms: vec![],
        calibration_history: vec![],
    };
    let view = build_policy_effectiveness_view(&input).unwrap();
    assert!(view.detection_rate_by_category.is_empty());
    assert_eq!(view.containment_latency_p50_ms, 0);
    assert_eq!(view.containment_latency_p95_ms, 0);
}

#[test]
fn policy_effectiveness_zero_total_events() {
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
fn policy_effectiveness_rejects_negative_fp_rate() {
    let input = PolicyEffectivenessInput {
        detection_counts: vec![],
        false_positive_rate_trend_millionths: vec![-1],
        containment_latencies_ms: vec![],
        calibration_history: vec![],
    };
    let err = build_policy_effectiveness_view(&input).unwrap_err();
    assert!(matches!(err, CopilotError::InvalidProbability { .. }));
}

#[test]
fn policy_effectiveness_serde_roundtrip() {
    let input = PolicyEffectivenessInput {
        detection_counts: vec![CategoryDetectionCount {
            category: "phishing".to_string(),
            detected_events: 7,
            total_events: 10,
        }],
        false_positive_rate_trend_millionths: vec![50_000],
        containment_latencies_ms: vec![100, 200, 300],
        calibration_history: vec![CalibrationPoint {
            timestamp_ns: 1,
            expected_millionths: 700_000,
            observed_millionths: 680_000,
        }],
    };
    let view = build_policy_effectiveness_view(&input).unwrap();
    let json = serde_json::to_string(&view).unwrap();
    let back: PolicyEffectivenessView = serde_json::from_str(&json).unwrap();
    assert_eq!(view, back);
}

// ===========================================================================
// Section 11: Surface output determinism
// ===========================================================================

#[test]
fn surface_output_deterministic() {
    let input = sample_input();
    let s1 = build_operator_safety_copilot_surface(&input).unwrap();
    let s2 = build_operator_safety_copilot_surface(&input).unwrap();
    assert_eq!(s1, s2);
}

#[test]
fn surface_serde_roundtrip() {
    let input = sample_input();
    let surface = build_operator_safety_copilot_surface(&input).unwrap();
    let json = serde_json::to_string(&surface).unwrap();
    let back: OperatorSafetyCopilotSurface = serde_json::from_str(&json).unwrap();
    assert_eq!(surface, back);
}

// ===========================================================================
// Section 12: Render summary
// ===========================================================================

#[test]
fn render_summary_includes_key_fields() {
    let surface = build_operator_safety_copilot_surface(&sample_input()).unwrap();
    let summary = render_copilot_summary(&surface);
    assert!(summary.contains("trace_id: trace-enrich-1"));
    assert!(summary.contains("decision_id: decision-enrich-1"));
    assert!(summary.contains("policy_id: policy-enrich-1"));
    assert!(summary.contains("incident_id: incident-enrich-1"));
    assert!(summary.contains("read_only: true"));
    assert!(summary.contains("evidence_strength: 20 atoms / 300s"));
}

// ===========================================================================
// Section 13: JSON field name stability
// ===========================================================================

#[test]
fn json_field_names_confidence_band() {
    let cb = ConfidenceBand {
        metric: "m".to_string(),
        point_millionths: 500_000,
        lower_millionths: 300_000,
        upper_millionths: 700_000,
        confidence_level_bps: 9_000,
    };
    let json = serde_json::to_value(&cb).unwrap();
    let obj = json.as_object().unwrap();
    assert!(obj.contains_key("metric"));
    assert!(obj.contains_key("point_millionths"));
    assert!(obj.contains_key("lower_millionths"));
    assert!(obj.contains_key("upper_millionths"));
    assert!(obj.contains_key("confidence_level_bps"));
}

#[test]
fn json_field_names_copilot_log_event() {
    let le = CopilotStructuredLogEvent {
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        component: "c".to_string(),
        event: "e".to_string(),
        outcome: "o".to_string(),
        error_code: None,
    };
    let json = serde_json::to_value(&le).unwrap();
    let obj = json.as_object().unwrap();
    assert!(obj.contains_key("trace_id"));
    assert!(obj.contains_key("decision_id"));
    assert!(obj.contains_key("policy_id"));
    assert!(obj.contains_key("component"));
    assert!(obj.contains_key("event"));
    assert!(obj.contains_key("outcome"));
    assert!(obj.contains_key("error_code"));
}

// ===========================================================================
// Section 14: End-to-end selection → confirmation → rollback pipeline
// ===========================================================================

#[test]
fn e2e_select_confirm_rollback_pipeline() {
    let input = sample_input();
    let surface = build_operator_safety_copilot_surface(&input).unwrap();
    let operator = op("op-pipeline", OperatorRole::Operator);

    // Select rank 2 (sandbox, which is the lower-loss alternative)
    let review = select_recommendation_for_review(&surface, &operator, 2, 1000).unwrap();
    assert_eq!(review.selected_recommendation.action_type, "sandbox");
    assert!(review.impact_summary.reversible);
    assert_eq!(
        review.impact_summary.rollback_window_ms_remaining,
        Some(600_000)
    );

    // Confirm
    let confirmed = confirm_selected_recommendation(&review, &operator, "my-token", 2000).unwrap();
    assert!(confirmed.execution_command.contains("execute sandbox"));
    assert!(!confirmed.receipt.receipt_id.is_empty());
    assert!(!confirmed.receipt.signature.is_empty());

    // Rollback
    let rb_input = RollbackReceiptInput {
        trace_id: confirmed.receipt.trace_id.clone(),
        decision_id: confirmed.receipt.decision_id.clone(),
        policy_id: confirmed.receipt.policy_id.clone(),
        action_receipt_id: confirmed.receipt.receipt_id.clone(),
        rollback_decision_id: "rb-decision-1".to_string(),
        evidence_pointer: "ev://rb-1".to_string(),
        restoration_verification: "restored snapshot".to_string(),
        executed_at_ns: 3000,
    };
    let rb_receipt = build_rollback_execution_receipt(&rb_input).unwrap();
    assert!(!rb_receipt.receipt_id.is_empty());
    assert_eq!(rb_receipt.action_receipt_id, confirmed.receipt.receipt_id);

    // Serde roundtrip of confirmed action
    let json = serde_json::to_string(&confirmed).unwrap();
    let back: ConfirmedActionExecution = serde_json::from_str(&json).unwrap();
    assert_eq!(confirmed, back);
}

// ===========================================================================
// Section 15: Action recommendation candidate serde
// ===========================================================================

#[test]
fn action_recommendation_candidate_serde() {
    let arc = ActionRecommendationCandidate {
        action_type: "challenge".to_string(),
        target_extension: "ext-b".to_string(),
        expected_loss_reduction_millionths: 200_000,
        confidence_millionths: 900_000,
        side_effects: vec!["latency".to_string()],
        collateral_extensions: 0,
        estimated_action_latency_ms: 50,
        reversibility: RecommendationReversibility::Reversible,
        time_sensitivity: TimeSensitivity::Routine,
        rollback_window_ms: None,
        snapshot_id: Some("snap-b".to_string()),
    };
    let json = serde_json::to_string(&arc).unwrap();
    let back: ActionRecommendationCandidate = serde_json::from_str(&json).unwrap();
    assert_eq!(arc, back);
}

// ===========================================================================
// Section 16: Debug distinctness
// ===========================================================================

#[test]
fn debug_distinct_reversibility() {
    let debugs: std::collections::BTreeSet<String> = [
        RecommendationReversibility::Reversible,
        RecommendationReversibility::LimitedWindow,
        RecommendationReversibility::Irreversible,
    ]
    .iter()
    .map(|v| format!("{v:?}"))
    .collect();
    assert_eq!(debugs.len(), 3);
}

#[test]
fn debug_distinct_time_sensitivity() {
    let debugs: std::collections::BTreeSet<String> = [
        TimeSensitivity::Immediate,
        TimeSensitivity::NearTerm,
        TimeSensitivity::Routine,
    ]
    .iter()
    .map(|v| format!("{v:?}"))
    .collect();
    assert_eq!(debugs.len(), 3);
}

#[test]
fn debug_distinct_operator_role() {
    let debugs: std::collections::BTreeSet<String> = [
        OperatorRole::Viewer,
        OperatorRole::Operator,
        OperatorRole::Administrator,
    ]
    .iter()
    .map(|v| format!("{v:?}"))
    .collect();
    assert_eq!(debugs.len(), 3);
}
