#![forbid(unsafe_code)]
//! Enrichment integration tests for `frankentui_adapter`.
//!
//! Adds serde roundtrips for enum variants, JSON field-name stability,
//! Debug distinctness, Default coverage, AdapterEnvelope construction,
//! dashboard builder functions, and constants stability beyond the
//! existing 103 integration tests.

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

use std::collections::BTreeSet;

use frankenengine_engine::frankentui_adapter::{
    AdapterEnvelope, AdapterStream, BenchmarkTrendPointView, BenchmarkTrendsPanelView,
    CancellationEventView, CancellationKind, CapabilityDeltaDashboardFilter,
    CapabilityDeltaDashboardView, CapabilityDeltaPartial, ConfinementProofView, ConfinementStatus,
    ControlDashboardPartial, ControlDashboardView, ControlPlaneDashboardFilter,
    ControlPlaneInvariantsDashboardView, ControlPlaneInvariantsPartial, DashboardAlertMetric,
    DashboardAlertRule, DashboardMetricView, DashboardRefreshPolicy, DashboardSeverity,
    DecisionOutcomeKind, DecisionOutcomesPanelView, DeclassificationOutcome, ExtensionStatusRow,
    FRANKENTUI_ADAPTER_SCHEMA_VERSION, FlowDecisionDashboardFilter, FlowDecisionDashboardView,
    FlowDecisionPartial, FlowProofCoverageView, FlowSensitivityLevel, FrankentuiViewPayload,
    GrantExpiryStatus, IncidentReplayView, LabelMapEdgeView, LabelMapNodeView, ObligationState,
    ObligationStatusPanelView, ObligationStatusRowView, OverrideReviewStatus,
    PolicyExplanationCardView, PolicyExplanationPartial, ProofInventoryKind,
    ProofSpecializationDashboardFilter, ProofSpecializationInvalidationReason,
    ProofSpecializationLineageDashboardView, ProofSpecializationLineagePartial,
    ProofValidityStatus, RecoveryStatus, RegionLifecyclePanelView, RegionLifecycleRowView,
    ReplacementDashboardFilter, ReplacementProgressDashboardView, ReplacementProgressPartial,
    ReplacementRiskLevel, ReplayEventView, ReplayHealthPanelView, ReplayHealthStatus, ReplayStatus,
    RollbackEventView, RollbackStatus, SafeModeActivationView, SchemaCompatibilityStatus,
    SchemaVersionPanelView, SlotStatusOverviewRow, SpecializationFallbackReason,
    SpecializationPerformanceImpactView, ThresholdComparator, TriggeredAlertView, UpdateKind,
};

// ===========================================================================
// 1) Constants stability
// ===========================================================================

#[test]
fn constants_stable() {
    assert_eq!(FRANKENTUI_ADAPTER_SCHEMA_VERSION, 1);
}

// ===========================================================================
// 2) Serde roundtrips — status enums
// ===========================================================================

#[test]
fn serde_roundtrip_replay_status() {
    for s in [
        ReplayStatus::Running,
        ReplayStatus::Complete,
        ReplayStatus::Failed,
        ReplayStatus::NoEvents,
    ] {
        let json = serde_json::to_string(&s).unwrap();
        let rt: ReplayStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(s, rt);
    }
}

#[test]
fn serde_roundtrip_dashboard_severity() {
    for s in [
        DashboardSeverity::Info,
        DashboardSeverity::Warning,
        DashboardSeverity::Critical,
    ] {
        let json = serde_json::to_string(&s).unwrap();
        let rt: DashboardSeverity = serde_json::from_str(&json).unwrap();
        assert_eq!(s, rt);
    }
}

#[test]
fn serde_roundtrip_decision_outcome_kind() {
    for k in [
        DecisionOutcomeKind::Allow,
        DecisionOutcomeKind::Deny,
        DecisionOutcomeKind::Fallback,
    ] {
        let json = serde_json::to_string(&k).unwrap();
        let rt: DecisionOutcomeKind = serde_json::from_str(&json).unwrap();
        assert_eq!(k, rt);
    }
}

#[test]
fn serde_roundtrip_obligation_state() {
    for s in [
        ObligationState::Open,
        ObligationState::Fulfilled,
        ObligationState::Failed,
    ] {
        let json = serde_json::to_string(&s).unwrap();
        let rt: ObligationState = serde_json::from_str(&json).unwrap();
        assert_eq!(s, rt);
    }
}

#[test]
fn serde_roundtrip_cancellation_kind() {
    for k in [
        CancellationKind::Unload,
        CancellationKind::Quarantine,
        CancellationKind::Suspend,
        CancellationKind::Terminate,
        CancellationKind::Revocation,
    ] {
        let json = serde_json::to_string(&k).unwrap();
        let rt: CancellationKind = serde_json::from_str(&json).unwrap();
        assert_eq!(k, rt);
    }
}

#[test]
fn serde_roundtrip_replay_health_status() {
    for s in [
        ReplayHealthStatus::Pass,
        ReplayHealthStatus::Fail,
        ReplayHealthStatus::Unknown,
    ] {
        let json = serde_json::to_string(&s).unwrap();
        let rt: ReplayHealthStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(s, rt);
    }
}

#[test]
fn serde_roundtrip_recovery_status() {
    for s in [
        RecoveryStatus::Recovering,
        RecoveryStatus::Recovered,
        RecoveryStatus::Waived,
    ] {
        let json = serde_json::to_string(&s).unwrap();
        let rt: RecoveryStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(s, rt);
    }
}

#[test]
fn serde_roundtrip_schema_compatibility_status() {
    for s in [
        SchemaCompatibilityStatus::Unknown,
        SchemaCompatibilityStatus::Compatible,
        SchemaCompatibilityStatus::NeedsMigration,
        SchemaCompatibilityStatus::Incompatible,
    ] {
        let json = serde_json::to_string(&s).unwrap();
        let rt: SchemaCompatibilityStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(s, rt);
    }
}

#[test]
fn serde_roundtrip_update_kind() {
    for k in [
        UpdateKind::Snapshot,
        UpdateKind::Delta,
        UpdateKind::Heartbeat,
    ] {
        let json = serde_json::to_string(&k).unwrap();
        let rt: UpdateKind = serde_json::from_str(&json).unwrap();
        assert_eq!(k, rt);
    }
}

#[test]
fn serde_roundtrip_threshold_comparator() {
    for c in [
        ThresholdComparator::GreaterThan,
        ThresholdComparator::GreaterOrEqual,
        ThresholdComparator::LessThan,
        ThresholdComparator::LessOrEqual,
        ThresholdComparator::Equal,
    ] {
        let json = serde_json::to_string(&c).unwrap();
        let rt: ThresholdComparator = serde_json::from_str(&json).unwrap();
        assert_eq!(c, rt);
    }
}

#[test]
fn serde_roundtrip_flow_sensitivity_level() {
    for l in [
        FlowSensitivityLevel::Low,
        FlowSensitivityLevel::Medium,
        FlowSensitivityLevel::High,
        FlowSensitivityLevel::Critical,
    ] {
        let json = serde_json::to_string(&l).unwrap();
        let rt: FlowSensitivityLevel = serde_json::from_str(&json).unwrap();
        assert_eq!(l, rt);
    }
}

#[test]
fn serde_roundtrip_declassification_outcome() {
    for o in [
        DeclassificationOutcome::Approved,
        DeclassificationOutcome::Denied,
    ] {
        let json = serde_json::to_string(&o).unwrap();
        let rt: DeclassificationOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(o, rt);
    }
}

#[test]
fn serde_roundtrip_confinement_status() {
    for s in [
        ConfinementStatus::Full,
        ConfinementStatus::Partial,
        ConfinementStatus::Degraded,
    ] {
        let json = serde_json::to_string(&s).unwrap();
        let rt: ConfinementStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(s, rt);
    }
}

#[test]
fn serde_roundtrip_replacement_risk_level() {
    for l in [
        ReplacementRiskLevel::Low,
        ReplacementRiskLevel::Medium,
        ReplacementRiskLevel::High,
    ] {
        let json = serde_json::to_string(&l).unwrap();
        let rt: ReplacementRiskLevel = serde_json::from_str(&json).unwrap();
        assert_eq!(l, rt);
    }
}

#[test]
fn serde_roundtrip_rollback_status() {
    for s in [
        RollbackStatus::Investigating,
        RollbackStatus::Resolved,
        RollbackStatus::Waived,
    ] {
        let json = serde_json::to_string(&s).unwrap();
        let rt: RollbackStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(s, rt);
    }
}

#[test]
fn serde_roundtrip_proof_inventory_kind() {
    for k in [
        ProofInventoryKind::CapabilityWitness,
        ProofInventoryKind::FlowProof,
        ProofInventoryKind::ReplayMotif,
    ] {
        let json = serde_json::to_string(&k).unwrap();
        let rt: ProofInventoryKind = serde_json::from_str(&json).unwrap();
        assert_eq!(k, rt);
    }
}

#[test]
fn serde_roundtrip_proof_validity_status() {
    for s in [
        ProofValidityStatus::Valid,
        ProofValidityStatus::ExpiringSoon,
        ProofValidityStatus::Expired,
        ProofValidityStatus::Revoked,
    ] {
        let json = serde_json::to_string(&s).unwrap();
        let rt: ProofValidityStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(s, rt);
    }
}

#[test]
fn serde_roundtrip_override_review_status() {
    for s in [
        OverrideReviewStatus::Pending,
        OverrideReviewStatus::Approved,
        OverrideReviewStatus::Rejected,
        OverrideReviewStatus::Waived,
    ] {
        let json = serde_json::to_string(&s).unwrap();
        let rt: OverrideReviewStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(s, rt);
    }
}

#[test]
fn serde_roundtrip_grant_expiry_status() {
    for s in [
        GrantExpiryStatus::Active,
        GrantExpiryStatus::ExpiringSoon,
        GrantExpiryStatus::Expired,
        GrantExpiryStatus::NotApplicable,
    ] {
        let json = serde_json::to_string(&s).unwrap();
        let rt: GrantExpiryStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(s, rt);
    }
}

#[test]
fn serde_roundtrip_proof_invalidation_reason() {
    for r in [
        ProofSpecializationInvalidationReason::EpochChange,
        ProofSpecializationInvalidationReason::ProofExpired,
        ProofSpecializationInvalidationReason::ProofRevoked,
    ] {
        let json = serde_json::to_string(&r).unwrap();
        let rt: ProofSpecializationInvalidationReason = serde_json::from_str(&json).unwrap();
        assert_eq!(r, rt);
    }
}

#[test]
fn serde_roundtrip_specialization_fallback_reason() {
    for r in [
        SpecializationFallbackReason::ProofUnavailable,
        SpecializationFallbackReason::ProofExpired,
        SpecializationFallbackReason::ProofRevoked,
        SpecializationFallbackReason::ValidationFailed,
    ] {
        let json = serde_json::to_string(&r).unwrap();
        let rt: SpecializationFallbackReason = serde_json::from_str(&json).unwrap();
        assert_eq!(r, rt);
    }
}

// ===========================================================================
// 3) Debug distinctness
// ===========================================================================

#[test]
fn debug_distinct_adapter_stream() {
    let variants = [
        format!("{:?}", AdapterStream::IncidentReplay),
        format!("{:?}", AdapterStream::PolicyExplanation),
        format!("{:?}", AdapterStream::ControlDashboard),
        format!("{:?}", AdapterStream::ControlPlaneInvariantsDashboard),
        format!("{:?}", AdapterStream::FlowDecisionDashboard),
        format!("{:?}", AdapterStream::CapabilityDeltaDashboard),
        format!("{:?}", AdapterStream::ReplacementProgressDashboard),
        format!("{:?}", AdapterStream::ProofSpecializationLineageDashboard),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 8);
}

#[test]
fn debug_distinct_dashboard_alert_metric() {
    let variants = [
        format!(
            "{:?}",
            DashboardAlertMetric::ObligationFailureRateMillionths
        ),
        format!("{:?}", DashboardAlertMetric::ReplayDivergenceCount),
        format!("{:?}", DashboardAlertMetric::SafeModeActivationCount),
        format!("{:?}", DashboardAlertMetric::CancellationEventCount),
        format!("{:?}", DashboardAlertMetric::FallbackActivationCount),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 5);
}

#[test]
fn debug_distinct_update_kind() {
    let variants = [
        format!("{:?}", UpdateKind::Snapshot),
        format!("{:?}", UpdateKind::Delta),
        format!("{:?}", UpdateKind::Heartbeat),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 3);
}

// ===========================================================================
// 4) Default implementations
// ===========================================================================

#[test]
fn default_dashboard_severity_is_info() {
    assert_eq!(DashboardSeverity::default(), DashboardSeverity::Info);
}

#[test]
fn default_replay_health_status_is_unknown() {
    assert_eq!(ReplayHealthStatus::default(), ReplayHealthStatus::Unknown);
}

#[test]
fn default_recovery_status_is_recovering() {
    assert_eq!(RecoveryStatus::default(), RecoveryStatus::Recovering);
}

#[test]
fn default_schema_compatibility_status_is_unknown() {
    assert_eq!(
        SchemaCompatibilityStatus::default(),
        SchemaCompatibilityStatus::Unknown
    );
}

#[test]
fn default_flow_sensitivity_level_is_low() {
    assert_eq!(FlowSensitivityLevel::default(), FlowSensitivityLevel::Low);
}

#[test]
fn default_proof_validity_status_is_valid() {
    assert_eq!(ProofValidityStatus::default(), ProofValidityStatus::Valid);
}

#[test]
fn default_override_review_status_is_pending() {
    assert_eq!(
        OverrideReviewStatus::default(),
        OverrideReviewStatus::Pending
    );
}

#[test]
fn default_grant_expiry_status_is_active() {
    assert_eq!(GrantExpiryStatus::default(), GrantExpiryStatus::Active);
}

#[test]
fn default_decision_outcomes_panel() {
    let panel = DecisionOutcomesPanelView::default();
    assert_eq!(panel.allow_count, 0);
    assert_eq!(panel.deny_count, 0);
    assert_eq!(panel.fallback_count, 0);
}

#[test]
fn default_obligation_status_panel() {
    let panel = ObligationStatusPanelView::default();
    assert_eq!(panel.open_count, 0);
    assert_eq!(panel.fulfilled_count, 0);
    assert_eq!(panel.failed_count, 0);
}

#[test]
fn default_dashboard_refresh_policy() {
    let policy = DashboardRefreshPolicy::default();
    assert_eq!(policy.evidence_stream_refresh_secs, 5);
    assert_eq!(policy.aggregate_refresh_secs, 60);
}

// ===========================================================================
// 5) AdapterEnvelope — construction + encode
// ===========================================================================

fn test_payload() -> FrankentuiViewPayload {
    FrankentuiViewPayload::ControlDashboard(ControlDashboardView::from_partial(
        ControlDashboardPartial::default(),
    ))
}

#[test]
fn adapter_envelope_new() {
    let env = AdapterEnvelope::new(
        "trace-1",
        1_700_000_000_000,
        AdapterStream::ControlDashboard,
        UpdateKind::Snapshot,
        test_payload(),
    );
    assert_eq!(env.stream, AdapterStream::ControlDashboard);
    assert_eq!(env.update_kind, UpdateKind::Snapshot);
    assert_eq!(env.schema_version, FRANKENTUI_ADAPTER_SCHEMA_VERSION);
}

#[test]
fn adapter_envelope_with_decision_context() {
    let env = AdapterEnvelope::new(
        "trace-1",
        1_700_000_000_000,
        AdapterStream::PolicyExplanation,
        UpdateKind::Delta,
        test_payload(),
    )
    .with_decision_context("dec-1", "pol-1");
    assert_eq!(env.decision_id, Some("dec-1".into()));
    assert_eq!(env.policy_id, Some("pol-1".into()));
}

#[test]
fn adapter_envelope_encode_json() {
    let env = AdapterEnvelope::new(
        "trace-1",
        1_700_000_000_000,
        AdapterStream::ControlDashboard,
        UpdateKind::Heartbeat,
        test_payload(),
    );
    let encoded = env.encode_json().unwrap();
    let json_str = String::from_utf8(encoded).unwrap();
    assert!(json_str.contains("schema_version"));
    assert!(json_str.contains("stream"));
}

#[test]
fn adapter_envelope_serde_roundtrip() {
    let env = AdapterEnvelope::new(
        "trace-1",
        1_700_000_000_000,
        AdapterStream::ControlDashboard,
        UpdateKind::Snapshot,
        test_payload(),
    )
    .with_decision_context("d", "p");
    let json = serde_json::to_string(&env).unwrap();
    let rt: AdapterEnvelope = serde_json::from_str(&json).unwrap();
    assert_eq!(env, rt);
}

// ===========================================================================
// 6) JSON field-name stability — AdapterEnvelope
// ===========================================================================

#[test]
fn json_fields_adapter_envelope() {
    let env = AdapterEnvelope::new(
        "trace-1",
        1_700_000_000_000,
        AdapterStream::ControlDashboard,
        UpdateKind::Snapshot,
        test_payload(),
    );
    let v: serde_json::Value = serde_json::to_value(&env).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "stream",
        "update_kind",
        "schema_version",
        "trace_id",
        "generated_at_unix_ms",
        "payload",
    ] {
        assert!(
            obj.contains_key(key),
            "AdapterEnvelope missing field: {key}"
        );
    }
}

// ===========================================================================
// 7) Dashboard views — from_partial defaults
// ===========================================================================

#[test]
fn control_plane_invariants_from_empty_partial() {
    let partial = ControlPlaneInvariantsPartial::default();
    let view = ControlPlaneInvariantsDashboardView::from_partial(partial);
    assert_eq!(view.decision_outcomes.allow_count, 0);
    assert_eq!(view.obligation_status.open_count, 0);
}

#[test]
fn flow_decision_from_empty_partial() {
    let partial = FlowDecisionPartial::default();
    let view = FlowDecisionDashboardView::from_partial(partial);
    assert!(view.label_map.nodes.is_empty());
    assert!(view.blocked_flows.is_empty());
}

// ===========================================================================
// 8) Panel defaults
// ===========================================================================

#[test]
fn default_region_lifecycle_panel() {
    let panel = RegionLifecyclePanelView::default();
    assert_eq!(panel.active_region_count, 0);
}

#[test]
fn default_replay_health_panel() {
    let panel = ReplayHealthPanelView::default();
    assert_eq!(panel.divergence_count, 0);
}

#[test]
fn default_benchmark_trends_panel() {
    let panel = BenchmarkTrendsPanelView::default();
    assert!(panel.points.is_empty());
}

#[test]
fn default_schema_version_panel() {
    let panel = SchemaVersionPanelView::default();
    assert_eq!(
        panel.compatibility_status,
        SchemaCompatibilityStatus::Unknown
    );
}

// ===========================================================================
// 9) Debug distinctness — additional enums
// ===========================================================================

#[test]
fn debug_distinct_replay_status() {
    let variants = [
        format!("{:?}", ReplayStatus::Running),
        format!("{:?}", ReplayStatus::Complete),
        format!("{:?}", ReplayStatus::Failed),
        format!("{:?}", ReplayStatus::NoEvents),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 4);
}

#[test]
fn debug_distinct_dashboard_severity() {
    let variants = [
        format!("{:?}", DashboardSeverity::Info),
        format!("{:?}", DashboardSeverity::Warning),
        format!("{:?}", DashboardSeverity::Critical),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 3);
}

#[test]
fn debug_distinct_decision_outcome_kind() {
    let variants = [
        format!("{:?}", DecisionOutcomeKind::Allow),
        format!("{:?}", DecisionOutcomeKind::Deny),
        format!("{:?}", DecisionOutcomeKind::Fallback),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 3);
}

#[test]
fn debug_distinct_obligation_state() {
    let variants = [
        format!("{:?}", ObligationState::Open),
        format!("{:?}", ObligationState::Fulfilled),
        format!("{:?}", ObligationState::Failed),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 3);
}

#[test]
fn debug_distinct_cancellation_kind() {
    let variants = [
        format!("{:?}", CancellationKind::Unload),
        format!("{:?}", CancellationKind::Quarantine),
        format!("{:?}", CancellationKind::Suspend),
        format!("{:?}", CancellationKind::Terminate),
        format!("{:?}", CancellationKind::Revocation),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 5);
}

#[test]
fn debug_distinct_replay_health_status() {
    let variants = [
        format!("{:?}", ReplayHealthStatus::Pass),
        format!("{:?}", ReplayHealthStatus::Fail),
        format!("{:?}", ReplayHealthStatus::Unknown),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 3);
}

#[test]
fn debug_distinct_recovery_status() {
    let variants = [
        format!("{:?}", RecoveryStatus::Recovered),
        format!("{:?}", RecoveryStatus::Recovering),
        format!("{:?}", RecoveryStatus::Waived),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 3);
}

#[test]
fn debug_distinct_schema_compatibility_status() {
    let variants = [
        format!("{:?}", SchemaCompatibilityStatus::Compatible),
        format!("{:?}", SchemaCompatibilityStatus::Incompatible),
        format!("{:?}", SchemaCompatibilityStatus::Unknown),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 3);
}

#[test]
fn debug_distinct_flow_sensitivity_level() {
    let variants = [
        format!("{:?}", FlowSensitivityLevel::Low),
        format!("{:?}", FlowSensitivityLevel::Medium),
        format!("{:?}", FlowSensitivityLevel::High),
        format!("{:?}", FlowSensitivityLevel::Critical),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 4);
}

#[test]
fn debug_distinct_replacement_risk_level() {
    let variants = [
        format!("{:?}", ReplacementRiskLevel::Low),
        format!("{:?}", ReplacementRiskLevel::Medium),
        format!("{:?}", ReplacementRiskLevel::High),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 3);
}

#[test]
fn debug_distinct_rollback_status() {
    let variants = [
        format!("{:?}", RollbackStatus::Investigating),
        format!("{:?}", RollbackStatus::Resolved),
        format!("{:?}", RollbackStatus::Waived),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 3);
}

#[test]
fn debug_distinct_declassification_outcome() {
    let variants = [
        format!("{:?}", DeclassificationOutcome::Approved),
        format!("{:?}", DeclassificationOutcome::Denied),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 2);
}

#[test]
fn debug_distinct_confinement_status() {
    let variants = [
        format!("{:?}", ConfinementStatus::Full),
        format!("{:?}", ConfinementStatus::Partial),
        format!("{:?}", ConfinementStatus::Degraded),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 3);
}

#[test]
fn debug_distinct_override_review_status() {
    let variants = [
        format!("{:?}", OverrideReviewStatus::Pending),
        format!("{:?}", OverrideReviewStatus::Approved),
        format!("{:?}", OverrideReviewStatus::Rejected),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 3);
}

#[test]
fn debug_distinct_grant_expiry_status() {
    let variants = [
        format!("{:?}", GrantExpiryStatus::Active),
        format!("{:?}", GrantExpiryStatus::ExpiringSoon),
        format!("{:?}", GrantExpiryStatus::Expired),
        format!("{:?}", GrantExpiryStatus::NotApplicable),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 4);
}

// ===========================================================================
// 10) Serde exact tags — rename_all snake_case
// ===========================================================================

#[test]
fn serde_exact_decision_outcome_kind_tags() {
    let kinds = [
        DecisionOutcomeKind::Allow,
        DecisionOutcomeKind::Deny,
        DecisionOutcomeKind::Fallback,
    ];
    let expected = ["\"allow\"", "\"deny\"", "\"fallback\""];
    for (k, exp) in kinds.iter().zip(expected.iter()) {
        let json = serde_json::to_string(k).unwrap();
        assert_eq!(json, *exp, "DecisionOutcomeKind tag mismatch for {k:?}");
    }
}

#[test]
fn serde_exact_obligation_state_tags() {
    let states = [
        ObligationState::Open,
        ObligationState::Fulfilled,
        ObligationState::Failed,
    ];
    let expected = ["\"open\"", "\"fulfilled\"", "\"failed\""];
    for (s, exp) in states.iter().zip(expected.iter()) {
        let json = serde_json::to_string(s).unwrap();
        assert_eq!(json, *exp, "ObligationState tag mismatch for {s:?}");
    }
}

#[test]
fn serde_exact_cancellation_kind_tags() {
    let kinds = [
        CancellationKind::Unload,
        CancellationKind::Quarantine,
        CancellationKind::Suspend,
        CancellationKind::Terminate,
        CancellationKind::Revocation,
    ];
    let expected = [
        "\"unload\"",
        "\"quarantine\"",
        "\"suspend\"",
        "\"terminate\"",
        "\"revocation\"",
    ];
    for (k, exp) in kinds.iter().zip(expected.iter()) {
        let json = serde_json::to_string(k).unwrap();
        assert_eq!(json, *exp, "CancellationKind tag mismatch for {k:?}");
    }
}

#[test]
fn serde_exact_flow_sensitivity_level_tags() {
    let levels = [
        FlowSensitivityLevel::Low,
        FlowSensitivityLevel::Medium,
        FlowSensitivityLevel::High,
        FlowSensitivityLevel::Critical,
    ];
    let expected = ["\"low\"", "\"medium\"", "\"high\"", "\"critical\""];
    for (l, exp) in levels.iter().zip(expected.iter()) {
        let json = serde_json::to_string(l).unwrap();
        assert_eq!(json, *exp, "FlowSensitivityLevel tag mismatch for {l:?}");
    }
}

#[test]
fn serde_exact_replacement_risk_level_tags() {
    let levels = [
        ReplacementRiskLevel::Low,
        ReplacementRiskLevel::Medium,
        ReplacementRiskLevel::High,
    ];
    let expected = ["\"low\"", "\"medium\"", "\"high\""];
    for (l, exp) in levels.iter().zip(expected.iter()) {
        let json = serde_json::to_string(l).unwrap();
        assert_eq!(json, *exp, "ReplacementRiskLevel tag mismatch for {l:?}");
    }
}

// ===========================================================================
// 11) DashboardRefreshPolicy — default values and normalization
// ===========================================================================

#[test]
fn dashboard_refresh_policy_default_exact_values() {
    let p = DashboardRefreshPolicy::default();
    assert_eq!(p.evidence_stream_refresh_secs, 5);
    assert_eq!(p.aggregate_refresh_secs, 60);
}

#[test]
fn dashboard_refresh_policy_serde_roundtrip() {
    let p = DashboardRefreshPolicy {
        evidence_stream_refresh_secs: 10,
        aggregate_refresh_secs: 120,
    };
    let json = serde_json::to_string(&p).unwrap();
    let rt: DashboardRefreshPolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(p, rt);
}

// ===========================================================================
// 12) JSON field-name stability — ControlDashboardView
// ===========================================================================

#[test]
fn json_fields_control_dashboard_view() {
    let view = ControlDashboardView::from_partial(ControlDashboardPartial::default());
    let v: serde_json::Value = serde_json::to_value(&view).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "cluster",
        "zone",
        "security_epoch",
        "runtime_mode",
        "metrics",
        "extension_rows",
        "incident_counts",
    ] {
        assert!(
            obj.contains_key(key),
            "ControlDashboardView missing field: {key}"
        );
    }
}

// ===========================================================================
// 13) DecisionOutcomesPanelView — JSON fields
// ===========================================================================

#[test]
fn json_fields_decision_outcomes_panel() {
    let panel = DecisionOutcomesPanelView::default();
    let v: serde_json::Value = serde_json::to_value(&panel).unwrap();
    let obj = v.as_object().unwrap();
    for key in ["allow_count", "deny_count", "fallback_count"] {
        assert!(
            obj.contains_key(key),
            "DecisionOutcomesPanelView missing field: {key}"
        );
    }
}

// ===========================================================================
// 16) ObligationStatusPanelView — JSON fields
// ===========================================================================

#[test]
fn json_fields_obligation_status_panel() {
    let panel = ObligationStatusPanelView::default();
    let v: serde_json::Value = serde_json::to_value(&panel).unwrap();
    let obj = v.as_object().unwrap();
    for key in ["open_count", "fulfilled_count", "failed_count"] {
        assert!(
            obj.contains_key(key),
            "ObligationStatusPanelView missing field: {key}"
        );
    }
}

// ===========================================================================
// 17) Copy semantics — all Copy enums
// ===========================================================================

#[test]
fn enrichment_copy_semantics_replay_status() {
    let original = ReplayStatus::Running;
    let copied = original;
    assert_eq!(original, copied);
}

#[test]
fn enrichment_copy_semantics_dashboard_severity() {
    let original = DashboardSeverity::Critical;
    let copied = original;
    assert_eq!(original, copied);
}

#[test]
fn enrichment_copy_semantics_decision_outcome_kind() {
    let original = DecisionOutcomeKind::Deny;
    let copied = original;
    assert_eq!(original, copied);
}

#[test]
fn enrichment_copy_semantics_obligation_state() {
    let original = ObligationState::Fulfilled;
    let copied = original;
    assert_eq!(original, copied);
}

#[test]
fn enrichment_copy_semantics_cancellation_kind() {
    let original = CancellationKind::Quarantine;
    let copied = original;
    assert_eq!(original, copied);
}

#[test]
fn enrichment_copy_semantics_replay_health_status() {
    let original = ReplayHealthStatus::Fail;
    let copied = original;
    assert_eq!(original, copied);
}

#[test]
fn enrichment_copy_semantics_flow_sensitivity_level() {
    let original = FlowSensitivityLevel::Critical;
    let copied = original;
    assert_eq!(original, copied);
}

#[test]
fn enrichment_copy_semantics_confinement_status() {
    let original = ConfinementStatus::Degraded;
    let copied = original;
    assert_eq!(original, copied);
}

#[test]
fn enrichment_copy_semantics_replacement_risk_level() {
    let original = ReplacementRiskLevel::High;
    let copied = original;
    assert_eq!(original, copied);
}

#[test]
fn enrichment_copy_semantics_proof_inventory_kind() {
    let original = ProofInventoryKind::FlowProof;
    let copied = original;
    assert_eq!(original, copied);
}

#[test]
fn enrichment_copy_semantics_threshold_comparator() {
    let original = ThresholdComparator::LessOrEqual;
    let copied = original;
    assert_eq!(original, copied);
}

#[test]
fn enrichment_copy_semantics_dashboard_alert_metric() {
    let original = DashboardAlertMetric::SafeModeActivationCount;
    let copied = original;
    assert_eq!(original, copied);
}

// ===========================================================================
// 18) Clone independence — struct types
// ===========================================================================

fn test_envelope() -> AdapterEnvelope {
    AdapterEnvelope::new(
        "trace-enrich",
        1_700_000_000_000,
        AdapterStream::ControlDashboard,
        UpdateKind::Snapshot,
        test_payload(),
    )
    .with_decision_context("dec-enrich", "pol-enrich")
}

#[test]
fn enrichment_adapter_envelope_clone_independence() {
    let original = test_envelope();
    let mut cloned = original.clone();
    cloned.trace_id = "modified".to_string();
    assert_eq!(original.trace_id, "trace-enrich");
    assert_eq!(cloned.trace_id, "modified");
}

#[test]
fn enrichment_incident_replay_view_clone_independence() {
    let original = IncidentReplayView::snapshot("trace-1", "scenario-1", vec![]);
    let mut cloned = original.clone();
    cloned.scenario_name = "modified".to_string();
    assert_eq!(original.scenario_name, "scenario-1");
    assert_eq!(cloned.scenario_name, "modified");
}

#[test]
fn enrichment_control_dashboard_view_clone_independence() {
    let original = ControlDashboardView::from_partial(ControlDashboardPartial::default());
    let mut cloned = original.clone();
    cloned.cluster = "modified".to_string();
    assert_eq!(original.cluster, "unknown");
    assert_eq!(cloned.cluster, "modified");
}

#[test]
fn enrichment_policy_explanation_card_clone_independence() {
    let original = PolicyExplanationCardView::from_partial(PolicyExplanationPartial::default());
    let mut cloned = original.clone();
    cloned.selected_action = "modified".to_string();
    assert_eq!(original.selected_action, "unknown");
    assert_eq!(cloned.selected_action, "modified");
}

#[test]
fn enrichment_cpid_clone_independence() {
    let original =
        ControlPlaneInvariantsDashboardView::from_partial(ControlPlaneInvariantsPartial::default());
    let mut cloned = original.clone();
    cloned.cluster = "modified".to_string();
    assert_eq!(original.cluster, "unknown");
    assert_eq!(cloned.cluster, "modified");
}

#[test]
fn enrichment_flow_decision_dashboard_clone_independence() {
    let original = FlowDecisionDashboardView::from_partial(FlowDecisionPartial::default());
    let mut cloned = original.clone();
    cloned.cluster = "modified".to_string();
    assert_eq!(original.cluster, "unknown");
    assert_eq!(cloned.cluster, "modified");
}

// ===========================================================================
// 19) BTreeSet ordering — enum variants
// ===========================================================================

#[test]
fn enrichment_adapter_stream_btreeset_ordering() {
    let json_tags: Vec<String> = [
        AdapterStream::IncidentReplay,
        AdapterStream::PolicyExplanation,
        AdapterStream::ControlDashboard,
        AdapterStream::ControlPlaneInvariantsDashboard,
        AdapterStream::FlowDecisionDashboard,
        AdapterStream::CapabilityDeltaDashboard,
        AdapterStream::ReplacementProgressDashboard,
        AdapterStream::ProofSpecializationLineageDashboard,
    ]
    .iter()
    .map(|v| serde_json::to_string(v).unwrap())
    .collect();
    let unique: BTreeSet<_> = json_tags.iter().collect();
    assert_eq!(unique.len(), 8);
}

#[test]
fn enrichment_update_kind_btreeset_ordering() {
    let tags: Vec<String> = [
        UpdateKind::Snapshot,
        UpdateKind::Delta,
        UpdateKind::Heartbeat,
    ]
    .iter()
    .map(|v| serde_json::to_string(v).unwrap())
    .collect();
    let unique: BTreeSet<_> = tags.iter().collect();
    assert_eq!(unique.len(), 3);
}

// ===========================================================================
// 20) Struct serde roundtrips — uncovered struct types
// ===========================================================================

#[test]
fn enrichment_dashboard_alert_rule_serde_roundtrip() {
    let rule = DashboardAlertRule {
        rule_id: "rule-1".into(),
        description: "test rule".into(),
        metric: DashboardAlertMetric::ReplayDivergenceCount,
        comparator: ThresholdComparator::GreaterThan,
        threshold: 5,
        severity: DashboardSeverity::Warning,
    };
    let json = serde_json::to_string(&rule).unwrap();
    let rt: DashboardAlertRule = serde_json::from_str(&json).unwrap();
    assert_eq!(rule, rt);
}

#[test]
fn enrichment_triggered_alert_view_serde_roundtrip() {
    let alert = TriggeredAlertView {
        rule_id: "rule-1".into(),
        description: "desc".into(),
        metric: DashboardAlertMetric::CancellationEventCount,
        observed_value: 10,
        threshold: 5,
        severity: DashboardSeverity::Critical,
        triggered_at_unix_ms: 1_000_000,
    };
    let json = serde_json::to_string(&alert).unwrap();
    let rt: TriggeredAlertView = serde_json::from_str(&json).unwrap();
    assert_eq!(alert, rt);
}

#[test]
fn enrichment_dashboard_metric_view_serde_roundtrip() {
    let metric = DashboardMetricView {
        metric: "latency_p99".into(),
        value: 42,
        unit: "ms".into(),
    };
    let json = serde_json::to_string(&metric).unwrap();
    let rt: DashboardMetricView = serde_json::from_str(&json).unwrap();
    assert_eq!(metric, rt);
}

#[test]
fn enrichment_extension_status_row_serde_roundtrip() {
    let row = ExtensionStatusRow {
        extension_id: "ext-1".into(),
        state: "running".into(),
        trust_level: "verified".into(),
    };
    let json = serde_json::to_string(&row).unwrap();
    let rt: ExtensionStatusRow = serde_json::from_str(&json).unwrap();
    assert_eq!(row, rt);
}

#[test]
fn enrichment_obligation_status_row_serde_roundtrip() {
    let row = ObligationStatusRowView {
        obligation_id: "obl-1".into(),
        extension_id: "ext-1".into(),
        region_id: "region-1".into(),
        state: ObligationState::Open,
        severity: DashboardSeverity::Warning,
        due_at_unix_ms: 1_000_000,
        updated_at_unix_ms: 900_000,
        detail: "pending review".into(),
    };
    let json = serde_json::to_string(&row).unwrap();
    let rt: ObligationStatusRowView = serde_json::from_str(&json).unwrap();
    assert_eq!(row, rt);
}

#[test]
fn enrichment_region_lifecycle_row_serde_roundtrip() {
    let row = RegionLifecycleRowView {
        region_id: "region-1".into(),
        is_active: true,
        active_extensions: 3,
        created_at_unix_ms: 1_000_000,
        closed_at_unix_ms: None,
        quiescent_close_time_ms: None,
    };
    let json = serde_json::to_string(&row).unwrap();
    let rt: RegionLifecycleRowView = serde_json::from_str(&json).unwrap();
    assert_eq!(row, rt);
}

#[test]
fn enrichment_cancellation_event_view_serde_roundtrip() {
    let event = CancellationEventView {
        extension_id: "ext-1".into(),
        region_id: "region-1".into(),
        cancellation_kind: CancellationKind::Terminate,
        severity: DashboardSeverity::Critical,
        detail: "forced shutdown".into(),
        timestamp_unix_ms: 1_000_000,
    };
    let json = serde_json::to_string(&event).unwrap();
    let rt: CancellationEventView = serde_json::from_str(&json).unwrap();
    assert_eq!(event, rt);
}

#[test]
fn enrichment_safe_mode_activation_serde_roundtrip() {
    let activation = SafeModeActivationView {
        activation_id: "act-1".into(),
        activation_type: "memory_exceeded".into(),
        extension_id: "ext-1".into(),
        region_id: "region-1".into(),
        severity: DashboardSeverity::Warning,
        recovery_status: RecoveryStatus::Recovering,
        activated_at_unix_ms: 1_000_000,
        recovered_at_unix_ms: None,
    };
    let json = serde_json::to_string(&activation).unwrap();
    let rt: SafeModeActivationView = serde_json::from_str(&json).unwrap();
    assert_eq!(activation, rt);
}

#[test]
fn enrichment_benchmark_trend_point_serde_roundtrip() {
    let point = BenchmarkTrendPointView {
        timestamp_unix_ms: 1_000_000,
        throughput_tps: 5000,
        latency_p95_ms: 12,
        memory_peak_mb: 256,
    };
    let json = serde_json::to_string(&point).unwrap();
    let rt: BenchmarkTrendPointView = serde_json::from_str(&json).unwrap();
    assert_eq!(point, rt);
}

#[test]
fn enrichment_label_map_node_serde_roundtrip() {
    let node = LabelMapNodeView {
        label_id: "secret".into(),
        sensitivity: FlowSensitivityLevel::High,
        description: "secret data".into(),
        extension_overlays: vec!["ext-1".into()],
    };
    let json = serde_json::to_string(&node).unwrap();
    let rt: LabelMapNodeView = serde_json::from_str(&json).unwrap();
    assert_eq!(node, rt);
}

#[test]
fn enrichment_label_map_edge_serde_roundtrip() {
    let edge = LabelMapEdgeView {
        source_label: "secret".into(),
        sink_clearance: "public".into(),
        route_policy_id: Some("pol-1".into()),
        route_enabled: true,
    };
    let json = serde_json::to_string(&edge).unwrap();
    let rt: LabelMapEdgeView = serde_json::from_str(&json).unwrap();
    assert_eq!(edge, rt);
}

#[test]
fn enrichment_flow_proof_coverage_serde_roundtrip() {
    let proof = FlowProofCoverageView {
        proof_id: "proof-1".into(),
        source_label: "secret".into(),
        sink_clearance: "public".into(),
        covered: true,
        proof_ref: "ref-1".into(),
    };
    let json = serde_json::to_string(&proof).unwrap();
    let rt: FlowProofCoverageView = serde_json::from_str(&json).unwrap();
    assert_eq!(proof, rt);
}

#[test]
fn enrichment_confinement_proof_serde_roundtrip() {
    let proof = ConfinementProofView {
        extension_id: "ext-1".into(),
        status: ConfinementStatus::Full,
        covered_flow_count: 10,
        uncovered_flow_count: 0,
        proof_rows: vec![],
        uncovered_flow_refs: vec![],
    };
    let json = serde_json::to_string(&proof).unwrap();
    let rt: ConfinementProofView = serde_json::from_str(&json).unwrap();
    assert_eq!(proof, rt);
}

#[test]
fn enrichment_slot_status_overview_row_serde_roundtrip() {
    let row = SlotStatusOverviewRow {
        slot_id: "slot-1".into(),
        slot_kind: "builtin".into(),
        implementation_kind: "native".into(),
        promotion_status: "promoted".into(),
        risk_level: ReplacementRiskLevel::Low,
        last_transition_unix_ms: 1_000_000,
        health: "healthy".into(),
        lineage_ref: "ref-1".into(),
    };
    let json = serde_json::to_string(&row).unwrap();
    let rt: SlotStatusOverviewRow = serde_json::from_str(&json).unwrap();
    assert_eq!(row, rt);
}

#[test]
fn enrichment_rollback_event_view_serde_roundtrip() {
    let event = RollbackEventView {
        slot_id: "slot-1".into(),
        receipt_id: "receipt-1".into(),
        reason: "regression detected".into(),
        status: RollbackStatus::Investigating,
        occurred_at_unix_ms: 1_000_000,
        lineage_ref: "ref-1".into(),
        evidence_ref: "ref-2".into(),
    };
    let json = serde_json::to_string(&event).unwrap();
    let rt: RollbackEventView = serde_json::from_str(&json).unwrap();
    assert_eq!(event, rt);
}

// ===========================================================================
// 21) Filter struct Default implementations
// ===========================================================================

#[test]
fn enrichment_control_plane_filter_default() {
    let filter = ControlPlaneDashboardFilter::default();
    assert!(filter.extension_id.is_none());
    assert!(filter.region_id.is_none());
    assert!(filter.severity.is_none());
    assert!(filter.start_unix_ms.is_none());
    assert!(filter.end_unix_ms.is_none());
}

#[test]
fn enrichment_flow_decision_filter_default() {
    let filter = FlowDecisionDashboardFilter::default();
    assert!(filter.extension_id.is_none());
    assert!(filter.source_label.is_none());
    assert!(filter.sink_clearance.is_none());
    assert!(filter.sensitivity.is_none());
    assert!(filter.start_unix_ms.is_none());
    assert!(filter.end_unix_ms.is_none());
}

#[test]
fn enrichment_replacement_filter_default() {
    let filter = ReplacementDashboardFilter::default();
    assert!(filter.slot_kind.is_none());
    assert!(filter.risk_level.is_none());
    assert!(filter.promotion_status.is_none());
}

#[test]
fn enrichment_proof_specialization_filter_default() {
    let filter = ProofSpecializationDashboardFilter::default();
    assert!(filter.target_id.is_none());
    assert!(filter.proof_id.is_none());
    assert!(filter.optimization_class.is_none());
    assert!(filter.start_unix_ms.is_none());
    assert!(filter.end_unix_ms.is_none());
}

#[test]
fn enrichment_capability_delta_filter_default() {
    let filter = CapabilityDeltaDashboardFilter::default();
    assert!(filter.extension_id.is_none());
    assert!(filter.capability.is_none());
    assert!(filter.outcome.is_none());
    assert!(filter.min_over_privilege_ratio_millionths.is_none());
    assert!(filter.grant_expiry_status.is_none());
}

// ===========================================================================
// 22) SpecializationPerformanceImpactView Default
// ===========================================================================

#[test]
fn enrichment_specialization_performance_impact_default() {
    let impact = SpecializationPerformanceImpactView::default();
    assert_eq!(impact.active_specialization_count, 0);
    assert_eq!(impact.aggregate_latency_reduction_millionths, 0);
    assert_eq!(impact.aggregate_throughput_increase_millionths, 0);
    assert_eq!(impact.specialization_coverage_millionths, 0);
}

// ===========================================================================
// 23) IncidentReplayView::snapshot logic
// ===========================================================================

#[test]
fn enrichment_incident_replay_snapshot_empty_is_no_events() {
    let view = IncidentReplayView::snapshot("trace-1", "scenario-1", vec![]);
    assert_eq!(view.replay_status, ReplayStatus::NoEvents);
    assert!(view.deterministic);
    assert!(view.artifact_handles.is_empty());
}

#[test]
fn enrichment_incident_replay_snapshot_with_events_is_complete() {
    let event = ReplayEventView::new(0, "comp", "evt", "ok", 1_000);
    let view = IncidentReplayView::snapshot("trace-1", "scenario-1", vec![event]);
    assert_eq!(view.replay_status, ReplayStatus::Complete);
    assert_eq!(view.events.len(), 1);
}

// ===========================================================================
// 24) ReplayEventView::new normalizes empty strings
// ===========================================================================

#[test]
fn enrichment_replay_event_normalizes_empty_component() {
    let event = ReplayEventView::new(0, "", "evt", "ok", 1_000);
    assert_eq!(event.component, "unknown");
}

#[test]
fn enrichment_replay_event_preserves_nonempty() {
    let event = ReplayEventView::new(1, "comp-1", "evt-1", "pass", 2_000);
    assert_eq!(event.component, "comp-1");
    assert_eq!(event.event, "evt-1");
    assert_eq!(event.outcome, "pass");
    assert_eq!(event.sequence, 1);
    assert_eq!(event.timestamp_unix_ms, 2_000);
    assert!(event.error_code.is_none());
}

// ===========================================================================
// 25) FrankentuiViewPayload — all 8 variant serde roundtrips
// ===========================================================================

#[test]
fn enrichment_payload_incident_replay_serde() {
    let view = IncidentReplayView::snapshot("t", "s", vec![]);
    let payload = FrankentuiViewPayload::IncidentReplay(view);
    let json = serde_json::to_string(&payload).unwrap();
    let rt: FrankentuiViewPayload = serde_json::from_str(&json).unwrap();
    assert_eq!(payload, rt);
}

#[test]
fn enrichment_payload_policy_explanation_serde() {
    let view = PolicyExplanationCardView::from_partial(PolicyExplanationPartial::default());
    let payload = FrankentuiViewPayload::PolicyExplanation(view);
    let json = serde_json::to_string(&payload).unwrap();
    let rt: FrankentuiViewPayload = serde_json::from_str(&json).unwrap();
    assert_eq!(payload, rt);
}

#[test]
fn enrichment_payload_control_dashboard_serde() {
    let view = ControlDashboardView::from_partial(ControlDashboardPartial::default());
    let payload = FrankentuiViewPayload::ControlDashboard(view);
    let json = serde_json::to_string(&payload).unwrap();
    let rt: FrankentuiViewPayload = serde_json::from_str(&json).unwrap();
    assert_eq!(payload, rt);
}

#[test]
fn enrichment_payload_cpid_serde() {
    let view =
        ControlPlaneInvariantsDashboardView::from_partial(ControlPlaneInvariantsPartial::default());
    let payload = FrankentuiViewPayload::ControlPlaneInvariantsDashboard(Box::new(view));
    let json = serde_json::to_string(&payload).unwrap();
    let rt: FrankentuiViewPayload = serde_json::from_str(&json).unwrap();
    assert_eq!(payload, rt);
}

#[test]
fn enrichment_payload_flow_decision_serde() {
    let view = FlowDecisionDashboardView::from_partial(FlowDecisionPartial::default());
    let payload = FrankentuiViewPayload::FlowDecisionDashboard(view);
    let json = serde_json::to_string(&payload).unwrap();
    let rt: FrankentuiViewPayload = serde_json::from_str(&json).unwrap();
    assert_eq!(payload, rt);
}

#[test]
fn enrichment_payload_capability_delta_serde() {
    let view = CapabilityDeltaDashboardView::from_partial(CapabilityDeltaPartial::default());
    let payload = FrankentuiViewPayload::CapabilityDeltaDashboard(view);
    let json = serde_json::to_string(&payload).unwrap();
    let rt: FrankentuiViewPayload = serde_json::from_str(&json).unwrap();
    assert_eq!(payload, rt);
}

#[test]
fn enrichment_payload_proof_specialization_serde() {
    let view = ProofSpecializationLineageDashboardView::from_partial(
        ProofSpecializationLineagePartial::default(),
    );
    let payload = FrankentuiViewPayload::ProofSpecializationLineageDashboard(view);
    let json = serde_json::to_string(&payload).unwrap();
    let rt: FrankentuiViewPayload = serde_json::from_str(&json).unwrap();
    assert_eq!(payload, rt);
}

#[test]
fn enrichment_payload_replacement_progress_serde() {
    let view =
        ReplacementProgressDashboardView::from_partial(ReplacementProgressPartial::default());
    let payload = FrankentuiViewPayload::ReplacementProgressDashboard(view);
    let json = serde_json::to_string(&payload).unwrap();
    let rt: FrankentuiViewPayload = serde_json::from_str(&json).unwrap();
    assert_eq!(payload, rt);
}

// ===========================================================================
// 26) AdapterEnvelope — encode_json roundtrip
// ===========================================================================

#[test]
fn enrichment_adapter_envelope_encode_json_decode_roundtrip() {
    let env = test_envelope();
    let encoded = env.encode_json().unwrap();
    let decoded: AdapterEnvelope = serde_json::from_slice(&encoded).unwrap();
    assert_eq!(env, decoded);
}

// ===========================================================================
// 27) Debug nonempty for key struct types
// ===========================================================================

#[test]
fn enrichment_debug_nonempty_adapter_envelope() {
    let env = test_envelope();
    let debug = format!("{env:?}");
    assert!(!debug.is_empty());
    assert!(debug.contains("AdapterEnvelope"));
}

#[test]
fn enrichment_debug_nonempty_incident_replay_view() {
    let view = IncidentReplayView::snapshot("t", "s", vec![]);
    let debug = format!("{view:?}");
    assert!(!debug.is_empty());
    assert!(debug.contains("IncidentReplayView"));
}

#[test]
fn enrichment_debug_nonempty_dashboard_alert_rule() {
    let rule = DashboardAlertRule {
        rule_id: "r".into(),
        description: "d".into(),
        metric: DashboardAlertMetric::ReplayDivergenceCount,
        comparator: ThresholdComparator::GreaterThan,
        threshold: 1,
        severity: DashboardSeverity::Info,
    };
    let debug = format!("{rule:?}");
    assert!(!debug.is_empty());
    assert!(debug.contains("DashboardAlertRule"));
}

// ===========================================================================
// 28) meets_refresh_sla edge cases
// ===========================================================================

#[test]
fn enrichment_meets_refresh_sla_exact_boundary() {
    let view = ControlPlaneInvariantsDashboardView::from_partial(ControlPlaneInvariantsPartial {
        generated_at_unix_ms: Some(10_000),
        evidence_stream_last_updated_unix_ms: Some(5_001),
        aggregates_last_updated_unix_ms: Some(10_000),
        refresh_policy: Some(DashboardRefreshPolicy {
            evidence_stream_refresh_secs: 5,
            aggregate_refresh_secs: 60,
        }),
        ..ControlPlaneInvariantsPartial::default()
    });
    assert!(view.meets_refresh_sla());
}

#[test]
fn enrichment_meets_refresh_sla_zero_lag() {
    let view = ControlPlaneInvariantsDashboardView::from_partial(ControlPlaneInvariantsPartial {
        generated_at_unix_ms: Some(10_000),
        evidence_stream_last_updated_unix_ms: Some(10_000),
        aggregates_last_updated_unix_ms: Some(10_000),
        ..ControlPlaneInvariantsPartial::default()
    });
    assert!(view.meets_refresh_sla());
}

// ===========================================================================
// 29) evaluate_alerts — different comparator types
// ===========================================================================

#[test]
fn enrichment_evaluate_alerts_greater_than_triggers() {
    let view = ControlPlaneInvariantsDashboardView::from_partial(ControlPlaneInvariantsPartial {
        replay_health: Some(ReplayHealthPanelView {
            last_run_status: ReplayHealthStatus::Fail,
            divergence_count: 10,
            last_replay_timestamp_unix_ms: None,
        }),
        ..ControlPlaneInvariantsPartial::default()
    });
    let rules = vec![DashboardAlertRule {
        rule_id: "divergence-high".into(),
        description: "high divergence".into(),
        metric: DashboardAlertMetric::ReplayDivergenceCount,
        comparator: ThresholdComparator::GreaterThan,
        threshold: 5,
        severity: DashboardSeverity::Critical,
    }];
    let alerts = view.evaluate_alerts(&rules);
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].observed_value, 10);
}

#[test]
fn enrichment_evaluate_alerts_less_than_no_trigger() {
    let view = ControlPlaneInvariantsDashboardView::from_partial(ControlPlaneInvariantsPartial {
        replay_health: Some(ReplayHealthPanelView {
            last_run_status: ReplayHealthStatus::Pass,
            divergence_count: 10,
            last_replay_timestamp_unix_ms: None,
        }),
        ..ControlPlaneInvariantsPartial::default()
    });
    let rules = vec![DashboardAlertRule {
        rule_id: "low-divergence".into(),
        description: "low divergence".into(),
        metric: DashboardAlertMetric::ReplayDivergenceCount,
        comparator: ThresholdComparator::LessThan,
        threshold: 5,
        severity: DashboardSeverity::Info,
    }];
    let alerts = view.evaluate_alerts(&rules);
    assert!(alerts.is_empty());
}

#[test]
fn enrichment_evaluate_alerts_equal_triggers() {
    let view = ControlPlaneInvariantsDashboardView::from_partial(ControlPlaneInvariantsPartial {
        replay_health: Some(ReplayHealthPanelView {
            last_run_status: ReplayHealthStatus::Pass,
            divergence_count: 5,
            last_replay_timestamp_unix_ms: None,
        }),
        ..ControlPlaneInvariantsPartial::default()
    });
    let rules = vec![DashboardAlertRule {
        rule_id: "exact-match".into(),
        description: "exactly 5".into(),
        metric: DashboardAlertMetric::ReplayDivergenceCount,
        comparator: ThresholdComparator::Equal,
        threshold: 5,
        severity: DashboardSeverity::Warning,
    }];
    let alerts = view.evaluate_alerts(&rules);
    assert_eq!(alerts.len(), 1);
}

// ===========================================================================
// 30) Filter struct serde roundtrips
// ===========================================================================

#[test]
fn enrichment_control_plane_filter_serde_roundtrip() {
    let filter = ControlPlaneDashboardFilter {
        extension_id: Some("ext-1".into()),
        region_id: None,
        severity: Some(DashboardSeverity::Critical),
        start_unix_ms: Some(1_000),
        end_unix_ms: Some(2_000),
    };
    let json = serde_json::to_string(&filter).unwrap();
    let rt: ControlPlaneDashboardFilter = serde_json::from_str(&json).unwrap();
    assert_eq!(filter, rt);
}

#[test]
fn enrichment_flow_decision_filter_serde_roundtrip() {
    let filter = FlowDecisionDashboardFilter {
        extension_id: Some("ext-1".into()),
        source_label: Some("secret".into()),
        sink_clearance: None,
        sensitivity: Some(FlowSensitivityLevel::High),
        start_unix_ms: None,
        end_unix_ms: None,
    };
    let json = serde_json::to_string(&filter).unwrap();
    let rt: FlowDecisionDashboardFilter = serde_json::from_str(&json).unwrap();
    assert_eq!(filter, rt);
}

#[test]
fn enrichment_replacement_filter_serde_roundtrip() {
    let filter = ReplacementDashboardFilter {
        slot_kind: Some("builtin".into()),
        risk_level: Some(ReplacementRiskLevel::Medium),
        promotion_status: None,
    };
    let json = serde_json::to_string(&filter).unwrap();
    let rt: ReplacementDashboardFilter = serde_json::from_str(&json).unwrap();
    assert_eq!(filter, rt);
}

#[test]
fn enrichment_specialization_performance_impact_serde_roundtrip() {
    let impact = SpecializationPerformanceImpactView {
        active_specialization_count: 3,
        aggregate_latency_reduction_millionths: 250_000,
        aggregate_throughput_increase_millionths: 150_000,
        specialization_coverage_millionths: 800_000,
    };
    let json = serde_json::to_string(&impact).unwrap();
    let rt: SpecializationPerformanceImpactView = serde_json::from_str(&json).unwrap();
    assert_eq!(impact, rt);
}

// ===========================================================================
// 31) normalize_non_empty — empty strings become "unknown"
// ===========================================================================

#[test]
fn enrichment_envelope_normalizes_empty_decision_context() {
    let env = AdapterEnvelope::new(
        "trace-1",
        1_000,
        AdapterStream::ControlDashboard,
        UpdateKind::Snapshot,
        test_payload(),
    )
    .with_decision_context("", "");
    assert_eq!(env.decision_id, Some("unknown".into()));
    assert_eq!(env.policy_id, Some("unknown".into()));
}

#[test]
fn enrichment_incident_replay_normalizes_empty_scenario_name() {
    let view = IncidentReplayView::snapshot("t", "", vec![]);
    assert_eq!(view.scenario_name, "unknown");
}

// ===========================================================================
// 32) DashboardRefreshPolicy normalization
// ===========================================================================

#[test]
fn enrichment_refresh_policy_zero_evidence_normalizes_to_minimum() {
    let view = ControlPlaneInvariantsDashboardView::from_partial(ControlPlaneInvariantsPartial {
        refresh_policy: Some(DashboardRefreshPolicy {
            evidence_stream_refresh_secs: 0,
            aggregate_refresh_secs: 0,
        }),
        ..ControlPlaneInvariantsPartial::default()
    });
    assert!(view.refresh_policy.evidence_stream_refresh_secs >= 5);
    assert!(view.refresh_policy.aggregate_refresh_secs >= 60);
}

#[test]
fn enrichment_refresh_policy_below_minimum_clamped() {
    let view = ControlPlaneInvariantsDashboardView::from_partial(ControlPlaneInvariantsPartial {
        refresh_policy: Some(DashboardRefreshPolicy {
            evidence_stream_refresh_secs: 1,
            aggregate_refresh_secs: 10,
        }),
        ..ControlPlaneInvariantsPartial::default()
    });
    assert!(view.refresh_policy.evidence_stream_refresh_secs >= 5);
    assert!(view.refresh_policy.aggregate_refresh_secs >= 60);
}

// ===========================================================================
// 33) JSON field-name stability — additional views
// ===========================================================================

#[test]
fn enrichment_json_fields_flow_decision_dashboard() {
    let view = FlowDecisionDashboardView::from_partial(FlowDecisionPartial::default());
    let v: serde_json::Value = serde_json::to_value(&view).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "cluster",
        "zone",
        "security_epoch",
        "generated_at_unix_ms",
        "label_map",
        "blocked_flows",
        "declassification_history",
        "confinement_proofs",
        "alert_indicators",
    ] {
        assert!(
            obj.contains_key(key),
            "FlowDecisionDashboardView missing field: {key}"
        );
    }
}

#[test]
fn enrichment_json_fields_capability_delta_dashboard() {
    let view = CapabilityDeltaDashboardView::from_partial(CapabilityDeltaPartial::default());
    let v: serde_json::Value = serde_json::to_value(&view).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "cluster",
        "zone",
        "security_epoch",
        "generated_at_unix_ms",
        "current_capability_rows",
        "proposed_minimal_rows",
        "escrow_event_feed",
        "override_rationale_rows",
        "batch_review_queue",
        "alert_indicators",
    ] {
        assert!(
            obj.contains_key(key),
            "CapabilityDeltaDashboardView missing field: {key}"
        );
    }
}

#[test]
fn enrichment_json_fields_proof_specialization_dashboard() {
    let view = ProofSpecializationLineageDashboardView::from_partial(
        ProofSpecializationLineagePartial::default(),
    );
    let v: serde_json::Value = serde_json::to_value(&view).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "cluster",
        "zone",
        "security_epoch",
        "generated_at_unix_ms",
        "proof_inventory",
        "active_specializations",
        "invalidation_feed",
        "fallback_events",
        "performance_impact",
        "alert_indicators",
    ] {
        assert!(
            obj.contains_key(key),
            "ProofSpecializationLineageDashboardView missing field: {key}"
        );
    }
}
