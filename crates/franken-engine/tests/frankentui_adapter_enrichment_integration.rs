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
    AdapterEnvelope, AdapterStream, BenchmarkTrendsPanelView, CancellationKind, ConfinementStatus,
    ControlDashboardPartial, ControlDashboardView, ControlPlaneInvariantsDashboardView,
    ControlPlaneInvariantsPartial, DashboardAlertMetric, DashboardRefreshPolicy, DashboardSeverity,
    DecisionOutcomeKind, DecisionOutcomesPanelView, DeclassificationOutcome,
    FRANKENTUI_ADAPTER_SCHEMA_VERSION, FlowDecisionDashboardView, FlowDecisionPartial,
    FlowSensitivityLevel, FrankentuiViewPayload, GrantExpiryStatus, ObligationState,
    ObligationStatusPanelView, OverrideReviewStatus, ProofInventoryKind,
    ProofSpecializationInvalidationReason, ProofValidityStatus, RecoveryStatus,
    RegionLifecyclePanelView, ReplacementRiskLevel, ReplayHealthPanelView, ReplayHealthStatus,
    ReplayStatus, RollbackStatus, SchemaCompatibilityStatus, SchemaVersionPanelView,
    SpecializationFallbackReason, ThresholdComparator, UpdateKind,
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
