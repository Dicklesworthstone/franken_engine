#![forbid(unsafe_code)]
//! Integration tests for the `frankentui_adapter` module.
//!
//! Exercises the FrankenTUI adapter presentation types from outside the crate
//! boundary: envelope construction, dashboard construction via partials,
//! normalization, sorting, filtering, alert evaluation, and serde round-trips.

use std::collections::BTreeMap;

use frankenengine_engine::frankentui_adapter::{
    ActionCandidateView, ActiveSpecializationRowView, AdapterEnvelope, AdapterStream,
    BenchmarkTrendPointView, BlockedFlowView, BlockedPromotionView, CancellationEventView,
    CancellationKind, CapabilityDeltaDashboardFilter, CapabilityDeltaDashboardView,
    CapabilityDeltaEscrowEventView, CapabilityDeltaPartial, CapabilityDeltaReplayJoinPartial,
    CapabilityJustificationDrillView, CapabilityPromotionBatchReviewView, ConfinementProofView,
    ConfinementStatus, ControlDashboardPartial, ControlDashboardView, ControlPlaneDashboardFilter,
    ControlPlaneInvariantsDashboardView, ControlPlaneInvariantsPartial, CoverageTrendPoint,
    CurrentCapabilityDeltaRowView, DashboardAlertMetric, DashboardAlertRule, DashboardMetricView,
    DashboardRefreshPolicy, DashboardSeverity, DecisionOutcomeKind, DeclassificationDecisionView,
    DeclassificationOutcome, DriverView, EvidenceStreamEntryView, ExtensionStatusRow,
    FRANKENTUI_ADAPTER_SCHEMA_VERSION, FlowDecisionDashboardFilter, FlowDecisionDashboardView,
    FlowDecisionPartial, FlowProofCoverageView, FlowSensitivityLevel, FrankentuiViewPayload,
    GrantExpiryStatus, IncidentReplayView, LabelMapEdgeView, LabelMapNodeView, LabelMapView,
    ObligationState, ObligationStatusRowView, OverrideRationaleView, OverrideReviewStatus,
    PolicyExplanationCardView, PolicyExplanationPartial, ProofInventoryKind, ProofInventoryRowView,
    ProofSpecializationDashboardFilter, ProofSpecializationInvalidationReason,
    ProofSpecializationLineageDashboardView, ProofSpecializationLineagePartial,
    ProofValidityStatus, ProposedMinimalCapabilityDeltaRowView, RecoveryStatus,
    RegionLifecycleRowView, ReplacementDashboardFilter, ReplacementOpportunityInput,
    ReplacementProgressDashboardView, ReplacementProgressPartial, ReplacementRiskLevel,
    ReplayEventView, ReplayHealthPanelView, ReplayHealthStatus, ReplayStatus, RollbackEventView,
    RollbackStatus, SafeModeActivationView, SchemaCompatibilityStatus, SlotStatusOverviewRow,
    SpecializationFallbackEventView, SpecializationFallbackReason,
    SpecializationInvalidationRowView, ThresholdComparator, UpdateKind,
    build_native_coverage_meter, build_specialization_performance_impact,
    rank_replacement_opportunities,
};
use frankenengine_engine::slot_registry::{
    AuthorityEnvelope, ReplacementProgressEvent, SlotCapability, SlotId, SlotKind, SlotRegistry,
    SlotReplacementSignal,
};

// ===========================================================================
// 1. Schema version constant
// ===========================================================================

#[test]
fn schema_version_is_positive() {
    const { assert!(FRANKENTUI_ADAPTER_SCHEMA_VERSION > 0) };
}

// ===========================================================================
// 2. AdapterEnvelope construction
// ===========================================================================

#[test]
fn envelope_basic_construction() {
    let view = IncidentReplayView::snapshot("trace-1", "scenario-1", vec![]);
    let payload = FrankentuiViewPayload::IncidentReplay(view);
    let env = AdapterEnvelope::new(
        "trace-1",
        1000,
        AdapterStream::IncidentReplay,
        UpdateKind::Snapshot,
        payload,
    );
    assert_eq!(env.schema_version, FRANKENTUI_ADAPTER_SCHEMA_VERSION);
    assert_eq!(env.trace_id, "trace-1");
    assert_eq!(env.generated_at_unix_ms, 1000);
    assert!(env.decision_id.is_none());
    assert!(env.policy_id.is_none());
}

#[test]
fn envelope_with_decision_context() {
    let view = IncidentReplayView::snapshot("t", "s", vec![]);
    let payload = FrankentuiViewPayload::IncidentReplay(view);
    let env = AdapterEnvelope::new(
        "t",
        1,
        AdapterStream::IncidentReplay,
        UpdateKind::Delta,
        payload,
    )
    .with_decision_context("dec-1", "pol-1");
    assert_eq!(env.decision_id.as_deref(), Some("dec-1"));
    assert_eq!(env.policy_id.as_deref(), Some("pol-1"));
}

#[test]
fn envelope_normalizes_empty_trace_id() {
    let view = IncidentReplayView::snapshot("t", "s", vec![]);
    let payload = FrankentuiViewPayload::IncidentReplay(view);
    let env = AdapterEnvelope::new(
        "",
        0,
        AdapterStream::IncidentReplay,
        UpdateKind::Heartbeat,
        payload,
    );
    assert_eq!(env.trace_id, "unknown");
}

#[test]
fn envelope_encode_json_succeeds() {
    let view = IncidentReplayView::snapshot("t", "s", vec![]);
    let payload = FrankentuiViewPayload::IncidentReplay(view);
    let env = AdapterEnvelope::new(
        "t",
        1,
        AdapterStream::IncidentReplay,
        UpdateKind::Snapshot,
        payload,
    );
    let bytes = env.encode_json().unwrap();
    assert!(!bytes.is_empty());
    let decoded: AdapterEnvelope = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(decoded.trace_id, "t");
}

// ===========================================================================
// 3. IncidentReplayView
// ===========================================================================

#[test]
fn incident_replay_snapshot_no_events() {
    let view = IncidentReplayView::snapshot("t1", "scen", vec![]);
    assert_eq!(view.trace_id, "t1");
    assert_eq!(view.scenario_name, "scen");
    assert!(view.deterministic);
    assert_eq!(view.replay_status, ReplayStatus::NoEvents);
    assert!(view.events.is_empty());
}

#[test]
fn incident_replay_snapshot_with_events() {
    let ev = ReplayEventView::new(0, "comp", "ev", "ok", 100);
    let view = IncidentReplayView::snapshot("t1", "scen", vec![ev]);
    assert_eq!(view.replay_status, ReplayStatus::Complete);
    assert_eq!(view.events.len(), 1);
    assert_eq!(view.events[0].sequence, 0);
    assert_eq!(view.events[0].component, "comp");
}

#[test]
fn replay_event_normalizes_empty_strings() {
    let ev = ReplayEventView::new(0, "", "", "", 0);
    assert_eq!(ev.component, "unknown");
    assert_eq!(ev.event, "unknown");
    assert_eq!(ev.outcome, "unknown");
}

// ===========================================================================
// 4. PolicyExplanationCardView
// ===========================================================================

#[test]
fn policy_explanation_from_partial_defaults() {
    let partial = PolicyExplanationPartial {
        decision_id: "d1".into(),
        policy_id: "p1".into(),
        selected_action: "allow".into(),
        confidence_millionths: None,
        expected_loss_millionths: None,
        action_candidates: vec![],
        key_drivers: vec![],
    };
    let card = PolicyExplanationCardView::from_partial(partial);
    assert_eq!(card.decision_id, "d1");
    assert_eq!(card.confidence_millionths, 0);
    assert_eq!(card.expected_loss_millionths, 0);
}

#[test]
fn policy_explanation_from_partial_with_values() {
    let partial = PolicyExplanationPartial {
        decision_id: "d".into(),
        policy_id: "p".into(),
        selected_action: "deny".into(),
        confidence_millionths: Some(900_000),
        expected_loss_millionths: Some(50_000),
        action_candidates: vec![ActionCandidateView {
            action: "deny".into(),
            expected_loss_millionths: 50_000,
        }],
        key_drivers: vec![DriverView {
            name: "driver1".into(),
            contribution_millionths: 400_000,
        }],
    };
    let card = PolicyExplanationCardView::from_partial(partial);
    assert_eq!(card.confidence_millionths, 900_000);
    assert_eq!(card.action_candidates.len(), 1);
    assert_eq!(card.key_drivers.len(), 1);
}

// ===========================================================================
// 5. ControlDashboardView
// ===========================================================================

#[test]
fn control_dashboard_from_empty_partial() {
    let partial = ControlDashboardPartial::default();
    let view = ControlDashboardView::from_partial(partial);
    assert_eq!(view.cluster, "unknown");
    assert_eq!(view.zone, "unknown");
    assert_eq!(view.security_epoch, 0);
}

#[test]
fn control_dashboard_from_partial_with_data() {
    let partial = ControlDashboardPartial {
        cluster: "us-east".into(),
        zone: "zone-1".into(),
        security_epoch: Some(5),
        runtime_mode: "production".into(),
        metrics: vec![DashboardMetricView {
            metric: "cpu".into(),
            value: 42,
            unit: "%".into(),
        }],
        extension_rows: vec![ExtensionStatusRow {
            extension_id: "ext-1".into(),
            state: "active".into(),
            trust_level: "high".into(),
        }],
        incident_counts: {
            let mut m = BTreeMap::new();
            m.insert("crash".into(), 3);
            m
        },
    };
    let view = ControlDashboardView::from_partial(partial);
    assert_eq!(view.cluster, "us-east");
    assert_eq!(view.security_epoch, 5);
    assert_eq!(view.metrics.len(), 1);
    assert_eq!(view.extension_rows.len(), 1);
    assert_eq!(view.incident_counts["crash"], 3);
}

// ===========================================================================
// 6. ControlPlaneInvariantsDashboardView
// ===========================================================================

fn sample_evidence_entry(
    trace: &str,
    outcome: DecisionOutcomeKind,
    ts: u64,
) -> EvidenceStreamEntryView {
    EvidenceStreamEntryView {
        trace_id: trace.into(),
        decision_id: "d1".into(),
        policy_id: "p1".into(),
        action_type: "access".into(),
        decision_outcome: outcome,
        expected_loss_millionths: 100_000,
        extension_id: "ext-1".into(),
        region_id: "region-1".into(),
        severity: DashboardSeverity::Info,
        component: "comp".into(),
        event: "event".into(),
        outcome: "ok".into(),
        error_code: None,
        timestamp_unix_ms: ts,
    }
}

fn sample_obligation_row(id: &str, state: ObligationState) -> ObligationStatusRowView {
    ObligationStatusRowView {
        obligation_id: id.into(),
        extension_id: "ext-1".into(),
        region_id: "region-1".into(),
        state,
        severity: DashboardSeverity::Info,
        due_at_unix_ms: 5000,
        updated_at_unix_ms: 1000,
        detail: "detail".into(),
    }
}

#[test]
fn cpid_from_empty_partial() {
    let partial = ControlPlaneInvariantsPartial::default();
    let view = ControlPlaneInvariantsDashboardView::from_partial(partial);
    assert_eq!(view.cluster, "unknown");
    assert!(view.evidence_stream.is_empty());
    assert_eq!(view.decision_outcomes.allow_count, 0);
}

#[test]
fn cpid_auto_summarizes_decision_outcomes() {
    let partial = ControlPlaneInvariantsPartial {
        evidence_stream: vec![
            sample_evidence_entry("t1", DecisionOutcomeKind::Allow, 100),
            sample_evidence_entry("t2", DecisionOutcomeKind::Allow, 200),
            sample_evidence_entry("t3", DecisionOutcomeKind::Deny, 300),
        ],
        ..Default::default()
    };
    let view = ControlPlaneInvariantsDashboardView::from_partial(partial);
    assert_eq!(view.decision_outcomes.allow_count, 2);
    assert_eq!(view.decision_outcomes.deny_count, 1);
    assert_eq!(view.decision_outcomes.fallback_count, 0);
}

#[test]
fn cpid_auto_summarizes_obligation_status() {
    let partial = ControlPlaneInvariantsPartial {
        obligation_rows: vec![
            sample_obligation_row("ob1", ObligationState::Open),
            sample_obligation_row("ob2", ObligationState::Fulfilled),
            sample_obligation_row("ob3", ObligationState::Failed),
            sample_obligation_row("ob4", ObligationState::Fulfilled),
        ],
        ..Default::default()
    };
    let view = ControlPlaneInvariantsDashboardView::from_partial(partial);
    assert_eq!(view.obligation_status.open_count, 1);
    assert_eq!(view.obligation_status.fulfilled_count, 2);
    assert_eq!(view.obligation_status.failed_count, 1);
}

#[test]
fn cpid_evidence_stream_sorted_by_timestamp() {
    let partial = ControlPlaneInvariantsPartial {
        evidence_stream: vec![
            sample_evidence_entry("t3", DecisionOutcomeKind::Allow, 300),
            sample_evidence_entry("t1", DecisionOutcomeKind::Deny, 100),
            sample_evidence_entry("t2", DecisionOutcomeKind::Fallback, 200),
        ],
        ..Default::default()
    };
    let view = ControlPlaneInvariantsDashboardView::from_partial(partial);
    let timestamps: Vec<_> = view
        .evidence_stream
        .iter()
        .map(|e| e.timestamp_unix_ms)
        .collect();
    assert_eq!(timestamps, vec![100, 200, 300]);
}

#[test]
fn cpid_filtering_by_extension_id() {
    let mut entry1 = sample_evidence_entry("t1", DecisionOutcomeKind::Allow, 100);
    entry1.extension_id = "ext-a".into();
    let mut entry2 = sample_evidence_entry("t2", DecisionOutcomeKind::Deny, 200);
    entry2.extension_id = "ext-b".into();

    let partial = ControlPlaneInvariantsPartial {
        evidence_stream: vec![entry1, entry2],
        ..Default::default()
    };
    let view = ControlPlaneInvariantsDashboardView::from_partial(partial);
    let filter = ControlPlaneDashboardFilter {
        extension_id: Some("ext-a".into()),
        ..Default::default()
    };
    let filtered = view.filtered(&filter);
    assert_eq!(filtered.evidence_stream.len(), 1);
    assert_eq!(filtered.evidence_stream[0].extension_id, "ext-a");
}

#[test]
fn cpid_filtering_by_timestamp_range() {
    let partial = ControlPlaneInvariantsPartial {
        evidence_stream: vec![
            sample_evidence_entry("t1", DecisionOutcomeKind::Allow, 100),
            sample_evidence_entry("t2", DecisionOutcomeKind::Allow, 200),
            sample_evidence_entry("t3", DecisionOutcomeKind::Allow, 300),
        ],
        ..Default::default()
    };
    let view = ControlPlaneInvariantsDashboardView::from_partial(partial);
    let filter = ControlPlaneDashboardFilter {
        start_unix_ms: Some(150),
        end_unix_ms: Some(250),
        ..Default::default()
    };
    let filtered = view.filtered(&filter);
    assert_eq!(filtered.evidence_stream.len(), 1);
    assert_eq!(filtered.evidence_stream[0].trace_id, "t2");
}

#[test]
fn cpid_refresh_sla_met_when_recent() {
    let now = 100_000;
    let partial = ControlPlaneInvariantsPartial {
        generated_at_unix_ms: Some(now),
        evidence_stream_last_updated_unix_ms: Some(now - 1000),
        aggregates_last_updated_unix_ms: Some(now - 10_000),
        refresh_policy: Some(DashboardRefreshPolicy {
            evidence_stream_refresh_secs: 5,
            aggregate_refresh_secs: 60,
        }),
        ..Default::default()
    };
    let view = ControlPlaneInvariantsDashboardView::from_partial(partial);
    assert!(view.meets_refresh_sla());
}

#[test]
fn cpid_refresh_sla_breached_when_stale() {
    let now = 100_000;
    let partial = ControlPlaneInvariantsPartial {
        generated_at_unix_ms: Some(now),
        evidence_stream_last_updated_unix_ms: Some(now - 30_000),
        aggregates_last_updated_unix_ms: Some(now - 30_000),
        refresh_policy: Some(DashboardRefreshPolicy {
            evidence_stream_refresh_secs: 5,
            aggregate_refresh_secs: 60,
        }),
        ..Default::default()
    };
    let view = ControlPlaneInvariantsDashboardView::from_partial(partial);
    assert!(!view.meets_refresh_sla());
}

#[test]
fn cpid_alert_rule_evaluation() {
    let partial = ControlPlaneInvariantsPartial {
        obligation_rows: vec![
            sample_obligation_row("ob1", ObligationState::Failed),
            sample_obligation_row("ob2", ObligationState::Fulfilled),
            sample_obligation_row("ob3", ObligationState::Failed),
            sample_obligation_row("ob4", ObligationState::Failed),
        ],
        alert_rules: vec![DashboardAlertRule {
            rule_id: "r1".into(),
            description: "high failure rate".into(),
            metric: DashboardAlertMetric::ObligationFailureRateMillionths,
            comparator: ThresholdComparator::GreaterThan,
            threshold: 500_000,
            severity: DashboardSeverity::Critical,
        }],
        ..Default::default()
    };
    let view = ControlPlaneInvariantsDashboardView::from_partial(partial);
    let alerts = view.triggered_alerts();
    // 3 failed out of 4 = 750_000 millionths > 500_000 threshold
    assert!(!alerts.is_empty());
    assert_eq!(alerts[0].rule_id, "r1");
}

#[test]
fn cpid_benchmark_trends_sorted() {
    let partial = ControlPlaneInvariantsPartial {
        benchmark_points: vec![
            BenchmarkTrendPointView {
                timestamp_unix_ms: 300,
                throughput_tps: 100,
                latency_p95_ms: 5,
                memory_peak_mb: 128,
            },
            BenchmarkTrendPointView {
                timestamp_unix_ms: 100,
                throughput_tps: 80,
                latency_p95_ms: 10,
                memory_peak_mb: 64,
            },
        ],
        ..Default::default()
    };
    let view = ControlPlaneInvariantsDashboardView::from_partial(partial);
    let timestamps: Vec<_> = view
        .benchmark_trends
        .points
        .iter()
        .map(|p| p.timestamp_unix_ms)
        .collect();
    assert_eq!(timestamps, vec![100, 300]);
}

// ===========================================================================
// 7. FlowDecisionDashboardView
// ===========================================================================

fn sample_blocked_flow(ext: &str, ts: u64) -> BlockedFlowView {
    BlockedFlowView {
        flow_id: "f1".into(),
        extension_id: ext.into(),
        source_label: "secret".into(),
        sink_clearance: "public".into(),
        sensitivity: FlowSensitivityLevel::High,
        blocked_reason: "policy violation".into(),
        attempted_exfiltration: false,
        code_path_ref: "ref1".into(),
        extension_context_ref: "ctx1".into(),
        trace_id: "t1".into(),
        decision_id: "d1".into(),
        policy_id: "p1".into(),
        error_code: None,
        occurred_at_unix_ms: ts,
    }
}

#[test]
fn flow_decision_from_empty_partial() {
    let partial = FlowDecisionPartial::default();
    let view = FlowDecisionDashboardView::from_partial(partial);
    assert_eq!(view.cluster, "unknown");
    assert!(view.blocked_flows.is_empty());
    assert!(view.label_map.nodes.is_empty());
}

#[test]
fn flow_decision_blocked_flows_sorted_by_timestamp() {
    let partial = FlowDecisionPartial {
        blocked_flows: vec![
            sample_blocked_flow("ext-a", 300),
            sample_blocked_flow("ext-b", 100),
            sample_blocked_flow("ext-c", 200),
        ],
        ..Default::default()
    };
    let view = FlowDecisionDashboardView::from_partial(partial);
    let timestamps: Vec<_> = view
        .blocked_flows
        .iter()
        .map(|b| b.occurred_at_unix_ms)
        .collect();
    assert_eq!(timestamps, vec![100, 200, 300]);
}

#[test]
fn flow_decision_with_label_map() {
    let partial = FlowDecisionPartial {
        label_map: LabelMapView {
            nodes: vec![
                LabelMapNodeView {
                    label_id: "secret".into(),
                    sensitivity: FlowSensitivityLevel::High,
                    description: "secret data".into(),
                    extension_overlays: vec!["ext-1".into()],
                },
                LabelMapNodeView {
                    label_id: "public".into(),
                    sensitivity: FlowSensitivityLevel::Low,
                    description: "public data".into(),
                    extension_overlays: vec![],
                },
            ],
            edges: vec![LabelMapEdgeView {
                source_label: "secret".into(),
                sink_clearance: "public".into(),
                route_policy_id: Some("pol-1".into()),
                route_enabled: false,
            }],
        },
        ..Default::default()
    };
    let view = FlowDecisionDashboardView::from_partial(partial);
    assert_eq!(view.label_map.nodes.len(), 2);
    assert_eq!(view.label_map.edges.len(), 1);
}

#[test]
fn flow_decision_filtering_by_extension_id() {
    let partial = FlowDecisionPartial {
        blocked_flows: vec![
            sample_blocked_flow("ext-a", 100),
            sample_blocked_flow("ext-b", 200),
        ],
        ..Default::default()
    };
    let view = FlowDecisionDashboardView::from_partial(partial);
    let filter = FlowDecisionDashboardFilter {
        extension_id: Some("ext-a".into()),
        ..Default::default()
    };
    let filtered = view.filtered(&filter);
    assert_eq!(filtered.blocked_flows.len(), 1);
    assert_eq!(filtered.blocked_flows[0].extension_id, "ext-a");
}

#[test]
fn flow_decision_auto_alerts_when_blocked_threshold_exceeded() {
    let mut flows = vec![];
    for i in 0..10 {
        let mut f = sample_blocked_flow("ext-a", 100 + i);
        f.flow_id = format!("f{i}");
        flows.push(f);
    }
    let partial = FlowDecisionPartial {
        blocked_flows: flows,
        blocked_flow_alert_threshold: Some(5),
        ..Default::default()
    };
    let view = FlowDecisionDashboardView::from_partial(partial);
    assert!(!view.alert_indicators.is_empty());
}

// ===========================================================================
// 8. CapabilityDeltaDashboardView
// ===========================================================================

fn sample_current_capability_row(ext: &str) -> CurrentCapabilityDeltaRowView {
    CurrentCapabilityDeltaRowView {
        extension_id: ext.into(),
        witness_id: "w1".into(),
        policy_id: "p1".into(),
        witness_epoch: 1,
        lifecycle_state: "active".into(),
        active_witness_capabilities: vec!["read".into(), "write".into(), "exec".into()],
        manifest_declared_capabilities: vec!["read".into(), "write".into()],
        over_privileged_capabilities: vec!["exec".into()],
        over_privilege_ratio_millionths: 333_333,
        over_privilege_replay_ref: "ref1".into(),
        latest_receipt_timestamp_ns: Some(1_000_000),
    }
}

#[test]
fn capability_delta_from_empty_partial() {
    let partial = CapabilityDeltaPartial::default();
    let view = CapabilityDeltaDashboardView::from_partial(partial);
    assert_eq!(view.cluster, "unknown");
    assert!(view.current_capability_rows.is_empty());
}

#[test]
fn capability_delta_from_partial_with_data() {
    let partial = CapabilityDeltaPartial {
        cluster: "us-east".into(),
        zone: "z1".into(),
        current_capability_rows: vec![sample_current_capability_row("ext-a")],
        ..Default::default()
    };
    let view = CapabilityDeltaDashboardView::from_partial(partial);
    assert_eq!(view.cluster, "us-east");
    assert_eq!(view.current_capability_rows.len(), 1);
}

#[test]
fn capability_delta_filtering_by_extension() {
    let partial = CapabilityDeltaPartial {
        current_capability_rows: vec![
            sample_current_capability_row("ext-a"),
            sample_current_capability_row("ext-b"),
        ],
        ..Default::default()
    };
    let view = CapabilityDeltaDashboardView::from_partial(partial);
    let filter = CapabilityDeltaDashboardFilter {
        extension_id: Some("ext-a".into()),
        ..Default::default()
    };
    let filtered = view.filtered(&filter);
    assert_eq!(filtered.current_capability_rows.len(), 1);
    assert_eq!(filtered.current_capability_rows[0].extension_id, "ext-a");
}

#[test]
fn capability_delta_capabilities_sorted_and_deduped() {
    let mut row = sample_current_capability_row("ext-a");
    row.active_witness_capabilities = vec!["write".into(), "read".into(), "write".into()];
    let partial = CapabilityDeltaPartial {
        current_capability_rows: vec![row],
        ..Default::default()
    };
    let view = CapabilityDeltaDashboardView::from_partial(partial);
    let caps = &view.current_capability_rows[0].active_witness_capabilities;
    // Should be sorted and deduped
    for w in caps.windows(2) {
        assert!(w[0] <= w[1], "capabilities should be sorted");
    }
}

// ===========================================================================
// 9. ReplacementProgressDashboardView
// ===========================================================================

fn sample_slot_row(id: &str, kind: &str, impl_kind: &str) -> SlotStatusOverviewRow {
    SlotStatusOverviewRow {
        slot_id: id.into(),
        slot_kind: kind.into(),
        implementation_kind: impl_kind.into(),
        promotion_status: "promoted".into(),
        risk_level: ReplacementRiskLevel::Low,
        last_transition_unix_ms: 1000,
        health: "healthy".into(),
        lineage_ref: "ref".into(),
    }
}

#[test]
fn replacement_progress_from_empty_partial() {
    let partial = ReplacementProgressPartial::default();
    let view = ReplacementProgressDashboardView::from_partial(partial);
    assert_eq!(view.cluster, "unknown");
    assert_eq!(view.native_coverage.native_slots, 0);
    assert_eq!(view.native_coverage.delegate_slots, 0);
}

#[test]
fn replacement_progress_native_coverage_computed() {
    let partial = ReplacementProgressPartial {
        slot_status_overview: vec![
            sample_slot_row("s1", "parser", "native"),
            sample_slot_row("s2", "gc", "native"),
            sample_slot_row("s3", "compiler", "delegate"),
        ],
        ..Default::default()
    };
    let view = ReplacementProgressDashboardView::from_partial(partial);
    assert_eq!(view.native_coverage.native_slots, 2);
    assert_eq!(view.native_coverage.delegate_slots, 1);
    // 2 / 3 = 666_666 or 666_667 millionths
    assert!(view.native_coverage.native_coverage_millionths > 600_000);
    assert!(view.native_coverage.native_coverage_millionths < 700_000);
}

#[test]
fn replacement_progress_blocked_promotions_sorted() {
    let partial = ReplacementProgressPartial {
        blocked_promotions: vec![
            BlockedPromotionView {
                slot_id: "s-b".into(),
                gate_failure_code: "GATE_A".into(),
                failure_detail: "detail".into(),
                recommended_remediation: "fix".into(),
                lineage_ref: "ref".into(),
                evidence_ref: "ref".into(),
            },
            BlockedPromotionView {
                slot_id: "s-a".into(),
                gate_failure_code: "GATE_B".into(),
                failure_detail: "detail".into(),
                recommended_remediation: "fix".into(),
                lineage_ref: "ref".into(),
                evidence_ref: "ref".into(),
            },
        ],
        ..Default::default()
    };
    let view = ReplacementProgressDashboardView::from_partial(partial);
    assert_eq!(view.blocked_promotions[0].slot_id, "s-a");
    assert_eq!(view.blocked_promotions[1].slot_id, "s-b");
}

#[test]
fn replacement_progress_filtering_by_slot_kind() {
    let partial = ReplacementProgressPartial {
        slot_status_overview: vec![
            sample_slot_row("s1", "parser", "native"),
            sample_slot_row("s2", "gc", "delegate"),
        ],
        ..Default::default()
    };
    let view = ReplacementProgressDashboardView::from_partial(partial);
    let filter = ReplacementDashboardFilter {
        slot_kind: Some("parser".into()),
        ..Default::default()
    };
    let filtered = view.filtered(&filter);
    assert_eq!(filtered.slot_status_overview.len(), 1);
    assert_eq!(filtered.slot_status_overview[0].slot_kind, "parser");
}

fn replacement_test_authority() -> AuthorityEnvelope {
    AuthorityEnvelope {
        required: vec![SlotCapability::EmitEvidence],
        permitted: vec![SlotCapability::EmitEvidence, SlotCapability::ReadSource],
    }
}

fn replacement_register_slot(registry: &mut SlotRegistry, id: &str, kind: SlotKind) -> SlotId {
    let slot_id = SlotId::new(id).expect("valid slot id");
    registry
        .register_delegate(
            slot_id.clone(),
            kind,
            replacement_test_authority(),
            format!("delegate-{id}"),
            "1000".to_string(),
        )
        .expect("register delegate");
    slot_id
}

#[test]
fn replacement_progress_from_slot_registry_snapshot_emits_drilldown_refs() {
    let mut registry = SlotRegistry::new();
    let parser_id = replacement_register_slot(&mut registry, "parser", SlotKind::Parser);
    let gc_id = replacement_register_slot(&mut registry, "gc", SlotKind::GarbageCollector);

    registry
        .begin_candidacy(&gc_id, "candidate-gc".to_string(), "2000".to_string())
        .expect("gc candidacy");
    registry
        .promote(
            &gc_id,
            "native-gc".to_string(),
            &replacement_test_authority(),
            "receipt-gc".to_string(),
            "3000".to_string(),
        )
        .expect("gc promote");
    registry
        .demote(&gc_id, "canary regression".to_string(), "4000".to_string())
        .expect("gc demote");

    let mut signals = BTreeMap::new();
    signals.insert(
        parser_id,
        SlotReplacementSignal {
            invocation_weight_millionths: 900_000,
            throughput_uplift_millionths: 450_000,
            security_risk_reduction_millionths: 300_000,
        },
    );
    signals.insert(
        gc_id,
        SlotReplacementSignal {
            invocation_weight_millionths: 100_000,
            throughput_uplift_millionths: 100_000,
            security_risk_reduction_millionths: 25_000,
        },
    );
    let mut snapshot = registry
        .snapshot_replacement_progress(
            "trace-bridge-1",
            "decision-bridge-1",
            "policy-bridge-1",
            &signals,
        )
        .expect("snapshot");
    snapshot.events.push(ReplacementProgressEvent {
        trace_id: "trace-bridge-1".to_string(),
        decision_id: "decision-bridge-1".to_string(),
        policy_id: "policy-bridge-1".to_string(),
        component: "self_replacement_progress".to_string(),
        event: "promotion_gate_failed".to_string(),
        outcome: "blocked".to_string(),
        error_code: Some("FE-GATE-REPLAY".to_string()),
        slot_id: Some("parser".to_string()),
        detail: "differential mismatch".to_string(),
    });

    let dashboard = ReplacementProgressDashboardView::from_slot_registry_snapshot(
        &registry,
        &snapshot,
        "prod",
        "us-east-1",
        9,
        5_000,
    );

    assert_eq!(dashboard.cluster, "prod");
    assert_eq!(dashboard.zone, "us-east-1");
    assert!(
        dashboard
            .slot_status_overview
            .iter()
            .any(|row| row.slot_id == "parser"
                && row.lineage_ref == "frankentui://replacement-lineage/parser")
    );
    assert!(
        dashboard
            .rollback_events
            .iter()
            .any(|event| event.slot_id == "gc" && event.evidence_ref.contains("trace-bridge-1"))
    );
    assert_eq!(dashboard.blocked_promotions.len(), 1);
    assert_eq!(
        dashboard.blocked_promotions[0].gate_failure_code,
        "FE-GATE-REPLAY"
    );
}

#[test]
fn replacement_progress_refresh_from_slot_registry_snapshot_updates_after_demotion() {
    let mut registry = SlotRegistry::new();
    let parser_id = replacement_register_slot(&mut registry, "parser", SlotKind::Parser);

    let mut signals = BTreeMap::new();
    signals.insert(
        parser_id.clone(),
        SlotReplacementSignal {
            invocation_weight_millionths: 1_000_000,
            throughput_uplift_millionths: 500_000,
            security_risk_reduction_millionths: 200_000,
        },
    );

    let snapshot_before = registry
        .snapshot_replacement_progress(
            "trace-bridge-2",
            "decision-bridge-2",
            "policy-bridge-2",
            &signals,
        )
        .expect("snapshot before");
    let before = ReplacementProgressDashboardView::from_slot_registry_snapshot(
        &registry,
        &snapshot_before,
        "prod",
        "us-west-2",
        13,
        6_000,
    );

    registry
        .begin_candidacy(
            &parser_id,
            "candidate-parser".to_string(),
            "7000".to_string(),
        )
        .expect("candidacy");
    registry
        .promote(
            &parser_id,
            "native-parser".to_string(),
            &replacement_test_authority(),
            "receipt-parser".to_string(),
            "8000".to_string(),
        )
        .expect("promote");
    registry
        .demote(
            &parser_id,
            "post-promotion regression".to_string(),
            "9000".to_string(),
        )
        .expect("demote");

    let snapshot_after = registry
        .snapshot_replacement_progress(
            "trace-bridge-2",
            "decision-bridge-2",
            "policy-bridge-2",
            &signals,
        )
        .expect("snapshot after");
    let refreshed = before.refreshed_from_slot_registry_snapshot(&registry, &snapshot_after, 9_500);

    assert_eq!(refreshed.cluster, "prod");
    assert_eq!(refreshed.zone, "us-west-2");
    assert_eq!(refreshed.security_epoch, 13);
    assert_eq!(refreshed.generated_at_unix_ms, 9_500);
    assert!(
        refreshed
            .slot_status_overview
            .iter()
            .any(|row| row.slot_id == "parser" && row.promotion_status == "demoted")
    );
    assert!(
        refreshed
            .rollback_events
            .iter()
            .any(|event| event.slot_id == "parser")
    );
}

// ===========================================================================
// 10. Public helper functions
// ===========================================================================

#[test]
fn build_native_coverage_meter_empty_slots() {
    let meter = build_native_coverage_meter(&[], vec![]);
    assert_eq!(meter.native_slots, 0);
    assert_eq!(meter.delegate_slots, 0);
    assert_eq!(meter.native_coverage_millionths, 0);
}

#[test]
fn build_native_coverage_meter_all_native() {
    let slots = vec![
        sample_slot_row("s1", "a", "native"),
        sample_slot_row("s2", "b", "native"),
    ];
    let meter = build_native_coverage_meter(&slots, vec![]);
    assert_eq!(meter.native_slots, 2);
    assert_eq!(meter.delegate_slots, 0);
    assert_eq!(meter.native_coverage_millionths, 1_000_000);
}

#[test]
fn rank_replacement_opportunities_empty() {
    let ranked = rank_replacement_opportunities(vec![]);
    assert!(ranked.is_empty());
}

#[test]
fn rank_replacement_opportunities_sorted_by_expected_value_desc() {
    let inputs = vec![
        ReplacementOpportunityInput {
            slot_id: "low".into(),
            slot_kind: "parser".into(),
            performance_uplift_millionths: 100_000,
            invocation_frequency_per_minute: 1,
            risk_reduction_millionths: 50_000,
        },
        ReplacementOpportunityInput {
            slot_id: "high".into(),
            slot_kind: "gc".into(),
            performance_uplift_millionths: 900_000,
            invocation_frequency_per_minute: 100,
            risk_reduction_millionths: 500_000,
        },
    ];
    let ranked = rank_replacement_opportunities(inputs);
    assert_eq!(ranked.len(), 2);
    assert_eq!(ranked[0].slot_id, "high");
    assert_eq!(ranked[1].slot_id, "low");
    assert!(ranked[0].expected_value_score_millionths >= ranked[1].expected_value_score_millionths);
}

#[test]
fn build_specialization_performance_impact_empty() {
    let impact = build_specialization_performance_impact(&[], &[]);
    assert_eq!(impact.active_specialization_count, 0);
    assert_eq!(impact.aggregate_latency_reduction_millionths, 0);
}

#[test]
fn build_specialization_performance_impact_with_data() {
    let specs = vec![ActiveSpecializationRowView {
        specialization_id: "sp1".into(),
        target_id: "t1".into(),
        target_kind: "parser".into(),
        optimization_class: "opt".into(),
        latency_reduction_millionths: 200_000,
        throughput_increase_millionths: 100_000,
        proof_input_ids: vec!["p1".into()],
        transformation_ref: "ref".into(),
        receipt_ref: "ref".into(),
        activated_at_unix_ms: 100,
    }];
    let proofs = vec![ProofInventoryRowView {
        proof_id: "p1".into(),
        proof_kind: ProofInventoryKind::CapabilityWitness,
        validity_status: ProofValidityStatus::Valid,
        epoch_id: 1,
        linked_specialization_count: 1,
        enabled_specialization_ids: vec!["sp1".into()],
        proof_ref: "ref".into(),
    }];
    let impact = build_specialization_performance_impact(&specs, &proofs);
    assert_eq!(impact.active_specialization_count, 1);
    assert_eq!(impact.aggregate_latency_reduction_millionths, 200_000);
    assert_eq!(impact.aggregate_throughput_increase_millionths, 100_000);
}

// ===========================================================================
// 11. ProofSpecializationLineageDashboardView
// ===========================================================================

#[test]
fn proof_specialization_from_empty_partial() {
    let partial = ProofSpecializationLineagePartial::default();
    let view = ProofSpecializationLineageDashboardView::from_partial(partial);
    assert_eq!(view.cluster, "unknown");
    assert!(view.proof_inventory.is_empty());
    assert_eq!(view.performance_impact.active_specialization_count, 0);
}

#[test]
fn proof_specialization_invalidation_feed_sorted() {
    let partial = ProofSpecializationLineagePartial {
        invalidation_feed: vec![
            SpecializationInvalidationRowView {
                invalidation_id: "inv2".into(),
                specialization_id: "sp1".into(),
                target_id: "t1".into(),
                reason: ProofSpecializationInvalidationReason::EpochChange,
                reason_detail: "epoch changed".into(),
                proof_id: Some("p1".into()),
                old_epoch_id: Some(1),
                new_epoch_id: Some(2),
                fallback_confirmed: true,
                fallback_confirmation_ref: "ref".into(),
                occurred_at_unix_ms: 300,
            },
            SpecializationInvalidationRowView {
                invalidation_id: "inv1".into(),
                specialization_id: "sp2".into(),
                target_id: "t2".into(),
                reason: ProofSpecializationInvalidationReason::ProofExpired,
                reason_detail: "proof expired".into(),
                proof_id: None,
                old_epoch_id: None,
                new_epoch_id: None,
                fallback_confirmed: false,
                fallback_confirmation_ref: "ref".into(),
                occurred_at_unix_ms: 100,
            },
        ],
        ..Default::default()
    };
    let view = ProofSpecializationLineageDashboardView::from_partial(partial);
    assert_eq!(view.invalidation_feed[0].occurred_at_unix_ms, 100);
    assert_eq!(view.invalidation_feed[1].occurred_at_unix_ms, 300);
}

#[test]
fn proof_specialization_bulk_invalidation_alert() {
    let mut invalidations = vec![];
    for i in 0..15 {
        invalidations.push(SpecializationInvalidationRowView {
            invalidation_id: format!("inv{i}"),
            specialization_id: format!("sp{i}"),
            target_id: "t1".into(),
            reason: ProofSpecializationInvalidationReason::EpochChange,
            reason_detail: "epoch changed".into(),
            proof_id: None,
            old_epoch_id: Some(1),
            new_epoch_id: Some(2),
            fallback_confirmed: true,
            fallback_confirmation_ref: "ref".into(),
            occurred_at_unix_ms: 100 + i as u64,
        });
    }
    let partial = ProofSpecializationLineagePartial {
        invalidation_feed: invalidations,
        bulk_invalidation_alert_threshold: Some(10),
        ..Default::default()
    };
    let view = ProofSpecializationLineageDashboardView::from_partial(partial);
    let has_bulk_alert = view
        .alert_indicators
        .iter()
        .any(|a| a.alert_id.contains("bulk"));
    assert!(has_bulk_alert, "should generate bulk invalidation alert");
}

#[test]
fn proof_specialization_filtering_by_target_id() {
    let partial = ProofSpecializationLineagePartial {
        active_specializations: vec![
            ActiveSpecializationRowView {
                specialization_id: "sp1".into(),
                target_id: "t-a".into(),
                target_kind: "parser".into(),
                optimization_class: "opt".into(),
                latency_reduction_millionths: 100_000,
                throughput_increase_millionths: 50_000,
                proof_input_ids: vec![],
                transformation_ref: "ref".into(),
                receipt_ref: "ref".into(),
                activated_at_unix_ms: 100,
            },
            ActiveSpecializationRowView {
                specialization_id: "sp2".into(),
                target_id: "t-b".into(),
                target_kind: "gc".into(),
                optimization_class: "opt".into(),
                latency_reduction_millionths: 200_000,
                throughput_increase_millionths: 100_000,
                proof_input_ids: vec![],
                transformation_ref: "ref".into(),
                receipt_ref: "ref".into(),
                activated_at_unix_ms: 200,
            },
        ],
        ..Default::default()
    };
    let view = ProofSpecializationLineageDashboardView::from_partial(partial);
    let filter = ProofSpecializationDashboardFilter {
        target_id: Some("t-a".into()),
        ..Default::default()
    };
    let filtered = view.filtered(&filter);
    assert_eq!(filtered.active_specializations.len(), 1);
    assert_eq!(filtered.active_specializations[0].target_id, "t-a");
}

// ===========================================================================
// 12. Enum serde round-trips
// ===========================================================================

#[test]
fn adapter_stream_serde_round_trip() {
    let streams = [
        AdapterStream::IncidentReplay,
        AdapterStream::PolicyExplanation,
        AdapterStream::ControlDashboard,
        AdapterStream::ControlPlaneInvariantsDashboard,
        AdapterStream::FlowDecisionDashboard,
        AdapterStream::CapabilityDeltaDashboard,
        AdapterStream::ReplacementProgressDashboard,
        AdapterStream::ProofSpecializationLineageDashboard,
    ];
    for s in streams {
        let json = serde_json::to_string(&s).unwrap();
        let back: AdapterStream = serde_json::from_str(&json).unwrap();
        assert_eq!(back, s);
    }
}

#[test]
fn update_kind_serde_round_trip() {
    for k in [
        UpdateKind::Snapshot,
        UpdateKind::Delta,
        UpdateKind::Heartbeat,
    ] {
        let json = serde_json::to_string(&k).unwrap();
        let back: UpdateKind = serde_json::from_str(&json).unwrap();
        assert_eq!(back, k);
    }
}

#[test]
fn replay_status_serde_round_trip() {
    for s in [
        ReplayStatus::Running,
        ReplayStatus::Complete,
        ReplayStatus::Failed,
        ReplayStatus::NoEvents,
    ] {
        let json = serde_json::to_string(&s).unwrap();
        let back: ReplayStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(back, s);
    }
}

#[test]
fn decision_outcome_kind_serde_round_trip() {
    for k in [
        DecisionOutcomeKind::Allow,
        DecisionOutcomeKind::Deny,
        DecisionOutcomeKind::Fallback,
    ] {
        let json = serde_json::to_string(&k).unwrap();
        let back: DecisionOutcomeKind = serde_json::from_str(&json).unwrap();
        assert_eq!(back, k);
    }
}

#[test]
fn obligation_state_serde_round_trip() {
    for s in [
        ObligationState::Open,
        ObligationState::Fulfilled,
        ObligationState::Failed,
    ] {
        let json = serde_json::to_string(&s).unwrap();
        let back: ObligationState = serde_json::from_str(&json).unwrap();
        assert_eq!(back, s);
    }
}

#[test]
fn cancellation_kind_serde_round_trip() {
    for k in [
        CancellationKind::Unload,
        CancellationKind::Quarantine,
        CancellationKind::Suspend,
        CancellationKind::Terminate,
        CancellationKind::Revocation,
    ] {
        let json = serde_json::to_string(&k).unwrap();
        let back: CancellationKind = serde_json::from_str(&json).unwrap();
        assert_eq!(back, k);
    }
}

#[test]
fn dashboard_severity_serde_round_trip() {
    for s in [
        DashboardSeverity::Info,
        DashboardSeverity::Warning,
        DashboardSeverity::Critical,
    ] {
        let json = serde_json::to_string(&s).unwrap();
        let back: DashboardSeverity = serde_json::from_str(&json).unwrap();
        assert_eq!(back, s);
    }
}

#[test]
fn flow_sensitivity_level_serde_round_trip() {
    for s in [
        FlowSensitivityLevel::Low,
        FlowSensitivityLevel::Medium,
        FlowSensitivityLevel::High,
        FlowSensitivityLevel::Critical,
    ] {
        let json = serde_json::to_string(&s).unwrap();
        let back: FlowSensitivityLevel = serde_json::from_str(&json).unwrap();
        assert_eq!(back, s);
    }
}

#[test]
fn replacement_risk_level_serde_round_trip() {
    for r in [
        ReplacementRiskLevel::Low,
        ReplacementRiskLevel::Medium,
        ReplacementRiskLevel::High,
    ] {
        let json = serde_json::to_string(&r).unwrap();
        let back: ReplacementRiskLevel = serde_json::from_str(&json).unwrap();
        assert_eq!(back, r);
    }
}

#[test]
fn proof_inventory_kind_serde_round_trip() {
    for k in [
        ProofInventoryKind::CapabilityWitness,
        ProofInventoryKind::FlowProof,
        ProofInventoryKind::ReplayMotif,
    ] {
        let json = serde_json::to_string(&k).unwrap();
        let back: ProofInventoryKind = serde_json::from_str(&json).unwrap();
        assert_eq!(back, k);
    }
}

#[test]
fn proof_validity_status_serde_round_trip() {
    for s in [
        ProofValidityStatus::Valid,
        ProofValidityStatus::ExpiringSoon,
        ProofValidityStatus::Expired,
        ProofValidityStatus::Revoked,
    ] {
        let json = serde_json::to_string(&s).unwrap();
        let back: ProofValidityStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(back, s);
    }
}

#[test]
fn override_review_status_serde_round_trip() {
    for s in [
        OverrideReviewStatus::Pending,
        OverrideReviewStatus::Approved,
        OverrideReviewStatus::Rejected,
        OverrideReviewStatus::Waived,
    ] {
        let json = serde_json::to_string(&s).unwrap();
        let back: OverrideReviewStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(back, s);
    }
}

#[test]
fn grant_expiry_status_serde_round_trip() {
    for s in [
        GrantExpiryStatus::Active,
        GrantExpiryStatus::ExpiringSoon,
        GrantExpiryStatus::Expired,
        GrantExpiryStatus::NotApplicable,
    ] {
        let json = serde_json::to_string(&s).unwrap();
        let back: GrantExpiryStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(back, s);
    }
}

#[test]
fn recovery_status_serde_round_trip() {
    for s in [
        RecoveryStatus::Recovering,
        RecoveryStatus::Recovered,
        RecoveryStatus::Waived,
    ] {
        let json = serde_json::to_string(&s).unwrap();
        let back: RecoveryStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(back, s);
    }
}

#[test]
fn schema_compatibility_status_serde_round_trip() {
    for s in [
        SchemaCompatibilityStatus::Unknown,
        SchemaCompatibilityStatus::Compatible,
        SchemaCompatibilityStatus::NeedsMigration,
        SchemaCompatibilityStatus::Incompatible,
    ] {
        let json = serde_json::to_string(&s).unwrap();
        let back: SchemaCompatibilityStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(back, s);
    }
}

#[test]
fn rollback_status_serde_round_trip() {
    for s in [
        RollbackStatus::Investigating,
        RollbackStatus::Resolved,
        RollbackStatus::Waived,
    ] {
        let json = serde_json::to_string(&s).unwrap();
        let back: RollbackStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(back, s);
    }
}

#[test]
fn confinement_status_serde_round_trip() {
    for s in [
        ConfinementStatus::Full,
        ConfinementStatus::Partial,
        ConfinementStatus::Degraded,
    ] {
        let json = serde_json::to_string(&s).unwrap();
        let back: ConfinementStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(back, s);
    }
}

#[test]
fn declassification_outcome_serde_round_trip() {
    for s in [
        DeclassificationOutcome::Approved,
        DeclassificationOutcome::Denied,
    ] {
        let json = serde_json::to_string(&s).unwrap();
        let back: DeclassificationOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(back, s);
    }
}

#[test]
fn replay_health_status_serde_round_trip() {
    for s in [
        ReplayHealthStatus::Pass,
        ReplayHealthStatus::Fail,
        ReplayHealthStatus::Unknown,
    ] {
        let json = serde_json::to_string(&s).unwrap();
        let back: ReplayHealthStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(back, s);
    }
}

#[test]
fn threshold_comparator_serde_round_trip() {
    for c in [
        ThresholdComparator::GreaterThan,
        ThresholdComparator::GreaterOrEqual,
        ThresholdComparator::LessThan,
        ThresholdComparator::LessOrEqual,
        ThresholdComparator::Equal,
    ] {
        let json = serde_json::to_string(&c).unwrap();
        let back: ThresholdComparator = serde_json::from_str(&json).unwrap();
        assert_eq!(back, c);
    }
}

#[test]
fn dashboard_alert_metric_serde_round_trip() {
    for m in [
        DashboardAlertMetric::ObligationFailureRateMillionths,
        DashboardAlertMetric::ReplayDivergenceCount,
        DashboardAlertMetric::SafeModeActivationCount,
        DashboardAlertMetric::CancellationEventCount,
        DashboardAlertMetric::FallbackActivationCount,
    ] {
        let json = serde_json::to_string(&m).unwrap();
        let back: DashboardAlertMetric = serde_json::from_str(&json).unwrap();
        assert_eq!(back, m);
    }
}

#[test]
fn specialization_fallback_reason_serde_round_trip() {
    for r in [
        SpecializationFallbackReason::ProofUnavailable,
        SpecializationFallbackReason::ProofExpired,
        SpecializationFallbackReason::ProofRevoked,
        SpecializationFallbackReason::ValidationFailed,
    ] {
        let json = serde_json::to_string(&r).unwrap();
        let back: SpecializationFallbackReason = serde_json::from_str(&json).unwrap();
        assert_eq!(back, r);
    }
}

#[test]
fn invalidation_reason_serde_round_trip() {
    for r in [
        ProofSpecializationInvalidationReason::EpochChange,
        ProofSpecializationInvalidationReason::ProofExpired,
        ProofSpecializationInvalidationReason::ProofRevoked,
    ] {
        let json = serde_json::to_string(&r).unwrap();
        let back: ProofSpecializationInvalidationReason = serde_json::from_str(&json).unwrap();
        assert_eq!(back, r);
    }
}

// ===========================================================================
// 13. Complex serde round-trips (full dashboard payloads)
// ===========================================================================

#[test]
fn adapter_envelope_serde_round_trip() {
    let view = IncidentReplayView::snapshot(
        "t1",
        "scen",
        vec![ReplayEventView::new(0, "comp", "ev", "ok", 100)],
    );
    let payload = FrankentuiViewPayload::IncidentReplay(view);
    let env = AdapterEnvelope::new(
        "t1",
        1000,
        AdapterStream::IncidentReplay,
        UpdateKind::Snapshot,
        payload,
    )
    .with_decision_context("d1", "p1");
    let json = serde_json::to_string(&env).unwrap();
    let back: AdapterEnvelope = serde_json::from_str(&json).unwrap();
    assert_eq!(back.trace_id, "t1");
    assert_eq!(back.decision_id.as_deref(), Some("d1"));
}

#[test]
fn control_dashboard_serde_round_trip() {
    let partial = ControlDashboardPartial {
        cluster: "us-east".into(),
        zone: "z1".into(),
        security_epoch: Some(5),
        runtime_mode: "prod".into(),
        metrics: vec![],
        extension_rows: vec![],
        incident_counts: BTreeMap::new(),
    };
    let view = ControlDashboardView::from_partial(partial);
    let json = serde_json::to_string(&view).unwrap();
    let back: ControlDashboardView = serde_json::from_str(&json).unwrap();
    assert_eq!(back.cluster, "us-east");
    assert_eq!(back.security_epoch, 5);
}

#[test]
fn cpid_serde_round_trip() {
    let partial = ControlPlaneInvariantsPartial {
        cluster: "cluster-a".into(),
        zone: "zone-1".into(),
        evidence_stream: vec![sample_evidence_entry("t1", DecisionOutcomeKind::Allow, 100)],
        obligation_rows: vec![sample_obligation_row("ob1", ObligationState::Open)],
        ..Default::default()
    };
    let view = ControlPlaneInvariantsDashboardView::from_partial(partial);
    let json = serde_json::to_string(&view).unwrap();
    let back: ControlPlaneInvariantsDashboardView = serde_json::from_str(&json).unwrap();
    assert_eq!(back.cluster, "cluster-a");
    assert_eq!(back.evidence_stream.len(), 1);
}

#[test]
fn replacement_progress_serde_round_trip() {
    let partial = ReplacementProgressPartial {
        cluster: "c1".into(),
        zone: "z1".into(),
        slot_status_overview: vec![sample_slot_row("s1", "parser", "native")],
        ..Default::default()
    };
    let view = ReplacementProgressDashboardView::from_partial(partial);
    let json = serde_json::to_string(&view).unwrap();
    let back: ReplacementProgressDashboardView = serde_json::from_str(&json).unwrap();
    assert_eq!(back.cluster, "c1");
    assert_eq!(back.slot_status_overview.len(), 1);
}

// ===========================================================================
// 14. Default trait implementations
// ===========================================================================

#[test]
fn dashboard_severity_default_is_info() {
    assert_eq!(DashboardSeverity::default(), DashboardSeverity::Info);
}

#[test]
fn replay_health_status_default_is_unknown() {
    assert_eq!(ReplayHealthStatus::default(), ReplayHealthStatus::Unknown);
}

#[test]
fn recovery_status_default_is_recovering() {
    assert_eq!(RecoveryStatus::default(), RecoveryStatus::Recovering);
}

#[test]
fn schema_compatibility_default_is_unknown() {
    assert_eq!(
        SchemaCompatibilityStatus::default(),
        SchemaCompatibilityStatus::Unknown
    );
}

#[test]
fn override_review_status_default_is_pending() {
    assert_eq!(
        OverrideReviewStatus::default(),
        OverrideReviewStatus::Pending
    );
}

#[test]
fn grant_expiry_status_default_is_active() {
    assert_eq!(GrantExpiryStatus::default(), GrantExpiryStatus::Active);
}

#[test]
fn flow_sensitivity_level_default_is_low() {
    assert_eq!(FlowSensitivityLevel::default(), FlowSensitivityLevel::Low);
}

#[test]
fn proof_validity_status_default_is_valid() {
    assert_eq!(ProofValidityStatus::default(), ProofValidityStatus::Valid);
}

// ===========================================================================
// 15. Dashboard refresh policy normalization
// ===========================================================================

#[test]
fn refresh_policy_default_values() {
    let policy = DashboardRefreshPolicy::default();
    assert_eq!(policy.evidence_stream_refresh_secs, 5);
    assert_eq!(policy.aggregate_refresh_secs, 60);
}

// ===========================================================================
// 16. Region lifecycle auto-computation
// ===========================================================================

#[test]
fn cpid_auto_summarizes_region_lifecycle() {
    let partial = ControlPlaneInvariantsPartial {
        region_rows: vec![
            RegionLifecycleRowView {
                region_id: "r1".into(),
                is_active: true,
                active_extensions: 3,
                created_at_unix_ms: 100,
                closed_at_unix_ms: None,
                quiescent_close_time_ms: None,
            },
            RegionLifecycleRowView {
                region_id: "r2".into(),
                is_active: false,
                active_extensions: 0,
                created_at_unix_ms: 50,
                closed_at_unix_ms: Some(200),
                quiescent_close_time_ms: Some(10),
            },
            RegionLifecycleRowView {
                region_id: "r3".into(),
                is_active: false,
                active_extensions: 0,
                created_at_unix_ms: 60,
                closed_at_unix_ms: Some(300),
                quiescent_close_time_ms: Some(20),
            },
        ],
        ..Default::default()
    };
    let view = ControlPlaneInvariantsDashboardView::from_partial(partial);
    assert_eq!(view.region_lifecycle.active_region_count, 1);
}

// ===========================================================================
// 17. Cancellation events sorted
// ===========================================================================

#[test]
fn cpid_cancellation_events_sorted_by_timestamp() {
    let partial = ControlPlaneInvariantsPartial {
        cancellation_events: vec![
            CancellationEventView {
                extension_id: "ext-a".into(),
                region_id: "r1".into(),
                cancellation_kind: CancellationKind::Quarantine,
                severity: DashboardSeverity::Critical,
                detail: "quarantined".into(),
                timestamp_unix_ms: 300,
            },
            CancellationEventView {
                extension_id: "ext-b".into(),
                region_id: "r2".into(),
                cancellation_kind: CancellationKind::Unload,
                severity: DashboardSeverity::Info,
                detail: "unloaded".into(),
                timestamp_unix_ms: 100,
            },
        ],
        ..Default::default()
    };
    let view = ControlPlaneInvariantsDashboardView::from_partial(partial);
    assert_eq!(view.cancellation_events[0].timestamp_unix_ms, 100);
    assert_eq!(view.cancellation_events[1].timestamp_unix_ms, 300);
}

// ===========================================================================
// 18. Safe mode activations sorted
// ===========================================================================

#[test]
fn cpid_safe_mode_activations_sorted() {
    let partial = ControlPlaneInvariantsPartial {
        safe_mode_activations: vec![
            SafeModeActivationView {
                activation_id: "act-2".into(),
                activation_type: "manual".into(),
                extension_id: "ext-1".into(),
                region_id: "r1".into(),
                severity: DashboardSeverity::Critical,
                recovery_status: RecoveryStatus::Recovering,
                activated_at_unix_ms: 500,
                recovered_at_unix_ms: None,
            },
            SafeModeActivationView {
                activation_id: "act-1".into(),
                activation_type: "auto".into(),
                extension_id: "ext-2".into(),
                region_id: "r2".into(),
                severity: DashboardSeverity::Warning,
                recovery_status: RecoveryStatus::Recovered,
                activated_at_unix_ms: 100,
                recovered_at_unix_ms: Some(200),
            },
        ],
        ..Default::default()
    };
    let view = ControlPlaneInvariantsDashboardView::from_partial(partial);
    assert_eq!(view.safe_mode_activations[0].activated_at_unix_ms, 100);
    assert_eq!(view.safe_mode_activations[1].activated_at_unix_ms, 500);
}

// ===========================================================================
// 19. Rollback events sorted
// ===========================================================================

#[test]
fn replacement_rollback_events_sorted() {
    let partial = ReplacementProgressPartial {
        rollback_events: vec![
            RollbackEventView {
                slot_id: "s1".into(),
                receipt_id: "r2".into(),
                reason: "crash".into(),
                status: RollbackStatus::Investigating,
                occurred_at_unix_ms: 300,
                lineage_ref: "ref".into(),
                evidence_ref: "ref".into(),
            },
            RollbackEventView {
                slot_id: "s1".into(),
                receipt_id: "r1".into(),
                reason: "perf".into(),
                status: RollbackStatus::Resolved,
                occurred_at_unix_ms: 100,
                lineage_ref: "ref".into(),
                evidence_ref: "ref".into(),
            },
        ],
        ..Default::default()
    };
    let view = ReplacementProgressDashboardView::from_partial(partial);
    assert_eq!(view.rollback_events[0].occurred_at_unix_ms, 100);
    assert_eq!(view.rollback_events[1].occurred_at_unix_ms, 300);
}

// ===========================================================================
// 20. Coverage trend clamping
// ===========================================================================

#[test]
fn coverage_trend_point_clamped() {
    let partial = ReplacementProgressPartial {
        native_coverage_history: vec![CoverageTrendPoint {
            timestamp_unix_ms: 100,
            native_coverage_millionths: 2_000_000, // above max
        }],
        ..Default::default()
    };
    let view = ReplacementProgressDashboardView::from_partial(partial);
    // Coverage in trend should be clamped to 1_000_000
    if !view.native_coverage.trend.is_empty() {
        assert!(view.native_coverage.trend[0].native_coverage_millionths <= 1_000_000);
    }
}

// ===========================================================================
// 21. CapabilityDelta replay join construction
// ===========================================================================

#[test]
fn capability_delta_from_replay_join_empty() {
    let partial = CapabilityDeltaReplayJoinPartial::default();
    let view = CapabilityDeltaDashboardView::from_replay_join_partial(partial);
    assert_eq!(view.cluster, "unknown");
    assert!(view.current_capability_rows.is_empty());
}

// ===========================================================================
// 22. All payload variants serde
// ===========================================================================

#[test]
fn payload_incident_replay_serde() {
    let view = IncidentReplayView::snapshot("t", "s", vec![]);
    let payload = FrankentuiViewPayload::IncidentReplay(view);
    let json = serde_json::to_string(&payload).unwrap();
    let back: FrankentuiViewPayload = serde_json::from_str(&json).unwrap();
    if let FrankentuiViewPayload::IncidentReplay(v) = back {
        assert_eq!(v.trace_id, "t");
    } else {
        panic!("wrong variant");
    }
}

#[test]
fn payload_policy_explanation_serde() {
    let card = PolicyExplanationCardView::from_partial(PolicyExplanationPartial {
        decision_id: "d".into(),
        policy_id: "p".into(),
        selected_action: "allow".into(),
        ..Default::default()
    });
    let payload = FrankentuiViewPayload::PolicyExplanation(card);
    let json = serde_json::to_string(&payload).unwrap();
    let back: FrankentuiViewPayload = serde_json::from_str(&json).unwrap();
    assert!(matches!(back, FrankentuiViewPayload::PolicyExplanation(_)));
}

#[test]
fn payload_control_dashboard_serde() {
    let view = ControlDashboardView::from_partial(ControlDashboardPartial::default());
    let payload = FrankentuiViewPayload::ControlDashboard(view);
    let json = serde_json::to_string(&payload).unwrap();
    let back: FrankentuiViewPayload = serde_json::from_str(&json).unwrap();
    assert!(matches!(back, FrankentuiViewPayload::ControlDashboard(_)));
}

// ===========================================================================
// 23. Obligation rows sorted by obligation_id
// ===========================================================================

#[test]
fn cpid_obligation_rows_sorted() {
    let partial = ControlPlaneInvariantsPartial {
        obligation_rows: vec![
            sample_obligation_row("ob-c", ObligationState::Open),
            sample_obligation_row("ob-a", ObligationState::Fulfilled),
            sample_obligation_row("ob-b", ObligationState::Failed),
        ],
        ..Default::default()
    };
    let view = ControlPlaneInvariantsDashboardView::from_partial(partial);
    let ids: Vec<_> = view
        .obligation_rows
        .iter()
        .map(|r| r.obligation_id.as_str())
        .collect();
    assert_eq!(ids, vec!["ob-a", "ob-b", "ob-c"]);
}

// ===========================================================================
// 24. Confinement proofs
// ===========================================================================

#[test]
fn flow_decision_confinement_proof_sorted() {
    let partial = FlowDecisionPartial {
        confinement_proofs: vec![
            ConfinementProofView {
                extension_id: "ext-b".into(),
                status: ConfinementStatus::Full,
                covered_flow_count: 5,
                uncovered_flow_count: 0,
                proof_rows: vec![],
                uncovered_flow_refs: vec![],
            },
            ConfinementProofView {
                extension_id: "ext-a".into(),
                status: ConfinementStatus::Partial,
                covered_flow_count: 3,
                uncovered_flow_count: 2,
                proof_rows: vec![FlowProofCoverageView {
                    proof_id: "p1".into(),
                    source_label: "secret".into(),
                    sink_clearance: "public".into(),
                    covered: true,
                    proof_ref: "ref".into(),
                }],
                uncovered_flow_refs: vec!["flow-1".into()],
            },
        ],
        ..Default::default()
    };
    let view = FlowDecisionDashboardView::from_partial(partial);
    assert_eq!(view.confinement_proofs[0].extension_id, "ext-a");
    assert_eq!(view.confinement_proofs[1].extension_id, "ext-b");
}

// ===========================================================================
// 25. Declassification history sorted by decided_at
// ===========================================================================

#[test]
fn flow_decision_declassification_sorted() {
    let partial = FlowDecisionPartial {
        declassification_history: vec![
            DeclassificationDecisionView {
                decision_id: "d2".into(),
                extension_id: "ext-a".into(),
                source_label: "secret".into(),
                sink_clearance: "public".into(),
                sensitivity: FlowSensitivityLevel::High,
                outcome: DeclassificationOutcome::Approved,
                policy_id: "p1".into(),
                loss_assessment_summary: "low risk".into(),
                rationale: "approved".into(),
                receipt_ref: "ref".into(),
                replay_ref: "ref".into(),
                decided_at_unix_ms: 300,
            },
            DeclassificationDecisionView {
                decision_id: "d1".into(),
                extension_id: "ext-b".into(),
                source_label: "internal".into(),
                sink_clearance: "external".into(),
                sensitivity: FlowSensitivityLevel::Medium,
                outcome: DeclassificationOutcome::Denied,
                policy_id: "p2".into(),
                loss_assessment_summary: "high risk".into(),
                rationale: "denied".into(),
                receipt_ref: "ref".into(),
                replay_ref: "ref".into(),
                decided_at_unix_ms: 100,
            },
        ],
        ..Default::default()
    };
    let view = FlowDecisionDashboardView::from_partial(partial);
    assert_eq!(view.declassification_history[0].decided_at_unix_ms, 100);
    assert_eq!(view.declassification_history[1].decided_at_unix_ms, 300);
}

// ===========================================================================
// 26. Escrow events sorted by timestamp_ns
// ===========================================================================

#[test]
fn capability_delta_escrow_events_sorted() {
    let partial = CapabilityDeltaPartial {
        escrow_event_feed: vec![
            CapabilityDeltaEscrowEventView {
                receipt_id: "r2".into(),
                extension_id: "ext-a".into(),
                capability: Some("write".into()),
                decision_kind: "grant".into(),
                outcome: "success".into(),
                trace_id: "t1".into(),
                decision_id: "d1".into(),
                policy_id: "p1".into(),
                error_code: None,
                timestamp_ns: 300,
                receipt_ref: "ref".into(),
                replay_ref: "ref".into(),
            },
            CapabilityDeltaEscrowEventView {
                receipt_id: "r1".into(),
                extension_id: "ext-b".into(),
                capability: None,
                decision_kind: "revoke".into(),
                outcome: "success".into(),
                trace_id: "t2".into(),
                decision_id: "d2".into(),
                policy_id: "p2".into(),
                error_code: Some("E001".into()),
                timestamp_ns: 100,
                receipt_ref: "ref".into(),
                replay_ref: "ref".into(),
            },
        ],
        ..Default::default()
    };
    let view = CapabilityDeltaDashboardView::from_partial(partial);
    assert_eq!(view.escrow_event_feed[0].timestamp_ns, 100);
    assert_eq!(view.escrow_event_feed[1].timestamp_ns, 300);
}

// ===========================================================================
// 27. Override rationale rows
// ===========================================================================

#[test]
fn capability_delta_override_rationale_rows_sorted() {
    let partial = CapabilityDeltaPartial {
        override_rationale_rows: vec![
            OverrideRationaleView {
                override_id: "ov2".into(),
                extension_id: "ext-a".into(),
                capability: Some("write".into()),
                rationale: "business need".into(),
                signed_justification_ref: "ref".into(),
                review_status: OverrideReviewStatus::Pending,
                grant_expiry_status: GrantExpiryStatus::Active,
                requested_at_unix_ms: 500,
                reviewed_at_unix_ms: None,
                expires_at_unix_ms: None,
                receipt_ref: "ref".into(),
                replay_ref: "ref".into(),
            },
            OverrideRationaleView {
                override_id: "ov1".into(),
                extension_id: "ext-b".into(),
                capability: None,
                rationale: "approved override".into(),
                signed_justification_ref: "ref".into(),
                review_status: OverrideReviewStatus::Approved,
                grant_expiry_status: GrantExpiryStatus::ExpiringSoon,
                requested_at_unix_ms: 100,
                reviewed_at_unix_ms: Some(200),
                expires_at_unix_ms: Some(1000),
                receipt_ref: "ref".into(),
                replay_ref: "ref".into(),
            },
        ],
        ..Default::default()
    };
    let view = CapabilityDeltaDashboardView::from_partial(partial);
    assert_eq!(view.override_rationale_rows[0].requested_at_unix_ms, 100);
    assert_eq!(view.override_rationale_rows[1].requested_at_unix_ms, 500);
}

// ===========================================================================
// 28. Batch review queue sorted by pending count DESC
// ===========================================================================

#[test]
fn capability_delta_batch_review_queue_sorted() {
    let partial = CapabilityDeltaPartial {
        batch_review_queue: vec![
            CapabilityPromotionBatchReviewView {
                batch_id: "b-low".into(),
                extension_ids: vec!["ext-a".into()],
                witness_ids: vec!["w1".into()],
                pending_review_count: 1,
                generated_at_unix_ms: 100,
                workflow_ref: "ref".into(),
            },
            CapabilityPromotionBatchReviewView {
                batch_id: "b-high".into(),
                extension_ids: vec!["ext-b".into(), "ext-c".into()],
                witness_ids: vec!["w2".into()],
                pending_review_count: 5,
                generated_at_unix_ms: 200,
                workflow_ref: "ref".into(),
            },
        ],
        ..Default::default()
    };
    let view = CapabilityDeltaDashboardView::from_partial(partial);
    assert_eq!(view.batch_review_queue[0].pending_review_count, 5);
    assert_eq!(view.batch_review_queue[1].pending_review_count, 1);
}

// ===========================================================================
// 29. Specialization fallback events sorted
// ===========================================================================

#[test]
fn proof_specialization_fallback_events_sorted() {
    let partial = ProofSpecializationLineagePartial {
        fallback_events: vec![
            SpecializationFallbackEventView {
                event_id: "e2".into(),
                specialization_id: Some("sp1".into()),
                target_id: "t1".into(),
                reason: SpecializationFallbackReason::ProofExpired,
                reason_detail: "expired".into(),
                unspecialized_path_ref: "ref".into(),
                compilation_ref: "ref".into(),
                occurred_at_unix_ms: 300,
            },
            SpecializationFallbackEventView {
                event_id: "e1".into(),
                specialization_id: None,
                target_id: "t2".into(),
                reason: SpecializationFallbackReason::ProofUnavailable,
                reason_detail: "no proof".into(),
                unspecialized_path_ref: "ref".into(),
                compilation_ref: "ref".into(),
                occurred_at_unix_ms: 100,
            },
        ],
        ..Default::default()
    };
    let view = ProofSpecializationLineageDashboardView::from_partial(partial);
    assert_eq!(view.fallback_events[0].occurred_at_unix_ms, 100);
    assert_eq!(view.fallback_events[1].occurred_at_unix_ms, 300);
}

// ===========================================================================
// 30. WitnessReplayJoinRow → CapabilityDelta conversion (empty case)
// ===========================================================================

#[test]
fn capability_delta_replay_join_empty_with_manifest() {
    let mut declared = BTreeMap::new();
    declared.insert(
        "ext-a".to_string(),
        vec!["read".to_string(), "write".to_string()],
    );

    let partial = CapabilityDeltaReplayJoinPartial {
        cluster: "c1".into(),
        zone: "z1".into(),
        manifest_declared_capabilities: declared,
        ..Default::default()
    };
    let view = CapabilityDeltaDashboardView::from_replay_join_partial(partial);
    assert_eq!(view.cluster, "c1");
    // No replay rows means no current capability rows
    assert!(view.current_capability_rows.is_empty());
}

// ===========================================================================
// 31. Proposed minimal capability rows
// ===========================================================================

#[test]
fn capability_delta_proposed_minimal_rows() {
    let partial = CapabilityDeltaPartial {
        proposed_minimal_rows: vec![ProposedMinimalCapabilityDeltaRowView {
            extension_id: "ext-a".into(),
            witness_id: "w1".into(),
            current_capabilities: vec!["read".into(), "write".into(), "exec".into()],
            proposed_minimal_capabilities: vec!["read".into(), "write".into()],
            removed_capabilities: vec!["exec".into()],
            capability_justifications: vec![CapabilityJustificationDrillView {
                capability: "read".into(),
                justification: "needed for data access".into(),
                static_analysis_ref: Some("ref1".into()),
                ablation_result_ref: None,
                theorem_check_ref: None,
                operator_attestation_ref: None,
                inherited_ref: None,
                playback_ref: "ref".into(),
            }],
        }],
        ..Default::default()
    };
    let view = CapabilityDeltaDashboardView::from_partial(partial);
    assert_eq!(view.proposed_minimal_rows.len(), 1);
    let row = &view.proposed_minimal_rows[0];
    assert_eq!(row.removed_capabilities, vec!["exec"]);
    assert_eq!(row.capability_justifications.len(), 1);
}

// ===========================================================================
// 32. Multiple alert rules evaluation
// ===========================================================================

#[test]
fn cpid_evaluate_multiple_alert_rules() {
    let partial = ControlPlaneInvariantsPartial {
        replay_health: Some(ReplayHealthPanelView {
            last_run_status: ReplayHealthStatus::Fail,
            divergence_count: 5,
            last_replay_timestamp_unix_ms: Some(1000),
        }),
        safe_mode_activations: vec![
            SafeModeActivationView {
                activation_id: "act1".into(),
                activation_type: "auto".into(),
                extension_id: "ext-1".into(),
                region_id: "r1".into(),
                severity: DashboardSeverity::Critical,
                recovery_status: RecoveryStatus::Recovering,
                activated_at_unix_ms: 100,
                recovered_at_unix_ms: None,
            },
            SafeModeActivationView {
                activation_id: "act2".into(),
                activation_type: "auto".into(),
                extension_id: "ext-2".into(),
                region_id: "r2".into(),
                severity: DashboardSeverity::Warning,
                recovery_status: RecoveryStatus::Recovered,
                activated_at_unix_ms: 200,
                recovered_at_unix_ms: Some(300),
            },
        ],
        ..Default::default()
    };
    let view = ControlPlaneInvariantsDashboardView::from_partial(partial);
    let rules = vec![
        DashboardAlertRule {
            rule_id: "div".into(),
            description: "divergence threshold".into(),
            metric: DashboardAlertMetric::ReplayDivergenceCount,
            comparator: ThresholdComparator::GreaterOrEqual,
            threshold: 3,
            severity: DashboardSeverity::Warning,
        },
        DashboardAlertRule {
            rule_id: "safe".into(),
            description: "safe mode threshold".into(),
            metric: DashboardAlertMetric::SafeModeActivationCount,
            comparator: ThresholdComparator::GreaterOrEqual,
            threshold: 5,
            severity: DashboardSeverity::Critical,
        },
    ];
    let alerts = view.evaluate_alerts(&rules);
    // Divergence is 5 >= 3, should trigger
    let div_triggered = alerts.iter().any(|a| a.rule_id == "div");
    assert!(div_triggered);
    // Safe mode count is 2 < 5, should NOT trigger
    let safe_triggered = alerts.iter().any(|a| a.rule_id == "safe");
    assert!(!safe_triggered);
}

// ===========================================================================
// 33. Filtering by severity
// ===========================================================================

#[test]
fn cpid_filtering_by_severity() {
    let mut entry1 = sample_evidence_entry("t1", DecisionOutcomeKind::Allow, 100);
    entry1.severity = DashboardSeverity::Info;
    let mut entry2 = sample_evidence_entry("t2", DecisionOutcomeKind::Deny, 200);
    entry2.severity = DashboardSeverity::Critical;

    let partial = ControlPlaneInvariantsPartial {
        evidence_stream: vec![entry1, entry2],
        ..Default::default()
    };
    let view = ControlPlaneInvariantsDashboardView::from_partial(partial);
    let filter = ControlPlaneDashboardFilter {
        severity: Some(DashboardSeverity::Critical),
        ..Default::default()
    };
    let filtered = view.filtered(&filter);
    assert_eq!(filtered.evidence_stream.len(), 1);
    assert_eq!(
        filtered.evidence_stream[0].severity,
        DashboardSeverity::Critical
    );
}

// ===========================================================================
// 34. Label map nodes sorted by label_id
// ===========================================================================

#[test]
fn flow_decision_label_map_nodes_sorted() {
    let partial = FlowDecisionPartial {
        label_map: LabelMapView {
            nodes: vec![
                LabelMapNodeView {
                    label_id: "z-label".into(),
                    sensitivity: FlowSensitivityLevel::Low,
                    description: "z".into(),
                    extension_overlays: vec![],
                },
                LabelMapNodeView {
                    label_id: "a-label".into(),
                    sensitivity: FlowSensitivityLevel::High,
                    description: "a".into(),
                    extension_overlays: vec![],
                },
            ],
            edges: vec![],
        },
        ..Default::default()
    };
    let view = FlowDecisionDashboardView::from_partial(partial);
    assert_eq!(view.label_map.nodes[0].label_id, "a-label");
    assert_eq!(view.label_map.nodes[1].label_id, "z-label");
}

// ===========================================================================
// 35. Proof inventory rows sorted by proof_id
// ===========================================================================

#[test]
fn proof_specialization_inventory_sorted() {
    let partial = ProofSpecializationLineagePartial {
        proof_inventory: vec![
            ProofInventoryRowView {
                proof_id: "p-b".into(),
                proof_kind: ProofInventoryKind::FlowProof,
                validity_status: ProofValidityStatus::Valid,
                epoch_id: 1,
                linked_specialization_count: 2,
                enabled_specialization_ids: vec!["sp1".into()],
                proof_ref: "ref".into(),
            },
            ProofInventoryRowView {
                proof_id: "p-a".into(),
                proof_kind: ProofInventoryKind::CapabilityWitness,
                validity_status: ProofValidityStatus::ExpiringSoon,
                epoch_id: 1,
                linked_specialization_count: 1,
                enabled_specialization_ids: vec![],
                proof_ref: "ref".into(),
            },
        ],
        ..Default::default()
    };
    let view = ProofSpecializationLineageDashboardView::from_partial(partial);
    assert_eq!(view.proof_inventory[0].proof_id, "p-a");
    assert_eq!(view.proof_inventory[1].proof_id, "p-b");
}
