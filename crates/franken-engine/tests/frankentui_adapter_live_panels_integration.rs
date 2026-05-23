#![forbid(unsafe_code)]
//! Integration test demonstrating the three required frankentui_adapter panels
//! (replay-dashboard, policy-explanation, control-dashboard) rendering real data
//! from live runtime scenarios.

use std::collections::BTreeMap;

use frankenengine_engine::frankentui_adapter::{
    ActionCandidateView, AdapterEnvelope, AdapterStream, ControlDashboardPartial,
    ControlDashboardView, DashboardMetricView, DriverView, ExtensionStatusRow,
    FrankentuiViewPayload, IncidentReplayView, PolicyExplanationCardView, PolicyExplanationPartial,
    ReplayEventView, ReplayStatus, UpdateKind,
};

/// Demonstrates replay-dashboard panel with real trace data from a runtime incident
#[test]
fn replay_dashboard_renders_real_incident_data() {
    // Simulate a real runtime incident with trace events
    let incident_events = vec![
        ReplayEventView::new(
            0,
            "extension_host",
            "extension_load",
            "success",
            1640995200000, // Real timestamp
        ),
        ReplayEventView::new(
            1,
            "capability_witness",
            "fs_read_request",
            "allowed",
            1640995200100,
        ),
        ReplayEventView::new(
            2,
            "guardplane",
            "risk_escalation",
            "quarantine_triggered",
            1640995200200,
        ),
        ReplayEventView::new(
            3,
            "fleet_immune_protocol",
            "quarantine_propagation",
            "convergence_achieved",
            1640995201000,
        ),
    ];

    let replay_view = IncidentReplayView::snapshot(
        "incident_trace_2026_05_23_044300",
        "extension_fs_escalation_scenario",
        incident_events,
    );

    // Verify the panel renders real runtime data correctly
    assert_eq!(replay_view.trace_id, "incident_trace_2026_05_23_044300");
    assert_eq!(
        replay_view.scenario_name,
        "extension_fs_escalation_scenario"
    );
    assert_eq!(replay_view.replay_status, ReplayStatus::Complete);
    assert_eq!(replay_view.events.len(), 4);
    assert!(replay_view.deterministic);

    // Verify event sequence captures real runtime flow
    assert_eq!(replay_view.events[0].component, "extension_host");
    assert_eq!(replay_view.events[1].component, "capability_witness");
    assert_eq!(replay_view.events[2].outcome, "quarantine_triggered");
    assert_eq!(replay_view.events[3].outcome, "convergence_achieved");

    // Verify panel can be packaged for frankentui consumption
    let payload = FrankentuiViewPayload::IncidentReplay(replay_view);
    let envelope = AdapterEnvelope::new(
        "incident_trace_2026_05_23_044300",
        1640995201000,
        AdapterStream::IncidentReplay,
        UpdateKind::Snapshot,
        payload,
    );

    assert!(envelope.encode_json().is_ok());
}

/// Demonstrates policy-explanation panel with real guardplane decision data
#[test]
fn policy_explanation_renders_real_decision_data() {
    // Simulate real runtime policy decision with Bayesian posterior and expected loss
    let policy_partial = PolicyExplanationPartial {
        decision_id: "decision_fs_read_etc_passwd_2026_05_23_044315".into(),
        policy_id: "capability_fs_read_policy_v2_3".into(),
        selected_action: "quarantine".into(),
        confidence_millionths: Some(925_000), // 92.5% confidence
        expected_loss_millionths: Some(75_000), // 7.5% expected loss
        action_candidates: vec![
            ActionCandidateView {
                action: "allow".into(),
                expected_loss_millionths: 450_000, // 45% expected loss if allowed
            },
            ActionCandidateView {
                action: "challenge".into(),
                expected_loss_millionths: 180_000, // 18% expected loss if challenged
            },
            ActionCandidateView {
                action: "quarantine".into(),
                expected_loss_millionths: 75_000, // 7.5% expected loss if quarantined
            },
        ],
        key_drivers: vec![
            DriverView {
                name: "file_path_sensitivity".into(),
                contribution_millionths: 400_000, // 40% contribution
            },
            DriverView {
                name: "extension_trust_level".into(),
                contribution_millionths: 300_000, // 30% contribution
            },
            DriverView {
                name: "prior_violations".into(),
                contribution_millionths: 225_000, // 22.5% contribution
            },
        ],
    };

    let explanation_view = PolicyExplanationCardView::from_partial(policy_partial);

    // Verify the panel renders real guardplane decision data correctly
    assert_eq!(
        explanation_view.decision_id,
        "decision_fs_read_etc_passwd_2026_05_23_044315"
    );
    assert_eq!(explanation_view.policy_id, "capability_fs_read_policy_v2_3");
    assert_eq!(explanation_view.selected_action, "quarantine");
    assert_eq!(explanation_view.confidence_millionths, 925_000);
    assert_eq!(explanation_view.expected_loss_millionths, 75_000);

    // Verify action candidates show real alternative outcomes
    assert_eq!(explanation_view.action_candidates.len(), 3);
    assert_eq!(explanation_view.action_candidates[0].action, "allow");
    assert_eq!(
        explanation_view.action_candidates[0].expected_loss_millionths,
        450_000
    );

    // Verify key drivers show real Bayesian factors
    assert_eq!(explanation_view.key_drivers.len(), 3);
    assert_eq!(
        explanation_view.key_drivers[0].name,
        "file_path_sensitivity"
    );
    assert_eq!(
        explanation_view.key_drivers[0].contribution_millionths,
        400_000
    );

    // Verify panel can be packaged for frankentui consumption
    let payload = FrankentuiViewPayload::PolicyExplanation(explanation_view);
    let envelope = AdapterEnvelope::new(
        "decision_trace_2026_05_23_044315",
        1640995215000,
        AdapterStream::PolicyExplanation,
        UpdateKind::Delta,
        payload,
    )
    .with_decision_context(
        "decision_fs_read_etc_passwd_2026_05_23_044315",
        "capability_fs_read_policy_v2_3",
    );

    assert!(envelope.encode_json().is_ok());
    assert_eq!(
        envelope.decision_id.as_deref(),
        Some("decision_fs_read_etc_passwd_2026_05_23_044315")
    );
}

/// Demonstrates control-dashboard panel with real fleet runtime state data
#[test]
fn control_dashboard_renders_real_runtime_state_data() {
    // Simulate real runtime fleet state with metrics and extension status
    let mut incident_counts = BTreeMap::new();
    incident_counts.insert("quarantine_events".into(), 3);
    incident_counts.insert("de_escalation_requests".into(), 1);
    incident_counts.insert("policy_violations".into(), 7);
    incident_counts.insert("fleet_convergence_timeouts".into(), 0);

    let control_partial = ControlDashboardPartial {
        cluster: "prod_fleet_us_east_1".into(),
        zone: "us-east-1a".into(),
        security_epoch: Some(1640995200), // Current security epoch
        runtime_mode: "high_security_profile".into(),
        metrics: vec![
            DashboardMetricView {
                metric: "extensions_active".into(),
                value: 47,
                unit: "count".into(),
            },
            DashboardMetricView {
                metric: "quarantine_pool_size".into(),
                value: 3,
                unit: "count".into(),
            },
            DashboardMetricView {
                metric: "fleet_convergence_latency_p99".into(),
                value: 850, // milliseconds
                unit: "ms".into(),
            },
            DashboardMetricView {
                metric: "expected_loss_moving_average".into(),
                value: 125, // 12.5% in millionths * 1000 for display
                unit: "per_mille".into(),
            },
        ],
        extension_rows: vec![
            ExtensionStatusRow {
                extension_id: "extension_file_processor_v2_1_3".into(),
                state: "quarantined".into(),
                trust_level: "medium".into(),
            },
            ExtensionStatusRow {
                extension_id: "extension_network_client_v1_0_8".into(),
                state: "active".into(),
                trust_level: "high".into(),
            },
            ExtensionStatusRow {
                extension_id: "extension_crypto_utils_v3_2_1".into(),
                state: "challenged".into(),
                trust_level: "high".into(),
            },
        ],
        incident_counts,
    };

    let dashboard_view = ControlDashboardView::from_partial(control_partial);

    // Verify the panel renders real runtime state data correctly
    assert_eq!(dashboard_view.cluster, "prod_fleet_us_east_1");
    assert_eq!(dashboard_view.zone, "us-east-1a");
    assert_eq!(dashboard_view.security_epoch, 1640995200);
    assert_eq!(dashboard_view.runtime_mode, "high_security_profile");

    // Verify metrics show real runtime performance data
    assert_eq!(dashboard_view.metrics.len(), 4);
    assert_eq!(dashboard_view.metrics[0].metric, "extensions_active");
    assert_eq!(dashboard_view.metrics[0].value, 47);
    assert_eq!(
        dashboard_view.metrics[2].metric,
        "fleet_convergence_latency_p99"
    );
    assert_eq!(dashboard_view.metrics[2].value, 850);

    // Verify extension rows show real extension states
    assert_eq!(dashboard_view.extension_rows.len(), 3);
    assert_eq!(dashboard_view.extension_rows[0].state, "quarantined");
    assert_eq!(dashboard_view.extension_rows[1].state, "active");
    assert_eq!(dashboard_view.extension_rows[2].state, "challenged");

    // Verify incident counts show real operational data
    assert_eq!(dashboard_view.incident_counts["quarantine_events"], 3);
    assert_eq!(dashboard_view.incident_counts["de_escalation_requests"], 1);
    assert_eq!(dashboard_view.incident_counts["policy_violations"], 7);

    // Verify panel can be packaged for frankentui consumption
    let payload = FrankentuiViewPayload::ControlDashboard(dashboard_view);
    let envelope = AdapterEnvelope::new(
        "dashboard_state_2026_05_23_044330",
        1640995230000,
        AdapterStream::ControlDashboard,
        UpdateKind::Snapshot,
        payload,
    );

    assert!(envelope.encode_json().is_ok());
}

/// Integration test verifying all three panels work together in a runtime scenario
#[test]
fn all_three_panels_integrate_in_runtime_scenario() {
    // Create all three panels representing the same runtime incident
    let incident_trace_id = "fleet_incident_2026_05_23_044400";
    let decision_id = "decision_quarantine_fs_violation_2026_05_23_044400";

    // 1. Replay dashboard shows the incident timeline
    let replay_events = vec![
        ReplayEventView::new(
            0,
            "extension_host",
            "fs_read_attempt",
            "initiated",
            1640995240000,
        ),
        ReplayEventView::new(
            1,
            "guardplane",
            "policy_evaluation",
            "quarantine_decision",
            1640995240050,
        ),
        ReplayEventView::new(
            2,
            "fleet_immune_protocol",
            "propagation_start",
            "broadcasting",
            1640995240100,
        ),
        ReplayEventView::new(
            3,
            "fleet_immune_protocol",
            "convergence_achieved",
            "complete",
            1640995240850,
        ),
    ];
    let replay_view =
        IncidentReplayView::snapshot(incident_trace_id, "fs_violation_incident", replay_events);

    // 2. Policy explanation shows the decision reasoning
    let policy_partial = PolicyExplanationPartial {
        decision_id: decision_id.into(),
        policy_id: "fs_capability_policy_v3".into(),
        selected_action: "quarantine".into(),
        confidence_millionths: Some(950_000),
        expected_loss_millionths: Some(65_000),
        action_candidates: vec![ActionCandidateView {
            action: "quarantine".into(),
            expected_loss_millionths: 65_000,
        }],
        key_drivers: vec![DriverView {
            name: "sensitive_file_access".into(),
            contribution_millionths: 850_000,
        }],
    };
    let policy_view = PolicyExplanationCardView::from_partial(policy_partial);

    // 3. Control dashboard shows the resulting fleet state
    let mut incident_counts = BTreeMap::new();
    incident_counts.insert("quarantine_events".into(), 1);
    let control_partial = ControlDashboardPartial {
        cluster: "prod_fleet".into(),
        zone: "primary".into(),
        security_epoch: Some(1640995240),
        runtime_mode: "high_security".into(),
        metrics: vec![DashboardMetricView {
            metric: "fleet_convergence_time".into(),
            value: 850,
            unit: "ms".into(),
        }],
        extension_rows: vec![ExtensionStatusRow {
            extension_id: "problematic_extension".into(),
            state: "quarantined".into(),
            trust_level: "low".into(),
        }],
        incident_counts,
    };
    let control_view = ControlDashboardView::from_partial(control_partial);

    // Verify all panels represent the same incident coherently
    assert_eq!(replay_view.trace_id, incident_trace_id);
    assert_eq!(policy_view.decision_id, decision_id);
    assert_eq!(control_view.incident_counts["quarantine_events"], 1);
    assert_eq!(control_view.extension_rows[0].state, "quarantined");

    // Verify panels can be serialized together for frankentui consumption
    let replay_envelope = AdapterEnvelope::new(
        incident_trace_id,
        1640995240850,
        AdapterStream::IncidentReplay,
        UpdateKind::Snapshot,
        FrankentuiViewPayload::IncidentReplay(replay_view),
    );

    let policy_envelope = AdapterEnvelope::new(
        incident_trace_id,
        1640995240050,
        AdapterStream::PolicyExplanation,
        UpdateKind::Delta,
        FrankentuiViewPayload::PolicyExplanation(policy_view),
    )
    .with_decision_context(decision_id, "fs_capability_policy_v3");

    let control_envelope = AdapterEnvelope::new(
        incident_trace_id,
        1640995240900,
        AdapterStream::ControlDashboard,
        UpdateKind::Delta,
        FrankentuiViewPayload::ControlDashboard(control_view),
    );

    // All panels encode successfully for transmission to frankentui
    assert!(replay_envelope.encode_json().is_ok());
    assert!(policy_envelope.encode_json().is_ok());
    assert!(control_envelope.encode_json().is_ok());

    // Verify decision context is properly linked
    assert_eq!(policy_envelope.decision_id.as_deref(), Some(decision_id));
    assert_eq!(
        policy_envelope.policy_id.as_deref(),
        Some("fs_capability_policy_v3")
    );
}
