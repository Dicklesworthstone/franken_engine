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

use std::collections::BTreeMap;

use frankenengine_engine::frankentui_adapter::{
    ActionCandidateView, ActiveSpecializationRowView, AdapterEnvelope, AdapterStream,
    BenchmarkTrendPointView, BlockedFlowView, CancellationEventView, CancellationKind,
    CapabilityDeltaDashboardFilter, CapabilityDeltaDashboardView, CapabilityDeltaPartial,
    CapabilityDeltaReplayJoinPartial, ConfinementProofView, ConfinementStatus,
    ControlDashboardPartial, ControlDashboardView, ControlPlaneDashboardFilter,
    ControlPlaneInvariantsDashboardView, ControlPlaneInvariantsPartial, CoverageTrendPoint,
    CurrentCapabilityDeltaRowView, DashboardAlertMetric, DashboardAlertRule, DashboardMetricView,
    DashboardRefreshPolicy, DashboardSeverity, DecisionOutcomeKind, DecisionOutcomesPanelView,
    DeclassificationDecisionView, DeclassificationOutcome, DriverView, EvidenceStreamEntryView,
    FRANKENTUI_ADAPTER_SCHEMA_VERSION, FlowDecisionDashboardFilter, FlowDecisionDashboardView,
    FlowDecisionPartial, FlowProofCoverageView, FlowSensitivityLevel, FrankentuiViewPayload,
    GrantExpiryStatus, IncidentReplayView, LabelMapEdgeView, LabelMapNodeView, LabelMapView,
    ObligationState, ObligationStatusPanelView, ObligationStatusRowView, OverrideReviewStatus,
    PolicyExplanationCardView, PolicyExplanationPartial, ProofInventoryKind, ProofInventoryRowView,
    ProofSpecializationDashboardFilter, ProofSpecializationInvalidationReason,
    ProofSpecializationLineageDashboardView, ProofSpecializationLineagePartial,
    ProofValidityStatus, RecoveryStatus, RegionLifecyclePanelView, RegionLifecycleRowView,
    ReplacementDashboardFilter, ReplacementOpportunityInput, ReplacementProgressDashboardView,
    ReplacementProgressPartial, ReplacementRiskLevel, ReplayEventView, ReplayHealthPanelView,
    ReplayHealthStatus, ReplayStatus, RollbackEventView, RollbackStatus, SafeModeActivationView,
    SchemaCompatibilityStatus, SchemaVersionPanelView, SlotStatusOverviewRow,
    SpecializationFallbackEventView, SpecializationFallbackReason,
    SpecializationInvalidationRowView, ThresholdComparator, UpdateKind,
    build_native_coverage_meter, build_specialization_performance_impact,
    rank_replacement_opportunities,
};

#[test]
fn incident_replay_view_round_trips_for_static_replay() {
    let replay = IncidentReplayView::snapshot(
        "trace-replay-1",
        "credential-exfiltration-drill",
        vec![ReplayEventView::new(
            1,
            "replay_engine",
            "decision_replayed",
            "allow",
            1_700_000_000_000,
        )],
    );

    let envelope = AdapterEnvelope::new(
        "trace-replay-1",
        1_700_000_000_001,
        AdapterStream::IncidentReplay,
        UpdateKind::Snapshot,
        FrankentuiViewPayload::IncidentReplay(replay),
    );

    let encoded = envelope.encode_json().expect("encode");
    let decoded: AdapterEnvelope = serde_json::from_slice(&encoded).expect("decode");
    assert_eq!(decoded.stream, AdapterStream::IncidentReplay);
    assert_eq!(decoded.trace_id, "trace-replay-1");
}

#[test]
fn policy_explanation_view_round_trips_for_card_rendering() {
    let policy = PolicyExplanationCardView::from_partial(PolicyExplanationPartial {
        decision_id: "decision-42".to_string(),
        policy_id: "policy-safe-default".to_string(),
        selected_action: "sandbox".to_string(),
        confidence_millionths: Some(812_000),
        expected_loss_millionths: Some(123_000),
        action_candidates: vec![
            ActionCandidateView {
                action: "allow".to_string(),
                expected_loss_millionths: 410_000,
            },
            ActionCandidateView {
                action: "sandbox".to_string(),
                expected_loss_millionths: 123_000,
            },
        ],
        key_drivers: vec![
            DriverView {
                name: "hostcall_anomaly_rate".to_string(),
                contribution_millionths: 80_000,
            },
            DriverView {
                name: "publisher_revocation_signal".to_string(),
                contribution_millionths: 43_000,
            },
        ],
    });

    let envelope = AdapterEnvelope::new(
        "trace-policy-1",
        1_700_000_000_100,
        AdapterStream::PolicyExplanation,
        UpdateKind::Snapshot,
        FrankentuiViewPayload::PolicyExplanation(policy),
    )
    .with_decision_context("decision-42", "policy-safe-default");

    let encoded = envelope.encode_json().expect("encode");
    let decoded: AdapterEnvelope = serde_json::from_slice(&encoded).expect("decode");
    assert_eq!(decoded.stream, AdapterStream::PolicyExplanation);
    assert_eq!(decoded.decision_id.as_deref(), Some("decision-42"));
    assert_eq!(decoded.policy_id.as_deref(), Some("policy-safe-default"));
}

#[test]
fn control_dashboard_view_supports_delta_updates() {
    let mut incidents = BTreeMap::new();
    incidents.insert("quarantine".to_string(), 2);

    let dashboard = ControlDashboardView::from_partial(ControlDashboardPartial {
        cluster: "prod".to_string(),
        zone: "us-east-1".to_string(),
        security_epoch: Some(9),
        runtime_mode: "secure".to_string(),
        metrics: vec![DashboardMetricView {
            metric: "containment_latency_p95_ms".to_string(),
            value: 84,
            unit: "ms".to_string(),
        }],
        extension_rows: vec![],
        incident_counts: incidents,
    });

    let envelope = AdapterEnvelope::new(
        "trace-dashboard-1",
        1_700_000_000_200,
        AdapterStream::ControlDashboard,
        UpdateKind::Delta,
        FrankentuiViewPayload::ControlDashboard(dashboard),
    );

    let encoded = envelope.encode_json().expect("encode");
    let decoded: AdapterEnvelope = serde_json::from_slice(&encoded).expect("decode");
    assert_eq!(decoded.stream, AdapterStream::ControlDashboard);
    assert_eq!(decoded.update_kind, UpdateKind::Delta);
}

#[test]
fn control_plane_invariants_dashboard_round_trips_with_alerts() {
    let invariants =
        ControlPlaneInvariantsDashboardView::from_partial(ControlPlaneInvariantsPartial {
            cluster: "prod".to_string(),
            zone: "us-central-1".to_string(),
            runtime_mode: "secure".to_string(),
            generated_at_unix_ms: Some(1_700_000_000_400),
            refresh_policy: Some(DashboardRefreshPolicy {
                evidence_stream_refresh_secs: 5,
                aggregate_refresh_secs: 45,
            }),
            evidence_stream_last_updated_unix_ms: Some(1_700_000_000_398),
            aggregates_last_updated_unix_ms: Some(1_700_000_000_380),
            evidence_stream: vec![EvidenceStreamEntryView {
                trace_id: "trace-inv-1".to_string(),
                decision_id: "decision-inv-1".to_string(),
                policy_id: "policy-safe".to_string(),
                action_type: "fallback".to_string(),
                decision_outcome: DecisionOutcomeKind::Fallback,
                expected_loss_millionths: 240_000,
                extension_id: "ext-critical".to_string(),
                region_id: "region-a".to_string(),
                severity: DashboardSeverity::Critical,
                component: "guardplane".to_string(),
                event: "safe_mode_activated".to_string(),
                outcome: "fallback".to_string(),
                error_code: Some("FE-SAFE-001".to_string()),
                timestamp_unix_ms: 1_700_000_000_397,
            }],
            obligation_rows: vec![ObligationStatusRowView {
                obligation_id: "obl-incident-1".to_string(),
                extension_id: "ext-critical".to_string(),
                region_id: "region-a".to_string(),
                state: ObligationState::Failed,
                severity: DashboardSeverity::Critical,
                due_at_unix_ms: 1_700_000_000_800,
                updated_at_unix_ms: 1_700_000_000_398,
                detail: "replay divergence unresolved".to_string(),
            }],
            region_rows: vec![RegionLifecycleRowView {
                region_id: "region-a".to_string(),
                is_active: true,
                active_extensions: 3,
                created_at_unix_ms: 1_700_000_000_000,
                closed_at_unix_ms: None,
                quiescent_close_time_ms: None,
            }],
            cancellation_events: vec![CancellationEventView {
                extension_id: "ext-critical".to_string(),
                region_id: "region-a".to_string(),
                cancellation_kind: CancellationKind::Quarantine,
                severity: DashboardSeverity::Critical,
                detail: "containment escalation".to_string(),
                timestamp_unix_ms: 1_700_000_000_399,
            }],
            replay_health: Some(ReplayHealthPanelView {
                last_run_status: ReplayHealthStatus::Fail,
                divergence_count: 2,
                last_replay_timestamp_unix_ms: Some(1_700_000_000_360),
            }),
            benchmark_points: vec![BenchmarkTrendPointView {
                timestamp_unix_ms: 1_700_000_000_300,
                throughput_tps: 1_900,
                latency_p95_ms: 140,
                memory_peak_mb: 780,
            }],
            throughput_floor_tps: Some(2_000),
            latency_p95_ceiling_ms: Some(120),
            memory_peak_ceiling_mb: Some(750),
            safe_mode_activations: vec![SafeModeActivationView {
                activation_id: "sm-critical-1".to_string(),
                activation_type: "replay_divergence".to_string(),
                extension_id: "ext-critical".to_string(),
                region_id: "region-a".to_string(),
                severity: DashboardSeverity::Critical,
                recovery_status: RecoveryStatus::Recovering,
                activated_at_unix_ms: 1_700_000_000_395,
                recovered_at_unix_ms: None,
            }],
            schema_version: Some(SchemaVersionPanelView {
                evidence_schema_version: 4,
                last_migration_unix_ms: Some(1_699_999_999_500),
                compatibility_status: SchemaCompatibilityStatus::Compatible,
            }),
            alert_rules: vec![DashboardAlertRule {
                rule_id: "alert-fallback-activation".to_string(),
                description: "fallback activations > 0".to_string(),
                metric: DashboardAlertMetric::FallbackActivationCount,
                comparator: ThresholdComparator::GreaterThan,
                threshold: 0,
                severity: DashboardSeverity::Critical,
            }],
            ..Default::default()
        });

    assert!(invariants.meets_refresh_sla());
    assert_eq!(invariants.triggered_alerts().len(), 1);

    let envelope = AdapterEnvelope::new(
        "trace-invariants-1",
        1_700_000_000_401,
        AdapterStream::ControlPlaneInvariantsDashboard,
        UpdateKind::Snapshot,
        FrankentuiViewPayload::ControlPlaneInvariantsDashboard(Box::new(invariants)),
    );

    let encoded = envelope.encode_json().expect("encode");
    let decoded: AdapterEnvelope = serde_json::from_slice(&encoded).expect("decode");
    assert_eq!(
        decoded.stream,
        AdapterStream::ControlPlaneInvariantsDashboard
    );
    match decoded.payload {
        FrankentuiViewPayload::ControlPlaneInvariantsDashboard(view) => {
            assert_eq!(view.evidence_stream.len(), 1);
            assert_eq!(view.obligation_status.failed_count, 1);
            assert_eq!(view.triggered_alerts().len(), 1);
        }
        other => panic!("expected invariants dashboard payload, got {other:?}"),
    }
}

#[test]
fn flow_decision_dashboard_round_trips_with_ifc_views() {
    let flow_dashboard = FlowDecisionDashboardView::from_partial(FlowDecisionPartial {
        cluster: "prod".to_string(),
        zone: "us-west-1".to_string(),
        security_epoch: Some(22),
        generated_at_unix_ms: Some(1_700_000_000_700),
        label_map: LabelMapView {
            nodes: vec![
                LabelMapNodeView {
                    label_id: "pii".to_string(),
                    sensitivity: FlowSensitivityLevel::High,
                    description: "personal data".to_string(),
                    extension_overlays: vec!["ext-a".to_string()],
                },
                LabelMapNodeView {
                    label_id: "public".to_string(),
                    sensitivity: FlowSensitivityLevel::Low,
                    description: "public".to_string(),
                    extension_overlays: vec!["ext-a".to_string(), "ext-b".to_string()],
                },
            ],
            edges: vec![LabelMapEdgeView {
                source_label: "pii".to_string(),
                sink_clearance: "high".to_string(),
                route_policy_id: Some("policy-ifc-1".to_string()),
                route_enabled: true,
            }],
        },
        blocked_flows: vec![BlockedFlowView {
            flow_id: "flow-1".to_string(),
            extension_id: "ext-a".to_string(),
            source_label: "pii".to_string(),
            sink_clearance: "external".to_string(),
            sensitivity: FlowSensitivityLevel::Critical,
            blocked_reason: "sink clearance mismatch".to_string(),
            attempted_exfiltration: true,
            code_path_ref: "src/ext_a/main.ts:90".to_string(),
            extension_context_ref: "frankentui://extension/ext-a".to_string(),
            trace_id: "trace-ifc-1".to_string(),
            decision_id: "decision-ifc-1".to_string(),
            policy_id: "policy-ifc-1".to_string(),
            error_code: Some("FE-IFC-BLOCK".to_string()),
            occurred_at_unix_ms: 1_700_000_000_680,
        }],
        declassification_history: vec![DeclassificationDecisionView {
            decision_id: "decl-1".to_string(),
            extension_id: "ext-a".to_string(),
            source_label: "pii".to_string(),
            sink_clearance: "external".to_string(),
            sensitivity: FlowSensitivityLevel::Critical,
            outcome: DeclassificationOutcome::Denied,
            policy_id: "policy-ifc-1".to_string(),
            loss_assessment_summary: "expected loss too high".to_string(),
            rationale: "deny".to_string(),
            receipt_ref: "frankentui://declassification/decl-1".to_string(),
            replay_ref: "frankentui://replay/decl-1".to_string(),
            decided_at_unix_ms: 1_700_000_000_690,
        }],
        confinement_proofs: vec![ConfinementProofView {
            extension_id: "ext-a".to_string(),
            status: ConfinementStatus::Partial,
            covered_flow_count: 5,
            uncovered_flow_count: 1,
            proof_rows: vec![FlowProofCoverageView {
                proof_id: "proof-1".to_string(),
                source_label: "pii".to_string(),
                sink_clearance: "external".to_string(),
                covered: false,
                proof_ref: "frankentui://proof/proof-1".to_string(),
            }],
            uncovered_flow_refs: vec!["frankentui://flow/flow-1".to_string()],
        }],
        blocked_flow_alert_threshold: Some(1),
        ..Default::default()
    });

    let envelope = AdapterEnvelope::new(
        "trace-flow-dashboard-1",
        1_700_000_000_701,
        AdapterStream::FlowDecisionDashboard,
        UpdateKind::Snapshot,
        FrankentuiViewPayload::FlowDecisionDashboard(flow_dashboard),
    );

    let encoded = envelope.encode_json().expect("encode");
    let decoded: AdapterEnvelope = serde_json::from_slice(&encoded).expect("decode");
    assert_eq!(decoded.stream, AdapterStream::FlowDecisionDashboard);
    match decoded.payload {
        FrankentuiViewPayload::FlowDecisionDashboard(view) => {
            assert_eq!(view.blocked_flows.len(), 1);
            assert_eq!(view.declassification_history.len(), 1);
            assert_eq!(view.confinement_proofs.len(), 1);
            assert!(!view.alert_indicators.is_empty());
        }
        other => panic!("expected flow decision dashboard payload, got {other:?}"),
    }
}

#[test]
fn capability_delta_dashboard_round_trips_with_replay_join_mapping() {
    let extension_id = frankenengine_engine::engine_object_id::EngineObjectId([0x11; 32]);
    let witness_id = frankenengine_engine::engine_object_id::EngineObjectId([0x22; 32]);
    let policy_id = frankenengine_engine::engine_object_id::EngineObjectId([0x33; 32]);
    let witness = frankenengine_engine::capability_witness::CapabilityWitness {
        witness_id: witness_id.clone(),
        schema_version: frankenengine_engine::capability_witness::WitnessSchemaVersion::CURRENT,
        extension_id: extension_id.clone(),
        policy_id: policy_id.clone(),
        lifecycle_state: frankenengine_engine::capability_witness::LifecycleState::Active,
        required_capabilities: std::collections::BTreeSet::from([
            frankenengine_engine::policy_theorem_compiler::Capability::new("fs.read"),
            frankenengine_engine::policy_theorem_compiler::Capability::new("network.fetch"),
        ]),
        denied_capabilities: std::collections::BTreeSet::new(),
        proof_obligations: vec![
            frankenengine_engine::capability_witness::ProofObligation {
                capability: frankenengine_engine::policy_theorem_compiler::Capability::new(
                    "fs.read",
                ),
                kind: frankenengine_engine::capability_witness::ProofKind::StaticAnalysis,
                proof_artifact_id: frankenengine_engine::engine_object_id::EngineObjectId(
                    [0x41; 32],
                ),
                justification: "file read path required".to_string(),
                artifact_hash: frankenengine_engine::hash_tiers::ContentHash::compute(
                    b"proof-static",
                ),
            },
            frankenengine_engine::capability_witness::ProofObligation {
                capability: frankenengine_engine::policy_theorem_compiler::Capability::new(
                    "network.fetch",
                ),
                kind: frankenengine_engine::capability_witness::ProofKind::PolicyTheoremCheck,
                proof_artifact_id: frankenengine_engine::engine_object_id::EngineObjectId(
                    [0x42; 32],
                ),
                justification: "remote fetch route required".to_string(),
                artifact_hash: frankenengine_engine::hash_tiers::ContentHash::compute(
                    b"proof-theorem",
                ),
            },
        ],
        denial_records: vec![],
        confidence: frankenengine_engine::capability_witness::ConfidenceInterval {
            lower_millionths: 800_000,
            upper_millionths: 950_000,
            n_trials: 20,
            n_successes: 18,
        },
        replay_seed: 42,
        transcript_hash: frankenengine_engine::hash_tiers::ContentHash::compute(
            b"witness-transcript",
        ),
        rollback_token: None,
        synthesizer_signature: vec![0xAA; 64],
        promotion_signatures: vec![vec![0xBB; 64]],
        epoch: frankenengine_engine::security_epoch::SecurityEpoch::from_raw(44),
        timestamp_ns: 1_700_000_005_000_000_000,
        content_hash: frankenengine_engine::hash_tiers::ContentHash::compute(b"witness-content"),
        metadata: BTreeMap::new(),
    };

    let replay_row = frankenengine_engine::capability_witness::WitnessReplayJoinRow {
        witness: frankenengine_engine::capability_witness::WitnessIndexRecord {
            witness_id,
            extension_id: extension_id.clone(),
            policy_id,
            epoch: frankenengine_engine::security_epoch::SecurityEpoch::from_raw(44),
            lifecycle_state: frankenengine_engine::capability_witness::LifecycleState::Active,
            promotion_timestamp_ns: 1_700_000_004_900_000_000,
            content_hash: frankenengine_engine::hash_tiers::ContentHash::compute(b"index-content"),
            witness,
        },
        receipts: vec![
            frankenengine_engine::capability_witness::CapabilityEscrowReceiptRecord {
                receipt_id: "escrow-1".to_string(),
                extension_id: extension_id.clone(),
                capability: Some(
                    frankenengine_engine::policy_theorem_compiler::Capability::new("network.fetch"),
                ),
                decision_kind: "challenge".to_string(),
                outcome: "pending".to_string(),
                timestamp_ns: 1_700_000_005_100_000_000,
                trace_id: "trace-escrow-1".to_string(),
                decision_id: "decision-escrow-1".to_string(),
                policy_id: "policy-escrow".to_string(),
                error_code: None,
            },
            frankenengine_engine::capability_witness::CapabilityEscrowReceiptRecord {
                receipt_id: "escrow-2".to_string(),
                extension_id,
                capability: Some(
                    frankenengine_engine::policy_theorem_compiler::Capability::new("network.fetch"),
                ),
                decision_kind: "operator_override".to_string(),
                outcome: "approved".to_string(),
                timestamp_ns: 1_700_000_005_200_000_000,
                trace_id: "trace-escrow-2".to_string(),
                decision_id: "decision-escrow-2".to_string(),
                policy_id: "policy-escrow".to_string(),
                error_code: None,
            },
        ],
    };

    let dashboard =
        CapabilityDeltaDashboardView::from_replay_join_partial(CapabilityDeltaReplayJoinPartial {
            cluster: "prod".to_string(),
            zone: "us-east-1".to_string(),
            security_epoch: Some(44),
            generated_at_unix_ms: Some(1_700_000_005_300),
            replay_rows: vec![replay_row],
            manifest_declared_capabilities: BTreeMap::from([(
                "1111111111111111111111111111111111111111111111111111111111111111".to_string(),
                vec!["fs.read".to_string()],
            )]),
            high_escrow_alert_threshold: Some(2),
            pending_override_alert_threshold: Some(1),
            ..Default::default()
        });

    assert_eq!(dashboard.current_capability_rows.len(), 1);
    assert_eq!(
        dashboard.current_capability_rows[0].over_privileged_capabilities,
        vec!["network.fetch".to_string()]
    );
    assert_eq!(dashboard.escrow_event_feed.len(), 2);
    assert_eq!(dashboard.override_rationale_rows.len(), 1);

    let envelope = AdapterEnvelope::new(
        "trace-cap-delta-1",
        1_700_000_005_301,
        AdapterStream::CapabilityDeltaDashboard,
        UpdateKind::Snapshot,
        FrankentuiViewPayload::CapabilityDeltaDashboard(dashboard),
    );
    let encoded = envelope.encode_json().expect("encode");
    let decoded: AdapterEnvelope = serde_json::from_slice(&encoded).expect("decode");
    assert_eq!(decoded.stream, AdapterStream::CapabilityDeltaDashboard);
    match decoded.payload {
        FrankentuiViewPayload::CapabilityDeltaDashboard(view) => {
            assert_eq!(view.current_capability_rows.len(), 1);
            assert_eq!(view.proposed_minimal_rows.len(), 1);
            assert_eq!(view.escrow_event_feed.len(), 2);
            assert_eq!(view.override_rationale_rows[0].override_id, "escrow-2");
        }
        other => panic!("expected capability-delta dashboard payload, got {other:?}"),
    }
}

#[test]
fn replacement_progress_dashboard_view_round_trips_with_ranked_ev() {
    let replacement = ReplacementProgressDashboardView::from_partial(ReplacementProgressPartial {
        cluster: "prod".to_string(),
        zone: "us-east-1".to_string(),
        security_epoch: Some(17),
        generated_at_unix_ms: Some(1_700_000_000_250),
        slot_status_overview: vec![
            SlotStatusOverviewRow {
                slot_id: "parser".to_string(),
                slot_kind: "parser".to_string(),
                implementation_kind: "delegate".to_string(),
                promotion_status: "promotion_candidate".to_string(),
                risk_level: ReplacementRiskLevel::High,
                last_transition_unix_ms: 1_700_000_000_100,
                health: "blocked".to_string(),
                lineage_ref: "frankentui://replacement-lineage/parser".to_string(),
            },
            SlotStatusOverviewRow {
                slot_id: "gc".to_string(),
                slot_kind: "garbage_collector".to_string(),
                implementation_kind: "native".to_string(),
                promotion_status: "promoted".to_string(),
                risk_level: ReplacementRiskLevel::Low,
                last_transition_unix_ms: 1_700_000_000_080,
                health: "healthy".to_string(),
                lineage_ref: "frankentui://replacement-lineage/gc".to_string(),
            },
        ],
        replacement_inputs: vec![
            ReplacementOpportunityInput {
                slot_id: "parser".to_string(),
                slot_kind: "parser".to_string(),
                performance_uplift_millionths: 500_000,
                invocation_frequency_per_minute: 150,
                risk_reduction_millionths: 200_000,
            },
            ReplacementOpportunityInput {
                slot_id: "async-runtime".to_string(),
                slot_kind: "async_runtime".to_string(),
                performance_uplift_millionths: 800_000,
                invocation_frequency_per_minute: 5,
                risk_reduction_millionths: 100_000,
            },
        ],
        rollback_events: vec![RollbackEventView {
            slot_id: "parser".to_string(),
            receipt_id: "rcpt-parser-1".to_string(),
            reason: "divergence detected".to_string(),
            status: RollbackStatus::Investigating,
            occurred_at_unix_ms: 1_700_000_000_200,
            lineage_ref: "frankentui://replacement-lineage/parser".to_string(),
            evidence_ref: "frankentui://evidence/parser".to_string(),
        }],
        ..Default::default()
    });

    let envelope = AdapterEnvelope::new(
        "trace-replacement-1",
        1_700_000_000_251,
        AdapterStream::ReplacementProgressDashboard,
        UpdateKind::Snapshot,
        FrankentuiViewPayload::ReplacementProgressDashboard(replacement),
    );

    let encoded = envelope.encode_json().expect("encode");
    let decoded: AdapterEnvelope = serde_json::from_slice(&encoded).expect("decode");
    assert_eq!(decoded.stream, AdapterStream::ReplacementProgressDashboard);
    match decoded.payload {
        FrankentuiViewPayload::ReplacementProgressDashboard(view) => {
            assert_eq!(view.native_coverage.native_slots, 1);
            assert_eq!(view.native_coverage.delegate_slots, 1);
            assert_eq!(view.next_best_replacements[0].slot_id, "parser");
        }
        other => panic!("expected replacement dashboard payload, got {other:?}"),
    }
}

#[test]
fn proof_specialization_lineage_dashboard_round_trips_with_alert_views() {
    let proof_lineage =
        ProofSpecializationLineageDashboardView::from_partial(ProofSpecializationLineagePartial {
            cluster: "prod".to_string(),
            zone: "us-east-2".to_string(),
            security_epoch: Some(33),
            generated_at_unix_ms: Some(1_700_000_000_900),
            proof_inventory: vec![
                ProofInventoryRowView {
                    proof_id: "proof-cap-1".to_string(),
                    proof_kind: ProofInventoryKind::CapabilityWitness,
                    validity_status: ProofValidityStatus::Valid,
                    epoch_id: 33,
                    linked_specialization_count: 2,
                    enabled_specialization_ids: vec!["spec-a".to_string(), "spec-b".to_string()],
                    proof_ref: "frankentui://proof/proof-cap-1".to_string(),
                },
                ProofInventoryRowView {
                    proof_id: "proof-flow-2".to_string(),
                    proof_kind: ProofInventoryKind::FlowProof,
                    validity_status: ProofValidityStatus::ExpiringSoon,
                    epoch_id: 33,
                    linked_specialization_count: 1,
                    enabled_specialization_ids: vec!["spec-b".to_string()],
                    proof_ref: "frankentui://proof/proof-flow-2".to_string(),
                },
            ],
            active_specializations: vec![
                ActiveSpecializationRowView {
                    specialization_id: "spec-a".to_string(),
                    target_id: "ext-a".to_string(),
                    target_kind: "extension".to_string(),
                    optimization_class: "ifc_check_elision".to_string(),
                    latency_reduction_millionths: 350_000,
                    throughput_increase_millionths: 450_000,
                    proof_input_ids: vec!["proof-cap-1".to_string()],
                    transformation_ref: "frankentui://transform/spec-a".to_string(),
                    receipt_ref: "frankentui://receipt/spec-a".to_string(),
                    activated_at_unix_ms: 1_700_000_000_860,
                },
                ActiveSpecializationRowView {
                    specialization_id: "spec-b".to_string(),
                    target_id: "slot-parser".to_string(),
                    target_kind: "slot".to_string(),
                    optimization_class: "hostcall_dispatch_specialization".to_string(),
                    latency_reduction_millionths: 120_000,
                    throughput_increase_millionths: 180_000,
                    proof_input_ids: vec!["proof-cap-1".to_string(), "proof-flow-2".to_string()],
                    transformation_ref: "frankentui://transform/spec-b".to_string(),
                    receipt_ref: "frankentui://receipt/spec-b".to_string(),
                    activated_at_unix_ms: 1_700_000_000_865,
                },
            ],
            invalidation_feed: vec![SpecializationInvalidationRowView {
                invalidation_id: "inv-1".to_string(),
                specialization_id: "spec-b".to_string(),
                target_id: "slot-parser".to_string(),
                reason: ProofSpecializationInvalidationReason::ProofExpired,
                reason_detail: "proof validity window elapsed".to_string(),
                proof_id: Some("proof-flow-2".to_string()),
                old_epoch_id: Some(33),
                new_epoch_id: Some(34),
                fallback_confirmed: true,
                fallback_confirmation_ref: "frankentui://fallback/spec-b".to_string(),
                occurred_at_unix_ms: 1_700_000_000_870,
            }],
            fallback_events: vec![SpecializationFallbackEventView {
                event_id: "fb-1".to_string(),
                specialization_id: Some("spec-b".to_string()),
                target_id: "slot-parser".to_string(),
                reason: SpecializationFallbackReason::ProofExpired,
                reason_detail: "using unspecialized parser path".to_string(),
                unspecialized_path_ref: "frankentui://path/slot-parser/unspecialized".to_string(),
                compilation_ref: "frankentui://compile/slot-parser/1".to_string(),
                occurred_at_unix_ms: 1_700_000_000_871,
            }],
            bulk_invalidation_alert_threshold: Some(1),
            degraded_coverage_alert_threshold_millionths: Some(950_000),
            ..Default::default()
        });

    let envelope = AdapterEnvelope::new(
        "trace-proof-lineage-1",
        1_700_000_000_901,
        AdapterStream::ProofSpecializationLineageDashboard,
        UpdateKind::Snapshot,
        FrankentuiViewPayload::ProofSpecializationLineageDashboard(proof_lineage),
    );

    let encoded = envelope.encode_json().expect("encode");
    let decoded: AdapterEnvelope = serde_json::from_slice(&encoded).expect("decode");
    assert_eq!(
        decoded.stream,
        AdapterStream::ProofSpecializationLineageDashboard
    );
    match decoded.payload {
        FrankentuiViewPayload::ProofSpecializationLineageDashboard(view) => {
            assert_eq!(view.proof_inventory.len(), 2);
            assert_eq!(view.active_specializations.len(), 2);
            assert_eq!(view.invalidation_feed.len(), 1);
            assert_eq!(view.fallback_events.len(), 1);
            assert_eq!(view.performance_impact.active_specialization_count, 2);
            assert!(!view.alert_indicators.is_empty());
        }
        other => panic!("expected proof specialization payload, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Integration enrichment: enum serde roundtrips
// ---------------------------------------------------------------------------

#[test]
fn adapter_stream_serde_roundtrip_all_variants() {
    for variant in [
        AdapterStream::IncidentReplay,
        AdapterStream::PolicyExplanation,
        AdapterStream::ControlDashboard,
        AdapterStream::ControlPlaneInvariantsDashboard,
        AdapterStream::FlowDecisionDashboard,
        AdapterStream::CapabilityDeltaDashboard,
        AdapterStream::ReplacementProgressDashboard,
        AdapterStream::ProofSpecializationLineageDashboard,
    ] {
        let json = serde_json::to_string(&variant).unwrap();
        let back: AdapterStream = serde_json::from_str(&json).unwrap();
        assert_eq!(variant, back);
    }
}

#[test]
fn update_kind_serde_roundtrip_all_variants() {
    for variant in [
        UpdateKind::Snapshot,
        UpdateKind::Delta,
        UpdateKind::Heartbeat,
    ] {
        let json = serde_json::to_string(&variant).unwrap();
        let back: UpdateKind = serde_json::from_str(&json).unwrap();
        assert_eq!(variant, back);
    }
}

#[test]
fn replay_status_serde_roundtrip_all_variants() {
    for variant in [
        ReplayStatus::Running,
        ReplayStatus::Complete,
        ReplayStatus::Failed,
        ReplayStatus::NoEvents,
    ] {
        let json = serde_json::to_string(&variant).unwrap();
        let back: ReplayStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(variant, back);
    }
}

#[test]
fn dashboard_severity_serde_roundtrip_all_variants() {
    for variant in [
        DashboardSeverity::Info,
        DashboardSeverity::Warning,
        DashboardSeverity::Critical,
    ] {
        let json = serde_json::to_string(&variant).unwrap();
        let back: DashboardSeverity = serde_json::from_str(&json).unwrap();
        assert_eq!(variant, back);
    }
}

#[test]
fn decision_outcome_kind_serde_roundtrip_all_variants() {
    for variant in [
        DecisionOutcomeKind::Allow,
        DecisionOutcomeKind::Deny,
        DecisionOutcomeKind::Fallback,
    ] {
        let json = serde_json::to_string(&variant).unwrap();
        let back: DecisionOutcomeKind = serde_json::from_str(&json).unwrap();
        assert_eq!(variant, back);
    }
}

#[test]
fn obligation_state_serde_roundtrip_all_variants() {
    for variant in [
        ObligationState::Open,
        ObligationState::Fulfilled,
        ObligationState::Failed,
    ] {
        let json = serde_json::to_string(&variant).unwrap();
        let back: ObligationState = serde_json::from_str(&json).unwrap();
        assert_eq!(variant, back);
    }
}

#[test]
fn cancellation_kind_serde_roundtrip_all_variants() {
    for variant in [
        CancellationKind::Unload,
        CancellationKind::Quarantine,
        CancellationKind::Suspend,
        CancellationKind::Terminate,
        CancellationKind::Revocation,
    ] {
        let json = serde_json::to_string(&variant).unwrap();
        let back: CancellationKind = serde_json::from_str(&json).unwrap();
        assert_eq!(variant, back);
    }
}

#[test]
fn flow_sensitivity_level_serde_roundtrip_all_variants() {
    for variant in [
        FlowSensitivityLevel::Low,
        FlowSensitivityLevel::Medium,
        FlowSensitivityLevel::High,
        FlowSensitivityLevel::Critical,
    ] {
        let json = serde_json::to_string(&variant).unwrap();
        let back: FlowSensitivityLevel = serde_json::from_str(&json).unwrap();
        assert_eq!(variant, back);
    }
}

#[test]
fn declassification_outcome_serde_roundtrip_all_variants() {
    for variant in [
        DeclassificationOutcome::Approved,
        DeclassificationOutcome::Denied,
    ] {
        let json = serde_json::to_string(&variant).unwrap();
        let back: DeclassificationOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(variant, back);
    }
}

#[test]
fn confinement_status_serde_roundtrip_all_variants() {
    for variant in [
        ConfinementStatus::Full,
        ConfinementStatus::Partial,
        ConfinementStatus::Degraded,
    ] {
        let json = serde_json::to_string(&variant).unwrap();
        let back: ConfinementStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(variant, back);
    }
}

#[test]
fn replacement_risk_level_serde_roundtrip_all_variants() {
    for variant in [
        ReplacementRiskLevel::Low,
        ReplacementRiskLevel::Medium,
        ReplacementRiskLevel::High,
    ] {
        let json = serde_json::to_string(&variant).unwrap();
        let back: ReplacementRiskLevel = serde_json::from_str(&json).unwrap();
        assert_eq!(variant, back);
    }
}

#[test]
fn rollback_status_serde_roundtrip_all_variants() {
    for variant in [
        RollbackStatus::Investigating,
        RollbackStatus::Resolved,
        RollbackStatus::Waived,
    ] {
        let json = serde_json::to_string(&variant).unwrap();
        let back: RollbackStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(variant, back);
    }
}

#[test]
fn proof_inventory_kind_serde_roundtrip_all_variants() {
    for variant in [
        ProofInventoryKind::CapabilityWitness,
        ProofInventoryKind::FlowProof,
        ProofInventoryKind::ReplayMotif,
    ] {
        let json = serde_json::to_string(&variant).unwrap();
        let back: ProofInventoryKind = serde_json::from_str(&json).unwrap();
        assert_eq!(variant, back);
    }
}

#[test]
fn proof_validity_status_serde_roundtrip_all_variants() {
    for variant in [
        ProofValidityStatus::Valid,
        ProofValidityStatus::ExpiringSoon,
        ProofValidityStatus::Expired,
        ProofValidityStatus::Revoked,
    ] {
        let json = serde_json::to_string(&variant).unwrap();
        let back: ProofValidityStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(variant, back);
    }
}

#[test]
fn override_review_status_serde_roundtrip_all_variants() {
    for variant in [
        OverrideReviewStatus::Pending,
        OverrideReviewStatus::Approved,
        OverrideReviewStatus::Rejected,
        OverrideReviewStatus::Waived,
    ] {
        let json = serde_json::to_string(&variant).unwrap();
        let back: OverrideReviewStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(variant, back);
    }
}

#[test]
fn grant_expiry_status_serde_roundtrip_all_variants() {
    for variant in [
        GrantExpiryStatus::Active,
        GrantExpiryStatus::ExpiringSoon,
        GrantExpiryStatus::Expired,
        GrantExpiryStatus::NotApplicable,
    ] {
        let json = serde_json::to_string(&variant).unwrap();
        let back: GrantExpiryStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(variant, back);
    }
}

#[test]
fn dashboard_alert_metric_serde_roundtrip_unique_json_names() {
    let mut names = std::collections::BTreeSet::new();
    for variant in [
        DashboardAlertMetric::ObligationFailureRateMillionths,
        DashboardAlertMetric::ReplayDivergenceCount,
        DashboardAlertMetric::SafeModeActivationCount,
        DashboardAlertMetric::CancellationEventCount,
        DashboardAlertMetric::FallbackActivationCount,
    ] {
        let json = serde_json::to_string(&variant).unwrap();
        let back: DashboardAlertMetric = serde_json::from_str(&json).unwrap();
        assert_eq!(variant, back);
        names.insert(json);
    }
    assert_eq!(
        names.len(),
        5,
        "all metric variants must have unique JSON names"
    );
}

#[test]
fn threshold_comparator_serde_roundtrip_unique_json_names() {
    let mut names = std::collections::BTreeSet::new();
    for variant in [
        ThresholdComparator::GreaterThan,
        ThresholdComparator::GreaterOrEqual,
        ThresholdComparator::LessThan,
        ThresholdComparator::LessOrEqual,
        ThresholdComparator::Equal,
    ] {
        let json = serde_json::to_string(&variant).unwrap();
        let back: ThresholdComparator = serde_json::from_str(&json).unwrap();
        assert_eq!(variant, back);
        names.insert(json);
    }
    assert_eq!(
        names.len(),
        5,
        "all comparator variants must have unique JSON names"
    );
}

// ---------------------------------------------------------------------------
// Integration enrichment: from_partial with blank/missing fields
// ---------------------------------------------------------------------------

#[test]
fn control_dashboard_from_partial_blank_fields_become_unknown() {
    let view = ControlDashboardView::from_partial(ControlDashboardPartial {
        cluster: "   ".to_string(),
        zone: "".to_string(),
        security_epoch: None,
        runtime_mode: " ".to_string(),
        metrics: Vec::new(),
        extension_rows: Vec::new(),
        incident_counts: BTreeMap::new(),
    });
    assert_eq!(view.cluster, "unknown");
    assert_eq!(view.zone, "unknown");
    assert_eq!(view.runtime_mode, "unknown");
    assert_eq!(view.security_epoch, 0);
}

#[test]
fn policy_explanation_from_partial_blank_ids_become_unknown() {
    let card = PolicyExplanationCardView::from_partial(PolicyExplanationPartial {
        decision_id: "  ".to_string(),
        policy_id: "".to_string(),
        selected_action: "   ".to_string(),
        confidence_millionths: None,
        expected_loss_millionths: None,
        action_candidates: vec![],
        key_drivers: vec![],
    });
    assert_eq!(card.decision_id, "unknown");
    assert_eq!(card.policy_id, "unknown");
    assert_eq!(card.selected_action, "unknown");
    assert_eq!(card.confidence_millionths, 0);
    assert_eq!(card.expected_loss_millionths, 0);
}

#[test]
fn incident_replay_snapshot_blank_fields_become_unknown() {
    let replay = IncidentReplayView::snapshot("  ", "  ", vec![]);
    assert_eq!(replay.trace_id, "unknown");
    assert_eq!(replay.scenario_name, "unknown");
    assert_eq!(replay.replay_status, ReplayStatus::NoEvents);
}

#[test]
fn incident_replay_snapshot_with_events_is_complete() {
    let events = vec![ReplayEventView::new(1, "comp", "evt", "ok", 100)];
    let replay = IncidentReplayView::snapshot("trace-1", "scenario-1", events);
    assert_eq!(replay.replay_status, ReplayStatus::Complete);
    assert!(replay.deterministic);
    assert_eq!(replay.events.len(), 1);
}

#[test]
fn replay_event_view_new_blank_fields_become_unknown() {
    let event = ReplayEventView::new(0, "", "   ", " ", 999);
    assert_eq!(event.component, "unknown");
    assert_eq!(event.event, "unknown");
    assert_eq!(event.outcome, "unknown");
    assert_eq!(event.timestamp_unix_ms, 999);
    assert!(event.error_code.is_none());
}

// ---------------------------------------------------------------------------
// Integration enrichment: ControlPlaneInvariantsDashboardView
// ---------------------------------------------------------------------------

#[test]
fn control_plane_invariants_empty_partial_defaults_all_panels() {
    let view =
        ControlPlaneInvariantsDashboardView::from_partial(ControlPlaneInvariantsPartial::default());
    assert_eq!(view.cluster, "unknown");
    assert_eq!(view.zone, "unknown");
    assert!(view.evidence_stream.is_empty());
    assert!(view.obligation_rows.is_empty());
    assert!(view.region_rows.is_empty());
    assert!(view.cancellation_events.is_empty());
    assert!(view.safe_mode_activations.is_empty());
    assert_eq!(view.decision_outcomes, DecisionOutcomesPanelView::default());
    assert_eq!(view.obligation_status, ObligationStatusPanelView::default());
    assert_eq!(view.region_lifecycle, RegionLifecyclePanelView::default());
    assert!(view.meets_refresh_sla());
    assert!(view.triggered_alerts().is_empty());
}

#[test]
fn control_plane_invariants_refresh_sla_breach_detected() {
    let view = ControlPlaneInvariantsDashboardView::from_partial(ControlPlaneInvariantsPartial {
        cluster: "prod".to_string(),
        zone: "us-east-1".to_string(),
        runtime_mode: "secure".to_string(),
        generated_at_unix_ms: Some(1_700_000_100_000),
        refresh_policy: Some(DashboardRefreshPolicy {
            evidence_stream_refresh_secs: 5,
            aggregate_refresh_secs: 60,
        }),
        evidence_stream_last_updated_unix_ms: Some(1_700_000_093_000),
        aggregates_last_updated_unix_ms: Some(1_700_000_030_000),
        ..Default::default()
    });
    assert!(!view.meets_refresh_sla());
}

#[test]
fn control_plane_invariants_filtered_narrows_by_extension() {
    let view = ControlPlaneInvariantsDashboardView::from_partial(ControlPlaneInvariantsPartial {
        cluster: "prod".to_string(),
        zone: "us-east-1".to_string(),
        runtime_mode: "secure".to_string(),
        generated_at_unix_ms: Some(1_700_000_000_600),
        evidence_stream: vec![
            EvidenceStreamEntryView {
                trace_id: "t1".to_string(),
                decision_id: "d1".to_string(),
                policy_id: "p1".to_string(),
                action_type: "allow".to_string(),
                decision_outcome: DecisionOutcomeKind::Allow,
                expected_loss_millionths: 100_000,
                extension_id: "ext-a".to_string(),
                region_id: "region-1".to_string(),
                severity: DashboardSeverity::Info,
                component: "guardplane".to_string(),
                event: "evaluated".to_string(),
                outcome: "allow".to_string(),
                error_code: None,
                timestamp_unix_ms: 1_700_000_000_550,
            },
            EvidenceStreamEntryView {
                trace_id: "t2".to_string(),
                decision_id: "d2".to_string(),
                policy_id: "p2".to_string(),
                action_type: "deny".to_string(),
                decision_outcome: DecisionOutcomeKind::Deny,
                expected_loss_millionths: 500_000,
                extension_id: "ext-b".to_string(),
                region_id: "region-2".to_string(),
                severity: DashboardSeverity::Critical,
                component: "guardplane".to_string(),
                event: "blocked".to_string(),
                outcome: "deny".to_string(),
                error_code: Some("FE-001".to_string()),
                timestamp_unix_ms: 1_700_000_000_560,
            },
        ],
        ..Default::default()
    });

    let filtered = view.filtered(&ControlPlaneDashboardFilter {
        extension_id: Some("ext-a".to_string()),
        ..Default::default()
    });
    assert_eq!(filtered.evidence_stream.len(), 1);
    assert_eq!(filtered.evidence_stream[0].extension_id, "ext-a");
}

#[test]
fn control_plane_invariants_triggered_alerts_fire_on_failure() {
    let view = ControlPlaneInvariantsDashboardView::from_partial(ControlPlaneInvariantsPartial {
        cluster: "prod".to_string(),
        zone: "us-east-1".to_string(),
        runtime_mode: "secure".to_string(),
        generated_at_unix_ms: Some(1_700_000_120_000),
        obligation_rows: vec![ObligationStatusRowView {
            obligation_id: "obl-fail".to_string(),
            extension_id: "ext-a".to_string(),
            region_id: "region-a".to_string(),
            state: ObligationState::Failed,
            severity: DashboardSeverity::Critical,
            due_at_unix_ms: 1_700_000_121_000,
            updated_at_unix_ms: 1_700_000_120_100,
            detail: "timeout".to_string(),
        }],
        alert_rules: vec![DashboardAlertRule {
            rule_id: "alert-failure-rate".to_string(),
            description: "obligation failure rate > 0".to_string(),
            metric: DashboardAlertMetric::ObligationFailureRateMillionths,
            comparator: ThresholdComparator::GreaterThan,
            threshold: 0,
            severity: DashboardSeverity::Critical,
        }],
        ..Default::default()
    });

    let alerts = view.triggered_alerts();
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].rule_id, "alert-failure-rate");
}

// ---------------------------------------------------------------------------
// Integration enrichment: FlowDecisionDashboardView
// ---------------------------------------------------------------------------

#[test]
fn flow_decision_dashboard_filtered_by_sensitivity() {
    let view = FlowDecisionDashboardView::from_partial(FlowDecisionPartial {
        cluster: "prod".to_string(),
        zone: "us-west-1".to_string(),
        security_epoch: Some(10),
        generated_at_unix_ms: Some(1_700_000_000_800),
        label_map: LabelMapView {
            nodes: vec![LabelMapNodeView {
                label_id: "pii".to_string(),
                sensitivity: FlowSensitivityLevel::High,
                description: "user pii".to_string(),
                extension_overlays: vec!["ext-a".to_string()],
            }],
            edges: vec![],
        },
        blocked_flows: vec![
            BlockedFlowView {
                flow_id: "f-high".to_string(),
                extension_id: "ext-a".to_string(),
                source_label: "pii".to_string(),
                sink_clearance: "ext".to_string(),
                sensitivity: FlowSensitivityLevel::High,
                blocked_reason: "no clearance".to_string(),
                attempted_exfiltration: false,
                code_path_ref: "src/a.ts:1".to_string(),
                extension_context_ref: "ctx-a".to_string(),
                trace_id: "t1".to_string(),
                decision_id: "d1".to_string(),
                policy_id: "p1".to_string(),
                error_code: None,
                occurred_at_unix_ms: 1_700_000_000_750,
            },
            BlockedFlowView {
                flow_id: "f-low".to_string(),
                extension_id: "ext-b".to_string(),
                source_label: "pub".to_string(),
                sink_clearance: "ext".to_string(),
                sensitivity: FlowSensitivityLevel::Low,
                blocked_reason: "test".to_string(),
                attempted_exfiltration: false,
                code_path_ref: "src/b.ts:1".to_string(),
                extension_context_ref: "ctx-b".to_string(),
                trace_id: "t2".to_string(),
                decision_id: "d2".to_string(),
                policy_id: "p2".to_string(),
                error_code: None,
                occurred_at_unix_ms: 1_700_000_000_760,
            },
        ],
        ..Default::default()
    });

    let filtered = view.filtered(&FlowDecisionDashboardFilter {
        sensitivity: Some(FlowSensitivityLevel::High),
        ..Default::default()
    });
    assert_eq!(filtered.blocked_flows.len(), 1);
    assert_eq!(filtered.blocked_flows[0].flow_id, "f-high");
}

// ---------------------------------------------------------------------------
// Integration enrichment: CapabilityDeltaDashboardView from_partial
// ---------------------------------------------------------------------------

#[test]
fn capability_delta_dashboard_from_partial_computes_over_privilege_ratio() {
    let view = CapabilityDeltaDashboardView::from_partial(CapabilityDeltaPartial {
        cluster: "prod".to_string(),
        zone: "us-east-1".to_string(),
        security_epoch: Some(44),
        generated_at_unix_ms: Some(1_700_000_005_000),
        current_capability_rows: vec![CurrentCapabilityDeltaRowView {
            extension_id: "ext-a".to_string(),
            witness_id: "w-a".to_string(),
            policy_id: "p-a".to_string(),
            witness_epoch: 44,
            lifecycle_state: "active".to_string(),
            active_witness_capabilities: vec!["fs.read".to_string(), "net.fetch".to_string()],
            manifest_declared_capabilities: vec!["fs.read".to_string()],
            over_privileged_capabilities: vec!["net.fetch".to_string()],
            over_privilege_ratio_millionths: 500_000,
            over_privilege_replay_ref: "ref-a".to_string(),
            latest_receipt_timestamp_ns: None,
        }],
        ..Default::default()
    });

    assert_eq!(view.current_capability_rows.len(), 1);
    assert_eq!(
        view.current_capability_rows[0].over_privilege_ratio_millionths,
        500_000
    );
}

#[test]
fn capability_delta_dashboard_filtered_by_extension() {
    let view = CapabilityDeltaDashboardView::from_partial(CapabilityDeltaPartial {
        cluster: "prod".to_string(),
        zone: "us-east-1".to_string(),
        security_epoch: Some(44),
        generated_at_unix_ms: Some(5000),
        current_capability_rows: vec![
            CurrentCapabilityDeltaRowView {
                extension_id: "ext-a".to_string(),
                witness_id: "w-a".to_string(),
                policy_id: "p-a".to_string(),
                witness_epoch: 44,
                lifecycle_state: "active".to_string(),
                active_witness_capabilities: vec!["fs.read".to_string()],
                manifest_declared_capabilities: vec!["fs.read".to_string()],
                over_privileged_capabilities: vec![],
                over_privilege_ratio_millionths: 0,
                over_privilege_replay_ref: "ref-a".to_string(),
                latest_receipt_timestamp_ns: None,
            },
            CurrentCapabilityDeltaRowView {
                extension_id: "ext-b".to_string(),
                witness_id: "w-b".to_string(),
                policy_id: "p-b".to_string(),
                witness_epoch: 44,
                lifecycle_state: "active".to_string(),
                active_witness_capabilities: vec![],
                manifest_declared_capabilities: vec![],
                over_privileged_capabilities: vec![],
                over_privilege_ratio_millionths: 0,
                over_privilege_replay_ref: "ref-b".to_string(),
                latest_receipt_timestamp_ns: None,
            },
        ],
        ..Default::default()
    });

    let filtered = view.filtered(&CapabilityDeltaDashboardFilter {
        extension_id: Some("ext-a".to_string()),
        ..Default::default()
    });
    assert_eq!(filtered.current_capability_rows.len(), 1);
    assert_eq!(filtered.current_capability_rows[0].extension_id, "ext-a");
}

// ---------------------------------------------------------------------------
// Integration enrichment: ReplacementProgressDashboardView
// ---------------------------------------------------------------------------

#[test]
fn replacement_progress_filtered_by_risk_level() {
    let view = ReplacementProgressDashboardView::from_partial(ReplacementProgressPartial {
        cluster: "prod".to_string(),
        zone: "us-west-2".to_string(),
        slot_status_overview: vec![
            SlotStatusOverviewRow {
                slot_id: "parser".to_string(),
                slot_kind: "parser".to_string(),
                implementation_kind: "delegate".to_string(),
                promotion_status: "candidate".to_string(),
                risk_level: ReplacementRiskLevel::High,
                last_transition_unix_ms: 10,
                health: "blocked".to_string(),
                lineage_ref: "lr-parser".to_string(),
            },
            SlotStatusOverviewRow {
                slot_id: "gc".to_string(),
                slot_kind: "garbage_collector".to_string(),
                implementation_kind: "native".to_string(),
                promotion_status: "promoted".to_string(),
                risk_level: ReplacementRiskLevel::Low,
                last_transition_unix_ms: 11,
                health: "healthy".to_string(),
                lineage_ref: "lr-gc".to_string(),
            },
        ],
        ..Default::default()
    });

    let filtered = view.filtered(&ReplacementDashboardFilter {
        risk_level: Some(ReplacementRiskLevel::High),
        ..Default::default()
    });
    assert_eq!(filtered.slot_status_overview.len(), 1);
    assert_eq!(filtered.slot_status_overview[0].slot_id, "parser");
}

// ---------------------------------------------------------------------------
// Integration enrichment: ProofSpecializationLineageDashboardView
// ---------------------------------------------------------------------------

#[test]
fn proof_specialization_filtered_by_target_id() {
    let view =
        ProofSpecializationLineageDashboardView::from_partial(ProofSpecializationLineagePartial {
            cluster: "prod".to_string(),
            zone: "us-east-1".to_string(),
            security_epoch: Some(31),
            generated_at_unix_ms: Some(2000),
            active_specializations: vec![
                ActiveSpecializationRowView {
                    specialization_id: "sp-a".to_string(),
                    target_id: "ext-a".to_string(),
                    target_kind: "extension".to_string(),
                    optimization_class: "elision".to_string(),
                    latency_reduction_millionths: 100_000,
                    throughput_increase_millionths: 200_000,
                    proof_input_ids: vec!["p1".to_string()],
                    transformation_ref: "tr-a".to_string(),
                    receipt_ref: "rr-a".to_string(),
                    activated_at_unix_ms: 1900,
                },
                ActiveSpecializationRowView {
                    specialization_id: "sp-b".to_string(),
                    target_id: "ext-b".to_string(),
                    target_kind: "extension".to_string(),
                    optimization_class: "dispatch".to_string(),
                    latency_reduction_millionths: 50_000,
                    throughput_increase_millionths: 80_000,
                    proof_input_ids: vec!["p2".to_string()],
                    transformation_ref: "tr-b".to_string(),
                    receipt_ref: "rr-b".to_string(),
                    activated_at_unix_ms: 1950,
                },
            ],
            ..Default::default()
        });

    let filtered = view.filtered(&ProofSpecializationDashboardFilter {
        target_id: Some("ext-a".to_string()),
        ..Default::default()
    });
    assert_eq!(filtered.active_specializations.len(), 1);
    assert_eq!(filtered.active_specializations[0].specialization_id, "sp-a");
}

// ---------------------------------------------------------------------------
// Integration enrichment: public helper functions
// ---------------------------------------------------------------------------

#[test]
fn build_native_coverage_meter_empty_slots() {
    let meter = build_native_coverage_meter(&[], vec![]);
    assert_eq!(meter.native_slots, 0);
    assert_eq!(meter.delegate_slots, 0);
    assert_eq!(meter.native_coverage_millionths, 0);
}

#[test]
fn build_native_coverage_meter_all_native() {
    let rows = vec![
        SlotStatusOverviewRow {
            slot_id: "s1".to_string(),
            slot_kind: "parser".to_string(),
            implementation_kind: "native".to_string(),
            promotion_status: "promoted".to_string(),
            risk_level: ReplacementRiskLevel::Low,
            last_transition_unix_ms: 1000,
            health: "healthy".to_string(),
            lineage_ref: "lr1".to_string(),
        },
        SlotStatusOverviewRow {
            slot_id: "s2".to_string(),
            slot_kind: "gc".to_string(),
            implementation_kind: "NATIVE".to_string(),
            promotion_status: "promoted".to_string(),
            risk_level: ReplacementRiskLevel::Low,
            last_transition_unix_ms: 2000,
            health: "healthy".to_string(),
            lineage_ref: "lr2".to_string(),
        },
    ];
    let meter = build_native_coverage_meter(&rows, vec![]);
    assert_eq!(meter.native_slots, 2);
    assert_eq!(meter.delegate_slots, 0);
    assert_eq!(meter.native_coverage_millionths, 1_000_000);
}

#[test]
fn build_native_coverage_meter_mixed_with_trend() {
    let rows = vec![
        SlotStatusOverviewRow {
            slot_id: "s1".to_string(),
            slot_kind: "a".to_string(),
            implementation_kind: "native".to_string(),
            promotion_status: "p".to_string(),
            risk_level: ReplacementRiskLevel::Low,
            last_transition_unix_ms: 0,
            health: "ok".to_string(),
            lineage_ref: String::new(),
        },
        SlotStatusOverviewRow {
            slot_id: "s2".to_string(),
            slot_kind: "b".to_string(),
            implementation_kind: "delegate".to_string(),
            promotion_status: "p".to_string(),
            risk_level: ReplacementRiskLevel::Medium,
            last_transition_unix_ms: 0,
            health: "ok".to_string(),
            lineage_ref: String::new(),
        },
    ];
    let trend = vec![CoverageTrendPoint {
        timestamp_unix_ms: 1000,
        native_coverage_millionths: 400_000,
    }];
    let meter = build_native_coverage_meter(&rows, trend);
    assert_eq!(meter.native_slots, 1);
    assert_eq!(meter.delegate_slots, 1);
    assert_eq!(meter.native_coverage_millionths, 500_000);
    assert_eq!(meter.trend.len(), 1);
}

#[test]
fn rank_replacement_opportunities_empty_input() {
    let ranked = rank_replacement_opportunities(vec![]);
    assert!(ranked.is_empty());
}

#[test]
fn rank_replacement_opportunities_sorts_by_ev_desc() {
    let inputs = vec![
        ReplacementOpportunityInput {
            slot_id: "low".to_string(),
            slot_kind: "a".to_string(),
            performance_uplift_millionths: 100_000,
            invocation_frequency_per_minute: 1,
            risk_reduction_millionths: 0,
        },
        ReplacementOpportunityInput {
            slot_id: "high".to_string(),
            slot_kind: "b".to_string(),
            performance_uplift_millionths: 500_000,
            invocation_frequency_per_minute: 10,
            risk_reduction_millionths: 100_000,
        },
    ];
    let ranked = rank_replacement_opportunities(inputs);
    assert_eq!(ranked.len(), 2);
    assert_eq!(ranked[0].slot_id, "high");
    assert_eq!(ranked[1].slot_id, "low");
    assert!(ranked[0].expected_value_score_millionths > ranked[1].expected_value_score_millionths);
}

#[test]
fn build_specialization_performance_impact_empty_inputs() {
    let impact = build_specialization_performance_impact(&[], &[]);
    assert_eq!(impact.active_specialization_count, 0);
    assert_eq!(impact.aggregate_latency_reduction_millionths, 0);
    assert_eq!(impact.aggregate_throughput_increase_millionths, 0);
    assert_eq!(impact.specialization_coverage_millionths, 1_000_000);
}

#[test]
fn build_specialization_performance_impact_aggregates() {
    let specs = vec![
        ActiveSpecializationRowView {
            specialization_id: "sp1".to_string(),
            target_id: "t1".to_string(),
            target_kind: "fn".to_string(),
            optimization_class: "oc".to_string(),
            proof_input_ids: vec!["p1".to_string()],
            latency_reduction_millionths: 100_000,
            throughput_increase_millionths: 200_000,
            transformation_ref: "tr1".to_string(),
            receipt_ref: "r1".to_string(),
            activated_at_unix_ms: 1000,
        },
        ActiveSpecializationRowView {
            specialization_id: "sp2".to_string(),
            target_id: "t2".to_string(),
            target_kind: "fn".to_string(),
            optimization_class: "oc".to_string(),
            proof_input_ids: vec!["p2".to_string()],
            latency_reduction_millionths: 50_000,
            throughput_increase_millionths: 80_000,
            transformation_ref: "tr2".to_string(),
            receipt_ref: "r2".to_string(),
            activated_at_unix_ms: 2000,
        },
    ];
    let impact = build_specialization_performance_impact(&specs, &[]);
    assert_eq!(impact.active_specialization_count, 2);
    assert_eq!(impact.aggregate_latency_reduction_millionths, 150_000);
    assert_eq!(impact.aggregate_throughput_increase_millionths, 280_000);
}

// ---------------------------------------------------------------------------
// Integration enrichment: AdapterEnvelope determinism
// ---------------------------------------------------------------------------

#[test]
fn adapter_envelope_encode_json_is_deterministic() {
    let replay = IncidentReplayView::snapshot("trace-1", "scenario-1", vec![]);
    let env = AdapterEnvelope::new(
        "trace-1",
        1000,
        AdapterStream::IncidentReplay,
        UpdateKind::Snapshot,
        FrankentuiViewPayload::IncidentReplay(replay),
    );
    let enc1 = env.encode_json().unwrap();
    let enc2 = env.encode_json().unwrap();
    assert_eq!(enc1, enc2);
}

#[test]
fn adapter_envelope_schema_version_matches_constant() {
    let replay = IncidentReplayView::snapshot("t", "s", vec![]);
    let env = AdapterEnvelope::new(
        "t",
        0,
        AdapterStream::IncidentReplay,
        UpdateKind::Snapshot,
        FrankentuiViewPayload::IncidentReplay(replay),
    );
    assert_eq!(env.schema_version, FRANKENTUI_ADAPTER_SCHEMA_VERSION);
}

// ---------------------------------------------------------------------------
// Integration enrichment: JSON field-name contracts
// ---------------------------------------------------------------------------

#[test]
fn adapter_envelope_json_field_names_stable() {
    let replay = IncidentReplayView::snapshot("t", "s", vec![]);
    let env = AdapterEnvelope::new(
        "t",
        42,
        AdapterStream::IncidentReplay,
        UpdateKind::Snapshot,
        FrankentuiViewPayload::IncidentReplay(replay),
    );
    let json = String::from_utf8(env.encode_json().unwrap()).unwrap();
    assert!(json.contains("\"schema_version\""));
    assert!(json.contains("\"trace_id\""));
    assert!(json.contains("\"generated_at_unix_ms\""));
    assert!(json.contains("\"stream\""));
    assert!(json.contains("\"update_kind\""));
    assert!(json.contains("\"payload\""));
}

#[test]
fn control_plane_invariants_json_field_names_stable() {
    let view = ControlPlaneInvariantsDashboardView::from_partial(ControlPlaneInvariantsPartial {
        cluster: "prod".to_string(),
        zone: "z1".to_string(),
        runtime_mode: "secure".to_string(),
        generated_at_unix_ms: Some(1000),
        ..Default::default()
    });
    let json = serde_json::to_string(&view).unwrap();
    for field in [
        "\"cluster\"",
        "\"zone\"",
        "\"runtime_mode\"",
        "\"generated_at_unix_ms\"",
        "\"evidence_stream\"",
        "\"obligation_rows\"",
        "\"region_rows\"",
        "\"decision_outcomes\"",
        "\"obligation_status\"",
        "\"region_lifecycle\"",
        "\"replay_health\"",
        "\"benchmark_trends\"",
        "\"safe_mode_activations\"",
        "\"cancellation_events\"",
        "\"schema_version\"",
    ] {
        assert!(json.contains(field), "missing field: {field}");
    }
}

#[test]
fn flow_decision_dashboard_json_field_names_stable() {
    let view = FlowDecisionDashboardView::from_partial(FlowDecisionPartial {
        cluster: "c".to_string(),
        zone: "z".to_string(),
        security_epoch: Some(1),
        generated_at_unix_ms: Some(100),
        ..Default::default()
    });
    let json = serde_json::to_string(&view).unwrap();
    for field in [
        "\"cluster\"",
        "\"zone\"",
        "\"security_epoch\"",
        "\"generated_at_unix_ms\"",
        "\"label_map\"",
        "\"blocked_flows\"",
        "\"declassification_history\"",
        "\"confinement_proofs\"",
        "\"alert_indicators\"",
    ] {
        assert!(json.contains(field), "missing field: {field}");
    }
}

#[test]
fn capability_delta_dashboard_json_field_names_stable() {
    let view = CapabilityDeltaDashboardView::from_partial(CapabilityDeltaPartial {
        cluster: "c".to_string(),
        zone: "z".to_string(),
        security_epoch: Some(1),
        generated_at_unix_ms: Some(100),
        ..Default::default()
    });
    let json = serde_json::to_string(&view).unwrap();
    for field in [
        "\"cluster\"",
        "\"zone\"",
        "\"security_epoch\"",
        "\"current_capability_rows\"",
        "\"proposed_minimal_rows\"",
        "\"escrow_event_feed\"",
        "\"override_rationale_rows\"",
        "\"batch_review_queue\"",
        "\"alert_indicators\"",
    ] {
        assert!(json.contains(field), "missing field: {field}");
    }
}

// ---------------------------------------------------------------------------
// Integration enrichment: clone independence
// ---------------------------------------------------------------------------

#[test]
fn control_plane_invariants_clone_independence() {
    let original =
        ControlPlaneInvariantsDashboardView::from_partial(ControlPlaneInvariantsPartial {
            cluster: "prod".to_string(),
            zone: "us-east-1".to_string(),
            runtime_mode: "secure".to_string(),
            generated_at_unix_ms: Some(1000),
            evidence_stream: vec![EvidenceStreamEntryView {
                trace_id: "t1".to_string(),
                decision_id: "d1".to_string(),
                policy_id: "p1".to_string(),
                action_type: "allow".to_string(),
                decision_outcome: DecisionOutcomeKind::Allow,
                expected_loss_millionths: 100_000,
                extension_id: "ext-a".to_string(),
                region_id: "r-1".to_string(),
                severity: DashboardSeverity::Info,
                component: "comp".to_string(),
                event: "ev".to_string(),
                outcome: "ok".to_string(),
                error_code: None,
                timestamp_unix_ms: 900,
            }],
            ..Default::default()
        });

    let cloned = original.clone();
    assert_eq!(original, cloned);
    // Modify original's first evidence entry via filter — cloned should remain unchanged
    let filtered = original.filtered(&ControlPlaneDashboardFilter {
        extension_id: Some("nonexistent".to_string()),
        ..Default::default()
    });
    assert!(filtered.evidence_stream.is_empty());
    assert_eq!(cloned.evidence_stream.len(), 1);
}

#[test]
fn flow_decision_dashboard_clone_independence() {
    let original = FlowDecisionDashboardView::from_partial(FlowDecisionPartial {
        cluster: "c".to_string(),
        zone: "z".to_string(),
        security_epoch: Some(1),
        generated_at_unix_ms: Some(100),
        blocked_flows: vec![BlockedFlowView {
            flow_id: "f1".to_string(),
            extension_id: "ext-a".to_string(),
            source_label: "secret".to_string(),
            sink_clearance: "public".to_string(),
            sensitivity: FlowSensitivityLevel::High,
            blocked_reason: "blocked".to_string(),
            attempted_exfiltration: false,
            code_path_ref: "cp".to_string(),
            extension_context_ref: "ec".to_string(),
            trace_id: "t1".to_string(),
            decision_id: "d1".to_string(),
            policy_id: "p1".to_string(),
            error_code: None,
            occurred_at_unix_ms: 50,
        }],
        ..Default::default()
    });

    let cloned = original.clone();
    assert_eq!(original, cloned);
    let filtered = original.filtered(&FlowDecisionDashboardFilter {
        extension_id: Some("nonexistent".to_string()),
        ..Default::default()
    });
    assert!(filtered.blocked_flows.is_empty());
    assert_eq!(cloned.blocked_flows.len(), 1);
}

// ---------------------------------------------------------------------------
// Integration enrichment: complex struct serde roundtrips
// ---------------------------------------------------------------------------

#[test]
fn control_plane_invariants_serde_roundtrip() {
    let view = ControlPlaneInvariantsDashboardView::from_partial(ControlPlaneInvariantsPartial {
        cluster: "prod".to_string(),
        zone: "us-east-1".to_string(),
        runtime_mode: "secure".to_string(),
        generated_at_unix_ms: Some(1_700_000_000_100),
        ..Default::default()
    });
    let json = serde_json::to_string(&view).unwrap();
    let back: ControlPlaneInvariantsDashboardView = serde_json::from_str(&json).unwrap();
    assert_eq!(view, back);
}

#[test]
fn flow_decision_dashboard_serde_roundtrip() {
    let view = FlowDecisionDashboardView::from_partial(FlowDecisionPartial {
        cluster: "prod".to_string(),
        zone: "us-east-1".to_string(),
        security_epoch: Some(5),
        generated_at_unix_ms: Some(1_000),
        ..Default::default()
    });
    let json = serde_json::to_string(&view).unwrap();
    let back: FlowDecisionDashboardView = serde_json::from_str(&json).unwrap();
    assert_eq!(view, back);
}

#[test]
fn capability_delta_dashboard_serde_roundtrip() {
    let view = CapabilityDeltaDashboardView::from_partial(CapabilityDeltaPartial {
        cluster: "prod".to_string(),
        zone: "us-east-1".to_string(),
        security_epoch: Some(44),
        generated_at_unix_ms: Some(5000),
        ..Default::default()
    });
    let json = serde_json::to_string(&view).unwrap();
    let back: CapabilityDeltaDashboardView = serde_json::from_str(&json).unwrap();
    assert_eq!(view, back);
}

#[test]
fn replacement_progress_dashboard_serde_roundtrip() {
    let view = ReplacementProgressDashboardView::from_partial(ReplacementProgressPartial {
        cluster: "prod".to_string(),
        zone: "us-east-1".to_string(),
        security_epoch: Some(10),
        generated_at_unix_ms: Some(3000),
        ..Default::default()
    });
    let json = serde_json::to_string(&view).unwrap();
    let back: ReplacementProgressDashboardView = serde_json::from_str(&json).unwrap();
    assert_eq!(view, back);
}

#[test]
fn proof_specialization_lineage_dashboard_serde_roundtrip() {
    let view =
        ProofSpecializationLineageDashboardView::from_partial(ProofSpecializationLineagePartial {
            cluster: "prod".to_string(),
            zone: "us-east-1".to_string(),
            security_epoch: Some(31),
            generated_at_unix_ms: Some(2000),
            ..Default::default()
        });
    let json = serde_json::to_string(&view).unwrap();
    let back: ProofSpecializationLineageDashboardView = serde_json::from_str(&json).unwrap();
    assert_eq!(view, back);
}

// ---------------------------------------------------------------------------
// Integration enrichment: all FrankentuiViewPayload variants round-trip
// ---------------------------------------------------------------------------

#[test]
fn all_payload_variants_envelope_round_trip() {
    let payloads: Vec<(AdapterStream, FrankentuiViewPayload)> = vec![
        (
            AdapterStream::IncidentReplay,
            FrankentuiViewPayload::IncidentReplay(IncidentReplayView::snapshot("t", "s", vec![])),
        ),
        (
            AdapterStream::PolicyExplanation,
            FrankentuiViewPayload::PolicyExplanation(PolicyExplanationCardView::from_partial(
                PolicyExplanationPartial {
                    decision_id: "d".to_string(),
                    policy_id: "p".to_string(),
                    selected_action: "allow".to_string(),
                    confidence_millionths: Some(500_000),
                    expected_loss_millionths: Some(100_000),
                    action_candidates: vec![],
                    key_drivers: vec![],
                },
            )),
        ),
        (
            AdapterStream::ControlDashboard,
            FrankentuiViewPayload::ControlDashboard(ControlDashboardView::from_partial(
                ControlDashboardPartial::default(),
            )),
        ),
        (
            AdapterStream::ControlPlaneInvariantsDashboard,
            FrankentuiViewPayload::ControlPlaneInvariantsDashboard(Box::new(
                ControlPlaneInvariantsDashboardView::from_partial(
                    ControlPlaneInvariantsPartial::default(),
                ),
            )),
        ),
        (
            AdapterStream::FlowDecisionDashboard,
            FrankentuiViewPayload::FlowDecisionDashboard(FlowDecisionDashboardView::from_partial(
                FlowDecisionPartial {
                    cluster: "c".to_string(),
                    zone: "z".to_string(),
                    ..Default::default()
                },
            )),
        ),
        (
            AdapterStream::CapabilityDeltaDashboard,
            FrankentuiViewPayload::CapabilityDeltaDashboard(
                CapabilityDeltaDashboardView::from_partial(CapabilityDeltaPartial {
                    cluster: "c".to_string(),
                    zone: "z".to_string(),
                    ..Default::default()
                }),
            ),
        ),
        (
            AdapterStream::ReplacementProgressDashboard,
            FrankentuiViewPayload::ReplacementProgressDashboard(
                ReplacementProgressDashboardView::from_partial(ReplacementProgressPartial {
                    cluster: "c".to_string(),
                    zone: "z".to_string(),
                    ..Default::default()
                }),
            ),
        ),
        (
            AdapterStream::ProofSpecializationLineageDashboard,
            FrankentuiViewPayload::ProofSpecializationLineageDashboard(
                ProofSpecializationLineageDashboardView::from_partial(
                    ProofSpecializationLineagePartial {
                        cluster: "c".to_string(),
                        zone: "z".to_string(),
                        ..Default::default()
                    },
                ),
            ),
        ),
    ];

    for (stream, payload) in payloads {
        let env = AdapterEnvelope::new(
            "trace-all",
            1000,
            stream.clone(),
            UpdateKind::Snapshot,
            payload,
        );
        let encoded = env.encode_json().unwrap();
        let decoded: AdapterEnvelope = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded.stream, stream);
        assert_eq!(decoded, env);
    }
}

// ---------------------------------------------------------------------------
// Integration enrichment: default value assertions
// ---------------------------------------------------------------------------

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
fn flow_sensitivity_level_default_is_low() {
    assert_eq!(FlowSensitivityLevel::default(), FlowSensitivityLevel::Low);
}

#[test]
fn proof_validity_status_default_is_valid() {
    assert_eq!(ProofValidityStatus::default(), ProofValidityStatus::Valid);
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

// ---------------------------------------------------------------------------
// Integration enrichment: DashboardRefreshPolicy normalization
// ---------------------------------------------------------------------------

#[test]
fn dashboard_refresh_policy_default_values() {
    let rp = DashboardRefreshPolicy::default();
    assert_eq!(rp.evidence_stream_refresh_secs, 5);
    assert_eq!(rp.aggregate_refresh_secs, 60);
}

#[test]
fn dashboard_refresh_policy_serde_roundtrip_with_zeros() {
    let rp = DashboardRefreshPolicy {
        evidence_stream_refresh_secs: 0,
        aggregate_refresh_secs: 0,
    };
    let json = serde_json::to_string(&rp).unwrap();
    let back: DashboardRefreshPolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(back.evidence_stream_refresh_secs, 0);
    assert_eq!(back.aggregate_refresh_secs, 0);
}

// ---------------------------------------------------------------------------
// Integration enrichment: Display uniqueness for Debug-derived enums
// ---------------------------------------------------------------------------

#[test]
fn adapter_stream_debug_names_unique() {
    let variants = [
        AdapterStream::IncidentReplay,
        AdapterStream::PolicyExplanation,
        AdapterStream::ControlDashboard,
        AdapterStream::ControlPlaneInvariantsDashboard,
        AdapterStream::FlowDecisionDashboard,
        AdapterStream::CapabilityDeltaDashboard,
        AdapterStream::ReplacementProgressDashboard,
        AdapterStream::ProofSpecializationLineageDashboard,
    ];
    let mut names = std::collections::BTreeSet::new();
    for v in &variants {
        names.insert(format!("{v:?}"));
    }
    assert_eq!(names.len(), variants.len());
}

#[test]
fn cancellation_kind_debug_names_unique() {
    let variants = [
        CancellationKind::Unload,
        CancellationKind::Quarantine,
        CancellationKind::Suspend,
        CancellationKind::Terminate,
        CancellationKind::Revocation,
    ];
    let mut names = std::collections::BTreeSet::new();
    for v in &variants {
        names.insert(format!("{v:?}"));
    }
    assert_eq!(names.len(), variants.len());
}

// ---------------------------------------------------------------------------
// Integration enrichment: filter default assertions
// ---------------------------------------------------------------------------

#[test]
fn control_plane_dashboard_filter_default_all_none() {
    let f = ControlPlaneDashboardFilter::default();
    assert!(f.extension_id.is_none());
    assert!(f.region_id.is_none());
    assert!(f.severity.is_none());
    assert!(f.start_unix_ms.is_none());
    assert!(f.end_unix_ms.is_none());
}

#[test]
fn flow_decision_dashboard_filter_default_all_none() {
    let f = FlowDecisionDashboardFilter::default();
    assert!(f.extension_id.is_none());
    assert!(f.source_label.is_none());
    assert!(f.sink_clearance.is_none());
    assert!(f.sensitivity.is_none());
    assert!(f.start_unix_ms.is_none());
    assert!(f.end_unix_ms.is_none());
}

#[test]
fn capability_delta_dashboard_filter_default_all_none() {
    let f = CapabilityDeltaDashboardFilter::default();
    assert!(f.extension_id.is_none());
    assert!(f.capability.is_none());
    assert!(f.outcome.is_none());
}

#[test]
fn replacement_dashboard_filter_default_all_none() {
    let f = ReplacementDashboardFilter::default();
    assert!(f.slot_kind.is_none());
    assert!(f.risk_level.is_none());
    assert!(f.promotion_status.is_none());
}

#[test]
fn proof_specialization_dashboard_filter_default_all_none() {
    let f = ProofSpecializationDashboardFilter::default();
    assert!(f.target_id.is_none());
    assert!(f.optimization_class.is_none());
    assert!(f.proof_id.is_none());
    assert!(f.start_unix_ms.is_none());
    assert!(f.end_unix_ms.is_none());
}
