//! Enrichment integration tests for `controller_composition_matrix`.

use std::collections::BTreeSet;

use frankenengine_engine::controller_composition_matrix::*;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_timescale(name: &str, role: ControllerRole, obs: i64, write: i64) -> ControllerTimescale {
    ControllerTimescale {
        controller_name: name.to_string(),
        role,
        observation_interval_millionths: obs,
        write_interval_millionths: write,
        statement: format!("{name} timescale statement"),
    }
}

#[allow(clippy::too_many_arguments)]
fn make_contract(
    name: &str,
    role: ControllerRole,
    obs: i64,
    write: i64,
    obs_channels: &[&str],
    action_channels: &[&str],
    state_channels: &[&str],
    shared_resources: &[&str],
    actuation_bounds: Vec<ActuationBound>,
    fallback: Option<DeterministicFallback>,
) -> ControllerContract {
    ControllerContract {
        timescale: make_timescale(name, role, obs, write),
        observation_channels: obs_channels.iter().map(|s| s.to_string()).collect(),
        action_channels: action_channels.iter().map(|s| s.to_string()).collect(),
        state_channels: state_channels.iter().map(|s| s.to_string()).collect(),
        actuation_bounds,
        shared_resources: shared_resources.iter().map(|s| s.to_string()).collect(),
        deterministic_fallback: fallback,
    }
}

fn make_full_contract(name: &str, role: ControllerRole) -> ControllerContract {
    make_contract(
        name,
        role,
        1_000_000,
        2_000_000,
        &["metric_in"],
        &["action_out"],
        &["state_summary"],
        &["shared_bus"],
        vec![ActuationBound {
            channel: "action_out".to_string(),
            lower_bound_millionths: 0,
            upper_bound_millionths: 1_000_000,
            units: "ppm".to_string(),
        }],
        Some(DeterministicFallback {
            fallback_mode: "static".to_string(),
            trigger: "budget_exceeded".to_string(),
            detail: "fall back to static config".to_string(),
        }),
    )
}

fn make_monitor_contract(name: &str) -> ControllerContract {
    make_contract(
        name,
        ControllerRole::Monitor,
        500_000,
        1_000_000,
        &["metric_in"],
        &[],
        &["state_summary"],
        &["shared_bus"],
        vec![],
        None,
    )
}

// ---------------------------------------------------------------------------
// ControllerRole — Display uniqueness
// ---------------------------------------------------------------------------

#[test]
fn enrichment_controller_role_display_uniqueness() {
    let roles = ControllerRole::all();
    let strings: BTreeSet<String> = roles.iter().map(|r| r.to_string()).collect();
    assert_eq!(strings.len(), roles.len());
}

#[test]
fn enrichment_controller_role_as_str_consistency() {
    for &role in ControllerRole::all() {
        assert_eq!(role.as_str(), format!("{role}"));
    }
}

#[test]
fn enrichment_controller_role_serde_all_variants() {
    for &role in ControllerRole::all() {
        let json = serde_json::to_string(&role).unwrap();
        let back: ControllerRole = serde_json::from_str(&json).unwrap();
        assert_eq!(role, back);
    }
}

#[test]
fn enrichment_controller_role_ordering_is_total() {
    let roles = ControllerRole::all();
    for (i, &a) in roles.iter().enumerate() {
        for &b in &roles[i + 1..] {
            assert!(a < b, "{a:?} should be < {b:?}");
        }
    }
}

#[test]
fn enrichment_controller_role_clone_eq() {
    for &role in ControllerRole::all() {
        let cloned = role;
        assert_eq!(role, cloned);
    }
}

// ---------------------------------------------------------------------------
// InteractionClass — Display uniqueness
// ---------------------------------------------------------------------------

fn all_interaction_classes() -> Vec<InteractionClass> {
    vec![
        InteractionClass::Independent,
        InteractionClass::ReadShared,
        InteractionClass::ProducerConsumer,
        InteractionClass::WriteConflict,
        InteractionClass::MutuallyExclusive,
    ]
}

#[test]
fn enrichment_interaction_class_display_uniqueness() {
    let classes = all_interaction_classes();
    let strings: BTreeSet<String> = classes.iter().map(|c| c.to_string()).collect();
    assert_eq!(strings.len(), classes.len());
}

#[test]
fn enrichment_interaction_class_as_str_consistency() {
    for class in all_interaction_classes() {
        assert_eq!(class.as_str(), format!("{class}"));
    }
}

#[test]
fn enrichment_interaction_class_serde_all_variants() {
    for class in all_interaction_classes() {
        let json = serde_json::to_string(&class).unwrap();
        let back: InteractionClass = serde_json::from_str(&json).unwrap();
        assert_eq!(class, back);
    }
}

#[test]
fn enrichment_interaction_class_requires_timescale_separation_taxonomy() {
    assert!(!InteractionClass::Independent.requires_timescale_separation());
    assert!(!InteractionClass::ReadShared.requires_timescale_separation());
    assert!(InteractionClass::ProducerConsumer.requires_timescale_separation());
    assert!(InteractionClass::WriteConflict.requires_timescale_separation());
    assert!(!InteractionClass::MutuallyExclusive.requires_timescale_separation());
}

#[test]
fn enrichment_interaction_class_blocks_composition_only_mutually_exclusive() {
    for class in all_interaction_classes() {
        let expected = matches!(class, InteractionClass::MutuallyExclusive);
        assert_eq!(
            class.blocks_composition(),
            expected,
            "mismatch for {class:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// MetadataGapKind — Display uniqueness
// ---------------------------------------------------------------------------

fn all_gap_kinds() -> Vec<MetadataGapKind> {
    vec![
        MetadataGapKind::MissingObservationChannels,
        MetadataGapKind::MissingActionChannels,
        MetadataGapKind::MissingStateChannels,
        MetadataGapKind::MissingActuationBounds,
        MetadataGapKind::MissingDeterministicFallback,
    ]
}

#[test]
fn enrichment_metadata_gap_kind_display_uniqueness() {
    let kinds = all_gap_kinds();
    let strings: BTreeSet<String> = kinds.iter().map(|k| k.to_string()).collect();
    assert_eq!(strings.len(), kinds.len());
}

#[test]
fn enrichment_metadata_gap_kind_as_str_consistency() {
    for kind in all_gap_kinds() {
        assert_eq!(kind.as_str(), format!("{kind}"));
    }
}

#[test]
fn enrichment_metadata_gap_kind_serde_roundtrip() {
    for kind in all_gap_kinds() {
        let json = serde_json::to_string(&kind).unwrap();
        let back: MetadataGapKind = serde_json::from_str(&json).unwrap();
        assert_eq!(kind, back);
    }
}

// ---------------------------------------------------------------------------
// EdgeUncertainty — Display uniqueness
// ---------------------------------------------------------------------------

fn all_edge_uncertainties() -> Vec<EdgeUncertainty> {
    vec![
        EdgeUncertainty::Observed,
        EdgeUncertainty::Partial,
        EdgeUncertainty::Unknown,
    ]
}

#[test]
fn enrichment_edge_uncertainty_display_uniqueness() {
    let variants = all_edge_uncertainties();
    let strings: BTreeSet<String> = variants.iter().map(|v| v.to_string()).collect();
    assert_eq!(strings.len(), variants.len());
}

#[test]
fn enrichment_edge_uncertainty_as_str_consistency() {
    for unc in all_edge_uncertainties() {
        assert_eq!(unc.as_str(), format!("{unc}"));
    }
}

#[test]
fn enrichment_edge_uncertainty_serde_roundtrip() {
    for unc in all_edge_uncertainties() {
        let json = serde_json::to_string(&unc).unwrap();
        let back: EdgeUncertainty = serde_json::from_str(&json).unwrap();
        assert_eq!(unc, back);
    }
}

// ---------------------------------------------------------------------------
// GateVerdict — Display uniqueness
// ---------------------------------------------------------------------------

#[test]
fn enrichment_gate_verdict_display_uniqueness() {
    let verdicts = [GateVerdict::Approved, GateVerdict::Rejected];
    let strings: BTreeSet<String> = verdicts.iter().map(|v| v.to_string()).collect();
    assert_eq!(strings.len(), verdicts.len());
}

#[test]
fn enrichment_gate_verdict_serde_roundtrip() {
    for verdict in &[GateVerdict::Approved, GateVerdict::Rejected] {
        let json = serde_json::to_string(verdict).unwrap();
        let back: GateVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(*verdict, back);
    }
}

// ---------------------------------------------------------------------------
// GateFailureReason — Display uniqueness
// ---------------------------------------------------------------------------

fn all_gate_failure_reasons() -> Vec<GateFailureReason> {
    vec![
        GateFailureReason::MutuallyExclusiveRoles {
            role_a: ControllerRole::Router,
            role_b: ControllerRole::Router,
            controller_a: "alpha".to_string(),
            controller_b: "beta".to_string(),
        },
        GateFailureReason::InsufficientTimescaleSeparation {
            controller_a: "ctrl_x".to_string(),
            controller_b: "ctrl_y".to_string(),
            required_millionths: 100_000,
            actual_millionths: 10_000,
        },
        GateFailureReason::MicrobenchBudgetExceeded {
            pair: "x vs y".to_string(),
            cost_millionths: 900_000,
            budget_millionths: 500_000,
        },
        GateFailureReason::InvalidTimescale {
            controller_name: "broken".to_string(),
            detail: "negative write interval".to_string(),
        },
        GateFailureReason::DuplicateController {
            controller_name: "dupe".to_string(),
        },
        GateFailureReason::EmptyDeployment,
    ]
}

#[test]
fn enrichment_gate_failure_reason_display_uniqueness() {
    let reasons = all_gate_failure_reasons();
    let strings: BTreeSet<String> = reasons.iter().map(|r| r.to_string()).collect();
    assert_eq!(strings.len(), reasons.len());
}

#[test]
fn enrichment_gate_failure_reason_serde_all_variants() {
    for reason in all_gate_failure_reasons() {
        let json = serde_json::to_string(&reason).unwrap();
        let back: GateFailureReason = serde_json::from_str(&json).unwrap();
        assert_eq!(reason, back);
    }
}

#[test]
fn enrichment_gate_failure_reason_display_contains_controller_names() {
    let reason = GateFailureReason::MutuallyExclusiveRoles {
        role_a: ControllerRole::Fallback,
        role_b: ControllerRole::Fallback,
        controller_a: "fb_primary".to_string(),
        controller_b: "fb_secondary".to_string(),
    };
    let display = format!("{reason}");
    assert!(display.contains("fb_primary"));
    assert!(display.contains("fb_secondary"));
    assert!(display.contains("fallback"));
}

// ---------------------------------------------------------------------------
// ControllerRegistryError — Display
// ---------------------------------------------------------------------------

#[test]
fn enrichment_controller_registry_error_display_duplicate() {
    let err = ControllerRegistryError::DuplicateController {
        controller_name: "dup_ctrl".to_string(),
    };
    let display = format!("{err}");
    assert!(display.contains("dup_ctrl"));
    assert!(display.contains("duplicate"));
}

#[test]
fn enrichment_controller_registry_error_display_invalid_timescale() {
    let err = ControllerRegistryError::InvalidTimescale {
        controller_name: "bad_ctrl".to_string(),
        observation_interval_millionths: -1,
        write_interval_millionths: 0,
    };
    let display = format!("{err}");
    assert!(display.contains("bad_ctrl"));
    assert!(display.contains("-1"));
}

#[test]
fn enrichment_controller_registry_error_display_invalid_actuation_bound() {
    let err = ControllerRegistryError::InvalidActuationBound {
        controller_name: "ctrl_ab".to_string(),
        channel: "throttle".to_string(),
        lower_bound_millionths: 500_000,
        upper_bound_millionths: 100_000,
    };
    let display = format!("{err}");
    assert!(display.contains("ctrl_ab"));
    assert!(display.contains("throttle"));
}

#[test]
fn enrichment_controller_registry_error_serde_roundtrip() {
    let errors = vec![
        ControllerRegistryError::DuplicateController {
            controller_name: "dup".to_string(),
        },
        ControllerRegistryError::InvalidTimescale {
            controller_name: "bad".to_string(),
            observation_interval_millionths: -5,
            write_interval_millionths: 0,
        },
        ControllerRegistryError::InvalidActuationBound {
            controller_name: "ctrl".to_string(),
            channel: "ch".to_string(),
            lower_bound_millionths: 100,
            upper_bound_millionths: 50,
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let back: ControllerRegistryError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, back);
    }
}

// ---------------------------------------------------------------------------
// Serde roundtrips for struct types
// ---------------------------------------------------------------------------

#[test]
fn enrichment_matrix_entry_serde_roundtrip() {
    let entry = MatrixEntry {
        role_a: ControllerRole::Optimizer,
        role_b: ControllerRole::Custom,
        interaction: InteractionClass::WriteConflict,
        min_timescale_separation_millionths: 300_000,
        rationale: "potential tuning knob clash".to_string(),
    };
    let json = serde_json::to_string(&entry).unwrap();
    let back: MatrixEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, back);
}

#[test]
fn enrichment_controller_timescale_serde_roundtrip() {
    let ts = make_timescale("ctrl_ts", ControllerRole::Fallback, 250_000, 750_000);
    let json = serde_json::to_string(&ts).unwrap();
    let back: ControllerTimescale = serde_json::from_str(&json).unwrap();
    assert_eq!(ts, back);
}

#[test]
fn enrichment_deterministic_fallback_serde_roundtrip() {
    let fb = DeterministicFallback {
        fallback_mode: "passthrough".to_string(),
        trigger: "error_rate > 5%".to_string(),
        detail: "switch to passthrough on high error rate".to_string(),
    };
    let json = serde_json::to_string(&fb).unwrap();
    let back: DeterministicFallback = serde_json::from_str(&json).unwrap();
    assert_eq!(fb, back);
}

#[test]
fn enrichment_actuation_bound_serde_roundtrip() {
    let bound = ActuationBound {
        channel: "throttle".to_string(),
        lower_bound_millionths: 0,
        upper_bound_millionths: 1_000_000,
        units: "fraction".to_string(),
    };
    let json = serde_json::to_string(&bound).unwrap();
    let back: ActuationBound = serde_json::from_str(&json).unwrap();
    assert_eq!(bound, back);
}

#[test]
fn enrichment_controller_contract_serde_roundtrip() {
    let contract = make_full_contract("roundtrip_ctrl", ControllerRole::Optimizer);
    let json = serde_json::to_string(&contract).unwrap();
    let back: ControllerContract = serde_json::from_str(&json).unwrap();
    assert_eq!(contract, back);
}

#[test]
fn enrichment_controller_metadata_gap_serde_roundtrip() {
    let gap = ControllerMetadataGap {
        controller_name: "ctrl_gap".to_string(),
        gap: MetadataGapKind::MissingActionChannels,
        detail: "no actions declared".to_string(),
    };
    let json = serde_json::to_string(&gap).unwrap();
    let back: ControllerMetadataGap = serde_json::from_str(&json).unwrap();
    assert_eq!(gap, back);
}

#[test]
fn enrichment_controller_interaction_edge_serde_roundtrip() {
    let edge = ControllerInteractionEdge {
        controller_a: "a_ctrl".to_string(),
        controller_b: "b_ctrl".to_string(),
        interaction: InteractionClass::ProducerConsumer,
        observed_channel_overlap: vec!["metric_x".to_string()],
        shared_resource_overlap: vec!["bus_z".to_string()],
        timescale_separation_millionths: 500_000,
        coupling_score_millionths: 350_000,
        uncertainty: EdgeUncertainty::Observed,
        rationale: "producer-consumer coupling".to_string(),
    };
    let json = serde_json::to_string(&edge).unwrap();
    let back: ControllerInteractionEdge = serde_json::from_str(&json).unwrap();
    assert_eq!(edge, back);
}

#[test]
fn enrichment_controller_operator_graph_serde_roundtrip() {
    let graph = ControllerOperatorGraph {
        schema_version: CONTROLLER_OPERATOR_GRAPH_SCHEMA_VERSION.to_string(),
        graph_id: "graph-test-001".to_string(),
        controller_names: vec!["ctrl_a".to_string(), "ctrl_b".to_string()],
        edges: vec![],
    };
    let json = serde_json::to_string(&graph).unwrap();
    let back: ControllerOperatorGraph = serde_json::from_str(&json).unwrap();
    assert_eq!(graph, back);
}

#[test]
fn enrichment_controller_telemetry_snapshot_serde_roundtrip() {
    let snap = ControllerTelemetrySnapshot {
        schema_version: CONTROLLER_TELEMETRY_SNAPSHOT_SCHEMA_VERSION.to_string(),
        controller_count: 3,
        edge_count: 3,
        partial_edge_count: 1,
        unknown_edge_count: 0,
        max_coupling_score_millionths: 400_000,
        fallback_ready_controllers: vec!["fb_ctrl".to_string()],
        shared_resource_hotspots: vec!["bus".to_string()],
    };
    let json = serde_json::to_string(&snap).unwrap();
    let back: ControllerTelemetrySnapshot = serde_json::from_str(&json).unwrap();
    assert_eq!(snap, back);
}

#[test]
fn enrichment_spectral_edge_trace_serde_roundtrip() {
    let trace = SpectralEdgeTrace {
        schema_version: SPECTRAL_EDGE_TRACE_SCHEMA_VERSION.to_string(),
        edge_id: "edge-abcdef0123".to_string(),
        controller_a: "ctrl_a".to_string(),
        controller_b: "ctrl_b".to_string(),
        interaction: "producer_consumer".to_string(),
        timescale_ratio_millionths: 500_000,
        coupling_score_millionths: 350_000,
        active_warning: false,
    };
    let json = serde_json::to_string(&trace).unwrap();
    let back: SpectralEdgeTrace = serde_json::from_str(&json).unwrap();
    assert_eq!(trace, back);
}

#[test]
fn enrichment_controller_edge_uncertainty_entry_serde_roundtrip() {
    let entry = ControllerEdgeUncertaintyEntry {
        schema_version: CONTROLLER_EDGE_UNCERTAINTY_SCHEMA_VERSION.to_string(),
        controller_a: "x".to_string(),
        controller_b: "y".to_string(),
        uncertainty: EdgeUncertainty::Partial,
        reasons: vec!["no_shared_resource_overlap_declared".to_string()],
    };
    let json = serde_json::to_string(&entry).unwrap();
    let back: ControllerEdgeUncertaintyEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, back);
}

#[test]
fn enrichment_microbench_config_serde_roundtrip() {
    let config = MicrobenchConfig {
        max_iterations: 500,
        budget_cap_millionths: 5_000_000,
        min_iterations: 20,
    };
    let json = serde_json::to_string(&config).unwrap();
    let back: MicrobenchConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, back);
}

#[test]
fn enrichment_microbench_entry_serde_roundtrip() {
    let entry = MicrobenchEntry {
        controller_a: "ctrl_a".to_string(),
        role_a: ControllerRole::Router,
        controller_b: "ctrl_b".to_string(),
        role_b: ControllerRole::Monitor,
        interference_cost_millionths: 1_500,
        iterations: 100,
        budget_exceeded: false,
    };
    let json = serde_json::to_string(&entry).unwrap();
    let back: MicrobenchEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, back);
}

#[test]
fn enrichment_gate_log_event_serde_roundtrip() {
    let event = GateLogEvent {
        trace_id: "trace-001".to_string(),
        gate_id: "gate-abc".to_string(),
        event: "gate_start".to_string(),
        detail: "2 controllers".to_string(),
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: GateLogEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

#[test]
fn enrichment_gate_result_serde_roundtrip_with_microbench() {
    let controllers = vec![
        make_timescale("router", ControllerRole::Router, 100_000, 1_000_000),
        make_timescale("monitor", ControllerRole::Monitor, 50_000, 500_000),
    ];
    let matrix = ControllerCompositionMatrix::default_matrix();
    let config = GateConfig {
        run_microbench: true,
        per_pair_budget_millionths: 100_000_000,
        ..GateConfig::default()
    };
    let result = evaluate_composition_gate("trace-serde-mb", &controllers, &matrix, &config);
    let json = serde_json::to_string(&result).unwrap();
    let back: GateResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, back);
}

#[test]
fn enrichment_operator_summary_serde_roundtrip() {
    let summary = OperatorSummary {
        gate_id: "gate-xyz".to_string(),
        verdict: "rejected".to_string(),
        failure_count: 2,
        controllers: 3,
        pairs: 3,
        microbench_total_cost: Some(750_000),
        lines: vec!["line 1".to_string(), "line 2".to_string()],
    };
    let json = serde_json::to_string(&summary).unwrap();
    let back: OperatorSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary, back);
}

// ---------------------------------------------------------------------------
// ControllerContract — method behavior
// ---------------------------------------------------------------------------

#[test]
fn enrichment_controller_contract_name_and_role() {
    let contract = make_full_contract("my_optimizer", ControllerRole::Optimizer);
    assert_eq!(contract.controller_name(), "my_optimizer");
    assert_eq!(contract.role(), ControllerRole::Optimizer);
}

// ---------------------------------------------------------------------------
// ControllerCompositionMatrix — default_matrix behavior
// ---------------------------------------------------------------------------

#[test]
fn enrichment_default_matrix_entry_count_is_15() {
    let matrix = ControllerCompositionMatrix::default_matrix();
    // 5 roles: C(5,2) + 5 diagonal = 15
    assert_eq!(matrix.entries.len(), 15);
}

#[test]
fn enrichment_default_matrix_schema_version() {
    let matrix = ControllerCompositionMatrix::default_matrix();
    assert_eq!(matrix.schema_version, "1.0.0");
}

#[test]
fn enrichment_default_matrix_all_pairs_covered() {
    let matrix = ControllerCompositionMatrix::default_matrix();
    for &a in ControllerRole::all() {
        for &b in ControllerRole::all() {
            assert!(
                matrix.lookup(a, b).is_some(),
                "missing entry for ({a:?}, {b:?})"
            );
        }
    }
}

#[test]
fn enrichment_default_matrix_symmetry() {
    let matrix = ControllerCompositionMatrix::default_matrix();
    for &a in ControllerRole::all() {
        for &b in ControllerRole::all() {
            let ab = matrix.lookup(a, b).unwrap();
            let ba = matrix.lookup(b, a).unwrap();
            assert_eq!(ab.interaction, ba.interaction, "asymmetry: {a:?} vs {b:?}");
        }
    }
}

#[test]
fn enrichment_default_matrix_blocked_pairs_exactly_router_and_fallback() {
    let matrix = ControllerCompositionMatrix::default_matrix();
    let blocked = matrix.blocked_pairs();
    assert_eq!(blocked.len(), 2);
    let blocked_pairs: BTreeSet<(ControllerRole, ControllerRole)> =
        blocked.iter().map(|e| (e.role_a, e.role_b)).collect();
    assert!(blocked_pairs.contains(&(ControllerRole::Router, ControllerRole::Router)));
    assert!(blocked_pairs.contains(&(ControllerRole::Fallback, ControllerRole::Fallback)));
}

#[test]
fn enrichment_default_matrix_separation_required_pairs_count() {
    let matrix = ControllerCompositionMatrix::default_matrix();
    let sep = matrix.separation_required_pairs();
    // ProducerConsumer + WriteConflict entries
    assert!(sep.len() >= 7);
    for entry in &sep {
        assert!(
            entry.interaction.requires_timescale_separation(),
            "entry {:?}-{:?} should require timescale separation",
            entry.role_a,
            entry.role_b,
        );
    }
}

#[test]
fn enrichment_default_matrix_custom_custom_write_conflict() {
    let matrix = ControllerCompositionMatrix::default_matrix();
    let entry = matrix
        .lookup(ControllerRole::Custom, ControllerRole::Custom)
        .unwrap();
    assert_eq!(entry.interaction, InteractionClass::WriteConflict);
    assert_eq!(entry.min_timescale_separation_millionths, 200_000);
}

// ---------------------------------------------------------------------------
// Matrix — set_entry and lookup
// ---------------------------------------------------------------------------

#[test]
fn enrichment_set_entry_normalizes_role_order() {
    let mut matrix = ControllerCompositionMatrix::default_matrix();
    let entry = MatrixEntry {
        role_a: ControllerRole::Custom,
        role_b: ControllerRole::Router,
        interaction: InteractionClass::Independent,
        min_timescale_separation_millionths: 0,
        rationale: "reversed".to_string(),
    };
    matrix.set_entry(entry);
    let found = matrix
        .lookup(ControllerRole::Router, ControllerRole::Custom)
        .unwrap();
    assert_eq!(found.role_a, ControllerRole::Router);
    assert_eq!(found.role_b, ControllerRole::Custom);
    assert_eq!(found.interaction, InteractionClass::Independent);
}

#[test]
fn enrichment_lookup_empty_matrix_returns_none() {
    let matrix = ControllerCompositionMatrix {
        entries: Vec::new(),
        schema_version: "1.0.0".to_string(),
    };
    assert!(
        matrix
            .lookup(ControllerRole::Router, ControllerRole::Monitor)
            .is_none()
    );
}

// ---------------------------------------------------------------------------
// Matrix — deterministic ID
// ---------------------------------------------------------------------------

#[test]
fn enrichment_matrix_id_deterministic_across_invocations() {
    let m1 = ControllerCompositionMatrix::default_matrix();
    let m2 = ControllerCompositionMatrix::default_matrix();
    assert_eq!(m1.derive_matrix_id(), m2.derive_matrix_id());
}

#[test]
fn enrichment_matrix_id_differs_after_override() {
    let m1 = ControllerCompositionMatrix::default_matrix();
    let mut m2 = ControllerCompositionMatrix::default_matrix();
    m2.set_entry(MatrixEntry {
        role_a: ControllerRole::Monitor,
        role_b: ControllerRole::Custom,
        interaction: InteractionClass::Independent,
        min_timescale_separation_millionths: 0,
        rationale: "override".to_string(),
    });
    assert_ne!(m1.derive_matrix_id(), m2.derive_matrix_id());
}

#[test]
fn enrichment_matrix_serde_roundtrip() {
    let matrix = ControllerCompositionMatrix::default_matrix();
    let json = serde_json::to_string(&matrix).unwrap();
    let back: ControllerCompositionMatrix = serde_json::from_str(&json).unwrap();
    assert_eq!(matrix, back);
    assert_eq!(matrix.derive_matrix_id(), back.derive_matrix_id());
}

// ---------------------------------------------------------------------------
// build_controller_registry
// ---------------------------------------------------------------------------

#[test]
fn enrichment_build_registry_success_with_full_contracts() {
    let contracts = vec![
        make_full_contract("optimizer_1", ControllerRole::Optimizer),
        make_full_contract("router_1", ControllerRole::Router),
    ];
    let registry = build_controller_registry(&contracts).unwrap();
    assert_eq!(registry.schema_version, CONTROLLER_REGISTRY_SCHEMA_VERSION);
    assert_eq!(registry.controllers.len(), 2);
    assert!(registry.metadata_gaps.is_empty());
    assert!(!registry.registry_id.is_empty());
}

#[test]
fn enrichment_build_registry_sorts_controllers_alphabetically() {
    let contracts = vec![
        make_full_contract("z_ctrl", ControllerRole::Router),
        make_full_contract("a_ctrl", ControllerRole::Optimizer),
        make_full_contract("m_ctrl", ControllerRole::Monitor),
    ];
    let registry = build_controller_registry(&contracts).unwrap();
    let names: Vec<&str> = registry
        .controllers
        .iter()
        .map(|c| c.controller_name())
        .collect();
    assert_eq!(names, vec!["a_ctrl", "m_ctrl", "z_ctrl"]);
}

#[test]
fn enrichment_build_registry_rejects_duplicate_controller_name() {
    let contracts = vec![
        make_full_contract("dup_name", ControllerRole::Router),
        make_full_contract("dup_name", ControllerRole::Optimizer),
    ];
    let err = build_controller_registry(&contracts).unwrap_err();
    match err {
        ControllerRegistryError::DuplicateController { controller_name } => {
            assert_eq!(controller_name, "dup_name");
        }
        _ => panic!("expected DuplicateController, got {err:?}"),
    }
}

#[test]
fn enrichment_build_registry_rejects_zero_observation_interval() {
    let contracts = vec![make_contract(
        "bad_obs",
        ControllerRole::Router,
        0,
        1_000_000,
        &["ch"],
        &["act"],
        &["st"],
        &[],
        vec![],
        None,
    )];
    let err = build_controller_registry(&contracts).unwrap_err();
    assert!(matches!(
        err,
        ControllerRegistryError::InvalidTimescale { .. }
    ));
}

#[test]
fn enrichment_build_registry_rejects_negative_write_interval() {
    let contracts = vec![make_contract(
        "neg_write",
        ControllerRole::Monitor,
        1_000_000,
        -1,
        &["ch"],
        &[],
        &["st"],
        &[],
        vec![],
        None,
    )];
    let err = build_controller_registry(&contracts).unwrap_err();
    assert!(matches!(
        err,
        ControllerRegistryError::InvalidTimescale { .. }
    ));
}

#[test]
fn enrichment_build_registry_rejects_inverted_actuation_bounds() {
    let contracts = vec![make_contract(
        "bad_bound",
        ControllerRole::Optimizer,
        1_000_000,
        2_000_000,
        &["ch"],
        &["act"],
        &["st"],
        &[],
        vec![ActuationBound {
            channel: "throttle".to_string(),
            lower_bound_millionths: 800_000,
            upper_bound_millionths: 200_000,
            units: "ppm".to_string(),
        }],
        None,
    )];
    let err = build_controller_registry(&contracts).unwrap_err();
    assert!(matches!(
        err,
        ControllerRegistryError::InvalidActuationBound { .. }
    ));
}

#[test]
fn enrichment_build_registry_detects_metadata_gaps_missing_obs_channels() {
    let contract = make_contract(
        "no_obs",
        ControllerRole::Router,
        1_000_000,
        2_000_000,
        &[], // no observation channels
        &["action"],
        &["state"],
        &[],
        vec![ActuationBound {
            channel: "action".to_string(),
            lower_bound_millionths: 0,
            upper_bound_millionths: 1_000_000,
            units: "ppm".to_string(),
        }],
        Some(DeterministicFallback {
            fallback_mode: "static".to_string(),
            trigger: "err".to_string(),
            detail: "det".to_string(),
        }),
    );
    let registry = build_controller_registry(&[contract]).unwrap();
    assert!(
        registry
            .metadata_gaps
            .iter()
            .any(|g| g.gap == MetadataGapKind::MissingObservationChannels)
    );
}

#[test]
fn enrichment_build_registry_detects_missing_fallback_for_adaptive() {
    let contract = make_contract(
        "no_fb",
        ControllerRole::Optimizer,
        1_000_000,
        2_000_000,
        &["obs"],
        &["act"],
        &["state"],
        &[],
        vec![ActuationBound {
            channel: "act".to_string(),
            lower_bound_millionths: 0,
            upper_bound_millionths: 1_000_000,
            units: "ppm".to_string(),
        }],
        None, // no fallback
    );
    let registry = build_controller_registry(&[contract]).unwrap();
    assert!(
        registry
            .metadata_gaps
            .iter()
            .any(|g| g.gap == MetadataGapKind::MissingDeterministicFallback)
    );
}

#[test]
fn enrichment_build_registry_monitor_no_action_channels_no_gap() {
    // Monitors are exempt from MissingActionChannels
    let contract = make_monitor_contract("mon_ok");
    let registry = build_controller_registry(&[contract]).unwrap();
    assert!(
        !registry
            .metadata_gaps
            .iter()
            .any(|g| g.gap == MetadataGapKind::MissingActionChannels),
        "monitor should not get MissingActionChannels gap"
    );
}

#[test]
fn enrichment_build_registry_deterministic_id() {
    let contracts = vec![make_full_contract("ctrl_det", ControllerRole::Router)];
    let r1 = build_controller_registry(&contracts).unwrap();
    let r2 = build_controller_registry(&contracts).unwrap();
    assert_eq!(r1.registry_id, r2.registry_id);
}

// ---------------------------------------------------------------------------
// validate_controller_registry
// ---------------------------------------------------------------------------

#[test]
fn enrichment_validate_registry_ship_ready_when_no_gaps() {
    let contracts = vec![make_full_contract("ready", ControllerRole::Router)];
    let registry = build_controller_registry(&contracts).unwrap();
    let report = validate_controller_registry(&registry);
    assert!(report.ship_ready);
    assert!(report.metadata_gaps.is_empty());
    assert_eq!(report.schema_version, CONTROLLER_REGISTRY_SCHEMA_VERSION);
}

#[test]
fn enrichment_validate_registry_not_ship_ready_when_gaps_exist() {
    let contract = make_contract(
        "incomplete",
        ControllerRole::Router,
        1_000_000,
        2_000_000,
        &[],
        &[],
        &[],
        &[],
        vec![],
        None,
    );
    let registry = build_controller_registry(&[contract]).unwrap();
    let report = validate_controller_registry(&registry);
    assert!(!report.ship_ready);
    assert!(!report.metadata_gaps.is_empty());
}

// ---------------------------------------------------------------------------
// derive_controller_operator_graph
// ---------------------------------------------------------------------------

#[test]
fn enrichment_derive_operator_graph_two_controllers() {
    let contracts = vec![
        make_full_contract("ctrl_a", ControllerRole::Router),
        make_full_contract("ctrl_b", ControllerRole::Optimizer),
    ];
    let registry = build_controller_registry(&contracts).unwrap();
    let matrix = ControllerCompositionMatrix::default_matrix();
    let graph = derive_controller_operator_graph(&registry, &matrix);

    assert_eq!(
        graph.schema_version,
        CONTROLLER_OPERATOR_GRAPH_SCHEMA_VERSION
    );
    assert_eq!(graph.controller_names.len(), 2);
    assert_eq!(graph.edges.len(), 1);
    assert!(!graph.graph_id.is_empty());
    assert!(graph.graph_id.starts_with("graph-"));
}

#[test]
fn enrichment_derive_operator_graph_three_controllers_three_edges() {
    let contracts = vec![
        make_full_contract("a", ControllerRole::Router),
        make_full_contract("b", ControllerRole::Optimizer),
        make_full_contract("c", ControllerRole::Monitor),
    ];
    let registry = build_controller_registry(&contracts).unwrap();
    let matrix = ControllerCompositionMatrix::default_matrix();
    let graph = derive_controller_operator_graph(&registry, &matrix);
    assert_eq!(graph.edges.len(), 3);
}

#[test]
fn enrichment_derive_operator_graph_shared_resource_overlap() {
    let contracts = vec![
        make_contract(
            "ctrl_x",
            ControllerRole::Router,
            1_000_000,
            2_000_000,
            &["obs"],
            &["act"],
            &["st"],
            &["shared_bus", "memory_pool"],
            vec![ActuationBound {
                channel: "act".to_string(),
                lower_bound_millionths: 0,
                upper_bound_millionths: 1_000_000,
                units: "ppm".to_string(),
            }],
            Some(DeterministicFallback {
                fallback_mode: "static".to_string(),
                trigger: "err".to_string(),
                detail: "det".to_string(),
            }),
        ),
        make_contract(
            "ctrl_y",
            ControllerRole::Optimizer,
            1_000_000,
            3_000_000,
            &["obs"],
            &["act"],
            &["st"],
            &["shared_bus"],
            vec![ActuationBound {
                channel: "act".to_string(),
                lower_bound_millionths: 0,
                upper_bound_millionths: 1_000_000,
                units: "ppm".to_string(),
            }],
            Some(DeterministicFallback {
                fallback_mode: "static".to_string(),
                trigger: "err".to_string(),
                detail: "det".to_string(),
            }),
        ),
    ];
    let registry = build_controller_registry(&contracts).unwrap();
    let matrix = ControllerCompositionMatrix::default_matrix();
    let graph = derive_controller_operator_graph(&registry, &matrix);
    assert_eq!(graph.edges.len(), 1);
    assert!(
        graph.edges[0]
            .shared_resource_overlap
            .contains(&"shared_bus".to_string())
    );
}

#[test]
fn enrichment_derive_operator_graph_deterministic_id() {
    let contracts = vec![make_full_contract("det_ctrl", ControllerRole::Monitor)];
    let registry = build_controller_registry(&contracts).unwrap();
    let matrix = ControllerCompositionMatrix::default_matrix();
    let g1 = derive_controller_operator_graph(&registry, &matrix);
    let g2 = derive_controller_operator_graph(&registry, &matrix);
    assert_eq!(g1.graph_id, g2.graph_id);
}

// ---------------------------------------------------------------------------
// build_controller_telemetry_snapshot
// ---------------------------------------------------------------------------

#[test]
fn enrichment_telemetry_snapshot_counts() {
    let contracts = vec![
        make_full_contract("t_a", ControllerRole::Router),
        make_full_contract("t_b", ControllerRole::Optimizer),
        make_monitor_contract("t_c"),
    ];
    let registry = build_controller_registry(&contracts).unwrap();
    let matrix = ControllerCompositionMatrix::default_matrix();
    let graph = derive_controller_operator_graph(&registry, &matrix);
    let snap = build_controller_telemetry_snapshot(&registry, &graph);

    assert_eq!(
        snap.schema_version,
        CONTROLLER_TELEMETRY_SNAPSHOT_SCHEMA_VERSION
    );
    assert_eq!(snap.controller_count, 3);
    assert_eq!(snap.edge_count, 3);
}

#[test]
fn enrichment_telemetry_snapshot_fallback_ready_controllers() {
    let contracts = vec![
        make_full_contract("fb_ready", ControllerRole::Router),
        make_monitor_contract("no_fb"),
    ];
    let registry = build_controller_registry(&contracts).unwrap();
    let matrix = ControllerCompositionMatrix::default_matrix();
    let graph = derive_controller_operator_graph(&registry, &matrix);
    let snap = build_controller_telemetry_snapshot(&registry, &graph);
    assert!(
        snap.fallback_ready_controllers
            .contains(&"fb_ready".to_string())
    );
    assert!(
        !snap
            .fallback_ready_controllers
            .contains(&"no_fb".to_string())
    );
}

// ---------------------------------------------------------------------------
// build_spectral_edge_traces
// ---------------------------------------------------------------------------

#[test]
fn enrichment_spectral_edge_traces_match_graph_edge_count() {
    let contracts = vec![
        make_full_contract("sp_a", ControllerRole::Router),
        make_full_contract("sp_b", ControllerRole::Optimizer),
    ];
    let registry = build_controller_registry(&contracts).unwrap();
    let matrix = ControllerCompositionMatrix::default_matrix();
    let graph = derive_controller_operator_graph(&registry, &matrix);
    let traces = build_spectral_edge_traces(&graph);
    assert_eq!(traces.len(), graph.edges.len());
}

#[test]
fn enrichment_spectral_edge_trace_schema_version() {
    let contracts = vec![
        make_full_contract("sv_a", ControllerRole::Router),
        make_full_contract("sv_b", ControllerRole::Monitor),
    ];
    let registry = build_controller_registry(&contracts).unwrap();
    let matrix = ControllerCompositionMatrix::default_matrix();
    let graph = derive_controller_operator_graph(&registry, &matrix);
    let traces = build_spectral_edge_traces(&graph);
    for trace in &traces {
        assert_eq!(trace.schema_version, SPECTRAL_EDGE_TRACE_SCHEMA_VERSION);
        assert!(trace.edge_id.starts_with("edge-"));
    }
}

#[test]
fn enrichment_spectral_edge_trace_high_coupling_triggers_warning() {
    // Two optimizers same timescale => WriteConflict, high coupling
    let contracts = vec![
        make_contract(
            "opt1",
            ControllerRole::Optimizer,
            1_000_000,
            1_000_000,
            &["obs"],
            &["act"],
            &["st"],
            &["bus"],
            vec![ActuationBound {
                channel: "act".to_string(),
                lower_bound_millionths: 0,
                upper_bound_millionths: 1_000_000,
                units: "ppm".to_string(),
            }],
            Some(DeterministicFallback {
                fallback_mode: "s".to_string(),
                trigger: "t".to_string(),
                detail: "d".to_string(),
            }),
        ),
        make_contract(
            "opt2",
            ControllerRole::Optimizer,
            1_000_000,
            1_000_000,
            &["obs"],
            &["act"],
            &["st"],
            &["bus"],
            vec![ActuationBound {
                channel: "act".to_string(),
                lower_bound_millionths: 0,
                upper_bound_millionths: 1_000_000,
                units: "ppm".to_string(),
            }],
            Some(DeterministicFallback {
                fallback_mode: "s".to_string(),
                trigger: "t".to_string(),
                detail: "d".to_string(),
            }),
        ),
    ];
    let registry = build_controller_registry(&contracts).unwrap();
    let matrix = ControllerCompositionMatrix::default_matrix();
    let graph = derive_controller_operator_graph(&registry, &matrix);
    let traces = build_spectral_edge_traces(&graph);
    assert_eq!(traces.len(), 1);
    // Same timescale + WriteConflict -> high coupling -> should trigger warning
    assert!(
        traces[0].coupling_score_millionths >= 700_000 || traces[0].active_warning,
        "high coupling should set active_warning"
    );
}

// ---------------------------------------------------------------------------
// build_controller_edge_uncertainty_ledger
// ---------------------------------------------------------------------------

#[test]
fn enrichment_uncertainty_ledger_empty_for_observed_edges() {
    let contracts = vec![
        make_full_contract("obs_a", ControllerRole::Router),
        make_full_contract("obs_b", ControllerRole::Monitor),
    ];
    let registry = build_controller_registry(&contracts).unwrap();
    let matrix = ControllerCompositionMatrix::default_matrix();
    let graph = derive_controller_operator_graph(&registry, &matrix);
    let ledger = build_controller_edge_uncertainty_ledger(&registry, &graph);
    for entry in &ledger {
        assert_ne!(entry.uncertainty, EdgeUncertainty::Observed);
    }
}

#[test]
fn enrichment_uncertainty_ledger_captures_partial_edges() {
    // Missing shared resources => Partial uncertainty for ReadShared/Independent
    let contract_a = make_contract(
        "partial_a",
        ControllerRole::Monitor,
        1_000_000,
        2_000_000,
        &["obs"],
        &[],
        &["st"],
        &[], // no shared resources
        vec![],
        None,
    );
    let contract_b = make_contract(
        "partial_b",
        ControllerRole::Monitor,
        1_000_000,
        3_000_000,
        &["obs"],
        &[],
        &["st"],
        &[], // no shared resources
        vec![],
        None,
    );
    let registry = build_controller_registry(&[contract_a, contract_b]).unwrap();
    let matrix = ControllerCompositionMatrix::default_matrix();
    let graph = derive_controller_operator_graph(&registry, &matrix);
    let ledger = build_controller_edge_uncertainty_ledger(&registry, &graph);
    // Monitor-Monitor is ReadShared, missing shared_resources -> Partial
    assert!(!ledger.is_empty());
    assert!(
        ledger
            .iter()
            .any(|e| e.uncertainty == EdgeUncertainty::Partial)
    );
}

// ---------------------------------------------------------------------------
// Microbench harness
// ---------------------------------------------------------------------------

#[test]
fn enrichment_microbench_default_config_values() {
    let config = MicrobenchConfig::default();
    assert_eq!(config.max_iterations, 1_000);
    assert_eq!(config.budget_cap_millionths, 10_000_000);
    assert_eq!(config.min_iterations, 10);
}

#[test]
fn enrichment_microbench_empty_controllers_zero_cost() {
    let matrix = ControllerCompositionMatrix::default_matrix();
    let result = run_microbench(&[], &matrix, &MicrobenchConfig::default());
    assert_eq!(result.pairs_measured, 0);
    assert_eq!(result.total_cost_millionths, 0);
    assert_eq!(result.max_pair_cost_millionths, 0);
    assert_eq!(result.pairs_over_budget, 0);
}

#[test]
fn enrichment_microbench_single_controller_no_pairs() {
    let controllers = vec![make_timescale(
        "solo",
        ControllerRole::Router,
        100_000,
        1_000_000,
    )];
    let matrix = ControllerCompositionMatrix::default_matrix();
    let result = run_microbench(&controllers, &matrix, &MicrobenchConfig::default());
    assert_eq!(result.pairs_measured, 0);
}

#[test]
fn enrichment_microbench_independent_pair_low_base_cost() {
    let controllers = vec![
        make_timescale("mon1", ControllerRole::Monitor, 100_000, 1_000_000),
        make_timescale("mon2", ControllerRole::Monitor, 200_000, 2_000_000),
    ];
    let matrix = ControllerCompositionMatrix::default_matrix();
    let result = run_microbench(&controllers, &matrix, &MicrobenchConfig::default());
    assert_eq!(result.pairs_measured, 1);
    // ReadShared base = 1000 + proximity penalty
    assert!(result.total_cost_millionths > 0);
}

#[test]
fn enrichment_microbench_mutually_exclusive_million_base_cost() {
    let controllers = vec![
        make_timescale("r1", ControllerRole::Router, 100_000, 100_000),
        make_timescale("r2", ControllerRole::Router, 100_000, 100_000),
    ];
    let matrix = ControllerCompositionMatrix::default_matrix();
    let result = run_microbench(&controllers, &matrix, &MicrobenchConfig::default());
    // MutuallyExclusive base = 1_000_000 + same timescale penalty 100_000
    assert!(result.max_pair_cost_millionths >= 1_000_000);
}

#[test]
fn enrichment_microbench_budget_exceeded_flag_set() {
    let controllers = vec![
        make_timescale("r1", ControllerRole::Router, 100_000, 100_000),
        make_timescale("r2", ControllerRole::Router, 100_000, 100_000),
    ];
    let matrix = ControllerCompositionMatrix::default_matrix();
    let config = MicrobenchConfig {
        budget_cap_millionths: 1, // impossibly low
        ..MicrobenchConfig::default()
    };
    let result = run_microbench(&controllers, &matrix, &config);
    assert!(result.pairs_over_budget > 0);
    assert!(result.entries[0].budget_exceeded);
}

#[test]
fn enrichment_microbench_four_controllers_six_pairs() {
    let controllers = vec![
        make_timescale("r", ControllerRole::Router, 100_000, 1_000_000),
        make_timescale("o", ControllerRole::Optimizer, 200_000, 2_000_000),
        make_timescale("f", ControllerRole::Fallback, 300_000, 3_000_000),
        make_timescale("m", ControllerRole::Monitor, 50_000, 500_000),
    ];
    let matrix = ControllerCompositionMatrix::default_matrix();
    let result = run_microbench(&controllers, &matrix, &MicrobenchConfig::default());
    assert_eq!(result.pairs_measured, 6);
}

#[test]
fn enrichment_microbench_deterministic_cost() {
    let controllers = vec![
        make_timescale("r", ControllerRole::Router, 100_000, 1_000_000),
        make_timescale("o", ControllerRole::Optimizer, 200_000, 2_000_000),
    ];
    let matrix = ControllerCompositionMatrix::default_matrix();
    let config = MicrobenchConfig::default();
    let r1 = run_microbench(&controllers, &matrix, &config);
    let r2 = run_microbench(&controllers, &matrix, &config);
    assert_eq!(r1.total_cost_millionths, r2.total_cost_millionths);
    assert_eq!(r1.max_pair_cost_millionths, r2.max_pair_cost_millionths);
}

// ---------------------------------------------------------------------------
// Acceptance gate (evaluate_composition_gate)
// ---------------------------------------------------------------------------

#[test]
fn enrichment_gate_empty_deployment_rejected() {
    let matrix = ControllerCompositionMatrix::default_matrix();
    let config = GateConfig::default();
    let result = evaluate_composition_gate("t-empty", &[], &matrix, &config);
    assert!(!result.is_approved());
    assert!(
        result
            .failures
            .iter()
            .any(|f| matches!(f, GateFailureReason::EmptyDeployment))
    );
    assert_eq!(result.controllers_evaluated, 0);
    assert_eq!(result.pairs_evaluated, 0);
}

#[test]
fn enrichment_gate_single_valid_controller_approved() {
    let controllers = vec![make_timescale(
        "solo",
        ControllerRole::Router,
        100_000,
        1_000_000,
    )];
    let matrix = ControllerCompositionMatrix::default_matrix();
    let config = GateConfig {
        run_microbench: false,
        ..GateConfig::default()
    };
    let result = evaluate_composition_gate("t-solo", &controllers, &matrix, &config);
    assert!(result.is_approved());
    assert_eq!(result.pairs_evaluated, 0);
}

#[test]
fn enrichment_gate_duplicate_controller_name_rejected() {
    let controllers = vec![
        make_timescale("same", ControllerRole::Monitor, 100_000, 1_000_000),
        make_timescale("same", ControllerRole::Monitor, 200_000, 2_000_000),
    ];
    let matrix = ControllerCompositionMatrix::default_matrix();
    let config = GateConfig {
        run_microbench: false,
        ..GateConfig::default()
    };
    let result = evaluate_composition_gate("t-dup", &controllers, &matrix, &config);
    assert!(!result.is_approved());
    assert!(
        result
            .failures
            .iter()
            .any(|f| matches!(f, GateFailureReason::DuplicateController { .. }))
    );
}

#[test]
fn enrichment_gate_zero_observation_interval_rejected() {
    let controllers = vec![make_timescale(
        "bad_obs",
        ControllerRole::Monitor,
        0,
        1_000_000,
    )];
    let matrix = ControllerCompositionMatrix::default_matrix();
    let config = GateConfig {
        run_microbench: false,
        ..GateConfig::default()
    };
    let result = evaluate_composition_gate("t-bad-obs", &controllers, &matrix, &config);
    assert!(!result.is_approved());
    assert!(
        result
            .failures
            .iter()
            .any(|f| matches!(f, GateFailureReason::InvalidTimescale { .. }))
    );
}

#[test]
fn enrichment_gate_negative_write_interval_rejected() {
    let controllers = vec![make_timescale(
        "neg_w",
        ControllerRole::Monitor,
        100_000,
        -5,
    )];
    let matrix = ControllerCompositionMatrix::default_matrix();
    let config = GateConfig {
        run_microbench: false,
        ..GateConfig::default()
    };
    let result = evaluate_composition_gate("t-neg-w", &controllers, &matrix, &config);
    assert!(!result.is_approved());
}

#[test]
fn enrichment_gate_mutually_exclusive_routers_rejected() {
    let controllers = vec![
        make_timescale("router_a", ControllerRole::Router, 100_000, 1_000_000),
        make_timescale("router_b", ControllerRole::Router, 200_000, 2_000_000),
    ];
    let matrix = ControllerCompositionMatrix::default_matrix();
    let config = GateConfig {
        run_microbench: false,
        ..GateConfig::default()
    };
    let result = evaluate_composition_gate("t-routers", &controllers, &matrix, &config);
    assert!(!result.is_approved());
    assert!(result.failures.iter().any(|f| matches!(
        f,
        GateFailureReason::MutuallyExclusiveRoles {
            role_a: ControllerRole::Router,
            role_b: ControllerRole::Router,
            ..
        }
    )));
}

#[test]
fn enrichment_gate_insufficient_timescale_separation_rejected() {
    // Router-Optimizer requires 100_000 separation; same write interval => 0 separation
    let controllers = vec![
        make_timescale("router", ControllerRole::Router, 100_000, 100_000),
        make_timescale("optimizer", ControllerRole::Optimizer, 100_000, 100_000),
    ];
    let matrix = ControllerCompositionMatrix::default_matrix();
    let config = GateConfig {
        run_microbench: false,
        ..GateConfig::default()
    };
    let result = evaluate_composition_gate("t-insuf-sep", &controllers, &matrix, &config);
    assert!(!result.is_approved());
    assert!(
        result
            .failures
            .iter()
            .any(|f| matches!(f, GateFailureReason::InsufficientTimescaleSeparation { .. }))
    );
}

#[test]
fn enrichment_gate_sufficient_timescale_separation_approved() {
    let controllers = vec![
        make_timescale("router", ControllerRole::Router, 100_000, 100_000),
        make_timescale("optimizer", ControllerRole::Optimizer, 200_000, 500_000),
    ];
    let matrix = ControllerCompositionMatrix::default_matrix();
    let config = GateConfig {
        run_microbench: false,
        ..GateConfig::default()
    };
    let result = evaluate_composition_gate("t-suf-sep", &controllers, &matrix, &config);
    assert!(result.is_approved());
}

#[test]
fn enrichment_gate_microbench_budget_failure() {
    let controllers = vec![
        make_timescale("opt1", ControllerRole::Optimizer, 100_000, 100_000),
        make_timescale("opt2", ControllerRole::Optimizer, 100_000, 100_000),
    ];
    let matrix = ControllerCompositionMatrix::default_matrix();
    let config = GateConfig {
        run_microbench: true,
        per_pair_budget_millionths: 1,
        ..GateConfig::default()
    };
    let result = evaluate_composition_gate("t-mb-fail", &controllers, &matrix, &config);
    assert!(!result.is_approved());
    assert!(
        result
            .failures
            .iter()
            .any(|f| matches!(f, GateFailureReason::MicrobenchBudgetExceeded { .. }))
    );
}

#[test]
fn enrichment_gate_logs_always_have_start_and_end() {
    let controllers = vec![make_timescale(
        "log_ctrl",
        ControllerRole::Monitor,
        100_000,
        1_000_000,
    )];
    let matrix = ControllerCompositionMatrix::default_matrix();
    let config = GateConfig {
        run_microbench: false,
        ..GateConfig::default()
    };
    let result = evaluate_composition_gate("t-logs", &controllers, &matrix, &config);
    assert!(result.logs.iter().any(|l| l.event == "gate_start"));
    assert!(result.logs.iter().any(|l| l.event == "gate_end"));
}

#[test]
fn enrichment_gate_logs_carry_correct_trace_id() {
    let controllers = vec![make_timescale(
        "tc",
        ControllerRole::Monitor,
        100_000,
        1_000_000,
    )];
    let matrix = ControllerCompositionMatrix::default_matrix();
    let config = GateConfig {
        run_microbench: false,
        ..GateConfig::default()
    };
    let result = evaluate_composition_gate("my-trace-42", &controllers, &matrix, &config);
    for log in &result.logs {
        assert_eq!(log.trace_id, "my-trace-42");
    }
}

#[test]
fn enrichment_gate_id_deterministic_for_same_inputs() {
    let controllers = vec![
        make_timescale("r", ControllerRole::Router, 100_000, 1_000_000),
        make_timescale("m", ControllerRole::Monitor, 50_000, 500_000),
    ];
    let matrix = ControllerCompositionMatrix::default_matrix();
    let config = GateConfig {
        run_microbench: false,
        ..GateConfig::default()
    };
    let r1 = evaluate_composition_gate("same-trace", &controllers, &matrix, &config);
    let r2 = evaluate_composition_gate("same-trace", &controllers, &matrix, &config);
    assert_eq!(r1.gate_id, r2.gate_id);
}

#[test]
fn enrichment_gate_id_differs_for_different_traces() {
    let controllers = vec![make_timescale(
        "c",
        ControllerRole::Monitor,
        100_000,
        1_000_000,
    )];
    let matrix = ControllerCompositionMatrix::default_matrix();
    let config = GateConfig {
        run_microbench: false,
        ..GateConfig::default()
    };
    let r1 = evaluate_composition_gate("trace-alpha", &controllers, &matrix, &config);
    let r2 = evaluate_composition_gate("trace-beta", &controllers, &matrix, &config);
    assert_ne!(r1.gate_id, r2.gate_id);
}

#[test]
fn enrichment_gate_result_evidence_id_deterministic() {
    let controllers = vec![make_timescale(
        "ev",
        ControllerRole::Monitor,
        100_000,
        1_000_000,
    )];
    let matrix = ControllerCompositionMatrix::default_matrix();
    let config = GateConfig {
        run_microbench: false,
        ..GateConfig::default()
    };
    let r1 = evaluate_composition_gate("t-ev", &controllers, &matrix, &config);
    let r2 = evaluate_composition_gate("t-ev", &controllers, &matrix, &config);
    assert_eq!(r1.derive_evidence_id(), r2.derive_evidence_id());
}

#[test]
fn enrichment_gate_multiple_failures_accumulate() {
    // router-a obs=0 => InvalidTimescale + Router-Router => MutuallyExclusive
    let controllers = vec![
        make_timescale("router-a", ControllerRole::Router, 0, 1_000_000),
        make_timescale("router-b", ControllerRole::Router, 200_000, 2_000_000),
    ];
    let matrix = ControllerCompositionMatrix::default_matrix();
    let config = GateConfig {
        run_microbench: false,
        ..GateConfig::default()
    };
    let result = evaluate_composition_gate("t-multi-fail", &controllers, &matrix, &config);
    assert!(!result.is_approved());
    assert!(result.failures.len() >= 2);
}

#[test]
fn enrichment_gate_override_mutually_exclusive_allows_composition() {
    let mut matrix = ControllerCompositionMatrix::default_matrix();
    matrix.set_entry(MatrixEntry {
        role_a: ControllerRole::Router,
        role_b: ControllerRole::Router,
        interaction: InteractionClass::Independent,
        min_timescale_separation_millionths: 0,
        rationale: "override for testing".to_string(),
    });
    let controllers = vec![
        make_timescale("r1", ControllerRole::Router, 100_000, 1_000_000),
        make_timescale("r2", ControllerRole::Router, 200_000, 2_000_000),
    ];
    let config = GateConfig {
        run_microbench: false,
        ..GateConfig::default()
    };
    let result = evaluate_composition_gate("t-override", &controllers, &matrix, &config);
    assert!(result.is_approved());
}

#[test]
fn enrichment_gate_five_controllers_ten_pairs() {
    let controllers = vec![
        make_timescale("r", ControllerRole::Router, 100_000, 100_000),
        make_timescale("o", ControllerRole::Optimizer, 200_000, 1_000_000),
        make_timescale("f", ControllerRole::Fallback, 300_000, 2_000_000),
        make_timescale("m", ControllerRole::Monitor, 50_000, 500_000),
        make_timescale("c", ControllerRole::Custom, 400_000, 3_000_000),
    ];
    let matrix = ControllerCompositionMatrix::default_matrix();
    let config = GateConfig {
        run_microbench: false,
        ..GateConfig::default()
    };
    let result = evaluate_composition_gate("t-five", &controllers, &matrix, &config);
    assert_eq!(result.controllers_evaluated, 5);
    assert_eq!(result.pairs_evaluated, 10);
}

// ---------------------------------------------------------------------------
// GateConfig defaults
// ---------------------------------------------------------------------------

#[test]
fn enrichment_gate_config_default_values() {
    let config = GateConfig::default();
    assert!(config.run_microbench);
    assert_eq!(config.per_pair_budget_millionths, 500_000);
    assert_eq!(config.microbench_config.max_iterations, 1_000);
}

#[test]
fn enrichment_gate_config_serde_roundtrip() {
    let config = GateConfig {
        run_microbench: false,
        microbench_config: MicrobenchConfig {
            max_iterations: 42,
            budget_cap_millionths: 99_999,
            min_iterations: 5,
        },
        per_pair_budget_millionths: 123_456,
    };
    let json = serde_json::to_string(&config).unwrap();
    let back: GateConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, back);
}

// ---------------------------------------------------------------------------
// render_operator_summary
// ---------------------------------------------------------------------------

#[test]
fn enrichment_operator_summary_approved_no_failures() {
    let controllers = vec![
        make_timescale("r", ControllerRole::Router, 100_000, 1_000_000),
        make_timescale("m", ControllerRole::Monitor, 50_000, 500_000),
    ];
    let matrix = ControllerCompositionMatrix::default_matrix();
    let config = GateConfig {
        run_microbench: false,
        ..GateConfig::default()
    };
    let result = evaluate_composition_gate("t-sum-ok", &controllers, &matrix, &config);
    let summary = render_operator_summary(&result);
    assert_eq!(summary.verdict, "approved");
    assert_eq!(summary.failure_count, 0);
    assert_eq!(summary.controllers, 2);
    assert_eq!(summary.pairs, 1);
    assert!(summary.microbench_total_cost.is_none());
}

#[test]
fn enrichment_operator_summary_rejected_has_failure_lines() {
    let controllers = vec![
        make_timescale("ra", ControllerRole::Router, 100_000, 1_000_000),
        make_timescale("rb", ControllerRole::Router, 200_000, 2_000_000),
    ];
    let matrix = ControllerCompositionMatrix::default_matrix();
    let config = GateConfig {
        run_microbench: false,
        ..GateConfig::default()
    };
    let result = evaluate_composition_gate("t-sum-rej", &controllers, &matrix, &config);
    let summary = render_operator_summary(&result);
    assert_eq!(summary.verdict, "rejected");
    assert!(summary.failure_count > 0);
    assert!(summary.lines.iter().any(|l| l.contains("Failures")));
}

#[test]
fn enrichment_operator_summary_with_microbench_includes_cost() {
    let controllers = vec![
        make_timescale("r", ControllerRole::Router, 100_000, 1_000_000),
        make_timescale("m", ControllerRole::Monitor, 50_000, 500_000),
    ];
    let matrix = ControllerCompositionMatrix::default_matrix();
    let config = GateConfig {
        run_microbench: true,
        per_pair_budget_millionths: 100_000_000,
        ..GateConfig::default()
    };
    let result = evaluate_composition_gate("t-sum-mb", &controllers, &matrix, &config);
    let summary = render_operator_summary(&result);
    assert!(summary.microbench_total_cost.is_some());
    assert!(summary.lines.iter().any(|l| l.contains("Microbench")));
}

#[test]
fn enrichment_operator_summary_gate_id_matches_result() {
    let controllers = vec![make_timescale(
        "g",
        ControllerRole::Monitor,
        100_000,
        1_000_000,
    )];
    let matrix = ControllerCompositionMatrix::default_matrix();
    let config = GateConfig {
        run_microbench: false,
        ..GateConfig::default()
    };
    let result = evaluate_composition_gate("t-gid", &controllers, &matrix, &config);
    let summary = render_operator_summary(&result);
    assert_eq!(summary.gate_id, result.gate_id);
}

// ---------------------------------------------------------------------------
// Schema version constants
// ---------------------------------------------------------------------------

#[test]
fn enrichment_schema_version_constants_are_nonempty() {
    assert!(!CONTROLLER_REGISTRY_SCHEMA_VERSION.is_empty());
    assert!(!CONTROLLER_OPERATOR_GRAPH_SCHEMA_VERSION.is_empty());
    assert!(!CONTROLLER_TELEMETRY_SNAPSHOT_SCHEMA_VERSION.is_empty());
    assert!(!SPECTRAL_EDGE_TRACE_SCHEMA_VERSION.is_empty());
    assert!(!CONTROLLER_EDGE_UNCERTAINTY_SCHEMA_VERSION.is_empty());
}

#[test]
fn enrichment_schema_version_constants_uniqueness() {
    let versions: BTreeSet<&str> = [
        CONTROLLER_REGISTRY_SCHEMA_VERSION,
        CONTROLLER_OPERATOR_GRAPH_SCHEMA_VERSION,
        CONTROLLER_TELEMETRY_SNAPSHOT_SCHEMA_VERSION,
        SPECTRAL_EDGE_TRACE_SCHEMA_VERSION,
        CONTROLLER_EDGE_UNCERTAINTY_SCHEMA_VERSION,
    ]
    .iter()
    .copied()
    .collect();
    assert_eq!(versions.len(), 5);
}

#[test]
fn enrichment_schema_version_constants_start_with_franken_engine() {
    assert!(CONTROLLER_REGISTRY_SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(CONTROLLER_OPERATOR_GRAPH_SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(CONTROLLER_TELEMETRY_SNAPSHOT_SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(SPECTRAL_EDGE_TRACE_SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(CONTROLLER_EDGE_UNCERTAINTY_SCHEMA_VERSION.starts_with("franken-engine."));
}

// ---------------------------------------------------------------------------
// Deterministic hash behavior
// ---------------------------------------------------------------------------

#[test]
fn enrichment_content_hash_deterministic() {
    use frankenengine_engine::hash_tiers::ContentHash;
    let h1 = ContentHash::compute(b"controller-composition-matrix-test");
    let h2 = ContentHash::compute(b"controller-composition-matrix-test");
    assert_eq!(h1.as_bytes(), h2.as_bytes());
}

#[test]
fn enrichment_content_hash_different_inputs_differ() {
    use frankenengine_engine::hash_tiers::ContentHash;
    let h1 = ContentHash::compute(b"input-alpha");
    let h2 = ContentHash::compute(b"input-beta");
    assert_ne!(h1.as_bytes(), h2.as_bytes());
}

// ---------------------------------------------------------------------------
// Edge cases and additional coverage
// ---------------------------------------------------------------------------

#[test]
fn enrichment_gate_without_microbench_has_none() {
    let controllers = vec![make_timescale(
        "nm",
        ControllerRole::Monitor,
        100_000,
        1_000_000,
    )];
    let matrix = ControllerCompositionMatrix::default_matrix();
    let config = GateConfig {
        run_microbench: false,
        ..GateConfig::default()
    };
    let result = evaluate_composition_gate("t-no-mb", &controllers, &matrix, &config);
    assert!(result.microbench.is_none());
}

#[test]
fn enrichment_gate_with_microbench_has_some() {
    let controllers = vec![
        make_timescale("r", ControllerRole::Router, 100_000, 1_000_000),
        make_timescale("m", ControllerRole::Monitor, 50_000, 500_000),
    ];
    let matrix = ControllerCompositionMatrix::default_matrix();
    let config = GateConfig {
        run_microbench: true,
        per_pair_budget_millionths: 100_000_000,
        ..GateConfig::default()
    };
    let result = evaluate_composition_gate("t-yes-mb", &controllers, &matrix, &config);
    assert!(result.microbench.is_some());
    assert_eq!(result.microbench.as_ref().unwrap().pairs_measured, 1);
}

#[test]
fn enrichment_gate_result_is_approved_reflects_verdict() {
    let approved = GateResult {
        gate_id: "test".to_string(),
        verdict: GateVerdict::Approved,
        failures: vec![],
        microbench: None,
        controllers_evaluated: 1,
        pairs_evaluated: 0,
        logs: vec![],
    };
    assert!(approved.is_approved());

    let rejected = GateResult {
        gate_id: "test".to_string(),
        verdict: GateVerdict::Rejected,
        failures: vec![GateFailureReason::EmptyDeployment],
        microbench: None,
        controllers_evaluated: 0,
        pairs_evaluated: 0,
        logs: vec![],
    };
    assert!(!rejected.is_approved());
}

#[test]
fn enrichment_full_pipeline_registry_graph_telemetry_traces_ledger() {
    // End-to-end pipeline test exercising all public functions
    let contracts = vec![
        make_full_contract("pipeline_router", ControllerRole::Router),
        make_full_contract("pipeline_optimizer", ControllerRole::Optimizer),
        make_monitor_contract("pipeline_monitor"),
    ];

    let registry = build_controller_registry(&contracts).unwrap();
    assert_eq!(registry.controllers.len(), 3);

    let report = validate_controller_registry(&registry);
    // monitor is exempt from some gaps but may have others
    assert_eq!(report.schema_version, CONTROLLER_REGISTRY_SCHEMA_VERSION);

    let matrix = ControllerCompositionMatrix::default_matrix();
    let graph = derive_controller_operator_graph(&registry, &matrix);
    assert_eq!(graph.edges.len(), 3); // C(3,2) = 3

    let telemetry = build_controller_telemetry_snapshot(&registry, &graph);
    assert_eq!(telemetry.controller_count, 3);
    assert_eq!(telemetry.edge_count, 3);

    let traces = build_spectral_edge_traces(&graph);
    assert_eq!(traces.len(), 3);

    let ledger = build_controller_edge_uncertainty_ledger(&registry, &graph);
    // All non-observed edges should appear
    for entry in &ledger {
        assert_ne!(entry.uncertainty, EdgeUncertainty::Observed);
        assert_eq!(
            entry.schema_version,
            CONTROLLER_EDGE_UNCERTAINTY_SCHEMA_VERSION
        );
    }
}

#[test]
fn enrichment_matrix_entry_rationale_nonempty_for_all_defaults() {
    let matrix = ControllerCompositionMatrix::default_matrix();
    for entry in &matrix.entries {
        assert!(
            !entry.rationale.is_empty(),
            "rationale should be non-empty for {:?}-{:?}",
            entry.role_a,
            entry.role_b,
        );
    }
}

#[test]
fn enrichment_registry_serde_roundtrip() {
    let contracts = vec![
        make_full_contract("sr_a", ControllerRole::Router),
        make_full_contract("sr_b", ControllerRole::Optimizer),
    ];
    let registry = build_controller_registry(&contracts).unwrap();
    let json = serde_json::to_string(&registry).unwrap();
    let back: ControllerRegistrySnapshot = serde_json::from_str(&json).unwrap();
    assert_eq!(registry, back);
}

#[test]
fn enrichment_validation_report_serde_roundtrip() {
    let contracts = vec![make_full_contract("vr_a", ControllerRole::Router)];
    let registry = build_controller_registry(&contracts).unwrap();
    let report = validate_controller_registry(&registry);
    let json = serde_json::to_string(&report).unwrap();
    let back: ControllerRegistryValidationReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, back);
}
