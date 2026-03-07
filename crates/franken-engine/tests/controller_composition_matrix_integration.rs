#![forbid(unsafe_code)]
//! Integration tests for the `controller_composition_matrix` module (FRX-13.4).
//!
//! Exercises the full composition gate pipeline from outside the crate
//! boundary: matrix construction, interaction classification, microbench
//! harness, acceptance gate evaluation, and operator summary rendering.

use std::collections::BTreeSet;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use frankenengine_engine::controller_composition_matrix::ControllerOperatorGraph;
use frankenengine_engine::controller_composition_matrix::{
    ActuationBound, CONTROLLER_EDGE_UNCERTAINTY_SCHEMA_VERSION,
    CONTROLLER_OPERATOR_GRAPH_SCHEMA_VERSION, CONTROLLER_REGISTRY_SCHEMA_VERSION,
    CONTROLLER_TELEMETRY_SNAPSHOT_SCHEMA_VERSION, ControllerCompositionMatrix, ControllerContract,
    ControllerEdgeUncertaintyEntry, ControllerMetadataGap, ControllerRegistryError,
    ControllerRegistrySnapshot, ControllerRole, ControllerTelemetrySnapshot, ControllerTimescale,
    DeterministicFallback, EdgeUncertainty, GateConfig, GateFailureReason, GateResult, GateVerdict,
    InteractionClass, MatrixEntry, MicrobenchConfig, MicrobenchResult, OperatorSummary,
    SPECTRAL_EDGE_TRACE_SCHEMA_VERSION, SpectralEdgeTrace,
    build_controller_edge_uncertainty_ledger, build_controller_registry,
    build_controller_telemetry_snapshot, build_spectral_edge_traces,
    derive_controller_operator_graph, evaluate_composition_gate, render_operator_summary,
    run_microbench, validate_controller_registry,
};
use frankenengine_engine::rgc_test_harness::{
    DeterministicTestContext, EventInput, HarnessLane, HarnessLogEvent,
};
use serde::{Deserialize, Serialize};

// ===========================================================================
// Helpers
// ===========================================================================

fn ts(name: &str, role: ControllerRole, obs: i64, write: i64) -> ControllerTimescale {
    ControllerTimescale {
        controller_name: name.to_string(),
        role,
        observation_interval_millionths: obs,
        write_interval_millionths: write,
        statement: format!("{name} timescale"),
    }
}

#[allow(clippy::too_many_arguments)]
fn contract(
    name: &str,
    role: ControllerRole,
    obs: i64,
    write: i64,
    observed: &[&str],
    actions: &[&str],
    state: &[&str],
    resources: &[&str],
) -> ControllerContract {
    ControllerContract {
        timescale: ts(name, role, obs, write),
        observation_channels: observed.iter().map(|value| value.to_string()).collect(),
        action_channels: actions.iter().map(|value| value.to_string()).collect(),
        state_channels: state.iter().map(|value| value.to_string()).collect(),
        actuation_bounds: actions
            .iter()
            .map(|channel| ActuationBound {
                channel: (*channel).to_string(),
                lower_bound_millionths: 0,
                upper_bound_millionths: 1_000_000,
                units: "ratio".to_string(),
            })
            .collect(),
        shared_resources: resources.iter().map(|value| value.to_string()).collect(),
        deterministic_fallback: if role == ControllerRole::Monitor {
            None
        } else {
            Some(DeterministicFallback {
                fallback_mode: "safe".to_string(),
                trigger: "telemetry-gap".to_string(),
                detail: format!("{name} falls back deterministically"),
            })
        },
    }
}

type ArtifactTestResult<T> = Result<T, Box<dyn Error>>;

const CONTROLLER_OPERATOR_GRAPH_RUN_MANIFEST_SCHEMA_VERSION: &str =
    "franken-engine.controller-operator-graph.run-manifest.v1";
const CONTROLLER_OPERATOR_GRAPH_TRACE_IDS_SCHEMA_VERSION: &str =
    "franken-engine.controller-operator-graph.trace-ids.v1";
const CONTROLLER_OPERATOR_GRAPH_BEAD_ID: &str = "bd-1lsy.7.14.1";
const CONTROLLER_OPERATOR_GRAPH_COMPONENT: &str = "controller_operator_graph_suite";
const CONTROLLER_OPERATOR_GRAPH_SCENARIO_ID: &str = "rgc-614a-controller-operator-graph";
const CONTROLLER_OPERATOR_GRAPH_GENERATED_AT_UNIX_MS: u64 = 1_700_006_140_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ControllerOperatorGraphArtifactPaths {
    manifest: String,
    events: String,
    commands: String,
    controller_registry: String,
    controller_operator_graph: String,
    controller_telemetry_snapshot: String,
    spectral_edge_trace: String,
    controller_edge_uncertainty_ledger: String,
    trace_ids: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ControllerOperatorGraphRunManifest {
    schema_version: String,
    bead_id: String,
    component: String,
    scenario_id: String,
    run_id: String,
    replay_command: String,
    trace_id: String,
    decision_id: String,
    policy_id: String,
    generated_at_unix_ms: u64,
    ship_ready: bool,
    metadata_gap_count: usize,
    blocked_controller_names: Vec<String>,
    controller_count: usize,
    edge_count: usize,
    partial_edge_count: usize,
    unknown_edge_count: usize,
    artifacts: ControllerOperatorGraphArtifactPaths,
    commands: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ControllerOperatorGraphTraceIds {
    schema_version: String,
    trace_ids: Vec<String>,
    decision_ids: Vec<String>,
    policy_ids: Vec<String>,
}

#[derive(Debug, Clone)]
struct ControllerOperatorGraphArtifactBundle {
    run_dir: PathBuf,
    manifest_path: PathBuf,
    events_path: PathBuf,
    commands_path: PathBuf,
    controller_registry_path: PathBuf,
    controller_operator_graph_path: PathBuf,
    controller_telemetry_snapshot_path: PathBuf,
    spectral_edge_trace_path: PathBuf,
    controller_edge_uncertainty_ledger_path: PathBuf,
    trace_ids_path: PathBuf,
}

fn temp_dir(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock drift")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "franken_engine_{label}_{nanos}_{}",
        std::process::id()
    ))
}

fn write_json_file<T: Serialize>(path: &Path, value: &T) -> ArtifactTestResult<()> {
    fs::write(path, serde_json::to_vec_pretty(value)?)?;
    Ok(())
}

fn write_jsonl_file<T: Serialize>(path: &Path, values: &[T]) -> ArtifactTestResult<()> {
    let mut jsonl = String::new();
    for value in values {
        jsonl.push_str(&serde_json::to_string(value)?);
        jsonl.push('\n');
    }
    fs::write(path, jsonl)?;
    Ok(())
}

fn read_jsonl_file<T>(path: &Path) -> ArtifactTestResult<Vec<T>>
where
    T: for<'de> Deserialize<'de>,
{
    let raw = fs::read_to_string(path)?;
    raw.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str::<T>(line).map_err(Into::into))
        .collect()
}

fn controller_operator_graph_demo_state() -> (
    ControllerRegistrySnapshot,
    ControllerOperatorGraph,
    ControllerTelemetrySnapshot,
    Vec<SpectralEdgeTrace>,
    Vec<ControllerEdgeUncertaintyEntry>,
) {
    let router = contract(
        "router",
        ControllerRole::Router,
        1_000_000,
        500_000,
        &["queue.depth", "optimizer.gain", "fallback.mode"],
        &["lane.route"],
        &["router.state"],
        &["work-queue", "allocator"],
    );
    let optimizer = contract(
        "optimizer",
        ControllerRole::Optimizer,
        5_000_000,
        2_000_000,
        &["lane.route"],
        &["optimizer.gain"],
        &["optimizer.state"],
        &["allocator"],
    );
    let mut custom = contract(
        "custom",
        ControllerRole::Custom,
        2_000_000,
        500_000,
        &["lane.route"],
        &["custom.override"],
        &["custom.state"],
        &[],
    );
    custom.deterministic_fallback = None;

    let registry = build_controller_registry(&[router, optimizer, custom]).unwrap();
    let graph =
        derive_controller_operator_graph(&registry, &ControllerCompositionMatrix::default_matrix());
    let telemetry = build_controller_telemetry_snapshot(&registry, &graph);
    let traces = build_spectral_edge_traces(&graph);
    let ledger = build_controller_edge_uncertainty_ledger(&registry, &graph);
    (registry, graph, telemetry, traces, ledger)
}

fn emit_controller_operator_graph_artifacts_to_dir(
    run_dir: &Path,
) -> ArtifactTestResult<ControllerOperatorGraphArtifactBundle> {
    fs::create_dir_all(run_dir)?;

    let manifest_path = run_dir.join("run_manifest.json");
    let events_path = run_dir.join("events.jsonl");
    let commands_path = run_dir.join("commands.txt");
    let controller_registry_path = run_dir.join("controller_registry.json");
    let controller_operator_graph_path = run_dir.join("controller_operator_graph.json");
    let controller_telemetry_snapshot_path = run_dir.join("controller_telemetry_snapshot.json");
    let spectral_edge_trace_path = run_dir.join("spectral_edge_trace.jsonl");
    let controller_edge_uncertainty_ledger_path =
        run_dir.join("controller_edge_uncertainty_ledger.json");
    let trace_ids_path = run_dir.join("trace_ids.json");

    let (registry, graph, telemetry, traces, ledger) = controller_operator_graph_demo_state();
    let validation = validate_controller_registry(&registry);
    let context = DeterministicTestContext::new(
        CONTROLLER_OPERATOR_GRAPH_SCENARIO_ID,
        "controller-composition-matrix",
        HarnessLane::E2e,
        614_001,
    );
    let replay_command = std::env::var("CONTROLLER_OPERATOR_GRAPH_REPLAY_COMMAND")
        .unwrap_or_else(|_| "./scripts/run_controller_operator_graph_suite.sh ci".to_string());
    let command = std::env::var("CONTROLLER_OPERATOR_GRAPH_COMMAND").unwrap_or_else(|_| {
        "env CONTROLLER_OPERATOR_GRAPH_ARTIFACT_DIR=<run_dir> cargo test -p frankenengine-engine --test controller_composition_matrix_integration controller_operator_graph_artifact -- --nocapture".to_string()
    });
    let blocked_controller_names = registry
        .metadata_gaps
        .iter()
        .map(|gap| gap.controller_name.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let run_id = run_dir
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or(CONTROLLER_OPERATOR_GRAPH_SCENARIO_ID)
        .to_string();
    let events = vec![
        context.event(EventInput {
            sequence: 1,
            component: CONTROLLER_OPERATOR_GRAPH_COMPONENT,
            event: "registry_evaluated",
            outcome: if validation.ship_ready {
                "pass"
            } else {
                "blocked"
            },
            error_code: if validation.ship_ready {
                None
            } else {
                Some("FE-CONTROLLER-REGISTRY-INCOMPLETE")
            },
            timing_us: 614_001,
            timestamp_unix_ms: CONTROLLER_OPERATOR_GRAPH_GENERATED_AT_UNIX_MS,
        }),
        context.event(EventInput {
            sequence: 2,
            component: CONTROLLER_OPERATOR_GRAPH_COMPONENT,
            event: "artifacts_emitted",
            outcome: "pass",
            error_code: None,
            timing_us: 614_101,
            timestamp_unix_ms: CONTROLLER_OPERATOR_GRAPH_GENERATED_AT_UNIX_MS + 1,
        }),
    ];
    let commands = vec![command];
    let manifest = ControllerOperatorGraphRunManifest {
        schema_version: CONTROLLER_OPERATOR_GRAPH_RUN_MANIFEST_SCHEMA_VERSION.to_string(),
        bead_id: CONTROLLER_OPERATOR_GRAPH_BEAD_ID.to_string(),
        component: CONTROLLER_OPERATOR_GRAPH_COMPONENT.to_string(),
        scenario_id: CONTROLLER_OPERATOR_GRAPH_SCENARIO_ID.to_string(),
        run_id,
        replay_command,
        trace_id: context.trace_id.clone(),
        decision_id: context.decision_id.clone(),
        policy_id: context.policy_id.clone(),
        generated_at_unix_ms: CONTROLLER_OPERATOR_GRAPH_GENERATED_AT_UNIX_MS,
        ship_ready: validation.ship_ready,
        metadata_gap_count: validation.metadata_gaps.len(),
        blocked_controller_names,
        controller_count: registry.controllers.len(),
        edge_count: graph.edges.len(),
        partial_edge_count: telemetry.partial_edge_count,
        unknown_edge_count: telemetry.unknown_edge_count,
        artifacts: ControllerOperatorGraphArtifactPaths {
            manifest: manifest_path.display().to_string(),
            events: events_path.display().to_string(),
            commands: commands_path.display().to_string(),
            controller_registry: controller_registry_path.display().to_string(),
            controller_operator_graph: controller_operator_graph_path.display().to_string(),
            controller_telemetry_snapshot: controller_telemetry_snapshot_path.display().to_string(),
            spectral_edge_trace: spectral_edge_trace_path.display().to_string(),
            controller_edge_uncertainty_ledger: controller_edge_uncertainty_ledger_path
                .display()
                .to_string(),
            trace_ids: trace_ids_path.display().to_string(),
        },
        commands: commands.clone(),
    };
    let trace_ids = ControllerOperatorGraphTraceIds {
        schema_version: CONTROLLER_OPERATOR_GRAPH_TRACE_IDS_SCHEMA_VERSION.to_string(),
        trace_ids: vec![context.trace_id.clone()],
        decision_ids: vec![context.decision_id.clone()],
        policy_ids: vec![context.policy_id.clone()],
    };

    write_json_file(&manifest_path, &manifest)?;
    write_jsonl_file(&events_path, &events)?;
    fs::write(&commands_path, format!("{}\n", commands.join("\n")))?;
    write_json_file(&controller_registry_path, &registry)?;
    write_json_file(&controller_operator_graph_path, &graph)?;
    write_json_file(&controller_telemetry_snapshot_path, &telemetry)?;
    write_jsonl_file(&spectral_edge_trace_path, &traces)?;
    write_json_file(&controller_edge_uncertainty_ledger_path, &ledger)?;
    write_json_file(&trace_ids_path, &trace_ids)?;

    Ok(ControllerOperatorGraphArtifactBundle {
        run_dir: run_dir.to_path_buf(),
        manifest_path,
        events_path,
        commands_path,
        controller_registry_path,
        controller_operator_graph_path,
        controller_telemetry_snapshot_path,
        spectral_edge_trace_path,
        controller_edge_uncertainty_ledger_path,
        trace_ids_path,
    })
}

fn emit_controller_operator_graph_artifacts_if_configured()
-> ArtifactTestResult<Option<ControllerOperatorGraphArtifactBundle>> {
    match std::env::var("CONTROLLER_OPERATOR_GRAPH_ARTIFACT_DIR") {
        Ok(path) => emit_controller_operator_graph_artifacts_to_dir(Path::new(&path)).map(Some),
        Err(_) => Ok(None),
    }
}

fn default_gate_config() -> GateConfig {
    GateConfig::default()
}

fn no_bench_config() -> GateConfig {
    GateConfig {
        run_microbench: false,
        microbench_config: MicrobenchConfig::default(),
        per_pair_budget_millionths: 500_000,
    }
}

// ===========================================================================
// 1. ControllerRole
// ===========================================================================

#[test]
fn controller_role_display_all() {
    let roles = ControllerRole::all();
    let displays: BTreeSet<String> = roles.iter().map(|r| r.to_string()).collect();
    assert_eq!(displays.len(), roles.len(), "all roles have unique display");
}

#[test]
fn controller_role_as_str() {
    let r = ControllerRole::Router;
    assert!(!r.as_str().is_empty());
}

#[test]
fn controller_role_serde_round_trip() {
    for role in ControllerRole::all() {
        let json = serde_json::to_string(role).unwrap();
        let back: ControllerRole = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, role);
    }
}

#[test]
fn controller_role_ordering() {
    assert!(ControllerRole::Router < ControllerRole::Custom);
}

// ===========================================================================
// 2. InteractionClass
// ===========================================================================

#[test]
fn interaction_class_display_all() {
    let classes = [
        InteractionClass::Independent,
        InteractionClass::ReadShared,
        InteractionClass::ProducerConsumer,
        InteractionClass::WriteConflict,
        InteractionClass::MutuallyExclusive,
    ];
    let displays: BTreeSet<String> = classes.iter().map(|c| c.to_string()).collect();
    assert_eq!(displays.len(), classes.len());
}

#[test]
fn interaction_class_as_str() {
    assert!(!InteractionClass::Independent.as_str().is_empty());
}

#[test]
fn mutually_exclusive_blocks_composition() {
    assert!(InteractionClass::MutuallyExclusive.blocks_composition());
    assert!(!InteractionClass::WriteConflict.blocks_composition());
    assert!(!InteractionClass::Independent.blocks_composition());
}

#[test]
fn write_conflict_requires_timescale_separation() {
    assert!(InteractionClass::WriteConflict.requires_timescale_separation());
    assert!(InteractionClass::ProducerConsumer.requires_timescale_separation());
}

#[test]
fn independent_no_separation_needed() {
    assert!(!InteractionClass::Independent.requires_timescale_separation());
}

#[test]
fn read_shared_no_separation_needed() {
    assert!(!InteractionClass::ReadShared.requires_timescale_separation());
}

#[test]
fn interaction_class_serde_round_trip() {
    let c = InteractionClass::ProducerConsumer;
    let json = serde_json::to_string(&c).unwrap();
    let back: InteractionClass = serde_json::from_str(&json).unwrap();
    assert_eq!(back, c);
}

// ===========================================================================
// 3. Default matrix
// ===========================================================================

#[test]
fn default_matrix_has_fifteen_entries() {
    let m = ControllerCompositionMatrix::default_matrix();
    // 5 roles: 5 diagonal + C(5,2) = 10 off-diagonal = 15
    assert_eq!(m.entries.len(), 15);
}

#[test]
fn default_matrix_schema_version() {
    let m = ControllerCompositionMatrix::default_matrix();
    assert!(!m.schema_version.is_empty());
}

#[test]
fn default_matrix_symmetric_lookup() {
    let m = ControllerCompositionMatrix::default_matrix();
    let ab = m.lookup(ControllerRole::Router, ControllerRole::Optimizer);
    let ba = m.lookup(ControllerRole::Optimizer, ControllerRole::Router);
    assert!(ab.is_some());
    assert_eq!(ab.unwrap().interaction, ba.unwrap().interaction);
}

#[test]
fn default_matrix_router_router_exclusive() {
    let m = ControllerCompositionMatrix::default_matrix();
    let e = m
        .lookup(ControllerRole::Router, ControllerRole::Router)
        .unwrap();
    assert_eq!(e.interaction, InteractionClass::MutuallyExclusive);
}

#[test]
fn default_matrix_monitor_monitor_shared() {
    let m = ControllerCompositionMatrix::default_matrix();
    let e = m
        .lookup(ControllerRole::Monitor, ControllerRole::Monitor)
        .unwrap();
    assert_eq!(e.interaction, InteractionClass::ReadShared);
}

#[test]
fn default_matrix_blocked_pairs() {
    let m = ControllerCompositionMatrix::default_matrix();
    let blocked = m.blocked_pairs();
    assert!(blocked.len() >= 2); // Router-Router, Fallback-Fallback
    assert!(
        blocked
            .iter()
            .any(|e| e.role_a == ControllerRole::Router && e.role_b == ControllerRole::Router)
    );
}

#[test]
fn default_matrix_separation_required_pairs() {
    let m = ControllerCompositionMatrix::default_matrix();
    let sep = m.separation_required_pairs();
    assert!(!sep.is_empty());
    for e in &sep {
        assert!(e.min_timescale_separation_millionths > 0);
    }
}

// ===========================================================================
// 4. Matrix modification
// ===========================================================================

#[test]
fn set_entry_overrides() {
    let mut m = ControllerCompositionMatrix::default_matrix();
    let original = m
        .lookup(ControllerRole::Router, ControllerRole::Optimizer)
        .unwrap()
        .interaction;
    m.set_entry(MatrixEntry {
        role_a: ControllerRole::Router,
        role_b: ControllerRole::Optimizer,
        interaction: InteractionClass::Independent,
        min_timescale_separation_millionths: 0,
        rationale: "overridden for test".to_string(),
    });
    let updated = m
        .lookup(ControllerRole::Router, ControllerRole::Optimizer)
        .unwrap();
    assert_eq!(updated.interaction, InteractionClass::Independent);
    assert_ne!(updated.interaction, original);
}

// ===========================================================================
// 5. Matrix deterministic ID
// ===========================================================================

#[test]
fn matrix_id_deterministic() {
    let m1 = ControllerCompositionMatrix::default_matrix();
    let m2 = ControllerCompositionMatrix::default_matrix();
    assert_eq!(m1.derive_matrix_id(), m2.derive_matrix_id());
}

#[test]
fn matrix_id_changes_on_modification() {
    let m1 = ControllerCompositionMatrix::default_matrix();
    let mut m2 = ControllerCompositionMatrix::default_matrix();
    m2.set_entry(MatrixEntry {
        role_a: ControllerRole::Router,
        role_b: ControllerRole::Optimizer,
        interaction: InteractionClass::Independent,
        min_timescale_separation_millionths: 0,
        rationale: "changed".to_string(),
    });
    assert_ne!(m1.derive_matrix_id(), m2.derive_matrix_id());
}

// ===========================================================================
// 6. Matrix serde
// ===========================================================================

#[test]
fn matrix_serde_round_trip() {
    let m = ControllerCompositionMatrix::default_matrix();
    let json = serde_json::to_string(&m).unwrap();
    let back: ControllerCompositionMatrix = serde_json::from_str(&json).unwrap();
    assert_eq!(back.entries.len(), m.entries.len());
    assert_eq!(back.schema_version, m.schema_version);
}

// ===========================================================================
// 7. Microbench — independent controllers
// ===========================================================================

#[test]
fn microbench_independent_pair_low_cost() {
    let controllers = vec![
        ts("mon_1", ControllerRole::Monitor, 1_000_000, 500_000),
        ts("mon_2", ControllerRole::Monitor, 1_000_000, 500_000),
    ];
    let m = ControllerCompositionMatrix::default_matrix();
    let cfg = MicrobenchConfig::default();
    let result = run_microbench(&controllers, &m, &cfg);
    assert_eq!(result.pairs_measured, 1);
    // ReadShared monitors should have low cost
    assert_eq!(result.pairs_over_budget, 0);
}

// ===========================================================================
// 8. Microbench — write conflict pair
// ===========================================================================

#[test]
fn microbench_write_conflict_has_higher_cost() {
    let controllers = vec![
        ts("opt_1", ControllerRole::Optimizer, 1_000_000, 500_000),
        ts("opt_2", ControllerRole::Optimizer, 1_000_000, 500_000),
    ];
    let m = ControllerCompositionMatrix::default_matrix();
    let cfg = MicrobenchConfig::default();
    let result = run_microbench(&controllers, &m, &cfg);
    assert!(result.total_cost_millionths > 0);
}

// ===========================================================================
// 9. Microbench — empty controllers
// ===========================================================================

#[test]
fn microbench_empty_controllers() {
    let m = ControllerCompositionMatrix::default_matrix();
    let cfg = MicrobenchConfig::default();
    let result = run_microbench(&[], &m, &cfg);
    assert_eq!(result.pairs_measured, 0);
    assert_eq!(result.total_cost_millionths, 0);
}

// ===========================================================================
// 10. Microbench — single controller (no pairs)
// ===========================================================================

#[test]
fn microbench_single_controller() {
    let controllers = vec![ts("solo", ControllerRole::Router, 1_000_000, 500_000)];
    let m = ControllerCompositionMatrix::default_matrix();
    let cfg = MicrobenchConfig::default();
    let result = run_microbench(&controllers, &m, &cfg);
    assert_eq!(result.pairs_measured, 0);
}

// ===========================================================================
// 11. Microbench serde
// ===========================================================================

#[test]
fn microbench_result_serde_round_trip() {
    let controllers = vec![
        ts("mon_1", ControllerRole::Monitor, 1_000_000, 500_000),
        ts("mon_2", ControllerRole::Monitor, 1_000_000, 500_000),
    ];
    let m = ControllerCompositionMatrix::default_matrix();
    let cfg = MicrobenchConfig::default();
    let result = run_microbench(&controllers, &m, &cfg);
    let json = serde_json::to_string(&result).unwrap();
    let back: MicrobenchResult = serde_json::from_str(&json).unwrap();
    assert_eq!(back.pairs_measured, result.pairs_measured);
    assert_eq!(back.total_cost_millionths, result.total_cost_millionths);
}

// ===========================================================================
// 12. Gate — approved deployment
// ===========================================================================

#[test]
fn gate_approves_compatible_deployment() {
    let controllers = vec![
        ts("my_router", ControllerRole::Router, 1_000_000, 500_000),
        ts("my_monitor", ControllerRole::Monitor, 2_000_000, 1_000_000),
    ];
    let m = ControllerCompositionMatrix::default_matrix();
    let result = evaluate_composition_gate("trace-1", &controllers, &m, &no_bench_config());
    assert!(result.is_approved());
    assert_eq!(result.verdict, GateVerdict::Approved);
    assert!(result.failures.is_empty());
}

// ===========================================================================
// 13. Gate — empty deployment rejected
// ===========================================================================

#[test]
fn gate_rejects_empty_deployment() {
    let m = ControllerCompositionMatrix::default_matrix();
    let result = evaluate_composition_gate("trace-2", &[], &m, &no_bench_config());
    assert!(!result.is_approved());
    assert!(
        result
            .failures
            .iter()
            .any(|f| matches!(f, GateFailureReason::EmptyDeployment))
    );
}

// ===========================================================================
// 14. Gate — duplicate controllers rejected
// ===========================================================================

#[test]
fn gate_rejects_duplicate_controllers() {
    let controllers = vec![
        ts("dup", ControllerRole::Router, 1_000_000, 500_000),
        ts("dup", ControllerRole::Monitor, 2_000_000, 1_000_000),
    ];
    let m = ControllerCompositionMatrix::default_matrix();
    let result = evaluate_composition_gate("trace-3", &controllers, &m, &no_bench_config());
    assert!(!result.is_approved());
    assert!(
        result
            .failures
            .iter()
            .any(|f| matches!(f, GateFailureReason::DuplicateController { .. }))
    );
}

// ===========================================================================
// 15. Gate — mutually exclusive roles rejected
// ===========================================================================

#[test]
fn gate_rejects_mutually_exclusive_roles() {
    let controllers = vec![
        ts("router_a", ControllerRole::Router, 1_000_000, 500_000),
        ts("router_b", ControllerRole::Router, 2_000_000, 1_000_000),
    ];
    let m = ControllerCompositionMatrix::default_matrix();
    let result = evaluate_composition_gate("trace-4", &controllers, &m, &no_bench_config());
    assert!(!result.is_approved());
    assert!(
        result
            .failures
            .iter()
            .any(|f| matches!(f, GateFailureReason::MutuallyExclusiveRoles { .. }))
    );
}

// ===========================================================================
// 16. Gate — insufficient timescale separation
// ===========================================================================

#[test]
fn gate_rejects_insufficient_timescale_separation() {
    // Optimizer-Optimizer requires 500K separation, give them same timescale
    let controllers = vec![
        ts("opt_a", ControllerRole::Optimizer, 100_000, 100_000),
        ts("opt_b", ControllerRole::Optimizer, 100_000, 100_000),
    ];
    let m = ControllerCompositionMatrix::default_matrix();
    let result = evaluate_composition_gate("trace-5", &controllers, &m, &no_bench_config());
    assert!(!result.is_approved());
}

// ===========================================================================
// 17. Gate — invalid timescale rejected
// ===========================================================================

#[test]
fn gate_rejects_invalid_timescale() {
    let controllers = vec![ts(
        "bad",
        ControllerRole::Router,
        0, // invalid: zero observation interval
        500_000,
    )];
    let m = ControllerCompositionMatrix::default_matrix();
    let result = evaluate_composition_gate("trace-6", &controllers, &m, &no_bench_config());
    assert!(!result.is_approved());
    assert!(
        result
            .failures
            .iter()
            .any(|f| matches!(f, GateFailureReason::InvalidTimescale { .. }))
    );
}

// ===========================================================================
// 18. Gate — deterministic gate ID
// ===========================================================================

#[test]
fn gate_id_deterministic() {
    let controllers = vec![
        ts("router", ControllerRole::Router, 1_000_000, 500_000),
        ts("monitor", ControllerRole::Monitor, 2_000_000, 1_000_000),
    ];
    let m = ControllerCompositionMatrix::default_matrix();
    let r1 = evaluate_composition_gate("trace-7", &controllers, &m, &no_bench_config());
    let r2 = evaluate_composition_gate("trace-7", &controllers, &m, &no_bench_config());
    assert_eq!(r1.gate_id, r2.gate_id);
}

// ===========================================================================
// 19. Gate — evidence ID
// ===========================================================================

#[test]
fn gate_evidence_id_stable() {
    let controllers = vec![ts("router", ControllerRole::Router, 1_000_000, 500_000)];
    let m = ControllerCompositionMatrix::default_matrix();
    let r1 = evaluate_composition_gate("trace-8", &controllers, &m, &no_bench_config());
    let r2 = evaluate_composition_gate("trace-8", &controllers, &m, &no_bench_config());
    assert_eq!(r1.derive_evidence_id(), r2.derive_evidence_id());
}

// ===========================================================================
// 20. Gate — logs are populated
// ===========================================================================

#[test]
fn gate_has_logs() {
    let controllers = vec![ts("router", ControllerRole::Router, 1_000_000, 500_000)];
    let m = ControllerCompositionMatrix::default_matrix();
    let result = evaluate_composition_gate("trace-9", &controllers, &m, &no_bench_config());
    assert!(!result.logs.is_empty());
}

// ===========================================================================
// 21. Gate — controllers and pairs counts
// ===========================================================================

#[test]
fn gate_counts_controllers_and_pairs() {
    let controllers = vec![
        ts("router", ControllerRole::Router, 1_000_000, 500_000),
        ts("monitor", ControllerRole::Monitor, 2_000_000, 1_000_000),
        ts("optimizer", ControllerRole::Optimizer, 3_000_000, 1_000_000),
    ];
    let m = ControllerCompositionMatrix::default_matrix();
    let result = evaluate_composition_gate("trace-10", &controllers, &m, &no_bench_config());
    assert_eq!(result.controllers_evaluated, 3);
    assert_eq!(result.pairs_evaluated, 3); // C(3,2) = 3
}

// ===========================================================================
// 22. Gate — with microbench enabled
// ===========================================================================

#[test]
fn gate_with_microbench() {
    let controllers = vec![
        ts("router", ControllerRole::Router, 1_000_000, 500_000),
        ts("monitor", ControllerRole::Monitor, 2_000_000, 1_000_000),
    ];
    let m = ControllerCompositionMatrix::default_matrix();
    let result = evaluate_composition_gate("trace-11", &controllers, &m, &default_gate_config());
    assert!(result.microbench.is_some());
}

// ===========================================================================
// 23. Gate result serde
// ===========================================================================

#[test]
fn gate_result_serde_round_trip() {
    let controllers = vec![
        ts("router", ControllerRole::Router, 1_000_000, 500_000),
        ts("monitor", ControllerRole::Monitor, 2_000_000, 1_000_000),
    ];
    let m = ControllerCompositionMatrix::default_matrix();
    let result = evaluate_composition_gate("trace-12", &controllers, &m, &no_bench_config());
    let json = serde_json::to_string(&result).unwrap();
    let back: GateResult = serde_json::from_str(&json).unwrap();
    assert_eq!(back.verdict, result.verdict);
    assert_eq!(back.gate_id, result.gate_id);
    assert_eq!(back.controllers_evaluated, result.controllers_evaluated);
}

// ===========================================================================
// 24. GateFailureReason display
// ===========================================================================

#[test]
fn gate_failure_reason_display_all() {
    let reasons = [
        GateFailureReason::EmptyDeployment,
        GateFailureReason::DuplicateController {
            controller_name: "dup".to_string(),
        },
        GateFailureReason::MutuallyExclusiveRoles {
            role_a: ControllerRole::Router,
            role_b: ControllerRole::Router,
            controller_a: "a".to_string(),
            controller_b: "b".to_string(),
        },
        GateFailureReason::InvalidTimescale {
            controller_name: "bad".to_string(),
            detail: "zero interval".to_string(),
        },
        GateFailureReason::InsufficientTimescaleSeparation {
            controller_a: "a".to_string(),
            controller_b: "b".to_string(),
            required_millionths: 500_000,
            actual_millionths: 100_000,
        },
        GateFailureReason::MicrobenchBudgetExceeded {
            pair: "a-b".to_string(),
            cost_millionths: 800_000,
            budget_millionths: 500_000,
        },
    ];
    for r in &reasons {
        let s = r.to_string();
        assert!(!s.is_empty());
    }
}

#[test]
fn gate_failure_reason_serde_round_trip() {
    let r = GateFailureReason::MutuallyExclusiveRoles {
        role_a: ControllerRole::Router,
        role_b: ControllerRole::Router,
        controller_a: "a".to_string(),
        controller_b: "b".to_string(),
    };
    let json = serde_json::to_string(&r).unwrap();
    let back: GateFailureReason = serde_json::from_str(&json).unwrap();
    assert_eq!(back, r);
}

// ===========================================================================
// 25. GateVerdict display and serde
// ===========================================================================

#[test]
fn gate_verdict_display() {
    assert!(!GateVerdict::Approved.to_string().is_empty());
    assert!(!GateVerdict::Rejected.to_string().is_empty());
    assert_ne!(
        GateVerdict::Approved.to_string(),
        GateVerdict::Rejected.to_string()
    );
}

#[test]
fn gate_verdict_serde_round_trip() {
    let v = GateVerdict::Approved;
    let json = serde_json::to_string(&v).unwrap();
    let back: GateVerdict = serde_json::from_str(&json).unwrap();
    assert_eq!(back, v);
}

// ===========================================================================
// 26. Operator summary
// ===========================================================================

#[test]
fn operator_summary_approved() {
    let controllers = vec![
        ts("router", ControllerRole::Router, 1_000_000, 500_000),
        ts("monitor", ControllerRole::Monitor, 2_000_000, 1_000_000),
    ];
    let m = ControllerCompositionMatrix::default_matrix();
    let result = evaluate_composition_gate("trace-13", &controllers, &m, &no_bench_config());
    let summary = render_operator_summary(&result);
    assert_eq!(summary.verdict, "approved");
    assert_eq!(summary.failure_count, 0);
    assert!(!summary.lines.is_empty());
}

#[test]
fn operator_summary_rejected() {
    let controllers = vec![
        ts("r1", ControllerRole::Router, 1_000_000, 500_000),
        ts("r2", ControllerRole::Router, 2_000_000, 1_000_000),
    ];
    let m = ControllerCompositionMatrix::default_matrix();
    let result = evaluate_composition_gate("trace-14", &controllers, &m, &no_bench_config());
    let summary = render_operator_summary(&result);
    assert_eq!(summary.verdict, "rejected");
    assert!(summary.failure_count > 0);
}

#[test]
fn operator_summary_serde_round_trip() {
    let controllers = vec![ts("router", ControllerRole::Router, 1_000_000, 500_000)];
    let m = ControllerCompositionMatrix::default_matrix();
    let result = evaluate_composition_gate("trace-15", &controllers, &m, &no_bench_config());
    let summary = render_operator_summary(&result);
    let json = serde_json::to_string(&summary).unwrap();
    let back: OperatorSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(back.verdict, summary.verdict);
    assert_eq!(back.controllers, summary.controllers);
}

// ===========================================================================
// 27. GateConfig defaults and serde
// ===========================================================================

#[test]
fn gate_config_default() {
    let cfg = GateConfig::default();
    assert!(cfg.run_microbench);
    assert!(cfg.per_pair_budget_millionths > 0);
}

#[test]
fn gate_config_serde_round_trip() {
    let cfg = GateConfig::default();
    let json = serde_json::to_string(&cfg).unwrap();
    let back: GateConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(back, cfg);
}

// ===========================================================================
// 28. MicrobenchConfig defaults and serde
// ===========================================================================

#[test]
fn microbench_config_default() {
    let cfg = MicrobenchConfig::default();
    assert!(cfg.max_iterations > 0);
    assert!(cfg.budget_cap_millionths > 0);
    assert!(cfg.min_iterations > 0);
}

#[test]
fn microbench_config_serde_round_trip() {
    let cfg = MicrobenchConfig::default();
    let json = serde_json::to_string(&cfg).unwrap();
    let back: MicrobenchConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(back, cfg);
}

// ===========================================================================
// 29. MatrixEntry serde
// ===========================================================================

#[test]
fn matrix_entry_serde_round_trip() {
    let e = MatrixEntry {
        role_a: ControllerRole::Router,
        role_b: ControllerRole::Optimizer,
        interaction: InteractionClass::ProducerConsumer,
        min_timescale_separation_millionths: 100_000,
        rationale: "Router → Optimizer".to_string(),
    };
    let json = serde_json::to_string(&e).unwrap();
    let back: MatrixEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(back, e);
}

// ===========================================================================
// 30. ControllerTimescale serde
// ===========================================================================

#[test]
fn controller_timescale_serde_round_trip() {
    let t = ts("my_router", ControllerRole::Router, 1_000_000, 500_000);
    let json = serde_json::to_string(&t).unwrap();
    let back: ControllerTimescale = serde_json::from_str(&json).unwrap();
    assert_eq!(back, t);
}

// ===========================================================================
// 31. Five-controller deployment
// ===========================================================================

#[test]
fn five_controller_deployment() {
    let controllers = vec![
        ts("router", ControllerRole::Router, 1_000_000, 500_000),
        ts("optimizer", ControllerRole::Optimizer, 5_000_000, 3_000_000),
        ts("fallback", ControllerRole::Fallback, 10_000_000, 5_000_000),
        ts("monitor", ControllerRole::Monitor, 2_000_000, 1_000_000),
        ts("custom_ext", ControllerRole::Custom, 8_000_000, 4_000_000),
    ];
    let m = ControllerCompositionMatrix::default_matrix();
    let result = evaluate_composition_gate("trace-big", &controllers, &m, &default_gate_config());
    assert_eq!(result.controllers_evaluated, 5);
    assert_eq!(result.pairs_evaluated, 10); // C(5,2) = 10
    // Should have microbench results
    assert!(result.microbench.is_some());
}

// ===========================================================================
// 32. Multiple failures accumulate
// ===========================================================================

#[test]
fn multiple_failures_accumulate() {
    let controllers = vec![
        ts("r1", ControllerRole::Router, 1_000_000, 500_000),
        ts("r2", ControllerRole::Router, 1_000_000, 500_000),
        ts("f1", ControllerRole::Fallback, 1_000_000, 500_000),
        ts("f2", ControllerRole::Fallback, 1_000_000, 500_000),
    ];
    let m = ControllerCompositionMatrix::default_matrix();
    let result = evaluate_composition_gate("trace-multi", &controllers, &m, &no_bench_config());
    assert!(!result.is_approved());
    // Should have at least 2 failures: Router-Router and Fallback-Fallback exclusions
    assert!(result.failures.len() >= 2);
}

// ===========================================================================
// 33. GateLogEvent serde
// ===========================================================================

#[test]
fn gate_log_event_serde_round_trip() {
    use frankenengine_engine::controller_composition_matrix::GateLogEvent;
    let e = GateLogEvent {
        trace_id: "t1".to_string(),
        gate_id: "g1".to_string(),
        event: "gate_start".to_string(),
        detail: "evaluating 3 controllers".to_string(),
    };
    let json = serde_json::to_string(&e).unwrap();
    let back: GateLogEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(back, e);
}

// ===========================================================================
// 34. Approved deployment with wide timescale separation
// ===========================================================================

#[test]
fn approved_with_wide_separation() {
    // Give optimizers very different timescales to satisfy separation
    let controllers = vec![
        ts("opt_fast", ControllerRole::Optimizer, 1_000_000, 500_000),
        ts(
            "opt_slow",
            ControllerRole::Optimizer,
            100_000_000,
            50_000_000,
        ),
    ];
    let m = ControllerCompositionMatrix::default_matrix();
    let result = evaluate_composition_gate("trace-sep", &controllers, &m, &no_bench_config());
    // Wide separation should satisfy the 500K requirement
    assert!(result.is_approved());
}

// ===========================================================================
// 35. Matrix lookup for all role pairs
// ===========================================================================

#[test]
fn matrix_has_entries_for_all_role_pairs() {
    let m = ControllerCompositionMatrix::default_matrix();
    let roles = ControllerRole::all();
    for a in roles {
        for b in roles {
            assert!(
                m.lookup(*a, *b).is_some(),
                "missing entry for ({a:?}, {b:?})"
            );
        }
    }
}

// ===========================================================================
// 36. Controller registry contracts
// ===========================================================================

#[test]
fn controller_registry_schema_version_constant_nonempty() {
    assert!(CONTROLLER_REGISTRY_SCHEMA_VERSION.starts_with("franken-engine."));
}

#[test]
fn controller_registry_rejects_duplicate_controller_names() {
    let controllers = vec![
        contract(
            "router",
            ControllerRole::Router,
            1_000_000,
            500_000,
            &["queue.depth"],
            &["lane.route"],
            &["router.state"],
            &["work-queue"],
        ),
        contract(
            "router",
            ControllerRole::Monitor,
            2_000_000,
            1_000_000,
            &["queue.depth"],
            &[],
            &["monitor.state"],
            &["work-queue"],
        ),
    ];
    let err = build_controller_registry(&controllers).unwrap_err();
    assert!(matches!(
        err,
        ControllerRegistryError::DuplicateController { .. }
    ));
}

#[test]
fn controller_registry_collects_metadata_gaps_for_incomplete_contracts() {
    let mut incomplete = contract(
        "optimizer",
        ControllerRole::Optimizer,
        2_000_000,
        750_000,
        &["latency.p95"],
        &["optimizer.gain"],
        &[],
        &[],
    );
    incomplete.actuation_bounds.clear();
    incomplete.deterministic_fallback = None;

    let registry = build_controller_registry(&[incomplete]).unwrap();
    let report = validate_controller_registry(&registry);
    assert!(!report.ship_ready);
    assert!(
        report
            .metadata_gaps
            .iter()
            .any(|gap: &ControllerMetadataGap| { gap.gap.to_string() == "missing_state_channels" })
    );
    assert!(
        report
            .metadata_gaps
            .iter()
            .any(|gap: &ControllerMetadataGap| {
                gap.gap.to_string() == "missing_actuation_bounds"
            })
    );
    assert!(
        report
            .metadata_gaps
            .iter()
            .any(|gap: &ControllerMetadataGap| {
                gap.gap.to_string() == "missing_deterministic_fallback"
            })
    );
}

#[test]
fn controller_registry_normalizes_order_deterministically() {
    let left = contract(
        "router",
        ControllerRole::Router,
        1_000_000,
        500_000,
        &["queue.depth"],
        &["lane.route"],
        &["router.state"],
        &["work-queue"],
    );
    let right = contract(
        "optimizer",
        ControllerRole::Optimizer,
        5_000_000,
        2_000_000,
        &["lane.route"],
        &["optimizer.gain"],
        &["optimizer.state"],
        &["work-queue", "allocator"],
    );

    let a = build_controller_registry(&[left.clone(), right.clone()]).unwrap();
    let b = build_controller_registry(&[right, left]).unwrap();
    assert_eq!(a.registry_id, b.registry_id);
    assert_eq!(a.controllers, b.controllers);
}

// ===========================================================================
// 37. Operator graph and telemetry artifacts
// ===========================================================================

#[test]
fn operator_graph_schema_version_constant_nonempty() {
    assert!(CONTROLLER_OPERATOR_GRAPH_SCHEMA_VERSION.contains("graph"));
}

#[test]
fn operator_graph_derivation_is_order_independent() {
    let router = contract(
        "router",
        ControllerRole::Router,
        1_000_000,
        500_000,
        &["queue.depth", "optimizer.gain"],
        &["lane.route"],
        &["router.state"],
        &["work-queue", "allocator"],
    );
    let optimizer = contract(
        "optimizer",
        ControllerRole::Optimizer,
        5_000_000,
        2_000_000,
        &["lane.route"],
        &["optimizer.gain"],
        &["optimizer.state"],
        &["work-queue", "allocator"],
    );

    let matrix = ControllerCompositionMatrix::default_matrix();
    let left = build_controller_registry(&[router.clone(), optimizer.clone()]).unwrap();
    let right = build_controller_registry(&[optimizer, router]).unwrap();
    let graph_left = derive_controller_operator_graph(&left, &matrix);
    let graph_right = derive_controller_operator_graph(&right, &matrix);

    assert_eq!(graph_left.graph_id, graph_right.graph_id);
    assert_eq!(graph_left.edges, graph_right.edges);
}

#[test]
fn operator_graph_edge_captures_overlap_and_coupling() {
    let router = contract(
        "router",
        ControllerRole::Router,
        1_000_000,
        500_000,
        &["optimizer.gain"],
        &["lane.route"],
        &["router.state"],
        &["work-queue", "allocator"],
    );
    let optimizer = contract(
        "optimizer",
        ControllerRole::Optimizer,
        5_000_000,
        2_000_000,
        &["lane.route"],
        &["optimizer.gain"],
        &["optimizer.state"],
        &["work-queue", "allocator"],
    );

    let registry = build_controller_registry(&[router, optimizer]).unwrap();
    let graph =
        derive_controller_operator_graph(&registry, &ControllerCompositionMatrix::default_matrix());
    let edge = graph.edges.first().expect("expected one edge");
    assert_eq!(edge.interaction, InteractionClass::ProducerConsumer);
    assert!(!edge.observed_channel_overlap.is_empty());
    assert!(!edge.shared_resource_overlap.is_empty());
    assert!(edge.coupling_score_millionths > 0);
}

#[test]
fn operator_telemetry_snapshot_counts_uncertain_edges() {
    let router = contract(
        "router",
        ControllerRole::Router,
        1_000_000,
        500_000,
        &["queue.depth"],
        &["lane.route"],
        &["router.state"],
        &[],
    );
    let mut custom = contract(
        "custom",
        ControllerRole::Custom,
        1_500_000,
        500_000,
        &["lane.route"],
        &["custom.override"],
        &["custom.state"],
        &[],
    );
    custom.deterministic_fallback = None;

    let registry = build_controller_registry(&[router, custom]).unwrap();
    let graph =
        derive_controller_operator_graph(&registry, &ControllerCompositionMatrix::default_matrix());
    let snapshot: ControllerTelemetrySnapshot =
        build_controller_telemetry_snapshot(&registry, &graph);
    assert_eq!(
        snapshot.schema_version,
        CONTROLLER_TELEMETRY_SNAPSHOT_SCHEMA_VERSION
    );
    assert_eq!(snapshot.edge_count, 1);
    assert!(snapshot.unknown_edge_count >= 1 || snapshot.partial_edge_count >= 1);
}

#[test]
fn spectral_edge_traces_emit_warning_for_unknown_high_coupling_edges() {
    let router = contract(
        "router",
        ControllerRole::Router,
        1_000_000,
        500_000,
        &["queue.depth"],
        &["lane.route"],
        &["router.state"],
        &[],
    );
    let mut custom = contract(
        "custom",
        ControllerRole::Custom,
        1_000_000,
        500_000,
        &["lane.route"],
        &["custom.override"],
        &["custom.state"],
        &[],
    );
    custom.deterministic_fallback = None;

    let registry = build_controller_registry(&[router, custom]).unwrap();
    let graph =
        derive_controller_operator_graph(&registry, &ControllerCompositionMatrix::default_matrix());
    let traces: Vec<SpectralEdgeTrace> = build_spectral_edge_traces(&graph);
    assert_eq!(traces[0].schema_version, SPECTRAL_EDGE_TRACE_SCHEMA_VERSION);
    assert!(traces[0].active_warning);
}

#[test]
fn uncertainty_ledger_records_non_observed_edges() {
    let router = contract(
        "router",
        ControllerRole::Router,
        1_000_000,
        500_000,
        &["queue.depth"],
        &["lane.route"],
        &["router.state"],
        &[],
    );
    let mut custom = contract(
        "custom",
        ControllerRole::Custom,
        2_000_000,
        500_000,
        &["lane.route"],
        &["custom.override"],
        &["custom.state"],
        &[],
    );
    custom.deterministic_fallback = None;

    let registry: ControllerRegistrySnapshot =
        build_controller_registry(&[router, custom]).unwrap();
    let graph =
        derive_controller_operator_graph(&registry, &ControllerCompositionMatrix::default_matrix());
    let ledger: Vec<ControllerEdgeUncertaintyEntry> =
        build_controller_edge_uncertainty_ledger(&registry, &graph);
    assert_eq!(
        ledger[0].schema_version,
        CONTROLLER_EDGE_UNCERTAINTY_SCHEMA_VERSION
    );
    assert!(matches!(
        ledger[0].uncertainty,
        EdgeUncertainty::Partial | EdgeUncertainty::Unknown
    ));
    assert!(!ledger[0].reasons.is_empty());
}

#[test]
fn controller_operator_graph_artifact_bundle_has_expected_contents() {
    let run_dir = temp_dir("controller_operator_graph_artifacts");
    let bundle = emit_controller_operator_graph_artifacts_to_dir(&run_dir)
        .expect("artifact bundle should emit cleanly");

    assert!(bundle.run_dir.exists());
    assert!(bundle.manifest_path.exists());
    assert!(bundle.events_path.exists());
    assert!(bundle.commands_path.exists());
    assert!(bundle.controller_registry_path.exists());
    assert!(bundle.controller_operator_graph_path.exists());
    assert!(bundle.controller_telemetry_snapshot_path.exists());
    assert!(bundle.spectral_edge_trace_path.exists());
    assert!(bundle.controller_edge_uncertainty_ledger_path.exists());
    assert!(bundle.trace_ids_path.exists());

    let manifest: ControllerOperatorGraphRunManifest = serde_json::from_str(
        &fs::read_to_string(&bundle.manifest_path).expect("manifest should be readable"),
    )
    .expect("manifest should parse");
    assert_eq!(
        manifest.schema_version,
        CONTROLLER_OPERATOR_GRAPH_RUN_MANIFEST_SCHEMA_VERSION
    );
    assert_eq!(manifest.bead_id, CONTROLLER_OPERATOR_GRAPH_BEAD_ID);
    assert_eq!(manifest.component, CONTROLLER_OPERATOR_GRAPH_COMPONENT);
    assert_eq!(manifest.scenario_id, CONTROLLER_OPERATOR_GRAPH_SCENARIO_ID);
    assert!(!manifest.ship_ready);
    assert!(manifest.metadata_gap_count >= 1);
    assert!(
        manifest
            .blocked_controller_names
            .iter()
            .any(|controller| controller == "custom")
    );
    assert!(manifest.commands[0].contains("cargo test"));

    let registry: ControllerRegistrySnapshot = serde_json::from_str(
        &fs::read_to_string(&bundle.controller_registry_path).expect("registry should be readable"),
    )
    .expect("registry should parse");
    assert_eq!(registry.schema_version, CONTROLLER_REGISTRY_SCHEMA_VERSION);
    assert!(
        registry
            .metadata_gaps
            .iter()
            .any(|gap| gap.controller_name == "custom")
    );

    let graph: ControllerOperatorGraph = serde_json::from_str(
        &fs::read_to_string(&bundle.controller_operator_graph_path)
            .expect("graph should be readable"),
    )
    .expect("graph should parse");
    assert_eq!(
        graph.schema_version,
        CONTROLLER_OPERATOR_GRAPH_SCHEMA_VERSION
    );
    assert_eq!(graph.controller_names.len(), 3);
    assert!(!graph.edges.is_empty());

    let telemetry: ControllerTelemetrySnapshot = serde_json::from_str(
        &fs::read_to_string(&bundle.controller_telemetry_snapshot_path)
            .expect("telemetry should be readable"),
    )
    .expect("telemetry should parse");
    assert_eq!(
        telemetry.schema_version,
        CONTROLLER_TELEMETRY_SNAPSHOT_SCHEMA_VERSION
    );
    assert!(telemetry.unknown_edge_count >= 1);

    let traces: Vec<SpectralEdgeTrace> =
        read_jsonl_file(&bundle.spectral_edge_trace_path).expect("trace jsonl should parse");
    assert!(!traces.is_empty());
    assert_eq!(traces[0].schema_version, SPECTRAL_EDGE_TRACE_SCHEMA_VERSION);
    assert!(traces.iter().any(|trace| trace.active_warning));

    let ledger: Vec<ControllerEdgeUncertaintyEntry> = serde_json::from_str(
        &fs::read_to_string(&bundle.controller_edge_uncertainty_ledger_path)
            .expect("ledger should be readable"),
    )
    .expect("ledger should parse");
    assert!(!ledger.is_empty());
    assert_eq!(
        ledger[0].schema_version,
        CONTROLLER_EDGE_UNCERTAINTY_SCHEMA_VERSION
    );

    let events: Vec<HarnessLogEvent> =
        read_jsonl_file(&bundle.events_path).expect("events should parse");
    assert_eq!(events.len(), 2);
    assert!(
        events
            .iter()
            .any(|event| event.event == "registry_evaluated" && event.outcome == "blocked")
    );
    assert!(
        events
            .iter()
            .any(|event| event.event == "artifacts_emitted" && event.outcome == "pass")
    );

    let trace_ids: ControllerOperatorGraphTraceIds = serde_json::from_str(
        &fs::read_to_string(&bundle.trace_ids_path).expect("trace ids should be readable"),
    )
    .expect("trace ids should parse");
    assert_eq!(
        trace_ids.schema_version,
        CONTROLLER_OPERATOR_GRAPH_TRACE_IDS_SCHEMA_VERSION
    );
    assert_eq!(trace_ids.trace_ids.len(), 1);
    assert_eq!(trace_ids.trace_ids[0], manifest.trace_id);
    assert_eq!(trace_ids.decision_ids[0], manifest.decision_id);
    assert_eq!(trace_ids.policy_ids[0], manifest.policy_id);
}

#[test]
fn controller_operator_graph_artifact_emits_if_env_configured() {
    let emitted = emit_controller_operator_graph_artifacts_if_configured()
        .expect("env-gated artifact emission should not fail");
    if let Ok(run_dir) = std::env::var("CONTROLLER_OPERATOR_GRAPH_ARTIFACT_DIR") {
        let bundle = emitted.expect("artifact bundle should emit when env is set");
        assert_eq!(bundle.run_dir, PathBuf::from(run_dir));
        assert!(bundle.manifest_path.exists());
        assert!(bundle.events_path.exists());
        assert!(bundle.commands_path.exists());
        assert!(bundle.controller_registry_path.exists());
        assert!(bundle.controller_operator_graph_path.exists());
        assert!(bundle.spectral_edge_trace_path.exists());
        assert!(bundle.controller_edge_uncertainty_ledger_path.exists());
        assert!(bundle.trace_ids_path.exists());
    } else {
        assert!(
            emitted.is_none(),
            "without CONTROLLER_OPERATOR_GRAPH_ARTIFACT_DIR set, emission should be a no-op"
        );
    }
}
