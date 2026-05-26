#![forbid(unsafe_code)]
//! Integration tests for the `counterfactual_replay_engine` module.
//!
//! Exercises AlternatePolicy, ReplayScope, AssumptionCategory, AssumptionCard,
//! DecisionComparison, PolicyComparisonReport, ReplayComparisonResult,
//! Recommendation, ReplayEngineError, ReplayEngineConfig,
//! CounterfactualReplayEngine (compare, replay_count), and serde round-trips.
//!
//! ## Why the recorded outcomes are not hand-picked numbers
//!
//! The engine reports each decision's recorded `outcome_millionths` verbatim in
//! the original column and re-scores substituted actions through its own
//! outcome model. If the recorded outcomes were author-chosen magic numbers the
//! comparisons would degenerate into arithmetic over those numbers — a bug in
//! how a real execution turns an action/loss into an outcome would be invisible.
//!
//! To give the comparisons teeth, every recorded `outcome_millionths` here is
//! produced by the engine's **real** outcome model
//! ([`estimate_lane_outcome_millionths`]) applied to that decision's chosen
//! action and loss matrix — the exact function
//! `CounterfactualReplayEngine::compute_counterfactual` uses to score
//! substituted actions. The ground-truth totals are recomputed independently
//! in-test through that same model (not read back from the report), so the
//! original-column and forced-action counterfactual assertions verify a genuine
//! model output rather than an echoed integer.

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
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use frankenengine_engine::causal_replay::{
    CounterfactualConfig, DecisionSnapshot, RecorderConfig, RecordingMode, TraceRecord,
    TraceRecorder,
};
use frankenengine_engine::counterfactual_evaluator::{EnvelopeStatus, EstimatorKind, PolicyId};
use frankenengine_engine::counterfactual_replay_engine::{
    AlternatePolicy, AssumptionCard, AssumptionCategory, CounterfactualReplayEngine,
    DecisionComparison, FLEET_COUNTERFACTUAL_SCHEMA_VERSION, FleetCounterfactualReport,
    PolicyComparisonReport, REPLAY_ENGINE_SCHEMA_VERSION, Recommendation, ReplayComparisonResult,
    ReplayEngineConfig, ReplayEngineError, ReplayScope, SUBSTITUTED_POLICY_SNAPSHOT_SCHEMA_VERSION,
    SubstitutedPolicySnapshot, estimate_lane_outcome_millionths,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::runtime_decision_theory::LaneAction;
use frankenengine_engine::security_epoch::SecurityEpoch;

static TEST_DIR_COUNTER: AtomicU64 = AtomicU64::new(0);

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn test_epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(1)
}

/// The risk threshold recorded for every decision in this suite. Shared with
/// the in-test ground-truth recomputation so the expected outcomes are scored
/// against the exact threshold the engine sees.
const RECORDED_THRESHOLD: i64 = 500_000;

/// Build a decision's per-action loss matrix from a recorded native-lane loss.
/// The wasm lane is twice as costly, so `native` is the loss-minimizing action
/// and the matrix max-loss is `2 * native_loss`. Distinct `native_loss` values
/// therefore yield distinct model outcomes, keeping the per-decision sums
/// non-degenerate.
fn loss_matrix_for(native_loss: i64) -> BTreeMap<String, i64> {
    let mut loss_matrix = BTreeMap::new();
    loss_matrix.insert("native".to_string(), native_loss);
    loss_matrix.insert("wasm".to_string(), native_loss * 2);
    loss_matrix
}

/// The outcome the engine's **real** outcome model assigns to `action` for a
/// decision recorded with `native_loss`. This is the same function
/// `CounterfactualReplayEngine::compute_counterfactual` uses to score
/// substituted actions, so seeding recorded outcomes from it makes the recorded
/// trace a model-consistent ground truth rather than a hand-picked number.
fn recorded_outcome(action: &str, native_loss: i64) -> i64 {
    estimate_lane_outcome_millionths(action, &loss_matrix_for(native_loss), RECORDED_THRESHOLD)
}

/// A recorded decision whose `outcome_millionths` is produced by the engine's
/// real outcome model applied to its chosen `action` and `native_loss` — never
/// a hand-set magic number. A bug in how the model turns an action/loss into an
/// outcome is therefore observable in the original column the engine reports.
fn make_decision(index: u64, action: &str, native_loss: i64) -> DecisionSnapshot {
    let loss_matrix = loss_matrix_for(native_loss);
    let outcome_millionths =
        estimate_lane_outcome_millionths(action, &loss_matrix, RECORDED_THRESHOLD);

    DecisionSnapshot {
        decision_index: index,
        trace_id: "test-trace".to_string(),
        decision_id: format!("decision-{index}"),
        policy_id: "baseline".to_string(),
        policy_version: 1,
        epoch: test_epoch(),
        tick: 100 + index,
        threshold_millionths: RECORDED_THRESHOLD,
        loss_matrix,
        evidence_hashes: vec![ContentHash::compute(b"evidence")],
        chosen_action: action.to_string(),
        outcome_millionths,
        extension_id: "ext-1".to_string(),
        nondeterminism_range: (0, 0),
    }
}

fn make_trace(decisions: Vec<DecisionSnapshot>) -> TraceRecord {
    let trace_id = decisions
        .first()
        .map(|decision| decision.trace_id.clone())
        .unwrap_or_else(|| "test-trace".to_string());
    let mut recorder = TraceRecorder::new(RecorderConfig {
        trace_id,
        recording_mode: RecordingMode::Full,
        epoch: test_epoch(),
        start_tick: 100,
        signing_key: b"test-key".to_vec(),
    });

    for d in decisions {
        recorder.record_decision(d);
    }

    recorder.finalize()
}

fn make_alternate_policy(id: &str, desc: &str) -> AlternatePolicy {
    AlternatePolicy {
        policy_id: PolicyId(id.to_string()),
        description: desc.to_string(),
        counterfactual_config: CounterfactualConfig {
            branch_id: format!("branch-{id}"),
            threshold_override_millionths: Some(600_000),
            loss_matrix_overrides: BTreeMap::new(),
            policy_version_override: None,
            containment_overrides: BTreeMap::new(),
            evidence_weight_overrides: BTreeMap::new(),
            branch_from_index: 0,
        },
        default_action: None,
    }
}

fn make_override_policy(id: &str, action: LaneAction) -> AlternatePolicy {
    AlternatePolicy {
        policy_id: PolicyId(id.to_string()),
        description: format!("Force {action}"),
        counterfactual_config: CounterfactualConfig {
            branch_id: format!("branch-{id}"),
            threshold_override_millionths: None,
            loss_matrix_overrides: BTreeMap::new(),
            policy_version_override: None,
            containment_overrides: BTreeMap::new(),
            evidence_weight_overrides: BTreeMap::new(),
            branch_from_index: 0,
        },
        default_action: Some(action),
    }
}

fn default_scope() -> ReplayScope {
    ReplayScope::default()
}

fn default_engine() -> CounterfactualReplayEngine {
    CounterfactualReplayEngine::new(ReplayEngineConfig::default())
}

/// The (chosen-action, native-loss) spec for the decisions in `simple_trace`.
/// Shared so the model-ground-truth tests can recompute the expected outcomes
/// from the exact same inputs the trace was built from.
const SIMPLE_TRACE_SPEC: &[(&str, i64)] =
    &[("native", 800_000), ("wasm", 600_000), ("native", 900_000)];

fn simple_trace() -> TraceRecord {
    make_trace(
        SIMPLE_TRACE_SPEC
            .iter()
            .enumerate()
            .map(|(index, (action, native_loss))| make_decision(index as u64, action, *native_loss))
            .collect(),
    )
}

fn unique_fleet_dir(label: &str) -> PathBuf {
    let n = TEST_DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "franken-engine-fleet-counterfactual-{label}-{}-{n}",
        std::process::id()
    ))
}

fn make_node_trace(node_id: &str, trace_id: &str, native_losses: &[i64]) -> TraceRecord {
    let decisions: Vec<DecisionSnapshot> = native_losses
        .iter()
        .enumerate()
        .map(|(index, native_loss)| {
            let mut decision = make_decision(index as u64, "native", *native_loss);
            decision.trace_id = trace_id.to_string();
            decision.decision_id = format!("{trace_id}-decision-{index}");
            decision
        })
        .collect();
    let mut trace = make_trace(decisions);
    trace
        .metadata
        .insert("node_id".to_string(), node_id.to_string());
    trace
}

fn write_trace(root: &Path, relative_path: &str, trace: &TraceRecord) -> PathBuf {
    let path = root.join(relative_path);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    let bytes = serde_json::to_vec(trace).unwrap();
    fs::write(&path, bytes).unwrap();
    path
}

fn substituted_policy_snapshot(scope: ReplayScope) -> SubstitutedPolicySnapshot {
    SubstitutedPolicySnapshot::new(
        PolicyId("fleet-policy-v1".to_string()),
        "force deterministic safe-mode for fleet replay".to_string(),
        CounterfactualConfig {
            branch_id: "fleet-branch".to_string(),
            threshold_override_millionths: None,
            loss_matrix_overrides: BTreeMap::new(),
            policy_version_override: Some(2),
            containment_overrides: BTreeMap::new(),
            evidence_weight_overrides: BTreeMap::new(),
            branch_from_index: 0,
        },
        Some(LaneAction::FallbackSafe),
        scope,
        Some(ContentHash::compute(b"fleet-policy-v1")),
    )
}

// ===========================================================================
// 1. Constants
// ===========================================================================

#[test]
fn schema_version_nonempty() {
    assert!(!REPLAY_ENGINE_SCHEMA_VERSION.is_empty());
    assert!(REPLAY_ENGINE_SCHEMA_VERSION.contains("counterfactual-replay-engine"));
}

#[test]
fn fleet_counterfactual_schema_versions_are_stable() {
    assert_eq!(
        FLEET_COUNTERFACTUAL_SCHEMA_VERSION,
        "franken-engine.fleet-counterfactual-report.v1"
    );
    assert_eq!(
        SUBSTITUTED_POLICY_SNAPSHOT_SCHEMA_VERSION,
        "franken-engine.substituted-policy-snapshot.v1"
    );
}

#[test]
fn substituted_policy_snapshot_serde_roundtrip() {
    let snapshot = substituted_policy_snapshot(default_scope());
    let json = serde_json::to_string(&snapshot).unwrap();
    let back: SubstitutedPolicySnapshot = serde_json::from_str(&json).unwrap();
    assert_eq!(back, snapshot);
}

#[test]
fn substituted_policy_snapshot_load_from_file_roundtrips() {
    let root = unique_fleet_dir("policy-load");
    fs::create_dir_all(&root).unwrap();
    let snapshot = substituted_policy_snapshot(default_scope());
    let path = root.join("policy.json");
    fs::write(&path, serde_json::to_vec(&snapshot).unwrap()).unwrap();

    let loaded = SubstitutedPolicySnapshot::load_from_file(&path).expect("load policy snapshot");
    assert_eq!(loaded, snapshot);
}

#[test]
fn substituted_policy_snapshot_load_from_file_drives_fleet_replay() {
    let root = unique_fleet_dir("policy-load-replay");
    fs::create_dir_all(&root).unwrap();
    let trace = make_node_trace("node-load", "trace-load-1", &[820_000, 610_000]);
    write_trace(&root, "node-load/trace-load-1.json", &trace);
    // The policy snapshot must live OUTSIDE the scanned fleet root:
    // `compare_fleet_trace_dir` recursively decodes every `*.json` under `root`
    // as a `TraceRecord`, so a policy file inside it would be (mis)read as a
    // malformed trace and fail the whole replay with `FleetTraceDecode`.
    let policy_dir = unique_fleet_dir("policy-load-replay-snapshot");
    fs::create_dir_all(&policy_dir).unwrap();
    let policy_path = policy_dir.join("substituted-policy.json");
    fs::write(
        &policy_path,
        serde_json::to_vec(&substituted_policy_snapshot(default_scope())).unwrap(),
    )
    .unwrap();

    let snapshot = SubstitutedPolicySnapshot::load_from_file(&policy_path).expect("load snapshot");
    let mut engine = default_engine();
    let report = engine
        .compare_fleet_trace_dir(&root, &snapshot, None)
        .expect("fleet counterfactual report");
    assert_eq!(report.schema_version, FLEET_COUNTERFACTUAL_SCHEMA_VERSION);
    assert_eq!(report.substituted_policy, snapshot);
    assert_eq!(report.trace_count, 1);
}

#[test]
fn substituted_policy_snapshot_load_from_file_missing_path_errors() {
    let root = unique_fleet_dir("policy-missing");
    let path = root.join("does-not-exist.json");
    match SubstitutedPolicySnapshot::load_from_file(&path) {
        Err(ReplayEngineError::PolicySnapshotRead { .. }) => {}
        other => panic!("expected PolicySnapshotRead, got {other:?}"),
    }
}

#[test]
fn substituted_policy_snapshot_load_from_file_rejects_bad_schema() {
    let root = unique_fleet_dir("policy-bad-schema");
    fs::create_dir_all(&root).unwrap();
    let mut snapshot = substituted_policy_snapshot(default_scope());
    snapshot.schema_version = "franken-engine.substituted-policy-snapshot.v0".to_string();
    let path = root.join("policy.json");
    fs::write(&path, serde_json::to_vec(&snapshot).unwrap()).unwrap();

    match SubstitutedPolicySnapshot::load_from_file(&path) {
        Err(ReplayEngineError::InvalidPolicySnapshotSchema { expected, found }) => {
            assert_eq!(expected, SUBSTITUTED_POLICY_SNAPSHOT_SCHEMA_VERSION);
            assert_eq!(found, "franken-engine.substituted-policy-snapshot.v0");
        }
        other => panic!("expected InvalidPolicySnapshotSchema, got {other:?}"),
    }
}

#[test]
fn substituted_policy_snapshot_load_from_file_rejects_malformed_json() {
    let root = unique_fleet_dir("policy-malformed");
    fs::create_dir_all(&root).unwrap();
    let path = root.join("policy.json");
    fs::write(&path, b"{not valid json").unwrap();

    match SubstitutedPolicySnapshot::load_from_file(&path) {
        Err(ReplayEngineError::PolicySnapshotDecode { .. }) => {}
        other => panic!("expected PolicySnapshotDecode, got {other:?}"),
    }
}

#[test]
fn fleet_trace_dir_replay_aggregates_by_node_and_trace() {
    let root = unique_fleet_dir("aggregate");
    fs::create_dir_all(&root).unwrap();
    let trace_a1 = make_node_trace("node-a", "trace-a1", &[800_000, 700_000]);
    let trace_a2 = make_node_trace("node-a", "trace-a2", &[600_000]);
    let trace_b1 = make_node_trace("node-b", "trace-b1", &[900_000, 500_000]);
    write_trace(&root, "node-b/trace-b1.json", &trace_b1);
    write_trace(&root, "node-a/trace-a2.json", &trace_a2);
    write_trace(&root, "node-a/trace-a1.json", &trace_a1);

    let snapshot = substituted_policy_snapshot(default_scope());
    let mut engine = default_engine();
    let report = engine
        .compare_fleet_trace_dir(&root, &snapshot, None)
        .expect("fleet counterfactual report");

    assert_eq!(report.schema_version, FLEET_COUNTERFACTUAL_SCHEMA_VERSION);
    assert_eq!(report.substituted_policy, snapshot);
    assert_eq!(report.node_count, 2);
    assert_eq!(report.trace_count, 3);
    assert_eq!(report.total_decisions, 5);
    assert_eq!(report.aggregate_result.trace_count, 3);
    assert_eq!(report.aggregate_result.total_decisions, 5);
    assert_eq!(report.node_reports.len(), 2);
    assert_eq!(report.node_reports[0].node_id, "node-a");
    assert_eq!(report.node_reports[0].trace_count, 2);
    assert_eq!(
        report.node_reports[0].trace_ids,
        vec!["trace-a1".to_string(), "trace-a2".to_string()]
    );
    assert_eq!(
        report.node_reports[0].trace_paths,
        vec![
            "node-a/trace-a1.json".to_string(),
            "node-a/trace-a2.json".to_string()
        ]
    );
    assert_eq!(report.node_reports[1].node_id, "node-b");
    assert_eq!(report.node_reports[1].trace_count, 1);
    assert_eq!(
        report.total_divergences,
        report
            .node_reports
            .iter()
            .map(|node| node.divergence_count)
            .sum::<u64>()
    );
    assert_eq!(
        report.net_improvement_millionths,
        report
            .node_reports
            .iter()
            .map(|node| node.net_improvement_millionths)
            .sum::<i64>()
    );
    assert_ne!(report.artifact_hash, ContentHash::compute(b""));
}

#[test]
fn fleet_trace_dir_report_is_serde_roundtrip_stable() {
    let root = unique_fleet_dir("serde");
    fs::create_dir_all(&root).unwrap();
    let trace = make_node_trace("node-c", "trace-c1", &[750_000, 650_000]);
    write_trace(&root, "trace-c1.json", &trace);

    let snapshot = substituted_policy_snapshot(default_scope());
    let mut engine = default_engine();
    let report = engine
        .compare_fleet_trace_dir(&root, &snapshot, None)
        .expect("fleet counterfactual report");
    let json = serde_json::to_string(&report).unwrap();
    let back: FleetCounterfactualReport = serde_json::from_str(&json).unwrap();

    assert_eq!(back, report);
}

#[test]
fn fleet_trace_dir_uses_trace_id_when_node_metadata_absent() {
    let root = unique_fleet_dir("fallback-node");
    fs::create_dir_all(&root).unwrap();
    let mut trace = make_node_trace("node-unused", "trace-fallback", &[700_000]);
    trace.metadata.clear();
    write_trace(&root, "trace-fallback.json", &trace);

    let snapshot = substituted_policy_snapshot(default_scope());
    let mut engine = default_engine();
    let report = engine
        .compare_fleet_trace_dir(&root, &snapshot, None)
        .expect("fleet counterfactual report");

    assert_eq!(report.node_count, 1);
    assert_eq!(report.node_reports[0].node_id, "trace-fallback");
}

#[test]
fn fleet_trace_dir_rejects_invalid_snapshot_schema() {
    let root = unique_fleet_dir("bad-schema");
    fs::create_dir_all(&root).unwrap();
    let trace = make_node_trace("node-a", "trace-a", &[800_000]);
    write_trace(&root, "trace-a.json", &trace);
    let mut snapshot = substituted_policy_snapshot(default_scope());
    snapshot.schema_version = "franken-engine.substituted-policy-snapshot.v0".to_string();

    let mut engine = default_engine();
    let err = engine
        .compare_fleet_trace_dir(&root, &snapshot, None)
        .unwrap_err();

    assert!(matches!(
        err,
        ReplayEngineError::InvalidPolicySnapshotSchema { .. }
    ));
}

#[test]
fn fleet_trace_dir_rejects_invalid_trace_json() {
    let root = unique_fleet_dir("bad-json");
    fs::create_dir_all(&root).unwrap();
    fs::write(root.join("not-a-trace.json"), b"{\"schema\":\"wrong\"}").unwrap();

    let snapshot = substituted_policy_snapshot(default_scope());
    let mut engine = default_engine();
    let err = engine
        .compare_fleet_trace_dir(&root, &snapshot, None)
        .unwrap_err();

    assert!(matches!(err, ReplayEngineError::FleetTraceDecode { .. }));
}

// ===========================================================================
// 2. AlternatePolicy
// ===========================================================================

#[test]
fn alternate_policy_display() {
    let ap = make_alternate_policy("alt-1", "Alternative One");
    let display = ap.to_string();
    assert!(display.contains("alt-1"));
    assert!(display.contains("Alternative One"));
}

#[test]
fn alternate_policy_serde() {
    let ap = make_alternate_policy("alt-1", "Test");
    let json = serde_json::to_string(&ap).unwrap();
    let back: AlternatePolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(back, ap);
}

// ===========================================================================
// 3. ReplayScope
// ===========================================================================

#[test]
fn replay_scope_default() {
    let scope = ReplayScope::default();
    assert_eq!(scope.start_epoch, SecurityEpoch::GENESIS);
    assert_eq!(scope.start_tick, 0);
    assert!(scope.incident_filter.is_empty());
    assert_eq!(scope.min_decisions, 1);
}

#[test]
fn replay_scope_serde() {
    let scope = default_scope();
    let json = serde_json::to_string(&scope).unwrap();
    let back: ReplayScope = serde_json::from_str(&json).unwrap();
    assert_eq!(back, scope);
}

// ===========================================================================
// 4. AssumptionCategory
// ===========================================================================

#[test]
fn assumption_category_display() {
    assert_eq!(
        AssumptionCategory::NoUnmeasuredConfounding.to_string(),
        "no-unmeasured-confounding"
    );
    assert_eq!(AssumptionCategory::Positivity.to_string(), "positivity");
    assert_eq!(AssumptionCategory::Consistency.to_string(), "consistency");
    assert_eq!(AssumptionCategory::Sutva.to_string(), "sutva");
    assert_eq!(
        AssumptionCategory::ModelSpecification.to_string(),
        "model-specification"
    );
    assert_eq!(
        AssumptionCategory::TemporalStability.to_string(),
        "temporal-stability"
    );
}

#[test]
fn assumption_category_serde() {
    for cat in [
        AssumptionCategory::NoUnmeasuredConfounding,
        AssumptionCategory::Positivity,
        AssumptionCategory::Consistency,
        AssumptionCategory::Sutva,
        AssumptionCategory::ModelSpecification,
        AssumptionCategory::TemporalStability,
    ] {
        let json = serde_json::to_string(&cat).unwrap();
        let back: AssumptionCategory = serde_json::from_str(&json).unwrap();
        assert_eq!(back, cat);
    }
}

// ===========================================================================
// 5. ReplayEngineError
// ===========================================================================

#[test]
fn replay_engine_error_display() {
    let errors: Vec<ReplayEngineError> = vec![
        ReplayEngineError::NoTraces,
        ReplayEngineError::NoPolicies,
        ReplayEngineError::TooManyPolicies {
            count: 100,
            max: 64,
        },
        ReplayEngineError::TooManyDecisions {
            count: 200_000,
            max: 100_000,
        },
        ReplayEngineError::InsufficientDecisions {
            found: 1,
            required: 10,
        },
        ReplayEngineError::TraceIntegrityFailure {
            trace_id: "t1".into(),
            detail: "bad chain".into(),
        },
        ReplayEngineError::IdDerivation("id error".into()),
        ReplayEngineError::EmptyScope,
        ReplayEngineError::DuplicatePolicy {
            policy_id: "dup".into(),
        },
    ];
    for e in &errors {
        assert!(!e.to_string().is_empty());
    }
}

#[test]
fn replay_engine_error_serde() {
    let err = ReplayEngineError::NoTraces;
    let json = serde_json::to_string(&err).unwrap();
    let back: ReplayEngineError = serde_json::from_str(&json).unwrap();
    assert_eq!(back, err);
}

// ===========================================================================
// 6. ReplayEngineConfig
// ===========================================================================

#[test]
fn config_default() {
    let config = ReplayEngineConfig::default();
    assert_eq!(config.baseline_policy_id, PolicyId("baseline".to_string()));
    assert_eq!(config.estimator, EstimatorKind::DoublyRobust);
    assert!(config.regime_breakdown);
    assert!(config.record_divergences);
    assert!(config.verify_integrity);
}

#[test]
fn config_serde() {
    let config = ReplayEngineConfig::default();
    let json = serde_json::to_string(&config).unwrap();
    let back: ReplayEngineConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(back, config);
}

// ===========================================================================
// 7. CounterfactualReplayEngine — construction
// ===========================================================================

#[test]
fn engine_new_initial_state() {
    let engine = default_engine();
    assert_eq!(engine.replay_count(), 0);
    assert_eq!(
        engine.config().baseline_policy_id,
        PolicyId("baseline".to_string())
    );
}

// ===========================================================================
// 8. CounterfactualReplayEngine — compare: error paths
// ===========================================================================

#[test]
fn compare_no_traces_error() {
    let mut engine = default_engine();
    let result = engine.compare(
        &[],
        &[make_alternate_policy("alt", "d")],
        &default_scope(),
        None,
    );
    assert!(matches!(result, Err(ReplayEngineError::NoTraces)));
}

#[test]
fn compare_no_policies_error() {
    let mut engine = default_engine();
    let trace = simple_trace();
    let result = engine.compare(&[trace], &[], &default_scope(), None);
    assert!(matches!(result, Err(ReplayEngineError::NoPolicies)));
}

#[test]
fn compare_duplicate_policy_error() {
    let mut engine = default_engine();
    let trace = simple_trace();
    let policies = vec![
        make_alternate_policy("same-id", "first"),
        make_alternate_policy("same-id", "second"),
    ];
    let result = engine.compare(&[trace], &policies, &default_scope(), None);
    assert!(matches!(
        result,
        Err(ReplayEngineError::DuplicatePolicy { .. })
    ));
}

#[test]
fn compare_insufficient_decisions_error() {
    let mut engine = default_engine();
    let trace = simple_trace(); // 3 decisions
    let mut scope = default_scope();
    scope.min_decisions = 1000; // require more than we have
    let result = engine.compare(&[trace], &[make_alternate_policy("alt", "d")], &scope, None);
    assert!(matches!(
        result,
        Err(ReplayEngineError::InsufficientDecisions { .. })
    ));
}

// ===========================================================================
// 9. CounterfactualReplayEngine — compare: success
// ===========================================================================

#[test]
fn compare_single_policy_success() {
    let mut engine = default_engine();
    let trace = simple_trace();
    let policies = vec![make_alternate_policy("alt-threshold", "Higher threshold")];
    let result = engine
        .compare(&[trace], &policies, &default_scope(), None)
        .unwrap();

    assert_eq!(result.schema_version, REPLAY_ENGINE_SCHEMA_VERSION);
    assert_eq!(result.trace_count, 1);
    assert_eq!(result.total_decisions, 3);
    assert_eq!(result.policy_reports.len(), 1);
    assert_eq!(result.ranked_recommendations.len(), 1);
    assert!(!result.global_assumptions.is_empty());
}

#[test]
fn compare_increments_replay_count() {
    let mut engine = default_engine();
    let trace = simple_trace();
    let policies = vec![make_alternate_policy("alt", "d")];
    engine
        .compare(
            std::slice::from_ref(&trace),
            &policies,
            &default_scope(),
            None,
        )
        .unwrap();
    assert_eq!(engine.replay_count(), 1);
    engine
        .compare(
            std::slice::from_ref(&trace),
            &policies,
            &default_scope(),
            None,
        )
        .unwrap();
    assert_eq!(engine.replay_count(), 2);
}

#[test]
fn compare_multiple_policies() {
    let mut engine = default_engine();
    let trace = simple_trace();
    let policies = vec![
        make_alternate_policy("alt-1", "Policy 1"),
        make_alternate_policy("alt-2", "Policy 2"),
        make_override_policy("force-safe", LaneAction::FallbackSafe),
    ];
    let result = engine
        .compare(&[trace], &policies, &default_scope(), None)
        .unwrap();

    assert_eq!(result.policy_reports.len(), 3);
    assert_eq!(result.ranked_recommendations.len(), 3);
    // Recommendations should be ranked 1, 2, 3
    assert_eq!(result.ranked_recommendations[0].rank, 1);
    assert_eq!(result.ranked_recommendations[1].rank, 2);
    assert_eq!(result.ranked_recommendations[2].rank, 3);
}

// ===========================================================================
// 10. PolicyComparisonReport
// ===========================================================================

#[test]
fn policy_report_fields() {
    let mut engine = default_engine();
    let trace = simple_trace();
    let policies = vec![make_alternate_policy("alt", "d")];
    let result = engine
        .compare(&[trace], &policies, &default_scope(), None)
        .unwrap();
    let report = &result.policy_reports[0];

    assert_eq!(report.schema_version, REPLAY_ENGINE_SCHEMA_VERSION);
    assert_eq!(report.baseline_policy_id, PolicyId("baseline".into()));
    assert_eq!(report.alternate_policy_id, PolicyId("alt".into()));
    assert_eq!(report.decisions_evaluated, 3);
    assert!(!report.assumptions.is_empty());
}

#[test]
fn policy_report_divergence_rate() {
    let mut engine = default_engine();
    let trace = simple_trace();
    let policies = vec![make_override_policy("force-safe", LaneAction::FallbackSafe)];
    let result = engine
        .compare(&[trace], &policies, &default_scope(), None)
        .unwrap();
    let report = &result.policy_reports[0];
    // With FallbackSafe override, all actions should diverge
    let rate = report.divergence_rate_millionths();
    assert!(
        rate > 0,
        "expected some divergences with forced action override"
    );
}

#[test]
fn policy_report_serde() {
    let mut engine = default_engine();
    let trace = simple_trace();
    let policies = vec![make_alternate_policy("alt", "d")];
    let result = engine
        .compare(&[trace], &policies, &default_scope(), None)
        .unwrap();
    let report = &result.policy_reports[0];

    let json = serde_json::to_string(report).unwrap();
    let back: PolicyComparisonReport = serde_json::from_str(&json).unwrap();
    assert_eq!(back, *report);
}

// ===========================================================================
// 11. Recommendation
// ===========================================================================

#[test]
fn recommendation_display() {
    let mut engine = default_engine();
    let trace = simple_trace();
    let policies = vec![make_alternate_policy("alt-x", "d")];
    let result = engine
        .compare(&[trace], &policies, &default_scope(), None)
        .unwrap();

    let rec = &result.ranked_recommendations[0];
    let display = rec.to_string();
    assert!(display.contains("alt-x"));
    assert!(display.contains("#1"));
}

#[test]
fn recommendation_serde() {
    let rec = Recommendation {
        rank: 1,
        policy_id: PolicyId("alt-1".into()),
        expected_improvement_millionths: 100_000,
        confidence_millionths: 950_000,
        safety_status: EnvelopeStatus::Safe,
        rationale: "test".into(),
    };
    let json = serde_json::to_string(&rec).unwrap();
    let back: Recommendation = serde_json::from_str(&json).unwrap();
    assert_eq!(back, rec);
}

// ===========================================================================
// 12. AssumptionCard
// ===========================================================================

#[test]
fn assumption_card_serde() {
    let card = AssumptionCard {
        assumption_id: "test".into(),
        category: AssumptionCategory::Consistency,
        description: "test assumption".into(),
        testable: false,
        test_passed: None,
        sensitivity_bound_millionths: 0,
    };
    let json = serde_json::to_string(&card).unwrap();
    let back: AssumptionCard = serde_json::from_str(&json).unwrap();
    assert_eq!(back, card);
}

// ===========================================================================
// 13. DecisionComparison
// ===========================================================================

#[test]
fn decision_comparison_serde() {
    let dc = DecisionComparison {
        decision_index: 0,
        tick: 100,
        epoch: test_epoch(),
        original_action: "native".into(),
        alternate_action: "wasm".into(),
        original_outcome_millionths: 800_000,
        counterfactual_outcome_millionths: 600_000,
        diverged: true,
        regime: "normal".into(),
    };
    let json = serde_json::to_string(&dc).unwrap();
    let back: DecisionComparison = serde_json::from_str(&json).unwrap();
    assert_eq!(back, dc);
}

// ===========================================================================
// 14. ReplayComparisonResult
// ===========================================================================

#[test]
fn comparison_result_serde() {
    let mut engine = default_engine();
    let trace = simple_trace();
    let policies = vec![make_alternate_policy("alt", "d")];
    let result = engine
        .compare(&[trace], &policies, &default_scope(), None)
        .unwrap();

    let json = serde_json::to_string(&result).unwrap();
    let back: ReplayComparisonResult = serde_json::from_str(&json).unwrap();
    assert_eq!(back, result);
}

#[test]
fn comparison_result_artifact_hash_deterministic() {
    let mut engine1 = default_engine();
    let mut engine2 = default_engine();
    let trace = simple_trace();
    let policies = vec![make_alternate_policy("alt", "d")];
    let scope = default_scope();

    let r1 = engine1
        .compare(std::slice::from_ref(&trace), &policies, &scope, None)
        .unwrap();
    let r2 = engine2
        .compare(std::slice::from_ref(&trace), &policies, &scope, None)
        .unwrap();
    assert_eq!(r1.artifact_hash, r2.artifact_hash);
}

#[test]
fn policy_report_artifact_hash_tracks_public_report_content() {
    let trace = simple_trace();
    let mut engine_a = default_engine();
    let mut engine_b = default_engine();
    let policy_a = vec![make_alternate_policy("alt", "description-a")];
    let policy_b = vec![make_alternate_policy("alt", "description-b")];

    let result_a = engine_a
        .compare(
            std::slice::from_ref(&trace),
            &policy_a,
            &default_scope(),
            None,
        )
        .unwrap();
    let result_b = engine_b
        .compare(
            std::slice::from_ref(&trace),
            &policy_b,
            &default_scope(),
            None,
        )
        .unwrap();

    assert_ne!(
        result_a.policy_reports[0].alternate_description,
        result_b.policy_reports[0].alternate_description
    );
    assert_ne!(
        result_a.policy_reports[0].artifact_hash,
        result_b.policy_reports[0].artifact_hash
    );
}

#[test]
fn comparison_result_artifact_hash_tracks_scope_payload() {
    let trace = simple_trace();
    let policies = vec![make_alternate_policy("alt", "d")];
    let mut engine_a = default_engine();
    let mut engine_b = default_engine();
    let scope_a = default_scope();
    let mut scope_b = default_scope();
    scope_b.start_tick = 100;

    let result_a = engine_a
        .compare(std::slice::from_ref(&trace), &policies, &scope_a, None)
        .unwrap();
    let result_b = engine_b
        .compare(&[trace], &policies, &scope_b, None)
        .unwrap();

    assert_eq!(result_a.total_decisions, result_b.total_decisions);
    assert_eq!(result_a.trace_count, result_b.trace_count);
    assert_eq!(result_a.policy_reports, result_b.policy_reports);
    assert_ne!(result_a.scope, result_b.scope);
    assert_ne!(result_a.artifact_hash, result_b.artifact_hash);
}

// ===========================================================================
// 15. Scoped replay
// ===========================================================================

#[test]
fn compare_with_epoch_scope() {
    let mut engine = default_engine();
    let trace = simple_trace();
    let mut scope = default_scope();
    scope.start_epoch = test_epoch();
    scope.end_epoch = test_epoch();
    let policies = vec![make_alternate_policy("alt", "d")];
    let result = engine.compare(&[trace], &policies, &scope, None).unwrap();
    assert_eq!(result.total_decisions, 3);
}

#[test]
fn compare_with_empty_scope_error() {
    let mut engine = default_engine();
    let trace = simple_trace();
    let mut scope = default_scope();
    // Set scope to an epoch range that excludes all decisions
    scope.start_epoch = SecurityEpoch::from_raw(999);
    scope.end_epoch = SecurityEpoch::from_raw(1000);
    let policies = vec![make_alternate_policy("alt", "d")];
    let result = engine.compare(&[trace], &policies, &scope, None);
    assert!(matches!(result, Err(ReplayEngineError::EmptyScope)));
}

// ===========================================================================
// 16. Full lifecycle
// ===========================================================================

#[test]
fn full_lifecycle_compare_rank_serialize() {
    // 1. Build traces
    let trace = make_trace(vec![
        make_decision(0, "native", 800_000),
        make_decision(1, "native", 900_000),
        make_decision(2, "wasm", 600_000),
        make_decision(3, "native", 700_000),
        make_decision(4, "native", 850_000),
    ]);

    // 2. Define alternate policies
    let policies = vec![
        make_alternate_policy("higher-threshold", "Raise threshold to 600k"),
        make_override_policy("force-safe", LaneAction::FallbackSafe),
    ];

    // 3. Run comparison
    let mut engine = default_engine();
    let result = engine
        .compare(&[trace], &policies, &default_scope(), None)
        .unwrap();

    // 4. Verify structure
    assert_eq!(result.trace_count, 1);
    assert_eq!(result.total_decisions, 5);
    assert_eq!(result.policy_reports.len(), 2);
    assert_eq!(result.ranked_recommendations.len(), 2);
    assert!(!result.global_assumptions.is_empty());

    // 5. Verify ranking order
    let recs = &result.ranked_recommendations;
    assert_eq!(recs[0].rank, 1);
    assert_eq!(recs[1].rank, 2);
    // Best recommendation should have higher improvement
    assert!(recs[0].expected_improvement_millionths >= recs[1].expected_improvement_millionths);

    // 6. Verify reports have assumptions
    for report in &result.policy_reports {
        assert!(!report.assumptions.is_empty());
        assert_eq!(report.decisions_evaluated, 5);
    }

    // 7. Serde round-trip
    let json = serde_json::to_string(&result).unwrap();
    let back: ReplayComparisonResult = serde_json::from_str(&json).unwrap();
    assert_eq!(back, result);

    // 8. Engine state
    assert_eq!(engine.replay_count(), 1);
}

// ===========================================================================
// 17. PolicyComparisonReport edge cases
// ===========================================================================

#[test]
fn policy_report_is_confident_improvement() {
    let mut engine = default_engine();
    let trace = simple_trace();
    let policies = vec![make_alternate_policy("alt", "d")];
    let result = engine
        .compare(&[trace], &policies, &default_scope(), None)
        .unwrap();
    let report = &result.policy_reports[0];
    // is_confident_improvement depends on safety_status == Safe AND net > 0
    let expected =
        report.safety_status == EnvelopeStatus::Safe && report.net_improvement_millionths > 0;
    assert_eq!(report.is_confident_improvement(), expected);
}

#[test]
fn policy_report_divergence_rate_zero_decisions() {
    // A manually constructed report with zero decisions
    let report = PolicyComparisonReport {
        schema_version: REPLAY_ENGINE_SCHEMA_VERSION.to_string(),
        baseline_policy_id: PolicyId("base".to_string()),
        alternate_policy_id: PolicyId("alt".to_string()),
        alternate_description: "test".to_string(),
        decisions_evaluated: 0,
        divergence_count: 0,
        total_original_outcome_millionths: 0,
        total_counterfactual_outcome_millionths: 0,
        net_improvement_millionths: 0,
        regime_breakdown: BTreeMap::new(),
        confidence_envelope: frankenengine_engine::counterfactual_evaluator::ConfidenceEnvelope {
            estimate_millionths: 0,
            lower_millionths: 0,
            upper_millionths: 0,
            confidence_millionths: 950_000,
            effective_samples: 0,
        },
        safety_status: EnvelopeStatus::Inconclusive,
        divergent_decisions: vec![],
        assumptions: vec![],
        artifact_hash: ContentHash::compute(b"test"),
    };
    assert_eq!(report.divergence_rate_millionths(), 0);
}

// ===========================================================================
// 18. ReplayEngineError additional coverage
// ===========================================================================

#[test]
fn replay_engine_error_is_std_error() {
    let err = ReplayEngineError::NoTraces;
    let _: &dyn std::error::Error = &err;
}

#[test]
fn replay_engine_error_all_variants_serde() {
    let errors = vec![
        ReplayEngineError::NoTraces,
        ReplayEngineError::NoPolicies,
        ReplayEngineError::TooManyPolicies {
            count: 100,
            max: 64,
        },
        ReplayEngineError::TooManyDecisions {
            count: 200_000,
            max: 100_000,
        },
        ReplayEngineError::InsufficientDecisions {
            found: 1,
            required: 10,
        },
        ReplayEngineError::TraceIntegrityFailure {
            trace_id: "t1".into(),
            detail: "bad".into(),
        },
        ReplayEngineError::IdDerivation("id err".into()),
        ReplayEngineError::EmptyScope,
        ReplayEngineError::DuplicatePolicy {
            policy_id: "dup".into(),
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let back: ReplayEngineError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, back);
    }
}

// ===========================================================================
// 19. Multiple traces
// ===========================================================================

#[test]
fn compare_multiple_traces() {
    let mut engine = default_engine();
    let trace1 = make_trace(vec![
        make_decision(0, "native", 800_000),
        make_decision(1, "wasm", 600_000),
    ]);
    let trace2 = make_trace(vec![
        make_decision(0, "native", 700_000),
        make_decision(1, "native", 900_000),
        make_decision(2, "wasm", 500_000),
    ]);
    let policies = vec![make_alternate_policy("alt", "d")];
    let result = engine
        .compare(&[trace1, trace2], &policies, &default_scope(), None)
        .unwrap();
    assert_eq!(result.trace_count, 2);
    assert_eq!(result.total_decisions, 5);
}

// ===========================================================================
// 20. AssumptionCard with testable fields
// ===========================================================================

#[test]
fn assumption_card_testable_with_result() {
    let card = AssumptionCard {
        assumption_id: "test-pass".into(),
        category: AssumptionCategory::Positivity,
        description: "positivity holds".into(),
        testable: true,
        test_passed: Some(true),
        sensitivity_bound_millionths: 50_000,
    };
    let json = serde_json::to_string(&card).unwrap();
    let back: AssumptionCard = serde_json::from_str(&json).unwrap();
    assert_eq!(back, card);
    assert!(back.testable);
    assert_eq!(back.test_passed, Some(true));
}

#[test]
fn assumption_card_testable_failed() {
    let card = AssumptionCard {
        assumption_id: "test-fail".into(),
        category: AssumptionCategory::Sutva,
        description: "SUTVA violated".into(),
        testable: true,
        test_passed: Some(false),
        sensitivity_bound_millionths: 200_000,
    };
    let json = serde_json::to_string(&card).unwrap();
    let back: AssumptionCard = serde_json::from_str(&json).unwrap();
    assert_eq!(back.test_passed, Some(false));
}

// ===========================================================================
// 21. Config with non-default settings
// ===========================================================================

#[test]
fn config_non_default_settings() {
    let config = ReplayEngineConfig {
        baseline_policy_id: PolicyId("custom-baseline".to_string()),
        baseline_action: LaneAction::SuspendAdaptive,
        estimator: EstimatorKind::Ips,
        confidence_millionths: 990_000,
        regime_breakdown: false,
        record_divergences: false,
        max_divergences_per_policy: 10,
        verify_integrity: false,
    };
    let json = serde_json::to_string(&config).unwrap();
    let back: ReplayEngineConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(back, config);
    assert!(!back.regime_breakdown);
    assert!(!back.record_divergences);
}

// ===========================================================================
// 22. ReplayScope with incident filter
// ===========================================================================

#[test]
fn replay_scope_with_incident_filter_serde() {
    let mut scope = ReplayScope::default();
    scope.incident_filter.insert("incident-1".to_string());
    scope.incident_filter.insert("incident-2".to_string());
    scope.min_decisions = 5;
    let json = serde_json::to_string(&scope).unwrap();
    let back: ReplayScope = serde_json::from_str(&json).unwrap();
    assert_eq!(back, scope);
    assert_eq!(back.incident_filter.len(), 2);
}

// ===========================================================================
// 23. Ranked recommendations ordering
// ===========================================================================

#[test]
fn recommendations_ranked_by_improvement() {
    let mut engine = default_engine();
    let trace = make_trace(vec![
        make_decision(0, "native", 800_000),
        make_decision(1, "wasm", 600_000),
        make_decision(2, "native", 900_000),
        make_decision(3, "wasm", 400_000),
    ]);
    let policies = vec![
        make_alternate_policy("alt-1", "d1"),
        make_alternate_policy("alt-2", "d2"),
        make_override_policy("force-safe", LaneAction::FallbackSafe),
    ];
    let result = engine
        .compare(&[trace], &policies, &default_scope(), None)
        .unwrap();
    let recs = &result.ranked_recommendations;
    // Ranks should be monotonically increasing
    for window in recs.windows(2) {
        assert!(window[0].rank < window[1].rank);
    }
}

// ===========================================================================
// 24. Global assumptions present
// ===========================================================================

#[test]
fn global_assumptions_non_empty() {
    let mut engine = default_engine();
    let trace = simple_trace();
    let policies = vec![make_alternate_policy("alt", "d")];
    let result = engine
        .compare(&[trace], &policies, &default_scope(), None)
        .unwrap();
    assert!(!result.global_assumptions.is_empty());
    for a in &result.global_assumptions {
        assert!(!a.assumption_id.is_empty());
        assert!(!a.description.is_empty());
    }
}

// ===========================================================================
// 25. Outcome ground truth — the recorded and counterfactual columns are real
//     model outputs, not echoed magic numbers (bd-bg9l1.4)
// ===========================================================================

#[test]
fn original_total_is_real_model_ground_truth() {
    // The engine reports the recorded `outcome_millionths` verbatim in the
    // original column. Because those outcomes are produced by the engine's real
    // outcome model, the reported total must equal an independent in-test
    // recomputation through that same model. If the recorded outcomes were
    // arbitrary hand-set numbers this would only prove "the engine echoes what I
    // wrote"; tying both sides to the model gives it teeth — a regression in how
    // an action/loss becomes an outcome is now observable here.
    let mut engine = default_engine();
    let trace = simple_trace();
    let policies = vec![make_alternate_policy("alt", "d")];
    let result = engine
        .compare(&[trace], &policies, &default_scope(), None)
        .unwrap();
    let report = &result.policy_reports[0];

    let expected: i64 = SIMPLE_TRACE_SPEC
        .iter()
        .map(|(action, native_loss)| recorded_outcome(action, *native_loss))
        .sum();
    assert_eq!(
        report.total_original_outcome_millionths, expected,
        "the reported original total must equal the real model's score for the recorded decisions"
    );

    // Teeth: the outcomes are genuinely loss-sensitive, not a constant. Every
    // chosen action carries loss, so the recorded total is strictly below the
    // zero-loss ceiling the model assigns the (unpriced) fallback action. A
    // model that ignored loss (returned a constant) would collapse these and
    // fail here.
    let zero_loss_ceiling: i64 = SIMPLE_TRACE_SPEC
        .iter()
        .map(|(_, native_loss)| {
            estimate_lane_outcome_millionths(
                &LaneAction::FallbackSafe.to_string(),
                &loss_matrix_for(*native_loss),
                RECORDED_THRESHOLD,
            )
        })
        .sum();
    assert!(
        expected < zero_loss_ceiling,
        "loss must move the outcome: recorded={expected}, zero-loss ceiling={zero_loss_ceiling}"
    );
}

#[test]
fn fallback_override_total_is_real_model_score() {
    // A forced-`FallbackSafe` policy makes the engine re-score every decision on
    // the substituted action through the **real** model. With `fallback_safe`
    // absent from each decision's loss matrix the model prices it at the
    // zero-loss ceiling, so the counterfactual total must equal the exact model
    // score for the forced action — not merely "some different number". This
    // proves the engine runs the genuine model on the substituted action rather
    // than fabricating a delta over the recorded numbers.
    let mut engine = default_engine();
    let trace = simple_trace();
    let policies = vec![make_override_policy("force-safe", LaneAction::FallbackSafe)];
    let result = engine
        .compare(&[trace], &policies, &default_scope(), None)
        .unwrap();
    let report = &result.policy_reports[0];

    let forced = LaneAction::FallbackSafe.to_string();
    let expected_cf: i64 = SIMPLE_TRACE_SPEC
        .iter()
        .map(|(_, native_loss)| {
            estimate_lane_outcome_millionths(
                &forced,
                &loss_matrix_for(*native_loss),
                RECORDED_THRESHOLD,
            )
        })
        .sum();
    let expected_original: i64 = SIMPLE_TRACE_SPEC
        .iter()
        .map(|(action, native_loss)| recorded_outcome(action, *native_loss))
        .sum();

    assert_eq!(
        report.total_counterfactual_outcome_millionths, expected_cf,
        "the counterfactual total must equal the real model's score for the forced fallback action"
    );
    assert_eq!(
        report.total_original_outcome_millionths, expected_original,
        "the original column must remain the model-derived recorded ground truth"
    );
    assert_eq!(
        report.net_improvement_millionths,
        expected_cf - expected_original,
        "net improvement must be the exact model-computed delta, not a fabricated one"
    );
    // Teeth: the perturbation genuinely moved the outcome (the engine is not a
    // no-op echoing the recorded column).
    assert_ne!(
        report.total_original_outcome_millionths, report.total_counterfactual_outcome_millionths,
        "forcing the fallback action must move the outcome away from the recorded one"
    );
}
