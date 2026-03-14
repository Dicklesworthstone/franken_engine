#![forbid(unsafe_code)]
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
use std::fs;
use std::path::{Path, PathBuf};

use frankenengine_engine::{
    EVAL_ERROR_MIGRATION_NOTES, EvalCorrelationIds, EvalError, EvalErrorClass, EvalErrorCode,
    EvalSourceLocation, EvalStackFrame, ExceptionBoundary, ExceptionTransitionEvent, HybridRouter,
    JsEngine, QuickJsInspiredNativeEngine, V8InspiredNativeEngine, emit_exception_transition_event,
    propagate_error_across_boundary, propagate_result_across_boundary, sorted_eval_errors,
    stable_sort_eval_errors,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const CONTRACT_SCHEMA_VERSION: &str = "franken-engine.rgc-exception-diagnostics-semantics.v1";
const VECTORS_SCHEMA_VERSION: &str =
    "franken-engine.rgc-exception-diagnostics-semantics-vectors.v1";
const TRACE_SCHEMA_VERSION: &str = "franken-engine.rgc-exception-diagnostics-semantics.trace.v1";
const TRACE_BEGIN_MARKER: &str = "__RGC305_TRACE_BEGIN__";
const TRACE_END_MARKER: &str = "__RGC305_TRACE_END__";
const CONTRACT_JSON: &str =
    include_str!("../../../docs/rgc_exception_diagnostics_semantics_v1.json");
const VECTORS_JSON: &str =
    include_str!("../../../docs/rgc_exception_diagnostics_semantics_vectors_v1.json");

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ExceptionDiagnosticsContract {
    schema_version: String,
    contract_version: String,
    bead_id: String,
    policy_id: String,
    required_semantics_classes: Vec<String>,
    required_log_keys: Vec<String>,
    required_artifacts: Vec<String>,
    test_vectors_source: String,
    gate_runner: GateRunner,
    operator_verification: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct GateRunner {
    script: String,
    replay_wrapper: String,
    strict_mode: String,
    manifest_schema_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ExceptionDiagnosticsVectors {
    schema_version: String,
    contract_version: String,
    bead_id: String,
    generated_by: String,
    generated_at_utc: String,
    vectors: Vec<ExceptionDiagnosticsVector>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ExceptionDiagnosticsVector {
    scenario_id: String,
    semantics_class: String,
    severity: String,
    deterministic_seed: u64,
    input_source: String,
    boundaries: Vec<String>,
    expected_error_class: String,
    expected_error_code: String,
    expected_divergence_class: String,
    command_template: String,
    minimal_repro_pointer: String,
    remediation_guidance: String,
    requires_replay: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DiagnosticSnapshot {
    scenario_id: String,
    lane: String,
    error_class: String,
    error_code: String,
    location: Option<String>,
    trace_id: String,
    decision_id: String,
    policy_id: String,
    stack_trace: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DifferentialClassification {
    scenario_id: String,
    classification: String,
    remediation_guidance: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DiagnosticTraceArtifact {
    schema_version: String,
    bead_id: String,
    trace_hash: String,
    snapshots: Vec<DiagnosticSnapshot>,
    differential: Vec<DifferentialClassification>,
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_to_string(path: &Path) -> String {
    fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()))
}

fn parse_contract() -> ExceptionDiagnosticsContract {
    serde_json::from_str(CONTRACT_JSON).expect("exception diagnostics contract must parse")
}

fn parse_vectors() -> ExceptionDiagnosticsVectors {
    serde_json::from_str(VECTORS_JSON).expect("exception diagnostics vectors must parse")
}

fn parse_boundaries(boundaries: &[String]) -> Vec<ExceptionBoundary> {
    boundaries
        .iter()
        .map(|boundary| match boundary.as_str() {
            "sync_callframe" => ExceptionBoundary::SyncCallframe,
            "async_job" => ExceptionBoundary::AsyncJob,
            "hostcall" => ExceptionBoundary::Hostcall,
            other => panic!("unknown boundary `{other}`"),
        })
        .collect()
}

fn error_for_lane(lane: &str, input: &str) -> EvalError {
    match lane {
        "quickjs" => {
            let mut engine = QuickJsInspiredNativeEngine;
            engine
                .eval(input)
                .expect_err("quickjs scenario should error")
        }
        "v8" => {
            let mut engine = V8InspiredNativeEngine;
            engine.eval(input).expect_err("v8 scenario should error")
        }
        other => panic!("unknown lane `{other}`"),
    }
}

fn collect_snapshot(
    scenario_id: &str,
    lane: &str,
    input: &str,
    boundaries: &[ExceptionBoundary],
) -> DiagnosticSnapshot {
    let mut error = error_for_lane(lane, input);
    for boundary in boundaries {
        error = propagate_error_across_boundary(error, *boundary);
    }

    let (trace_id, decision_id, policy_id) =
        if let Some(correlation) = error.correlation_ids.clone() {
            (
                correlation.trace_id,
                correlation.decision_id,
                correlation.policy_id,
            )
        } else {
            // Empty-source normalization errors are raised before eval correlation IDs are attached.
            // Use deterministic per-lane placeholders so cross-lane diffs remain intentional/stable.
            (
                format!("missing-trace-id-{lane}"),
                format!("missing-decision-id-{lane}"),
                format!("missing-policy-id-{lane}"),
            )
        };

    DiagnosticSnapshot {
        scenario_id: scenario_id.to_string(),
        lane: lane.to_string(),
        error_class: error.class().stable_label().to_string(),
        error_code: error.stable_namespace().to_string(),
        location: error
            .location
            .as_ref()
            .map(|location| format!("{location}")),
        trace_id,
        decision_id,
        policy_id,
        stack_trace: error.formatted_stack_trace(),
    }
}

fn normalized_signature(
    snapshot: &DiagnosticSnapshot,
) -> (String, String, Option<String>, Vec<String>) {
    (
        snapshot.error_class.clone(),
        snapshot.error_code.clone(),
        snapshot.location.clone(),
        snapshot.stack_trace.clone(),
    )
}

fn classify_pair(
    left: &DiagnosticSnapshot,
    right: &DiagnosticSnapshot,
    remediation_guidance: &str,
) -> DifferentialClassification {
    let normalized_left = normalized_signature(left);
    let normalized_right = normalized_signature(right);

    let classification = if normalized_left != normalized_right {
        "incompatible"
    } else if left.trace_id != right.trace_id
        || left.decision_id != right.decision_id
        || left.policy_id != right.policy_id
    {
        "intentional_divergence"
    } else {
        "compatible"
    };

    DifferentialClassification {
        scenario_id: left.scenario_id.clone(),
        classification: classification.to_string(),
        remediation_guidance: remediation_guidance.to_string(),
    }
}

fn build_trace_artifact(vectors: &ExceptionDiagnosticsVectors) -> DiagnosticTraceArtifact {
    let mut snapshots = Vec::<DiagnosticSnapshot>::new();
    let mut differential = Vec::<DifferentialClassification>::new();

    for vector in &vectors.vectors {
        let parsed_boundaries = parse_boundaries(&vector.boundaries);
        let quickjs = collect_snapshot(
            vector.scenario_id.as_str(),
            "quickjs",
            vector.input_source.as_str(),
            &parsed_boundaries,
        );
        let v8 = collect_snapshot(
            vector.scenario_id.as_str(),
            "v8",
            vector.input_source.as_str(),
            &parsed_boundaries,
        );

        let classification = classify_pair(&quickjs, &v8, vector.remediation_guidance.as_str());

        snapshots.push(quickjs);
        snapshots.push(v8);
        differential.push(classification);
    }

    snapshots.sort_by(|left, right| {
        left.scenario_id
            .cmp(&right.scenario_id)
            .then(left.lane.cmp(&right.lane))
    });
    differential.sort_by(|left, right| left.scenario_id.cmp(&right.scenario_id));

    let payload = serde_json::to_vec(&(snapshots.clone(), differential.clone()))
        .expect("trace payload should serialize");
    let trace_hash = format!("sha256:{}", hex::encode(Sha256::digest(payload)));

    DiagnosticTraceArtifact {
        schema_version: TRACE_SCHEMA_VERSION.to_string(),
        bead_id: "bd-1lsy.4.5".to_string(),
        trace_hash,
        snapshots,
        differential,
    }
}

#[test]
fn rgc_305_doc_contains_required_sections() {
    let path = repo_root().join("docs/RGC_EXCEPTION_DIAGNOSTICS_SEMANTICS_V1.md");
    let doc = read_to_string(&path);

    for section in [
        "# RGC Exception and Diagnostic Semantics V1",
        "## Scope",
        "## Contract Version",
        "## Required Semantics Classes",
        "## Structured Logging Contract",
        "## Differential Conformance Rules",
        "## Replay and Execution",
        "## Required Artifacts",
        "## Operator Verification",
    ] {
        assert!(
            doc.contains(section),
            "missing section in {}: {section}",
            path.display()
        );
    }
}

#[test]
fn rgc_305_readme_section_documents_gate_commands_and_artifacts() {
    let path = repo_root().join("README.md");
    let readme = read_to_string(&path);

    for fragment in [
        "## RGC Exception and Diagnostic Semantics Gate",
        "./scripts/run_rgc_exception_diagnostics_semantics.sh ci",
        "./scripts/e2e/rgc_exception_diagnostics_semantics_replay.sh ci",
        "docs/rgc_exception_diagnostics_semantics_v1.json",
        "docs/rgc_exception_diagnostics_semantics_vectors_v1.json",
        "artifacts/rgc_exception_diagnostics_semantics/<timestamp>/run_manifest.json",
        "artifacts/rgc_exception_diagnostics_semantics/<timestamp>/events.jsonl",
        "artifacts/rgc_exception_diagnostics_semantics/<timestamp>/commands.txt",
        "artifacts/rgc_exception_diagnostics_semantics/<timestamp>/diagnostic_trace.json",
    ] {
        assert!(
            readme.contains(fragment),
            "missing README fragment in {}: {fragment}",
            path.display()
        );
    }
}

#[test]
fn rgc_305_contract_is_versioned_and_replay_bound() {
    let contract = parse_contract();

    assert_eq!(contract.schema_version, CONTRACT_SCHEMA_VERSION);
    assert_eq!(contract.contract_version, "1.0.0");
    assert_eq!(contract.bead_id, "bd-1lsy.4.5");
    assert_eq!(
        contract.policy_id,
        "policy-rgc-exception-diagnostics-semantics-v1"
    );
    assert_eq!(
        contract.test_vectors_source,
        "docs/rgc_exception_diagnostics_semantics_vectors_v1.json"
    );

    let required_classes: BTreeSet<&str> = contract
        .required_semantics_classes
        .iter()
        .map(String::as_str)
        .collect();
    for class_name in [
        "sync_exception_propagation",
        "async_exception_propagation",
        "diagnostic_metadata_stability",
    ] {
        assert!(
            required_classes.contains(class_name),
            "missing required semantics class {class_name}"
        );
    }

    let log_keys: BTreeSet<&str> = contract
        .required_log_keys
        .iter()
        .map(String::as_str)
        .collect();
    for key in [
        "trace_id",
        "decision_id",
        "policy_id",
        "component",
        "event",
        "scenario_id",
        "lane",
        "error_class",
        "error_code",
        "outcome",
    ] {
        assert!(log_keys.contains(key), "missing required log key {key}");
    }

    let artifacts: BTreeSet<&str> = contract
        .required_artifacts
        .iter()
        .map(String::as_str)
        .collect();
    for artifact in [
        "run_manifest.json",
        "events.jsonl",
        "commands.txt",
        "diagnostic_trace.json",
        "step_logs/step_*.log",
    ] {
        assert!(
            artifacts.contains(artifact),
            "missing required artifact {artifact}"
        );
    }

    assert_eq!(
        contract.gate_runner.script,
        "scripts/run_rgc_exception_diagnostics_semantics.sh"
    );
    assert_eq!(
        contract.gate_runner.replay_wrapper,
        "scripts/e2e/rgc_exception_diagnostics_semantics_replay.sh"
    );
    assert_eq!(
        contract.gate_runner.strict_mode,
        "rch_only_no_local_fallback"
    );
    assert_eq!(
        contract.gate_runner.manifest_schema_version,
        "franken-engine.rgc-exception-diagnostics-semantics.run-manifest.v1"
    );
}

#[test]
fn rgc_305_vectors_cover_required_classes_and_unique_seeds() {
    let contract = parse_contract();
    let vectors = parse_vectors();

    assert_eq!(vectors.schema_version, VECTORS_SCHEMA_VERSION);
    assert_eq!(vectors.contract_version, contract.contract_version);
    assert_eq!(vectors.bead_id, contract.bead_id);

    let classes_in_vectors = vectors
        .vectors
        .iter()
        .map(|vector| vector.semantics_class.as_str())
        .collect::<BTreeSet<_>>();
    let required_classes = contract
        .required_semantics_classes
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    assert_eq!(classes_in_vectors, required_classes);

    let mut seen_scenario_ids = BTreeSet::<&str>::new();
    let mut seen_seeds = BTreeSet::<u64>::new();
    for vector in &vectors.vectors {
        assert!(
            seen_scenario_ids.insert(vector.scenario_id.as_str()),
            "duplicate scenario_id: {}",
            vector.scenario_id
        );
        assert!(
            seen_seeds.insert(vector.deterministic_seed),
            "duplicate deterministic seed: {}",
            vector.deterministic_seed
        );
        assert!(
            !vector.command_template.trim().is_empty(),
            "empty command_template for scenario {}",
            vector.scenario_id
        );
        assert!(
            !vector.minimal_repro_pointer.trim().is_empty(),
            "empty minimal_repro_pointer for scenario {}",
            vector.scenario_id
        );
        assert!(
            !vector.remediation_guidance.trim().is_empty(),
            "empty remediation guidance for scenario {}",
            vector.scenario_id
        );
        assert!(vector.requires_replay, "scenario must require replay");
    }
}

#[test]
fn rgc_305_boundary_propagation_semantics_cover_sync_async_hostcall() {
    let vector = parse_vectors()
        .vectors
        .into_iter()
        .find(|vector| vector.scenario_id == "rgc-305-async-boundary-chain")
        .expect("missing async boundary chain vector");

    let boundaries = parse_boundaries(&vector.boundaries);
    let snapshot = collect_snapshot(
        vector.scenario_id.as_str(),
        "quickjs",
        vector.input_source.as_str(),
        &boundaries,
    );

    assert_eq!(snapshot.error_class, vector.expected_error_class);
    assert_eq!(snapshot.error_code, vector.expected_error_code);
    assert_eq!(snapshot.stack_trace.len(), 4);
    assert!(snapshot.stack_trace[0].starts_with("parse@"));
    assert!(
        snapshot.stack_trace[0].contains("<inline>") || snapshot.stack_trace[0].contains("<eval>"),
        "unexpected parse stack frame: {}",
        snapshot.stack_trace[0]
    );
    assert!(snapshot.stack_trace[1].starts_with("boundary_transition[sync_callframe]"));
    assert!(snapshot.stack_trace[2].starts_with("boundary_transition[async_job]"));
    assert!(snapshot.stack_trace[3].starts_with("boundary_transition[hostcall]"));
}

#[test]
fn rgc_305_machine_stable_fields_are_replay_deterministic() {
    let vector = parse_vectors()
        .vectors
        .into_iter()
        .find(|vector| vector.scenario_id == "rgc-305-runtime-division-by-zero")
        .expect("missing runtime division vector");

    let boundaries = parse_boundaries(&vector.boundaries);
    let first = collect_snapshot(
        vector.scenario_id.as_str(),
        "quickjs",
        vector.input_source.as_str(),
        &boundaries,
    );
    let second = collect_snapshot(
        vector.scenario_id.as_str(),
        "quickjs",
        vector.input_source.as_str(),
        &boundaries,
    );

    assert_eq!(first.error_class, second.error_class);
    assert_eq!(first.error_code, second.error_code);
    assert_eq!(first.location, second.location);
    assert_eq!(first.stack_trace, second.stack_trace);
}

#[test]
fn rgc_305_differential_vectors_classify_intentional_divergence_with_guidance() {
    let vectors = parse_vectors();

    let mut intentional_divergence_seen = false;

    for vector in &vectors.vectors {
        let boundaries = parse_boundaries(&vector.boundaries);
        let quickjs = collect_snapshot(
            vector.scenario_id.as_str(),
            "quickjs",
            vector.input_source.as_str(),
            &boundaries,
        );
        let v8 = collect_snapshot(
            vector.scenario_id.as_str(),
            "v8",
            vector.input_source.as_str(),
            &boundaries,
        );

        assert_eq!(
            normalized_signature(&quickjs),
            normalized_signature(&v8),
            "core diagnostic compatibility drift for {}",
            vector.scenario_id
        );

        let classification = classify_pair(&quickjs, &v8, vector.remediation_guidance.as_str());
        assert_eq!(
            classification.classification, vector.expected_divergence_class,
            "unexpected divergence class for {}",
            vector.scenario_id
        );
        assert!(
            classification
                .remediation_guidance
                .contains("Normalize lane-specific correlation IDs"),
            "expected remediation guidance for {}",
            vector.scenario_id
        );

        if classification.classification == "intentional_divergence" {
            intentional_divergence_seen = true;
        }
    }

    assert!(
        intentional_divergence_seen,
        "expected intentional divergence coverage"
    );
}

#[test]
fn rgc_305_emit_deterministic_diagnostic_trace_artifact_when_requested() {
    let vectors = parse_vectors();
    let artifact = build_trace_artifact(&vectors);

    assert_eq!(artifact.schema_version, TRACE_SCHEMA_VERSION);
    assert_eq!(artifact.bead_id, "bd-1lsy.4.5");
    assert!(artifact.trace_hash.starts_with("sha256:"));
    assert_eq!(artifact.snapshots.len(), vectors.vectors.len() * 2);
    assert_eq!(artifact.differential.len(), vectors.vectors.len());

    let trace_payload =
        serde_json::to_vec(&(artifact.snapshots.clone(), artifact.differential.clone()))
            .expect("diagnostic trace payload should serialize");
    let recomputed_hash = format!("sha256:{}", hex::encode(Sha256::digest(&trace_payload)));
    assert_eq!(artifact.trace_hash, recomputed_hash);

    let serialized =
        serde_json::to_vec_pretty(&artifact).expect("diagnostic trace artifact should serialize");

    if let Ok(path) = std::env::var("RGC_305_DIAGNOSTIC_TRACE_OUT") {
        let path = PathBuf::from(path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .unwrap_or_else(|error| panic!("failed to create {}: {error}", parent.display()));
        }
        fs::write(&path, serialized)
            .unwrap_or_else(|error| panic!("failed to write {}: {error}", path.display()));

        // Emit the payload in-band so rch-backed runs can reconstruct this artifact
        // locally even when worker-generated files are not synced back.
        let payload = fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
        println!("{TRACE_BEGIN_MARKER}");
        println!("{payload}");
        println!("{TRACE_END_MARKER}");
    }
}

#[test]
fn rgc_305_contract_has_nonempty_bead_id() {
    let contract = parse_contract();
    assert!(!contract.bead_id.trim().is_empty());
}

#[test]
fn rgc_305_vectors_has_nonempty_generated_by() {
    let vectors = parse_vectors();
    assert!(!vectors.generated_by.trim().is_empty());
}

#[test]
fn rgc_305_contract_deterministic_double_parse() {
    let a = parse_contract();
    let b = parse_contract();
    assert_eq!(a, b);
}

// -----------------------------------------------------------------------
// Enrichment: PearlTower 2026-03-05 — serde, determinism, edge cases
// -----------------------------------------------------------------------

#[test]
fn rgc_305_contract_serde_roundtrip() {
    let contract = parse_contract();
    let json = serde_json::to_string_pretty(&contract).unwrap();
    let back: ExceptionDiagnosticsContract = serde_json::from_str(&json).unwrap();
    assert_eq!(contract, back);
}

#[test]
fn rgc_305_vectors_serde_roundtrip() {
    let vectors = parse_vectors();
    let json = serde_json::to_string_pretty(&vectors).unwrap();
    let back: ExceptionDiagnosticsVectors = serde_json::from_str(&json).unwrap();
    assert_eq!(vectors, back);
}

#[test]
fn rgc_305_vectors_deterministic_double_parse() {
    let a = parse_vectors();
    let b = parse_vectors();
    assert_eq!(a, b);
}

#[test]
fn rgc_305_trace_artifact_serde_roundtrip() {
    let vectors = parse_vectors();
    let artifact = build_trace_artifact(&vectors);
    let json = serde_json::to_string_pretty(&artifact).unwrap();
    let back: DiagnosticTraceArtifact = serde_json::from_str(&json).unwrap();
    assert_eq!(artifact, back);
}

#[test]
fn rgc_305_trace_artifact_hash_stability() {
    let vectors = parse_vectors();
    let artifact_a = build_trace_artifact(&vectors);
    let artifact_b = build_trace_artifact(&vectors);
    assert_eq!(artifact_a.trace_hash, artifact_b.trace_hash);
    assert_eq!(artifact_a.snapshots, artifact_b.snapshots);
    assert_eq!(artifact_a.differential, artifact_b.differential);
}

#[test]
fn rgc_305_trace_artifact_snapshots_sorted_by_scenario_then_lane() {
    let vectors = parse_vectors();
    let artifact = build_trace_artifact(&vectors);
    for window in artifact.snapshots.windows(2) {
        let ordering = window[0]
            .scenario_id
            .cmp(&window[1].scenario_id)
            .then(window[0].lane.cmp(&window[1].lane));
        assert!(
            ordering != std::cmp::Ordering::Greater,
            "snapshots not sorted: {} {} comes after {} {}",
            window[0].scenario_id,
            window[0].lane,
            window[1].scenario_id,
            window[1].lane,
        );
    }
}

#[test]
fn rgc_305_trace_artifact_differential_sorted_by_scenario() {
    let vectors = parse_vectors();
    let artifact = build_trace_artifact(&vectors);
    for window in artifact.differential.windows(2) {
        assert!(
            window[0].scenario_id <= window[1].scenario_id,
            "differential not sorted: {} comes after {}",
            window[0].scenario_id,
            window[1].scenario_id,
        );
    }
}

#[test]
fn rgc_305_diagnostic_snapshot_serde_roundtrip() {
    let vectors = parse_vectors();
    let first_vector = vectors.vectors.first().expect("need at least one vector");
    let boundaries = parse_boundaries(&first_vector.boundaries);
    let snapshot = collect_snapshot(
        first_vector.scenario_id.as_str(),
        "quickjs",
        first_vector.input_source.as_str(),
        &boundaries,
    );
    let json = serde_json::to_string(&snapshot).unwrap();
    let back: DiagnosticSnapshot = serde_json::from_str(&json).unwrap();
    assert_eq!(snapshot, back);
}

#[test]
fn rgc_305_differential_classification_serde_roundtrip() {
    let classification = DifferentialClassification {
        scenario_id: "test-scenario".into(),
        classification: "intentional_divergence".into(),
        remediation_guidance: "Normalize lane-specific correlation IDs".into(),
    };
    let json = serde_json::to_string(&classification).unwrap();
    let back: DifferentialClassification = serde_json::from_str(&json).unwrap();
    assert_eq!(classification, back);
}

#[test]
fn rgc_305_classify_pair_compatible_when_identical() {
    let snapshot = DiagnosticSnapshot {
        scenario_id: "test".into(),
        lane: "quickjs".into(),
        error_class: "Parse".into(),
        error_code: "FE-001".into(),
        location: Some("1:1".into()),
        trace_id: "trace-1".into(),
        decision_id: "dec-1".into(),
        policy_id: "pol-1".into(),
        stack_trace: vec!["parse@<eval>:1:1".into()],
    };
    let other = DiagnosticSnapshot {
        lane: "v8".into(),
        ..snapshot.clone()
    };
    let result = classify_pair(&snapshot, &other, "no remediation needed");
    assert_eq!(result.classification, "compatible");
}

#[test]
fn rgc_305_classify_pair_intentional_divergence_on_trace_id_diff() {
    let left = DiagnosticSnapshot {
        scenario_id: "test".into(),
        lane: "quickjs".into(),
        error_class: "Parse".into(),
        error_code: "FE-001".into(),
        location: None,
        trace_id: "trace-quickjs".into(),
        decision_id: "dec-1".into(),
        policy_id: "pol-1".into(),
        stack_trace: vec![],
    };
    let right = DiagnosticSnapshot {
        lane: "v8".into(),
        trace_id: "trace-v8".into(),
        ..left.clone()
    };
    let result = classify_pair(&left, &right, "guidance");
    assert_eq!(result.classification, "intentional_divergence");
}

#[test]
fn rgc_305_classify_pair_incompatible_on_error_class_diff() {
    let left = DiagnosticSnapshot {
        scenario_id: "test".into(),
        lane: "quickjs".into(),
        error_class: "Parse".into(),
        error_code: "FE-001".into(),
        location: None,
        trace_id: "trace-1".into(),
        decision_id: "dec-1".into(),
        policy_id: "pol-1".into(),
        stack_trace: vec![],
    };
    let right = DiagnosticSnapshot {
        lane: "v8".into(),
        error_class: "Runtime".into(),
        ..left.clone()
    };
    let result = classify_pair(&left, &right, "guidance");
    assert_eq!(result.classification, "incompatible");
}

#[test]
fn rgc_305_each_vector_produces_valid_snapshots_on_both_lanes() {
    let vectors = parse_vectors();
    for vector in &vectors.vectors {
        let boundaries = parse_boundaries(&vector.boundaries);
        let quickjs = collect_snapshot(
            vector.scenario_id.as_str(),
            "quickjs",
            vector.input_source.as_str(),
            &boundaries,
        );
        let v8 = collect_snapshot(
            vector.scenario_id.as_str(),
            "v8",
            vector.input_source.as_str(),
            &boundaries,
        );
        assert!(
            !quickjs.error_class.is_empty(),
            "empty error_class for quickjs lane in {}",
            vector.scenario_id
        );
        assert!(
            !v8.error_class.is_empty(),
            "empty error_class for v8 lane in {}",
            vector.scenario_id
        );
        assert!(
            !quickjs.error_code.is_empty(),
            "empty error_code for quickjs lane in {}",
            vector.scenario_id
        );
        assert!(
            !v8.error_code.is_empty(),
            "empty error_code for v8 lane in {}",
            vector.scenario_id
        );
    }
}

#[test]
fn rgc_305_snapshot_replay_determinism_across_lanes() {
    let vectors = parse_vectors();
    for vector in &vectors.vectors {
        let boundaries = parse_boundaries(&vector.boundaries);
        let q1 = collect_snapshot(
            vector.scenario_id.as_str(),
            "quickjs",
            vector.input_source.as_str(),
            &boundaries,
        );
        let q2 = collect_snapshot(
            vector.scenario_id.as_str(),
            "quickjs",
            vector.input_source.as_str(),
            &boundaries,
        );
        assert_eq!(
            q1.error_class, q2.error_class,
            "quickjs error_class not deterministic for {}",
            vector.scenario_id
        );
        assert_eq!(
            q1.error_code, q2.error_code,
            "quickjs error_code not deterministic for {}",
            vector.scenario_id
        );
        assert_eq!(
            q1.stack_trace, q2.stack_trace,
            "quickjs stack_trace not deterministic for {}",
            vector.scenario_id
        );
    }
}

#[test]
fn rgc_305_gate_runner_fields_are_nonempty() {
    let contract = parse_contract();
    assert!(!contract.gate_runner.script.is_empty());
    assert!(!contract.gate_runner.replay_wrapper.is_empty());
    assert!(!contract.gate_runner.strict_mode.is_empty());
    assert!(!contract.gate_runner.manifest_schema_version.is_empty());
}

#[test]
fn rgc_305_operator_verification_non_empty() {
    let contract = parse_contract();
    assert!(
        !contract.operator_verification.is_empty(),
        "operator_verification must have at least one entry"
    );
    for entry in &contract.operator_verification {
        assert!(
            !entry.trim().is_empty(),
            "empty operator verification entry"
        );
    }
}

#[test]
fn rgc_305_all_vector_severities_are_nonempty() {
    let vectors = parse_vectors();
    for vector in &vectors.vectors {
        assert!(
            !vector.severity.trim().is_empty(),
            "empty severity for scenario {}",
            vector.scenario_id
        );
    }
}

#[test]
fn rgc_305_parse_boundaries_covers_all_known_types() {
    let boundaries = parse_boundaries(&[
        "sync_callframe".to_string(),
        "async_job".to_string(),
        "hostcall".to_string(),
    ]);
    assert_eq!(boundaries.len(), 3);
    assert_eq!(boundaries[0], ExceptionBoundary::SyncCallframe);
    assert_eq!(boundaries[1], ExceptionBoundary::AsyncJob);
    assert_eq!(boundaries[2], ExceptionBoundary::Hostcall);
}

#[test]
fn rgc_305_normalized_signature_excludes_trace_decision_policy() {
    let snapshot = DiagnosticSnapshot {
        scenario_id: "test".into(),
        lane: "quickjs".into(),
        error_class: "Parse".into(),
        error_code: "FE-001".into(),
        location: Some("1:1".into()),
        trace_id: "trace-A".into(),
        decision_id: "dec-A".into(),
        policy_id: "pol-A".into(),
        stack_trace: vec!["frame".into()],
    };
    let other = DiagnosticSnapshot {
        trace_id: "trace-B".into(),
        decision_id: "dec-B".into(),
        policy_id: "pol-B".into(),
        ..snapshot.clone()
    };
    assert_eq!(
        normalized_signature(&snapshot),
        normalized_signature(&other),
        "normalized_signature should ignore trace/decision/policy IDs"
    );
}

#[test]
fn rgc_305_contract_json_field_names_present() {
    let raw: serde_json::Value =
        serde_json::from_str(CONTRACT_JSON).expect("contract JSON must parse");
    let obj = raw.as_object().expect("contract should be a JSON object");
    for key in [
        "schema_version",
        "contract_version",
        "bead_id",
        "policy_id",
        "required_semantics_classes",
        "required_log_keys",
        "required_artifacts",
        "test_vectors_source",
        "gate_runner",
        "operator_verification",
    ] {
        assert!(obj.contains_key(key), "missing contract JSON key: {key}");
    }
}

#[test]
fn rgc_305_vectors_json_field_names_present() {
    let raw: serde_json::Value =
        serde_json::from_str(VECTORS_JSON).expect("vectors JSON must parse");
    let obj = raw.as_object().expect("vectors should be a JSON object");
    for key in [
        "schema_version",
        "contract_version",
        "bead_id",
        "generated_by",
        "generated_at_utc",
        "vectors",
    ] {
        assert!(obj.contains_key(key), "missing vectors JSON key: {key}");
    }
}

// -----------------------------------------------------------------------
// Enrichment: PearlTower 2026-03-14 — source module API coverage
// -----------------------------------------------------------------------

#[test]
fn eval_error_class_stable_label_all_variants() {
    let cases = [
        (EvalErrorClass::Parse, "parse"),
        (EvalErrorClass::Resolution, "resolution"),
        (EvalErrorClass::Policy, "policy"),
        (EvalErrorClass::Capability, "capability"),
        (EvalErrorClass::Runtime, "runtime"),
        (EvalErrorClass::Hostcall, "hostcall"),
        (EvalErrorClass::Invariant, "invariant"),
    ];
    let mut seen = BTreeSet::new();
    for (class, expected) in cases {
        assert_eq!(class.stable_label(), expected);
        assert!(seen.insert(expected), "duplicate label: {expected}");
    }
}

#[test]
fn eval_error_class_display_matches_stable_label() {
    for class in [
        EvalErrorClass::Parse,
        EvalErrorClass::Resolution,
        EvalErrorClass::Policy,
        EvalErrorClass::Capability,
        EvalErrorClass::Runtime,
        EvalErrorClass::Hostcall,
        EvalErrorClass::Invariant,
    ] {
        assert_eq!(class.to_string(), class.stable_label());
    }
}

#[test]
fn eval_error_class_serde_roundtrip_all_variants() {
    for class in [
        EvalErrorClass::Parse,
        EvalErrorClass::Resolution,
        EvalErrorClass::Policy,
        EvalErrorClass::Capability,
        EvalErrorClass::Runtime,
        EvalErrorClass::Hostcall,
        EvalErrorClass::Invariant,
    ] {
        let json = serde_json::to_string(&class).unwrap();
        let recovered: EvalErrorClass = serde_json::from_str(&json).unwrap();
        assert_eq!(class, recovered);
    }
}

#[test]
fn eval_error_class_ordering() {
    assert!(EvalErrorClass::Parse < EvalErrorClass::Resolution);
    assert!(EvalErrorClass::Resolution < EvalErrorClass::Policy);
    assert!(EvalErrorClass::Policy < EvalErrorClass::Capability);
    assert!(EvalErrorClass::Capability < EvalErrorClass::Runtime);
    assert!(EvalErrorClass::Runtime < EvalErrorClass::Hostcall);
    assert!(EvalErrorClass::Hostcall < EvalErrorClass::Invariant);
}

#[test]
fn eval_error_code_class_mapping_all_variants() {
    let cases = [
        (EvalErrorCode::EmptySource, EvalErrorClass::Parse),
        (EvalErrorCode::ParseFailure, EvalErrorClass::Parse),
        (EvalErrorCode::ResolutionFailure, EvalErrorClass::Resolution),
        (EvalErrorCode::PolicyDenied, EvalErrorClass::Policy),
        (EvalErrorCode::CapabilityDenied, EvalErrorClass::Capability),
        (EvalErrorCode::RuntimeFault, EvalErrorClass::Runtime),
        (EvalErrorCode::HostcallFault, EvalErrorClass::Hostcall),
        (EvalErrorCode::InvariantViolation, EvalErrorClass::Invariant),
    ];
    for (code, expected_class) in cases {
        assert_eq!(code.class(), expected_class, "wrong class for {code:?}");
    }
}

#[test]
fn eval_error_code_stable_namespace_all_unique() {
    let codes = [
        EvalErrorCode::EmptySource,
        EvalErrorCode::ParseFailure,
        EvalErrorCode::ResolutionFailure,
        EvalErrorCode::PolicyDenied,
        EvalErrorCode::CapabilityDenied,
        EvalErrorCode::RuntimeFault,
        EvalErrorCode::HostcallFault,
        EvalErrorCode::InvariantViolation,
    ];
    let mut namespaces = BTreeSet::new();
    for code in codes {
        let ns = code.stable_namespace();
        assert!(
            ns.starts_with("eval."),
            "namespace must start with eval.: {ns}"
        );
        assert!(namespaces.insert(ns), "duplicate namespace: {ns}");
    }
    assert_eq!(namespaces.len(), 8);
}

#[test]
fn eval_error_code_serde_roundtrip_all_variants() {
    for code in [
        EvalErrorCode::EmptySource,
        EvalErrorCode::ParseFailure,
        EvalErrorCode::ResolutionFailure,
        EvalErrorCode::PolicyDenied,
        EvalErrorCode::CapabilityDenied,
        EvalErrorCode::RuntimeFault,
        EvalErrorCode::HostcallFault,
        EvalErrorCode::InvariantViolation,
    ] {
        let json = serde_json::to_string(&code).unwrap();
        let recovered: EvalErrorCode = serde_json::from_str(&json).unwrap();
        assert_eq!(code, recovered);
    }
}

#[test]
fn exception_boundary_stable_label_and_display() {
    for (boundary, expected) in [
        (ExceptionBoundary::SyncCallframe, "sync_callframe"),
        (ExceptionBoundary::AsyncJob, "async_job"),
        (ExceptionBoundary::Hostcall, "hostcall"),
    ] {
        assert_eq!(boundary.stable_label(), expected);
        assert_eq!(boundary.to_string(), expected);
    }
}

#[test]
fn exception_boundary_serde_roundtrip() {
    for boundary in [
        ExceptionBoundary::SyncCallframe,
        ExceptionBoundary::AsyncJob,
        ExceptionBoundary::Hostcall,
    ] {
        let json = serde_json::to_string(&boundary).unwrap();
        let recovered: ExceptionBoundary = serde_json::from_str(&json).unwrap();
        assert_eq!(boundary, recovered);
    }
}

#[test]
fn eval_error_factory_methods_produce_correct_codes() {
    let cases: Vec<(EvalError, EvalErrorCode)> = vec![
        (EvalError::parse_failure("p"), EvalErrorCode::ParseFailure),
        (
            EvalError::resolution_failure("r"),
            EvalErrorCode::ResolutionFailure,
        ),
        (EvalError::policy_denied("d"), EvalErrorCode::PolicyDenied),
        (
            EvalError::capability_denied("c"),
            EvalErrorCode::CapabilityDenied,
        ),
        (EvalError::runtime_fault("rt"), EvalErrorCode::RuntimeFault),
        (EvalError::hostcall_fault("h"), EvalErrorCode::HostcallFault),
        (
            EvalError::invariant_violation("i"),
            EvalErrorCode::InvariantViolation,
        ),
    ];
    for (error, expected_code) in cases {
        assert_eq!(error.code, expected_code);
        assert!(error.correlation_ids.is_none());
        assert!(error.location.is_none());
        assert!(error.stack_frames.is_empty());
    }
}

#[test]
fn eval_error_builder_chain_with_correlation_and_location() {
    let loc = EvalSourceLocation {
        source_label: "test.js".to_string(),
        start_line: 10,
        start_column: 5,
        end_line: 10,
        end_column: 20,
    };
    let error = EvalError::parse_failure("syntax error")
        .with_correlation_ids("trace-1", "dec-1", "pol-1")
        .with_location(loc.clone());
    assert!(error.correlation_ids.is_some());
    let ids = error.correlation_ids.as_ref().unwrap();
    assert_eq!(ids.trace_id, "trace-1");
    assert_eq!(ids.decision_id, "dec-1");
    assert_eq!(ids.policy_id, "pol-1");
    assert_eq!(error.location.as_ref().unwrap().source_label, "test.js");
}

#[test]
fn eval_error_diagnostic_summary_includes_all_components() {
    let loc = EvalSourceLocation {
        source_label: "mod.js".to_string(),
        start_line: 1,
        start_column: 0,
        end_line: 1,
        end_column: 10,
    };
    let mut error = EvalError::runtime_fault("division by zero")
        .with_correlation_ids("t-1", "d-1", "p-1")
        .with_location(loc);
    error.push_stack_frame(EvalStackFrame {
        stage: "eval".to_string(),
        boundary: None,
        location: None,
    });

    let summary = error.diagnostic_summary();
    assert!(summary.contains("eval.runtime.fault"));
    assert!(summary.contains("[runtime]"));
    assert!(summary.contains("division by zero"));
    assert!(summary.contains("mod.js:1:0-1:10"));
    assert!(summary.contains("trace_id=t-1"));
    assert!(summary.contains("[stack="));
}

#[test]
fn eval_error_display_equals_diagnostic_summary() {
    let error = EvalError::policy_denied("forbidden");
    assert_eq!(error.to_string(), error.diagnostic_summary());
}

#[test]
fn eval_error_serde_roundtrip_with_all_optional_fields() {
    let error = EvalError::hostcall_fault("timeout")
        .with_correlation_ids("t", "d", "p")
        .with_location(EvalSourceLocation {
            source_label: "host.js".to_string(),
            start_line: 5,
            start_column: 0,
            end_line: 5,
            end_column: 30,
        });
    let json = serde_json::to_string(&error).unwrap();
    let recovered: EvalError = serde_json::from_str(&json).unwrap();
    assert_eq!(error, recovered);
}

#[test]
fn eval_error_serde_skip_serializing_empty_optional_fields() {
    let error = EvalError::new(EvalErrorCode::EmptySource, "empty");
    let json = serde_json::to_string(&error).unwrap();
    let raw: serde_json::Value = serde_json::from_str(&json).unwrap();
    let obj = raw.as_object().unwrap();
    assert!(!obj.contains_key("correlation_ids"));
    assert!(!obj.contains_key("location"));
    assert!(!obj.contains_key("stack_frames"));
}

#[test]
fn eval_correlation_ids_serde_roundtrip() {
    let ids = EvalCorrelationIds {
        trace_id: "trace-abc".to_string(),
        decision_id: "dec-xyz".to_string(),
        policy_id: "pol-123".to_string(),
    };
    let json = serde_json::to_string(&ids).unwrap();
    let recovered: EvalCorrelationIds = serde_json::from_str(&json).unwrap();
    assert_eq!(ids, recovered);
}

#[test]
fn eval_source_location_display_format() {
    let loc = EvalSourceLocation {
        source_label: "<eval>".to_string(),
        start_line: 3,
        start_column: 7,
        end_line: 3,
        end_column: 15,
    };
    assert_eq!(loc.to_string(), "<eval>:3:7-3:15");
}

#[test]
fn eval_source_location_serde_roundtrip() {
    let loc = EvalSourceLocation {
        source_label: "script.js".to_string(),
        start_line: 1,
        start_column: 0,
        end_line: 100,
        end_column: 50,
    };
    let json = serde_json::to_string(&loc).unwrap();
    let recovered: EvalSourceLocation = serde_json::from_str(&json).unwrap();
    assert_eq!(loc, recovered);
}

#[test]
fn eval_stack_frame_serde_with_and_without_optional_fields() {
    let frame_minimal = EvalStackFrame {
        stage: "parse".to_string(),
        boundary: None,
        location: None,
    };
    let json_minimal = serde_json::to_string(&frame_minimal).unwrap();
    let raw: serde_json::Value = serde_json::from_str(&json_minimal).unwrap();
    assert!(!raw.as_object().unwrap().contains_key("boundary"));
    assert!(!raw.as_object().unwrap().contains_key("location"));
    let recovered: EvalStackFrame = serde_json::from_str(&json_minimal).unwrap();
    assert_eq!(frame_minimal, recovered);

    let frame_full = EvalStackFrame {
        stage: "boundary_transition".to_string(),
        boundary: Some("sync_callframe".to_string()),
        location: Some(EvalSourceLocation {
            source_label: "x.js".to_string(),
            start_line: 1,
            start_column: 0,
            end_line: 1,
            end_column: 5,
        }),
    };
    let json_full = serde_json::to_string(&frame_full).unwrap();
    let recovered_full: EvalStackFrame = serde_json::from_str(&json_full).unwrap();
    assert_eq!(frame_full, recovered_full);
}

#[test]
fn exception_transition_event_serde_roundtrip() {
    let error = EvalError::runtime_fault("test fault");
    let event = emit_exception_transition_event(
        "trace-1",
        Some("dec-1".to_string()),
        Some("pol-1".to_string()),
        "test_component",
        ExceptionBoundary::AsyncJob,
        &error,
    );
    assert_eq!(event.event, "exception_transition");
    assert_eq!(event.outcome, "error");
    assert_eq!(event.error_class, "runtime");
    assert_eq!(event.error_code, "eval.runtime.fault");
    assert_eq!(event.boundary, ExceptionBoundary::AsyncJob);

    let json = serde_json::to_string(&event).unwrap();
    let recovered: ExceptionTransitionEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, recovered);
}

#[test]
fn propagate_error_appends_boundary_to_message_and_stack() {
    let error = EvalError::parse_failure("bad syntax");
    let propagated = propagate_error_across_boundary(error, ExceptionBoundary::SyncCallframe);
    assert!(propagated.message.contains("boundary=sync_callframe"));
    assert_eq!(propagated.stack_frames.len(), 1);
    assert_eq!(
        propagated.stack_frames[0].boundary.as_deref(),
        Some("sync_callframe")
    );
}

#[test]
fn propagate_error_multiple_boundaries_accumulate() {
    let error = EvalError::runtime_fault("error");
    let p1 = propagate_error_across_boundary(error, ExceptionBoundary::SyncCallframe);
    let p2 = propagate_error_across_boundary(p1, ExceptionBoundary::AsyncJob);
    let p3 = propagate_error_across_boundary(p2, ExceptionBoundary::Hostcall);
    assert_eq!(p3.stack_frames.len(), 3);
    assert!(p3.message.contains("boundary=sync_callframe"));
    assert!(p3.message.contains("boundary=async_job"));
    assert!(p3.message.contains("boundary=hostcall"));
}

#[test]
fn propagate_result_across_boundary_ok_passes_through() {
    let result: Result<i32, EvalError> = Ok(42);
    let propagated = propagate_result_across_boundary(result, ExceptionBoundary::Hostcall);
    assert_eq!(propagated.unwrap(), 42);
}

#[test]
fn propagate_result_across_boundary_err_propagates() {
    let result: Result<i32, EvalError> = Err(EvalError::policy_denied("no"));
    let propagated = propagate_result_across_boundary(result, ExceptionBoundary::AsyncJob);
    let err = propagated.unwrap_err();
    assert!(err.message.contains("boundary=async_job"));
    assert_eq!(err.stack_frames.len(), 1);
}

#[test]
fn stable_sort_eval_errors_orders_by_class_then_code_then_message() {
    let mut errors = vec![
        EvalError::invariant_violation("z"),
        EvalError::parse_failure("b"),
        EvalError::runtime_fault("a"),
        EvalError::parse_failure("a"),
    ];
    stable_sort_eval_errors(&mut errors);
    assert_eq!(errors[0].code, EvalErrorCode::ParseFailure);
    assert_eq!(errors[0].message, "a");
    assert_eq!(errors[1].code, EvalErrorCode::ParseFailure);
    assert_eq!(errors[1].message, "b");
    assert_eq!(errors[2].code, EvalErrorCode::RuntimeFault);
    assert_eq!(errors[3].code, EvalErrorCode::InvariantViolation);
}

#[test]
fn sorted_eval_errors_returns_new_sorted_vec() {
    let errors = vec![
        EvalError::hostcall_fault("b"),
        EvalError::parse_failure("a"),
    ];
    let sorted = sorted_eval_errors(errors);
    assert_eq!(sorted[0].code, EvalErrorCode::ParseFailure);
    assert_eq!(sorted[1].code, EvalErrorCode::HostcallFault);
}

#[test]
fn eval_error_migration_notes_is_nonempty() {
    assert!(!EVAL_ERROR_MIGRATION_NOTES.is_empty());
    assert!(EVAL_ERROR_MIGRATION_NOTES.contains("EvalErrorClass"));
    assert!(EVAL_ERROR_MIGRATION_NOTES.contains("EvalErrorCode"));
}

#[test]
fn hybrid_router_routes_import_to_v8() {
    use frankenengine_engine::EngineKind;
    let mut router = HybridRouter::default();
    let result = router.eval("import 'mod';");
    // Whether it errors or not, the routing should go through V8 path
    match result {
        Ok(outcome) => assert_eq!(outcome.engine, EngineKind::V8InspiredNative),
        Err(_) => { /* V8 path may error on invalid import syntax */ }
    }
}

#[test]
fn quickjs_engine_kind_is_correct() {
    use frankenengine_engine::EngineKind;
    let engine = QuickJsInspiredNativeEngine;
    assert_eq!(engine.kind(), EngineKind::QuickJsInspiredNative);
}

#[test]
fn v8_engine_kind_is_correct() {
    use frankenengine_engine::EngineKind;
    let engine = V8InspiredNativeEngine;
    assert_eq!(engine.kind(), EngineKind::V8InspiredNative);
}

#[test]
fn eval_error_formatted_stack_trace_empty_on_new_error() {
    let error = EvalError::new(EvalErrorCode::EmptySource, "empty");
    assert!(error.formatted_stack_trace().is_empty());
}

#[test]
fn eval_error_push_stack_frame_grows_trace() {
    let mut error = EvalError::runtime_fault("test");
    assert!(error.stack_frames.is_empty());
    error.push_stack_frame(EvalStackFrame {
        stage: "compile".to_string(),
        boundary: None,
        location: None,
    });
    error.push_stack_frame(EvalStackFrame {
        stage: "eval".to_string(),
        boundary: None,
        location: None,
    });
    assert_eq!(error.stack_frames.len(), 2);
    let trace = error.formatted_stack_trace();
    assert_eq!(trace.len(), 2);
    assert_eq!(trace[0], "compile");
    assert_eq!(trace[1], "eval");
}
