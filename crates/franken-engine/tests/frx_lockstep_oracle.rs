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

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use frankenengine_engine::frx_lockstep_oracle::{
    FrxDivergenceClass, FrxLockstepCaseInput, FrxLockstepOracleError, FrxLockstepRunContext,
    FrxObservableTrace, FrxTraceEvent, evaluate_case, load_trace_file, run_lockstep_oracle,
};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn build_trace(
    fixture_ref: &str,
    scenario_id: &str,
    trace_id: &str,
    events: Vec<FrxTraceEvent>,
) -> FrxObservableTrace {
    FrxObservableTrace {
        schema_version: "frx.react.observable.trace.v1".to_string(),
        trace_id: trace_id.to_string(),
        decision_id: format!("decision-{trace_id}"),
        policy_id: "policy-frx-react-corpus-v1".to_string(),
        component: "frx_react_corpus".to_string(),
        scenario_id: scenario_id.to_string(),
        fixture_ref: fixture_ref.to_string(),
        seed: 42,
        events,
        outcome: "pass".to_string(),
        error_code: None,
    }
}

fn event(seq: u64, phase: &str, event: &str, decision_path: &str, timing_us: u64) -> FrxTraceEvent {
    FrxTraceEvent {
        seq,
        phase: phase.to_string(),
        actor: "Harness".to_string(),
        event: event.to_string(),
        decision_path: decision_path.to_string(),
        timing_us,
        outcome: "ok".to_string(),
    }
}

fn unique_temp_dir(prefix: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock drift")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("frx_lockstep_oracle_{prefix}_{nanos}"));
    fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn write_trace_file(dir: &Path, fixture_ref: &str, trace: &FrxObservableTrace) {
    let path = dir.join(format!("{fixture_ref}.trace.json"));
    let json = serde_json::to_string_pretty(trace).expect("serialize trace");
    fs::write(path, json).expect("write trace");
}

#[test]
fn evaluate_case_identical_traces_passes() {
    let fixture_ref = "compat.render.dom_snapshot_basic";
    let scenario_id = "frx-react-test-001";
    let events = vec![
        event(1, "render", "dom_commit", "render_path", 100),
        event(2, "effects", "effect_cleanup", "effect_path", 140),
    ];

    let react_trace = build_trace(fixture_ref, scenario_id, "trace-react-001", events.clone());
    let franken_trace = build_trace(fixture_ref, scenario_id, "trace-franken-001", events);

    let result = evaluate_case(FrxLockstepCaseInput {
        fixture_ref: fixture_ref.to_string(),
        scenario_id: scenario_id.to_string(),
        react_trace,
        franken_trace,
        react_trace_path: None,
        franken_trace_path: None,
    })
    .expect("case should evaluate");

    assert!(result.pass);
    assert!(result.divergence.is_none());
}

#[test]
fn evaluate_case_classifies_hydration_drift() {
    let fixture_ref = "compat.hydration.server_client_mismatch";
    let scenario_id = "frx-react-test-002";

    let react_trace = build_trace(
        fixture_ref,
        scenario_id,
        "trace-react-002",
        vec![
            event(1, "hydrate", "server_markup_loaded", "hydrate_path", 100),
            event(2, "hydrate", "mismatch_detected:text", "hydrate_path", 120),
        ],
    );
    let franken_trace = build_trace(
        fixture_ref,
        scenario_id,
        "trace-franken-002",
        vec![
            event(1, "hydrate", "server_markup_loaded", "hydrate_path", 100),
            event(2, "hydrate", "recover_client_render", "hydrate_path", 120),
        ],
    );

    let result = evaluate_case(FrxLockstepCaseInput {
        fixture_ref: fixture_ref.to_string(),
        scenario_id: scenario_id.to_string(),
        react_trace,
        franken_trace,
        react_trace_path: None,
        franken_trace_path: None,
    })
    .expect("case should evaluate");

    assert!(!result.pass);
    let divergence = result.divergence.expect("divergence should be present");
    assert_eq!(divergence.class, FrxDivergenceClass::HydrationOutcome);
    assert_eq!(divergence.event_index, Some(1));
}

#[test]
fn run_lockstep_oracle_corpus_self_compare_is_green() {
    let traces_dir =
        repo_root().join("crates/franken-engine/tests/conformance/frx_react_corpus/traces");
    let report = run_lockstep_oracle(
        traces_dir.as_path(),
        traces_dir.as_path(),
        FrxLockstepRunContext::deterministic(
            "trace-frx-lockstep-test-corpus",
            "decision-frx-lockstep-test-corpus",
            "policy-frx-lockstep-test-corpus",
        ),
        None,
    )
    .expect("oracle run should succeed");

    let total_cases = report.case_results.len() as u64;
    assert!(
        total_cases >= 10,
        "expected canonical corpus to include at least 10 fixtures"
    );
    assert_eq!(report.summary.total_cases, total_cases);
    assert_eq!(report.summary.failed_cases, 0);
    assert_eq!(report.summary.pass_cases, total_cases);
    assert!(report.case_results.iter().all(|result| result.pass));
    assert!(
        report
            .case_results
            .iter()
            .any(|result| result.fixture_ref.starts_with("compat.hydration"))
    );
}

#[test]
fn run_lockstep_oracle_marks_missing_candidate_trace_as_schema_violation() {
    let react_dir = unique_temp_dir("react");
    let franken_dir = unique_temp_dir("franken");

    let fixture_ref = "compat.custom.synthetic";
    let scenario_id = "frx-react-synthetic-001";
    let react_trace = build_trace(
        fixture_ref,
        scenario_id,
        "trace-react-synthetic",
        vec![event(1, "render", "dom_commit", "render_path", 100)],
    );
    write_trace_file(react_dir.as_path(), fixture_ref, &react_trace);

    let report = run_lockstep_oracle(
        react_dir.as_path(),
        franken_dir.as_path(),
        FrxLockstepRunContext::deterministic(
            "trace-frx-lockstep-test-missing",
            "decision-frx-lockstep-test-missing",
            "policy-frx-lockstep-test-missing",
        ),
        None,
    )
    .expect("oracle run should still succeed with failed case");

    assert_eq!(report.summary.total_cases, 1);
    assert_eq!(report.summary.failed_cases, 1);
    let case = &report.case_results[0];
    assert!(!case.pass);
    assert_eq!(
        case.divergence.as_ref().expect("divergence expected").class,
        FrxDivergenceClass::SchemaViolation
    );
}

// ---------- build_trace ----------

#[test]
fn build_trace_sets_correct_fields() {
    let events = vec![event(1, "render", "dom_commit", "path", 100)];
    let trace = build_trace("fixture-a", "scenario-a", "trace-a", events);
    assert_eq!(trace.fixture_ref, "fixture-a");
    assert_eq!(trace.scenario_id, "scenario-a");
    assert_eq!(trace.trace_id, "trace-a");
    assert_eq!(trace.seed, 42);
    assert_eq!(trace.outcome, "pass");
    assert_eq!(trace.component, "frx_react_corpus");
}

#[test]
fn build_trace_decision_id_includes_trace_id() {
    let trace = build_trace("f", "s", "trace-x", vec![]);
    assert!(trace.decision_id.contains("trace-x"));
}

// ---------- event helper ----------

#[test]
fn event_helper_sets_fields() {
    let e = event(5, "render", "dom_commit", "render_path", 200);
    assert_eq!(e.seq, 5);
    assert_eq!(e.phase, "render");
    assert_eq!(e.event, "dom_commit");
    assert_eq!(e.decision_path, "render_path");
    assert_eq!(e.timing_us, 200);
    assert_eq!(e.actor, "Harness");
    assert_eq!(e.outcome, "ok");
}

// ---------- FrxDivergenceClass ----------

#[test]
fn divergence_class_serde_roundtrip() {
    for class in [
        FrxDivergenceClass::HydrationOutcome,
        FrxDivergenceClass::SchemaViolation,
    ] {
        let json = serde_json::to_string(&class).expect("serialize");
        let recovered: FrxDivergenceClass = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(recovered, class);
    }
}

// ---------- FrxObservableTrace ----------

#[test]
fn observable_trace_serde_roundtrip() {
    let trace = build_trace(
        "ref-a",
        "scenario-a",
        "trace-a",
        vec![event(1, "render", "commit", "path", 100)],
    );
    let json = serde_json::to_string(&trace).expect("serialize");
    let recovered: FrxObservableTrace = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.fixture_ref, trace.fixture_ref);
    assert_eq!(recovered.scenario_id, trace.scenario_id);
    assert_eq!(recovered.events.len(), trace.events.len());
}

// ---------- evaluate_case ----------

#[test]
fn evaluate_case_detects_event_count_mismatch() {
    let react = build_trace(
        "ref",
        "scen",
        "trace-r",
        vec![
            event(1, "render", "commit", "path", 100),
            event(2, "render", "done", "path", 200),
        ],
    );
    let franken = build_trace(
        "ref",
        "scen",
        "trace-f",
        vec![event(1, "render", "commit", "path", 100)],
    );

    let result = evaluate_case(FrxLockstepCaseInput {
        fixture_ref: "ref".to_string(),
        scenario_id: "scen".to_string(),
        react_trace: react,
        franken_trace: franken,
        react_trace_path: None,
        franken_trace_path: None,
    })
    .expect("should evaluate");

    assert!(!result.pass);
    assert!(result.divergence.is_some());
}

// ---------- FrxLockstepRunContext ----------

#[test]
fn lockstep_run_context_deterministic_sets_fields() {
    let ctx = FrxLockstepRunContext::deterministic("trace-1", "decision-1", "policy-1");
    assert_eq!(ctx.trace_id, "trace-1");
    assert_eq!(ctx.decision_id, "decision-1");
    assert_eq!(ctx.policy_id, "policy-1");
}

// ---------- write_trace_file ----------

#[test]
fn write_trace_file_creates_file() {
    let dir = unique_temp_dir("write-trace-test");
    let trace = build_trace(
        "ref-write",
        "scen-write",
        "trace-write",
        vec![event(1, "render", "commit", "path", 100)],
    );
    write_trace_file(dir.as_path(), "ref-write", &trace);
    let path = dir.join("ref-write.trace.json");
    assert!(path.exists());
    let content = fs::read_to_string(&path).expect("read");
    let parsed: FrxObservableTrace = serde_json::from_str(&content).expect("parse");
    assert_eq!(parsed.fixture_ref, "ref-write");
}

#[test]
fn trace_event_serde_roundtrip() {
    let e = event(1, "render", "dom_commit", "render_path", 100);
    let json = serde_json::to_string(&e).expect("serialize");
    let recovered: FrxTraceEvent = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.seq, e.seq);
    assert_eq!(recovered.phase, e.phase);
    assert_eq!(recovered.event, e.event);
}

#[test]
fn lockstep_run_context_deterministic_fields_are_stable() {
    let a = FrxLockstepRunContext::deterministic("t", "d", "p");
    let b = FrxLockstepRunContext::deterministic("t", "d", "p");
    assert_eq!(a.trace_id, b.trace_id);
    assert_eq!(a.decision_id, b.decision_id);
    assert_eq!(a.policy_id, b.policy_id);
}

#[test]
fn evaluate_case_rejects_empty_traces() {
    let react = build_trace("ref-empty", "scen-empty", "trace-r-empty", vec![]);
    let franken = build_trace("ref-empty", "scen-empty", "trace-f-empty", vec![]);
    let result = evaluate_case(FrxLockstepCaseInput {
        fixture_ref: "ref-empty".to_string(),
        scenario_id: "scen-empty".to_string(),
        react_trace: react,
        franken_trace: franken,
        react_trace_path: None,
        franken_trace_path: None,
    });
    assert!(result.is_err(), "empty traces should be rejected");
}

#[test]
fn divergence_class_serde_round_trip() {
    for class in [
        FrxDivergenceClass::DomMutationTrace,
        FrxDivergenceClass::EffectInvocationOrder,
        FrxDivergenceClass::StateTransition,
        FrxDivergenceClass::HydrationOutcome,
        FrxDivergenceClass::EventSequence,
        FrxDivergenceClass::SchemaViolation,
    ] {
        let json = serde_json::to_string(&class).expect("serialize");
        let recovered: FrxDivergenceClass = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(class, recovered);
    }
}

#[test]
fn divergence_class_as_str_is_non_empty() {
    for class in [
        FrxDivergenceClass::DomMutationTrace,
        FrxDivergenceClass::EffectInvocationOrder,
        FrxDivergenceClass::StateTransition,
    ] {
        assert!(!class.as_str().is_empty());
    }
}

#[test]
fn lockstep_run_context_deterministic_sets_policy_id() {
    let ctx = FrxLockstepRunContext::deterministic("t", "d", "p");
    assert_eq!(ctx.policy_id, "p");
}

#[test]
fn lockstep_run_context_deterministic_sets_trace_id() {
    let ctx = FrxLockstepRunContext::deterministic("my-trace", "my-decision", "my-policy");
    assert_eq!(ctx.trace_id, "my-trace");
    assert_eq!(ctx.decision_id, "my-decision");
}

#[test]
fn divergence_class_all_variants_as_str_nonempty() {
    for class in [
        FrxDivergenceClass::DomMutationTrace,
        FrxDivergenceClass::EffectInvocationOrder,
        FrxDivergenceClass::StateTransition,
        FrxDivergenceClass::HydrationOutcome,
        FrxDivergenceClass::EventSequence,
        FrxDivergenceClass::SchemaViolation,
    ] {
        assert!(
            !class.as_str().is_empty(),
            "as_str must not be empty for {class:?}"
        );
    }
}

#[test]
fn trace_event_fields_are_preserved_after_roundtrip() {
    let event = FrxTraceEvent {
        seq: 0,
        phase: "render".to_string(),
        actor: "Counter".to_string(),
        event: "state_change".to_string(),
        decision_path: "path/to/decision".to_string(),
        timing_us: 1_000,
        outcome: "pass".to_string(),
    };
    let json = serde_json::to_string(&event).expect("serialize");
    let recovered: FrxTraceEvent = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.actor, "Counter");
    assert_eq!(recovered.outcome, "pass");
}

// ---------- enrichment: error types ----------

#[test]
fn oracle_error_invalid_input_display_is_nonempty() {
    let err = FrxLockstepOracleError::InvalidInput("empty traces".to_string());
    let msg = err.to_string();
    assert!(!msg.is_empty());
    assert!(msg.contains("empty traces"));
}

#[test]
fn oracle_error_is_std_error() {
    let err = FrxLockstepOracleError::InvalidInput("test".to_string());
    let dyn_err: &dyn std::error::Error = &err;
    assert!(!dyn_err.to_string().is_empty());
}

#[test]
fn load_trace_file_nonexistent_returns_read_error() {
    let path = std::path::Path::new("/nonexistent/path/trace.json");
    let err = load_trace_file(path).expect_err("should fail on missing file");
    assert!(matches!(err, FrxLockstepOracleError::ReadFile { .. }));
    assert!(!err.to_string().is_empty());
}

#[test]
fn load_trace_file_invalid_json_returns_parse_error() {
    let dir = unique_temp_dir("invalid-json");
    let path = dir.join("bad.trace.json");
    fs::write(&path, "not valid json").expect("write");
    let err = load_trace_file(&path).expect_err("should fail on invalid JSON");
    assert!(matches!(err, FrxLockstepOracleError::ParseTrace { .. }));
    assert!(!err.to_string().is_empty());
}

// ---------- enrichment: deeper edge-case and structural tests ----------

#[test]
fn evaluate_case_detects_phase_divergence_at_specific_index() {
    let fixture_ref = "compat.effects.phase_mismatch";
    let scenario_id = "frx-react-test-phase";
    let react_trace = build_trace(
        fixture_ref,
        scenario_id,
        "trace-react-phase",
        vec![
            event(1, "render", "dom_commit", "render_path", 100),
            event(2, "effects", "effect_fire", "effect_path", 200),
        ],
    );
    let franken_trace = build_trace(
        fixture_ref,
        scenario_id,
        "trace-franken-phase",
        vec![
            event(1, "render", "dom_commit", "render_path", 100),
            event(2, "commit", "effect_fire", "effect_path", 200),
        ],
    );
    let result = evaluate_case(FrxLockstepCaseInput {
        fixture_ref: fixture_ref.to_string(),
        scenario_id: scenario_id.to_string(),
        react_trace,
        franken_trace,
        react_trace_path: None,
        franken_trace_path: None,
    })
    .expect("should evaluate");
    assert!(!result.pass);
    let div = result.divergence.expect("divergence expected");
    assert_eq!(div.event_index, Some(1), "divergence should be at index 1");
}

#[test]
fn lockstep_case_result_serde_roundtrip() {
    use frankenengine_engine::frx_lockstep_oracle::{FrxDivergenceDetail, FrxLockstepCaseResult};
    let case_result = FrxLockstepCaseResult {
        fixture_ref: "compat.render.basic".to_string(),
        scenario_id: "scen-rt".to_string(),
        react_trace_id: "trace-r".to_string(),
        franken_trace_id: "trace-f".to_string(),
        pass: false,
        divergence: Some(FrxDivergenceDetail {
            class: FrxDivergenceClass::EventSequence,
            message: "event mismatch at index 0".to_string(),
            event_index: Some(0),
            react_signature: None,
            franken_signature: None,
        }),
        replay_command: "replay --fixture compat.render.basic".to_string(),
    };
    let json = serde_json::to_string(&case_result).expect("serialize");
    let recovered: FrxLockstepCaseResult = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.fixture_ref, case_result.fixture_ref);
    assert!(!recovered.pass);
    assert_eq!(
        recovered.divergence.as_ref().unwrap().class,
        FrxDivergenceClass::EventSequence
    );
}

#[test]
fn lockstep_report_serde_roundtrip() {
    use frankenengine_engine::frx_lockstep_oracle::{FrxLockstepReport, FrxLockstepSummary};
    let report = FrxLockstepReport {
        schema_version: "frx.lockstep.report.v1".to_string(),
        generated_at_utc: "2026-01-01T00:00:00Z".to_string(),
        trace_id: "trace-1".to_string(),
        decision_id: "decision-1".to_string(),
        policy_id: "policy-1".to_string(),
        component: "test".to_string(),
        react_traces_dir: "/tmp/react".to_string(),
        franken_traces_dir: "/tmp/franken".to_string(),
        summary: FrxLockstepSummary {
            total_cases: 5,
            pass_cases: 3,
            failed_cases: 2,
            divergence_counts_by_class: std::collections::BTreeMap::from([
                ("HydrationOutcome".to_string(), 1),
                ("EventSequence".to_string(), 1),
            ]),
        },
        case_results: vec![],
    };
    let json = serde_json::to_string_pretty(&report).expect("serialize");
    let recovered: FrxLockstepReport = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.summary.total_cases, 5);
    assert_eq!(recovered.summary.failed_cases, 2);
    assert_eq!(recovered.summary.divergence_counts_by_class.len(), 2);
}

#[test]
fn load_trace_file_valid_roundtrip() {
    let dir = unique_temp_dir("load-valid");
    let trace = build_trace(
        "compat.load.roundtrip",
        "load-scenario",
        "trace-load",
        vec![
            event(1, "render", "dom_commit", "path", 50),
            event(2, "effects", "cleanup", "path", 75),
        ],
    );
    write_trace_file(dir.as_path(), "compat.load.roundtrip", &trace);
    let loaded = load_trace_file(&dir.join("compat.load.roundtrip.trace.json"))
        .expect("should load valid trace");
    assert_eq!(loaded.fixture_ref, "compat.load.roundtrip");
    assert_eq!(loaded.events.len(), 2);
    assert_eq!(loaded.events[0].timing_us, 50);
    assert_eq!(loaded.events[1].event, "cleanup");
}

#[test]
fn run_lockstep_oracle_empty_dirs_returns_invalid_input_error() {
    let react_dir = unique_temp_dir("empty-react2");
    let franken_dir = unique_temp_dir("empty-franken2");
    let err = run_lockstep_oracle(
        react_dir.as_path(),
        franken_dir.as_path(),
        FrxLockstepRunContext::deterministic("trace-empty", "decision-empty", "policy-empty"),
        None,
    )
    .expect_err("empty dirs should be rejected");
    assert!(
        matches!(err, FrxLockstepOracleError::InvalidInput(_)),
        "expected InvalidInput error for empty directories"
    );
    assert!(err.to_string().contains("trace.json"));
}

// ---------- enrichment: additional edge-case tests ----------

#[test]
fn evaluate_case_detects_event_name_divergence() {
    let fixture_ref = "compat.events.name_mismatch";
    let scenario_id = "frx-react-test-name";
    let react_trace = build_trace(
        fixture_ref,
        scenario_id,
        "trace-react-name",
        vec![
            event(1, "render", "dom_commit", "render_path", 100),
            event(2, "effects", "effect_fire", "effect_path", 200),
        ],
    );
    let franken_trace = build_trace(
        fixture_ref,
        scenario_id,
        "trace-franken-name",
        vec![
            event(1, "render", "dom_commit", "render_path", 100),
            event(2, "effects", "effect_cleanup", "effect_path", 200),
        ],
    );
    let result = evaluate_case(FrxLockstepCaseInput {
        fixture_ref: fixture_ref.to_string(),
        scenario_id: scenario_id.to_string(),
        react_trace,
        franken_trace,
        react_trace_path: None,
        franken_trace_path: None,
    })
    .expect("should evaluate");
    assert!(!result.pass, "different event names should cause failure");
    assert!(result.divergence.is_some());
}

#[test]
fn lockstep_report_summary_pass_plus_failed_equals_total() {
    use frankenengine_engine::frx_lockstep_oracle::FrxLockstepSummary;
    let summary = FrxLockstepSummary {
        total_cases: 10,
        pass_cases: 7,
        failed_cases: 3,
        divergence_counts_by_class: std::collections::BTreeMap::new(),
    };
    assert_eq!(
        summary.pass_cases + summary.failed_cases,
        summary.total_cases,
        "pass + failed must equal total"
    );
}

#[test]
fn oracle_error_read_file_display_includes_path() {
    let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "not found");
    let err = FrxLockstepOracleError::ReadFile {
        path: "/some/file.json".to_string(),
        source: io_err,
    };
    let msg = err.to_string();
    assert!(
        msg.contains("/some/file.json"),
        "ReadFile error display must include the path"
    );
}

#[test]
fn oracle_error_parse_trace_display_includes_path() {
    // Create a serde_json::Error by attempting to parse invalid JSON
    let parse_err = serde_json::from_str::<serde_json::Value>("not valid json").unwrap_err();
    let err = FrxLockstepOracleError::ParseTrace {
        path: "/some/bad.json".to_string(),
        source: parse_err,
    };
    let msg = err.to_string();
    assert!(
        msg.contains("/some/bad.json"),
        "ParseTrace error display must include the path"
    );
}

#[test]
fn run_lockstep_oracle_single_matching_pair_passes() {
    let react_dir = unique_temp_dir("single-react");
    let franken_dir = unique_temp_dir("single-franken");
    let fixture_ref = "compat.single.basic";
    let scenario_id = "frx-react-single";
    let events = vec![
        event(1, "render", "dom_commit", "render_path", 100),
        event(2, "effects", "cleanup", "effect_path", 200),
    ];
    let react_trace = build_trace(
        fixture_ref,
        scenario_id,
        "trace-react-single",
        events.clone(),
    );
    let franken_trace = build_trace(fixture_ref, scenario_id, "trace-franken-single", events);
    write_trace_file(react_dir.as_path(), fixture_ref, &react_trace);
    write_trace_file(franken_dir.as_path(), fixture_ref, &franken_trace);

    let report = run_lockstep_oracle(
        react_dir.as_path(),
        franken_dir.as_path(),
        FrxLockstepRunContext::deterministic(
            "trace-single-test",
            "decision-single-test",
            "policy-single-test",
        ),
        None,
    )
    .expect("oracle should succeed");
    assert_eq!(report.summary.total_cases, 1);
    assert_eq!(report.summary.pass_cases, 1);
    assert_eq!(report.summary.failed_cases, 0);
}

// ---------- enrichment: additional structural tests ----------

#[test]
fn divergence_class_all_variants_unique_as_str() {
    use std::collections::BTreeSet;
    let strs: BTreeSet<&str> = [
        FrxDivergenceClass::DomMutationTrace,
        FrxDivergenceClass::EffectInvocationOrder,
        FrxDivergenceClass::StateTransition,
        FrxDivergenceClass::HydrationOutcome,
        FrxDivergenceClass::EventSequence,
        FrxDivergenceClass::SchemaViolation,
    ]
    .iter()
    .map(|c| c.as_str())
    .collect();
    assert_eq!(
        strs.len(),
        6,
        "each divergence class should produce a unique as_str()"
    );
}

#[test]
fn divergence_class_debug_all_unique() {
    use std::collections::BTreeSet;
    let dbgs: BTreeSet<String> = [
        FrxDivergenceClass::DomMutationTrace,
        FrxDivergenceClass::EffectInvocationOrder,
        FrxDivergenceClass::StateTransition,
        FrxDivergenceClass::HydrationOutcome,
        FrxDivergenceClass::EventSequence,
        FrxDivergenceClass::SchemaViolation,
    ]
    .iter()
    .map(|c| format!("{c:?}"))
    .collect();
    assert_eq!(dbgs.len(), 6);
}

#[test]
fn build_trace_error_code_is_none_by_default() {
    let trace = build_trace("ref", "scen", "tid", vec![event(1, "p", "e", "d", 1)]);
    assert!(trace.error_code.is_none());
}

#[test]
fn observable_trace_schema_version_is_stable() {
    let a = build_trace("r", "s", "t1", vec![event(1, "p", "e", "d", 1)]);
    let b = build_trace("r2", "s2", "t2", vec![event(1, "p", "e", "d", 1)]);
    assert_eq!(a.schema_version, b.schema_version);
}

#[test]
fn observable_trace_policy_id_is_stable() {
    let a = build_trace("r", "s", "t1", vec![event(1, "p", "e", "d", 1)]);
    let b = build_trace("r2", "s2", "t2", vec![event(1, "p", "e", "d", 1)]);
    assert_eq!(a.policy_id, b.policy_id);
}

#[test]
fn evaluate_case_identical_single_event_passes() {
    let events = vec![event(1, "render", "dom_commit", "path", 100)];
    let react = build_trace("ref-single", "scen-single", "trace-r", events.clone());
    let franken = build_trace("ref-single", "scen-single", "trace-f", events);
    let result = evaluate_case(FrxLockstepCaseInput {
        fixture_ref: "ref-single".to_string(),
        scenario_id: "scen-single".to_string(),
        react_trace: react,
        franken_trace: franken,
        react_trace_path: None,
        franken_trace_path: None,
    })
    .expect("should evaluate");
    assert!(result.pass);
}

#[test]
fn evaluate_case_detects_decision_path_divergence() {
    let react = build_trace(
        "ref-dp",
        "scen-dp",
        "trace-r-dp",
        vec![event(1, "render", "dom_commit", "path_a", 100)],
    );
    let franken = build_trace(
        "ref-dp",
        "scen-dp",
        "trace-f-dp",
        vec![event(1, "render", "dom_commit", "path_b", 100)],
    );
    let result = evaluate_case(FrxLockstepCaseInput {
        fixture_ref: "ref-dp".to_string(),
        scenario_id: "scen-dp".to_string(),
        react_trace: react,
        franken_trace: franken,
        react_trace_path: None,
        franken_trace_path: None,
    })
    .expect("should evaluate");
    assert!(!result.pass);
}

#[test]
fn write_trace_file_content_is_valid_json() {
    let dir = unique_temp_dir("json-valid");
    let trace = build_trace(
        "ref-jv",
        "scen-jv",
        "trace-jv",
        vec![event(1, "r", "e", "d", 1)],
    );
    write_trace_file(dir.as_path(), "ref-jv", &trace);
    let content = fs::read_to_string(dir.join("ref-jv.trace.json")).expect("read");
    let parsed: serde_json::Value = serde_json::from_str(&content).expect("should be valid JSON");
    assert!(parsed.is_object());
}

#[test]
fn lockstep_run_context_clone_stability() {
    let a = FrxLockstepRunContext::deterministic("t", "d", "p");
    let b = a.clone();
    assert_eq!(a.trace_id, b.trace_id);
    assert_eq!(a.decision_id, b.decision_id);
    assert_eq!(a.policy_id, b.policy_id);
}

#[test]
fn oracle_error_debug_is_nonempty() {
    let err = FrxLockstepOracleError::InvalidInput("test".to_string());
    assert!(!format!("{err:?}").is_empty());
}

#[test]
fn run_lockstep_corpus_report_has_stable_schema_version() {
    let traces_dir =
        repo_root().join("crates/franken-engine/tests/conformance/frx_react_corpus/traces");
    let report = run_lockstep_oracle(
        traces_dir.as_path(),
        traces_dir.as_path(),
        FrxLockstepRunContext::deterministic("t-schema", "d-schema", "p-schema"),
        None,
    )
    .expect("oracle run should succeed");
    assert!(report.schema_version.contains("lockstep"));
}

#[test]
fn run_lockstep_corpus_report_component_is_nonempty() {
    let traces_dir =
        repo_root().join("crates/franken-engine/tests/conformance/frx_react_corpus/traces");
    let report = run_lockstep_oracle(
        traces_dir.as_path(),
        traces_dir.as_path(),
        FrxLockstepRunContext::deterministic("t-comp", "d-comp", "p-comp"),
        None,
    )
    .expect("oracle run should succeed");
    assert!(!report.component.is_empty());
}

#[test]
fn run_lockstep_corpus_divergence_counts_empty_for_self_compare() {
    let traces_dir =
        repo_root().join("crates/franken-engine/tests/conformance/frx_react_corpus/traces");
    let report = run_lockstep_oracle(
        traces_dir.as_path(),
        traces_dir.as_path(),
        FrxLockstepRunContext::deterministic("t-div", "d-div", "p-div"),
        None,
    )
    .expect("oracle run should succeed");
    let total_divergences: u64 = report.summary.divergence_counts_by_class.values().sum();
    assert_eq!(
        total_divergences, 0,
        "self-compare should have no divergences"
    );
}
