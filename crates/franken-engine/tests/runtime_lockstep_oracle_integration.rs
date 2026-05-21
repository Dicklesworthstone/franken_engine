//! Integration tests for runtime lockstep oracle (Node.js and Bun comparison).
//!
//! Tests the Node and Bun lockstep oracle functions added for bd-cixqu.9.1,
//! verifying integration between runtime comparison benchmarks and differential
//! checking in the lockstep oracle pipeline.

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

use frankenengine_engine::frx_lockstep_oracle::{
    FRX_LOCKSTEP_TRACE_SCHEMA_VERSION, FrxLockstepRunContext, FrxObservableTrace, FrxTraceEvent,
    RuntimeBenchmarkResult, create_runtime_benchmark_trace, run_bun_lockstep_oracle,
    run_node_lockstep_oracle,
};

// ── Helpers ─────────────────────────────────────────────────────────────

fn create_test_trace(
    workload_id: &str,
    runtime_name: &str,
    events: Vec<FrxTraceEvent>,
    outcome: &str,
) -> FrxObservableTrace {
    FrxObservableTrace {
        schema_version: FRX_LOCKSTEP_TRACE_SCHEMA_VERSION.to_string(),
        trace_id: format!("trace-{runtime_name}-{workload_id}-test"),
        decision_id: format!("decision-{runtime_name}-{workload_id}-test"),
        policy_id: format!("policy-runtime-comparison-{runtime_name}-v1"),
        component: "runtime_comparison_benchmark".to_string(),
        scenario_id: format!("benchmark-{workload_id}"),
        fixture_ref: workload_id.to_string(),
        seed: 42,
        events,
        outcome: outcome.to_string(),
        error_code: None,
    }
}

fn create_test_event(seq: u64, event: &str, timing_us: u64, outcome: &str) -> FrxTraceEvent {
    FrxTraceEvent {
        seq,
        phase: "execution".to_string(),
        actor: "Test".to_string(),
        event: event.to_string(),
        decision_path: "benchmark/test_workload".to_string(),
        timing_us,
        outcome: outcome.to_string(),
    }
}

fn setup_test_directories(test_name: &str) -> (PathBuf, PathBuf, PathBuf) {
    let temp_dir = std::env::temp_dir().join(format!("runtime_lockstep_{test_name}"));
    let baseline_dir = temp_dir.join("baseline_traces");
    let franken_dir = temp_dir.join("franken_traces");

    let _ = fs::create_dir_all(&baseline_dir);
    let _ = fs::create_dir_all(&franken_dir);

    (temp_dir, baseline_dir, franken_dir)
}

fn write_trace_file(trace: &FrxObservableTrace, path: &Path) {
    let json = serde_json::to_string_pretty(trace).expect("should serialize trace");
    fs::write(path, json).expect("should write trace file");
}

// ── Integration Tests ───────────────────────────────────────────────────

#[test]
fn node_lockstep_oracle_matching_traces() {
    let (temp_dir, node_dir, franken_dir) = setup_test_directories("node_matching");

    // Create matching traces for Node and FrankenEngine
    let events = vec![
        create_test_event(1, "start", 0, "ok"),
        create_test_event(2, "console_output:42", 1000, "ok"),
        create_test_event(3, "completion", 1500, "ok"),
    ];

    let node_trace = create_test_trace("numeric_loop", "Node.js", events.clone(), "ok");
    let franken_trace = create_test_trace("numeric_loop", "FrankenEngine", events, "ok");

    write_trace_file(&node_trace, &node_dir.join("numeric_loop.trace.json"));
    write_trace_file(&franken_trace, &franken_dir.join("numeric_loop.trace.json"));

    let context =
        FrxLockstepRunContext::deterministic("test-node-lockstep", "test-decision", "test-policy");

    let result = run_node_lockstep_oracle(&node_dir, &franken_dir, context, None);
    assert!(
        result.is_ok(),
        "lockstep oracle should succeed for matching traces"
    );

    let report = result.unwrap();
    assert_eq!(report.summary.total_cases, 1);
    assert_eq!(report.summary.pass_cases, 1);
    assert_eq!(report.summary.failed_cases, 0);
    assert_eq!(report.case_results.len(), 1);
    assert!(report.case_results[0].pass);

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn bun_lockstep_oracle_divergent_traces() {
    let (temp_dir, bun_dir, franken_dir) = setup_test_directories("bun_divergent");

    // Create divergent traces - different console output
    let bun_events = vec![
        create_test_event(1, "start", 0, "ok"),
        create_test_event(2, "console_output:100", 800, "ok"),
        create_test_event(3, "completion", 1200, "ok"),
    ];

    let franken_events = vec![
        create_test_event(1, "start", 0, "ok"),
        create_test_event(2, "console_output:42", 1000, "ok"),
        create_test_event(3, "completion", 1500, "ok"),
    ];

    let bun_trace = create_test_trace("json_roundtrip", "Bun", bun_events, "ok");
    let franken_trace = create_test_trace("json_roundtrip", "FrankenEngine", franken_events, "ok");

    write_trace_file(&bun_trace, &bun_dir.join("json_roundtrip.trace.json"));
    write_trace_file(
        &franken_trace,
        &franken_dir.join("json_roundtrip.trace.json"),
    );

    let context =
        FrxLockstepRunContext::deterministic("test-bun-lockstep", "test-decision", "test-policy");

    let result = run_bun_lockstep_oracle(&bun_dir, &franken_dir, context, None);
    assert!(
        result.is_ok(),
        "lockstep oracle should complete even with divergent traces"
    );

    let report = result.unwrap();
    assert_eq!(report.summary.total_cases, 1);
    assert_eq!(report.summary.pass_cases, 0);
    assert_eq!(report.summary.failed_cases, 1);
    assert_eq!(report.case_results.len(), 1);
    assert!(!report.case_results[0].pass);
    assert!(report.case_results[0].divergence.is_some());

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn node_lockstep_oracle_missing_franken_trace() {
    let (temp_dir, node_dir, franken_dir) = setup_test_directories("node_missing");

    // Create only Node trace, no corresponding FrankenEngine trace
    let events = vec![
        create_test_event(1, "start", 0, "ok"),
        create_test_event(2, "completion", 1000, "ok"),
    ];

    let node_trace = create_test_trace("array_indexing", "Node.js", events, "ok");
    write_trace_file(&node_trace, &node_dir.join("array_indexing.trace.json"));

    let context =
        FrxLockstepRunContext::deterministic("test-node-missing", "test-decision", "test-policy");

    let result = run_node_lockstep_oracle(&node_dir, &franken_dir, context, None);
    assert!(
        result.is_ok(),
        "lockstep oracle should handle missing franken trace"
    );

    let report = result.unwrap();
    assert_eq!(report.summary.total_cases, 1);
    assert_eq!(report.summary.pass_cases, 0);
    assert_eq!(report.summary.failed_cases, 1);

    let case_result = &report.case_results[0];
    assert!(!case_result.pass);
    assert_eq!(case_result.franken_trace_id, "missing");
    assert!(case_result.divergence.is_some());

    let divergence = case_result.divergence.as_ref().unwrap();
    assert!(divergence.message.contains("missing FrankenEngine trace"));

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn create_runtime_benchmark_trace_integration_node() {
    let temp_dir = std::env::temp_dir().join("runtime_trace_integration_node");
    let _ = fs::create_dir_all(&temp_dir);

    let result = RuntimeBenchmarkResult {
        stdout: "49995000".to_string(),
        stderr: "".to_string(),
        wall_time_ns: 2_500_000,
        peak_rss_bytes: 8192,
        exit_success: true,
        exit_code: Some(0),
    };

    let trace_path = temp_dir.join("numeric_loop.trace.json");
    let create_result =
        create_runtime_benchmark_trace("numeric_loop", "Node.js", result, &trace_path);

    assert!(create_result.is_ok());
    assert!(trace_path.exists());

    // Verify the trace can be used in lockstep oracle
    let franken_dir = temp_dir.join("franken");
    let _ = fs::create_dir_all(&franken_dir);

    // Create a matching FrankenEngine trace
    let franken_events = vec![
        create_test_event(1, "start", 0, "ok"),
        create_test_event(2, "console_output:49995000", 2500, "ok"),
        create_test_event(3, "completion", 2500, "ok"),
    ];
    let franken_trace = create_test_trace("numeric_loop", "FrankenEngine", franken_events, "ok");
    write_trace_file(&franken_trace, &franken_dir.join("numeric_loop.trace.json"));

    let context = FrxLockstepRunContext::deterministic(
        "integration-test",
        "integration-decision",
        "integration-policy",
    );

    let oracle_result = run_node_lockstep_oracle(&temp_dir, &franken_dir, context, None);
    assert!(
        oracle_result.is_ok(),
        "oracle should process generated trace"
    );

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn create_runtime_benchmark_trace_integration_bun() {
    let temp_dir = std::env::temp_dir().join("runtime_trace_integration_bun");
    let _ = fs::create_dir_all(&temp_dir);

    let result = RuntimeBenchmarkResult {
        stdout: "10000".to_string(),
        stderr: "".to_string(),
        wall_time_ns: 1_800_000,
        peak_rss_bytes: 6144,
        exit_success: true,
        exit_code: Some(0),
    };

    let trace_path = temp_dir.join("json_roundtrip.trace.json");
    let create_result =
        create_runtime_benchmark_trace("json_roundtrip", "Bun", result, &trace_path);

    assert!(create_result.is_ok());

    // Use in Bun lockstep oracle
    let franken_dir = temp_dir.join("franken");
    let _ = fs::create_dir_all(&franken_dir);

    let franken_events = vec![
        create_test_event(1, "start", 0, "ok"),
        create_test_event(2, "console_output:10000", 1800, "ok"),
        create_test_event(3, "completion", 1800, "ok"),
    ];
    let franken_trace = create_test_trace("json_roundtrip", "FrankenEngine", franken_events, "ok");
    write_trace_file(
        &franken_trace,
        &franken_dir.join("json_roundtrip.trace.json"),
    );

    let context = FrxLockstepRunContext::deterministic(
        "bun-integration-test",
        "bun-integration-decision",
        "bun-integration-policy",
    );

    let oracle_result = run_bun_lockstep_oracle(&temp_dir, &franken_dir, context, None);
    assert!(oracle_result.is_ok(), "oracle should process Bun trace");

    let report = oracle_result.unwrap();
    assert_eq!(report.summary.total_cases, 1);
    assert_eq!(report.summary.pass_cases, 1);

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn runtime_lockstep_oracle_filter_functionality() {
    let (temp_dir, node_dir, franken_dir) = setup_test_directories("filter_test");

    // Create multiple trace files
    let workloads = ["numeric_loop", "json_roundtrip", "array_indexing"];
    for workload in &workloads {
        let events = vec![
            create_test_event(1, "start", 0, "ok"),
            create_test_event(2, "completion", 1000, "ok"),
        ];

        let node_trace = create_test_trace(workload, "Node.js", events.clone(), "ok");
        let franken_trace = create_test_trace(workload, "FrankenEngine", events, "ok");

        write_trace_file(
            &node_trace,
            &node_dir.join(format!("{workload}.trace.json")),
        );
        write_trace_file(
            &franken_trace,
            &franken_dir.join(format!("{workload}.trace.json")),
        );
    }

    let context =
        FrxLockstepRunContext::deterministic("filter-test", "filter-decision", "filter-policy");

    // Test filtering for specific workload
    let result = run_node_lockstep_oracle(
        &node_dir,
        &franken_dir,
        context.clone(),
        Some("json_roundtrip"),
    );
    assert!(result.is_ok());

    let report = result.unwrap();
    assert_eq!(
        report.summary.total_cases, 1,
        "should process only filtered workload"
    );
    assert_eq!(report.case_results[0].fixture_ref, "json_roundtrip");

    // Test no filter (all workloads)
    let result_all = run_node_lockstep_oracle(&node_dir, &franken_dir, context, None);
    assert!(result_all.is_ok());

    let report_all = result_all.unwrap();
    assert_eq!(
        report_all.summary.total_cases, 3,
        "should process all workloads without filter"
    );

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn runtime_lockstep_oracle_context_validation() {
    let (temp_dir, node_dir, franken_dir) = setup_test_directories("context_validation");

    // Test empty trace_id
    let empty_trace_context = FrxLockstepRunContext::deterministic("", "decision", "policy");
    let result = run_node_lockstep_oracle(&node_dir, &franken_dir, empty_trace_context, None);
    assert!(result.is_err());

    // Test empty decision_id
    let empty_decision_context = FrxLockstepRunContext::deterministic("trace", "", "policy");
    let result = run_node_lockstep_oracle(&node_dir, &franken_dir, empty_decision_context, None);
    assert!(result.is_err());

    // Test empty policy_id
    let empty_policy_context = FrxLockstepRunContext::deterministic("trace", "decision", "");
    let result = run_node_lockstep_oracle(&node_dir, &franken_dir, empty_policy_context, None);
    assert!(result.is_err());

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn runtime_benchmark_result_error_conditions() {
    let temp_dir = std::env::temp_dir().join("runtime_trace_error_test");
    let _ = fs::create_dir_all(&temp_dir);

    // Test failed execution with error code
    let failed_result = RuntimeBenchmarkResult {
        stdout: "".to_string(),
        stderr: "ReferenceError: undefined variable".to_string(),
        wall_time_ns: 100_000,
        peak_rss_bytes: 1024,
        exit_success: false,
        exit_code: Some(1),
    };

    let trace_path = temp_dir.join("failed_workload.trace.json");
    let create_result =
        create_runtime_benchmark_trace("failed_workload", "Node.js", failed_result, &trace_path);

    assert!(create_result.is_ok());

    // Verify error is captured in trace
    let loaded_trace = frankenengine_engine::frx_lockstep_oracle::load_trace_file(&trace_path)
        .expect("should load trace");
    assert_eq!(loaded_trace.outcome, "error");
    assert!(loaded_trace.error_code.is_some());
    assert!(loaded_trace.error_code.unwrap().contains("exit_code_1"));

    // Verify completion event has error outcome
    let completion_event = loaded_trace.events.iter().find(|e| e.event == "completion");
    assert!(completion_event.is_some());
    assert_eq!(completion_event.unwrap().outcome, "error");

    let _ = fs::remove_dir_all(&temp_dir);
}
