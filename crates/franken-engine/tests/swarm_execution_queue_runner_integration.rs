#![forbid(unsafe_code)]

use std::fs;
use std::path::Path;

use frankenengine_engine::swarm_execution_queue_runner::{
    ExecutionQueueRunOptions, run_normalized_input_file,
};
use serde_json::{Value, json};
use tempfile::tempdir;

fn task(id: &str, deps: &[&str], impact: i64, friction: i64, fallback: &str) -> Value {
    json!({
        "task_id": id,
        "title": format!("Task {id}"),
        "status": "open",
        "priority": 2,
        "assignee": "",
        "depends_on": deps,
        "dependents": [],
        "completed": false,
        "open_blocker_count": deps.len(),
        "owner_freshness": {
            "state": "unassigned",
            "last_active_age_seconds": 0
        },
        "reservation_pressure": {
            "state": "clear",
            "active_reservation_count": 0
        },
        "proof_transport": {
            "state": "remote_only_ok",
            "local_fallback_detected": false
        },
        "scores": {
            "impact_millionths": impact,
            "confidence_millionths": 900000,
            "reuse_millionths": 700000,
            "effort_millionths": 220000,
            "friction_millionths": friction
        },
        "fallback_trigger": fallback,
        "first_action": format!("first action for {id}")
    })
}

fn input(tasks: Vec<Value>) -> Value {
    json!({
        "schema_version": "franken-engine.swarm-execution-queue-input.v1",
        "source_revision": "fixture-rev",
        "generated_epoch_seconds": 1800000000,
        "decision": "pass",
        "accepted_inputs": [
            {"input": "br_ready_json"},
            {"input": "br_list_json"}
        ],
        "degraded_inputs": [],
        "fail_closed_reasons": [],
        "cross_cutting_signals": {
            "observability_quality_millionths": 900000,
            "catastrophic_tail_score_millionths": 10000,
            "bifurcation_distance_millionths": 900000,
            "unit_depth_score_millionths": 900000,
            "e2e_stability_score_millionths": 900000,
            "logging_integrity_score_millionths": 900000
        },
        "risk_budget": {
            "remaining_millionths": 900000,
            "consumed_millionths": 100000,
            "conservative_threshold_millionths": 200000,
            "conservative_mode": false
        },
        "tasks": tasks
    })
}

fn write_input(dir: &Path, value: &Value) -> std::path::PathBuf {
    let path = dir.join("normalized_input.json");
    fs::write(&path, serde_json::to_vec_pretty(value).unwrap()).unwrap();
    path
}

fn run(value: &Value, output_name: &str) -> (tempfile::TempDir, Value, Value, Value) {
    let dir = tempdir().unwrap();
    let input_path = write_input(dir.path(), value);
    let output_dir = dir.path().join(output_name);
    let output = run_normalized_input_file(
        &input_path,
        &output_dir,
        ExecutionQueueRunOptions {
            epoch: 7,
            timestamp_ns: 777,
            ..ExecutionQueueRunOptions::default()
        },
    )
    .unwrap();
    let queue: Value =
        serde_json::from_slice(&fs::read(output.execution_queue_artifact_json).unwrap()).unwrap();
    let risk: Value =
        serde_json::from_slice(&fs::read(output.risk_budget_receipt_json).unwrap()).unwrap();
    let bottlenecks: Value =
        serde_json::from_slice(&fs::read(output.bottleneck_report_json).unwrap()).unwrap();
    (dir, queue, risk, bottlenecks)
}

#[test]
fn runner_preserves_wave_ordering_and_artifacts() {
    let value = input(vec![
        task("bd-parent", &["bd-child"], 950000, 10000, "blocked_parent"),
        task("bd-child", &[], 700000, 10000, "none"),
    ]);

    let (_dir, queue, risk, bottlenecks) = run(&value, "out");
    let entries = queue["queue_artifact"]["queue"].as_array().unwrap();

    assert_eq!(
        queue["schema_version"],
        "franken-engine.swarm-execution-queue-artifact.v1"
    );
    assert_eq!(entries[0]["task_id"], "bd-child");
    assert_eq!(entries[0]["wave"], "ready_now");
    assert_eq!(entries[1]["task_id"], "bd-parent");
    assert_eq!(entries[1]["wave"], "ready_next");
    assert_eq!(
        risk["schema_version"],
        "franken-engine.swarm-execution-risk-budget-receipt.v1"
    );
    assert_eq!(
        bottlenecks["schema_version"],
        "franken-engine.swarm-execution-bottleneck-report.v1"
    );
}

#[test]
fn runner_preserves_conservative_risk_budget() {
    let mut value = input(vec![task(
        "bd-brownout",
        &[],
        700000,
        500000,
        "proof_brownout_conservative_mode",
    )]);
    value["decision"] = json!("degraded");
    value["degraded_inputs"] = json!([
        {"kind": "proof_transport_degraded", "label": "bd-brownout"}
    ]);
    value["risk_budget"] = json!({
        "remaining_millionths": 180000,
        "consumed_millionths": 820000,
        "conservative_threshold_millionths": 200000,
        "conservative_mode": true
    });
    value["tasks"][0]["proof_transport"]["state"] = json!("brownout");

    let (_dir, queue, risk, _bottlenecks) = run(&value, "out");

    assert_eq!(risk["conservative_mode"], true);
    assert_eq!(
        queue["queue_artifact"]["queue"][0]["fallback_trigger"],
        "proof_brownout_conservative_mode"
    );
}

#[test]
fn runner_keeps_stale_owner_friction_and_first_action() {
    let mut stale = task(
        "bd-stale",
        &[],
        900000,
        350000,
        "contact_or_reopen_required",
    );
    stale["owner_freshness"]["state"] = json!("stale");
    stale["assignee"] = json!("DormantAgent");
    let mut value = input(vec![stale]);
    value["decision"] = json!("degraded");
    value["degraded_inputs"] = json!([
        {"kind": "stale_owner", "label": "bd-stale"}
    ]);

    let (_dir, queue, _risk, _bottlenecks) = run(&value, "out");
    let entry = &queue["queue_artifact"]["queue"][0];

    assert_eq!(entry["task_id"], "bd-stale");
    assert_eq!(entry["friction_millionths"], 350000);
    assert_eq!(entry["fallback_trigger"], "contact_or_reopen_required");
    assert!(entry["first_action"].as_str().unwrap().contains("bd-stale"));
}

#[test]
fn runner_rejects_cycles() {
    let value = input(vec![
        task("bd-cycle-a", &["bd-cycle-b"], 700000, 0, "none"),
        task("bd-cycle-b", &["bd-cycle-a"], 700000, 0, "none"),
    ]);
    let dir = tempdir().unwrap();
    let input_path = write_input(dir.path(), &value);
    let err = run_normalized_input_file(
        &input_path,
        dir.path().join("out"),
        ExecutionQueueRunOptions::default(),
    )
    .unwrap_err();

    assert_eq!(err.exit_code(), 42);
    assert!(err.to_string().contains("cycle detected"));
}

#[test]
fn runner_rejects_unrecognized_degraded_evidence() {
    let mut value = input(vec![task("bd-a", &[], 700000, 0, "none")]);
    value["decision"] = json!("degraded");
    value["degraded_inputs"] = json!([
        {"kind": "mystery_degradation", "label": "bd-a"}
    ]);
    let dir = tempdir().unwrap();
    let input_path = write_input(dir.path(), &value);
    let err = run_normalized_input_file(
        &input_path,
        dir.path().join("out"),
        ExecutionQueueRunOptions::default(),
    )
    .unwrap_err();

    assert_eq!(err.exit_code(), 42);
    assert!(err.to_string().contains("unrecognized degraded evidence"));
}

#[test]
fn runner_rejects_duplicate_task_ids_before_writing_artifacts() {
    let value = input(vec![
        task("bd-duplicate", &[], 800000, 0, "none"),
        task("bd-duplicate", &[], 700000, 20000, "none"),
    ]);
    let dir = tempdir().unwrap();
    let input_path = write_input(dir.path(), &value);
    let output_dir = dir.path().join("out");
    let err = run_normalized_input_file(
        &input_path,
        &output_dir,
        ExecutionQueueRunOptions::default(),
    )
    .unwrap_err();

    assert_eq!(err.exit_code(), 42);
    assert!(
        err.to_string().contains("duplicate task_id bd-duplicate"),
        "unexpected diagnostic: {err}"
    );
    assert!(
        !output_dir.exists()
            || fs::read_dir(&output_dir)
                .expect("output dir should remain readable if it exists")
                .next()
                .is_none(),
        "duplicate task IDs must fail before runner artifacts are written"
    );
}

#[test]
fn runner_artifact_hash_is_stable_across_repeated_runs() {
    let value = input(vec![
        task("bd-alpha", &[], 800000, 10000, "none"),
        task("bd-beta", &[], 700000, 20000, "none"),
    ]);

    let (_dir_a, queue_a, _risk_a, _bottlenecks_a) = run(&value, "out-a");
    let (_dir_b, queue_b, _risk_b, _bottlenecks_b) = run(&value, "out-b");

    assert_eq!(queue_a["artifact_hash_hex"], queue_b["artifact_hash_hex"]);
    assert_eq!(
        queue_a["queue_artifact"]["queue"],
        queue_b["queue_artifact"]["queue"]
    );
}

/// Comprehensive conformance harness for swarm execution queue runner mutation-free contract.
///
/// Validates all documented invariants that the runner must satisfy:
/// - Mutation-free: does not touch live bead, reservation, Agent Mail, or worker state
/// - Deterministic: fixed inputs produce identical outputs
/// - Fail-closed: invalid inputs return exit code 42
/// - Schema stability: all outputs use documented schema versions
#[test]
fn swarm_execution_queue_runner_mutation_free_conformance() {
    // Test 1: Mutation-free contract with sentinel files
    assert_mutation_free_contract();

    // Test 2: Deterministic output contract
    assert_deterministic_output_contract();

    // Test 3: Fail-closed invalid input contract
    assert_fail_closed_invalid_input_contract();

    // Test 4: Schema stability contract
    assert_schema_stability_contract();
}

fn assert_mutation_free_contract() {
    let test_dir = tempdir().unwrap();

    // Create sentinel files outside output directory that should NEVER be modified
    let sentinel_bead_file = test_dir.path().join("sentinel_bead.json");
    let sentinel_mail_file = test_dir.path().join("sentinel_agent_mail.json");
    let sentinel_reservation_file = test_dir.path().join("sentinel_reservations.json");
    let sentinel_worker_file = test_dir.path().join("sentinel_worker_state.json");

    let sentinel_content = r#"{"sentinel": true, "timestamp": 1234567890}"#;
    fs::write(&sentinel_bead_file, sentinel_content).unwrap();
    fs::write(&sentinel_mail_file, sentinel_content).unwrap();
    fs::write(&sentinel_reservation_file, sentinel_content).unwrap();
    fs::write(&sentinel_worker_file, sentinel_content).unwrap();

    // Record initial state of sentinel files
    let initial_bead_content = fs::read(&sentinel_bead_file).unwrap();
    let initial_mail_content = fs::read(&sentinel_mail_file).unwrap();
    let initial_reservation_content = fs::read(&sentinel_reservation_file).unwrap();
    let initial_worker_content = fs::read(&sentinel_worker_file).unwrap();

    // Create valid input and dedicated output directory
    let valid_input = input(vec![task("bd-test-mutation", &[], 700000, 10000, "none")]);
    let input_path = write_input(test_dir.path(), &valid_input);
    let output_dir = test_dir.path().join("runner_output");

    // Run the queue runner
    let result = run_normalized_input_file(
        &input_path,
        &output_dir,
        ExecutionQueueRunOptions {
            epoch: 42,
            timestamp_ns: 999,
            queue_depth: 5,
            ..ExecutionQueueRunOptions::default()
        },
    );

    // Assert successful execution
    assert!(result.is_ok(), "Valid input should execute successfully");
    let output = result.unwrap();

    // Assert sentinel files were NOT modified (mutation-free contract)
    assert_eq!(
        fs::read(&sentinel_bead_file).unwrap(),
        initial_bead_content,
        "Runner must not modify bead state files"
    );
    assert_eq!(
        fs::read(&sentinel_mail_file).unwrap(),
        initial_mail_content,
        "Runner must not modify Agent Mail state files"
    );
    assert_eq!(
        fs::read(&sentinel_reservation_file).unwrap(),
        initial_reservation_content,
        "Runner must not modify reservation state files"
    );
    assert_eq!(
        fs::read(&sentinel_worker_file).unwrap(),
        initial_worker_content,
        "Runner must not modify worker state files"
    );

    // Assert only expected output files were created in the output directory
    let expected_output_files = [
        "run_manifest.json",
        "events.jsonl",
        "commands.txt",
        "execution_queue_artifact.json",
        "risk_budget_receipt.json",
        "bottleneck_report.json",
        "operator_summary.md",
    ];

    for expected_file in &expected_output_files {
        let expected_path = output_dir.join(expected_file);
        assert!(
            expected_path.exists(),
            "Expected output file {} should exist",
            expected_file
        );
    }

    // Assert no unexpected files were created
    let actual_files: std::collections::BTreeSet<_> = fs::read_dir(&output_dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().to_string())
        .collect();

    let expected_files: std::collections::BTreeSet<_> = expected_output_files
        .iter()
        .map(|s| s.to_string())
        .collect();

    assert_eq!(
        actual_files, expected_files,
        "Runner should only create expected output files"
    );

    // Verify output structure
    assert!(output.run_manifest_json.exists());
    assert!(output.events_jsonl.exists());
    assert!(output.execution_queue_artifact_json.exists());
    assert!(!output.artifact_hash_hex.is_empty());
}

fn assert_deterministic_output_contract() {
    let fixed_input = input(vec![
        task("bd-deterministic-a", &[], 800000, 15000, "none"),
        task(
            "bd-deterministic-b",
            &["bd-deterministic-a"],
            600000,
            25000,
            "blocked_parent",
        ),
    ]);

    let fixed_options = ExecutionQueueRunOptions {
        epoch: 123,
        timestamp_ns: 456789,
        queue_depth: 8,
        include_gated_in_queue: true,
        command_line: vec!["test".to_string(), "deterministic".to_string()],
    };

    // Run the same input twice with identical options
    let (_dir1, queue1, risk1, bottleneck1) =
        run_with_options(&fixed_input, "deterministic-1", fixed_options.clone());
    let (_dir2, queue2, risk2, bottleneck2) =
        run_with_options(&fixed_input, "deterministic-2", fixed_options);

    // Assert outputs are byte-for-byte identical (after path normalization)
    assert_eq!(
        normalize_paths(&queue1),
        normalize_paths(&queue2),
        "Queue artifacts should be deterministic"
    );
    assert_eq!(
        normalize_paths(&risk1),
        normalize_paths(&risk2),
        "Risk budget receipts should be deterministic"
    );
    assert_eq!(
        normalize_paths(&bottleneck1),
        normalize_paths(&bottleneck2),
        "Bottleneck reports should be deterministic"
    );

    // Verify artifact hash consistency
    assert_eq!(
        queue1["artifact_hash_hex"], queue2["artifact_hash_hex"],
        "Artifact hashes should be deterministic"
    );
}

fn assert_fail_closed_invalid_input_contract() {
    let invalid_inputs = [
        // Wrong schema version
        {
            let mut invalid = input(vec![task("bd-invalid", &[], 700000, 0, "none")]);
            invalid["schema_version"] = json!("wrong-schema-version");
            invalid
        },
        // Empty task graph
        input(vec![]),
        // Pre-existing fail_closed decision
        {
            let mut invalid = input(vec![task("bd-invalid", &[], 700000, 0, "none")]);
            invalid["decision"] = json!("fail_closed");
            invalid
        },
        // Pre-existing fail_closed_reasons
        {
            let mut invalid = input(vec![task("bd-invalid", &[], 700000, 0, "none")]);
            invalid["fail_closed_reasons"] = json!([
                {"kind": "pre_existing_failure", "label": "bd-invalid"}
            ]);
            invalid
        },
    ];

    for (i, invalid_input) in invalid_inputs.iter().enumerate() {
        let dir = tempdir().unwrap();
        let input_path = write_input(dir.path(), invalid_input);
        let output_dir = dir.path().join(format!("invalid-{}", i));

        let result = run_normalized_input_file(
            &input_path,
            &output_dir,
            ExecutionQueueRunOptions::default(),
        );

        // Assert failure with exit code 42
        assert!(result.is_err(), "Invalid input {} should fail", i);
        let error = result.unwrap_err();
        assert_eq!(
            error.exit_code(),
            42,
            "Invalid input {} should fail with exit code 42",
            i
        );

        // Assert no output directory was created or it's empty
        if output_dir.exists() {
            let entries: Vec<_> = fs::read_dir(&output_dir).unwrap().collect();
            assert!(
                entries.is_empty(),
                "Failed runs should not create output artifacts"
            );
        }
    }
}

fn assert_schema_stability_contract() {
    let test_input = input(vec![task("bd-schema", &[], 750000, 12000, "none")]);

    let (_dir, queue, risk, bottleneck) = run(&test_input, "schema-test");

    // Verify all schema versions match documented constants
    assert_eq!(queue["schema_version"],
        frankenengine_engine::swarm_execution_queue_runner::SWARM_EXECUTION_QUEUE_ARTIFACT_SCHEMA_VERSION,
        "Queue artifact schema must match constant");

    assert_eq!(risk["schema_version"],
        frankenengine_engine::swarm_execution_queue_runner::SWARM_EXECUTION_RISK_BUDGET_RECEIPT_SCHEMA_VERSION,
        "Risk budget receipt schema must match constant");

    assert_eq!(bottleneck["schema_version"],
        frankenengine_engine::swarm_execution_queue_runner::SWARM_EXECUTION_BOTTLENECK_REPORT_SCHEMA_VERSION,
        "Bottleneck report schema must match constant");

    // Verify specific schema version strings
    assert_eq!(
        queue["schema_version"],
        "franken-engine.swarm-execution-queue-artifact.v1"
    );
    assert_eq!(
        risk["schema_version"],
        "franken-engine.swarm-execution-risk-budget-receipt.v1"
    );
    assert_eq!(
        bottleneck["schema_version"],
        "franken-engine.swarm-execution-bottleneck-report.v1"
    );
}

fn run_with_options(
    value: &Value,
    output_name: &str,
    options: ExecutionQueueRunOptions,
) -> (tempfile::TempDir, Value, Value, Value) {
    let dir = tempdir().unwrap();
    let input_path = write_input(dir.path(), value);
    let output_dir = dir.path().join(output_name);
    let output = run_normalized_input_file(&input_path, &output_dir, options).unwrap();

    let queue: Value =
        serde_json::from_slice(&fs::read(output.execution_queue_artifact_json).unwrap()).unwrap();
    let risk: Value =
        serde_json::from_slice(&fs::read(output.risk_budget_receipt_json).unwrap()).unwrap();
    let bottleneck: Value =
        serde_json::from_slice(&fs::read(output.bottleneck_report_json).unwrap()).unwrap();

    (dir, queue, risk, bottleneck)
}

fn normalize_paths(value: &Value) -> Value {
    // Remove path-specific fields that would differ between runs
    let mut normalized = value.clone();
    if let Some(obj) = normalized.as_object_mut() {
        obj.remove("output_dir");
        obj.remove("input_path");
        obj.remove("generated_at");
        obj.remove("run_id");
    }
    normalized
}
