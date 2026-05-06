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
