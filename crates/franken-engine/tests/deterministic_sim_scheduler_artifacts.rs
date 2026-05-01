#![forbid(unsafe_code)]

use std::fs;
use std::process::Command;

use serde_json::Value;
use tempfile::TempDir;

fn artifact_bin() -> &'static str {
    env!("CARGO_BIN_EXE_franken_deterministic_sim_scheduler_artifacts")
}

fn read_json(path: &std::path::Path) -> Value {
    let text = fs::read_to_string(path).expect("artifact should be readable");
    serde_json::from_str(&text).expect("artifact should be valid JSON")
}

#[test]
fn deterministic_sim_artifact_emitter_writes_required_bundle() {
    let temp = TempDir::new().expect("temp dir");
    let out_dir = temp.path().join("bundle");

    let output = Command::new(artifact_bin())
        .args([
            "--out-dir",
            out_dir.to_str().expect("utf8 path"),
            "--seed",
            "803",
            "--trials",
            "3",
        ])
        .output()
        .expect("artifact command should run");

    assert!(
        output.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    for file in [
        "deterministic_simulation_report.json",
        "simulation_schedule_catalog.json",
        "simulated_nondeterminism_trace.jsonl",
        "simulation_oracle_matrix.json",
        "run_manifest.json",
        "events.jsonl",
        "commands.txt",
        "trace_ids.json",
        "env.json",
        "manifest.json",
        "repro.lock",
    ] {
        let path = out_dir.join(file);
        assert!(path.exists(), "missing {file}");
        assert!(
            fs::metadata(path).expect("metadata").len() > 0,
            "empty {file}"
        );
    }

    let report = read_json(&out_dir.join("deterministic_simulation_report.json"));
    assert_eq!(report["status"], "pass");
    assert_eq!(report["bead_id"], "bd-1lsy.9.3.3");
    assert_eq!(report["nondeterminism_detected"], false);

    let catalog = read_json(&out_dir.join("simulation_schedule_catalog.json"));
    assert_eq!(catalog["scenario_count"], 2);
    assert_eq!(
        catalog["stable_corpus_version"],
        "rgc-803c-sim-scheduler-corpus-v1"
    );

    let oracle = read_json(&out_dir.join("simulation_oracle_matrix.json"));
    assert_eq!(oracle["overall_outcome"], "pass");
}

#[test]
fn deterministic_sim_artifact_emitter_refuses_to_overwrite_report() {
    let temp = TempDir::new().expect("temp dir");
    let out_dir = temp.path().join("bundle");
    fs::create_dir_all(&out_dir).expect("create bundle");
    fs::write(out_dir.join("deterministic_simulation_report.json"), "{}\n")
        .expect("seed existing artifact");

    let output = Command::new(artifact_bin())
        .args([
            "--out-dir",
            out_dir.to_str().expect("utf8 path"),
            "--seed",
            "803",
            "--trials",
            "1",
        ])
        .output()
        .expect("artifact command should run");

    assert!(
        !output.status.success(),
        "command unexpectedly overwrote existing report"
    );
}

#[test]
fn deterministic_sim_artifact_events_are_jsonl_with_stable_logging_fields() {
    let temp = TempDir::new().expect("temp dir");
    let out_dir = temp.path().join("bundle");

    let output = Command::new(artifact_bin())
        .args([
            "--out-dir",
            out_dir.to_str().expect("utf8 path"),
            "--seed",
            "9001",
            "--trials",
            "2",
        ])
        .output()
        .expect("artifact command should run");
    assert!(
        output.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let events = fs::read_to_string(out_dir.join("events.jsonl")).expect("events");
    let parsed = events
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("valid jsonl event"))
        .collect::<Vec<_>>();

    assert_eq!(parsed.len(), 2);
    for event in parsed {
        assert_eq!(event["trace_id"], "trace-rgc-803c-9001");
        assert_eq!(event["decision_id"], "decision-rgc-803c-9001");
        assert_eq!(event["policy_id"], "policy-rgc-803c-scheduler-v1");
        assert_eq!(event["component"], "deterministic_sim_scheduler");
        assert_eq!(event["outcome"], "pass");
        assert!(event.get("error_code").is_some());
    }
}
