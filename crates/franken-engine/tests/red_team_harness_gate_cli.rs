#![forbid(unsafe_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::Value;

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);

struct TestDir(PathBuf);

impl TestDir {
    fn new(label: &str) -> Self {
        let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "franken-red-team-harness-gate-{label}-{}-{id}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).expect("create test directory");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_franken_red_team_harness_gate")
}

fn fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/red_team_harness_output_v1.json"))
        .expect("valid harness fixture")
}

fn ten_scenario_fixture() -> Value {
    let mut value = fixture();
    let additions = value["results"]
        .as_array()
        .expect("results array")
        .clone()
        .into_iter()
        .map(|mut result| {
            let scenario_id = result["scenario_id"]
                .as_str()
                .expect("scenario id")
                .to_string();
            result["scenario_id"] = Value::from(format!("{scenario_id}_variant_b"));
            for field in ["witness_path", "transcript_path", "replay_command"] {
                let original = result[field].as_str().expect("string field").to_string();
                result[field] = Value::from(format!("{original}.variant-b"));
            }
            result
        })
        .collect::<Vec<_>>();
    value["results"]
        .as_array_mut()
        .expect("results array")
        .extend(additions);
    value
}

fn write_json(path: &Path, value: &Value) {
    fs::write(
        path,
        serde_json::to_vec_pretty(value).expect("serialize test JSON"),
    )
    .expect("write test JSON");
}

fn run_with_input(test_dir: &TestDir, value: &Value) -> std::process::Output {
    let input = test_dir.path().join("input.json");
    write_json(&input, value);
    Command::new(binary())
        .args(["--input", input.to_str().expect("UTF-8 input path")])
        .output()
        .expect("run harness gate")
}

#[test]
fn ten_distinct_scenarios_emit_passing_machine_and_markdown_reports() {
    let test_dir = TestDir::new("pass");
    let input = test_dir.path().join("input.json");
    let output = test_dir.path().join("report.json");
    let markdown = test_dir.path().join("report.md");
    write_json(&input, &ten_scenario_fixture());

    let result = Command::new(binary())
        .args([
            "--input",
            input.to_str().expect("UTF-8 input path"),
            "--output",
            output.to_str().expect("UTF-8 output path"),
            "--markdown",
            markdown.to_str().expect("UTF-8 markdown path"),
        ])
        .output()
        .expect("run harness gate");

    assert!(
        result.status.success(),
        "gate failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(result.stdout.is_empty());
    let report: Value =
        serde_json::from_slice(&fs::read(output).expect("read report")).expect("parse report");
    assert_eq!(
        report["schema_version"],
        "franken-engine.red-team-harness-gate-output.v2"
    );
    assert_eq!(report["report"]["scenario_count"], 10);
    assert_eq!(report["report"]["attack_class_count"], 3);
    assert_eq!(report["report"]["conservative_reduction_floor_x"], 10);
    assert_eq!(
        report["report"]["reason"],
        "red_team_compromise_rate_reduction_verified_on_declared_scenario_corpus"
    );
    assert_eq!(
        report["report"]["confidence_interpretation"],
        "receipt completeness and outcome stability; not statistical population confidence"
    );
    let markdown = fs::read_to_string(markdown).expect("read markdown");
    assert!(markdown.contains("Red-Team Scenario-Corpus Compromise-Rate Gate"));
    assert!(markdown.contains("not treated as independent population samples"));
}

#[test]
fn five_scenarios_cannot_turn_zero_candidate_events_into_infinite_claim() {
    let test_dir = TestDir::new("five-scenario-guard");
    let result = run_with_input(&test_dir, &fixture());
    assert_eq!(result.status.code(), Some(1));
    assert!(result.stderr.is_empty());
    let report: Value = serde_json::from_slice(&result.stdout).expect("parse gate output");
    assert_eq!(report["report"]["scenario_count"], 5);
    assert_eq!(report["report"]["conservative_reduction_floor_x"], 5);
    assert_eq!(
        report["report"]["reason"],
        "insufficient_distinct_scenario_denominator"
    );
}

#[test]
fn below_minimum_harness_is_rejected_as_invalid_input() {
    let test_dir = TestDir::new("minimum");
    let mut value = ten_scenario_fixture();
    value["min_trials_per_runtime"] = Value::from(99);
    let result = run_with_input(&test_dir, &value);
    assert_eq!(result.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&result.stderr).contains("below required 100"),
        "unexpected stderr: {}",
        String::from_utf8_lossy(&result.stderr)
    );
}

#[test]
fn mixed_repeated_outcomes_fail_closed_instead_of_becoming_confidence() {
    let test_dir = TestDir::new("mixed");
    let mut value = ten_scenario_fixture();
    let result = value["results"]
        .as_array_mut()
        .expect("results array")
        .iter_mut()
        .find(|result| result["runtime"] == "franken_engine")
        .expect("FrankenEngine row");
    result["attempts_successful"] = Value::from(1);

    let output = run_with_input(&test_dir, &value);
    assert_eq!(output.status.code(), Some(1));
    let report: Value = serde_json::from_slice(&output.stdout).expect("parse gate output");
    assert_eq!(
        report["report"]["reason"],
        "unstable_runtime_scenario_outcomes"
    );
    assert_eq!(
        report["report"]["mixed_outcome_pairs"]
            .as_array()
            .expect("mixed pairs")
            .len(),
        1
    );
}

#[test]
fn two_compromised_candidate_scenarios_fail_guarded_ten_x_floor() {
    let test_dir = TestDir::new("candidate-compromise");
    let mut value = ten_scenario_fixture();
    for result in value["results"]
        .as_array_mut()
        .expect("results array")
        .iter_mut()
        .filter(|result| result["runtime"] == "franken_engine")
        .take(2)
    {
        result["attempts_successful"] = result["attempts_total"].clone();
    }

    let output = run_with_input(&test_dir, &value);
    assert_eq!(output.status.code(), Some(1));
    let report: Value = serde_json::from_slice(&output.stdout).expect("parse gate output");
    assert_eq!(report["report"]["frankenengine_compromised_scenarios"], 2);
    assert_eq!(report["report"]["conservative_reduction_floor_x"], 5);
    assert_eq!(
        report["report"]["reason"],
        "zero_cell_guarded_reduction_below_threshold"
    );
}

#[test]
fn unequal_runtime_attempt_denominators_are_invalid_input() {
    let test_dir = TestDir::new("unequal-denominator");
    let mut value = ten_scenario_fixture();
    let result = value["results"]
        .as_array_mut()
        .expect("results array")
        .iter_mut()
        .find(|result| result["runtime"] == "node")
        .expect("Node row");
    result["attempts_total"] = Value::from(101);

    let output = run_with_input(&test_dir, &value);
    assert_eq!(output.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("unequal runtime attempt denominators")
    );
}

#[test]
fn help_is_a_successful_non_mutating_surface() {
    let result = Command::new(binary())
        .arg("--help")
        .output()
        .expect("run harness gate help");
    assert!(result.status.success());
    assert!(String::from_utf8_lossy(&result.stdout).contains("usage:"));
    assert!(result.stderr.is_empty());
}
