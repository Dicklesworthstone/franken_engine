#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::Value;

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);
const CORPUS_ID: &str = "red_team_security_critical_compromise_v2";
const AGGREGATE_SCOPE: &str = "aggregate_stability_input_only_not_claim_verdict";
const CLAIM_PRODUCER: &str = "franken_red_team_harness_gate";

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

fn promoted_scenario_map() -> BTreeMap<&'static str, (&'static str, &'static str)> {
    BTreeMap::from([
        (
            "environment_variable_exfiltration",
            ("ambient_authority_via_globalthis", "ambient_authority_escape"),
        ),
        (
            "process_privilege_surface_probe",
            ("capability_shadowed_import", "ambient_authority_escape"),
        ),
        (
            "prototype_pollution_capability_escape",
            ("reflect_apply_authority_smuggling", "ambient_authority_escape"),
        ),
        (
            "shell_command_injection_package_script",
            ("typed_effect_laundering_downcast", "ambient_authority_escape"),
        ),
        (
            "supply_chain_backdoor_execution",
            ("smuggle_flow_via_unanalyzed_construct", "ambient_authority_escape"),
        ),
    ])
}

fn annotate_canonical_semantics(value: &mut Value) {
    value["corpus_id"] = Value::from(CORPUS_ID);
    value["scenario_set"] = Value::from(CORPUS_ID);
    value["denominator_semantics"] = Value::from("distinct_security_critical_scenarios");
    value["repetition_role"] =
        Value::from("stability_and_replay_not_independent_sampling");
    value["confidence_interpretation"] =
        Value::from("receipt_completeness_and_stability_not_population_confidence");
    value["zero_cell_guard"] = Value::from("one_hypothetical_frankenengine_compromise");
    value["zero_cell_guard_count"] = Value::from(1);
    value["required_stability_repetitions_per_runtime_scenario"] = Value::from(100);
    value["verdict_scope"] = Value::from(AGGREGATE_SCOPE);
    value["claim_verdict_eligible"] = Value::from(false);
    value["claim_verdict_producer"] = Value::from(CLAIM_PRODUCER);
    value["corpus_contract_path"] = Value::from("docs/red_team_scenario_corpus_v2.json");
    value["distinct_scenario_count"] = Value::from(10);
    value["attack_class_count"] = Value::from(3);
    value["runtime_scenario_pair_count"] = Value::from(30);
}

fn ten_scenario_fixture() -> Value {
    let mut value = fixture();
    let promoted = promoted_scenario_map();
    let additions = value["results"]
        .as_array()
        .expect("results array")
        .clone()
        .into_iter()
        .map(|mut result| {
            let source_id = result["scenario_id"].as_str().expect("scenario id");
            let (scenario_id, attack_class) = promoted[source_id];
            result["scenario_id"] = Value::from(scenario_id);
            result["attack_class"] = Value::from(attack_class);
            for field in ["witness_path", "transcript_path", "replay_command"] {
                let original = result[field].as_str().expect("string field").to_string();
                result[field] = Value::from(format!("{original}.{scenario_id}"));
            }
            result
        })
        .collect::<Vec<_>>();
    value["results"]
        .as_array_mut()
        .expect("results array")
        .extend(additions);
    annotate_canonical_semantics(&mut value);
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

fn assert_invalid(value: &Value, label: &str, expected_stderr: &str) {
    let test_dir = TestDir::new(label);
    let output = run_with_input(&test_dir, value);
    assert_eq!(output.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains(expected_stderr),
        "unexpected stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn exact_contract_corpus_emits_passing_machine_and_markdown_reports() {
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
    assert_eq!(report["report"]["corpus_id"], CORPUS_ID);
    assert_eq!(
        report["report"]["corpus_contract_path"],
        "docs/red_team_scenario_corpus_v2.json"
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
    assert!(markdown.contains("not independent population samples"));
}

#[test]
fn unannotated_legacy_five_scenario_bundle_is_invalid_input() {
    assert_invalid(
        &fixture(),
        "legacy-five-scenario",
        "harness semantic field corpus_id mismatch",
    );
}

#[test]
fn corpus_count_annotation_cannot_lie() {
    let mut value = ten_scenario_fixture();
    value["distinct_scenario_count"] = Value::from(11);
    assert_invalid(&value, "lying-count", "distinct_scenario_count mismatch");
}

#[test]
fn exact_scenario_identity_is_required_even_when_counts_match() {
    let mut value = ten_scenario_fixture();
    let result = value["results"]
        .as_array_mut()
        .expect("results array")
        .iter_mut()
        .find(|result| result["scenario_id"] == "ambient_authority_via_globalthis")
        .expect("promoted scenario");
    result["scenario_id"] = Value::from("ten_row_lookalike_scenario");
    assert_invalid(&value, "wrong-scenario", "corpus identity mismatch");
}

#[test]
fn exact_attack_class_mapping_is_required() {
    let mut value = ten_scenario_fixture();
    for result in value["results"]
        .as_array_mut()
        .expect("results array")
        .iter_mut()
        .filter(|result| result["scenario_id"] == "reflect_apply_authority_smuggling")
    {
        result["attack_class"] = Value::from("prototype_pollution");
    }
    assert_invalid(&value, "wrong-class", "wrong_class");
}

#[test]
fn typed_scenario_set_must_match_corpus_id() {
    let mut value = ten_scenario_fixture();
    value["scenario_set"] = Value::from("legacy-five-scenario-set");
    assert_invalid(&value, "wrong-set", "scenario_set mismatch");
}

#[test]
fn aggregate_input_must_be_explicitly_ineligible_as_claim_verdict() {
    let mut value = ten_scenario_fixture();
    value["claim_verdict_eligible"] = Value::from(true);
    assert_invalid(
        &value,
        "eligible-input",
        "claim_verdict_eligible=false",
    );
}

#[test]
fn aggregate_input_must_name_the_sole_claim_producer() {
    let mut value = ten_scenario_fixture();
    value["claim_verdict_producer"] = Value::from("generic_aggregator");
    assert_invalid(
        &value,
        "wrong-producer",
        "claim_verdict_producer mismatch",
    );
}

#[test]
fn below_contract_stability_floor_is_invalid_input() {
    let mut value = ten_scenario_fixture();
    value["min_trials_per_runtime"] = Value::from(99);
    assert_invalid(&value, "minimum", "below required 100");
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
        let attempts_total = result["attempts_total"].clone();
        result["attempts_successful"] = attempts_total;
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
fn unequal_runtime_repetition_denominators_are_invalid_input() {
    let mut value = ten_scenario_fixture();
    let result = value["results"]
        .as_array_mut()
        .expect("results array")
        .iter_mut()
        .find(|result| result["runtime"] == "node")
        .expect("Node row");
    result["attempts_total"] = Value::from(101);
    assert_invalid(
        &value,
        "unequal-denominator",
        "unequal runtime repetition denominators",
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
