#![forbid(unsafe_code)]

use std::fs;
use std::path::{Path, PathBuf};

use frankenengine_engine::performance_statistical_validation::{
    StatisticalValidationInput, StatisticalValidationPolicy, WorkloadOutcome, WorkloadSamples,
    evaluate_statistical_validation,
};
use serde::Deserialize;

const RGC_702_CONTRACT_SCHEMA_VERSION: &str =
    "franken-engine.rgc-statistical-validation-pipeline.v1";
const RGC_702_CONTRACT_JSON: &str =
    include_str!("../../../docs/rgc_statistical_validation_pipeline_v1.json");

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct Rgc702Contract {
    schema_version: String,
    contract_version: String,
    bead_id: String,
    policy_id: String,
    required_log_keys: Vec<String>,
    required_artifacts: Vec<String>,
    thresholds: Rgc702Thresholds,
    failure_scenarios: Vec<Rgc702FailureScenario>,
    gate_runner: Rgc702GateRunner,
    operator_verification: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct Rgc702Thresholds {
    max_cv_millionths: u32,
    warning_regression_millionths: u32,
    fail_regression_millionths: u32,
    max_p_value_millionths: u32,
    min_effect_size_millionths: u32,
    confidence_level_millionths: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct Rgc702FailureScenario {
    scenario_id: String,
    path_type: String,
    expected_exit_code: u8,
    expected_error_code: String,
    expected_message_fragment: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct Rgc702GateRunner {
    script: String,
    replay_wrapper: String,
    strict_mode: String,
    manifest_schema_version: String,
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_to_string(path: &Path) -> String {
    fs::read_to_string(path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()))
}

fn parse_contract() -> Rgc702Contract {
    serde_json::from_str(RGC_702_CONTRACT_JSON)
        .expect("RGC statistical validation pipeline contract must parse")
}

fn sample_workload() -> WorkloadSamples {
    WorkloadSamples::new(
        "router_hot_path",
        "golden",
        "sha256:router-hot-path",
        vec![1000, 1001, 999, 1000, 1002, 998, 1000, 1001, 999],
        vec![1030, 1031, 1029, 1030, 1032, 1028, 1031, 1030, 1029],
    )
}

#[test]
fn rgc_702_doc_contains_required_sections() {
    let path = repo_root().join("docs/RGC_STATISTICAL_VALIDATION_PIPELINE_V1.md");
    let doc = read_to_string(&path);

    for section in [
        "# RGC Statistical Validation Pipeline V1",
        "## Scope",
        "## Threshold Contract",
        "## Structured Logging Contract",
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
fn rgc_702_readme_gate_section_documents_contract_and_artifacts() {
    let path = repo_root().join("README.md");
    let readme = read_to_string(&path);

    for fragment in [
        "## RGC Statistical Validation Pipeline",
        "./scripts/run_rgc_statistical_validation_pipeline.sh ci",
        "./scripts/e2e/rgc_statistical_validation_pipeline_replay.sh ci",
        "docs/rgc_statistical_validation_pipeline_v1.json",
        "artifacts/rgc_statistical_validation_pipeline/<timestamp>/run_manifest.json",
    ] {
        assert!(
            readme.contains(fragment),
            "missing README fragment in {}: {fragment}",
            path.display()
        );
    }
}

#[test]
fn rgc_702_contract_schema_and_thresholds_are_valid() {
    let contract = parse_contract();

    assert_eq!(contract.schema_version, RGC_702_CONTRACT_SCHEMA_VERSION);
    assert_eq!(contract.contract_version, "1.0.0");
    assert_eq!(contract.bead_id, "bd-1lsy.8.2");
    assert_eq!(
        contract.policy_id,
        "policy-rgc-statistical-validation-pipeline-v1"
    );

    assert!(
        contract.thresholds.fail_regression_millionths
            >= contract.thresholds.warning_regression_millionths,
        "fail threshold must not be lower than warning"
    );
    assert!(
        contract.thresholds.max_p_value_millionths <= 1_000_000,
        "p-value threshold must be within millionths"
    );
    assert!(
        (500_000..=999_999).contains(&contract.thresholds.confidence_level_millionths),
        "confidence must be in (0.5, 1.0)"
    );
}

#[test]
fn rgc_702_gate_runner_references_expected_scripts() {
    let contract = parse_contract();

    assert_eq!(
        contract.gate_runner.script,
        "scripts/run_rgc_statistical_validation_pipeline.sh"
    );
    assert_eq!(
        contract.gate_runner.replay_wrapper,
        "scripts/e2e/rgc_statistical_validation_pipeline_replay.sh"
    );
    assert_eq!(
        contract.gate_runner.manifest_schema_version,
        "franken-engine.rgc-statistical-validation-pipeline.run-manifest.v1"
    );
    assert_eq!(
        contract.gate_runner.strict_mode,
        "rch_only_no_local_fallback"
    );
}

#[test]
fn rgc_702_failure_scenarios_cover_core_fail_closed_paths() {
    let contract = parse_contract();

    assert!(
        contract
            .failure_scenarios
            .iter()
            .any(|scenario| scenario.expected_error_code == "FE-RGC-702-INTEGRITY-0001"),
        "missing integrity failure scenario"
    );
    assert!(
        contract
            .failure_scenarios
            .iter()
            .any(|scenario| scenario.expected_error_code == "FE-RGC-702-VARIANCE-0003"),
        "missing variance quarantine scenario"
    );
    assert!(
        contract
            .failure_scenarios
            .iter()
            .any(|scenario| scenario.expected_error_code == "FE-RGC-702-REGRESSION-0004"),
        "missing regression failure scenario"
    );
}

#[test]
fn rgc_702_pipeline_flags_regression_failure() {
    let mut policy = StatisticalValidationPolicy {
        warmup_drop_samples: 0,
        min_samples_after_filter: 5,
        ..StatisticalValidationPolicy::default()
    };
    policy.outlier_policy.min_retained_samples = 5;
    policy.thresholds.warning_regression_millionths = 10_000;
    policy.thresholds.fail_regression_millionths = 20_000;
    policy.thresholds.max_p_value_millionths = 50_000;
    policy.thresholds.min_effect_size_millionths = 3_000;

    let input = StatisticalValidationInput::new(
        "trace-rgc-702",
        "decision-rgc-702",
        "policy-rgc-statistical-validation-pipeline-v1",
        vec![sample_workload()],
    );

    let report = evaluate_statistical_validation(&input, &policy);

    assert!(!report.promote_allowed);
    assert_eq!(report.verdicts.len(), 1);
    assert_eq!(report.verdicts[0].outcome, WorkloadOutcome::Fail);
    assert!(
        report
            .failed_workloads
            .contains(&"router_hot_path".to_string()),
        "expected failing workload list to include router_hot_path"
    );
    assert!(
        report.logs.iter().any(|event| {
            event.event == "workload_evaluated" && event.workload_id == "router_hot_path"
        }),
        "expected workload evaluation log event"
    );
}

// ---------- parse_contract ----------

#[test]
fn contract_schema_version_is_stable() {
    let contract = parse_contract();
    assert_eq!(contract.schema_version, RGC_702_CONTRACT_SCHEMA_VERSION);
}

#[test]
fn contract_bead_id_is_correct() {
    let contract = parse_contract();
    assert_eq!(contract.bead_id, "bd-1lsy.8.2");
}

// ---------- Rgc702Thresholds ----------

#[test]
fn contract_thresholds_warning_less_than_fail() {
    let contract = parse_contract();
    assert!(
        contract.thresholds.fail_regression_millionths
            >= contract.thresholds.warning_regression_millionths
    );
}

#[test]
fn contract_thresholds_p_value_within_range() {
    let contract = parse_contract();
    assert!(contract.thresholds.max_p_value_millionths <= 1_000_000);
}

// ---------- Rgc702FailureScenario ----------

#[test]
fn failure_scenarios_have_unique_ids() {
    let contract = parse_contract();
    let mut ids = std::collections::BTreeSet::new();
    for scenario in &contract.failure_scenarios {
        assert!(
            ids.insert(scenario.scenario_id.clone()),
            "duplicate failure scenario id"
        );
    }
}

#[test]
fn failure_scenarios_all_have_error_codes() {
    let contract = parse_contract();
    for scenario in &contract.failure_scenarios {
        assert!(scenario.expected_error_code.starts_with("FE-RGC-702"));
    }
}

// ---------- sample_workload ----------

#[test]
fn sample_workload_has_correct_id() {
    let workload = sample_workload();
    assert_eq!(workload.workload_id, "router_hot_path");
}

#[test]
fn sample_workload_serde_roundtrip() {
    let workload = sample_workload();
    let json = serde_json::to_string(&workload).expect("serialize");
    let recovered: WorkloadSamples = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.workload_id, workload.workload_id);
}

// ---------- StatisticalValidationPolicy ----------

#[test]
fn statistical_validation_policy_default_has_thresholds() {
    let policy = StatisticalValidationPolicy::default();
    assert!(policy.thresholds.fail_regression_millionths > 0);
    assert!(policy.thresholds.max_p_value_millionths > 0);
}

#[test]
fn statistical_validation_policy_serde_roundtrip() {
    let policy = StatisticalValidationPolicy::default();
    let json = serde_json::to_string(&policy).expect("serialize");
    let recovered: StatisticalValidationPolicy = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(
        recovered.thresholds.fail_regression_millionths,
        policy.thresholds.fail_regression_millionths
    );
}

// ---------- evaluate_statistical_validation ----------

#[test]
fn pipeline_with_no_regression_allows_promotion() {
    let mut policy = StatisticalValidationPolicy {
        warmup_drop_samples: 0,
        min_samples_after_filter: 5,
        ..StatisticalValidationPolicy::default()
    };
    policy.outlier_policy.min_retained_samples = 5;

    let input = StatisticalValidationInput::new(
        "trace-rgc-702-pass",
        "decision-rgc-702-pass",
        "policy-rgc-statistical-validation-pipeline-v1",
        vec![WorkloadSamples::new(
            "stable_path",
            "golden",
            "sha256:stable",
            vec![1000, 1001, 999, 1000, 1002, 998, 1000, 1001, 999],
            vec![1000, 1001, 999, 1000, 1002, 998, 1000, 1001, 999],
        )],
    );

    let report = evaluate_statistical_validation(&input, &policy);
    assert!(report.promote_allowed);
    assert!(report.failed_workloads.is_empty());
}

#[test]
fn pipeline_evaluation_is_deterministic() {
    let mut policy = StatisticalValidationPolicy {
        warmup_drop_samples: 0,
        min_samples_after_filter: 5,
        ..StatisticalValidationPolicy::default()
    };
    policy.outlier_policy.min_retained_samples = 5;

    let input = StatisticalValidationInput::new(
        "trace-det",
        "decision-det",
        "policy-det",
        vec![sample_workload()],
    );

    let left = evaluate_statistical_validation(&input, &policy);
    let right = evaluate_statistical_validation(&input, &policy);
    assert_eq!(
        serde_json::to_string(&left).unwrap(),
        serde_json::to_string(&right).unwrap()
    );
}

// ---------- operator verification ----------

#[test]
fn operator_verification_includes_ci_command() {
    let contract = parse_contract();
    assert!(
        contract
            .operator_verification
            .iter()
            .any(|entry| entry.contains("run_rgc_statistical_validation_pipeline.sh ci")),
    );
}

// ---------- required artifacts ----------

#[test]
fn required_artifacts_includes_manifest() {
    let contract = parse_contract();
    assert!(
        contract
            .required_artifacts
            .iter()
            .any(|a| a.contains("run_manifest")),
    );
}

#[test]
fn contract_has_nonempty_bead_id() {
    let contract = parse_contract();
    assert!(!contract.bead_id.trim().is_empty());
}

#[test]
fn contract_deterministic_double_parse() {
    let a = parse_contract();
    let b = parse_contract();
    assert_eq!(a.schema_version, b.schema_version);
}

#[test]
fn statistical_validation_policy_default_is_constructible() {
    let policy = StatisticalValidationPolicy::default();
    assert!(policy.min_samples_after_filter > 0 || policy.warmup_drop_samples == 0);
}

#[test]
fn contract_required_log_keys_include_trace_and_decision() {
    let contract = parse_contract();
    assert!(contract.required_log_keys.contains(&"trace_id".to_string()));
    assert!(
        contract
            .required_log_keys
            .contains(&"decision_id".to_string())
    );
}

#[test]
fn contract_policy_id_is_nonempty() {
    let contract = parse_contract();
    assert!(!contract.policy_id.trim().is_empty());
}

#[test]
fn contract_version_is_1_0_0() {
    let contract = parse_contract();
    assert_eq!(contract.contract_version, "1.0.0");
}

#[test]
fn sample_workload_has_both_baseline_and_candidate_samples() {
    let workload = sample_workload();
    assert!(!workload.baseline_samples_ns.is_empty());
    assert!(!workload.candidate_samples_ns.is_empty());
}

#[test]
fn pipeline_report_logs_are_nonempty_for_regression() {
    let mut policy = StatisticalValidationPolicy {
        warmup_drop_samples: 0,
        min_samples_after_filter: 5,
        ..StatisticalValidationPolicy::default()
    };
    policy.outlier_policy.min_retained_samples = 5;

    let input = StatisticalValidationInput::new(
        "trace-log-check",
        "decision-log-check",
        "policy-log-check",
        vec![sample_workload()],
    );

    let report = evaluate_statistical_validation(&input, &policy);
    assert!(
        !report.logs.is_empty(),
        "pipeline should emit at least one log event"
    );
}

#[test]
fn contract_thresholds_max_cv_is_positive() {
    let contract = parse_contract();
    assert!(contract.thresholds.max_cv_millionths > 0);
}

#[test]
fn contract_thresholds_min_effect_size_is_positive() {
    let contract = parse_contract();
    assert!(
        contract.thresholds.min_effect_size_millionths > 0,
        "min effect size threshold must be positive"
    );
}
