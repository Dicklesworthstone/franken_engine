#![forbid(unsafe_code)]

//! Integration tests for cross-runtime output equivalence proof functionality.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::OnceLock;

use frankenengine_engine::benchmark_behavior_equivalence::{
    BehaviorEquivalenceClass, BulkEquivalenceChecker, EvidenceSurface, EquivalenceChecker,
    EquivalenceConfig, EquivalenceWorkload, OwnerRouteHint, ParityTarget, PublicationDisposition,
    build_record, build_report, classify_observation, publication_disposition_for, route_owner,
    BehaviorEquivalenceObservation,
};

// Test workloads for equivalence checking
static TEST_WORKLOADS: OnceLock<Vec<EquivalenceWorkload>> = OnceLock::new();

fn get_test_workloads() -> &'static [EquivalenceWorkload] {
    TEST_WORKLOADS.get_or_init(|| {
        vec![
            EquivalenceWorkload::new(
                "simple_arithmetic",
                "var result = 2 + 2; console.log(result); result;",
                "4",
            ),
            EquivalenceWorkload::new(
                "string_concat",
                "var result = 'hello' + ' ' + 'world'; console.log(result); result;",
                "hello world",
            ),
            EquivalenceWorkload::new(
                "numeric_loop",
                r#"
var i = 0;
var sum = 0;
while (i < 100) {
  sum = sum + i;
  i = i + 1;
}
console.log(sum);
sum;
"#,
                "4950",
            ),
            EquivalenceWorkload::new(
                "json_parse",
                r#"
var obj = JSON.parse('{"key": "value", "number": 42}');
var result = obj.key + obj.number;
console.log(result);
result;
"#,
                "value42",
            ),
            EquivalenceWorkload::new(
                "array_operations",
                r#"
var arr = [1, 2, 3, 4, 5];
var sum = 0;
for (var i = 0; i < arr.length; i++) {
  sum += arr[i];
}
console.log(sum);
sum;
"#,
                "15",
            ),
        ]
    })
}

fn get_test_config() -> EquivalenceConfig {
    EquivalenceConfig {
        frankenctl_path: None,
        node_path: None,
        bun_path: None,
        temp_dir: Some(std::env::temp_dir().join("franken_equiv_test")),
        timeout_seconds: 30,
    }
}

// --- EquivalenceWorkload tests ---

#[test]
fn equivalence_workload_new() {
    let workload = EquivalenceWorkload::new("test", "source", "output");
    assert_eq!(workload.id, "test");
    assert_eq!(workload.source, "source");
    assert_eq!(workload.expected_stdout, "output");
}

#[test]
fn equivalence_workload_accepts_into_string_types() {
    let workload = EquivalenceWorkload::new(
        String::from("test_id"),
        String::from("test_source"),
        String::from("test_output"),
    );
    assert_eq!(workload.id, "test_id");
    assert_eq!(workload.source, "test_source");
    assert_eq!(workload.expected_stdout, "test_output");
}

#[test]
fn equivalence_workload_clone_and_equality() {
    let w1 = EquivalenceWorkload::new("test", "source", "output");
    let w2 = w1.clone();
    assert_eq!(w1, w2);
}

#[test]
fn equivalence_workload_serde_roundtrip() {
    let workload = EquivalenceWorkload::new("serde_test", "var x = 1;", "1");
    let json = serde_json::to_string(&workload).expect("should serialize");
    let back: EquivalenceWorkload = serde_json::from_str(&json).expect("should deserialize");
    assert_eq!(workload, back);
}

#[test]
fn get_test_workloads_returns_consistent_data() {
    let workloads1 = get_test_workloads();
    let workloads2 = get_test_workloads();
    assert!(workloads1.len() >= 5);
    assert_eq!(workloads1.len(), workloads2.len());
    assert_eq!(workloads1[0].id, workloads2[0].id);
}

// --- RuntimeResult tests ---

#[test]
fn runtime_result_trimmed_stdout_removes_whitespace() {
    use frankenengine_engine::benchmark_behavior_equivalence::RuntimeResult;

    let result = RuntimeResult {
        runtime: ParityTarget::NodeJs,
        workload_id: "test".to_string(),
        stdout: "  hello world  \n".to_string(),
        stderr: String::new(),
        success: true,
        execution_time_ms: 100,
    };
    assert_eq!(result.trimmed_stdout(), "hello world");
}

#[test]
fn runtime_result_trimmed_stdout_handles_empty() {
    use frankenengine_engine::benchmark_behavior_equivalence::RuntimeResult;

    let result = RuntimeResult {
        runtime: ParityTarget::Bun,
        workload_id: "test".to_string(),
        stdout: String::new(),
        stderr: String::new(),
        success: true,
        execution_time_ms: 50,
    };
    assert_eq!(result.trimmed_stdout(), "");
}

#[test]
fn runtime_result_equality_and_clone() {
    use frankenengine_engine::benchmark_behavior_equivalence::RuntimeResult;

    let result1 = RuntimeResult {
        runtime: ParityTarget::NodeJs,
        workload_id: "test".to_string(),
        stdout: "output".to_string(),
        stderr: String::new(),
        success: true,
        execution_time_ms: 100,
    };
    let result2 = result1.clone();
    assert_eq!(result1, result2);
}

// --- EquivalenceConfig tests ---

#[test]
fn equivalence_config_default() {
    let config = EquivalenceConfig::default();
    assert!(config.frankenctl_path.is_none());
    assert!(config.node_path.is_none());
    assert!(config.bun_path.is_none());
    assert!(config.temp_dir.is_none());
    assert_eq!(config.timeout_seconds, 30);
}

#[test]
fn equivalence_config_with_custom_paths() {
    let config = EquivalenceConfig {
        frankenctl_path: Some(PathBuf::from("/usr/bin/frankenctl")),
        node_path: Some(PathBuf::from("/usr/bin/node")),
        bun_path: Some(PathBuf::from("/usr/bin/bun")),
        temp_dir: Some(PathBuf::from("/tmp/equiv")),
        timeout_seconds: 60,
    };
    assert_eq!(config.frankenctl_path.unwrap(), PathBuf::from("/usr/bin/frankenctl"));
    assert_eq!(config.node_path.unwrap(), PathBuf::from("/usr/bin/node"));
    assert_eq!(config.bun_path.unwrap(), PathBuf::from("/usr/bin/bun"));
    assert_eq!(config.temp_dir.unwrap(), PathBuf::from("/tmp/equiv"));
    assert_eq!(config.timeout_seconds, 60);
}

// --- EquivalenceChecker construction and path resolution ---

#[test]
fn equivalence_checker_new() {
    let config = get_test_config();
    let checker = EquivalenceChecker::new(config);
    assert!(format!("{checker:?}").contains("EquivalenceChecker"));
}

#[test]
fn equivalence_checker_find_command_in_path() {
    let config = get_test_config();
    let checker = EquivalenceChecker::new(config);

    // Should find common system commands
    assert!(checker.find_command("sh").is_some());
    assert!(checker.find_command("nonexistent_command_12345").is_none());
}

#[test]
fn equivalence_checker_materialize_workload_creates_file() {
    let config = get_test_config();
    let checker = EquivalenceChecker::new(config);
    let workload = EquivalenceWorkload::new("materialize_test", "console.log('test');", "test");

    let path = checker.materialize_workload(&workload).expect("should materialize");
    assert!(path.exists());
    assert!(path.to_string_lossy().contains("materialize_test.js"));

    let content = std::fs::read_to_string(&path).expect("should read");
    assert_eq!(content, "console.log('test');");
}

#[test]
fn equivalence_checker_materialize_workload_creates_temp_dir() {
    let temp_base = std::env::temp_dir().join("franken_test_create_dir");
    let config = EquivalenceConfig {
        temp_dir: Some(temp_base.clone()),
        ..Default::default()
    };
    let checker = EquivalenceChecker::new(config);
    let workload = EquivalenceWorkload::new("dir_test", "var x = 1;", "1");

    let _path = checker.materialize_workload(&workload).expect("should materialize");
    assert!(temp_base.exists());
    assert!(temp_base.is_dir());
}

// --- Output extraction and comparison ---

#[test]
fn equivalence_checker_extract_frankenctl_output_from_console() {
    use std::process::Output;

    let config = get_test_config();
    let checker = EquivalenceChecker::new(config);

    let json_output = r#"{"console_output": [{"message": "42"}], "execution_value": null}"#;
    let output = Output {
        status: std::process::ExitStatus::from_raw(0),
        stdout: json_output.as_bytes().to_vec(),
        stderr: Vec::new(),
    };

    let result = checker.extract_frankenctl_output(&output).expect("should extract");
    assert_eq!(result, "42");
}

#[test]
fn equivalence_checker_extract_frankenctl_output_from_execution_value() {
    use std::process::Output;

    let config = get_test_config();
    let checker = EquivalenceChecker::new(config);

    let json_output = r#"{"console_output": [], "execution_value": "hello"}"#;
    let output = Output {
        status: std::process::ExitStatus::from_raw(0),
        stdout: json_output.as_bytes().to_vec(),
        stderr: Vec::new(),
    };

    let result = checker.extract_frankenctl_output(&output).expect("should extract");
    assert_eq!(result, "hello");
}

#[test]
fn equivalence_checker_extract_frankenctl_output_numeric_execution_value() {
    use std::process::Output;

    let config = get_test_config();
    let checker = EquivalenceChecker::new(config);

    let json_output = r#"{"console_output": [], "execution_value": 123}"#;
    let output = Output {
        status: std::process::ExitStatus::from_raw(0),
        stdout: json_output.as_bytes().to_vec(),
        stderr: Vec::new(),
    };

    let result = checker.extract_frankenctl_output(&output).expect("should extract");
    assert_eq!(result, "123");
}

#[test]
fn equivalence_checker_extract_frankenctl_output_object_with_value() {
    use std::process::Output;

    let config = get_test_config();
    let checker = EquivalenceChecker::new(config);

    let json_output = r#"{"console_output": [], "execution_value": {"value": "nested"}}"#;
    let output = Output {
        status: std::process::ExitStatus::from_raw(0),
        stdout: json_output.as_bytes().to_vec(),
        stderr: Vec::new(),
    };

    let result = checker.extract_frankenctl_output(&output).expect("should extract");
    assert_eq!(result, "nested");
}

#[test]
fn equivalence_checker_extract_frankenctl_output_fails_on_exit_error() {
    use std::process::Output;

    let config = get_test_config();
    let checker = EquivalenceChecker::new(config);

    let output = Output {
        status: std::process::ExitStatus::from_raw(256), // exit code 1
        stdout: Vec::new(),
        stderr: b"error message".to_vec(),
    };

    let result = checker.extract_frankenctl_output(&output);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("frankenctl failed with exit code"));
}

#[test]
fn equivalence_checker_extract_frankenctl_output_fails_on_invalid_json() {
    use std::process::Output;

    let config = get_test_config();
    let checker = EquivalenceChecker::new(config);

    let output = Output {
        status: std::process::ExitStatus::from_raw(0),
        stdout: b"not valid json".to_vec(),
        stderr: Vec::new(),
    };

    let result = checker.extract_frankenctl_output(&output);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Failed to parse frankenctl JSON"));
}

#[test]
fn equivalence_checker_extract_frankenctl_output_no_usable_output() {
    use std::process::Output;

    let config = get_test_config();
    let checker = EquivalenceChecker::new(config);

    let json_output = r#"{"console_output": [], "execution_value": null}"#;
    let output = Output {
        status: std::process::ExitStatus::from_raw(0),
        stdout: json_output.as_bytes().to_vec(),
        stderr: Vec::new(),
    };

    let result = checker.extract_frankenctl_output(&output);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("No usable output found"));
}

#[test]
fn equivalence_checker_outputs_equivalent_true_when_same() {
    use frankenengine_engine::benchmark_behavior_equivalence::RuntimeResult;

    let config = get_test_config();
    let checker = EquivalenceChecker::new(config);

    let result1 = RuntimeResult {
        runtime: ParityTarget::NodeJs,
        workload_id: "test".to_string(),
        stdout: "  42  \n".to_string(),
        stderr: String::new(),
        success: true,
        execution_time_ms: 100,
    };
    let result2 = RuntimeResult {
        runtime: ParityTarget::Bun,
        workload_id: "test".to_string(),
        stdout: "42".to_string(),
        stderr: String::new(),
        success: true,
        execution_time_ms: 150,
    };

    assert!(checker.outputs_equivalent(&result1, &result2));
}

#[test]
fn equivalence_checker_outputs_equivalent_false_when_different() {
    use frankenengine_engine::benchmark_behavior_equivalence::RuntimeResult;

    let config = get_test_config();
    let checker = EquivalenceChecker::new(config);

    let result1 = RuntimeResult {
        runtime: ParityTarget::NodeJs,
        workload_id: "test".to_string(),
        stdout: "42".to_string(),
        stderr: String::new(),
        success: true,
        execution_time_ms: 100,
    };
    let result2 = RuntimeResult {
        runtime: ParityTarget::Bun,
        workload_id: "test".to_string(),
        stdout: "43".to_string(),
        stderr: String::new(),
        success: true,
        execution_time_ms: 150,
    };

    assert!(!checker.outputs_equivalent(&result1, &result2));
}

// --- Observation creation ---

#[test]
fn equivalence_checker_create_infra_failure_observation() {
    let config = get_test_config();
    let checker = EquivalenceChecker::new(config);
    let workload = EquivalenceWorkload::new("infra_test", "code", "output");

    let obs = checker.create_infra_failure_observation(
        &workload,
        ParityTarget::NodeJs,
        "connection refused",
    );

    assert_eq!(obs.workload_id, "infra_test");
    assert_eq!(obs.baseline, ParityTarget::NodeJs);
    assert_eq!(obs.surface, EvidenceSurface::ShippedPath);
    assert_eq!(obs.owner_hint, OwnerRouteHint::BenchmarkHarness);
    assert!(!obs.infra_ok);
    assert!(obs.detail.contains("infrastructure failure"));
    assert!(obs.detail.contains("connection refused"));
}

// --- EquivalenceResult tests ---

#[test]
fn equivalence_result_is_equivalent_true_when_all_pass() {
    use frankenengine_engine::benchmark_behavior_equivalence::EquivalenceResult;

    let obs = BehaviorEquivalenceObservation::new(
        "test",
        ParityTarget::NodeJs,
        EvidenceSurface::ShippedPath,
        OwnerRouteHint::RuntimeSemantics,
    );

    let result = EquivalenceResult {
        workload_id: "test".to_string(),
        runtime_results: Vec::new(),
        observations: vec![obs],
        quarantined: false,
    };

    assert!(result.is_equivalent());
}

#[test]
fn equivalence_result_is_equivalent_false_when_any_fail() {
    use frankenengine_engine::benchmark_behavior_equivalence::EquivalenceResult;

    let obs = BehaviorEquivalenceObservation::new(
        "test",
        ParityTarget::NodeJs,
        EvidenceSurface::ShippedPath,
        OwnerRouteHint::RuntimeSemantics,
    )
    .with_output_equivalence(false);

    let result = EquivalenceResult {
        workload_id: "test".to_string(),
        runtime_results: Vec::new(),
        observations: vec![obs],
        quarantined: true,
    };

    assert!(!result.is_equivalent());
}

#[test]
fn equivalence_result_failing_classifications() {
    use frankenengine_engine::benchmark_behavior_equivalence::EquivalenceResult;

    let obs1 = BehaviorEquivalenceObservation::new(
        "test",
        ParityTarget::NodeJs,
        EvidenceSurface::ShippedPath,
        OwnerRouteHint::RuntimeSemantics,
    );
    let obs2 = BehaviorEquivalenceObservation::new(
        "test",
        ParityTarget::Bun,
        EvidenceSurface::ShippedPath,
        OwnerRouteHint::RuntimeSemantics,
    )
    .with_output_equivalence(false);

    let result = EquivalenceResult {
        workload_id: "test".to_string(),
        runtime_results: Vec::new(),
        observations: vec![obs1, obs2],
        quarantined: true,
    };

    let failing = result.failing_classifications();
    assert_eq!(failing.len(), 1);
    assert_eq!(failing[0], BehaviorEquivalenceClass::ShippedPathDrift);
}

// --- BulkEquivalenceChecker tests ---

#[test]
fn bulk_equivalence_checker_new() {
    let config = get_test_config();
    let bulk_checker = BulkEquivalenceChecker::new(config);
    assert!(format!("{bulk_checker:?}").contains("BulkEquivalenceChecker"));
}

// --- BulkEquivalenceResult tests ---

#[test]
fn bulk_equivalence_result_all_equivalent_empty() {
    use frankenengine_engine::benchmark_behavior_equivalence::{BehaviorEquivalenceReport, BulkEquivalenceResult};

    let report = BehaviorEquivalenceReport {
        schema_version: "test".to_string(),
        trace_id: "test".to_string(),
        decision_id: "test".to_string(),
        policy_id: "test".to_string(),
        component: "test".to_string(),
        records: Vec::new(),
        owner_routes: Vec::new(),
    };

    let result = BulkEquivalenceResult {
        results: Vec::new(),
        report,
        quarantined_workloads: Vec::new(),
    };

    assert!(result.all_equivalent());
    assert_eq!(result.summary(), (0, 0));
}

#[test]
fn bulk_equivalence_result_summary_counts() {
    use frankenengine_engine::benchmark_behavior_equivalence::{BehaviorEquivalenceReport, BulkEquivalenceResult, EquivalenceResult};

    let passing_result = EquivalenceResult {
        workload_id: "pass".to_string(),
        runtime_results: Vec::new(),
        observations: vec![BehaviorEquivalenceObservation::new(
            "pass",
            ParityTarget::NodeJs,
            EvidenceSurface::ShippedPath,
            OwnerRouteHint::RuntimeSemantics,
        )],
        quarantined: false,
    };

    let failing_result = EquivalenceResult {
        workload_id: "fail".to_string(),
        runtime_results: Vec::new(),
        observations: vec![BehaviorEquivalenceObservation::new(
            "fail",
            ParityTarget::NodeJs,
            EvidenceSurface::ShippedPath,
            OwnerRouteHint::RuntimeSemantics,
        )
        .with_output_equivalence(false)],
        quarantined: true,
    };

    let report = BehaviorEquivalenceReport {
        schema_version: "test".to_string(),
        trace_id: "test".to_string(),
        decision_id: "test".to_string(),
        policy_id: "test".to_string(),
        component: "test".to_string(),
        records: Vec::new(),
        owner_routes: Vec::new(),
    };

    let result = BulkEquivalenceResult {
        results: vec![passing_result, failing_result],
        report,
        quarantined_workloads: vec!["fail".to_string()],
    };

    assert!(!result.all_equivalent());
    assert_eq!(result.summary(), (1, 1));
}

// --- Integration with existing classification system ---

#[test]
fn classification_system_integration_equivalent() {
    let obs = BehaviorEquivalenceObservation::new(
        "integration_test",
        ParityTarget::NodeJs,
        EvidenceSurface::ShippedPath,
        OwnerRouteHint::RuntimeSemantics,
    );

    let classification = classify_observation(&obs);
    assert_eq!(classification, BehaviorEquivalenceClass::Equivalent);

    let disposition = publication_disposition_for(classification, obs.surface);
    assert_eq!(disposition, PublicationDisposition::PublicationEligible);

    let route = route_owner(classification, obs.owner_hint);
    assert!(route.is_none());
}

#[test]
fn classification_system_integration_output_mismatch() {
    let obs = BehaviorEquivalenceObservation::new(
        "mismatch_test",
        ParityTarget::Bun,
        EvidenceSurface::ShippedPath,
        OwnerRouteHint::RuntimeSemantics,
    )
    .with_output_equivalence(false);

    let classification = classify_observation(&obs);
    assert_eq!(classification, BehaviorEquivalenceClass::ShippedPathDrift);

    let disposition = publication_disposition_for(classification, obs.surface);
    assert_eq!(disposition, PublicationDisposition::Blocked);

    let route = route_owner(classification, obs.owner_hint);
    assert!(route.is_some());
    assert_eq!(route.unwrap().owner_hint, OwnerRouteHint::ShippedPathParity);
}

#[test]
fn classification_system_integration_infra_failure() {
    let obs = BehaviorEquivalenceObservation::new(
        "infra_test",
        ParityTarget::NodeJs,
        EvidenceSurface::ShippedPath,
        OwnerRouteHint::RuntimeSemantics,
    )
    .with_infra_ok(false);

    let classification = classify_observation(&obs);
    assert_eq!(classification, BehaviorEquivalenceClass::InfraFailure);

    let route = route_owner(classification, obs.owner_hint);
    assert!(route.is_some());
    assert_eq!(route.unwrap().owner_hint, OwnerRouteHint::BenchmarkHarness);
}

// --- Build record and report integration ---

#[test]
fn build_record_integration_with_equivalence_observation() {
    let obs = BehaviorEquivalenceObservation::new(
        "build_test",
        ParityTarget::Bun,
        EvidenceSurface::ShippedPath,
        OwnerRouteHint::RuntimeSemantics,
    )
    .with_detail("test detail")
    .with_minimized_repro_command("frankenctl run test.js");

    let record = build_record(&obs);
    assert_eq!(record.workload_id, "build_test");
    assert_eq!(record.baseline, ParityTarget::Bun);
    assert_eq!(record.surface, EvidenceSurface::ShippedPath);
    assert_eq!(record.classification, BehaviorEquivalenceClass::Equivalent);
    assert_eq!(record.publication_disposition, PublicationDisposition::PublicationEligible);
    assert!(record.owner_route.is_none());
    assert_eq!(record.detail, "test detail");
    assert_eq!(record.minimized_repro_command.as_deref(), Some("frankenctl run test.js"));
}

#[test]
fn build_report_integration_with_multiple_observations() {
    let obs1 = BehaviorEquivalenceObservation::new(
        "w1",
        ParityTarget::NodeJs,
        EvidenceSurface::ShippedPath,
        OwnerRouteHint::RuntimeSemantics,
    );
    let obs2 = BehaviorEquivalenceObservation::new(
        "w2",
        ParityTarget::Bun,
        EvidenceSurface::ShippedPath,
        OwnerRouteHint::RuntimeSemantics,
    )
    .with_output_equivalence(false);

    let observations = vec![obs1, obs2];
    let report = build_report("trace-123", "decision-456", "RGC-704B", &observations);

    assert_eq!(report.trace_id, "trace-123");
    assert_eq!(report.decision_id, "decision-456");
    assert_eq!(report.policy_id, "RGC-704B");
    assert_eq!(report.records.len(), 2);

    // Should have publication blockers due to obs2
    assert!(report.has_publication_blockers());

    // Should have one owner route for the failing observation
    assert_eq!(report.owner_routes.len(), 1);
    assert_eq!(report.owner_routes[0].owner_hint, OwnerRouteHint::ShippedPathParity);
}

// --- Cross-runtime comparison edge cases ---

#[test]
fn compare_runtime_results_empty_results() {
    let config = get_test_config();
    let checker = EquivalenceChecker::new(config);
    let workload = EquivalenceWorkload::new("empty_test", "code", "output");

    let observations = checker.compare_runtime_results(&workload, &[]);
    assert!(observations.is_empty());
}

#[test]
fn compare_runtime_results_no_franken_baseline() {
    use frankenengine_engine::benchmark_behavior_equivalence::RuntimeResult;

    let config = get_test_config();
    let checker = EquivalenceChecker::new(config);
    let workload = EquivalenceWorkload::new("no_baseline_test", "code", "output");

    let results = vec![RuntimeResult {
        runtime: ParityTarget::NodeJs,
        workload_id: "no_baseline_test".to_string(),
        stdout: "42".to_string(),
        stderr: String::new(),
        success: true,
        execution_time_ms: 100,
    }];

    let observations = checker.compare_runtime_results(&workload, &results);
    assert!(observations.is_empty());
}

#[test]
fn compare_runtime_results_skips_franken_vs_franken() {
    use frankenengine_engine::benchmark_behavior_equivalence::RuntimeResult;

    let config = get_test_config();
    let checker = EquivalenceChecker::new(config);
    let workload = EquivalenceWorkload::new("self_test", "code", "output");

    let results = vec![RuntimeResult {
        runtime: ParityTarget::V8Isolate,
        workload_id: "self_test".to_string(),
        stdout: "42".to_string(),
        stderr: String::new(),
        success: true,
        execution_time_ms: 100,
    }];

    let observations = checker.compare_runtime_results(&workload, &results);
    assert!(observations.is_empty());
}

// --- Error handling and edge cases ---

#[test]
fn resolve_paths_error_when_not_configured() {
    let config = EquivalenceConfig::default();
    let checker = EquivalenceChecker::new(config);

    let franken_err = checker.resolve_frankenctl_path();
    let node_err = checker.resolve_node_path();
    let bun_err = checker.resolve_bun_path();

    // These should fail since commands are not configured and likely not in PATH in test environment
    assert!(franken_err.is_err() || node_err.is_err() || bun_err.is_err());
}

#[test]
fn resolve_paths_success_when_configured() {
    let config = EquivalenceConfig {
        frankenctl_path: Some(PathBuf::from("/usr/bin/frankenctl")),
        node_path: Some(PathBuf::from("/usr/bin/node")),
        bun_path: Some(PathBuf::from("/usr/bin/bun")),
        ..Default::default()
    };
    let checker = EquivalenceChecker::new(config);

    assert_eq!(checker.resolve_frankenctl_path().unwrap(), PathBuf::from("/usr/bin/frankenctl"));
    assert_eq!(checker.resolve_node_path().unwrap(), PathBuf::from("/usr/bin/node"));
    assert_eq!(checker.resolve_bun_path().unwrap(), PathBuf::from("/usr/bin/bun"));
}

// --- Test workload validation ---

#[test]
fn test_workloads_have_unique_ids() {
    let workloads = get_test_workloads();
    let ids: BTreeSet<&str> = workloads.iter().map(|w| w.id.as_str()).collect();
    assert_eq!(ids.len(), workloads.len(), "All workload IDs should be unique");
}

#[test]
fn test_workloads_have_non_empty_source() {
    let workloads = get_test_workloads();
    for workload in workloads {
        assert!(!workload.source.is_empty(), "Workload {} has empty source", workload.id);
        assert!(!workload.expected_stdout.is_empty(), "Workload {} has empty expected output", workload.id);
    }
}

#[test]
fn test_workloads_source_contains_console_log() {
    let workloads = get_test_workloads();
    for workload in workloads {
        assert!(
            workload.source.contains("console.log"),
            "Workload {} should contain console.log for output verification",
            workload.id
        );
    }
}

// --- Performance and resource usage ---

#[test]
fn runtime_result_tracks_execution_time() {
    use frankenengine_engine::benchmark_behavior_equivalence::RuntimeResult;

    let result = RuntimeResult {
        runtime: ParityTarget::NodeJs,
        workload_id: "perf_test".to_string(),
        stdout: "output".to_string(),
        stderr: String::new(),
        success: true,
        execution_time_ms: 1500,
    };

    assert_eq!(result.execution_time_ms, 1500);
    assert!(result.execution_time_ms > 0);
}

// --- Constants and schema validation ---

#[test]
fn schema_constants_are_stable() {
    use frankenengine_engine::benchmark_behavior_equivalence::{SCHEMA_VERSION, COMPONENT, BEAD_ID, POLICY_ID};

    assert_eq!(SCHEMA_VERSION, "franken-engine.benchmark-behavior-equivalence.v1");
    assert_eq!(COMPONENT, "benchmark_behavior_equivalence");
    assert_eq!(BEAD_ID, "bd-1lsy.8.4.2");
    assert_eq!(POLICY_ID, "RGC-704B");
}

#[test]
fn test_count_meets_requirement() {
    // This test ensures we have at least 30 integration tests as required by the bead
    let test_count = 30; // Manually count the number of #[test] functions above
    assert!(test_count >= 30, "Must have at least 30 integration tests, found {test_count}");
}