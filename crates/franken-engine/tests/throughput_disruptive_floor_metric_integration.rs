#![forbid(unsafe_code)]

//! Integration test verifying throughput disruptive-floor metric gate
//! integrates correctly with the parent disruptive_floor_metric_gate.

use std::fs;
use std::path::PathBuf;

use frankenengine_engine::disruptive_floor_metric_gate::{
    BEAD_ID as PARENT_BEAD_ID, DisruptiveMetricId, MetricArtifact,
};
use frankenengine_engine::throughput_disruptive_floor_metric_gate::{
    BEAD_ID, RuntimeDenominator, SCHEMA_VERSION, ThroughputEvidence, ThroughputMetricInput,
    create_throughput_metric_artifact, evaluate_throughput_metric,
};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn fixture_path() -> PathBuf {
    repo_root().join("tests/fixtures/throughput_disruptive_floor_metric_input_v1.json")
}

fn load_fixture_input() -> ThroughputMetricInput {
    let content =
        fs::read_to_string(fixture_path()).expect("Failed to read throughput metric fixture");
    serde_json::from_str(&content).expect("Failed to parse throughput metric fixture")
}

#[test]
fn test_fixture_loads_and_validates() {
    let input = load_fixture_input();

    assert_eq!(input.schema_version, SCHEMA_VERSION);
    assert_eq!(input.bead_id, BEAD_ID);
    assert_eq!(input.scenario_set, "throughput_node_bun_baseline");
    assert_eq!(input.floor_ratio_millionths, 950_000);
    assert_eq!(input.max_freshness_days, 14);
    assert_eq!(input.evidence.len(), 6);

    // Verify we have both Node and Bun evidence
    let node_count = input
        .evidence
        .iter()
        .filter(|e| e.runtime_denominator == RuntimeDenominator::Node)
        .count();
    let bun_count = input
        .evidence
        .iter()
        .filter(|e| e.runtime_denominator == RuntimeDenominator::Bun)
        .count();

    assert_eq!(node_count, 3);
    assert_eq!(bun_count, 3);
}

#[test]
fn test_throughput_metric_evaluation() {
    let input = load_fixture_input();
    let report = evaluate_throughput_metric(&input).expect("Failed to evaluate throughput metric");

    // Basic validation
    assert_eq!(report.schema_version, SCHEMA_VERSION);
    assert_eq!(report.bead_id, BEAD_ID);
    assert_eq!(report.evidence_count, 6);
    assert_eq!(report.node_evidence_count, 3);
    assert_eq!(report.bun_evidence_count, 3);

    // Should pass the floor threshold based on fixture data
    assert_eq!(report.overall_outcome, "pass");
    assert!(report.weighted_ratio_millionths >= input.floor_ratio_millionths);

    // Verify passing evidence count
    assert!(report.passing_evidence_count >= 4); // Most evidence should pass

    // Verify verification commands are collected
    assert!(!report.verification_commands.is_empty());
}

#[test]
fn test_create_metric_artifact_for_parent_integrator() {
    let input = load_fixture_input();
    let report = evaluate_throughput_metric(&input).expect("Failed to evaluate throughput metric");

    let artifact_path = "test_throughput_metric_report.json";
    let artifact_hash = "test_hash_123abc";

    let artifact = create_throughput_metric_artifact(&input, &report, artifact_path, artifact_hash);

    // Verify artifact matches parent integrator expectations
    assert_eq!(
        artifact.metric_id,
        DisruptiveMetricId::WeightedThroughputNodeBun
    );
    assert_eq!(artifact.threshold, input.floor_ratio_millionths);
    assert_eq!(artifact.observed_value, report.weighted_ratio_millionths);
    assert_eq!(artifact.unit, "ratio_millionths");
    assert_eq!(artifact.baseline, "node_bun_denominators");
    assert_eq!(artifact.candidate, "frankenengine");
    assert_eq!(artifact.denominator_id, "node_and_bun");
    assert_eq!(artifact.scenario_set, input.scenario_set);
    assert_eq!(artifact.artifact_path, artifact_path);
    assert_eq!(artifact.artifact_hash, artifact_hash);
    assert_eq!(artifact.code_revision, input.code_revision);
    assert_eq!(artifact.freshness_days, input.max_freshness_days);
    assert_eq!(artifact.confidence_millionths, 950_000);
    assert_eq!(artifact.coverage_millionths, 900_000);
    assert!(
        artifact
            .verification_command
            .contains("run_throughput_disruptive_floor_metric_gate.sh")
    );
    assert_eq!(artifact.redaction_status, "none");
}

#[test]
fn test_parent_integrator_recognizes_metric_id() {
    // Verify the parent integrator knows about our metric ID
    let metric_id = DisruptiveMetricId::WeightedThroughputNodeBun;
    assert_eq!(metric_id.as_str(), "weighted_throughput_node_bun");
    assert_eq!(metric_id.threshold(), 3); // Should have a reasonable threshold
}

#[test]
fn test_bead_hierarchy_relationship() {
    // Verify the bead relationship is correct
    assert_eq!(BEAD_ID, "bd-y6v8s"); // Child bead
    assert_eq!(PARENT_BEAD_ID, "bd-x7nod"); // Parent integrator bead
    assert_ne!(BEAD_ID, PARENT_BEAD_ID); // Should be different beads
}

#[test]
fn test_script_exists_and_executable() {
    let script_path = repo_root().join("scripts/run_throughput_disruptive_floor_metric_gate.sh");
    assert!(
        script_path.exists(),
        "Script not found: {}",
        script_path.display()
    );

    // Check if script is executable (on Unix systems)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = fs::metadata(&script_path).expect("Failed to get script metadata");
        let permissions = metadata.permissions();
        assert!(permissions.mode() & 0o111 != 0, "Script is not executable");
    }
}

#[test]
fn test_artifact_schema_compatibility() {
    let input = load_fixture_input();
    let report = evaluate_throughput_metric(&input).unwrap();
    let artifact = create_throughput_metric_artifact(&input, &report, "test.json", "hash123");

    // Verify the artifact can be serialized and deserialized
    let serialized = serde_json::to_string(&artifact).expect("Failed to serialize metric artifact");

    let deserialized: MetricArtifact =
        serde_json::from_str(&serialized).expect("Failed to deserialize metric artifact");

    assert_eq!(artifact, deserialized);
}

#[test]
fn test_edge_case_single_denominator() {
    // Test with only Node evidence
    let node_only_evidence = vec![ThroughputEvidence {
        scenario_id: "node_only_test".to_string(),
        runtime_denominator: RuntimeDenominator::Node,
        frankenengine_ops_per_second: 2600,
        denominator_ops_per_second: 2500,
        throughput_ratio_millionths: 1_040_000,
        benchmark_duration_ms: 10_000,
        request_count: 26_000,
        error_count: 0,
        success_rate_millionths: 1_000_000,
        scenario_path: "node_test.json".to_string(),
        output_path: "node_output.json".to_string(),
        output_hash: "node123".to_string(),
        verification_command: "verify_node.sh".to_string(),
    }];

    let input = ThroughputMetricInput {
        schema_version: SCHEMA_VERSION.to_string(),
        bead_id: BEAD_ID.to_string(),
        scenario_set: "node_only".to_string(),
        floor_ratio_millionths: 950_000,
        max_freshness_days: 14,
        evidence: node_only_evidence,
        code_revision: "test123".to_string(),
        generated_at_utc: "2026-05-01T00:00:00Z".to_string(),
    };

    let report = evaluate_throughput_metric(&input).unwrap();
    assert_eq!(report.overall_outcome, "pass");
    assert_eq!(report.node_evidence_count, 1);
    assert_eq!(report.bun_evidence_count, 0);
    assert_eq!(report.weighted_ratio_millionths, 1_040_000);
}

#[test]
fn test_failing_throughput_scenario() {
    // Create evidence that fails the floor threshold
    let failing_evidence = vec![ThroughputEvidence {
        scenario_id: "failing_test".to_string(),
        runtime_denominator: RuntimeDenominator::Node,
        frankenengine_ops_per_second: 2000, // Low performance
        denominator_ops_per_second: 2500,
        throughput_ratio_millionths: 800_000, // 0.8x ratio - below 0.95 floor
        benchmark_duration_ms: 10_000,
        request_count: 20_000,
        error_count: 100,
        success_rate_millionths: 995_000,
        scenario_path: "failing_test.json".to_string(),
        output_path: "failing_output.json".to_string(),
        output_hash: "fail123".to_string(),
        verification_command: "verify_fail.sh".to_string(),
    }];

    let input = ThroughputMetricInput {
        schema_version: SCHEMA_VERSION.to_string(),
        bead_id: BEAD_ID.to_string(),
        scenario_set: "failing_scenario".to_string(),
        floor_ratio_millionths: 950_000,
        max_freshness_days: 14,
        evidence: failing_evidence,
        code_revision: "test123".to_string(),
        generated_at_utc: "2026-05-01T00:00:00Z".to_string(),
    };

    let report = evaluate_throughput_metric(&input).unwrap();
    assert_eq!(report.overall_outcome, "fail");
    assert_eq!(report.passing_evidence_count, 0);
    assert!(report.weighted_ratio_millionths < 950_000);
}
