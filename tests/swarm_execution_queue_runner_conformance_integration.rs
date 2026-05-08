//! Conformance harness for swarm_execution_queue_runner mutation-free contract.
//!
//! Tests the documented invariants:
//! - Does not mutate live bead, reservation, Agent Mail, or worker state
//! - Runner artifacts use fixed schema versions and deterministic timestamp options
//! - Invalid normalized inputs fail closed
//! - Two runs with fixed epoch/timestamp match byte-for-byte after path normalization

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::swarm_execution_queue_runner::{
    run_normalized_input_file, ExecutionQueueRunOptions, ExecutionQueueRunnerError,
    SWARM_EXECUTION_BOTTLENECK_REPORT_SCHEMA_VERSION,
    SWARM_EXECUTION_QUEUE_ARTIFACT_SCHEMA_VERSION, SWARM_EXECUTION_QUEUE_INPUT_SCHEMA_VERSION,
    SWARM_EXECUTION_QUEUE_RUNNER_SCHEMA_VERSION,
    SWARM_EXECUTION_RISK_BUDGET_RECEIPT_SCHEMA_VERSION,
};

/// Contract test for swarm execution queue runner mutation-free guarantees
fn assert_swarm_execution_queue_runner_contract(
    normalized_input_json: &str,
    options: ExecutionQueueRunOptions,
    expect_success: bool,
) {
    let temp_dir = tempfile::tempdir().expect("Failed to create temp directory");
    let test_dir = temp_dir.path();

    // Create input file
    let input_path = test_dir.join("normalized_input.json");
    fs::write(&input_path, normalized_input_json).expect("Failed to write input file");

    // Create sentinel files outside output_dir to detect unauthorized mutations
    let sentinel_bead_file = test_dir.join("sentinel_bead.json");
    let sentinel_reservation_file = test_dir.join("sentinel_reservation.json");
    let sentinel_mail_file = test_dir.join("sentinel_agent_mail.json");
    let sentinel_worker_file = test_dir.join("sentinel_worker_state.json");

    let sentinel_content = r#"{"sentinel": "DO_NOT_MUTATE", "timestamp": 123456789}"#;
    fs::write(&sentinel_bead_file, sentinel_content).expect("Failed to write bead sentinel");
    fs::write(&sentinel_reservation_file, sentinel_content)
        .expect("Failed to write reservation sentinel");
    fs::write(&sentinel_mail_file, sentinel_content).expect("Failed to write mail sentinel");
    fs::write(&sentinel_worker_file, sentinel_content).expect("Failed to write worker sentinel");

    let original_bead_content =
        fs::read(&sentinel_bead_file).expect("Failed to read bead sentinel");
    let original_reservation_content =
        fs::read(&sentinel_reservation_file).expect("Failed to read reservation sentinel");
    let original_mail_content =
        fs::read(&sentinel_mail_file).expect("Failed to read mail sentinel");
    let original_worker_content =
        fs::read(&sentinel_worker_file).expect("Failed to read worker sentinel");

    // Create output directory
    let output_dir = test_dir.join("output");

    // Run the runner
    let result = run_normalized_input_file(&input_path, &output_dir, options.clone());

    if expect_success {
        let output = result.expect("Expected successful run");

        // Test 1: Mutation-free guarantee - sentinel files must remain unchanged
        let final_bead_content =
            fs::read(&sentinel_bead_file).expect("Failed to read bead sentinel");
        let final_reservation_content =
            fs::read(&sentinel_reservation_file).expect("Failed to read reservation sentinel");
        let final_mail_content =
            fs::read(&sentinel_mail_file).expect("Failed to read mail sentinel");
        let final_worker_content =
            fs::read(&sentinel_worker_file).expect("Failed to read worker sentinel");

        assert_eq!(
            original_bead_content, final_bead_content,
            "Runner mutated sentinel bead file - violates mutation-free contract"
        );
        assert_eq!(
            original_reservation_content, final_reservation_content,
            "Runner mutated sentinel reservation file - violates mutation-free contract"
        );
        assert_eq!(
            original_mail_content, final_mail_content,
            "Runner mutated sentinel mail file - violates mutation-free contract"
        );
        assert_eq!(
            original_worker_content, final_worker_content,
            "Runner mutated sentinel worker file - violates mutation-free contract"
        );

        // Test 2: Only expected artifact files should be created in output_dir
        let expected_files = BTreeSet::from([
            "events.jsonl",
            "commands.txt",
            "run_manifest.json",
            "execution_queue_artifact.json",
            "risk_budget_receipt.json",
            "bottleneck_report.json",
            "operator_summary.md",
        ]);

        let mut actual_files = BTreeSet::new();
        for entry in fs::read_dir(&output_dir).expect("Failed to read output directory") {
            let entry = entry.expect("Failed to read directory entry");
            if entry
                .file_type()
                .expect("Failed to get file type")
                .is_file()
            {
                actual_files.insert(entry.file_name().to_string_lossy().to_string());
            }
        }

        assert_eq!(
            expected_files, actual_files,
            "Runner created unexpected files or missed expected files"
        );

        // Test 3: Schema constants match all JSON outputs
        validate_schema_constants(&output_dir);

        // Test 4: Deterministic behavior - second run should match byte-for-byte
        let output_dir2 = test_dir.join("output2");
        let result2 = run_normalized_input_file(&input_path, &output_dir2, options)
            .expect("Second run should succeed");

        assert_eq!(
            output.exit_code(),
            result2.exit_code(),
            "Exit codes should match"
        );

        // Compare all artifact files byte-for-byte (excluding run_manifest.json which has timestamps)
        let deterministic_files = [
            "execution_queue_artifact.json",
            "risk_budget_receipt.json",
            "bottleneck_report.json",
        ];

        for file in deterministic_files {
            let content1 = fs::read(output_dir.join(file)).expect("Failed to read file from run 1");
            let content2 =
                fs::read(output_dir2.join(file)).expect("Failed to read file from run 2");
            assert_eq!(
                content1, content2,
                "File {} differs between runs - violates deterministic contract",
                file
            );
        }
    } else {
        // Test for expected failure cases
        match result {
            Err(err) => {
                // Test that invalid input fails closed with appropriate exit code
                let exit_code = err.exit_code();
                assert_ne!(
                    exit_code, 0,
                    "Invalid input should fail with non-zero exit code, got: {}",
                    exit_code
                );

                // Verify no output artifacts were created on failure
                assert!(
                    !output_dir.exists() || fs::read_dir(&output_dir).unwrap().count() == 0,
                    "Failed run should not create output artifacts"
                );
            }
            Ok(_) => panic!("Expected failure for invalid input, but run succeeded"),
        }

        // Even on failure, mutation-free guarantee must hold
        let final_bead_content =
            fs::read(&sentinel_bead_file).expect("Failed to read bead sentinel");
        let final_reservation_content =
            fs::read(&sentinel_reservation_file).expect("Failed to read reservation sentinel");
        let final_mail_content =
            fs::read(&sentinel_mail_file).expect("Failed to read mail sentinel");
        let final_worker_content =
            fs::read(&sentinel_worker_file).expect("Failed to read worker sentinel");

        assert_eq!(
            original_bead_content, final_bead_content,
            "Runner mutated sentinel bead file even on failure - violates mutation-free contract"
        );
        assert_eq!(
            original_reservation_content, final_reservation_content,
            "Runner mutated sentinel reservation file even on failure - violates mutation-free contract"
        );
        assert_eq!(
            original_mail_content, final_mail_content,
            "Runner mutated sentinel mail file even on failure - violates mutation-free contract"
        );
        assert_eq!(
            original_worker_content, final_worker_content,
            "Runner mutated sentinel worker file even on failure - violates mutation-free contract"
        );
    }
}

fn validate_schema_constants(output_dir: &std::path::Path) {
    // Validate execution_queue_artifact.json schema
    let artifact_content = fs::read_to_string(output_dir.join("execution_queue_artifact.json"))
        .expect("Failed to read execution queue artifact");
    let artifact: serde_json::Value = serde_json::from_str(&artifact_content)
        .expect("Failed to parse execution queue artifact JSON");

    assert_eq!(
        artifact["schema_version"], SWARM_EXECUTION_QUEUE_ARTIFACT_SCHEMA_VERSION,
        "Execution queue artifact schema version mismatch"
    );
    assert_eq!(
        artifact["runner_schema_version"], SWARM_EXECUTION_QUEUE_RUNNER_SCHEMA_VERSION,
        "Runner schema version mismatch in artifact"
    );

    // Validate risk_budget_receipt.json schema
    let risk_content = fs::read_to_string(output_dir.join("risk_budget_receipt.json"))
        .expect("Failed to read risk budget receipt");
    let risk: serde_json::Value =
        serde_json::from_str(&risk_content).expect("Failed to parse risk budget receipt JSON");

    assert_eq!(
        risk["schema_version"], SWARM_EXECUTION_RISK_BUDGET_RECEIPT_SCHEMA_VERSION,
        "Risk budget receipt schema version mismatch"
    );
    assert_eq!(
        risk["runner_schema_version"], SWARM_EXECUTION_QUEUE_RUNNER_SCHEMA_VERSION,
        "Runner schema version mismatch in risk budget"
    );

    // Validate bottleneck_report.json schema
    let bottleneck_content = fs::read_to_string(output_dir.join("bottleneck_report.json"))
        .expect("Failed to read bottleneck report");
    let bottleneck: serde_json::Value =
        serde_json::from_str(&bottleneck_content).expect("Failed to parse bottleneck report JSON");

    assert_eq!(
        bottleneck["schema_version"], SWARM_EXECUTION_BOTTLENECK_REPORT_SCHEMA_VERSION,
        "Bottleneck report schema version mismatch"
    );
    assert_eq!(
        bottleneck["runner_schema_version"], SWARM_EXECUTION_QUEUE_RUNNER_SCHEMA_VERSION,
        "Runner schema version mismatch in bottleneck report"
    );
}

fn create_valid_normalized_input() -> String {
    format!(
        r#"{{
        "schema_version": "{}",
        "source_revision": "test-revision-001",
        "decision": "execute-test-queue",
        "risk_budget": {{
            "conservative_threshold_millionths": 50000,
            "current_risk_millionths": 10000,
            "remaining_budget_millionths": 40000,
            "conservative_mode": false
        }},
        "tasks": [
            {{
                "task_id": "test-task-001",
                "priority": 1000000,
                "dependencies": [],
                "estimated_duration_millis": 5000,
                "risk_profile": {{
                    "base_risk_millionths": 1000,
                    "complexity_multiplier_millionths": 1200000,
                    "uncertainty_adjustment_millionths": 100000
                }}
            }}
        ],
        "cross_cutting_signals": {{
            "operator_attention_available": true,
            "system_load_normalized_millionths": 300000,
            "error_rate_last_hour_millionths": 2000
        }}
    }}"#,
        SWARM_EXECUTION_QUEUE_INPUT_SCHEMA_VERSION
    )
}

fn create_invalid_normalized_input() -> String {
    r#"{
        "schema_version": "invalid-schema-version",
        "malformed": "missing required fields"
    }"#
    .to_string()
}

fn create_test_options() -> ExecutionQueueRunOptions {
    ExecutionQueueRunOptions {
        queue_depth: 10,
        epoch: SecurityEpoch::from_raw(42).as_u64(),
        timestamp_ns: 1_234_567_890_000_000, // Fixed deterministic timestamp
        include_gated_in_queue: false,
    }
}

#[test]
fn valid_input_conforms_to_mutation_free_contract() {
    let valid_input = create_valid_normalized_input();
    let options = create_test_options();
    assert_swarm_execution_queue_runner_contract(&valid_input, options, true);
}

#[test]
fn invalid_input_fails_closed_with_mutation_free_contract() {
    let invalid_input = create_invalid_normalized_input();
    let options = create_test_options();
    assert_swarm_execution_queue_runner_contract(&invalid_input, options, false);
}

#[test]
fn empty_input_fails_closed_with_mutation_free_contract() {
    let empty_input = "";
    let options = create_test_options();
    assert_swarm_execution_queue_runner_contract(empty_input, options, false);
}

#[test]
fn malformed_json_fails_closed_with_mutation_free_contract() {
    let malformed_json = r#"{"invalid": json syntax"#;
    let options = create_test_options();
    assert_swarm_execution_queue_runner_contract(malformed_json, options, false);
}

#[test]
fn deterministic_behavior_across_multiple_runs() {
    let valid_input = create_valid_normalized_input();
    let options = create_test_options();

    let temp_dir = tempfile::tempdir().expect("Failed to create temp directory");
    let test_dir = temp_dir.path();

    let input_path = test_dir.join("input.json");
    fs::write(&input_path, &valid_input).expect("Failed to write input file");

    // Run multiple times with same input and verify deterministic output
    let mut output_dirs = Vec::new();
    let mut results = Vec::new();

    for i in 0..3 {
        let output_dir = test_dir.join(format!("output_{}", i));
        let result = run_normalized_input_file(&input_path, &output_dir, options.clone())
            .expect("Run should succeed");

        output_dirs.push(output_dir);
        results.push(result);
    }

    // All exit codes should match
    for i in 1..results.len() {
        assert_eq!(
            results[0].exit_code(),
            results[i].exit_code(),
            "Exit code mismatch between run 0 and run {}",
            i
        );
    }

    // All deterministic artifact files should match byte-for-byte
    let deterministic_files = [
        "execution_queue_artifact.json",
        "risk_budget_receipt.json",
        "bottleneck_report.json",
    ];

    for file in deterministic_files {
        let baseline_content =
            fs::read(output_dirs[0].join(file)).expect("Failed to read baseline file");

        for (i, output_dir) in output_dirs.iter().enumerate().skip(1) {
            let comparison_content =
                fs::read(output_dir.join(file)).expect("Failed to read comparison file");

            assert_eq!(
                baseline_content, comparison_content,
                "File {} differs between run 0 and run {} - violates deterministic contract",
                file, i
            );
        }
    }
}

#[test]
fn schema_version_consistency_across_artifacts() {
    let valid_input = create_valid_normalized_input();
    let options = create_test_options();

    let temp_dir = tempfile::tempdir().expect("Failed to create temp directory");
    let test_dir = temp_dir.path();

    let input_path = test_dir.join("input.json");
    fs::write(&input_path, &valid_input).expect("Failed to write input file");

    let output_dir = test_dir.join("output");
    let _result =
        run_normalized_input_file(&input_path, &output_dir, options).expect("Run should succeed");

    validate_schema_constants(&output_dir);
}

#[test]
fn output_isolation_contract() {
    // Test that runner only writes to designated output directory
    let valid_input = create_valid_normalized_input();
    let options = create_test_options();

    let temp_dir = tempfile::tempdir().expect("Failed to create temp directory");
    let test_dir = temp_dir.path();

    let input_path = test_dir.join("input.json");
    fs::write(&input_path, &valid_input).expect("Failed to write input file");

    // Create files that should NOT be modified
    let protected_file1 = test_dir.join("protected_bead_state.json");
    let protected_file2 = test_dir.join("protected_reservation.json");
    let protected_file3 = test_dir.join("other_data.txt");

    fs::write(&protected_file1, "original_bead_content").expect("Failed to write protected file 1");
    fs::write(&protected_file2, "original_reservation_content")
        .expect("Failed to write protected file 2");
    fs::write(&protected_file3, "other_important_data").expect("Failed to write protected file 3");

    let original_content1 = fs::read(&protected_file1).expect("Failed to read protected file 1");
    let original_content2 = fs::read(&protected_file2).expect("Failed to read protected file 2");
    let original_content3 = fs::read(&protected_file3).expect("Failed to read protected file 3");

    let output_dir = test_dir.join("isolated_output");
    let _result =
        run_normalized_input_file(&input_path, &output_dir, options).expect("Run should succeed");

    // Verify protected files were not modified
    let final_content1 = fs::read(&protected_file1).expect("Failed to read protected file 1");
    let final_content2 = fs::read(&protected_file2).expect("Failed to read protected file 2");
    let final_content3 = fs::read(&protected_file3).expect("Failed to read protected file 3");

    assert_eq!(
        original_content1, final_content1,
        "Protected bead state file was modified - violates isolation contract"
    );
    assert_eq!(
        original_content2, final_content2,
        "Protected reservation file was modified - violates isolation contract"
    );
    assert_eq!(
        original_content3, final_content3,
        "Protected data file was modified - violates isolation contract"
    );

    // Verify all outputs are contained within the designated output directory
    assert!(output_dir.exists(), "Output directory should exist");

    for entry in fs::read_dir(&test_dir).expect("Failed to read test directory") {
        let entry = entry.expect("Failed to read directory entry");
        let path = entry.path();

        if path.is_file() && path != input_path && !path.starts_with(&output_dir) {
            // These should only be our protected test files
            let file_name = path.file_name().unwrap().to_string_lossy();
            assert!(
                file_name.starts_with("protected_") || file_name == "other_data.txt",
                "Unexpected file created outside output directory: {}",
                path.display()
            );
        }
    }
}
