use std::fs;
use std::path::PathBuf;
use std::process::Command;

#[test]
fn test_parser_phase0_generates_performance_receipt() {
    // Verify that the script generates a performance receipt instead of placeholder flamegraph

    let output = Command::new("scripts/generate_parser_phase0_artifacts.sh")
        .output()
        .expect("Failed to run parser phase0 artifacts script");

    if !output.status.success() {
        panic!("Script failed: {}", String::from_utf8_lossy(&output.stderr));
    }

    let artifact_dir = PathBuf::from("artifacts/parser_phase0");
    assert!(artifact_dir.exists(), "Artifact directory should exist");

    // Check that performance receipt exists instead of flamegraph.svg
    let receipt_path = artifact_dir.join("parser_phase0_performance_artifact_receipt.json");
    assert!(receipt_path.exists(), "Performance receipt should exist");

    // Verify the receipt has correct structure
    let receipt_content =
        fs::read_to_string(&receipt_path).expect("Should be able to read performance receipt");

    let receipt: serde_json::Value =
        serde_json::from_str(&receipt_content).expect("Performance receipt should be valid JSON");

    // Verify required fields according to the contract
    assert!(receipt["schema_version"].is_string());
    assert!(receipt["trace_id"].is_string());
    assert!(receipt["decision_id"].is_string());
    assert!(receipt["policy_id"].is_string());
    assert!(receipt["component"].is_string());
    assert_eq!(receipt["mode"].as_str().unwrap(), "degraded_receipt");
    assert!(receipt["artifact_path"].is_string());
    assert!(receipt["reason_code"].is_string());
    assert!(receipt["reason_id"].is_string());
    assert!(receipt["stage"].is_string());
    assert!(receipt["consumer_action"].is_string());
    assert_eq!(receipt["placeholder_rejected"].as_bool().unwrap(), true);
    assert!(receipt["outcome"].is_string());
    assert!(receipt["error_code"].is_string());

    // Verify reason_code is one of the accepted ones
    let reason_code = receipt["reason_code"].as_str().unwrap();
    let valid_codes = [
        "FE-PARSER-PHASE0-ARTIFACT-RECEIPT-0001",
        "FE-PARSER-PHASE0-ARTIFACT-RECEIPT-0002",
        "FE-PARSER-PHASE0-ARTIFACT-RECEIPT-0003",
        "FE-PARSER-PHASE0-ARTIFACT-RECEIPT-0004",
        "FE-PARSER-PHASE0-ARTIFACT-RECEIPT-0005",
        "FE-PARSER-PHASE0-ARTIFACT-RECEIPT-0006",
    ];
    assert!(
        valid_codes.contains(&reason_code),
        "Reason code {} should be one of the valid codes",
        reason_code
    );

    // Verify that placeholder flamegraph.svg does NOT exist
    let flamegraph_path = artifact_dir.join("flamegraph.svg");
    assert!(
        !flamegraph_path.exists(),
        "Placeholder flamegraph.svg should not exist"
    );
}

#[test]
fn test_performance_receipt_content_validation() {
    // Test that the performance receipt content follows the contract

    let artifact_dir = PathBuf::from("artifacts/parser_phase0");
    let receipt_path = artifact_dir.join("parser_phase0_performance_artifact_receipt.json");

    if !receipt_path.exists() {
        // Run the script first if artifacts don't exist
        let output = Command::new("scripts/generate_parser_phase0_artifacts.sh")
            .output()
            .expect("Failed to run parser phase0 artifacts script");
        assert!(output.status.success(), "Script should succeed");
    }

    let receipt_content =
        fs::read_to_string(&receipt_path).expect("Should be able to read performance receipt");

    let receipt: serde_json::Value =
        serde_json::from_str(&receipt_content).expect("Performance receipt should be valid JSON");

    // Verify specific content according to our implementation
    assert_eq!(
        receipt["reason_id"].as_str().unwrap(),
        "profiler_unavailable"
    );
    assert_eq!(receipt["stage"].as_str().unwrap(), "capture_preflight");
    assert_eq!(
        receipt["consumer_action"].as_str().unwrap(),
        "treat_as_unsupported_environment"
    );
    assert_eq!(
        receipt["component"].as_str().unwrap(),
        "parser_phase0_generator"
    );

    // Verify explanation field exists and is meaningful
    assert!(receipt["explanation"].is_string());
    let explanation = receipt["explanation"].as_str().unwrap();
    assert!(
        explanation.contains("profiling"),
        "Explanation should mention profiling"
    );

    // Verify alternative_evidence structure
    assert!(receipt["alternative_evidence"].is_object());
    let alt_evidence = &receipt["alternative_evidence"];
    assert!(alt_evidence["latency_metrics"].is_string());
    assert!(alt_evidence["grammar_completeness"].is_string());
    assert!(alt_evidence["determinism_proof"].is_string());
}

#[test]
fn test_manifest_references_performance_receipt() {
    // Verify that manifest.json correctly references the performance receipt

    let artifact_dir = PathBuf::from("artifacts/parser_phase0");
    let manifest_path = artifact_dir.join("manifest.json");

    if !manifest_path.exists() {
        // Run the script first if artifacts don't exist
        let output = Command::new("scripts/generate_parser_phase0_artifacts.sh")
            .output()
            .expect("Failed to run parser phase0 artifacts script");
        assert!(output.status.success(), "Script should succeed");
    }

    let manifest_content =
        fs::read_to_string(&manifest_path).expect("Should be able to read manifest");

    let manifest: serde_json::Value =
        serde_json::from_str(&manifest_content).expect("Manifest should be valid JSON");

    // Verify that artifacts section references performance_receipt instead of flamegraph
    let artifacts = &manifest["artifacts"];
    assert!(
        artifacts["performance_receipt"].is_object(),
        "Should have performance_receipt artifact"
    );
    assert!(
        !artifacts["flamegraph"].is_object(),
        "Should not have flamegraph artifact"
    );

    // Verify the performance_receipt artifact has correct path and sha256
    let perf_receipt_artifact = &artifacts["performance_receipt"];
    let path = perf_receipt_artifact["path"].as_str().unwrap();
    assert!(path.contains("parser_phase0_performance_artifact_receipt.json"));

    let sha256 = perf_receipt_artifact["sha256"].as_str().unwrap();
    assert!(
        sha256.starts_with("sha256:"),
        "SHA256 should have proper prefix"
    );
    assert_eq!(
        sha256.len(),
        71,
        "SHA256 should be correct length (7 prefix + 64 hex)"
    );
}

#[test]
fn test_no_placeholder_signatures_in_artifacts() {
    // Verify that none of the artifacts contain forbidden placeholder signatures

    let artifact_dir = PathBuf::from("artifacts/parser_phase0");
    if !artifact_dir.exists() {
        // Run the script first if artifacts don't exist
        let output = Command::new("scripts/generate_parser_phase0_artifacts.sh")
            .output()
            .expect("Failed to run parser phase0 artifacts script");
        assert!(output.status.success(), "Script should succeed");
    }

    // List of forbidden placeholder signatures from the contract
    let forbidden_signatures = [
        "parser phase0 flamegraph placeholder",
        "parser_phase0 scalar_reference baseline lane (placeholder flamegraph artifact)",
        r##"<rect x="40" y="72" width="1200" height="24" fill="#22c55e" />"##,
    ];

    // Check all files in the artifact directory
    for entry in fs::read_dir(&artifact_dir).expect("Should be able to read artifact directory") {
        let entry = entry.expect("Should be able to read directory entry");
        let path = entry.path();

        if path.is_file() {
            if let Ok(content) = fs::read_to_string(&path) {
                for signature in &forbidden_signatures {
                    assert!(
                        !content.contains(signature),
                        "File {:?} should not contain forbidden placeholder signature: {}",
                        path,
                        signature
                    );
                }
            }
        }
    }
}

#[test]
fn test_golden_checksums_includes_performance_receipt() {
    // Verify that golden_checksums.txt includes the performance receipt

    let artifact_dir = PathBuf::from("artifacts/parser_phase0");
    let checksums_path = artifact_dir.join("golden_checksums.txt");

    if !checksums_path.exists() {
        // Run the script first if artifacts don't exist
        let output = Command::new("scripts/generate_parser_phase0_artifacts.sh")
            .output()
            .expect("Failed to run parser phase0 artifacts script");
        assert!(output.status.success(), "Script should succeed");
    }

    let checksums_content =
        fs::read_to_string(&checksums_path).expect("Should be able to read checksums file");

    // Should include performance receipt
    assert!(
        checksums_content.contains("parser_phase0_performance_artifact_receipt.json"),
        "Golden checksums should include performance receipt"
    );

    // Should NOT include flamegraph.svg
    assert!(
        !checksums_content.contains("flamegraph.svg"),
        "Golden checksums should not include flamegraph.svg"
    );
}
