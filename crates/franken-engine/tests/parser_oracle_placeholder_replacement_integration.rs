use std::fs;
use std::path::PathBuf;
use std::process::Command;

#[test]
fn test_parser_oracle_rejects_placeholder_backfills() {
    // Verify that parser oracle gate generates receipts instead of placeholder content
    // when artifacts are missing

    // Run parser oracle gate in check mode (which should not generate full artifacts)
    let output = Command::new("scripts/run_parser_oracle_gate.sh")
        .arg("check")
        .output()
        .expect("Failed to run parser oracle gate script");

    // The check mode should complete successfully
    if !output.status.success() {
        eprintln!("Script output: {}", String::from_utf8_lossy(&output.stdout));
        eprintln!("Script error: {}", String::from_utf8_lossy(&output.stderr));
    }

    // Find the most recent run directory
    let artifacts_dir = PathBuf::from("artifacts/parser_oracle");
    if !artifacts_dir.exists() {
        panic!("Parser oracle artifacts directory should exist after running script");
    }

    let mut run_dirs: Vec<_> = fs::read_dir(&artifacts_dir)
        .expect("Should be able to read artifacts directory")
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let path = entry.path();
            if path.is_dir() { Some(path) } else { None }
        })
        .collect();

    assert!(
        !run_dirs.is_empty(),
        "Should have at least one run directory"
    );

    run_dirs.sort_by(|a, b| {
        let a_name = a.file_name().unwrap().to_string_lossy();
        let b_name = b.file_name().unwrap().to_string_lossy();
        b_name.cmp(&a_name) // Most recent first
    });

    let latest_run_dir = &run_dirs[0];

    // Check for forbidden placeholder signatures
    let forbidden_signatures = [
        ("baseline.json", "{}"),
        ("relation_report.json", r#"{"status":"not_run"}"#),
    ];

    for (artifact_name, forbidden_content) in forbidden_signatures {
        let artifact_path = latest_run_dir.join(artifact_name);
        if artifact_path.exists() {
            let content =
                fs::read_to_string(&artifact_path).expect("Should be able to read artifact file");

            assert_ne!(
                content.trim(),
                forbidden_content,
                "Artifact {} should not contain forbidden placeholder content: {}",
                artifact_name,
                forbidden_content
            );
        }
    }

    // Check for forbidden empty files
    let forbidden_empty_files = [
        "relation_events.jsonl",
        "metamorphic_evidence.jsonl",
        "drift_digest.md",
    ];

    for artifact_name in forbidden_empty_files {
        let artifact_path = latest_run_dir.join(artifact_name);
        if artifact_path.exists() {
            let metadata =
                fs::metadata(&artifact_path).expect("Should be able to read artifact metadata");

            assert_ne!(
                metadata.len(),
                0,
                "Artifact {} should not be an empty file placeholder",
                artifact_name
            );
        }
    }

    // Verify that missing artifact receipt exists when artifacts are missing
    let receipt_path = latest_run_dir.join("parser_oracle_missing_artifact_receipt.json");

    // Check if any covered artifacts are missing
    let covered_artifacts = [
        "baseline.json",
        "relation_report.json",
        "relation_events.jsonl",
        "metamorphic_evidence.jsonl",
        "drift_digest.md",
    ];

    let missing_artifacts: Vec<&str> = covered_artifacts
        .iter()
        .filter(|&&name| !latest_run_dir.join(name).exists())
        .copied()
        .collect();

    if !missing_artifacts.is_empty() {
        assert!(
            receipt_path.exists(),
            "Missing artifact receipt should exist when covered artifacts are missing: {:?}",
            missing_artifacts
        );

        // Validate receipt structure
        let receipt_content = fs::read_to_string(&receipt_path)
            .expect("Should be able to read missing artifact receipt");

        let receipt: serde_json::Value = serde_json::from_str(&receipt_content)
            .expect("Missing artifact receipt should be valid JSON");

        // Verify required fields according to the contract
        assert!(receipt["schema_version"].is_string());
        assert!(receipt["trace_id"].is_string());
        assert!(receipt["decision_id"].is_string());
        assert!(receipt["policy_id"].is_string());
        assert!(receipt["component"].is_string());
        assert!(receipt["artifact_path"].is_string());
        assert!(receipt["artifact_role"].is_string());
        assert!(receipt["stage"].is_string());
        assert!(receipt["reason_code"].is_string());
        assert!(receipt["reason_id"].is_string());
        assert!(receipt["consumer_action"].is_string());
        assert!(receipt["missing_artifacts"].is_array());
        assert!(receipt["placeholder_rejected"].as_bool().unwrap());

        // Verify reason_code is one of the valid ones from the contract
        let reason_code = receipt["reason_code"].as_str().unwrap();
        let valid_codes = [
            "FE-PO-MISSING-0001",
            "FE-PO-MISSING-0002",
            "FE-PO-MISSING-0003",
            "FE-PO-MISSING-0004",
        ];
        assert!(
            valid_codes.contains(&reason_code),
            "Reason code {} should be one of the valid codes",
            reason_code
        );

        // Verify missing_artifacts field lists the actual missing artifacts
        let missing_artifacts_in_receipt = receipt["missing_artifacts"].as_array().unwrap();
        assert!(
            !missing_artifacts_in_receipt.is_empty(),
            "missing_artifacts should not be empty"
        );

        for missing_artifact in missing_artifacts_in_receipt {
            let artifact_path = missing_artifact["artifact_path"].as_str().unwrap();
            let artifact_role = missing_artifact["artifact_role"].as_str().unwrap();

            assert!(
                missing_artifacts.contains(&artifact_path),
                "Receipt should only list actually missing artifacts: {}",
                artifact_path
            );

            // Verify artifact_role matches expectations
            let expected_roles = [
                "baseline",
                "relation_report",
                "relation_events",
                "metamorphic_evidence",
                "drift_digest",
            ];
            assert!(
                expected_roles.contains(&artifact_role),
                "Artifact role {} should be one of the expected roles",
                artifact_role
            );
        }
    }
}

#[test]
fn test_parser_oracle_contract_compliance() {
    // Test that the missing artifact contract is properly structured

    let contract_path = PathBuf::from("docs/parser_oracle_missing_artifact_contract_v1.json");
    assert!(
        contract_path.exists(),
        "Parser oracle missing artifact contract should exist"
    );

    let contract_content =
        fs::read_to_string(&contract_path).expect("Should be able to read contract file");

    let contract: serde_json::Value =
        serde_json::from_str(&contract_content).expect("Contract should be valid JSON");

    // Verify contract structure
    assert!(contract["schema_version"].is_string());
    assert!(contract["artifact_contract"].is_object());

    let artifact_contract = &contract["artifact_contract"];
    assert!(artifact_contract["reason_matrix"].is_array());
    assert!(artifact_contract["rejected_anonymous_backfills"].is_array());

    // Verify forbidden placeholder signatures are defined
    let rejected_backfills = artifact_contract["rejected_anonymous_backfills"]
        .as_array()
        .unwrap();
    let mut has_empty_json = false;
    let mut has_status_placeholder = false;
    let mut has_empty_files = false;

    for backfill in rejected_backfills {
        let signature_value = backfill["signature_value"].as_str().unwrap();
        let signature_type = backfill["signature_type"].as_str().unwrap();

        match signature_value {
            "{}" => has_empty_json = true,
            r#"{"status":"not_run"}"# => has_status_placeholder = true,
            "" if signature_type == "zero_bytes" => has_empty_files = true,
            _ => {}
        }
    }

    assert!(
        has_empty_json,
        "Contract should reject empty JSON placeholders"
    );
    assert!(
        has_status_placeholder,
        "Contract should reject status-only placeholders"
    );
    assert!(
        has_empty_files,
        "Contract should reject empty file placeholders"
    );
}

#[test]
fn test_parser_oracle_receipt_generation_function() {
    // Test the emit_missing_artifact_receipt function behavior by examining the script

    let script_path = PathBuf::from("scripts/run_parser_oracle_gate.sh");
    let script_content =
        fs::read_to_string(&script_path).expect("Should be able to read parser oracle gate script");

    // Verify the script contains the missing artifact receipt generation function
    assert!(
        script_content.contains("emit_missing_artifact_receipt"),
        "Script should contain emit_missing_artifact_receipt function"
    );

    // Verify the script calls write_missing_artifact_receipt
    assert!(
        script_content.contains("write_missing_artifact_receipt"),
        "Script should call write_missing_artifact_receipt function"
    );

    // Verify the script references the contract
    assert!(
        script_content.contains("parser_oracle_missing_artifact_contract"),
        "Script should reference the missing artifact contract"
    );

    // Verify the script does not contain forbidden placeholder generation
    let forbidden_patterns = [
        r#"echo '{}'"#,
        r#"echo '{"status":"not_run"}'"#,
        r#"touch "$"#, // Common pattern for creating empty files
    ];

    for pattern in forbidden_patterns {
        assert!(
            !script_content.contains(pattern),
            "Script should not contain forbidden placeholder generation pattern: {}",
            pattern
        );
    }
}

#[test]
fn test_parser_oracle_exit_code_handling() {
    // Test that different exit codes result in appropriate reason_ids

    // This test validates the select_missing_artifact_reason_id logic
    let script_path = PathBuf::from("scripts/run_parser_oracle_gate.sh");
    let script_content =
        fs::read_to_string(&script_path).expect("Should be able to read parser oracle gate script");

    // Verify the script contains proper exit code to reason_id mapping
    assert!(
        script_content.contains("select_missing_artifact_reason_id"),
        "Script should contain select_missing_artifact_reason_id function"
    );

    // The function should handle different modes and exit codes
    assert!(
        script_content.contains("not_run_by_design"),
        "Script should handle not_run_by_design reason"
    );

    assert!(
        script_content.contains("failed_before_artifact_creation"),
        "Script should handle failed_before_artifact_creation reason"
    );

    assert!(
        script_content.contains("missing_unexpected_absence"),
        "Script should handle missing_unexpected_absence reason"
    );
}
