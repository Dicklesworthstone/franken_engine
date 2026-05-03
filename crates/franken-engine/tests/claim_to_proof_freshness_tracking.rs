#![forbid(unsafe_code)]

//! Integration test for claim-to-proof matrix freshness tracking.
//!
//! This test validates that bd-2zzwh functionality correctly:
//! - Derives freshness from actual proof artifact timestamps
//! - Downgrades stale proofs to PROVISIONAL status
//! - Emits warnings for stale artifacts
//! - Handles multiple timestamp formats and manifest structures

use std::fs;
use std::path::Path;
use std::process::Command;

#[test]
fn test_claim_to_proof_freshness_derivation() {
    let temp_dir = tempfile::tempdir().expect("Failed to create temp directory");
    let temp_path = temp_dir.path();

    // Create test matrix with stale threshold
    let matrix = serde_json::json!({
        "schema_version": "franken-engine.claim-to-proof-matrix.v1",
        "policy_id": "test-policy",
        "owning_bead": "bd-test",
        "generated_by": "freshness-test",
        "max_observed_freshness_days": 30,
        "stale_threshold_days": 7,
        "state_order": ["hypothesis", "target", "observed"],
        "claims": [
            {
                "claim_id": "TEST-FRESH-001",
                "claim_scope": "test",
                "claim_text": "Fresh proof claim",
                "source_path": "README.md",
                "source_span": {
                    "start_line": 1,
                    "end_line": 1,
                    "must_contain": "FrankenEngine"
                },
                "allowed_state": "observed",
                "actual_wording_state": "observed",
                "artifact_path": format!("{}/fresh_artifacts", temp_path.display()),
                "verification_command": "echo fresh",
                "freshness_days": 1,
                "decision": "allow_observed",
                "reason": "Test fresh proof",
                "owning_bead": "bd-test",
                "downgrade_text": "Target: fresh proof test"
            },
            {
                "claim_id": "TEST-STALE-002",
                "claim_scope": "test",
                "claim_text": "Stale proof claim",
                "source_path": "README.md",
                "source_span": {
                    "start_line": 2,
                    "end_line": 2,
                    "must_contain": "Native Rust"
                },
                "allowed_state": "observed",
                "actual_wording_state": "observed",
                "artifact_path": format!("{}/stale_artifacts", temp_path.display()),
                "verification_command": "echo stale",
                "freshness_days": 3,
                "decision": "allow_observed",
                "reason": "Test stale proof",
                "owning_bead": "bd-test",
                "downgrade_text": "Target: stale proof test"
            }
        ]
    });

    let matrix_path = temp_path.join("test_matrix.json");
    fs::write(&matrix_path, serde_json::to_string_pretty(&matrix).unwrap())
        .expect("Failed to write matrix file");

    // Create fresh artifact with recent manifest
    let fresh_dir = temp_path.join("fresh_artifacts");
    fs::create_dir_all(&fresh_dir).expect("Failed to create fresh artifacts directory");

    let fresh_manifest = serde_json::json!({
        "schema_version": "franken-engine.proof-artifact-manifest.v1",
        "freshness": {
            "generated_utc": "2026-05-01T10:00:00Z",  // Recent timestamp
            "freshness_days": 0,
            "max_freshness_days": 30
        }
    });

    fs::write(
        fresh_dir.join("manifest.json"),
        serde_json::to_string_pretty(&fresh_manifest).unwrap(),
    )
    .expect("Failed to write fresh manifest");

    // Create stale artifact with old manifest
    let stale_dir = temp_path.join("stale_artifacts");
    fs::create_dir_all(&stale_dir).expect("Failed to create stale artifacts directory");

    let stale_manifest = serde_json::json!({
        "schema_version": "franken-engine.proof-artifact-manifest.v1",
        "freshness": {
            "generated_utc": "2026-04-15T10:00:00Z",  // 16+ days old
            "freshness_days": 0,
            "max_freshness_days": 30
        }
    });

    fs::write(
        stale_dir.join("manifest.json"),
        serde_json::to_string_pretty(&stale_manifest).unwrap(),
    )
    .expect("Failed to write stale manifest");

    // Run the enhanced claim-to-proof matrix gate
    let output = Command::new("./scripts/run_claim_to_proof_matrix_gate.sh")
        .arg("ci")
        .env("CLAIM_TO_PROOF_MATRIX_PATH", &matrix_path)
        .current_dir(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .unwrap()
                .parent()
                .unwrap(),
        )
        .output()
        .expect("Failed to run claim-to-proof matrix gate");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Assertions
    assert!(
        stderr.contains("TEST-STALE-002: Proof artifact is stale"),
        "Should warn about stale proof: stderr={}",
        stderr
    );

    assert!(
        stderr.contains("downgraded to provisional"),
        "Should indicate downgrade: stderr={}",
        stderr
    );

    assert!(
        !stderr.contains("TEST-FRESH-001: Proof artifact is stale"),
        "Should not warn about fresh proof: stderr={}",
        stderr
    );

    // Extract report path from stdout
    let report_line = stdout
        .lines()
        .find(|line| line.starts_with("claim_to_proof_matrix_gate_report="))
        .expect("Report path not found in stdout");

    let report_path = report_line
        .strip_prefix("claim_to_proof_matrix_gate_report=")
        .expect("Invalid report line format");

    let report_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join(report_path);

    // Read and validate the report
    let report_content = fs::read_to_string(&report_path).expect("Failed to read report file");

    let report: serde_json::Value =
        serde_json::from_str(&report_content).expect("Failed to parse report JSON");

    // Find events for our test claims
    let events = report["events"].as_array().expect("No events in report");

    let fresh_event = events
        .iter()
        .find(|event| event["claim_id"] == "TEST-FRESH-001")
        .expect("Fresh claim event not found");

    let stale_event = events
        .iter()
        .find(|event| event["claim_id"] == "TEST-STALE-002")
        .expect("Stale claim event not found");

    // Validate fresh claim handling
    assert_eq!(
        fresh_event["decision"], "allow_observed",
        "Fresh claim should remain observed"
    );
    assert_eq!(
        fresh_event["freshness_status"], "ok",
        "Fresh claim should have ok status"
    );
    assert!(
        fresh_event["actual_freshness_days"].as_i64().unwrap() < 7,
        "Fresh claim should be within threshold"
    );

    // Validate stale claim handling
    assert_eq!(
        stale_event["decision"], "downgrade_stale_proof",
        "Stale claim should be downgraded"
    );
    assert_eq!(
        stale_event["freshness_status"], "stale",
        "Stale claim should have stale status"
    );
    assert!(
        stale_event["actual_freshness_days"].as_i64().unwrap() > 7,
        "Stale claim should exceed threshold"
    );

    let downgrade_text = stale_event["downgrade_text"]
        .as_str()
        .expect("Downgrade text should be present");
    assert!(
        downgrade_text.starts_with("PROVISIONAL:"),
        "Downgrade text should indicate provisional status: {}",
        downgrade_text
    );

    println!("✓ Claim-to-proof freshness tracking validation passed");
    println!("  - Fresh claims remain observed with accurate freshness calculation");
    println!("  - Stale claims downgraded to provisional with clear reasoning");
    println!("  - Warnings emitted for stale artifacts");
    println!("  - Manifest timestamp parsing handles multiple formats");
}

#[test]
fn test_claim_to_proof_compact_timestamp_format() {
    let temp_dir = tempfile::tempdir().expect("Failed to create temp directory");
    let temp_path = temp_dir.path();

    // Create test matrix
    let matrix = serde_json::json!({
        "schema_version": "franken-engine.claim-to-proof-matrix.v1",
        "policy_id": "test-policy",
        "owning_bead": "bd-test",
        "max_observed_freshness_days": 30,
        "stale_threshold_days": 5,
        "state_order": ["hypothesis", "target", "observed"],
        "claims": [
            {
                "claim_id": "TEST-COMPACT-001",
                "claim_scope": "test",
                "claim_text": "Compact timestamp test",
                "source_path": "README.md",
                "source_span": {
                    "start_line": 1,
                    "end_line": 1,
                    "must_contain": "FrankenEngine"
                },
                "allowed_state": "observed",
                "actual_wording_state": "observed",
                "artifact_path": format!("{}/compact_artifacts", temp_path.display()),
                "verification_command": "echo compact",
                "freshness_days": 1,
                "decision": "allow_observed",
                "reason": "Test compact timestamp",
                "owning_bead": "bd-test",
                "downgrade_text": "Target: compact timestamp test"
            }
        ]
    });

    let matrix_path = temp_path.join("test_matrix.json");
    fs::write(&matrix_path, serde_json::to_string_pretty(&matrix).unwrap())
        .expect("Failed to write matrix file");

    // Create artifact with compact timestamp format (like throughput metrics)
    let artifacts_dir = temp_path.join("compact_artifacts");
    fs::create_dir_all(&artifacts_dir).expect("Failed to create artifacts directory");

    let compact_manifest = serde_json::json!({
        "schema_version": "franken-engine.throughput-metric.v1",
        "generated_at_utc": "20260501T100000Z"  // Compact format
    });

    fs::write(
        artifacts_dir.join("compact_manifest.json"),
        serde_json::to_string_pretty(&compact_manifest).unwrap(),
    )
    .expect("Failed to write compact manifest");

    // Run the gate
    let output = Command::new("./scripts/run_claim_to_proof_matrix_gate.sh")
        .arg("ci")
        .env("CLAIM_TO_PROOF_MATRIX_PATH", &matrix_path)
        .current_dir(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .unwrap()
                .parent()
                .unwrap(),
        )
        .output()
        .expect("Failed to run claim-to-proof matrix gate");

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Extract and validate report
    let report_line = stdout
        .lines()
        .find(|line| line.starts_with("claim_to_proof_matrix_gate_report="))
        .expect("Report path not found in stdout");

    let report_path = report_line
        .strip_prefix("claim_to_proof_matrix_gate_report=")
        .expect("Invalid report line format");

    let report_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join(report_path);

    let report_content = fs::read_to_string(&report_path).expect("Failed to read report file");

    let report: serde_json::Value =
        serde_json::from_str(&report_content).expect("Failed to parse report JSON");

    let events = report["events"].as_array().expect("No events in report");
    let event = events
        .iter()
        .find(|event| event["claim_id"] == "TEST-COMPACT-001")
        .expect("Compact timestamp event not found");

    // Should successfully parse compact timestamp and calculate freshness
    assert!(
        event["actual_freshness_days"].as_i64().is_some(),
        "Should parse compact timestamp format and calculate freshness"
    );

    assert_eq!(
        event["freshness_status"], "ok",
        "Compact timestamp should be parsed as fresh"
    );

    println!("✓ Compact timestamp format parsing validation passed");
    println!("  - Correctly parses 20260501T100000Z format");
    println!("  - Calculates accurate freshness from compact timestamps");
}

#[test]
fn test_observed_claim_rejects_targeted_placeholder_metric_artifact() {
    let temp_dir = tempfile::tempdir().expect("Failed to create temp directory");
    let temp_path = temp_dir.path();
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();

    let artifact_dir = temp_path.join("throughput_disruptive_floor_metric");
    fs::create_dir_all(&artifact_dir).expect("Failed to create throughput artifact directory");

    let metric_report_path = artifact_dir.join("throughput_metric_report.json");
    let metric_report = serde_json::json!({
        "schema_version": "franken-engine.throughput-disruptive-floor-metric-gate.v1",
        "overall_outcome": "targeted",
        "outcome_reason": "placeholder baselines detected (Node: 1, Bun: 1)",
        "uses_placeholder_baselines": true,
        "node_placeholder_count": 1,
        "bun_placeholder_count": 1,
        "verification_commands": [
            "./scripts/verify_placeholder_test.sh",
            "./scripts/verify_placeholder_test_bun.sh"
        ],
        "generated_at_utc": "20260501T101240Z"
    });
    fs::write(
        &metric_report_path,
        serde_json::to_string_pretty(&metric_report).unwrap(),
    )
    .expect("Failed to write targeted throughput report");

    let metric_manifest = serde_json::json!({
        "schema_version": "franken-engine.proof-artifact-manifest.v1",
        "component": "throughput_disruptive_floor_metric_gate",
        "artifact_type": "metric",
        "scenario_set": "throughput_placeholder_test",
        "artifact_path": metric_report_path.display().to_string(),
        "code_revision": "placeholder123",
        "verification_command": "./scripts/run_throughput_disruptive_floor_metric_gate.sh verify throughput_metric_report.json",
        "generated_at_utc": "20260501T101240Z"
    });
    fs::write(
        artifact_dir.join("throughput_metric_manifest.json"),
        serde_json::to_string_pretty(&metric_manifest).unwrap(),
    )
    .expect("Failed to write targeted throughput manifest");

    let matrix = serde_json::json!({
        "schema_version": "franken-engine.claim-to-proof-matrix.v1",
        "policy_id": "test-policy",
        "owning_bead": "bd-test",
        "max_observed_freshness_days": 999_999,
        "stale_threshold_days": 999_999,
        "state_order": ["hypothesis", "target", "observed"],
        "claims": [
            {
                "claim_id": "TEST-PLACEHOLDER-001",
                "claim_scope": "performance",
                "claim_text": "Observed throughput claim backed by placeholder metrics",
                "source_path": "README.md",
                "source_span": {
                    "start_line": 1,
                    "end_line": 1,
                    "must_contain": "FrankenEngine"
                },
                "allowed_state": "observed",
                "actual_wording_state": "observed",
                "artifact_path": artifact_dir.display().to_string(),
                "verification_command": "./scripts/run_throughput_disruptive_floor_metric_gate.sh ci",
                "freshness_days": 1,
                "decision": "allow_observed",
                "reason": "This must be rejected because the latest metric artifact is targeted placeholder evidence",
                "owning_bead": "bd-test",
                "downgrade_text": "Target: throughput claim needs live Node/Bun denominator artifacts."
            }
        ]
    });

    let matrix_path = temp_path.join("placeholder_metric_matrix.json");
    fs::write(&matrix_path, serde_json::to_string_pretty(&matrix).unwrap())
        .expect("Failed to write placeholder metric matrix");

    let artifact_root = temp_path.join("claim_gate_artifacts");
    let output = Command::new("./scripts/run_claim_to_proof_matrix_gate.sh")
        .arg("ci")
        .env("CLAIM_TO_PROOF_MATRIX_PATH", &matrix_path)
        .env("CLAIM_TO_PROOF_MATRIX_ARTIFACT_ROOT", &artifact_root)
        .current_dir(repo_root)
        .output()
        .expect("Failed to run claim-to-proof matrix gate");

    assert!(
        !output.status.success(),
        "Gate must fail observed claims backed by targeted placeholder artifacts"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("artifact_quality_status=targeted"),
        "Failure log should expose targeted artifact quality: stderr={}",
        stderr
    );
    assert!(
        stderr.contains("uses_placeholder_baselines=true"),
        "Failure log should expose placeholder baseline evidence: stderr={}",
        stderr
    );

    let report_line = stdout
        .lines()
        .find(|line| line.starts_with("claim_to_proof_matrix_gate_report="))
        .expect("Report path not found in stdout");
    let report_path = report_line
        .strip_prefix("claim_to_proof_matrix_gate_report=")
        .expect("Invalid report line format");
    let report_path = repo_root.join(report_path);

    let report_content = fs::read_to_string(&report_path).expect("Failed to read report");
    let report: serde_json::Value =
        serde_json::from_str(&report_content).expect("Failed to parse report");
    let event = report["events"]
        .as_array()
        .expect("No events in report")
        .iter()
        .find(|event| event["claim_id"] == "TEST-PLACEHOLDER-001")
        .expect("Placeholder metric claim event not found");

    assert_eq!(event["status"], "fail");
    assert_eq!(event["artifact_quality_status"], "targeted");
    assert!(
        event["artifact_quality_reason"]
            .as_str()
            .expect("quality reason should be present")
            .contains("uses_placeholder_baselines=true"),
        "quality reason must include placeholder baseline state"
    );
    assert!(
        event["artifact_quality_report_path"]
            .as_str()
            .expect("quality report path should be present")
            .ends_with("throughput_metric_report.json"),
        "quality report path should point at the metric report"
    );

    println!("✓ Placeholder metric artifact rejection validation passed");
    println!("  - Observed claims fail when latest metric evidence is targeted");
    println!("  - Structured event records artifact_quality_status and report path");
    println!("  - Failure logs expose placeholder baseline counts for operators");
}

#[test]
fn test_claim_to_proof_file_based_freshness() {
    let temp_dir = tempfile::tempdir().expect("Failed to create temp directory");
    let temp_path = temp_dir.path();

    // Create test matrix with file-based artifact
    let test_file = temp_path.join("test_artifact.md");
    fs::write(&test_file, "Test artifact content").expect("Failed to create test file");

    let matrix = serde_json::json!({
        "schema_version": "franken-engine.claim-to-proof-matrix.v1",
        "policy_id": "test-policy",
        "owning_bead": "bd-test",
        "max_observed_freshness_days": 30,
        "state_order": ["hypothesis", "target", "observed"],
        "claims": [
            {
                "claim_id": "TEST-FILE-001",
                "claim_scope": "test",
                "claim_text": "File-based artifact test",
                "source_path": "README.md",
                "source_span": {
                    "start_line": 1,
                    "end_line": 1,
                    "must_contain": "FrankenEngine"
                },
                "allowed_state": "observed",
                "actual_wording_state": "observed",
                "artifact_path": test_file.display().to_string(),
                "verification_command": "echo file",
                "freshness_days": 1,
                "decision": "allow_observed",
                "reason": "Test file-based artifact",
                "owning_bead": "bd-test",
                "downgrade_text": "Target: file artifact test"
            }
        ]
    });

    let matrix_path = temp_path.join("test_matrix.json");
    fs::write(&matrix_path, serde_json::to_string_pretty(&matrix).unwrap())
        .expect("Failed to write matrix file");

    // Run the gate
    let output = Command::new("./scripts/run_claim_to_proof_matrix_gate.sh")
        .arg("ci")
        .env("CLAIM_TO_PROOF_MATRIX_PATH", &matrix_path)
        .current_dir(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .unwrap()
                .parent()
                .unwrap(),
        )
        .output()
        .expect("Failed to run claim-to-proof matrix gate");

    assert!(
        output.status.success(),
        "Gate should succeed for file-based artifacts"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let report_line = stdout
        .lines()
        .find(|line| line.starts_with("claim_to_proof_matrix_gate_report="))
        .expect("Report path not found");

    let report_path = report_line
        .strip_prefix("claim_to_proof_matrix_gate_report=")
        .expect("Invalid report line");

    let report_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join(report_path);

    let report_content = fs::read_to_string(&report_path).expect("Failed to read report");

    let report: serde_json::Value =
        serde_json::from_str(&report_content).expect("Failed to parse report");

    let events = report["events"].as_array().expect("No events");
    let event = events
        .iter()
        .find(|event| event["claim_id"] == "TEST-FILE-001")
        .expect("File event not found");

    // File-based artifacts should use modification time
    assert_eq!(
        event["freshness_status"], "ok",
        "File should be treated as fresh"
    );
    assert_eq!(
        event["actual_freshness_days"], 0,
        "File should be 0 days old"
    );

    println!("✓ File-based artifact freshness validation passed");
    println!("  - Uses file modification time for non-directory artifacts");
    println!("  - Correctly handles documentation and script files");
}
