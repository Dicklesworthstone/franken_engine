#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::Command;

use serde_json::Value;

#[test]
fn red_team_compromise_rate_script_detects_stubs_and_refuses_observed_status() {
    // Use isolated CARGO_TARGET_DIR as required
    let test_target_dir = "/tmp/test_compromise_rate_mock_detection";

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let project_root = manifest_dir.parent().unwrap().parent().unwrap();
    let script_path = project_root.join("scripts/run_red_team_compromise_rate_metric_gate.sh");

    // Create a temporary test directory
    let test_artifact_dir = "/tmp/test_red_team_compromise_rate_bd_12vhs";

    // Execute the script in pass mode (should use stubs since real scenarios will fall back)
    let output = Command::new("bash")
        .arg(&script_path)
        .arg("pass")
        .current_dir(&project_root)
        .env("CARGO_TARGET_DIR", test_target_dir)
        .env(
            "RED_TEAM_COMPROMISE_RATE_METRIC_ARTIFACT_ROOT",
            test_artifact_dir,
        )
        .env("RED_TEAM_COMPROMISE_RATE_METRIC_RUN_ID", "test_bd_12vhs")
        .output()
        .expect("Failed to execute compromise rate script");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    println!("Script stdout: {}", stdout);
    println!("Script stderr: {}", stderr);

    // Script should succeed but warn about stubs
    assert!(
        output.status.success() || output.status.code() == Some(0),
        "Script should succeed even with stubs, exit code: {:?}, stderr: {}",
        output.status.code(),
        stderr
    );

    // Check that the metric artifact was generated
    let metric_path = format!("{}/test_bd_12vhs/metric_artifact.json", test_artifact_dir);
    let metric_content = std::fs::read_to_string(&metric_path)
        .unwrap_or_else(|e| panic!("Failed to read metric artifact at {}: {}", metric_path, e));

    let metric: Value =
        serde_json::from_str(&metric_content).expect("Failed to parse metric artifact JSON");

    // Verify defensive pattern: TARGETED status when using stubs
    if let Some(has_stubs) = metric.get("has_placeholder_data").and_then(|v| v.as_bool()) {
        if has_stubs {
            // When stubs are detected, measurement_status should be "targeted"
            assert_eq!(
                metric["measurement_status"].as_str().unwrap(),
                "targeted",
                "When using placeholder data, measurement_status must be 'targeted', not 'observed'"
            );

            // Confidence should be 0 when using stubs
            assert_eq!(
                metric["confidence_millionths"].as_u64().unwrap(),
                0,
                "Confidence must be 0 when using placeholder data"
            );

            // Should have remediation note
            assert!(
                metric["remediation_note"].is_string(),
                "Should have remediation note when using stubs"
            );

            println!("✓ Defensive pattern working: TARGETED status with stubs detected");
        } else {
            // When real data is used, should have observed status
            assert_eq!(
                metric["measurement_status"].as_str().unwrap(),
                "observed",
                "When using real data, measurement_status should be 'observed'"
            );

            // Confidence should be 100% when using real data
            assert_eq!(
                metric["confidence_millionths"].as_u64().unwrap(),
                1_000_000,
                "Confidence should be 100% when using real data"
            );

            println!("✓ Real data detected: OBSERVED status with full confidence");
        }
    } else {
        panic!("Metric artifact should include has_placeholder_data field");
    }

    // Check that metric report exists and includes proper decision logic
    let report_path = format!("{}/test_bd_12vhs/metric_report.json", test_artifact_dir);
    let report_content =
        std::fs::read_to_string(&report_path).expect("Failed to read metric report");

    let report: Value =
        serde_json::from_str(&report_content).expect("Failed to parse metric report JSON");

    // When using stubs, decision should be "targeted" not "pass"/"fail"
    if metric["has_placeholder_data"].as_bool().unwrap_or(false) {
        assert!(
            report["decision"].as_str().unwrap() == "targeted"
                || report["reason"]
                    .as_str()
                    .unwrap()
                    .contains("awaiting_real_scenario_measurements"),
            "Decision should reflect stub/placeholder status"
        );
    }

    // Clean up test directory
    let _ = std::fs::remove_dir_all(test_artifact_dir);
    let _ = std::fs::remove_dir_all(test_target_dir);

    println!(
        "✓ Red team compromise rate script correctly detects stubs and applies defensive pattern"
    );
}
