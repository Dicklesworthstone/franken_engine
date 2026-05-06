#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::Command;

use serde_json::Value;

#[test]
fn red_team_compromise_rate_script_refuses_placeholder_metric_rows() {
    // Use isolated CARGO_TARGET_DIR as required
    let test_target_dir = "/tmp/test_compromise_rate_mock_detection";

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let project_root = manifest_dir.parent().unwrap().parent().unwrap();
    let script_path = project_root.join("scripts/run_red_team_compromise_rate_metric_gate.sh");

    // Create a temporary test directory
    let test_artifact_dir = "/tmp/test_red_team_compromise_rate_bd_12vhs";

    // Force the prerequisite failure path so the script cannot discover a repo-local binary.
    let output = Command::new("bash")
        .arg(&script_path)
        .arg("pass")
        .current_dir(project_root)
        .env("CARGO_TARGET_DIR", test_target_dir)
        .env(
            "RED_TEAM_COMPROMISE_RATE_METRIC_ARTIFACT_ROOT",
            test_artifact_dir,
        )
        .env("RED_TEAM_COMPROMISE_RATE_METRIC_RUN_ID", "test_bd_12vhs")
        .env(
            "RED_TEAM_COMPROMISE_RATE_DISABLE_FRANKENCTL_AUTO_DISCOVERY",
            "true",
        )
        .env_remove("FRANKENENGINE_BIN")
        .output()
        .expect("Failed to execute compromise rate script");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    println!("Script stdout: {}", stdout);
    println!("Script stderr: {}", stderr);

    // The script must fail closed instead of emitting placeholder scenario rows.
    assert!(
        !output.status.success(),
        "Script should fail closed when frankenctl is unavailable, exit code: {:?}, stderr: {}",
        output.status.code(),
        stderr
    );

    // Check that the metric artifact was generated
    let metric_path = format!("{}/test_bd_12vhs/metric_artifact.json", test_artifact_dir);
    let metric_content = std::fs::read_to_string(&metric_path)
        .unwrap_or_else(|e| panic!("Failed to read metric artifact at {}: {}", metric_path, e));

    let metric: Value =
        serde_json::from_str(&metric_content).expect("Failed to parse metric artifact JSON");

    assert_eq!(metric["has_placeholder_data"].as_bool(), Some(false));
    assert_eq!(metric["placeholder_scenario_count"].as_u64(), Some(0));
    assert_eq!(metric["measurement_status"].as_str(), Some("blocked"));
    assert_eq!(metric["confidence_millionths"].as_u64(), Some(0));
    assert_eq!(metric["coverage_millionths"].as_u64(), Some(0));
    assert_eq!(
        metric["blocker_reason"].as_str(),
        Some("frankenctl_unavailable")
    );
    assert!(
        metric["remediation_note"].is_string(),
        "Blocked metric artifact should include remediation guidance"
    );

    // Check that metric report exists and includes proper decision logic
    let report_path = format!("{}/test_bd_12vhs/metric_report.json", test_artifact_dir);
    let report_content =
        std::fs::read_to_string(&report_path).expect("Failed to read metric report");

    let report: Value =
        serde_json::from_str(&report_content).expect("Failed to parse metric report JSON");

    assert_eq!(report["decision"].as_str(), Some("fail_closed"));
    assert_eq!(report["reason"].as_str(), Some("frankenctl_unavailable"));
    assert_eq!(report["scenarios_total"].as_u64(), Some(0));
    assert_eq!(
        report["blocker"]["placeholder_rows_emitted"].as_bool(),
        Some(false)
    );

    let scenarios_path = format!("{}/test_bd_12vhs/scenarios.jsonl", test_artifact_dir);
    let scenarios_content = std::fs::read_to_string(&scenarios_path)
        .unwrap_or_else(|e| panic!("Failed to read scenarios at {}: {}", scenarios_path, e));
    assert!(
        scenarios_content.trim().is_empty(),
        "Blocked bundle must not emit placeholder scenarios: {}",
        scenarios_content
    );

    // Clean up test directory
    let _ = std::fs::remove_dir_all(test_artifact_dir);
    let _ = std::fs::remove_dir_all(test_target_dir);

    println!("Red team compromise rate script refuses placeholder metric rows");
}
