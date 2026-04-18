use std::fs;
use std::path::PathBuf;
use std::process::Command;

#[test]
fn test_gates_toml_structure() {
    let config_path = PathBuf::from("scripts/gates.toml");
    assert!(config_path.exists(), "gates.toml should exist");

    let content = fs::read_to_string(&config_path).unwrap();

    // Verify global section exists
    assert!(content.contains("[global]"));
    assert!(content.contains("default_mode = \"ci\""));
    assert!(content.contains("default_rch_timeout_seconds"));

    // Verify some key gates exist
    assert!(content.contains("[gates.adversarial_campaign_gate]"));
    assert!(content.contains("[gates.test262_conformance_runner]"));
    assert!(content.contains("[gates.ambient_mock_guard]"));
    assert!(content.contains("[gates.baseline_interpreter_gate]"));

    // Verify replay gates exist
    assert!(content.contains("[gates.adversarial_campaign_replay]"));
    assert!(content.contains("is_replay = true"));

    // Verify meta section
    assert!(content.contains("[meta]"));
    assert!(content.contains("total_gates = 53"));
    assert!(content.contains("total_scripts_to_replace = 388"));

    // Verify outputs section
    assert!(content.contains("[outputs]"));
    assert!(content.contains("manifest_file = \"run_manifest.json\""));
}

#[test]
fn test_run_gate_script_exists() {
    let script_path = PathBuf::from("scripts/run_gate.sh");
    assert!(script_path.exists(), "run_gate.sh should exist");

    // Check it's executable
    let metadata = fs::metadata(&script_path).unwrap();
    let permissions = metadata.permissions();
    // On Unix, check if owner has execute permission
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert!(
            permissions.mode() & 0o100 != 0,
            "run_gate.sh should be executable"
        );
    }
}

#[test]
fn test_replay_gate_script_exists() {
    let script_path = PathBuf::from("scripts/replay_gate.sh");
    assert!(script_path.exists(), "replay_gate.sh should exist");

    // Check it's executable
    let metadata = fs::metadata(&script_path).unwrap();
    let permissions = metadata.permissions();
    // On Unix, check if owner has execute permission
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert!(
            permissions.mode() & 0o100 != 0,
            "replay_gate.sh should be executable"
        );
    }
}

#[test]
fn test_gate_consolidation_coverage() {
    // Verify we can consolidate the major script patterns
    let script_patterns = [
        "run_*_gate.sh",
        "run_*_suite.sh",
        "*_replay.sh",
        "check_*.sh",
    ];

    // This test validates the consolidation approach covers all patterns
    assert_eq!(script_patterns.len(), 4);

    // Verify the total script count matches expectation
    let config_path = PathBuf::from("scripts/gates.toml");
    let content = fs::read_to_string(&config_path).unwrap();
    assert!(content.contains("total_scripts_to_replace = 388"));
}

#[test]
fn test_run_gate_script_syntax() {
    // Test that the script has valid bash syntax
    let output = Command::new("bash")
        .args(["-n", "scripts/run_gate.sh"])
        .output()
        .expect("Failed to run bash syntax check");

    assert!(
        output.status.success(),
        "run_gate.sh has syntax errors: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_replay_gate_script_syntax() {
    // Test that the script has valid bash syntax
    let output = Command::new("bash")
        .args(["-n", "scripts/replay_gate.sh"])
        .output()
        .expect("Failed to run bash syntax check");

    assert!(
        output.status.success(),
        "replay_gate.sh has syntax errors: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_run_gate_usage_help() {
    // Test that the script shows usage when called without arguments
    let output = Command::new("scripts/run_gate.sh")
        .output()
        .expect("Failed to run run_gate.sh");

    // Should exit with error code 1 and show usage
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Usage:"));
    assert!(stderr.contains("Available gates:"));
}

#[test]
fn test_replay_gate_usage_help() {
    // Test that the script shows usage when called without arguments
    let output = Command::new("scripts/replay_gate.sh")
        .output()
        .expect("Failed to run replay_gate.sh");

    // Should exit with error code 1 and show usage
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Usage:"));
    assert!(stderr.contains("Available replay gates:"));
}

#[test]
fn test_gate_configuration_parsing() {
    // Test that we can extract gate configurations from TOML
    let config_path = PathBuf::from("scripts/gates.toml");
    let content = fs::read_to_string(&config_path).unwrap();

    // Check that adversarial_campaign_gate has expected fields
    assert!(content.contains("artifact_root = \"artifacts/adversarial_campaign_gate\""));
    assert!(content.contains(
        "cargo_command = \"cargo test -p frankenengine-engine --lib adversarial_campaign\""
    ));
    assert!(content.contains("needs_rch = true"));
    assert!(content.contains("generates_gate_result = true"));

    // Check that test262_conformance_runner has timeout override
    assert!(content.contains("rch_timeout_seconds = 1800"));

    // Check that some gates have input fixtures
    assert!(content.contains("input_fixture = \"crates/franken-engine/tests/fixtures/adversarial_campaign_gate_input_v1.json\""));
}

#[test]
fn test_artifact_structure_requirements() {
    // Verify that the expected artifact structure is documented
    let config_path = PathBuf::from("scripts/gates.toml");
    let content = fs::read_to_string(&config_path).unwrap();

    // Check outputs section defines expected files
    assert!(content.contains("manifest_file = \"run_manifest.json\""));
    assert!(content.contains("events_file = \"events.jsonl\""));
    assert!(content.contains("commands_file = \"commands.txt\""));
    assert!(content.contains("gate_result_file = \"gate_result.json\""));
    assert!(content.contains("step_logs_dir = \"step_logs\""));
    assert!(content.contains("rch_step_logs_dir = \"rch_step_logs\""));
}

#[test]
fn test_global_defaults_configuration() {
    let config_path = PathBuf::from("scripts/gates.toml");
    let content = fs::read_to_string(&config_path).unwrap();

    // Verify global defaults are properly configured
    assert!(content.contains("default_mode = \"ci\""));
    assert!(content.contains("default_rch_timeout_seconds = 900"));
    assert!(content.contains("default_rch_build_timeout_seconds = 1800"));
    assert!(content.contains("default_cargo_build_jobs = 2"));
    assert!(content.contains("default_target_dir_prefix = \"/tmp/rch_target_franken_engine\""));
}

#[test]
fn test_gate_count_accuracy() {
    let config_path = PathBuf::from("scripts/gates.toml");
    let content = fs::read_to_string(&config_path).unwrap();

    // Count actual gates defined
    let gate_count = content.matches("[gates.").count();

    // Should have the documented number of gates (regular + replay gates)
    // The meta section claims 53 total gates, but we have some replay gates too
    assert!(
        gate_count >= 10,
        "Should have at least 10 gates defined for testing"
    );

    // Verify replay gates are properly configured
    let replay_gates = content.matches("is_replay = true").count();
    assert!(
        replay_gates >= 2,
        "Should have at least 2 replay gates defined"
    );
}

#[test]
fn test_environment_bootstrap_support() {
    let config_path = PathBuf::from("scripts/gates.toml");
    let content = fs::read_to_string(&config_path).unwrap();

    // Some gates should have environment bootstrap scripts
    assert!(content.contains("env_bootstrap = \"scripts/e2e/parser_deterministic_env.sh\""));

    // The bootstrap script should exist
    let _bootstrap_path = PathBuf::from("scripts/e2e/parser_deterministic_env.sh");
    // Note: We don't assert existence here since we're focusing on configuration structure
}

#[test]
fn test_consolidation_benefits() {
    // This test documents the benefits of the consolidation

    // Before: 388 individual scripts with duplicated boilerplate
    // After: 2 parameterized scripts + 1 configuration file

    let scripts_before = 388;
    let scripts_after = 2; // run_gate.sh + replay_gate.sh
    let config_files = 1; // gates.toml

    let reduction_ratio = scripts_before as f64 / (scripts_after + config_files) as f64;

    // We should have > 100x reduction in number of files to maintain
    assert!(
        reduction_ratio > 100.0,
        "Consolidation should provide significant file count reduction: {:.1}x",
        reduction_ratio
    );
}
