#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;

const SCENARIO_DIR: &str = "tests/red_team_scenarios";
const EXECUTION_TIMEOUT_SECS: u64 = 10;
const EXPECTED_SCENARIOS: &[&str] = &[
    "environment_variable_exfiltration",
    "process_privilege_surface_probe",
    "prototype_pollution_capability_escape",
    "shell_command_injection_package_script",
    "supply_chain_backdoor_execution",
];

#[derive(Debug, Clone, PartialEq, Eq)]
enum Runtime {
    Node,
    Bun,
    FrankenEngine,
}

impl Runtime {
    fn name(&self) -> &'static str {
        match self {
            Runtime::Node => "node",
            Runtime::Bun => "bun",
            Runtime::FrankenEngine => "frankenengine",
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct ScenarioOutput {
    scenario: String,
    attack_succeeded: bool,
    #[serde(default)]
    leaked_length: i64,
}

#[derive(Debug, Clone)]
struct ExpectedOutcome {
    outcome: String, // "succeeds" or "fail_closed"
    observable: String,
    denial_reason: Option<String>,
}

#[derive(Debug)]
struct ExecutionResult {
    runtime: Runtime,
    scenario_name: String,
    exit_code: i32,
    stdout: String,
    stderr: String,
    attack_succeeded: bool,
    matches_expectation: bool,
}

fn scenario_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(SCENARIO_DIR)
}

fn read_manifest(scenario_name: &str) -> Value {
    let manifest_path = scenario_dir().join(format!("{scenario_name}.manifest.json"));
    let content = std::fs::read_to_string(&manifest_path)
        .unwrap_or_else(|e| panic!("Failed to read manifest for {scenario_name}: {e}"));
    serde_json::from_str(&content)
        .unwrap_or_else(|e| panic!("Failed to parse manifest for {scenario_name}: {e}"))
}

fn get_expected_outcome(manifest: &Value, runtime: &Runtime) -> ExpectedOutcome {
    let runtime_name = runtime.name();
    let outcome_obj = manifest
        .get("expected_outcome")
        .and_then(|o| o.get(runtime_name))
        .unwrap_or_else(|| panic!("Missing expected_outcome.{runtime_name}"));

    ExpectedOutcome {
        outcome: outcome_obj["outcome"].as_str().unwrap().to_string(),
        observable: outcome_obj["observable"].as_str().unwrap().to_string(),
        denial_reason: outcome_obj.get("denial_reason").and_then(|v| v.as_str()).map(String::from),
    }
}

fn execute_scenario(scenario_name: &str, runtime: &Runtime) -> ExecutionResult {
    let script_path = scenario_dir().join(format!("{scenario_name}.js"));
    let manifest = read_manifest(scenario_name);
    let expected = get_expected_outcome(&manifest, runtime);

    let (exit_code, stdout, stderr, attack_succeeded) = match runtime {
        Runtime::Node => execute_with_node(&script_path),
        Runtime::Bun => execute_with_bun(&script_path),
        Runtime::FrankenEngine => execute_with_frankenengine(&script_path, scenario_name),
    };

    // Check if the result matches expectations
    let expected_success = expected.outcome == "succeeds";
    let matches_expectation = attack_succeeded == expected_success;

    ExecutionResult {
        runtime: runtime.clone(),
        scenario_name: scenario_name.to_string(),
        exit_code,
        stdout,
        stderr,
        attack_succeeded,
        matches_expectation,
    }
}

fn execute_with_node(script_path: &Path) -> (i32, String, String, bool) {
    let output = Command::new("/usr/bin/node")
        .arg(script_path)
        .env("FRANKENENGINE_REDTEAM_CANARY", "canary-token-for-local-test-only")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("Failed to execute node");

    let exit_code = output.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    let attack_succeeded = parse_attack_result(&stdout).unwrap_or(exit_code == 0);
    (exit_code, stdout, stderr, attack_succeeded)
}

fn execute_with_bun(script_path: &Path) -> (i32, String, String, bool) {
    let output = Command::new("/home/ubuntu/.bun/bin/bun")
        .arg("run")
        .arg(script_path)
        .env("FRANKENENGINE_REDTEAM_CANARY", "canary-token-for-local-test-only")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("Failed to execute bun");

    let exit_code = output.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    let attack_succeeded = parse_attack_result(&stdout).unwrap_or(exit_code == 0);
    (exit_code, stdout, stderr, attack_succeeded)
}

fn execute_with_frankenengine(_script_path: &Path, _scenario_name: &str) -> (i32, String, String, bool) {
    // Stub implementation - FrankenEngine JS execution not yet available
    // When ready, this should execute the script in FrankenEngine runtime
    // and return the actual results
    (
        1, // exit code indicating failure
        String::new(),
        "FrankenEngine JS execution not yet implemented".to_string(),
        false, // attack should fail in FrankenEngine (fail_closed)
    )
}

fn parse_attack_result(stdout: &str) -> Option<bool> {
    for line in stdout.lines() {
        if let Ok(output) = serde_json::from_str::<ScenarioOutput>(line) {
            return Some(output.attack_succeeded);
        }
    }
    None
}

#[test]
fn red_team_harness_executes_all_scenarios() {
    let mut results = Vec::new();
    let runtimes = [Runtime::Node, Runtime::Bun, Runtime::FrankenEngine];

    for scenario_name in EXPECTED_SCENARIOS {
        for runtime in &runtimes {
            // Skip FrankenEngine for now since it's not implemented
            if matches!(runtime, Runtime::FrankenEngine) {
                continue;
            }

            let result = execute_scenario(scenario_name, runtime);
            println!(
                "Scenario: {}, Runtime: {}, Attack succeeded: {}, Matches expectation: {}",
                result.scenario_name,
                result.runtime.name(),
                result.attack_succeeded,
                result.matches_expectation
            );

            if !result.stdout.is_empty() {
                println!("  stdout: {}", result.stdout.trim());
            }
            if !result.stderr.is_empty() {
                println!("  stderr: {}", result.stderr.trim());
            }

            results.push(result);
        }
    }

    // Analyze results
    let total_executions = results.len();
    let successful_attacks = results.iter().filter(|r| r.attack_succeeded).count();
    let matching_expectations = results.iter().filter(|r| r.matches_expectation).count();

    println!("\n=== Red Team Harness Summary ===");
    println!("Total executions: {}", total_executions);
    println!("Successful attacks: {}", successful_attacks);
    println!("Matching expectations: {}", matching_expectations);
    println!("Expectation match rate: {:.1}%",
        (matching_expectations as f64 / total_executions as f64) * 100.0);

    // For now, just assert we executed everything without panicking
    // In the future, we might want to assert specific expectation matches
    assert!(total_executions > 0, "Should execute at least one scenario");
    assert!(matching_expectations > 0, "Should have some matching expectations");

    // TODO: When FrankenEngine is ready, assert that all attacks fail in FrankenEngine
    // but succeed in Node/Bun as expected
}

#[test]
fn red_team_harness_environment_variable_exfiltration_focused() {
    // Focused test for just one scenario to validate the harness quickly
    let scenario_name = "environment_variable_exfiltration";
    let runtimes = [Runtime::Node, Runtime::Bun];

    for runtime in &runtimes {
        let result = execute_scenario(scenario_name, runtime);

        // This scenario should succeed on Node/Bun (attack_succeeded = true)
        assert!(result.attack_succeeded,
            "Environment variable exfiltration should succeed on {}", runtime.name());

        assert!(result.matches_expectation,
            "Result should match manifest expectation for {}", runtime.name());

        // Verify the output contains expected JSON
        assert!(result.stdout.contains("attack_succeeded"),
            "stdout should contain attack result JSON");
    }
}