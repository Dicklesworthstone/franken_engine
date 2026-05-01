#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde::{Deserialize, Serialize};
use serde_json::Value;

const SCENARIO_DIR: &str = "tests/red_team_scenarios";
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
}

#[derive(Debug)]
struct ExecutionResult {
    runtime: Runtime,
    scenario_name: String,
    exit_code: i32,
    stdout: String,
    stderr: String,
    structured_log: String,
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
    let structured_log = if matches!(runtime, Runtime::FrankenEngine) {
        extract_frankenengine_structured_log(&stdout, &stderr).unwrap_or_default()
    } else {
        String::new()
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
        structured_log,
        attack_succeeded,
        matches_expectation,
    }
}

fn execute_with_node(script_path: &Path) -> (i32, String, String, bool) {
    let output = Command::new("/usr/bin/node")
        .arg(script_path)
        .env(
            "FRANKENENGINE_REDTEAM_CANARY",
            "canary-token-for-local-test-only",
        )
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
        .env(
            "FRANKENENGINE_REDTEAM_CANARY",
            "canary-token-for-local-test-only",
        )
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

fn execute_with_frankenengine(
    script_path: &Path,
    scenario_name: &str,
) -> (i32, String, String, bool) {
    let report_path = std::env::temp_dir().join(format!(
        "frankenengine-red-team-{scenario_name}-{}.json",
        std::process::id()
    ));
    let output = Command::new(frankenctl_binary())
        .arg("run")
        .arg("--input")
        .arg(script_path)
        .arg("--extension-id")
        .arg(format!("red-team-{scenario_name}"))
        .arg("--goal")
        .arg("script")
        .arg("--out")
        .arg(&report_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("Failed to execute frankenctl run");

    let exit_code = output.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let mut stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let report_content = std::fs::read_to_string(&report_path).ok();
    if let Some(report) = &report_content {
        stderr.push_str("\n[frankenengine-structured-log]\n");
        stderr.push_str(&report);
    }

    let attack_succeeded = parse_attack_result(&stdout)
        .or_else(|| parse_frankenctl_attack_result(&stdout))
        .or_else(|| {
            report_content
                .as_deref()
                .and_then(parse_frankenctl_attack_result)
        })
        .unwrap_or(false);
    (exit_code, stdout, stderr, attack_succeeded)
}

fn parse_attack_result(stdout: &str) -> Option<bool> {
    for line in stdout.lines() {
        if let Ok(output) = serde_json::from_str::<ScenarioOutput>(line) {
            return Some(output.attack_succeeded);
        }
    }
    None
}

fn frankenctl_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_frankenctl"))
}

fn parse_frankenctl_report(stdout: &str) -> Option<String> {
    let value = serde_json::from_str::<Value>(stdout).ok()?;
    serde_json::to_string(&value).ok()
}

fn extract_frankenengine_structured_log(stdout: &str, stderr: &str) -> Option<String> {
    if let Some((_, report)) = stderr.split_once("[frankenengine-structured-log]\n") {
        let report = report.trim();
        return serde_json::from_str::<Value>(report)
            .ok()
            .and_then(|value| serde_json::to_string(&value).ok())
            .or_else(|| Some(report.to_string()));
    }
    parse_frankenctl_report(stdout)
}

fn parse_frankenctl_attack_result(stdout: &str) -> Option<bool> {
    let value = serde_json::from_str::<Value>(stdout).ok()?;
    value
        .get("console_output")
        .and_then(Value::as_array)
        .and_then(|lines| {
            lines.iter().find_map(|line| {
                let line = line.as_str()?;
                serde_json::from_str::<ScenarioOutput>(line)
                    .ok()
                    .map(|output| output.attack_succeeded)
            })
        })
}

#[test]
fn red_team_harness_executes_all_scenarios() {
    let mut results = Vec::new();
    let runtimes = [Runtime::Node, Runtime::Bun, Runtime::FrankenEngine];

    for scenario_name in EXPECTED_SCENARIOS {
        for runtime in &runtimes {
            let result = execute_scenario(scenario_name, runtime);
            println!(
                "Scenario: {}, Runtime: {}, Exit code: {}, Attack succeeded: {}, Matches expectation: {}",
                result.scenario_name,
                result.runtime.name(),
                result.exit_code,
                result.attack_succeeded,
                result.matches_expectation
            );

            if !result.stdout.is_empty() {
                println!("  stdout: {}", result.stdout.trim());
            }
            if !result.stderr.is_empty() {
                println!("  stderr: {}", result.stderr.trim());
            }
            if !result.structured_log.is_empty() {
                println!("  structured_log: {}", result.structured_log.trim());
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
    println!(
        "Expectation match rate: {:.1}%",
        (matching_expectations as f64 / total_executions as f64) * 100.0
    );

    assert_eq!(
        total_executions,
        EXPECTED_SCENARIOS.len() * 3,
        "Should execute every scenario across Node, Bun, and FrankenEngine"
    );
    assert!(
        matching_expectations > 0,
        "Should have some matching expectations"
    );
    assert!(
        results
            .iter()
            .filter(|result| result.runtime == Runtime::FrankenEngine)
            .all(|result| !result.attack_succeeded && result.matches_expectation),
        "FrankenEngine red-team arm should execute all scenarios and fail closed"
    );
}

#[test]
fn red_team_harness_environment_variable_exfiltration_focused() {
    // Focused test for just one scenario to validate the harness quickly
    let scenario_name = "environment_variable_exfiltration";
    let runtimes = [Runtime::Node, Runtime::Bun];

    for runtime in &runtimes {
        let result = execute_scenario(scenario_name, runtime);

        // This scenario should succeed on Node/Bun (attack_succeeded = true)
        assert!(
            result.attack_succeeded,
            "Environment variable exfiltration should succeed on {}",
            runtime.name()
        );

        assert!(
            result.matches_expectation,
            "Result should match manifest expectation for {}",
            runtime.name()
        );

        // Verify the output contains expected JSON
        assert!(
            result.stdout.contains("attack_succeeded"),
            "stdout should contain attack result JSON"
        );
    }
}
