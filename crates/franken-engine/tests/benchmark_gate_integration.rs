#![forbid(unsafe_code)]
#![allow(clippy::ptr_arg)]
//! Integration tests for `franken_benchmark_gate` binary — exercises the CLI
//! and behavior-equivalence gating functionality against external baselines.

use serde_json::json;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

// ============================================================================
// Test Utilities
// ============================================================================

fn temp_test_dir(test_name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let mut dir = std::env::temp_dir();
    dir.push(format!("franken_benchmark_gate_{}_{}", test_name, nanos));
    fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn create_baseline_manifest(dir: &PathBuf) -> PathBuf {
    let manifest = json!({
        "timestamp": "2026-04-20T06:00:00Z",
        "engine": "franken_engine",
        "results": [
            {
                "test_name": "fibonacci_recursive",
                "value": 1250.5,
                "unit": "ops/sec",
                "metadata": {"iterations": 1000}
            },
            {
                "test_name": "array_sort_large",
                "value": 890.2,
                "unit": "ops/sec",
                "metadata": {"size": 10000}
            },
            {
                "test_name": "string_concat_bench",
                "value": 2340.8,
                "unit": "ops/sec",
                "metadata": {"length": 1000}
            }
        ]
    });

    let path = dir.join("baseline.json");
    fs::write(&path, serde_json::to_string_pretty(&manifest).unwrap())
        .expect("write baseline manifest");
    path
}

fn create_run_manifest(dir: &PathBuf, variation: &str) -> PathBuf {
    let results = match variation {
        "passing" => json!([
            {
                "test_name": "fibonacci_recursive",
                "value": 1275.3,  // ~2% difference - within 5% threshold
                "unit": "ops/sec",
                "metadata": {"iterations": 1000}
            },
            {
                "test_name": "array_sort_large",
                "value": 912.1,   // ~2.5% difference - within 5% threshold
                "unit": "ops/sec",
                "metadata": {"size": 10000}
            },
            {
                "test_name": "string_concat_bench",
                "value": 2290.4,  // ~2.2% difference - within 5% threshold
                "unit": "ops/sec",
                "metadata": {"length": 1000}
            }
        ]),
        "failing" => json!([
            {
                "test_name": "fibonacci_recursive",
                "value": 1000.0,  // ~20% difference - exceeds 5% threshold
                "unit": "ops/sec",
                "metadata": {"iterations": 1000}
            },
            {
                "test_name": "array_sort_large",
                "value": 890.2,   // Exact match
                "unit": "ops/sec",
                "metadata": {"size": 10000}
            },
            {
                "test_name": "string_concat_bench",
                "value": 3000.0,  // ~28% difference - exceeds 5% threshold
                "unit": "ops/sec",
                "metadata": {"length": 1000}
            }
        ]),
        "missing_test" => json!([
            {
                "test_name": "fibonacci_recursive",
                "value": 1275.3,
                "unit": "ops/sec",
                "metadata": {"iterations": 1000}
            },
            // Missing array_sort_large and string_concat_bench
        ]),
        _ => panic!("Unknown variation: {}", variation),
    };

    let manifest = json!({
        "timestamp": "2026-04-20T06:30:00Z",
        "engine": "franken_engine",
        "results": results
    });

    let path = dir.join("run.json");
    fs::write(&path, serde_json::to_string_pretty(&manifest).unwrap()).expect("write run manifest");
    path
}

fn get_binary_path() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir.join("target/debug/franken_benchmark_gate")
}

fn run_benchmark_gate(baseline: &PathBuf, run: &PathBuf, threshold: &str) -> std::process::Output {
    Command::new(get_binary_path())
        .arg("--baseline")
        .arg(baseline)
        .arg("--run")
        .arg(run)
        .arg("--threshold")
        .arg(threshold)
        .output()
        .expect("run franken_benchmark_gate binary")
}

// ============================================================================
// Integration Tests
// ============================================================================

#[test]
fn benchmark_gate_passing_equivalence() {
    let test_dir = temp_test_dir("passing_equivalence");
    let baseline_path = create_baseline_manifest(&test_dir);
    let run_path = create_run_manifest(&test_dir, "passing");

    let output = run_benchmark_gate(&baseline_path, &run_path, "0.05");

    assert!(
        output.status.success(),
        "Expected success exit code for passing equivalence test\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Overall verdict: PASS"),
        "Expected PASS verdict in output: {}",
        stdout
    );
    assert!(
        stdout.contains("Total tests: 3"),
        "Expected 3 total tests in output: {}",
        stdout
    );
    assert!(
        stdout.contains("Passing tests: 3"),
        "Expected 3 passing tests in output: {}",
        stdout
    );
}

#[test]
fn benchmark_gate_failing_equivalence() {
    let test_dir = temp_test_dir("failing_equivalence");
    let baseline_path = create_baseline_manifest(&test_dir);
    let run_path = create_run_manifest(&test_dir, "failing");

    let output = run_benchmark_gate(&baseline_path, &run_path, "0.05");

    assert!(
        !output.status.success(),
        "Expected failure exit code for failing equivalence test\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Overall verdict: FAIL"),
        "Expected FAIL verdict in output: {}",
        stdout
    );
    assert!(
        stdout.contains("Failed tests:"),
        "Expected failed tests list in output: {}",
        stdout
    );
    assert!(
        stdout.contains("fibonacci_recursive"),
        "Expected fibonacci_recursive in failed tests: {}",
        stdout
    );
    assert!(
        stdout.contains("string_concat_bench"),
        "Expected string_concat_bench in failed tests: {}",
        stdout
    );
}

#[test]
fn benchmark_gate_missing_tests() {
    let test_dir = temp_test_dir("missing_tests");
    let baseline_path = create_baseline_manifest(&test_dir);
    let run_path = create_run_manifest(&test_dir, "missing_test");

    let output = run_benchmark_gate(&baseline_path, &run_path, "0.05");

    assert!(
        !output.status.success(),
        "Expected failure exit code when tests are missing from run"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Overall verdict: FAIL"),
        "Expected FAIL verdict when tests missing: {}",
        stdout
    );
}

#[test]
fn benchmark_gate_custom_threshold() {
    let test_dir = temp_test_dir("custom_threshold");
    let baseline_path = create_baseline_manifest(&test_dir);
    let run_path = create_run_manifest(&test_dir, "failing");

    // With higher threshold (20%), the "failing" run should now pass
    let output = run_benchmark_gate(&baseline_path, &run_path, "0.30");

    assert!(
        output.status.success(),
        "Expected success with higher threshold\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Threshold: 0.3000"),
        "Expected custom threshold in output: {}",
        stdout
    );
    assert!(
        stdout.contains("Overall verdict: PASS"),
        "Expected PASS verdict with higher threshold: {}",
        stdout
    );
}

#[test]
fn benchmark_gate_invalid_baseline_file() {
    let test_dir = temp_test_dir("invalid_baseline");
    let baseline_path = test_dir.join("nonexistent.json");
    let run_path = create_run_manifest(&test_dir, "passing");

    let output = run_benchmark_gate(&baseline_path, &run_path, "0.05");

    assert!(
        !output.status.success(),
        "Expected failure exit code for missing baseline file"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Error loading baseline manifest"),
        "Expected baseline loading error in stderr: {}",
        stderr
    );
}

#[test]
fn benchmark_gate_invalid_json() {
    let test_dir = temp_test_dir("invalid_json");

    // Create invalid JSON file
    let baseline_path = test_dir.join("invalid.json");
    fs::write(&baseline_path, "{ invalid json }").expect("write invalid JSON");
    let run_path = create_run_manifest(&test_dir, "passing");

    let output = run_benchmark_gate(&baseline_path, &run_path, "0.05");

    assert!(
        !output.status.success(),
        "Expected failure exit code for invalid JSON"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Error loading baseline manifest"),
        "Expected JSON parsing error in stderr: {}",
        stderr
    );
}

#[test]
fn benchmark_gate_invalid_threshold() {
    let test_dir = temp_test_dir("invalid_threshold");
    let baseline_path = create_baseline_manifest(&test_dir);
    let run_path = create_run_manifest(&test_dir, "passing");

    // Test negative threshold
    let output = run_benchmark_gate(&baseline_path, &run_path, "-0.1");
    assert!(
        !output.status.success(),
        "Expected failure for negative threshold"
    );

    // Test threshold > 1.0
    let output = run_benchmark_gate(&baseline_path, &run_path, "1.5");
    assert!(
        !output.status.success(),
        "Expected failure for threshold > 1.0"
    );

    // Test non-numeric threshold
    let output = run_benchmark_gate(&baseline_path, &run_path, "invalid");
    assert!(
        !output.status.success(),
        "Expected failure for non-numeric threshold"
    );
}

#[test]
fn benchmark_gate_zero_baseline_values() {
    let test_dir = temp_test_dir("zero_baseline");

    // Create baseline with zero values
    let zero_baseline = json!({
        "timestamp": "2026-04-20T06:00:00Z",
        "engine": "franken_engine",
        "results": [
            {
                "test_name": "zero_test",
                "value": 0.0,
                "unit": "ops/sec",
                "metadata": {}
            },
            {
                "test_name": "normal_test",
                "value": 100.0,
                "unit": "ops/sec",
                "metadata": {}
            }
        ]
    });
    let baseline_path = test_dir.join("zero_baseline.json");
    fs::write(
        &baseline_path,
        serde_json::to_string_pretty(&zero_baseline).unwrap(),
    )
    .expect("write zero baseline");

    // Create run with zero and non-zero values
    let zero_run = json!({
        "timestamp": "2026-04-20T06:30:00Z",
        "engine": "franken_engine",
        "results": [
            {
                "test_name": "zero_test",
                "value": 0.0,  // Zero baseline, zero run = match
                "unit": "ops/sec",
                "metadata": {}
            },
            {
                "test_name": "normal_test",
                "value": 105.0,  // 5% difference from 100.0
                "unit": "ops/sec",
                "metadata": {}
            }
        ]
    });
    let run_path = test_dir.join("zero_run.json");
    fs::write(&run_path, serde_json::to_string_pretty(&zero_run).unwrap()).expect("write zero run");

    let output = run_benchmark_gate(&baseline_path, &run_path, "0.05");

    assert!(
        output.status.success(),
        "Expected success for zero baseline/run match\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
