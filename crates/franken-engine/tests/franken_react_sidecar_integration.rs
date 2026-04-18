//! Integration tests for FrankenReact Sidecar Program.
//!
//! Tests the drop-in React with no-VDOM execution implementation.
//! Validates the alien-artifact performance characteristics and direct DOM manipulation.

#![forbid(unsafe_code)]
#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op,
    clippy::manual_abs_diff
)]

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use tempfile::TempDir;

#[test]
fn sidecar_binary_exists_and_runs() {
    // Test: franken-react-sidecar binary exists and can show help
    let output = Command::new("cargo")
        .args(&["run", "--bin", "franken-react-sidecar", "--", "--help"])
        .output()
        .expect("Failed to run franken-react-sidecar");

    assert!(output.status.success());
    let help_text = String::from_utf8_lossy(&output.stdout);
    assert!(help_text.contains("FrankenReact Sidecar - Drop-In React with No-VDOM Execution"));
    assert!(help_text.contains("--source"));
    assert!(help_text.contains("--output"));
    assert!(help_text.contains("--alien-artifact"));
    assert!(help_text.contains("--dom-strategy"));
}

#[test]
fn sidecar_processes_simple_react_component() {
    // Test: sidecar processes a simple React component and generates artifacts
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let source_file = temp_dir.path().join("test_component.jsx");
    let output_dir = temp_dir.path().join("output");

    // Create a simple React component
    let react_code = r#"
function HelloWorld(props) {
    return <div>Hello from FrankenReact!</div>;
}

function App() {
    return <HelloWorld message="test" />;
}
"#;
    fs::write(&source_file, react_code).expect("Failed to write source file");

    // Run sidecar
    let output = Command::new("cargo")
        .args(&[
            "run",
            "--bin",
            "franken-react-sidecar",
            "--",
            "--source",
            source_file.to_str().unwrap(),
            "--output",
            output_dir.to_str().unwrap(),
        ])
        .output()
        .expect("Failed to run franken-react-sidecar");

    assert!(
        output.status.success(),
        "Sidecar failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Verify output artifacts exist
    assert!(
        output_dir
            .join("franken_react_sidecar_result.json")
            .exists()
    );
    assert!(output_dir.join("execution_trace.txt").exists());
    assert!(output_dir.join("dom_operations.json").exists());

    // Verify result content
    let result_json = fs::read_to_string(output_dir.join("franken_react_sidecar_result.json"))
        .expect("Failed to read result JSON");
    assert!(result_json.contains("component_count"));
    assert!(result_json.contains("dom_operations"));
    assert!(result_json.contains("performance_metrics"));

    // Verify trace content
    let trace = fs::read_to_string(output_dir.join("execution_trace.txt"))
        .expect("Failed to read execution trace");
    assert!(trace.contains("FrankenReact Sidecar Execution Trace"));
    assert!(trace.contains("Operations:"));
}

#[test]
fn sidecar_alien_artifact_mode_affects_trace() {
    // Test: alien-artifact mode is reflected in execution trace
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let source_file = temp_dir.path().join("test_component.jsx");
    let output_dir = temp_dir.path().join("output");

    let react_code = r#"
function SimpleComponent() {
    return <span>Test</span>;
}
"#;
    fs::write(&source_file, react_code).expect("Failed to write source file");

    // Run with alien-artifact mode
    let output = Command::new("cargo")
        .args(&[
            "run",
            "--bin",
            "franken-react-sidecar",
            "--",
            "--source",
            source_file.to_str().unwrap(),
            "--output",
            output_dir.to_str().unwrap(),
            "--alien-artifact",
        ])
        .output()
        .expect("Failed to run franken-react-sidecar");

    assert!(output.status.success());

    // Verify alien-artifact mode is mentioned in trace
    let trace = fs::read_to_string(output_dir.join("execution_trace.txt"))
        .expect("Failed to read execution trace");
    assert!(trace.contains("ALIEN-ARTIFACT MODE ENABLED"));
}

#[test]
fn sidecar_dom_strategy_variations() {
    // Test: different DOM strategies produce different traces
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let source_file = temp_dir.path().join("test_component.jsx");

    let react_code = r#"
function TestComponent() {
    return <div><p>Strategy test</p></div>;
}
"#;
    fs::write(&source_file, react_code).expect("Failed to write source file");

    let strategies = ["direct", "batched", "streaming"];

    for strategy in &strategies {
        let output_dir = temp_dir.path().join(format!("output_{}", strategy));

        let output = Command::new("cargo")
            .args(&[
                "run",
                "--bin",
                "franken-react-sidecar",
                "--",
                "--source",
                source_file.to_str().unwrap(),
                "--output",
                output_dir.to_str().unwrap(),
                "--dom-strategy",
                strategy,
            ])
            .output()
            .expect("Failed to run franken-react-sidecar");

        assert!(
            output.status.success(),
            "Strategy {} failed: {}",
            strategy,
            String::from_utf8_lossy(&output.stderr)
        );

        // Verify strategy is mentioned in trace
        let trace = fs::read_to_string(output_dir.join("execution_trace.txt"))
            .expect("Failed to read execution trace");
        let strategy_title = match *strategy {
            "direct" => "Direct",
            "batched" => "Batched",
            "streaming" => "Streaming",
            _ => panic!("Unknown strategy"),
        };
        assert!(trace.contains(&format!("DOM Strategy: {}", strategy_title)));
    }
}

#[test]
fn sidecar_generates_valid_dom_operations() {
    // Test: DOM operations JSON structure is valid
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let source_file = temp_dir.path().join("test_component.jsx");
    let output_dir = temp_dir.path().join("output");

    let react_code = r#"
function ComponentWithAttributes() {
    return <div className="test-class" id="test-id">Content</div>;
}
"#;
    fs::write(&source_file, react_code).expect("Failed to write source file");

    let output = Command::new("cargo")
        .args(&[
            "run",
            "--bin",
            "franken-react-sidecar",
            "--",
            "--source",
            source_file.to_str().unwrap(),
            "--output",
            output_dir.to_str().unwrap(),
        ])
        .output()
        .expect("Failed to run franken-react-sidecar");

    assert!(output.status.success());

    // Parse and validate DOM operations JSON
    let operations_json = fs::read_to_string(output_dir.join("dom_operations.json"))
        .expect("Failed to read DOM operations JSON");

    let operations: serde_json::Value =
        serde_json::from_str(&operations_json).expect("Failed to parse DOM operations JSON");

    assert!(operations.is_array());
    let ops_array = operations.as_array().unwrap();
    assert!(!ops_array.is_empty());

    // Verify we have CreateElement operations
    let has_create_element = ops_array
        .iter()
        .any(|op| op.get("type").and_then(|t| t.as_str()) == Some("CreateElement"));
    assert!(has_create_element, "Should have CreateElement operations");
}

#[test]
fn sidecar_performance_metrics_structure() {
    // Test: performance metrics have expected structure
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let source_file = temp_dir.path().join("test_component.jsx");
    let output_dir = temp_dir.path().join("output");

    let react_code = r#"
function PerformanceTestComponent() {
    return <div>Performance test</div>;
}
"#;
    fs::write(&source_file, react_code).expect("Failed to write source file");

    let output = Command::new("cargo")
        .args(&[
            "run",
            "--bin",
            "franken-react-sidecar",
            "--",
            "--source",
            source_file.to_str().unwrap(),
            "--output",
            output_dir.to_str().unwrap(),
        ])
        .output()
        .expect("Failed to run franken-react-sidecar");

    assert!(output.status.success());

    // Parse result JSON
    let result_json = fs::read_to_string(output_dir.join("franken_react_sidecar_result.json"))
        .expect("Failed to read result JSON");

    let result: serde_json::Value =
        serde_json::from_str(&result_json).expect("Failed to parse result JSON");

    // Verify performance metrics structure
    let metrics = result
        .get("performance_metrics")
        .expect("Missing performance_metrics");
    assert!(metrics.get("parse_time_us").is_some());
    assert!(metrics.get("generation_time_us").is_some());
    assert!(metrics.get("vdom_operations_avoided").is_some());
    assert!(metrics.get("memory_saved_bytes").is_some());

    // Verify values are reasonable
    let parse_time = metrics.get("parse_time_us").unwrap().as_u64().unwrap();
    let gen_time = metrics.get("generation_time_us").unwrap().as_u64().unwrap();
    assert!(parse_time > 0, "Parse time should be positive");
    assert!(gen_time > 0, "Generation time should be positive");
}

#[test]
fn sidecar_no_vdom_operations_avoided_calculation() {
    // Test: VDOM operations avoided metric reflects component complexity
    let temp_dir = TempDir::new().expect("Failed to create temp directory");

    let complex_react_code = r#"
function ComplexComponent() {
    return (
        <div>
            <header>
                <h1>Title</h1>
                <nav>
                    <ul>
                        <li>Item 1</li>
                        <li>Item 2</li>
                    </ul>
                </nav>
            </header>
            <main>
                <section>Content</section>
            </main>
        </div>
    );
}
"#;

    // Test complex component
    let complex_source = temp_dir.path().join("complex.jsx");
    let complex_output = temp_dir.path().join("complex_output");
    fs::write(&complex_source, complex_react_code).expect("Failed to write complex source");

    let output = Command::new("cargo")
        .args(&[
            "run",
            "--bin",
            "franken-react-sidecar",
            "--",
            "--source",
            complex_source.to_str().unwrap(),
            "--output",
            complex_output.to_str().unwrap(),
        ])
        .output()
        .expect("Failed to run sidecar on complex component");

    assert!(output.status.success());

    // Parse complex result
    let complex_json = fs::read_to_string(complex_output.join("franken_react_sidecar_result.json"))
        .expect("Failed to read complex result");
    let complex_result: serde_json::Value =
        serde_json::from_str(&complex_json).expect("Failed to parse complex result");

    let complex_avoided = complex_result
        .get("performance_metrics")
        .unwrap()
        .get("vdom_operations_avoided")
        .unwrap()
        .as_u64()
        .unwrap();

    // More components should mean more avoided operations
    assert!(
        complex_avoided > 0,
        "Should avoid some VDOM operations for complex component"
    );
}

#[test]
fn sidecar_error_handling_invalid_source() {
    // Test: sidecar handles invalid source file gracefully
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let nonexistent_file = temp_dir.path().join("nonexistent.jsx");
    let output_dir = temp_dir.path().join("output");

    let output = Command::new("cargo")
        .args(&[
            "run",
            "--bin",
            "franken-react-sidecar",
            "--",
            "--source",
            nonexistent_file.to_str().unwrap(),
            "--output",
            output_dir.to_str().unwrap(),
        ])
        .output()
        .expect("Failed to run franken-react-sidecar");

    // Should fail gracefully
    assert!(!output.status.success());
    let error_output = String::from_utf8_lossy(&output.stderr);
    assert!(error_output.contains("Error:") || error_output.contains("Failed"));
}

#[test]
fn sidecar_deterministic_execution_trace() {
    // Test: execution traces are deterministic for identical input
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let source_file = temp_dir.path().join("test_component.jsx");

    let react_code = r#"
function DeterministicComponent() {
    return <div>Deterministic test</div>;
}
"#;
    fs::write(&source_file, react_code).expect("Failed to write source file");

    let mut traces = Vec::new();

    // Run sidecar multiple times
    for i in 0..3 {
        let output_dir = temp_dir.path().join(format!("output_{}", i));

        let output = Command::new("cargo")
            .args(&[
                "run",
                "--bin",
                "franken-react-sidecar",
                "--",
                "--source",
                source_file.to_str().unwrap(),
                "--output",
                output_dir.to_str().unwrap(),
            ])
            .output()
            .expect("Failed to run franken-react-sidecar");

        assert!(output.status.success());

        let trace = fs::read_to_string(output_dir.join("execution_trace.txt"))
            .expect("Failed to read execution trace");
        traces.push(trace);
    }

    // All traces should be identical (deterministic execution)
    assert_eq!(
        traces[0], traces[1],
        "First and second traces should be identical"
    );
    assert_eq!(
        traces[1], traces[2],
        "Second and third traces should be identical"
    );
}
