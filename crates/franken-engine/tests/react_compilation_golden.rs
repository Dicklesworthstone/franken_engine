//! Golden tests for React JSX→JS compilation output.
//!
//! These tests capture known-good React compilation outputs and compare them against current outputs
//! to detect compilation changes that could alter generated JS output, breaking existing applications.
//!
//! Test pattern: Run JSX inputs through the React lowering pipeline, serialize outputs as JSON,
//! and compare against frozen golden files for exact regression detection.

#![forbid(unsafe_code)]

use std::fs;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use frankenengine_engine::jsx_tsx_parser::{JsxNode, JsxParserConfig, JsxRuntimeMode, parse_jsx};
use frankenengine_engine::react_jsx_lowering::{
    BuildMode, ReactLoweringConfig, ReactLoweringResult, lower_jsx_to_react,
};

/// Test case configuration for React compilation golden tests.
#[derive(Debug, Clone)]
struct ReactCompilationTestCase {
    /// Test case name for golden file
    name: &'static str,
    /// JSX source input to compile
    jsx_source: &'static str,
    /// React runtime mode to use
    runtime_mode: JsxRuntimeMode,
    /// Whether this is a dev build
    is_dev: bool,
}

/// Serializable golden fixture format.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ReactCompilationFixture {
    /// Test case name
    test_name: String,
    /// Input JSX (serialized)
    input_jsx: JsxNode,
    /// Lowering configuration used
    config: ReactLoweringConfig,
    /// Compilation result
    result: ReactLoweringResult,
    /// Schema version for compatibility
    schema_version: String,
}

impl ReactCompilationTestCase {
    const fn new(
        name: &'static str,
        jsx_source: &'static str,
        runtime_mode: JsxRuntimeMode,
        is_dev: bool,
    ) -> Self {
        Self {
            name,
            jsx_source,
            runtime_mode,
            is_dev,
        }
    }
}

/// Test cases for React compilation golden tests.
fn react_compilation_test_cases() -> Vec<ReactCompilationTestCase> {
    vec![
        // Simple div element - classic mode
        ReactCompilationTestCase::new(
            "simple_div_classic",
            "<div>Hello</div>",
            JsxRuntimeMode::Classic,
            false,
        ),
        // Simple div element - automatic mode
        ReactCompilationTestCase::new(
            "simple_div_automatic",
            "<div>Hello</div>",
            JsxRuntimeMode::Automatic,
            false,
        ),
        // Component with props - classic mode
        ReactCompilationTestCase::new(
            "component_with_props_classic",
            r#"<button type="submit" disabled="true" />"#,
            JsxRuntimeMode::Classic,
            false,
        ),
        // Component with props - automatic mode
        ReactCompilationTestCase::new(
            "component_with_props_automatic",
            r#"<input type="text" placeholder="Enter text" />"#,
            JsxRuntimeMode::Automatic,
            false,
        ),
        // React component - classic mode
        ReactCompilationTestCase::new(
            "react_component_classic",
            "<MyComponent>Content</MyComponent>",
            JsxRuntimeMode::Classic,
            false,
        ),
        // React component - automatic mode
        ReactCompilationTestCase::new(
            "react_component_automatic",
            "<UserProfile>Profile</UserProfile>",
            JsxRuntimeMode::Automatic,
            false,
        ),
        // Fragment - classic mode
        ReactCompilationTestCase::new(
            "fragment_classic",
            "<>First Second</>",
            JsxRuntimeMode::Classic,
            false,
        ),
        // Fragment - automatic mode
        ReactCompilationTestCase::new(
            "fragment_automatic",
            "<>One Two</>",
            JsxRuntimeMode::Automatic,
            false,
        ),
        // Nested elements - automatic mode
        ReactCompilationTestCase::new(
            "nested_elements_automatic",
            "<div><span>Nested</span></div>",
            JsxRuntimeMode::Automatic,
            false,
        ),
        // Dev mode - automatic
        ReactCompilationTestCase::new(
            "simple_dev_automatic",
            "<div>Dev build</div>",
            JsxRuntimeMode::Automatic,
            true,
        ),
    ]
}

/// Get the path to the golden file for a test case.
fn golden_file_path(test_name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("goldens")
        .join("react_compilation")
        .join(format!("{}.json", test_name))
}

/// Load golden fixture from file if it exists.
fn load_golden_fixture(test_name: &str) -> Option<ReactCompilationFixture> {
    let path = golden_file_path(test_name);
    if !path.exists() {
        return None;
    }

    let content = fs::read_to_string(path).ok()?;
    serde_json::from_str(&content).ok()
}

/// Save golden fixture to file.
fn save_golden_fixture(
    fixture: &ReactCompilationFixture,
) -> Result<(), Box<dyn std::error::Error>> {
    let path = golden_file_path(&fixture.test_name);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let content = serde_json::to_string_pretty(fixture)?;
    fs::write(path, content)?;

    Ok(())
}

/// Convert a typed fixture into a comparison value with source coordinates stripped.
fn normalized_fixture_value(fixture: &ReactCompilationFixture) -> Value {
    let mut value =
        serde_json::to_value(fixture).expect("React golden fixtures should serialize to JSON");
    normalize_spans(&mut value);
    value
}

fn normalize_spans(value: &mut Value) {
    const SPAN_FIELDS: [(&str, &str); 6] = [
        ("start_offset", "[START_OFFSET]"),
        ("end_offset", "[END_OFFSET]"),
        ("start_line", "[START_LINE]"),
        ("start_column", "[START_COLUMN]"),
        ("end_line", "[END_LINE]"),
        ("end_column", "[END_COLUMN]"),
    ];

    match value {
        Value::Object(map) => {
            for (field, replacement) in SPAN_FIELDS {
                if map.contains_key(field) {
                    map.insert(field.to_string(), Value::String(replacement.to_string()));
                }
            }

            for child in map.values_mut() {
                normalize_spans(child);
            }
        }
        Value::Array(items) => {
            for child in items {
                normalize_spans(child);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

/// Compile JSX input and create golden fixture.
fn compile_to_fixture(test_case: &ReactCompilationTestCase) -> ReactCompilationFixture {
    let parser_config = JsxParserConfig {
        runtime_mode: test_case.runtime_mode,
        ..Default::default()
    };
    let parse_result = parse_jsx(test_case.jsx_source, &parser_config)
        .expect("React golden test JSX source should parse");
    let config = ReactLoweringConfig {
        runtime_mode: test_case.runtime_mode,
        build_mode: if test_case.is_dev {
            BuildMode::Development
        } else {
            BuildMode::Production
        },
        max_depth: 100,
        ..Default::default()
    };

    let result = lower_jsx_to_react(&parse_result.node, &config)
        .expect("React lowering should succeed for golden test inputs");

    ReactCompilationFixture {
        test_name: test_case.name.to_string(),
        input_jsx: parse_result.node,
        config,
        result,
        schema_version: "franken-engine.react-compilation-golden.v1".to_string(),
    }
}

/// Test a single React compilation golden case.
fn test_react_compilation_golden(test_case: &ReactCompilationTestCase) {
    let current_fixture = compile_to_fixture(test_case);

    match load_golden_fixture(test_case.name) {
        Some(golden_fixture) => {
            let current_value = normalized_fixture_value(&current_fixture);
            let golden_value = normalized_fixture_value(&golden_fixture);

            // Compare against existing golden while ignoring non-semantic source coordinates.
            if current_value != golden_value {
                // Print detailed diff for debugging
                eprintln!("Golden test mismatch for {}", test_case.name);
                eprintln!("Current fixture: {:#}", current_value);
                eprintln!("Expected fixture: {:#}", golden_value);

                panic!(
                    "React compilation output does not match golden file for {}. Run with REGENERATE_GOLDEN=1 to update.",
                    test_case.name
                );
            }
        }
        None => {
            // No golden file exists - create it if in regenerate mode
            if std::env::var("REGENERATE_GOLDEN").is_ok() {
                save_golden_fixture(&current_fixture).unwrap_or_else(|e| {
                    panic!(
                        "Failed to save golden fixture for {}: {}",
                        test_case.name, e
                    )
                });
                eprintln!("Generated golden file for {}", test_case.name);
            } else {
                panic!(
                    "No golden file found for {}. Run with REGENERATE_GOLDEN=1 to create it.",
                    test_case.name
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_spans_strips_source_coordinates() {
        let fixture = serde_json::json!({
            "input_jsx": {
                "span": {
                    "start_offset": 8,
                    "end_offset": 16,
                    "start_line": 2,
                    "start_column": 5,
                    "end_line": 2,
                    "end_column": 13
                },
                "children": [
                    {
                        "span": {
                            "start_offset": 17,
                            "end_offset": 21,
                            "start_line": 2,
                            "start_column": 14,
                            "end_line": 2,
                            "end_column": 18
                        }
                    }
                ]
            },
            "result": {
                "literal": "span field names inside nested output are normalized"
            }
        });

        let mut normalized = fixture;
        normalize_spans(&mut normalized);

        assert_eq!(
            normalized["input_jsx"]["span"]["start_offset"],
            "[START_OFFSET]"
        );
        assert_eq!(
            normalized["input_jsx"]["span"]["end_column"],
            "[END_COLUMN]"
        );
        assert_eq!(
            normalized["input_jsx"]["children"][0]["span"]["start_line"],
            "[START_LINE]"
        );
        assert_eq!(
            normalized["result"]["literal"],
            "span field names inside nested output are normalized"
        );
    }

    #[test]
    fn test_simple_div_classic() {
        let test_cases = react_compilation_test_cases();
        test_react_compilation_golden(&test_cases[0]);
    }

    #[test]
    fn test_simple_div_automatic() {
        let test_cases = react_compilation_test_cases();
        test_react_compilation_golden(&test_cases[1]);
    }

    #[test]
    fn test_component_with_props_classic() {
        let test_cases = react_compilation_test_cases();
        test_react_compilation_golden(&test_cases[2]);
    }

    #[test]
    fn test_component_with_props_automatic() {
        let test_cases = react_compilation_test_cases();
        test_react_compilation_golden(&test_cases[3]);
    }

    #[test]
    fn test_react_component_classic() {
        let test_cases = react_compilation_test_cases();
        test_react_compilation_golden(&test_cases[4]);
    }

    #[test]
    fn test_react_component_automatic() {
        let test_cases = react_compilation_test_cases();
        test_react_compilation_golden(&test_cases[5]);
    }

    #[test]
    fn test_fragment_classic() {
        let test_cases = react_compilation_test_cases();
        test_react_compilation_golden(&test_cases[6]);
    }

    #[test]
    fn test_fragment_automatic() {
        let test_cases = react_compilation_test_cases();
        test_react_compilation_golden(&test_cases[7]);
    }

    #[test]
    fn test_nested_elements_automatic() {
        let test_cases = react_compilation_test_cases();
        test_react_compilation_golden(&test_cases[8]);
    }

    #[test]
    fn test_simple_dev_automatic() {
        let test_cases = react_compilation_test_cases();
        test_react_compilation_golden(&test_cases[9]);
    }
}
