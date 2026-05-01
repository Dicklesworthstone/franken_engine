//! Golden tests for React JSX→JS compilation output.
//!
//! These tests capture known-good React compilation outputs and compare them against current outputs
//! to detect compilation changes that could alter generated JS output, breaking existing applications.
//!
//! Test pattern: Run JSX inputs through the React lowering pipeline, serialize outputs as JSON,
//! and compare against frozen golden files for exact regression detection.

#![forbid(unsafe_code)]

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use frankenengine_engine::jsx_tsx_parser::{JsxNode, JsxParserConfig, JsxRuntimeMode, parse_jsx};
use frankenengine_engine::react_jsx_lowering::{
    BuildMode, ReactLoweringConfig, ReactLoweringResult, lower_jsx_to_react,
};

mod golden_diag;

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
        // Spread props - automatic mode
        ReactCompilationTestCase::new(
            "spread_props_automatic",
            r#"<Foo {...rest} bar="baz" />"#,
            JsxRuntimeMode::Automatic,
            false,
        ),
        // Conditional rendering with && - automatic mode
        ReactCompilationTestCase::new(
            "conditional_and_automatic",
            r#"<div>{isVisible && <span>Show me</span>}</div>"#,
            JsxRuntimeMode::Automatic,
            false,
        ),
        // Conditional rendering with ternary - automatic mode
        ReactCompilationTestCase::new(
            "conditional_ternary_automatic",
            r#"<div>{isActive ? <span>Active</span> : <span>Inactive</span>}</div>"#,
            JsxRuntimeMode::Automatic,
            false,
        ),
        // JSX in array/map output - automatic mode
        ReactCompilationTestCase::new(
            "jsx_array_automatic",
            r#"<ul>{items.map(item => <li key={item.id}>{item.name}</li>)}</ul>"#,
            JsxRuntimeMode::Automatic,
            false,
        ),
        // Boolean/null/undefined children - automatic mode
        ReactCompilationTestCase::new(
            "falsy_children_automatic",
            r#"<div>{true}{false}{null}{undefined}</div>"#,
            JsxRuntimeMode::Automatic,
            false,
        ),
        // dangerouslySetInnerHTML - automatic mode
        ReactCompilationTestCase::new(
            "dangerous_html_automatic",
            r#"<div dangerouslySetInnerHTML={{__html: "<em>raw html</em>"}} />"#,
            JsxRuntimeMode::Automatic,
            false,
        ),
        // Member expression components - automatic mode
        ReactCompilationTestCase::new(
            "member_expression_automatic",
            r#"<UI.Button variant="primary">Click me</UI.Button>"#,
            JsxRuntimeMode::Automatic,
            false,
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

    // Use improved golden diagnostics with span normalization
    let current_value = normalized_fixture_value(&current_fixture);
    let actual_json = serde_json::to_string_pretty(&current_value)
        .expect("React fixture should serialize to JSON");

    let diag = golden_diag::GoldenDiag::react();
    let fixture_path = golden_file_path(test_case.name);
    let hint = format!(
        "React compilation: mode={:?}, dev={}, jsx_source='{}'",
        test_case.runtime_mode, test_case.is_dev, test_case.jsx_source
    );

    diag.assert_golden_match(&actual_json, &fixture_path, test_case.name, Some(&hint));
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

    #[test]
    fn test_spread_props_automatic() {
        let test_cases = react_compilation_test_cases();
        test_react_compilation_golden(&test_cases[10]);
    }

    #[test]
    fn test_conditional_and_automatic() {
        let test_cases = react_compilation_test_cases();
        test_react_compilation_golden(&test_cases[11]);
    }

    #[test]
    fn test_conditional_ternary_automatic() {
        let test_cases = react_compilation_test_cases();
        test_react_compilation_golden(&test_cases[12]);
    }

    #[test]
    fn test_jsx_array_automatic() {
        let test_cases = react_compilation_test_cases();
        test_react_compilation_golden(&test_cases[13]);
    }

    #[test]
    fn test_falsy_children_automatic() {
        let test_cases = react_compilation_test_cases();
        test_react_compilation_golden(&test_cases[14]);
    }

    #[test]
    fn test_dangerous_html_automatic() {
        let test_cases = react_compilation_test_cases();
        test_react_compilation_golden(&test_cases[15]);
    }

    #[test]
    fn test_member_expression_automatic() {
        let test_cases = react_compilation_test_cases();
        test_react_compilation_golden(&test_cases[16]);
    }
}
