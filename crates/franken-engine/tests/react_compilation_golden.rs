//! Golden tests for React JSX→JS compilation output.
//!
//! These tests capture known-good React compilation outputs and compare them against current outputs
//! to detect compilation changes that could alter generated JS output, breaking existing applications.
//!
//! Test pattern: Run JSX inputs through the React lowering pipeline, serialize outputs as JSON,
//! and compare against frozen golden files for exact regression detection.

#![forbid(unsafe_code)]

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use frankenengine_engine::ast::SourceSpan;
use frankenengine_engine::jsx_tsx_parser::{
    JsxAttribute, JsxAttributeValue, JsxChild, JsxElement, JsxElementName, JsxFragment,
    JsxNode, JsxParseResult, JsxRuntimeMode, JsxText,
};
use frankenengine_engine::react_jsx_lowering::{
    lower_jsx_to_react, ReactLoweringConfig, ReactLoweringResult,
};

/// Test case configuration for React compilation golden tests.
#[derive(Debug, Clone)]
struct ReactCompilationTestCase {
    /// Test case name for golden file
    name: &'static str,
    /// JSX input to compile
    jsx_input: JsxNode,
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
        jsx_input: JsxNode,
        runtime_mode: JsxRuntimeMode,
        is_dev: bool,
    ) -> Self {
        Self {
            name,
            jsx_input,
            runtime_mode,
            is_dev,
        }
    }
}

/// Helper function to create a simple JSX element.
fn simple_jsx_element(tag: &str, children: Vec<JsxChild>) -> JsxNode {
    let span = SourceSpan::new(0, tag.len(), 1, 1, 1, tag.len() + 1);
    JsxNode::Element(JsxElement {
        name: JsxElementName::Identifier {
            name: tag.to_string(),
            span,
        },
        attributes: vec![],
        children,
        span,
    })
}

/// Helper function to create JSX text.
fn jsx_text(content: &str) -> JsxChild {
    let span = SourceSpan::new(0, content.len(), 1, 1, 1, content.len() + 1);
    JsxChild::Text(JsxText {
        content: content.to_string(),
        span,
    })
}

/// Helper function to create JSX element with props.
fn jsx_element_with_props(tag: &str, props: Vec<(&str, &str)>) -> JsxNode {
    let span = SourceSpan::new(0, tag.len(), 1, 1, 1, tag.len() + 1);
    let attributes = props
        .into_iter()
        .map(|(name, value)| {
            let attr_span = SourceSpan::new(0, name.len(), 1, 1, 1, name.len() + 1);
            let value_span = SourceSpan::new(0, value.len(), 1, 1, 1, value.len() + 1);
            JsxAttribute {
                name: name.to_string(),
                value: Some(JsxAttributeValue::String {
                    value: value.to_string(),
                    span: value_span,
                }),
                span: attr_span,
            }
        })
        .collect();

    JsxNode::Element(JsxElement {
        name: JsxElementName::Identifier {
            name: tag.to_string(),
            span,
        },
        attributes,
        children: vec![],
        span,
    })
}

/// Helper function to create a component JSX element.
fn jsx_component(name: &str, children: Vec<JsxChild>) -> JsxNode {
    let span = SourceSpan::new(0, name.len(), 1, 1, 1, name.len() + 1);
    JsxNode::Element(JsxElement {
        name: JsxElementName::Identifier {
            name: name.to_string(),
            span,
        },
        attributes: vec![],
        children,
        span,
    })
}

/// Create JSX fragment.
fn jsx_fragment(children: Vec<JsxChild>) -> JsxNode {
    let span = SourceSpan::new(0, 10, 1, 1, 1, 11);
    JsxNode::Fragment(JsxFragment { children, span })
}

/// Test cases for React compilation golden tests.
fn react_compilation_test_cases() -> Vec<ReactCompilationTestCase> {
    vec![
        // Simple div element - classic mode
        ReactCompilationTestCase::new(
            "simple_div_classic",
            simple_jsx_element("div", vec![jsx_text("Hello")]),
            JsxRuntimeMode::Classic,
            false,
        ),
        // Simple div element - automatic mode
        ReactCompilationTestCase::new(
            "simple_div_automatic",
            simple_jsx_element("div", vec![jsx_text("Hello")]),
            JsxRuntimeMode::Automatic,
            false,
        ),
        // Component with props - classic mode
        ReactCompilationTestCase::new(
            "component_with_props_classic",
            jsx_element_with_props("button", vec![("type", "submit"), ("disabled", "true")]),
            JsxRuntimeMode::Classic,
            false,
        ),
        // Component with props - automatic mode
        ReactCompilationTestCase::new(
            "component_with_props_automatic",
            jsx_element_with_props("input", vec![("type", "text"), ("placeholder", "Enter text")]),
            JsxRuntimeMode::Automatic,
            false,
        ),
        // React component - classic mode
        ReactCompilationTestCase::new(
            "react_component_classic",
            jsx_component("MyComponent", vec![jsx_text("Content")]),
            JsxRuntimeMode::Classic,
            false,
        ),
        // React component - automatic mode
        ReactCompilationTestCase::new(
            "react_component_automatic",
            jsx_component("UserProfile", vec![jsx_text("Profile")]),
            JsxRuntimeMode::Automatic,
            false,
        ),
        // Fragment - classic mode
        ReactCompilationTestCase::new(
            "fragment_classic",
            jsx_fragment(vec![jsx_text("First"), jsx_text("Second")]),
            JsxRuntimeMode::Classic,
            false,
        ),
        // Fragment - automatic mode
        ReactCompilationTestCase::new(
            "fragment_automatic",
            jsx_fragment(vec![jsx_text("One"), jsx_text("Two")]),
            JsxRuntimeMode::Automatic,
            false,
        ),
        // Nested elements - automatic mode
        ReactCompilationTestCase::new(
            "nested_elements_automatic",
            simple_jsx_element(
                "div",
                vec![
                    JsxChild::Element(JsxElement {
                        name: JsxElementName::Identifier {
                            name: "span".to_string(),
                            span: SourceSpan::new(0, 4, 1, 1, 1, 5),
                        },
                        attributes: vec![],
                        children: vec![jsx_text("Nested")],
                        span: SourceSpan::new(0, 4, 1, 1, 1, 5),
                    })
                ],
            ),
            JsxRuntimeMode::Automatic,
            false,
        ),
        // Dev mode - automatic
        ReactCompilationTestCase::new(
            "simple_dev_automatic",
            simple_jsx_element("div", vec![jsx_text("Dev build")]),
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
fn save_golden_fixture(fixture: &ReactCompilationFixture) -> Result<(), Box<dyn std::error::Error>> {
    let path = golden_file_path(&fixture.test_name);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let content = serde_json::to_string_pretty(fixture)?;
    fs::write(path, content)?;

    Ok(())
}

/// Compile JSX input and create golden fixture.
fn compile_to_fixture(test_case: &ReactCompilationTestCase) -> ReactCompilationFixture {
    let config = ReactLoweringConfig {
        runtime_mode: test_case.runtime_mode,
        is_dev: test_case.is_dev,
        max_depth: 100,
    };

    let result = lower_jsx_to_react(&test_case.jsx_input, &config)
        .expect("React lowering should succeed for golden test inputs");

    ReactCompilationFixture {
        test_name: test_case.name.to_string(),
        input_jsx: test_case.jsx_input.clone(),
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
            // Compare against existing golden
            if current_fixture != golden_fixture {
                // Print detailed diff for debugging
                eprintln!("Golden test mismatch for {}", test_case.name);
                eprintln!("Current result: {:#?}", current_fixture.result);
                eprintln!("Expected result: {:#?}", golden_fixture.result);

                panic!(
                    "React compilation output does not match golden file for {}. Run with REGENERATE_GOLDEN=1 to update.",
                    test_case.name
                );
            }
        }
        None => {
            // No golden file exists - create it if in regenerate mode
            if std::env::var("REGENERATE_GOLDEN").is_ok() {
                save_golden_fixture(&current_fixture)
                    .unwrap_or_else(|e| panic!("Failed to save golden fixture for {}: {}", test_case.name, e));
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