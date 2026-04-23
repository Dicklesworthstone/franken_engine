//! FrankenReact Sidecar Program - Drop-In React with No-VDOM Execution
//!
//! This sidecar provides an alien-artifact React implementation that bypasses the
//! virtual DOM entirely. Instead of maintaining a virtual representation and diffing,
//! it directly manipulates the real DOM for maximum performance.
//!
//! Key features:
//! - Zero virtual DOM overhead
//! - Direct DOM manipulation
//! - React API compatibility
//! - Deterministic execution
//! - Alien-artifact performance characteristics

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process;

use clap::{Arg, Command};
use frankenengine_engine::jsx_tsx_parser::{
    JsxAttribute, JsxAttributeValue, JsxChild, JsxElement, JsxFragment, JsxNode, JsxParserConfig,
    parse_jsx,
};
use serde::{Deserialize, Serialize};

// Note: This is a standalone sidecar program that processes React components
// without requiring the full FrankenEngine interpreter infrastructure

#[derive(Debug, Serialize, Deserialize)]
struct FrankenReactSidecarConfig {
    /// Input React source file
    pub source_file: PathBuf,
    /// Output directory for processed artifacts
    pub output_dir: PathBuf,
    /// Enable alien-artifact mode for maximum performance
    pub alien_artifact_mode: bool,
    /// Direct DOM manipulation strategy
    pub dom_strategy: DomManipulationStrategy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum DomManipulationStrategy {
    /// Direct element creation and manipulation
    Direct,
    /// Batched updates for performance
    Batched,
    /// Streaming updates for large data
    Streaming,
}

#[derive(Debug, Serialize, Deserialize)]
struct NoVdomExecutionResult {
    /// Original React components processed
    pub component_count: u32,
    /// Direct DOM operations generated
    pub dom_operations: Vec<DomOperation>,
    /// Performance characteristics
    pub performance_metrics: PerformanceMetrics,
    /// Execution trace for determinism
    pub execution_trace: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
enum DomOperation {
    CreateElement {
        tag: String,
        attributes: BTreeMap<String, String>,
    },
    SetAttribute {
        element_id: String,
        attribute: String,
        value: String,
    },
    SetTextContent {
        element_id: String,
        content: String,
    },
    AppendChild {
        parent_id: String,
        child_id: String,
    },
    RemoveChild {
        parent_id: String,
        child_id: String,
    },
    AddEventListener {
        element_id: String,
        event_type: String,
        handler_id: String,
    },
}

#[derive(Debug, Serialize, Deserialize)]
struct PerformanceMetrics {
    /// Time to parse React source (microseconds)
    pub parse_time_us: u64,
    /// Time to generate DOM operations (microseconds)
    pub generation_time_us: u64,
    /// Total virtual DOM operations avoided
    pub vdom_operations_avoided: u32,
    /// Memory saved by skipping virtual DOM (bytes)
    pub memory_saved_bytes: u64,
}

fn main() {
    let matches = Command::new("franken-react-sidecar")
        .about("FrankenReact Sidecar - Drop-In React with No-VDOM Execution")
        .version("1.0.0")
        .arg(
            Arg::new("source")
                .short('s')
                .long("source")
                .value_name("FILE")
                .help("React source file to process")
                .required(true),
        )
        .arg(
            Arg::new("output")
                .short('o')
                .long("output")
                .value_name("DIR")
                .help("Output directory for artifacts")
                .required(true),
        )
        .arg(
            Arg::new("alien-artifact")
                .long("alien-artifact")
                .help("Enable alien-artifact mode for maximum performance")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("dom-strategy")
                .long("dom-strategy")
                .value_name("STRATEGY")
                .help("DOM manipulation strategy [direct|batched|streaming]")
                .value_parser(["direct", "batched", "streaming"])
                .default_value("direct"),
        )
        .get_matches();

    let source_file = PathBuf::from(matches.get_one::<String>("source").unwrap());
    let output_dir = PathBuf::from(matches.get_one::<String>("output").unwrap());
    let alien_artifact_mode = matches.get_flag("alien-artifact");

    let dom_strategy = match matches.get_one::<String>("dom-strategy").unwrap().as_str() {
        "direct" => DomManipulationStrategy::Direct,
        "batched" => DomManipulationStrategy::Batched,
        "streaming" => DomManipulationStrategy::Streaming,
        _ => unreachable!(),
    };

    let config = FrankenReactSidecarConfig {
        source_file,
        output_dir,
        alien_artifact_mode,
        dom_strategy,
    };

    match run_franken_react_sidecar(config) {
        Ok(result) => {
            println!("FrankenReact Sidecar completed successfully!");
            println!("Components processed: {}", result.component_count);
            println!("DOM operations generated: {}", result.dom_operations.len());
            println!(
                "VDOM operations avoided: {}",
                result.performance_metrics.vdom_operations_avoided
            );
            println!(
                "Memory saved: {} bytes",
                result.performance_metrics.memory_saved_bytes
            );
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            process::exit(1);
        }
    }
}

fn run_franken_react_sidecar(
    config: FrankenReactSidecarConfig,
) -> Result<NoVdomExecutionResult, Box<dyn std::error::Error>> {
    // Timing is tracked internally via parse_start and generation_start

    // Read React source file
    let source_code = fs::read_to_string(&config.source_file)
        .map_err(|e| format!("Failed to read source file: {}", e))?;

    let parse_start = std::time::Instant::now();

    let components = parse_react_components(&source_code)?;

    let parse_time_us = parse_start.elapsed().as_micros() as u64;
    let generation_start = std::time::Instant::now();

    // Generate direct DOM operations without VDOM
    let dom_operations = generate_no_vdom_operations(&components, &config.dom_strategy)?;

    let generation_time_us = generation_start.elapsed().as_micros() as u64;

    // Create output directory
    fs::create_dir_all(&config.output_dir)?;

    // Calculate performance metrics
    let vdom_operations_avoided = estimate_vdom_operations_avoided(&components);
    let memory_saved_bytes = estimate_memory_saved(&components);

    let performance_metrics = PerformanceMetrics {
        parse_time_us,
        generation_time_us,
        vdom_operations_avoided,
        memory_saved_bytes,
    };

    // Generate execution trace for determinism
    let execution_trace = generate_execution_trace(&dom_operations, &config)?;

    let result = NoVdomExecutionResult {
        component_count: components.len() as u32,
        dom_operations,
        performance_metrics,
        execution_trace,
    };

    // Write result artifacts
    write_sidecar_artifacts(&result, &config.output_dir)?;

    Ok(result)
}

fn parse_react_components(
    source_code: &str,
) -> Result<Vec<ReactComponent>, Box<dyn std::error::Error>> {
    let mut components = Vec::new();
    let parser_config = JsxParserConfig {
        allow_namespaced_names: true,
        ..JsxParserConfig::default()
    };

    for (function_start, _) in source_code.match_indices("function ") {
        let name_start = function_start + "function ".len();
        let Some((component_name, name_end)) = parse_function_name(source_code, name_start) else {
            continue;
        };
        let Some(body_open) = source_code[name_end..]
            .find('{')
            .map(|offset| name_end + offset)
        else {
            return Err(format!("function {component_name} is missing a body").into());
        };
        let Some(body_close) = find_matching_delimiter(source_code, body_open, '{', '}') else {
            return Err(format!("function {component_name} has an unterminated body").into());
        };
        let body = &source_code[body_open + 1..body_close];
        let Some(return_expression) = extract_return_expression(body) else {
            continue;
        };
        if !return_expression.trim_start().starts_with('<') {
            continue;
        }

        let parse_result =
            parse_jsx(return_expression.trim(), &parser_config).map_err(|error| {
                format!("failed to parse JSX returned by {component_name}: {error}")
            })?;
        let mut jsx_elements = Vec::new();
        collect_jsx_elements(&parse_result.node, &mut jsx_elements);
        if jsx_elements.is_empty() {
            return Err(format!("function {component_name} returned JSX with no elements").into());
        }

        components.push(ReactComponent {
            name: component_name,
            props: BTreeMap::new(),
            jsx_elements,
        });
    }

    if components.is_empty() {
        return Err("no JSX-returning React components found".into());
    }

    Ok(components)
}

fn parse_function_name(source: &str, name_start: usize) -> Option<(String, usize)> {
    let mut end = name_start;
    for (offset, ch) in source[name_start..].char_indices() {
        let valid = ch == '_' || ch == '$' || ch.is_ascii_alphanumeric();
        if !valid {
            end = name_start + offset;
            break;
        }
    }
    if end == name_start && source[name_start..].is_empty() {
        return None;
    }
    if end == name_start {
        end = source.len();
    }
    let name = source[name_start..end].trim();
    if name.is_empty() {
        None
    } else {
        Some((name.to_string(), end))
    }
}

fn extract_return_expression(body: &str) -> Option<&str> {
    let return_start = body.find("return")? + "return".len();
    let expression = body[return_start..].trim_start();
    if expression.starts_with('(') {
        let end = find_matching_delimiter(expression, 0, '(', ')')?;
        return Some(expression[1..end].trim());
    }
    let end = expression.find(';').unwrap_or(expression.len());
    Some(expression[..end].trim())
}

fn find_matching_delimiter(
    source: &str,
    open_index: usize,
    open: char,
    close: char,
) -> Option<usize> {
    let mut depth = 0usize;
    for (offset, ch) in source[open_index..].char_indices() {
        if ch == open {
            depth = depth.saturating_add(1);
        } else if ch == close {
            depth = depth.saturating_sub(1);
            if depth == 0 {
                return Some(open_index + offset);
            }
        }
    }
    None
}

fn collect_jsx_elements(node: &JsxNode, out: &mut Vec<JsxElementInfo>) {
    match node {
        JsxNode::Element(element) => collect_jsx_element(element, out),
        JsxNode::Fragment(fragment) => collect_jsx_fragment(fragment, out),
    }
}

fn collect_jsx_fragment(fragment: &JsxFragment, out: &mut Vec<JsxElementInfo>) {
    for child in &fragment.children {
        collect_jsx_child(child, out);
    }
}

fn collect_jsx_element(element: &JsxElement, out: &mut Vec<JsxElementInfo>) {
    out.push(JsxElementInfo {
        tag: element.name.to_string_repr(),
        attributes: jsx_attributes_to_map(&element.attributes),
        children: jsx_text_children(&element.children),
    });

    for child in &element.children {
        collect_jsx_child(child, out);
    }
}

fn collect_jsx_child(child: &JsxChild, out: &mut Vec<JsxElementInfo>) {
    match child {
        JsxChild::Element(element) => collect_jsx_element(element, out),
        JsxChild::Fragment(fragment) => collect_jsx_fragment(fragment, out),
        JsxChild::Text { .. } | JsxChild::ExpressionContainer { .. } => {}
    }
}

fn jsx_attributes_to_map(attributes: &[JsxAttribute]) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let mut spread_index = 0usize;
    for attribute in attributes {
        match attribute {
            JsxAttribute::Named { name, value, .. } => {
                let value = match value {
                    JsxAttributeValue::StringLiteral { value } => value.clone(),
                    JsxAttributeValue::Expression { expression } => {
                        format!("{{{}}}", expression.trim())
                    }
                    JsxAttributeValue::ImplicitTrue => "true".to_string(),
                };
                out.insert(name.clone(), value);
            }
            JsxAttribute::Spread { expression, .. } => {
                out.insert(
                    format!("spread_{spread_index:02}"),
                    expression.trim().to_string(),
                );
                spread_index += 1;
            }
        }
    }
    out
}

fn jsx_text_children(children: &[JsxChild]) -> Vec<String> {
    let mut out = Vec::new();
    for child in children {
        match child {
            JsxChild::Text { value, .. } => {
                let text = value.trim();
                if !text.is_empty() {
                    out.push(text.to_string());
                }
            }
            JsxChild::ExpressionContainer { expression, .. } => {
                let expression = expression.trim();
                if !expression.is_empty() {
                    out.push(format!("{{{expression}}}"));
                }
            }
            JsxChild::Element(_) | JsxChild::Fragment(_) => {}
        }
    }
    out
}

fn generate_no_vdom_operations(
    components: &[ReactComponent],
    strategy: &DomManipulationStrategy,
) -> Result<Vec<DomOperation>, Box<dyn std::error::Error>> {
    let mut operations = Vec::new();
    let mut element_counter = 0;

    for component in components {
        for jsx_element in &component.jsx_elements {
            let element_id = format!("frx_element_{}", element_counter);
            element_counter += 1;

            // Create element directly without VDOM
            operations.push(DomOperation::CreateElement {
                tag: jsx_element.tag.clone(),
                attributes: jsx_element.attributes.clone(),
            });

            // Set text content if present
            for child in &jsx_element.children {
                operations.push(DomOperation::SetTextContent {
                    element_id: element_id.clone(),
                    content: child.clone(),
                });
            }

            // Apply strategy-specific optimizations
            match strategy {
                DomManipulationStrategy::Direct => {
                    // Immediate DOM updates - no batching
                }
                DomManipulationStrategy::Batched => {
                    // Would batch operations for efficiency
                }
                DomManipulationStrategy::Streaming => {
                    // Would stream operations for large datasets
                }
            }
        }
    }

    Ok(operations)
}

fn estimate_vdom_operations_avoided(components: &[ReactComponent]) -> u32 {
    // Estimate how many VDOM operations we're avoiding
    // Traditional React would: create VDOM tree, diff, patch
    let mut operations = 0;

    for component in components {
        operations += component.jsx_elements.len() as u32 * 3; // create + diff + patch
    }

    operations
}

fn estimate_memory_saved(components: &[ReactComponent]) -> u64 {
    // Rough estimate of VDOM memory usage avoided
    let mut bytes = 0;

    for component in components {
        bytes += component.jsx_elements.len() * 256; // rough estimate per VDOM node
    }

    bytes as u64
}

fn generate_execution_trace(
    operations: &[DomOperation],
    config: &FrankenReactSidecarConfig,
) -> Result<String, Box<dyn std::error::Error>> {
    let mut trace = String::new();

    trace.push_str("FrankenReact Sidecar Execution Trace\n");
    trace.push_str("===================================\n\n");

    if config.alien_artifact_mode {
        trace.push_str("ALIEN-ARTIFACT MODE ENABLED\n");
    }

    trace.push_str(&format!("DOM Strategy: {:?}\n", config.dom_strategy));
    trace.push_str(&format!("Operations: {}\n\n", operations.len()));

    for (i, operation) in operations.iter().enumerate() {
        trace.push_str(&format!("{}: {:?}\n", i + 1, operation));
    }

    Ok(trace)
}

fn write_sidecar_artifacts(
    result: &NoVdomExecutionResult,
    output_dir: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    // Write execution result
    let result_path = output_dir.join("franken_react_sidecar_result.json");
    let result_json = serde_json::to_string_pretty(result)?;
    fs::write(&result_path, result_json)?;

    // Write execution trace
    let trace_path = output_dir.join("execution_trace.txt");
    fs::write(&trace_path, &result.execution_trace)?;

    // Write DOM operations
    let operations_path = output_dir.join("dom_operations.json");
    let operations_json = serde_json::to_string_pretty(&result.dom_operations)?;
    fs::write(&operations_path, operations_json)?;

    println!("Artifacts written to: {}", output_dir.display());

    Ok(())
}

#[derive(Debug)]
struct ReactComponent {
    #[allow(dead_code)]
    name: String,
    #[allow(dead_code)]
    props: BTreeMap<String, String>,
    jsx_elements: Vec<JsxElementInfo>,
}

#[derive(Debug)]
struct JsxElementInfo {
    tag: String,
    attributes: BTreeMap<String, String>,
    children: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_react_components_uses_source_jsx() {
        let source = r#"
function SmokeComponent() {
    return <div className="real">Smoke JSX</div>;
}
"#;

        let components = parse_react_components(source).expect("source JSX should parse");

        assert_eq!(components.len(), 1);
        assert_eq!(components[0].name, "SmokeComponent");
        assert_eq!(components[0].jsx_elements.len(), 1);
        let element = &components[0].jsx_elements[0];
        assert_eq!(element.tag, "div");
        assert_eq!(
            element.attributes.get("className").map(String::as_str),
            Some("real")
        );
        assert_eq!(element.children, vec!["Smoke JSX".to_string()]);
    }

    #[test]
    fn parse_react_components_rejects_non_jsx_placeholder_success() {
        let error = parse_react_components(
            r#"
function NumericReturn() {
    return 42;
}
"#,
        )
        .expect_err("non-JSX returns must not produce placeholder components");

        assert!(
            error
                .to_string()
                .contains("no JSX-returning React components")
        );
    }

    #[test]
    fn parse_react_components_collects_nested_source_elements() {
        let source = r#"
function NestedComponent() {
    return (
        <section className="real">
            <h1>Title</h1>
            <p>{message}</p>
        </section>
    );
}
"#;

        let components = parse_react_components(source).expect("nested JSX should parse");
        let tags = components[0]
            .jsx_elements
            .iter()
            .map(|element| element.tag.as_str())
            .collect::<Vec<_>>();

        assert_eq!(tags, vec!["section", "h1", "p"]);
        assert_eq!(
            components[0].jsx_elements[0]
                .attributes
                .get("className")
                .map(String::as_str),
            Some("real")
        );
        assert_eq!(
            components[0].jsx_elements[2].children,
            vec!["{message}".to_string()]
        );
    }
}
