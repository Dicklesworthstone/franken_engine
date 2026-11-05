//! Integration tests for React compilation pipeline.
//!
//! These tests verify that the React compilation pipeline correctly integrates
//! JSX/TSX parsing, React lowering, and output generation to provide a complete
//! compilation path from React source to executable code.

use frankenengine_engine::react_compilation_pipeline::{
    ReactCompileConfig, ReactInputLanguage, compile_react_source, generate_compilation_evidence,
};
use frankenengine_engine::react_jsx_lowering::{CallConvention, LoweredPropValue, PropsEntry};
use frankenengine_engine::security_epoch::SecurityEpoch;

/// Execute the actual emitted module with an observable implementation of the
/// public React factory ABI. No JS engine bindings or expected-output hashes
/// substitute for native parsing, linking, lowering and execution here.
fn execute_generated(
    source: &str,
    config: &ReactCompileConfig,
    preamble: &str,
    assertions: &str,
) -> Vec<String> {
    use frankenengine_engine::ast::ParseGoal;
    use frankenengine_engine::execution_orchestrator::LabFixtureExecutionOrchestratorExt as _;
    use frankenengine_engine::execution_orchestrator::{
        ExecutionOrchestrator, ExtensionPackage, OrchestratorConfig,
    };

    let root = tempfile::tempdir().expect("module fixture");
    let mut config = config.clone();
    config.lowering_config.automatic_import_source = Some("./react-runtime.mjs".into());
    let compiled = compile_react_source(source, ReactInputLanguage::Jsx, &config)
        .unwrap_or_else(|error| panic!("JSX compilation failed: {error}"));
    std::fs::write(
        root.path().join("react-runtime.mjs"),
        r#"
export const Fragment = "fragment";
function record(factory, type, props, key, staticChildren, source, self) {
    const element = {factory, type, props, key, staticChildren, source, self};
    globalThis.jsxResult = element;
    return element;
}
export function jsx(type, props, key) { return record("jsx", type, props, key); }
export function jsxs(type, props, key) { return record("jsxs", type, props, key); }
export function jsxDEV(type, props, key, staticChildren, source, self) {
    return record("jsxDEV", type, props, key, staticChildren, source, self);
}
"#,
    )
    .expect("runtime fixture");
    let entry = root.path().join("main.mjs");
    let program = format!("{preamble}\n{}\n{assertions}\n", compiled.generated_code);
    std::fs::write(&entry, &program).expect("generated module fixture");
    let package = ExtensionPackage {
        extension_id: "compiled-jsx-execution".to_string(),
        source: program,
        source_file: Some(entry.display().to_string()),
        module_root: Some(root.path().display().to_string()),
        capabilities: vec!["builtin".to_string(), "module_load".to_string()],
        version: "1.0.0".to_string(),
        metadata: Default::default(),
    };
    ExecutionOrchestrator::new(OrchestratorConfig {
        parse_goal: ParseGoal::Module,
        ..Default::default()
    })
    .execute(&package)
    .unwrap_or_else(|error| {
        panic!(
            "generated JavaScript did not execute: {error}\n{}",
            compiled.generated_code
        )
    })
    .console_output
    .into_iter()
    .map(|line| line.message)
    .collect()
}

const ORDERED_PROPS: &str = r#"<ctx.widget first={mark("first", 1)} key={mark("key1", "a")} {...mark("spread", {key: "b", ref: "spread-ref", extra: 2})} ref={mark("ref", "final-ref")} key={mark("key2", "c")} __proto__="own">{mark("child", 3)}</ctx.widget>"#;
const ORDERED_PREAMBLE: &str = r#"
const calls = [];
function mark(label, value) { calls.push(label); return value; }
const ctx = {get widget() { calls.push("type"); return "widget"; }};
function h(type, props, ...children) {
    globalThis.jsxResult = {type, props, children};
    return globalThis.jsxResult;
}
"#;

#[test]
fn classic_output_executes_with_ordered_duplicate_keys_refs_and_spreads() {
    use frankenengine_engine::jsx_tsx_parser::JsxRuntimeMode;
    let mut config = ReactCompileConfig::default();
    config.lowering_config.runtime_mode = JsxRuntimeMode::Classic;
    config.lowering_config.classic_pragma = Some("h".into());
    let lines = execute_generated(
        ORDERED_PROPS,
        &config,
        ORDERED_PREAMBLE,
        "console.log(JSON.stringify(calls)); console.log(JSON.stringify(globalThis.jsxResult));",
    );
    assert_eq!(
        lines[0],
        r#"["type","first","key1","spread","ref","key2","child"]"#
    );
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&lines[1]).unwrap(),
        serde_json::json!({
            "type": "widget",
            "props": {"first": 1, "key": "c", "ref": "final-ref", "extra": 2, "__proto__": "own"},
            "children": [3]
        })
    );
}

#[test]
fn automatic_output_links_and_evaluates_key_once_in_source_order() {
    let lines = execute_generated(
        ORDERED_PROPS,
        &ReactCompileConfig::default(),
        ORDERED_PREAMBLE,
        "console.log(JSON.stringify(calls)); console.log(JSON.stringify(globalThis.jsxResult));",
    );
    assert_eq!(
        lines[0],
        r#"["type","first","key1","spread","ref","key2","child"]"#
    );
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&lines[1]).unwrap(),
        serde_json::json!({
            "factory": "jsx", "type": "widget", "key": "c",
            "props": {"first": 1, "ref": "final-ref", "extra": 2, "__proto__": "own", "children": 3}
        })
    );
}

#[test]
fn both_runtime_modes_preserve_state_dependent_key_and_prop_order() {
    use frankenengine_engine::jsx_tsx_parser::JsxRuntimeMode;
    // Babel's automatic transform moves the key expression behind props,
    // yielding key=2/title=1 here. Our explicit contract matches the classic
    // React source semantics: evaluate every attribute in source order.
    for mode in [JsxRuntimeMode::Classic, JsxRuntimeMode::Automatic] {
        let mut config = ReactCompileConfig::default();
        config.lowering_config.runtime_mode = mode;
        config.lowering_config.classic_pragma = Some("h".into());
        let lines = execute_generated(
            "<div key={++count} title={++count}/>",
            &config,
            "let count = 0; function h(type, props) { globalThis.jsxResult = {type, props}; return globalThis.jsxResult; }",
            "const result = globalThis.jsxResult; console.log(JSON.stringify({key: result.key === undefined ? result.props.key : result.key, title: result.props.title}));",
        );
        assert_eq!(lines, [r#"{"key":1,"title":2}"#], "{mode:?}");
    }
}

#[test]
fn expression_nested_jsx_discovers_fragment_and_jsxs_imports_and_executes() {
    let lines = execute_generated(
        r#"<main>{items.map(item => <><span>{item}</span><b>!</b></>)}</main>"#,
        &ReactCompileConfig::default(),
        "const items = [1, 2];",
        "console.log(JSON.stringify(globalThis.jsxResult));",
    );
    let result: serde_json::Value = serde_json::from_str(&lines[0]).unwrap();
    assert_eq!(result["factory"], "jsx");
    assert_eq!(result["type"], "main");
    let children = result["props"]["children"].as_array().unwrap();
    assert_eq!(children.len(), 2);
    for (index, child) in children.iter().enumerate() {
        assert_eq!(child["factory"], "jsxs");
        assert_eq!(child["type"], "fragment");
        assert_eq!(
            child["props"]["children"][0]["props"]["children"],
            index + 1
        );
        assert_eq!(child["props"]["children"][1]["props"]["children"], "!");
    }
}

#[test]
fn automatic_development_output_passes_complete_jsxdev_abi() {
    use frankenengine_engine::react_jsx_lowering::BuildMode;
    let mut config = ReactCompileConfig::default();
    config.lowering_config.build_mode = BuildMode::Development;
    config.lowering_config.source_file = Some("component.jsx".into());
    let lines = execute_generated(
        "<div key={7}>{left}{right}</div>",
        &config,
        "const left = 1; const right = 2;",
        "console.log(JSON.stringify(globalThis.jsxResult)); console.log(globalThis.jsxResult.self === undefined);",
    );
    let result: serde_json::Value = serde_json::from_str(&lines[0]).unwrap();
    assert_eq!(result["factory"], "jsxDEV");
    assert_eq!(result["key"], 7);
    assert_eq!(result["props"]["children"], serde_json::json!([1, 2]));
    assert_eq!(result["staticChildren"], true);
    assert_eq!(result["source"]["fileName"], "component.jsx");
    assert_eq!(result["source"]["lineNumber"], 1);
    assert_eq!(lines[1], "true");
}

#[test]
fn generated_imports_do_not_capture_unicode_escaped_source_identifiers() {
    let lines = execute_generated(
        r#"<div>{__fra\u006eken_react_0}{__franken_react_type}</div>"#,
        &ReactCompileConfig::default(),
        "const __franken_react_0 = 'source'; const __franken_react_type = 'type';",
        "console.log(JSON.stringify(globalThis.jsxResult.props.children));",
    );
    assert_eq!(lines, [r#"["source","type"]"#]);
}

#[test]
fn expression_lexing_preserves_braces_regex_comments_and_templates() {
    let lines = execute_generated(
        r#"<div title={"}"} match={/[{}]/.test("}")}>{/* omitted */}{`a${1 + 2}`}{(1, 4 // trailing comment
        )}</div>"#,
        &ReactCompileConfig::default(),
        "",
        "console.log(JSON.stringify(globalThis.jsxResult.props));",
    );
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&lines[0]).unwrap(),
        serde_json::json!({"title": "}", "match": true, "children": ["a3", 4]})
    );
}

#[test]
fn compiler_rejects_unparsed_javascript_and_trailing_roots() {
    for source in ["<div>{value + }</div>", "<div/><span/>", "<div>{</div>"] {
        assert!(
            compile_react_source(
                source,
                ReactInputLanguage::Jsx,
                &ReactCompileConfig::default()
            )
            .is_err(),
            "invalid source must not receive a successful compile result: {source}"
        );
    }
}

#[test]
fn compile_process_receipt_commits_to_executable_output() {
    let config = ReactCompileConfig::default();
    let mut result = compile_react_source("<div/>", ReactInputLanguage::Jsx, &config).unwrap();
    let original =
        generate_compilation_evidence(&result, &config, ReactInputLanguage::Jsx).unwrap();
    result
        .generated_code
        .push_str("throw new Error('modified');\n");
    let modified =
        generate_compilation_evidence(&result, &config, ReactInputLanguage::Jsx).unwrap();
    assert_ne!(
        original.compile_receipt.output_hash,
        modified.compile_receipt.output_hash
    );
    assert_ne!(
        original.compile_receipt.process_hash,
        modified.compile_receipt.process_hash
    );
}

#[test]
fn test_simple_jsx_compilation() {
    let source = r#"<div className="hello">Hello World</div>"#;
    let config = ReactCompileConfig::default();

    let result = compile_react_source(source, ReactInputLanguage::Jsx, &config);
    assert!(result.is_ok(), "Simple JSX should compile successfully");

    let result = result.unwrap();
    assert_eq!(result.source, source);
    assert!(
        !result.generated_code.is_empty(),
        "Should generate output code"
    );
    assert!(
        !result.parse_result.feature_families_used.is_empty(),
        "Should identify JSX features"
    );
}

#[test]
fn test_jsx_with_expressions() {
    let source = r#"<div>{name} + {age}</div>"#;
    let config = ReactCompileConfig::default();

    let result = compile_react_source(source, ReactInputLanguage::Jsx, &config);
    assert!(
        result.is_ok(),
        "JSX with expressions should compile successfully"
    );

    let result = result.unwrap();
    assert!(matches!(
        result.lowering_result.element.call_convention,
        CallConvention::Automatic { .. }
    ));
    assert!(
        result
            .lowering_result
            .element
            .props
            .entries
            .iter()
            .any(|entry| matches!(
                entry,
                PropsEntry::Named(prop)
                    if prop.name == "children"
                        && matches!(prop.value, LoweredPropValue::ChildrenArray { .. })
            )),
        "Automatic runtime should fold expression children into props"
    );
}

#[test]
fn test_jsx_fragment() {
    let source = r#"<>Fragment content</>"#;
    let config = ReactCompileConfig::default();

    let result = compile_react_source(source, ReactInputLanguage::Jsx, &config);
    assert!(result.is_ok(), "JSX fragment should compile successfully");
}

#[test]
fn test_self_closing_element() {
    let source = r#"<input type="text" disabled />"#;
    let config = ReactCompileConfig::default();

    let result = compile_react_source(source, ReactInputLanguage::Jsx, &config);
    assert!(
        result.is_ok(),
        "Self-closing element should compile successfully"
    );

    let result = result.unwrap();
    assert!(
        !result.generated_code.is_empty(),
        "Should generate code for self-closing element"
    );
}

#[test]
fn test_nested_elements() {
    let source = r#"
    <div className="container">
        <h1>Title</h1>
        <p>Description</p>
        <button onClick={handleClick}>Click me</button>
    </div>
    "#;
    let config = ReactCompileConfig::default();

    let result = compile_react_source(source, ReactInputLanguage::Jsx, &config);
    assert!(
        result.is_ok(),
        "Nested elements should compile successfully"
    );

    let result = result.unwrap();
    assert!(
        !result.metadata.feature_families.is_empty(),
        "Should identify multiple feature families"
    );
}

#[test]
fn test_compilation_evidence_generation() {
    let source = r#"<span>Test</span>"#;
    let config = ReactCompileConfig::default();

    let result = compile_react_source(source, ReactInputLanguage::Jsx, &config).unwrap();
    let evidence = generate_compilation_evidence(&result, &config, ReactInputLanguage::Jsx)
        .expect("evidence generation should succeed");

    assert!(evidence.output_spec.success);
    assert!(!evidence.compile_receipt.input_hash.as_bytes().is_empty());
    assert!(!evidence.compile_receipt.output_hash.as_bytes().is_empty());
    assert_eq!(evidence.input_spec.language, ReactInputLanguage::Jsx);
}

#[test]
fn test_tsx_language_detection() {
    let source = r#"<div className="test">TypeScript JSX</div>"#;
    let config = ReactCompileConfig::default();

    let result = compile_react_source(source, ReactInputLanguage::Tsx, &config);
    assert!(result.is_ok(), "TSX should compile successfully");

    let evidence =
        generate_compilation_evidence(&result.unwrap(), &config, ReactInputLanguage::Tsx)
            .expect("evidence generation should succeed");
    assert_eq!(evidence.input_spec.language, ReactInputLanguage::Tsx);
}

#[test]
fn test_empty_input_handling() {
    let config = ReactCompileConfig::default();
    let result = compile_react_source("", ReactInputLanguage::Jsx, &config);
    assert!(result.is_err(), "Empty input should produce error");
}

#[test]
fn test_whitespace_only_input() {
    let config = ReactCompileConfig::default();
    let result = compile_react_source("   \n   ", ReactInputLanguage::Jsx, &config);
    assert!(
        result.is_err(),
        "Whitespace-only input should produce error"
    );
}

#[test]
fn test_malformed_jsx() {
    let source = r#"<div>Unclosed element"#;
    let config = ReactCompileConfig::default();

    let result = compile_react_source(source, ReactInputLanguage::Jsx, &config);
    assert!(result.is_err(), "Malformed JSX should produce error");
}

#[test]
fn test_compilation_metadata() {
    let source = r#"<div><span>Nested</span></div>"#;
    let config = ReactCompileConfig {
        compile_epoch: SecurityEpoch::from_raw(42),
        ..Default::default()
    };

    let result = compile_react_source(source, ReactInputLanguage::Jsx, &config).unwrap();

    assert!(
        !result.metadata.input_hash.as_bytes().is_empty(),
        "Should have input hash"
    );
    assert!(
        !result.metadata.config_hash.as_bytes().is_empty(),
        "Should have config hash"
    );
    assert_eq!(
        result.metadata.timestamp,
        config.compile_epoch.as_u64(),
        "metadata should use the deterministic compile epoch"
    );
    assert!(
        !result.metadata.feature_families.is_empty(),
        "Should identify feature families"
    );
}

#[test]
fn test_source_map_generation() {
    let source = r#"<div>Test</div>"#;
    let config = ReactCompileConfig {
        generate_source_maps: true,
        ..Default::default()
    };

    let result = compile_react_source(source, ReactInputLanguage::Jsx, &config).unwrap();
    assert!(
        result.source_map.is_some(),
        "Should generate source map when requested"
    );

    let source_map = result.source_map.unwrap();
    assert!(
        source_map.contains("version"),
        "Source map should be valid JSON"
    );
}

#[test]
fn test_classic_vs_automatic_runtime() {
    use frankenengine_engine::jsx_tsx_parser::JsxRuntimeMode;

    let source = r#"<div>Hello</div>"#;

    // Test classic mode
    let mut config = ReactCompileConfig::default();
    config.lowering_config.runtime_mode = JsxRuntimeMode::Classic;
    let classic_result = compile_react_source(source, ReactInputLanguage::Jsx, &config).unwrap();

    // Test automatic mode
    config.lowering_config.runtime_mode = JsxRuntimeMode::Automatic;
    let automatic_result = compile_react_source(source, ReactInputLanguage::Jsx, &config).unwrap();

    assert!(matches!(
        classic_result.lowering_result.element.call_convention,
        CallConvention::Classic { .. }
    ));
    assert!(matches!(
        automatic_result.lowering_result.element.call_convention,
        CallConvention::Automatic { .. }
    ));
    assert!(
        !classic_result.lowering_result.element.children.is_empty(),
        "Classic runtime keeps children as positional call arguments"
    );
    assert!(
        automatic_result.lowering_result.element.children.is_empty(),
        "Automatic runtime folds children into props"
    );
}

#[test]
fn test_deterministic_compilation() {
    let source = r#"<div className="test">Deterministic test</div>"#;
    let config = ReactCompileConfig {
        compile_epoch: SecurityEpoch::from_raw(7),
        ..Default::default()
    };

    // Compile the same source twice
    let result1 = compile_react_source(source, ReactInputLanguage::Jsx, &config).unwrap();
    let result2 = compile_react_source(source, ReactInputLanguage::Jsx, &config).unwrap();

    // Results should be identical, including evidence timestamps.
    assert_eq!(result1.source, result2.source);
    assert_eq!(result1.generated_code, result2.generated_code);
    assert_eq!(result1.metadata.input_hash, result2.metadata.input_hash);
    assert_eq!(result1.metadata.config_hash, result2.metadata.config_hash);
    assert_eq!(result1.metadata, result2.metadata);

    let evidence1 =
        generate_compilation_evidence(&result1, &config, ReactInputLanguage::Jsx).unwrap();
    let evidence2 =
        generate_compilation_evidence(&result2, &config, ReactInputLanguage::Jsx).unwrap();
    assert_eq!(evidence1, evidence2);
    assert_eq!(evidence1.timestamp, config.compile_epoch.as_u64());
}

#[test]
fn test_large_jsx_component() {
    let source = r#"
    <div className="app">
        <header>
            <h1>Large Component</h1>
            <nav>
                <ul>
                    <li><a href="/home">Home</a></li>
                    <li><a href="/about">About</a></li>
                    <li><a href="/contact">Contact</a></li>
                </ul>
            </nav>
        </header>
        <main>
            <section className="content">
                <article>
                    <h2>Article Title</h2>
                    <p>Article content goes here.</p>
                    <footer>
                        <span>Published: {publishDate}</span>
                        <button onClick={handleLike}>Like</button>
                    </footer>
                </article>
            </section>
            <aside className="sidebar">
                <h3>Related Links</h3>
                <ul>
                    {links.map(link => (
                        <li key={link.id}>
                            <a href={link.url}>{link.title}</a>
                        </li>
                    ))}
                </ul>
            </aside>
        </main>
    </div>
    "#;

    let config = ReactCompileConfig::default();
    let result = compile_react_source(source, ReactInputLanguage::Jsx, &config);
    assert!(
        result.is_ok(),
        "Large JSX component should compile successfully"
    );

    let result = result.unwrap();
    assert!(
        !result.generated_code.is_empty(),
        "Should generate code for large component"
    );
    assert!(
        result.metadata.feature_families.len() >= 3,
        "Should identify multiple feature families"
    );
}
