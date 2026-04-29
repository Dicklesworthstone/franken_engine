//! Integration tests for React compilation pipeline.
//!
//! These tests verify that the React compilation pipeline correctly integrates
//! JSX/TSX parsing, React lowering, and output generation to provide a complete
//! compilation path from React source to executable code.

use frankenengine_engine::react_compilation_pipeline::{
    ReactCompileConfig, ReactInputLanguage, compile_react_source, generate_compilation_evidence,
};
use frankenengine_engine::react_jsx_lowering::{CallConvention, LoweredPropValue, PropsEntry};

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
    let evidence = generate_compilation_evidence(&result, &config, ReactInputLanguage::Jsx);

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
        generate_compilation_evidence(&result.unwrap(), &config, ReactInputLanguage::Tsx);
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
    let config = ReactCompileConfig::default();

    let result = compile_react_source(source, ReactInputLanguage::Jsx, &config).unwrap();

    assert!(
        !result.metadata.input_hash.as_bytes().is_empty(),
        "Should have input hash"
    );
    assert!(
        !result.metadata.config_hash.as_bytes().is_empty(),
        "Should have config hash"
    );
    assert!(result.metadata.timestamp > 0, "Should have timestamp");
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
    let config = ReactCompileConfig::default();

    // Compile the same source twice
    let result1 = compile_react_source(source, ReactInputLanguage::Jsx, &config).unwrap();
    let result2 = compile_react_source(source, ReactInputLanguage::Jsx, &config).unwrap();

    // Results should be identical (except timestamp)
    assert_eq!(result1.source, result2.source);
    assert_eq!(result1.generated_code, result2.generated_code);
    assert_eq!(result1.metadata.input_hash, result2.metadata.input_hash);
    assert_eq!(result1.metadata.config_hash, result2.metadata.config_hash);
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
