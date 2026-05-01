//! Generate React compilation golden fixtures manually.

#![forbid(unsafe_code)]

use std::fs;
use std::path::PathBuf;

use frankenengine_engine::ast::SourceSpan;
use frankenengine_engine::jsx_tsx_parser::{
    JsxChild, JsxElement, JsxElementName, JsxNode, JsxText, JsxRuntimeMode,
};
use frankenengine_engine::react_jsx_lowering::{
    lower_jsx_to_react, ReactLoweringConfig, ReactLoweringResult,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ReactCompilationFixture {
    test_name: String,
    input_jsx: JsxNode,
    config: ReactLoweringConfig,
    result: ReactLoweringResult,
    schema_version: String,
}

fn main() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let goldens_dir = PathBuf::from(manifest_dir).join("tests/goldens/react_compilation");
    fs::create_dir_all(&goldens_dir).expect("Failed to create goldens directory");

    // Generate a few key golden fixtures
    generate_simple_div_classic(&goldens_dir);
    generate_simple_div_automatic(&goldens_dir);
    generate_component_classic(&goldens_dir);

    println!("Generated React compilation golden fixtures");
}

fn save_fixture(fixture: &ReactCompilationFixture, dir: &PathBuf) {
    let path = dir.join(format!("{}.json", fixture.test_name));
    let content = serde_json::to_string_pretty(fixture).expect("Failed to serialize fixture");
    fs::write(path, content).expect("Failed to write fixture");
    println!("Generated: {}", fixture.test_name);
}

fn generate_simple_div_classic(dir: &PathBuf) {
    let span = SourceSpan::new(0, 3, 1, 1, 1, 4);
    let jsx = JsxNode::Element(JsxElement {
        name: JsxElementName::Identifier {
            name: "div".to_string(),
            span,
        },
        attributes: vec![],
        children: vec![JsxChild::Text(JsxText {
            content: "Hello".to_string(),
            span,
        })],
        span,
    });

    let config = ReactLoweringConfig {
        runtime_mode: JsxRuntimeMode::Classic,
        is_dev: false,
        max_depth: 100,
    };

    let result = lower_jsx_to_react(&jsx, &config)
        .expect("Lowering should succeed");

    let fixture = ReactCompilationFixture {
        test_name: "simple_div_classic".to_string(),
        input_jsx: jsx,
        config,
        result,
        schema_version: "franken-engine.react-compilation-golden.v1".to_string(),
    };

    save_fixture(&fixture, dir);
}

fn generate_simple_div_automatic(dir: &PathBuf) {
    let span = SourceSpan::new(0, 3, 1, 1, 1, 4);
    let jsx = JsxNode::Element(JsxElement {
        name: JsxElementName::Identifier {
            name: "div".to_string(),
            span,
        },
        attributes: vec![],
        children: vec![JsxChild::Text(JsxText {
            content: "World".to_string(),
            span,
        })],
        span,
    });

    let config = ReactLoweringConfig {
        runtime_mode: JsxRuntimeMode::Automatic,
        is_dev: false,
        max_depth: 100,
    };

    let result = lower_jsx_to_react(&jsx, &config)
        .expect("Lowering should succeed");

    let fixture = ReactCompilationFixture {
        test_name: "simple_div_automatic".to_string(),
        input_jsx: jsx,
        config,
        result,
        schema_version: "franken-engine.react-compilation-golden.v1".to_string(),
    };

    save_fixture(&fixture, dir);
}

fn generate_component_classic(dir: &PathBuf) {
    let span = SourceSpan::new(0, 11, 1, 1, 1, 12);
    let jsx = JsxNode::Element(JsxElement {
        name: JsxElementName::Identifier {
            name: "MyComponent".to_string(),
            span,
        },
        attributes: vec![],
        children: vec![JsxChild::Text(JsxText {
            content: "Content".to_string(),
            span,
        })],
        span,
    });

    let config = ReactLoweringConfig {
        runtime_mode: JsxRuntimeMode::Classic,
        is_dev: false,
        max_depth: 100,
    };

    let result = lower_jsx_to_react(&jsx, &config)
        .expect("Lowering should succeed");

    let fixture = ReactCompilationFixture {
        test_name: "component_classic".to_string(),
        input_jsx: jsx,
        config,
        result,
        schema_version: "franken-engine.react-compilation-golden.v1".to_string(),
    };

    save_fixture(&fixture, dir);
}