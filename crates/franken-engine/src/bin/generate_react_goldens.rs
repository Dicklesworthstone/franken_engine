//! Generate React compilation golden fixtures manually.

#![forbid(unsafe_code)]

use std::fs;
use std::path::PathBuf;

use frankenengine_engine::ast::SourceSpan;
use frankenengine_engine::jsx_tsx_parser::{
    JsxAttribute, JsxAttributeValue, JsxChild, JsxElement, JsxElementName, JsxFragment,
    JsxNode, JsxRuntimeMode,
};
use frankenengine_engine::react_jsx_lowering::{
    ReactLoweringConfig, ReactLoweringResult, BuildMode, lower_jsx_to_react,
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

    // Generate all fixtures
    generate_simple_div_classic(&goldens_dir);
    generate_simple_div_automatic(&goldens_dir);
    generate_component_with_props_classic(&goldens_dir);
    generate_component_with_props_automatic(&goldens_dir);
    generate_react_component_classic(&goldens_dir);
    generate_react_component_automatic(&goldens_dir);
    generate_fragment_classic(&goldens_dir);
    generate_fragment_automatic(&goldens_dir);
    generate_nested_elements_automatic(&goldens_dir);
    generate_simple_dev_automatic(&goldens_dir);

    println!("Generated all React compilation golden fixtures");
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
        children: vec![JsxChild::Text {
            value: "Hello".to_string(),
            span,
        }],
        self_closing: false,
        span,
    });

    let config = ReactLoweringConfig {
        runtime_mode: JsxRuntimeMode::Classic,
        build_mode: BuildMode::Production,
        source_file: None,
        emit_self: true,
        emit_source: true,
        classic_pragma: None,
        classic_fragment_pragma: None,
        automatic_import_source: None,
        max_depth: 100,
    };

    let result = lower_jsx_to_react(&jsx, &config).expect("Lowering should succeed");

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
        children: vec![JsxChild::Text {
            value: "Hello".to_string(),
            span,
        }],
        self_closing: false,
        span,
    });

    let config = ReactLoweringConfig {
        runtime_mode: JsxRuntimeMode::Automatic,
        build_mode: BuildMode::Production,
        source_file: None,
        emit_self: true,
        emit_source: true,
        classic_pragma: None,
        classic_fragment_pragma: None,
        automatic_import_source: None,
        max_depth: 100,
    };

    let result = lower_jsx_to_react(&jsx, &config).expect("Lowering should succeed");

    let fixture = ReactCompilationFixture {
        test_name: "simple_div_automatic".to_string(),
        input_jsx: jsx,
        config,
        result,
        schema_version: "franken-engine.react-compilation-golden.v1".to_string(),
    };

    save_fixture(&fixture, dir);
}

fn generate_component_with_props_classic(dir: &PathBuf) {
    let span = SourceSpan::new(0, 6, 1, 1, 1, 7);
    let jsx = JsxNode::Element(JsxElement {
        name: JsxElementName::Identifier {
            name: "button".to_string(),
            span,
        },
        attributes: vec![
            JsxAttribute {
                name: "type".to_string(),
                value: Some(JsxAttributeValue::String {
                    value: "submit".to_string(),
                    span,
                }),
                span,
            },
            JsxAttribute {
                name: "disabled".to_string(),
                value: Some(JsxAttributeValue::String {
                    value: "true".to_string(),
                    span,
                }),
                span,
            },
        ],
        children: vec![],
        self_closing: false,
        span,
    });

    let config = ReactLoweringConfig {
        runtime_mode: JsxRuntimeMode::Classic,
        build_mode: BuildMode::Production,
        source_file: None,
        emit_self: true,
        emit_source: true,
        classic_pragma: None,
        classic_fragment_pragma: None,
        automatic_import_source: None,
        max_depth: 100,
    };

    let result = lower_jsx_to_react(&jsx, &config).expect("Lowering should succeed");

    let fixture = ReactCompilationFixture {
        test_name: "component_with_props_classic".to_string(),
        input_jsx: jsx,
        config,
        result,
        schema_version: "franken-engine.react-compilation-golden.v1".to_string(),
    };

    save_fixture(&fixture, dir);
}

fn generate_component_with_props_automatic(dir: &PathBuf) {
    let span = SourceSpan::new(0, 5, 1, 1, 1, 6);
    let jsx = JsxNode::Element(JsxElement {
        name: JsxElementName::Identifier {
            name: "input".to_string(),
            span,
        },
        attributes: vec![
            JsxAttribute {
                name: "type".to_string(),
                value: Some(JsxAttributeValue::String {
                    value: "text".to_string(),
                    span,
                }),
                span,
            },
            JsxAttribute {
                name: "placeholder".to_string(),
                value: Some(JsxAttributeValue::String {
                    value: "Enter text".to_string(),
                    span,
                }),
                span,
            },
        ],
        children: vec![],
        self_closing: false,
        span,
    });

    let config = ReactLoweringConfig {
        runtime_mode: JsxRuntimeMode::Automatic,
        build_mode: BuildMode::Production,
        source_file: None,
        emit_self: true,
        emit_source: true,
        classic_pragma: None,
        classic_fragment_pragma: None,
        automatic_import_source: None,
        max_depth: 100,
    };

    let result = lower_jsx_to_react(&jsx, &config).expect("Lowering should succeed");

    let fixture = ReactCompilationFixture {
        test_name: "component_with_props_automatic".to_string(),
        input_jsx: jsx,
        config,
        result,
        schema_version: "franken-engine.react-compilation-golden.v1".to_string(),
    };

    save_fixture(&fixture, dir);
}

fn generate_react_component_classic(dir: &PathBuf) {
    let span = SourceSpan::new(0, 11, 1, 1, 1, 12);
    let jsx = JsxNode::Element(JsxElement {
        name: JsxElementName::Identifier {
            name: "MyComponent".to_string(),
            span,
        },
        attributes: vec![],
        children: vec![JsxChild::Text {
            value: "Content".to_string(),
            span,
        }],
        span,
    });

    let config = ReactLoweringConfig {
        runtime_mode: JsxRuntimeMode::Classic,
        build_mode: BuildMode::Production,
        source_file: None,
        emit_self: true,
        emit_source: true,
        classic_pragma: None,
        classic_fragment_pragma: None,
        automatic_import_source: None,
        max_depth: 100,
    };

    let result = lower_jsx_to_react(&jsx, &config).expect("Lowering should succeed");

    let fixture = ReactCompilationFixture {
        test_name: "react_component_classic".to_string(),
        input_jsx: jsx,
        config,
        result,
        schema_version: "franken-engine.react-compilation-golden.v1".to_string(),
    };

    save_fixture(&fixture, dir);
}

fn generate_react_component_automatic(dir: &PathBuf) {
    let span = SourceSpan::new(0, 11, 1, 1, 1, 12);
    let jsx = JsxNode::Element(JsxElement {
        name: JsxElementName::Identifier {
            name: "UserProfile".to_string(),
            span,
        },
        attributes: vec![],
        children: vec![JsxChild::Text {
            value: "Profile".to_string(),
            span,
        }],
        span,
    });

    let config = ReactLoweringConfig {
        runtime_mode: JsxRuntimeMode::Automatic,
        build_mode: BuildMode::Production,
        source_file: None,
        emit_self: true,
        emit_source: true,
        classic_pragma: None,
        classic_fragment_pragma: None,
        automatic_import_source: None,
        max_depth: 100,
    };

    let result = lower_jsx_to_react(&jsx, &config).expect("Lowering should succeed");

    let fixture = ReactCompilationFixture {
        test_name: "react_component_automatic".to_string(),
        input_jsx: jsx,
        config,
        result,
        schema_version: "franken-engine.react-compilation-golden.v1".to_string(),
    };

    save_fixture(&fixture, dir);
}

fn generate_fragment_classic(dir: &PathBuf) {
    let span = SourceSpan::new(0, 10, 1, 1, 1, 11);
    let jsx = JsxNode::Fragment(JsxFragment {
        children: vec![
            JsxChild::Text {
                value: "First".to_string(),
                span,
            },
            JsxChild::Text {
                value: "Second".to_string(),
                span,
            },
        ],
        span,
    });

    let config = ReactLoweringConfig {
        runtime_mode: JsxRuntimeMode::Classic,
        build_mode: BuildMode::Production,
        source_file: None,
        emit_self: true,
        emit_source: true,
        classic_pragma: None,
        classic_fragment_pragma: None,
        automatic_import_source: None,
        max_depth: 100,
    };

    let result = lower_jsx_to_react(&jsx, &config).expect("Lowering should succeed");

    let fixture = ReactCompilationFixture {
        test_name: "fragment_classic".to_string(),
        input_jsx: jsx,
        config,
        result,
        schema_version: "franken-engine.react-compilation-golden.v1".to_string(),
    };

    save_fixture(&fixture, dir);
}

fn generate_fragment_automatic(dir: &PathBuf) {
    let span = SourceSpan::new(0, 10, 1, 1, 1, 11);
    let jsx = JsxNode::Fragment(JsxFragment {
        children: vec![
            JsxChild::Text {
                value: "One".to_string(),
                span,
            },
            JsxChild::Text {
                value: "Two".to_string(),
                span,
            },
        ],
        span,
    });

    let config = ReactLoweringConfig {
        runtime_mode: JsxRuntimeMode::Automatic,
        build_mode: BuildMode::Production,
        source_file: None,
        emit_self: true,
        emit_source: true,
        classic_pragma: None,
        classic_fragment_pragma: None,
        automatic_import_source: None,
        max_depth: 100,
    };

    let result = lower_jsx_to_react(&jsx, &config).expect("Lowering should succeed");

    let fixture = ReactCompilationFixture {
        test_name: "fragment_automatic".to_string(),
        input_jsx: jsx,
        config,
        result,
        schema_version: "franken-engine.react-compilation-golden.v1".to_string(),
    };

    save_fixture(&fixture, dir);
}

fn generate_nested_elements_automatic(dir: &PathBuf) {
    let span = SourceSpan::new(0, 3, 1, 1, 1, 4);
    let jsx = JsxNode::Element(JsxElement {
        name: JsxElementName::Identifier {
            name: "div".to_string(),
            span,
        },
        attributes: vec![],
        children: vec![JsxChild::Element(Box::new(JsxElement {
            name: JsxElementName::Identifier {
                name: "span".to_string(),
                span,
            },
            attributes: vec![],
            children: vec![JsxChild::Text {
                value: "Nested".to_string(),
                span,
            }],
            self_closing: false,
            span,
        }))],
        span,
    });

    let config = ReactLoweringConfig {
        runtime_mode: JsxRuntimeMode::Automatic,
        build_mode: BuildMode::Production,
        source_file: None,
        emit_self: true,
        emit_source: true,
        classic_pragma: None,
        classic_fragment_pragma: None,
        automatic_import_source: None,
        max_depth: 100,
    };

    let result = lower_jsx_to_react(&jsx, &config).expect("Lowering should succeed");

    let fixture = ReactCompilationFixture {
        test_name: "nested_elements_automatic".to_string(),
        input_jsx: jsx,
        config,
        result,
        schema_version: "franken-engine.react-compilation-golden.v1".to_string(),
    };

    save_fixture(&fixture, dir);
}

fn generate_simple_dev_automatic(dir: &PathBuf) {
    let span = SourceSpan::new(0, 3, 1, 1, 1, 4);
    let jsx = JsxNode::Element(JsxElement {
        name: JsxElementName::Identifier {
            name: "div".to_string(),
            span,
        },
        attributes: vec![],
        children: vec![JsxChild::Text {
            value: "Dev build".to_string(),
            span,
        }],
        span,
    });

    let config = ReactLoweringConfig {
        runtime_mode: JsxRuntimeMode::Automatic,
        build_mode: BuildMode::Development,
        source_file: None,
        emit_self: true,
        emit_source: true,
        classic_pragma: None,
        classic_fragment_pragma: None,
        automatic_import_source: None,
        max_depth: 100,
    };

    let result = lower_jsx_to_react(&jsx, &config).expect("Lowering should succeed");

    let fixture = ReactCompilationFixture {
        test_name: "simple_dev_automatic".to_string(),
        input_jsx: jsx,
        config,
        result,
        schema_version: "franken-engine.react-compilation-golden.v1".to_string(),
    };

    save_fixture(&fixture, dir);
}