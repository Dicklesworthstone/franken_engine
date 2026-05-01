//! Generate React compilation golden fixtures manually.

#![forbid(unsafe_code)]

use std::fs;
use std::path::{Path, PathBuf};

use frankenengine_engine::jsx_tsx_parser::{JsxNode, JsxParserConfig, JsxRuntimeMode, parse_jsx};
use frankenengine_engine::react_jsx_lowering::{
    BuildMode, ReactLoweringConfig, ReactLoweringResult, lower_jsx_to_react,
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

fn save_fixture(fixture: &ReactCompilationFixture, dir: &Path) {
    let path = dir.join(format!("{}.json", fixture.test_name));
    let content = serde_json::to_string_pretty(fixture).expect("Failed to serialize fixture");
    fs::write(path, content).expect("Failed to write fixture");
    println!("Generated: {}", fixture.test_name);
}

fn compile_fixture(
    test_name: &str,
    jsx_source: &str,
    runtime_mode: JsxRuntimeMode,
    build_mode: BuildMode,
) -> ReactCompilationFixture {
    let parser_config = JsxParserConfig {
        runtime_mode,
        ..Default::default()
    };
    let parse_result =
        parse_jsx(jsx_source, &parser_config).expect("fixture JSX source should parse");
    let config = ReactLoweringConfig {
        runtime_mode,
        build_mode,
        max_depth: 100,
        ..Default::default()
    };
    let result = lower_jsx_to_react(&parse_result.node, &config).expect("Lowering should succeed");

    ReactCompilationFixture {
        test_name: test_name.to_string(),
        input_jsx: parse_result.node,
        config,
        result,
        schema_version: "franken-engine.react-compilation-golden.v1".to_string(),
    }
}

fn generate_simple_div_classic(dir: &Path) {
    let fixture = compile_fixture(
        "simple_div_classic",
        "<div>Hello</div>",
        JsxRuntimeMode::Classic,
        BuildMode::Production,
    );
    save_fixture(&fixture, dir);
}

fn generate_simple_div_automatic(dir: &Path) {
    let fixture = compile_fixture(
        "simple_div_automatic",
        "<div>Hello</div>",
        JsxRuntimeMode::Automatic,
        BuildMode::Production,
    );
    save_fixture(&fixture, dir);
}

fn generate_component_with_props_classic(dir: &Path) {
    let fixture = compile_fixture(
        "component_with_props_classic",
        r#"<button type="submit" disabled="true" />"#,
        JsxRuntimeMode::Classic,
        BuildMode::Production,
    );
    save_fixture(&fixture, dir);
}

fn generate_component_with_props_automatic(dir: &Path) {
    let fixture = compile_fixture(
        "component_with_props_automatic",
        r#"<input type="text" placeholder="Enter text" />"#,
        JsxRuntimeMode::Automatic,
        BuildMode::Production,
    );
    save_fixture(&fixture, dir);
}

fn generate_react_component_classic(dir: &Path) {
    let fixture = compile_fixture(
        "react_component_classic",
        "<MyComponent>Content</MyComponent>",
        JsxRuntimeMode::Classic,
        BuildMode::Production,
    );
    save_fixture(&fixture, dir);
}

fn generate_react_component_automatic(dir: &Path) {
    let fixture = compile_fixture(
        "react_component_automatic",
        "<UserProfile>Profile</UserProfile>",
        JsxRuntimeMode::Automatic,
        BuildMode::Production,
    );
    save_fixture(&fixture, dir);
}

fn generate_fragment_classic(dir: &Path) {
    let fixture = compile_fixture(
        "fragment_classic",
        "<>First Second</>",
        JsxRuntimeMode::Classic,
        BuildMode::Production,
    );
    save_fixture(&fixture, dir);
}

fn generate_fragment_automatic(dir: &Path) {
    let fixture = compile_fixture(
        "fragment_automatic",
        "<>One Two</>",
        JsxRuntimeMode::Automatic,
        BuildMode::Production,
    );
    save_fixture(&fixture, dir);
}

fn generate_nested_elements_automatic(dir: &Path) {
    let fixture = compile_fixture(
        "nested_elements_automatic",
        "<div><span>Nested</span></div>",
        JsxRuntimeMode::Automatic,
        BuildMode::Production,
    );
    save_fixture(&fixture, dir);
}

fn generate_simple_dev_automatic(dir: &Path) {
    let fixture = compile_fixture(
        "simple_dev_automatic",
        "<div>Dev build</div>",
        JsxRuntimeMode::Automatic,
        BuildMode::Development,
    );
    save_fixture(&fixture, dir);
}
