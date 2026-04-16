//! Minimal test for super() functionality

use frankenengine_engine::baseline_interpreter::{InterpreterConfig, QuickJsLane, Value};
use frankenengine_engine::capability::CapabilityProfile;
use frankenengine_engine::parser_api_stability::parse_script;
use frankenengine_engine::ir_contract::Ir0Module;
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};

fn main() {
    // Test basic super() parsing and lowering
    test_super_parsing();
    test_super_lowering();
}

fn engine_core_lane() -> QuickJsLane {
    let mut config = InterpreterConfig::quickjs_defaults();
    config.granted_capabilities = CapabilityProfile::engine_core().capabilities;
    QuickJsLane::with_config(config)
}

fn test_super_parsing() {
    println!("=== Test: super() parsing ===");

    let source = r#"
    class Parent {
        constructor(x) { this.x = x; }
    }
    class Child extends Parent {
        constructor(x, y) {
            super(x);
            this.y = y;
        }
    }
    "#;

    match parse_script(source) {
        Ok(_tree) => println!("✓ PASS: super() parsing works"),
        Err(e) => println!("✗ FAIL: super() parsing failed: {:?}", e),
    }
}

fn test_super_lowering() {
    println!("\n=== Test: super() lowering ===");

    let source = "super";

    let tree = match parse_script(source) {
        Ok(tree) => tree,
        Err(e) => {
            println!("✗ FAIL: Parse error: {:?}", e);
            return;
        }
    };

    let ir0 = Ir0Module::from_syntax_tree(tree, "test.js");

    match lower_ir0_to_ir3(
        &ir0,
        &LoweringContext::new("test-trace", "test-decision", "test-policy"),
    ) {
        Ok(_lowering_result) => println!("✓ PASS: super() lowering works"),
        Err(e) => println!("✗ FAIL: super() lowering failed: {:?}", e),
    }
}