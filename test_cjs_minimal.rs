//! Minimal test for CJS functionality

use frankenengine_engine::baseline_interpreter::{InterpreterConfig, QuickJsLane, Value};
use frankenengine_engine::capability::CapabilityProfile;
use frankenengine_engine::parser_api_stability::parse_script;
use frankenengine_engine::ir_contract::Ir0Module;
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};

fn main() {
    // Test basic module.exports functionality
    test_module_exports_basic();
    test_exports_object_property();
    test_require_builtin();
}

fn engine_core_lane() -> QuickJsLane {
    let mut config = InterpreterConfig::quickjs_defaults();
    config.granted_capabilities = CapabilityProfile::engine_core().capabilities;
    QuickJsLane::with_config(config)
}

fn eval_js(source: &str) -> Result<Value, String> {
    let tree = parse_script(source).map_err(|e| format!("Parse error: {:?}", e))?;
    let ir0 = Ir0Module::from_syntax_tree(tree, "test.js");
    let lowering_result = lower_ir0_to_ir3(
        &ir0,
        &LoweringContext::new("test-trace", "test-decision", "test-policy"),
    ).map_err(|e| format!("Lowering error: {:?}", e))?;

    let exec_result = engine_core_lane()
        .execute(&lowering_result.ir3, "cjs-test")
        .map_err(|e| format!("Execution error: {:?}", e))?;

    Ok(exec_result.value)
}

fn test_module_exports_basic() {
    println!("=== Test: module.exports basic ===");

    let result = eval_js("module.exports = 42; module.exports;");
    match result {
        Ok(Value::Int(42)) => println!("✓ PASS: module.exports = 42"),
        Ok(other) => println!("✗ FAIL: Expected 42, got {:?}", other),
        Err(e) => println!("✗ ERROR: {}", e),
    }
}

fn test_exports_object_property() {
    println!("\n=== Test: exports.prop assignment ===");

    let result = eval_js("exports.value = 'test'; exports.value;");
    match result {
        Ok(Value::Str(s)) if s == "test" => println!("✓ PASS: exports.value = 'test'"),
        Ok(other) => println!("✗ FAIL: Expected 'test', got {:?}", other),
        Err(e) => println!("✗ ERROR: {}", e),
    }
}

fn test_require_builtin() {
    println!("\n=== Test: require function exists ===");

    let result = eval_js("typeof require");
    match result {
        Ok(Value::Str(s)) if s == "function" => println!("✓ PASS: require is a function"),
        Ok(other) => println!("✗ FAIL: Expected 'function', got {:?}", other),
        Err(e) => println!("✗ ERROR: {}", e),
    }
}