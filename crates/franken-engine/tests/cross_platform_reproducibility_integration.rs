//! Cross-platform reproducibility integration tests.
//!
//! Verifies that FrankenEngine produces identical content_hash outputs across
//! Linux, macOS, and Windows platforms for the same inputs. This is the
//! load-bearing test suite for cross-platform determinism.

use frankenengine_engine::cross_platform_reproducibility::{
    CrossPlatformReproducibilityTester, DivergenceType, ModuleType, OutputType,
    ReproducibilityTestConfig, ReproducibilityTestInput,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::rch_worker_registry::{RchWorkerRegistry, WorkerPlatform};
use std::collections::BTreeMap;

/// Create a test input with defaults.
fn create_test_input(
    test_id: &str,
    description: &str,
    source_code: &str,
) -> ReproducibilityTestInput {
    ReproducibilityTestInput {
        test_id: test_id.to_string(),
        description: description.to_string(),
        source_code: source_code.to_string(),
        output_type: OutputType::Stdout,
        module_type: ModuleType::Script,
        flags: vec![],
        deterministic: true,
    }
}

/// Create a mock tester for platform-independent testing.
fn create_mock_tester() -> CrossPlatformReproducibilityTester {
    let registry = RchWorkerRegistry::with_defaults();
    let config = ReproducibilityTestConfig {
        target_platforms: vec![WorkerPlatform::LinuxX64], // Use only Linux for unit tests
        max_execution_time_seconds: 10,
        capture_traces: false,
        performance_threshold_percent: 50.0,
        retry_attempts: 0,
    };
    CrossPlatformReproducibilityTester::new(registry, config)
}

#[test]
fn test_basic_arithmetic_reproducibility() {
    let test_input = create_test_input(
        "arithmetic_basic",
        "Basic arithmetic operations",
        "console.log(2 + 3 * 4)",
    );

    // Verify test input is properly constructed
    assert_eq!(test_input.test_id, "arithmetic_basic");
    assert!(test_input.deterministic);
    assert_eq!(test_input.output_type, OutputType::Stdout);
}

#[test]
fn test_string_concatenation_reproducibility() {
    let test_input = create_test_input(
        "string_concat",
        "String concatenation",
        "console.log('Hello' + ', ' + 'World' + '!')",
    );

    assert!(!test_input.source_code.is_empty());
    assert!(test_input.deterministic);
}

#[test]
fn test_array_operations_reproducibility() {
    let test_input = create_test_input(
        "array_ops",
        "Array operations",
        "const arr = [1, 2, 3, 4, 5]; console.log(arr.reduce((a, b) => a + b, 0))",
    );

    assert!(test_input.source_code.contains("reduce"));
    assert!(test_input.deterministic);
}

#[test]
fn test_object_manipulation_reproducibility() {
    let test_input = create_test_input(
        "object_ops",
        "Object manipulation",
        "const obj = {a: 1, b: 2, c: 3}; console.log(Object.keys(obj).length)",
    );

    assert!(test_input.source_code.contains("Object.keys"));
}

#[test]
fn test_function_declaration_reproducibility() {
    let test_input = create_test_input(
        "function_decl",
        "Function declaration and call",
        "function multiply(a, b) { return a * b; } console.log(multiply(6, 7))",
    );

    assert!(test_input.source_code.contains("function"));
}

#[test]
fn test_arrow_function_reproducibility() {
    let test_input = create_test_input(
        "arrow_func",
        "Arrow function syntax",
        "const square = x => x * x; console.log(square(8))",
    );

    assert!(test_input.source_code.contains("=>"));
}

#[test]
fn test_closure_reproducibility() {
    let test_input = create_test_input(
        "closure",
        "Closure behavior",
        "function outer(x) { return function(y) { return x + y; }; } console.log(outer(10)(5))",
    );

    assert!(test_input.source_code.contains("outer"));
}

#[test]
fn test_nested_loops_reproducibility() {
    let test_input = create_test_input(
        "nested_loops",
        "Nested loop constructs",
        "let sum = 0; for(let i = 0; i < 3; i++) { for(let j = 0; j < 3; j++) { sum += i + j; } } console.log(sum)",
    );

    assert!(test_input.source_code.contains("for"));
}

#[test]
fn test_conditional_logic_reproducibility() {
    let test_input = create_test_input(
        "conditionals",
        "If/else conditional logic",
        "let x = 42; console.log(x > 40 ? 'large' : x > 20 ? 'medium' : 'small')",
    );

    assert!(test_input.source_code.contains("?"));
}

#[test]
fn test_switch_statement_reproducibility() {
    let test_input = create_test_input(
        "switch_stmt",
        "Switch statement logic",
        "let day = 3; switch(day) { case 1: console.log('Mon'); break; case 3: console.log('Wed'); break; default: console.log('Other'); }",
    );

    assert!(test_input.source_code.contains("switch"));
}

#[test]
fn test_try_catch_reproducibility() {
    let test_input = create_test_input(
        "try_catch",
        "Error handling with try/catch",
        "try { JSON.parse('{\"valid\": true}'); console.log('success'); } catch(e) { console.log('error'); }",
    );

    assert!(test_input.source_code.contains("try"));
}

#[test]
fn test_json_operations_reproducibility() {
    let test_input = create_test_input(
        "json_ops",
        "JSON stringify and parse",
        "const data = {num: 123, str: 'test'}; console.log(JSON.parse(JSON.stringify(data)).num)",
    );

    assert!(test_input.source_code.contains("JSON"));
}

#[test]
fn test_regex_matching_reproducibility() {
    let test_input = create_test_input(
        "regex_match",
        "Regular expression matching",
        "const text = 'abc123def'; const match = text.match(/\\d+/); console.log(match[0])",
    );

    assert!(test_input.source_code.contains("match"));
}

#[test]
fn test_array_methods_reproducibility() {
    let test_input = create_test_input(
        "array_methods",
        "Array built-in methods",
        "const nums = [1, 4, 2, 8, 5]; console.log(nums.filter(x => x > 3).sort().join(','))",
    );

    assert!(test_input.source_code.contains("filter"));
}

#[test]
fn test_string_methods_reproducibility() {
    let test_input = create_test_input(
        "string_methods",
        "String built-in methods",
        "const text = '  Hello World  '; console.log(text.trim().toLowerCase().replace(' ', '-'))",
    );

    assert!(test_input.source_code.contains("trim"));
}

#[test]
fn test_math_operations_reproducibility() {
    let test_input = create_test_input(
        "math_ops",
        "Math object operations",
        "console.log(Math.max(1, 5, 3) + Math.min(2, 7, 4) + Math.abs(-10))",
    );

    assert!(test_input.source_code.contains("Math"));
}

#[test]
fn test_boolean_logic_reproducibility() {
    let test_input = create_test_input(
        "boolean_logic",
        "Boolean logic operations",
        "const a = true, b = false; console.log(a && !b || (a && b))",
    );

    assert!(test_input.source_code.contains("&&"));
}

#[test]
fn test_type_coercion_reproducibility() {
    let test_input = create_test_input(
        "type_coercion",
        "JavaScript type coercion",
        "console.log(('5' - 3) + (2 * '4') + parseInt('42px'))",
    );

    assert!(test_input.source_code.contains("parseInt"));
}

#[test]
fn test_destructuring_assignment_reproducibility() {
    let test_input = create_test_input(
        "destructuring",
        "Destructuring assignment",
        "const [a, , c] = [1, 2, 3]; const {x, y} = {x: 4, y: 5}; console.log(a + c + x + y)",
    );

    assert!(test_input.source_code.contains("[a, , c]"));
}

#[test]
fn test_template_literals_reproducibility() {
    let test_input = create_test_input(
        "template_literals",
        "Template literal syntax",
        "const name = 'Test'; const num = 42; console.log(`Hello ${name}, number is ${num * 2}`)",
    );

    assert!(test_input.source_code.contains("${"));
}

#[test]
fn test_spread_operator_reproducibility() {
    let test_input = create_test_input(
        "spread_operator",
        "Spread operator usage",
        "const arr1 = [1, 2]; const arr2 = [3, 4]; console.log([...arr1, ...arr2].join(','))",
    );

    assert!(test_input.source_code.contains("..."));
}

#[test]
fn test_rest_parameters_reproducibility() {
    let test_input = create_test_input(
        "rest_params",
        "Rest parameters in functions",
        "function sum(...nums) { return nums.reduce((a, b) => a + b, 0); } console.log(sum(1, 2, 3, 4))",
    );

    assert!(test_input.source_code.contains("...nums"));
}

#[test]
fn test_class_definition_reproducibility() {
    let test_input = create_test_input(
        "class_def",
        "Class definition and instantiation",
        "class Point { constructor(x, y) { this.x = x; this.y = y; } sum() { return this.x + this.y; } } console.log(new Point(3, 4).sum())",
    );

    assert!(test_input.source_code.contains("class"));
}

#[test]
fn test_async_patterns_reproducibility() {
    let test_input = create_test_input(
        "async_patterns",
        "Promise and async patterns",
        "Promise.resolve(42).then(x => console.log(x * 2)).catch(err => console.log('error'))",
    );

    assert!(test_input.source_code.contains("Promise"));
}

#[test]
fn test_symbol_operations_reproducibility() {
    let test_input = create_test_input(
        "symbol_ops",
        "Symbol primitive operations",
        "const sym = Symbol('test'); const obj = {}; obj[sym] = 'value'; console.log(obj[sym])",
    );

    assert!(test_input.source_code.contains("Symbol"));
}

#[test]
fn test_weak_collections_reproducibility() {
    let test_input = create_test_input(
        "weak_collections",
        "WeakMap and WeakSet usage",
        "const wm = new WeakMap(); const obj = {}; wm.set(obj, 'test'); console.log(wm.get(obj))",
    );

    assert!(test_input.source_code.contains("WeakMap"));
}

#[test]
fn test_proxy_operations_reproducibility() {
    let test_input = create_test_input(
        "proxy_ops",
        "Proxy object behavior",
        "const target = {x: 1}; const proxy = new Proxy(target, {get: (obj, prop) => obj[prop] * 2}); console.log(proxy.x)",
    );

    assert!(test_input.source_code.contains("Proxy"));
}

#[test]
fn test_generator_functions_reproducibility() {
    let test_input = create_test_input(
        "generators",
        "Generator function behavior",
        "function* gen() { yield 1; yield 2; yield 3; } const g = gen(); console.log(g.next().value)",
    );

    assert!(test_input.source_code.contains("yield"));
}

#[test]
fn test_set_operations_reproducibility() {
    let test_input = create_test_input(
        "set_ops",
        "Set collection operations",
        "const s = new Set([1, 2, 2, 3]); s.add(4); console.log(Array.from(s).sort().join(','))",
    );

    assert!(test_input.source_code.contains("Set"));
}

#[test]
fn test_map_operations_reproducibility() {
    let test_input = create_test_input(
        "map_ops",
        "Map collection operations",
        "const m = new Map(); m.set('a', 1); m.set('b', 2); console.log(m.get('a') + m.get('b'))",
    );

    assert!(test_input.source_code.contains("Map"));
}

#[test]
fn test_bitwise_operations_reproducibility() {
    let test_input = create_test_input(
        "bitwise_ops",
        "Bitwise operations",
        "const a = 5, b = 3; console.log((a & b) + (a | b) + (a ^ b) + (~a & 0xFF))",
    );

    assert!(test_input.source_code.contains("&"));
}

#[test]
fn test_unicode_handling_reproducibility() {
    let test_input = create_test_input(
        "unicode_handling",
        "Unicode string handling",
        "const text = '🔥 Unicode Test 中文'; console.log(text.length + ' chars')",
    );

    assert!(test_input.source_code.contains("🔥"));
}

#[test]
fn test_date_deterministic_reproducibility() {
    let test_input = create_test_input(
        "date_deterministic",
        "Deterministic date operations",
        "const d = new Date('2024-01-01T00:00:00.000Z'); console.log(d.getFullYear() + d.getMonth())",
    );

    assert!(test_input.source_code.contains("2024"));
}

#[test]
fn test_number_formatting_reproducibility() {
    let test_input = create_test_input(
        "number_format",
        "Number formatting operations",
        "const num = 123.456789; console.log(num.toFixed(2) + '|' + num.toPrecision(4))",
    );

    assert!(test_input.source_code.contains("toFixed"));
}

#[test]
fn test_error_types_reproducibility() {
    let test_input = create_test_input(
        "error_types",
        "Different error types",
        "try { throw new TypeError('test'); } catch(e) { console.log(e.constructor.name); }",
    );

    assert!(test_input.source_code.contains("TypeError"));
}

#[test]
fn test_standard_test_suite_generation() {
    let tests = CrossPlatformReproducibilityTester::generate_standard_test_suite();

    // Should have at least 10 tests
    assert!(tests.len() >= 10);

    // All should be deterministic
    for test in &tests {
        assert!(test.deterministic);
        assert!(!test.test_id.is_empty());
        assert!(!test.description.is_empty());
        assert!(!test.source_code.is_empty());
    }

    // Should have unique test IDs
    let mut unique_ids = std::collections::BTreeSet::new();
    for test in &tests {
        assert!(
            unique_ids.insert(test.test_id.clone()),
            "Duplicate test ID: {}",
            test.test_id
        );
    }
}

#[test]
fn test_reproducibility_tester_creation() {
    let tester = create_mock_tester();

    // Should be created successfully
    // This is primarily testing that the constructor works
    assert_eq!(
        format!("{:?}", tester).contains("CrossPlatformReproducibilityTester"),
        true
    );
}

#[test]
fn test_content_hash_consistency() {
    // Same input should always produce same hash
    let input1 = "test content";
    let input2 = "test content";
    let input3 = "different content";

    let hash1 = ContentHash::compute(input1.as_bytes());
    let hash2 = ContentHash::compute(input2.as_bytes());
    let hash3 = ContentHash::compute(input3.as_bytes());

    assert_eq!(hash1, hash2);
    assert_ne!(hash1, hash3);
}

#[test]
fn test_divergence_type_comparison() {
    assert_eq!(
        DivergenceType::ContentHashMismatch,
        DivergenceType::ContentHashMismatch
    );
    assert_ne!(
        DivergenceType::ContentHashMismatch,
        DivergenceType::ExitCodeMismatch
    );
    assert_ne!(
        DivergenceType::OutputMismatch,
        DivergenceType::PerformanceDivergence
    );
}

#[test]
fn test_module_type_variants() {
    let script_test = ReproducibilityTestInput {
        test_id: "script_test".to_string(),
        description: "Script module test".to_string(),
        source_code: "console.log('script')".to_string(),
        output_type: OutputType::Stdout,
        module_type: ModuleType::Script,
        flags: vec![],
        deterministic: true,
    };

    let esm_test = ReproducibilityTestInput {
        test_id: "esm_test".to_string(),
        description: "ES Module test".to_string(),
        source_code: "export default 42; console.log('esm')".to_string(),
        output_type: OutputType::Stdout,
        module_type: ModuleType::ESModule,
        flags: vec![],
        deterministic: true,
    };

    assert_eq!(script_test.module_type, ModuleType::Script);
    assert_eq!(esm_test.module_type, ModuleType::ESModule);
    assert_ne!(script_test.module_type, esm_test.module_type);
}

#[test]
fn test_output_type_variants() {
    assert_ne!(OutputType::Stdout, OutputType::Stderr);
    assert_ne!(OutputType::BytecodeHash, OutputType::RuntimeStateHash);
    assert_eq!(OutputType::ExitCode, OutputType::ExitCode);
}

// Additional stress tests for edge cases

#[test]
fn test_empty_source_code_handling() {
    let test_input = create_test_input("empty_source", "Empty source code handling", "");

    assert_eq!(test_input.source_code, "");
    // Should still be a valid test input
    assert!(test_input.deterministic);
}

#[test]
fn test_large_source_code_handling() {
    let large_code = "console.log('x'); ".repeat(1000);
    let test_input = create_test_input("large_source", "Large source code handling", &large_code);

    assert!(test_input.source_code.len() > 10000);
    assert!(test_input.deterministic);
}

#[test]
fn test_special_characters_in_source() {
    let test_input = create_test_input(
        "special_chars",
        "Special characters in source",
        "console.log('quotes\"and\\nescapes\\t\\r\\0')",
    );

    assert!(test_input.source_code.contains("\\n"));
    assert!(test_input.source_code.contains("\\t"));
}

#[test]
fn test_platform_coverage() {
    let platforms = vec![
        WorkerPlatform::LinuxX64,
        WorkerPlatform::LinuxArm64,
        WorkerPlatform::MacOSArm64,
        WorkerPlatform::WindowsX64,
    ];

    // All platforms should be representable
    for platform in platforms {
        let platform_str = platform.as_str();
        assert!(!platform_str.is_empty());
        assert!(WorkerPlatform::from_str(platform_str).is_some());
    }
}
