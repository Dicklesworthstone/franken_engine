//! Adversarial memory exhaustion tests for memory budget system.
//!
//! These tests verify that the memory budget constraints properly prevent
//! denial-of-service attacks through unbounded memory allocation.

use frankenengine_engine::baseline_interpreter::{InterpreterConfig, InterpreterError, QuickJsLane};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::ir_contract::{Ir0Module, Ir3FunctionDesc, Ir3Instruction, Ir3Module};
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser_api_stability::parse_script;

/// Create a test configuration with tight memory limits for adversarial testing.
fn adversarial_config() -> InterpreterConfig {
    let mut config = InterpreterConfig::quickjs_defaults();
    config.max_heap_objects = 100; // Very low limit for testing
    config.max_total_memory_bytes = 1024 * 16; // 16KB limit
    config.max_scope_depth = 10; // Low depth limit
    config
}

/// Create a test module from JavaScript source using the lowering pipeline.
fn lower_source_to_ir3(source: &str) -> Ir3Module {
    let tree = parse_script(source).expect("source should parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "memory_adversarial_test.js");
    lower_ir0_to_ir3(
        &ir0,
        &LoweringContext::new(
            "trace-memory-adversarial",
            "decision-memory-adversarial",
            "policy-memory-adversarial",
        ),
    )
    .expect("source should lower")
    .ir3
}

/// Create a test module with specific IR3 instructions for direct testing.
fn test_module_with_instructions(instructions: Vec<Ir3Instruction>) -> Ir3Module {
    let mut m = Ir3Module::new(ContentHash::compute(b"adversarial-test"), "adversarial.js");
    m.instructions = instructions;
    m.function_table.push(Ir3FunctionDesc {
        entry: 0,
        arity: 0,
        frame_size: 16,
        name: Some("main".to_string()),
        is_generator: false,
    });
    m
}

/// Create a test lane with adversarial configuration.
fn adversarial_lane() -> QuickJsLane {
    let mut config = adversarial_config();
    config.granted_capabilities = std::collections::BTreeSet::new();
    QuickJsLane::with_config(config)
}

#[test]
fn test_object_allocation_exhaustion() {
    let lane = adversarial_lane();

    // Test: Allocate objects within instruction budget but exceeding object count limit
    let js_source = r#"
        for (let i = 0; i < 200; i++) {
            let obj = { value: i };
        }
    "#;

    let module = lower_source_to_ir3(js_source);
    let result = lane.execute(&module, "object-allocation-test");

    // Should fail with MemoryBudgetExceeded due to object count limit
    match result {
        Err(InterpreterError::MemoryBudgetExceeded {
            requested_heap_objects,
            max_heap_objects,
            ..
        }) => {
            assert!(
                requested_heap_objects >= max_heap_objects,
                "Should hit object count limit"
            );
        }
        other => panic!("Expected MemoryBudgetExceeded, got: {:?}", other),
    }
}

#[test]
fn test_memory_byte_exhaustion() {
    let lane = adversarial_lane();

    // Test: Create large string that exceeds memory byte limit
    let js_source = r#"
        let largeString = "";
        for (let i = 0; i < 1000; i++) {
            largeString += "This is a large string that will consume memory quickly";
        }
    "#;

    let module = lower_source_to_ir3(js_source);
    let result = lane.execute(&module, "memory-byte-test");

    // Should fail with MemoryBudgetExceeded due to memory byte limit
    match result {
        Err(InterpreterError::MemoryBudgetExceeded { .. }) => {
            // Expected outcome
        }
        other => panic!("Expected MemoryBudgetExceeded, got: {:?}", other),
    }
}

#[test]
fn test_scope_depth_exhaustion() {
    let lane = adversarial_lane();

    // Test: Deep scope nesting that exceeds scope depth limit
    let js_source = r#"
        function deepNesting() {
            function level1() {
                function level2() {
                    function level3() {
                        function level4() {
                            function level5() {
                                function level6() {
                                    function level7() {
                                        function level8() {
                                            function level9() {
                                                function level10() {
                                                    function level11() {
                                                        return 42;
                                                    }
                                                    return level11();
                                                }
                                                return level10();
                                            }
                                            return level9();
                                        }
                                        return level8();
                                    }
                                    return level7();
                                }
                                return level6();
                            }
                            return level5();
                        }
                        return level4();
                    }
                    return level3();
                }
                return level2();
            }
            return level1();
        }
        deepNesting();
    "#;

    let module = lower_source_to_ir3(js_source);
    let result = lane.execute(&module, "test");

    // Should fail with ScopeDepthExceeded
    match result {
        Err(InterpreterError::ScopeDepthExceeded {
            requested_depth,
            max_depth,
        }) => {
            assert!(
                requested_depth >= max_depth,
                "Should exceed scope depth limit"
            );
        }
        other => panic!("Expected ScopeDepthExceeded, got: {:?}", other),
    }
}

#[test]
fn test_closure_memory_amplification() {
    let lane = adversarial_lane();

    // Test: Create closures that capture large scope chains (O(n^2) amplification)
    let js_source = r#"
        let closures = [];
        for (let i = 0; i < 20; i++) {
            let capturedValue = i;
            let closure = function() {
                return capturedValue * 2;
            };
            closures.push(closure);
        }
    "#;

    let module = lower_source_to_ir3(js_source);
    let result = lane.execute(&module, "test");

    // Should either succeed within limits or fail with appropriate memory error
    match result {
        Ok(_) => {
            // Acceptable if within memory budget
        }
        Err(InterpreterError::MemoryBudgetExceeded { .. }) => {
            // Expected if closure snapshots exceed budget
        }
        other => panic!("Unexpected error: {:?}", other),
    }
}

#[test]
fn test_generator_memory_exhaustion() {
    let lane = adversarial_lane();

    // Test: Generator that creates objects on each yield
    let js_source = r#"
        function* objectGenerator() {
            for (let i = 0; i < 200; i++) {
                yield { id: i, data: "test data" };
            }
        }

        let gen = objectGenerator();
        let results = [];
        for (let i = 0; i < 200; i++) {
            let next = gen.next();
            if (next.done) break;
            results.push(next.value);
        }
    "#;

    let module = lower_source_to_ir3(js_source);
    let result = lane.execute(&module, "test");

    // Should fail with MemoryBudgetExceeded, not panic
    match result {
        Err(InterpreterError::MemoryBudgetExceeded { .. }) => {
            // Expected - fallible alloc_object should return error
        }
        Ok(_) => {
            // Acceptable if generator implementation is efficient enough
        }
        other => panic!("Expected clean error or success, got: {:?}", other),
    }
}

#[test]
fn test_iterator_allocation_loop() {
    let lane = adversarial_lane();

    // Test: Create many iterators to test iterator table bounds
    let js_source = r#"
        let arrays = [];
        for (let i = 0; i < 100; i++) {
            let arr = [1, 2, 3, 4, 5];
            let iterator = arr[Symbol.iterator]();
            arrays.push(iterator);
        }
    "#;

    let module = lower_source_to_ir3(js_source);
    let result = lane.execute(&module, "test");

    // Should either succeed or fail gracefully with budget error
    match result {
        Ok(_) => {
            // Acceptable if iterator allocation is efficient
        }
        Err(InterpreterError::MemoryBudgetExceeded { .. }) => {
            // Expected if iterator table exceeds budget
        }
        other => panic!("Expected success or budget error, got: {:?}", other),
    }
}

#[test]
fn test_combined_memory_exhaustion() {
    let lane = adversarial_lane();

    // Test: Combine objects, closures, and strings simultaneously
    let js_source = r#"
        let data = [];
        for (let i = 0; i < 50; i++) {
            let capturedValue = "captured_" + i;
            let obj = {
                id: i,
                name: "object_" + i,
                closure: function() {
                    return capturedValue + "_result";
                }
            };
            data.push(obj);
        }
    "#;

    let module = lower_source_to_ir3(js_source);
    let result = lane.execute(&module, "test");

    // Should fail with MemoryBudgetExceeded due to combined memory pressure
    match result {
        Err(InterpreterError::MemoryBudgetExceeded { .. }) => {
            // Expected outcome
        }
        Ok(_) => {
            // Acceptable if implementation is very efficient
        }
        other => panic!("Expected budget error or success, got: {:?}", other),
    }
}

#[test]
fn test_memory_budget_boundary_conditions() {
    let mut config = adversarial_config();
    config.max_heap_objects = 5; // Exact boundary testing
    config.granted_capabilities = std::collections::BTreeSet::new();

    let lane = QuickJsLane::with_config(config);

    // Test: Allocate exactly max_heap_objects - should succeed
    let js_source = r#"
        let obj1 = {};
        let obj2 = {};
        let obj3 = {};
        let obj4 = {};
        let obj5 = {}; // This should be the 5th object
    "#;

    let module = lower_source_to_ir3(js_source);
    let result = lane.execute(&module, "test");

    match result {
        Ok(_) => {
            // Should succeed with exactly 5 objects
        }
        other => panic!("Expected success with 5 objects, got: {:?}", other),
    }

    // Test: Allocate one more object - should fail
    let js_source_overflow = r#"
        let obj1 = {};
        let obj2 = {};
        let obj3 = {};
        let obj4 = {};
        let obj5 = {};
        let obj6 = {}; // This should exceed the limit
    "#;

    let module_overflow = lower_source_to_ir3(js_source_overflow);
    let result_overflow = lane.execute(&module_overflow, "test-overflow");

    match result_overflow {
        Err(InterpreterError::MemoryBudgetExceeded { .. }) => {
            // Expected with 6th object
        }
        other => panic!(
            "Expected MemoryBudgetExceeded with 6 objects, got: {:?}",
            other
        ),
    }
}

#[test]
fn test_memory_recovery_after_budget_error() {
    let lane = adversarial_lane();

    // First execution: exceed budget
    let js_source_fail = r#"
        for (let i = 0; i < 200; i++) {
            let obj = { value: i };
        }
    "#;

    let module_fail = lower_source_to_ir3(js_source_fail);
    let result_fail = lane.execute(&module_fail, "test-fail");

    assert!(matches!(
        result_fail,
        Err(InterpreterError::MemoryBudgetExceeded { .. })
    ));

    // Second execution: should succeed with smaller allocation
    let js_source_succeed = r#"
        let obj = { value: 42 };
    "#;

    let module_succeed = lower_source_to_ir3(js_source_succeed);
    let result_succeed = lane.execute(&module_succeed, "test-succeed");

    match result_succeed {
        Ok(_) => {
            // Expected - interpreter state should be clean after error
        }
        other => panic!("Expected recovery after budget error, got: {:?}", other),
    }
}
