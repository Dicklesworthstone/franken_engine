/// Integration tests for JIT hot path detection system.
/// Tests counter increment, threshold trigger, multi-function disambiguation,
/// BTreeMap determinism, threshold config respected, cold function eviction.

use std::collections::BTreeMap;

use frankenengine_engine::{
    Module, ModuleConfig,
    baseline_interpreter::{InterpreterCore, InterpreterConfig, InterpreterError},
    ir_contract::Ir3Instruction,
    value::Value,
    register::RegisterRange,
    function::Function,
};

fn create_test_module(instructions: Vec<Ir3Instruction>) -> Module {
    Module {
        functions: vec![Function {
            name: "test_function".to_string(),
            instructions,
            register_count: 10,
            parameter_count: 0,
            is_generator: false,
            is_async: false,
        }],
        config: ModuleConfig::default(),
        imports: vec![],
        exports: vec![],
    }
}

fn create_loop_module(loop_count: u32) -> Module {
    let instructions = vec![
        Ir3Instruction::LoadImmediate { dst: 0, value: Value::Number(0.0) },       // counter = 0
        Ir3Instruction::LoadImmediate { dst: 1, value: Value::Number(loop_count as f64) }, // limit
        // loop start (ip=2)
        Ir3Instruction::Add { lhs: 0, rhs: 2, dst: 0 },                           // counter += 1
        Ir3Instruction::LoadImmediate { dst: 2, value: Value::Number(1.0) },      // constant 1
        Ir3Instruction::Lt { lhs: 0, rhs: 1, dst: 3 },                           // counter < limit
        Ir3Instruction::JumpIf { cond: 3, target: 2 },                           // if true, jump back to loop start
        Ir3Instruction::Return { value: 0 },                                     // return counter
    ];
    create_test_module(instructions)
}

fn create_function_call_module() -> Module {
    Module {
        functions: vec![
            Function {
                name: "caller".to_string(),
                instructions: vec![
                    Ir3Instruction::LoadImmediate { dst: 0, value: Value::Function(1) }, // callee function
                    Ir3Instruction::Call {
                        callee: 0,
                        args: RegisterRange { start: 1, count: 0 },
                        dst: 2
                    },
                    Ir3Instruction::Return { value: 2 },
                ],
                register_count: 10,
                parameter_count: 0,
                is_generator: false,
                is_async: false,
            },
            Function {
                name: "callee".to_string(),
                instructions: vec![
                    Ir3Instruction::LoadImmediate { dst: 0, value: Value::Number(42.0) },
                    Ir3Instruction::Return { value: 0 },
                ],
                register_count: 10,
                parameter_count: 0,
                is_generator: false,
                is_async: false,
            },
        ],
        config: ModuleConfig::default(),
        imports: vec![],
        exports: vec![],
    }
}

#[test]
fn test_jit_function_call_counter_increment() {
    let mut interpreter = InterpreterCore::new(InterpreterConfig::quickjs_defaults(), "test");
    let module = create_function_call_module();

    // Initial state: no function calls recorded
    assert_eq!(interpreter.jit_get_function_call_count(1), 0);

    // Execute caller function - should increment call count for function 1 (callee)
    let result = interpreter.execute_function(&module, 0, &[]);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), Value::Number(42.0));

    // Function call count should be incremented
    assert_eq!(interpreter.jit_get_function_call_count(1), 1);

    // Call again to verify counter increments
    let result = interpreter.execute_function(&module, 0, &[]);
    assert!(result.is_ok());
    assert_eq!(interpreter.jit_get_function_call_count(1), 2);
}

#[test]
fn test_jit_loop_iteration_counter_increment() {
    let mut interpreter = InterpreterCore::new(InterpreterConfig::quickjs_defaults(), "test");
    let module = create_loop_module(5);

    // Initial state: no loop iterations recorded
    let loop_ip = 2; // IP of the loop backedge
    assert_eq!(interpreter.jit_get_loop_iteration_count(loop_ip), 0);

    // Execute function with loop
    let result = interpreter.execute_function(&module, 0, &[]);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), Value::Number(5.0));

    // Loop iterations should be recorded (5 iterations = 5 backedges)
    assert_eq!(interpreter.jit_get_loop_iteration_count(loop_ip), 5);
}

#[test]
fn test_jit_threshold_trigger_function_calls() {
    let mut interpreter = InterpreterCore::new(InterpreterConfig::quickjs_defaults(), "test");

    // Set a low threshold for testing
    interpreter.jit_set_hot_threshold(3);

    let module = create_function_call_module();

    // Call function multiple times to trigger threshold
    for i in 1..=3 {
        let result = interpreter.execute_function(&module, 0, &[]);
        assert!(result.is_ok());
        assert_eq!(interpreter.jit_get_function_call_count(1), i);
    }

    // At threshold, should still not be considered "hot" until exceeded
    assert_eq!(interpreter.jit_get_function_call_count(1), 3);

    // One more call should trigger hot path detection
    let result = interpreter.execute_function(&module, 0, &[]);
    assert!(result.is_ok());
    assert_eq!(interpreter.jit_get_function_call_count(1), 4);

    // Function should now be above threshold
    assert!(interpreter.jit_get_function_call_count(1) > interpreter.jit_get_hot_threshold());
}

#[test]
fn test_jit_threshold_trigger_loop_iterations() {
    let mut interpreter = InterpreterCore::new(InterpreterConfig::quickjs_defaults(), "test");

    // Set a low threshold for testing
    interpreter.jit_set_hot_threshold(3);

    let module = create_loop_module(5); // 5 iterations = 5 backedges
    let loop_ip = 2;

    // Execute function - loop should exceed threshold in single execution
    let result = interpreter.execute_function(&module, 0, &[]);
    assert!(result.is_ok());

    // Loop should be above threshold after single execution
    assert!(interpreter.jit_get_loop_iteration_count(loop_ip) > interpreter.jit_get_hot_threshold());
}

#[test]
fn test_jit_multi_function_disambiguation() {
    let mut interpreter = InterpreterCore::new(InterpreterConfig::quickjs_defaults(), "test");

    let module = Module {
        functions: vec![
            Function {
                name: "caller".to_string(),
                instructions: vec![
                    // Call function 1
                    Ir3Instruction::LoadImmediate { dst: 0, value: Value::Function(1) },
                    Ir3Instruction::Call {
                        callee: 0,
                        args: RegisterRange { start: 2, count: 0 },
                        dst: 3
                    },
                    // Call function 2
                    Ir3Instruction::LoadImmediate { dst: 0, value: Value::Function(2) },
                    Ir3Instruction::Call {
                        callee: 0,
                        args: RegisterRange { start: 2, count: 0 },
                        dst: 3
                    },
                    // Call function 1 again
                    Ir3Instruction::LoadImmediate { dst: 0, value: Value::Function(1) },
                    Ir3Instruction::Call {
                        callee: 0,
                        args: RegisterRange { start: 2, count: 0 },
                        dst: 3
                    },
                    Ir3Instruction::Return { value: 3 },
                ],
                register_count: 10,
                parameter_count: 0,
                is_generator: false,
                is_async: false,
            },
            Function {
                name: "func1".to_string(),
                instructions: vec![
                    Ir3Instruction::LoadImmediate { dst: 0, value: Value::Number(1.0) },
                    Ir3Instruction::Return { value: 0 },
                ],
                register_count: 10,
                parameter_count: 0,
                is_generator: false,
                is_async: false,
            },
            Function {
                name: "func2".to_string(),
                instructions: vec![
                    Ir3Instruction::LoadImmediate { dst: 0, value: Value::Number(2.0) },
                    Ir3Instruction::Return { value: 0 },
                ],
                register_count: 10,
                parameter_count: 0,
                is_generator: false,
                is_async: false,
            },
        ],
        config: ModuleConfig::default(),
        imports: vec![],
        exports: vec![],
    };

    // Execute caller function
    let result = interpreter.execute_function(&module, 0, &[]);
    assert!(result.is_ok());

    // Verify separate counters for each function
    assert_eq!(interpreter.jit_get_function_call_count(1), 2); // func1 called twice
    assert_eq!(interpreter.jit_get_function_call_count(2), 1); // func2 called once
}

#[test]
fn test_jit_btreemap_determinism() {
    let mut interpreter1 = InterpreterCore::new();
    let mut interpreter2 = InterpreterCore::new();

    let module = create_function_call_module();

    // Execute same sequence in both interpreters
    for _ in 0..5 {
        let result1 = interpreter1.execute_function(&module, 0, &[]);
        let result2 = interpreter2.execute_function(&module, 0, &[]);
        assert!(result1.is_ok());
        assert!(result2.is_ok());
        assert_eq!(result1, result2);
    }

    // Function call statistics should be identical
    let stats1 = interpreter1.jit_get_statistics();
    let stats2 = interpreter2.jit_get_statistics();

    // stats = (function_counts_len, loop_counts_len, hot_threshold, eviction_counter)
    assert_eq!(stats1, stats2);
}

#[test]
fn test_jit_threshold_config_respected() {
    let mut interpreter = InterpreterCore::new(InterpreterConfig::quickjs_defaults(), "test");

    // Test default threshold
    let default_threshold = 10_000;
    assert_eq!(interpreter.jit_get_hot_threshold(), default_threshold);

    // Test custom threshold
    let custom_threshold = 500;
    interpreter.jit_set_hot_threshold(custom_threshold);
    assert_eq!(interpreter.jit_get_hot_threshold(), custom_threshold);

    let module = create_function_call_module();

    // Execute functions just below threshold
    for _ in 0..custom_threshold {
        let result = interpreter.execute_function(&module, 0, &[]);
        assert!(result.is_ok());
    }

    // Should be at threshold but not yet "hot"
    assert_eq!(interpreter.jit_get_function_call_count(1), custom_threshold as u64);

    // One more execution should exceed threshold
    let result = interpreter.execute_function(&module, 0, &[]);
    assert!(result.is_ok());
    assert!(interpreter.jit_get_function_call_count(1) > custom_threshold as u64);
}

#[test]
fn test_jit_cold_function_eviction() {
    let mut interpreter = InterpreterCore::new(InterpreterConfig::quickjs_defaults(), "test");

    // Set low threshold for quick testing
    interpreter.jit_set_hot_threshold(2);

    let module = Module {
        functions: vec![
            Function {
                name: "caller".to_string(),
                instructions: vec![
                    // Call many different functions
                    Ir3Instruction::LoadImmediate { dst: 0, value: Value::Function(1) },
                    Ir3Instruction::Call {
                        callee: 0,
                        args: RegisterRange { start: 2, count: 0 },
                        dst: 3
                    },
                    Ir3Instruction::LoadImmediate { dst: 0, value: Value::Function(2) },
                    Ir3Instruction::Call {
                        callee: 0,
                        args: RegisterRange { start: 2, count: 0 },
                        dst: 3
                    },
                    Ir3Instruction::Return { value: 3 },
                ],
                register_count: 10,
                parameter_count: 0,
                is_generator: false,
                is_async: false,
            },
            Function {
                name: "func1".to_string(),
                instructions: vec![
                    Ir3Instruction::LoadImmediate { dst: 0, value: Value::Number(1.0) },
                    Ir3Instruction::Return { value: 0 },
                ],
                register_count: 10,
                parameter_count: 0,
                is_generator: false,
                is_async: false,
            },
            Function {
                name: "func2".to_string(),
                instructions: vec![
                    Ir3Instruction::LoadImmediate { dst: 0, value: Value::Number(2.0) },
                    Ir3Instruction::Return { value: 0 },
                ],
                register_count: 10,
                parameter_count: 0,
                is_generator: false,
                is_async: false,
            },
        ],
        config: ModuleConfig::default(),
        imports: vec![],
        exports: vec![],
    };

    // Execute several times to trigger eviction behavior
    for _ in 0..100 {
        let result = interpreter.execute_function(&module, 0, &[]);
        assert!(result.is_ok());
    }

    let stats = interpreter.jit_get_statistics();
    let (function_counts_len, _loop_counts_len, _hot_threshold, eviction_counter) = stats;

    // With periodic eviction, some functions should have been evicted
    // The eviction counter should show some activity
    assert!(eviction_counter > 0);

    // Function counts should still exist for recent calls
    assert!(function_counts_len > 0);
}

#[test]
fn test_jit_statistics_accuracy() {
    let mut interpreter = InterpreterCore::new(InterpreterConfig::quickjs_defaults(), "test");

    let module = create_loop_module(3);

    // Execute function multiple times
    for _ in 0..5 {
        let result = interpreter.execute_function(&module, 0, &[]);
        assert!(result.is_ok());
    }

    let stats = interpreter.jit_get_statistics();
    let (function_counts_len, loop_counts_len, _hot_threshold, _eviction_counter) = stats;

    // Verify statistics match expected values
    assert_eq!(function_counts_len, 1); // 1 function being tracked (function 0)
    assert_eq!(loop_counts_len, 1); // 1 loop being tracked (at IP 2)

    // Function call count should be recorded
    assert_eq!(interpreter.jit_get_function_call_count(0), 5);

    // Loop iteration count should be recorded for the backedge IP
    assert_eq!(interpreter.jit_get_loop_iteration_count(2), 15);
}

#[test]
fn test_jit_clear_counters() {
    let mut interpreter = InterpreterCore::new(InterpreterConfig::quickjs_defaults(), "test");
    let module = create_function_call_module();

    // Build up some statistics
    for _ in 0..3 {
        let result = interpreter.execute_function(&module, 0, &[]);
        assert!(result.is_ok());
    }

    // Verify statistics exist
    assert!(interpreter.jit_get_function_call_count(1) > 0);
    let stats = interpreter.jit_get_statistics();
    assert!(stats.total_function_calls > 0);

    // Clear all counters
    interpreter.jit_clear_counters();

    // Verify all statistics reset
    assert_eq!(interpreter.jit_get_function_call_count(1), 0);
    let stats = interpreter.jit_get_statistics();
    let (function_counts_len, loop_counts_len, _hot_threshold, eviction_counter) = stats;
    assert_eq!(function_counts_len, 0);
    assert_eq!(loop_counts_len, 0);
    assert_eq!(eviction_counter, 0);
}

#[test]
fn test_jit_edge_cases() {
    let mut interpreter = InterpreterCore::new(InterpreterConfig::quickjs_defaults(), "test");

    // Test getting statistics for non-existent function/loop
    assert_eq!(interpreter.jit_get_function_call_count(999), 0);
    assert_eq!(interpreter.jit_get_loop_iteration_count(999), 0);

    // Test setting invalid threshold
    interpreter.jit_set_hot_threshold(0);
    assert_eq!(interpreter.jit_get_hot_threshold(), 1); // Should clamp to minimum 1

    // Test statistics with no execution
    let stats = interpreter.jit_get_statistics();
    let (function_counts_len, loop_counts_len, _hot_threshold, eviction_counter) = stats;
    assert_eq!(function_counts_len, 0);
    assert_eq!(loop_counts_len, 0);
    assert_eq!(eviction_counter, 0);
}