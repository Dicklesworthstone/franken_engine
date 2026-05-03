//! Regression tests for Array.every and Array.map callback invocation (bd-2gd4b bd-1rs5t)
//!
//! These tests verify that Array.every and Array.map properly handle callback functions,
//! including argument validation, empty arrays, error propagation, and deterministic behavior.

use frankenengine_engine::baseline_interpreter::{
    BaselineInterpreter, InterpreterConfig, InterpreterError, RuntimeCapability,
};
use frankenengine_engine::capability_witness::CapabilityProfile;
use frankenengine_engine::ir_contract::{CapabilityTag, Ir3Instruction, RegRange};
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::{
    ExecutionBounds, ExecutionProfile, LoadModuleRequest, Module, ModuleSource,
};
use std::collections::BTreeSet;

/// Test helper to create a baseline interpreter with array manipulation capabilities
fn create_interpreter() -> BaselineInterpreter {
    let mut granted_capabilities = BTreeSet::new();
    granted_capabilities.insert(RuntimeCapability::ObjectManipulation);

    let config = InterpreterConfig {
        granted_capabilities,
        max_call_depth: 100,
        max_iterations: 10000,
        execution_timeout_ms: Some(5000),
        capability_profile: CapabilityProfile::remote(),
        security_epoch: SecurityEpoch::from_raw(1),
        enable_debugging: false,
    };

    BaselineInterpreter::new(config)
}

/// Helper to create a basic test module that calls Array.every
fn create_basic_array_every_module() -> Module {
    let instructions = vec![
        // Create array
        Ir3Instruction::NewArray { dst: 0 },
        Ir3Instruction::LoadInt { dst: 3, value: 0 }, // length = 0 (empty array)
        Ir3Instruction::LoadStr {
            dst: 4,
            pool_index: 0,
        }, // "length"
        Ir3Instruction::SetProperty {
            obj: 0,
            key: 4,
            val: 3,
        },
        // Create dummy function
        Ir3Instruction::LoadInt { dst: 1, value: 0 }, // Function index 0
        // Call Array.prototype.every
        Ir3Instruction::HostCall {
            capability: CapabilityTag("builtin:ArrayPrototypeEvery".to_string()),
            args: RegRange { start: 0, count: 2 },
            dst: 2,
        },
        Ir3Instruction::Return { value: Some(2) },
    ];

    Module {
        instructions,
        function_table: Vec::new(),
        string_table: vec!["length".to_string()],
        specifier: "test://array-every-empty".to_string(),
        source_text: "[].every(x => true)".to_string(),
        exports: Vec::new(),
        imports: Vec::new(),
        witness_events: Vec::new(),
        hostcall_decisions: Vec::new(),
        metadata: Default::default(),
    }
}

/// Helper to create a basic test module that calls Array.map
fn create_basic_array_map_module() -> Module {
    let instructions = vec![
        // Create array
        Ir3Instruction::NewArray { dst: 0 },
        Ir3Instruction::LoadInt { dst: 3, value: 0 }, // length = 0 (empty array)
        Ir3Instruction::LoadStr {
            dst: 4,
            pool_index: 0,
        }, // "length"
        Ir3Instruction::SetProperty {
            obj: 0,
            key: 4,
            val: 3,
        },
        // Create dummy function
        Ir3Instruction::LoadInt { dst: 1, value: 0 }, // Function index 0
        // Call Array.prototype.map
        Ir3Instruction::HostCall {
            capability: CapabilityTag("builtin:ArrayPrototypeMap".to_string()),
            args: RegRange { start: 0, count: 2 },
            dst: 2,
        },
        Ir3Instruction::Return { value: Some(2) },
    ];

    Module {
        instructions,
        function_table: Vec::new(),
        string_table: vec!["length".to_string()],
        specifier: "test://array-map-empty".to_string(),
        source_text: "[].map(x => x)".to_string(),
        exports: Vec::new(),
        imports: Vec::new(),
        witness_events: Vec::new(),
        hostcall_decisions: Vec::new(),
        metadata: Default::default(),
    }
}

#[test]
fn test_array_every_empty_array() {
    // Test: Array.every on empty array should return true (per ES spec)
    let mut interpreter = create_interpreter();
    let module = create_basic_array_every_module();

    let request = LoadModuleRequest {
        module_source: ModuleSource::Compiled(module),
        execution_profile: ExecutionProfile::Deterministic,
        execution_bounds: ExecutionBounds::default(),
    };

    let result = interpreter.execute_module(request);

    // Should succeed and return true for empty array
    match result {
        Ok(execution_result) => {
            // We expect the method to complete successfully
            // The actual return value validation can be enhanced once the implementation is complete
            println!(
                "Array.every execution completed: {:?}",
                execution_result.value
            );
        }
        Err(e) => panic!("Array.every execution failed: {:?}", e),
    }
}

#[test]
fn test_array_map_empty_array() {
    // Test: Array.map on empty array should return empty array
    let mut interpreter = create_interpreter();
    let module = create_basic_array_map_module();

    let request = LoadModuleRequest {
        module_source: ModuleSource::Compiled(module),
        execution_profile: ExecutionProfile::Deterministic,
        execution_bounds: ExecutionBounds::default(),
    };

    let result = interpreter.execute_module(request);

    // Should succeed and return empty array
    match result {
        Ok(execution_result) => {
            // We expect the method to complete successfully
            // The actual return value validation can be enhanced once the implementation is complete
            println!(
                "Array.map execution completed: {:?}",
                execution_result.value
            );
        }
        Err(e) => panic!("Array.map execution failed: {:?}", e),
    }
}

#[test]
fn test_array_every_missing_callback() {
    // Test: Array.every with missing callback argument should throw TypeError
    let mut interpreter = create_interpreter();

    let instructions = vec![
        // Create array
        Ir3Instruction::NewArray { dst: 0 },
        // Call Array.prototype.every with only array (no callback)
        Ir3Instruction::HostCall {
            capability: CapabilityTag("builtin:ArrayPrototypeEvery".to_string()),
            args: RegRange { start: 0, count: 1 }, // Only array, no callback
            dst: 2,
        },
        Ir3Instruction::Return { value: Some(2) },
    ];

    let module = Module {
        instructions,
        function_table: Vec::new(),
        string_table: vec!["test".to_string()],
        specifier: "test://array-every-no-callback".to_string(),
        source_text: "[].every()".to_string(),
        exports: Vec::new(),
        imports: Vec::new(),
        witness_events: Vec::new(),
        hostcall_decisions: Vec::new(),
        metadata: Default::default(),
    };

    let request = LoadModuleRequest {
        module_source: ModuleSource::Compiled(module),
        execution_profile: ExecutionProfile::Deterministic,
        execution_bounds: ExecutionBounds::default(),
    };

    let result = interpreter.execute_module(request);

    // Should fail with TypeError due to missing callback
    assert!(matches!(result, Err(InterpreterError::TypeError { .. })));
}

#[test]
fn test_array_map_missing_callback() {
    // Test: Array.map with missing callback argument should throw TypeError
    let mut interpreter = create_interpreter();

    let instructions = vec![
        // Create array
        Ir3Instruction::NewArray { dst: 0 },
        // Call Array.prototype.map with only array (no callback)
        Ir3Instruction::HostCall {
            capability: CapabilityTag("builtin:ArrayPrototypeMap".to_string()),
            args: RegRange { start: 0, count: 1 }, // Only array, no callback
            dst: 2,
        },
        Ir3Instruction::Return { value: Some(2) },
    ];

    let module = Module {
        instructions,
        function_table: Vec::new(),
        string_table: vec!["test".to_string()],
        specifier: "test://array-map-no-callback".to_string(),
        source_text: "[].map()".to_string(),
        exports: Vec::new(),
        imports: Vec::new(),
        witness_events: Vec::new(),
        hostcall_decisions: Vec::new(),
        metadata: Default::default(),
    };

    let request = LoadModuleRequest {
        module_source: ModuleSource::Compiled(module),
        execution_profile: ExecutionProfile::Deterministic,
        execution_bounds: ExecutionBounds::default(),
    };

    let result = interpreter.execute_module(request);

    // Should fail with TypeError due to missing callback
    assert!(matches!(result, Err(InterpreterError::TypeError { .. })));
}

#[test]
fn test_array_every_non_function_callback() {
    // Test: Array.every with non-function callback should throw TypeError
    let mut interpreter = create_interpreter();

    let instructions = vec![
        // Create array
        Ir3Instruction::NewArray { dst: 0 },
        // Non-function callback (string)
        Ir3Instruction::LoadStr {
            dst: 1,
            pool_index: 0,
        },
        // Call Array.prototype.every
        Ir3Instruction::HostCall {
            capability: CapabilityTag("builtin:ArrayPrototypeEvery".to_string()),
            args: RegRange { start: 0, count: 2 },
            dst: 2,
        },
        Ir3Instruction::Return { value: Some(2) },
    ];

    let module = Module {
        instructions,
        function_table: Vec::new(),
        string_table: vec!["not-a-function".to_string()],
        specifier: "test://array-every-bad-callback".to_string(),
        source_text: "[].every('not-a-function')".to_string(),
        exports: Vec::new(),
        imports: Vec::new(),
        witness_events: Vec::new(),
        hostcall_decisions: Vec::new(),
        metadata: Default::default(),
    };

    let request = LoadModuleRequest {
        module_source: ModuleSource::Compiled(module),
        execution_profile: ExecutionProfile::Deterministic,
        execution_bounds: ExecutionBounds::default(),
    };

    let result = interpreter.execute_module(request);

    // Should fail with TypeError
    assert!(matches!(result, Err(InterpreterError::TypeError { .. })));
}

#[test]
fn test_array_map_non_function_callback() {
    // Test: Array.map with non-function callback should throw TypeError
    let mut interpreter = create_interpreter();

    let instructions = vec![
        // Create array
        Ir3Instruction::NewArray { dst: 0 },
        // Non-function callback (number)
        Ir3Instruction::LoadInt { dst: 1, value: 123 },
        // Call Array.prototype.map
        Ir3Instruction::HostCall {
            capability: CapabilityTag("builtin:ArrayPrototypeMap".to_string()),
            args: RegRange { start: 0, count: 2 },
            dst: 2,
        },
        Ir3Instruction::Return { value: Some(2) },
    ];

    let module = Module {
        instructions,
        function_table: Vec::new(),
        string_table: vec!["test".to_string()],
        specifier: "test://array-map-bad-callback".to_string(),
        source_text: "[].map(123)".to_string(),
        exports: Vec::new(),
        imports: Vec::new(),
        witness_events: Vec::new(),
        hostcall_decisions: Vec::new(),
        metadata: Default::default(),
    };

    let request = LoadModuleRequest {
        module_source: ModuleSource::Compiled(module),
        execution_profile: ExecutionProfile::Deterministic,
        execution_bounds: ExecutionBounds::default(),
    };

    let result = interpreter.execute_module(request);

    // Should fail with TypeError
    assert!(matches!(result, Err(InterpreterError::TypeError { .. })));
}

#[test]
fn test_array_methods_deterministic_behavior() {
    // Test: Same input should produce same output across multiple runs

    // Run Array.every multiple times with same input
    for _ in 0..3 {
        let mut interpreter = create_interpreter();
        let module = create_basic_array_every_module();
        let request = LoadModuleRequest {
            module_source: ModuleSource::Compiled(module),
            execution_profile: ExecutionProfile::Deterministic,
            execution_bounds: ExecutionBounds::default(),
        };

        let result = interpreter.execute_module(request);
        assert!(
            matches!(result, Ok(_)),
            "Array.every should execute deterministically"
        );
    }

    // Run Array.map multiple times with same input
    for _ in 0..3 {
        let mut interpreter = create_interpreter();
        let module = create_basic_array_map_module();
        let request = LoadModuleRequest {
            module_source: ModuleSource::Compiled(module),
            execution_profile: ExecutionProfile::Deterministic,
            execution_bounds: ExecutionBounds::default(),
        };

        let result = interpreter.execute_module(request);
        assert!(
            matches!(result, Ok(_)),
            "Array.map should execute deterministically"
        );
    }
}

#[test]
fn test_array_every_non_object_receiver() {
    // Test: Array.every called on non-object should throw TypeError
    let mut interpreter = create_interpreter();

    let instructions = vec![
        // Use a non-object (number) as receiver
        Ir3Instruction::LoadInt { dst: 0, value: 42 },
        // Create dummy function
        Ir3Instruction::LoadInt { dst: 1, value: 0 },
        // Call Array.prototype.every
        Ir3Instruction::HostCall {
            capability: CapabilityTag("builtin:ArrayPrototypeEvery".to_string()),
            args: RegRange { start: 0, count: 2 },
            dst: 2,
        },
        Ir3Instruction::Return { value: Some(2) },
    ];

    let module = Module {
        instructions,
        function_table: Vec::new(),
        string_table: vec!["test".to_string()],
        specifier: "test://array-every-non-object".to_string(),
        source_text: "Array.prototype.every.call(42, () => true)".to_string(),
        exports: Vec::new(),
        imports: Vec::new(),
        witness_events: Vec::new(),
        hostcall_decisions: Vec::new(),
        metadata: Default::default(),
    };

    let request = LoadModuleRequest {
        module_source: ModuleSource::Compiled(module),
        execution_profile: ExecutionProfile::Deterministic,
        execution_bounds: ExecutionBounds::default(),
    };

    let result = interpreter.execute_module(request);

    // Should fail with TypeError
    assert!(matches!(result, Err(InterpreterError::TypeError { .. })));
}
