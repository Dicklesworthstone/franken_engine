//! Regression tests for Call instruction capability gate (bd-3mmzl)
//!
//! The Call instruction must apply the same capability checks as HostCall when
//! dispatching to builtin functions. This prevents security bypass where Call
//! could invoke privileged builtins without proper capability grants.

use frankenengine_engine::baseline_interpreter::{
    BaselineInterpreter, InterpreterConfig, InterpreterError, RuntimeCapability,
};
use frankenengine_engine::capability_witness::CapabilityProfile;
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::{
    ExecutionBounds, ExecutionProfile, LoadModuleRequest, Module, ModuleExecution, ModuleSource,
};
use std::collections::BTreeSet;

/// Test helper to create a baseline interpreter with specific capabilities
fn create_interpreter_with_capabilities(
    capabilities: Vec<RuntimeCapability>,
) -> BaselineInterpreter {
    let mut granted_capabilities = BTreeSet::new();
    for cap in capabilities {
        granted_capabilities.insert(cap);
    }

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

/// Test helper to create a module with Call instruction to builtin
fn create_call_builtin_module(builtin_idx: u32) -> Module {
    use frankenengine_engine::ir3::{Ir3Instruction, RegisterId};

    let instructions = vec![
        // Call builtin function (index maps to Object.keys, Array.isArray, etc.)
        Ir3Instruction::Call {
            function_index: builtin_idx,
            args: vec![],
            dst: RegisterId(0),
        },
        Ir3Instruction::Return {
            value: Some(RegisterId(0)),
        },
    ];

    Module {
        instructions,
        function_table: Vec::new(), // Empty - force builtin lookup
        string_table: vec!["test".to_string()],
        specifier: "test://call-builtin".to_string(),
        source_text: "// test call to builtin".to_string(),
        exports: Vec::new(),
        imports: Vec::new(),
        witness_events: Vec::new(),
        hostcall_decisions: Vec::new(),
        metadata: Default::default(),
    }
}

#[test]
fn test_call_builtin_no_capabilities_denied() {
    // Test: Call to builtin with NO capabilities granted should be denied
    let mut interpreter = create_interpreter_with_capabilities(vec![]);
    let module = create_call_builtin_module(0); // Object.keys

    let request = LoadModuleRequest {
        module_source: ModuleSource::Compiled(module),
        execution_profile: ExecutionProfile::Deterministic,
        execution_bounds: ExecutionBounds::default(),
    };

    let result = interpreter.execute_module(request);

    assert!(matches!(
        result,
        Err(InterpreterError::CapabilityDenied { .. })
    ));
    if let Err(InterpreterError::CapabilityDenied { capability }) = result {
        assert!(capability.contains("builtin:ObjectKeys"));
    }
}

#[test]
fn test_call_builtin_wrong_capability_denied() {
    // Test: Call to builtin with wrong capability granted should be denied
    let mut interpreter = create_interpreter_with_capabilities(vec![
        RuntimeCapability::FileSystemRead, // Wrong capability for Object.keys
    ]);
    let module = create_call_builtin_module(0); // Object.keys

    let request = LoadModuleRequest {
        module_source: ModuleSource::Compiled(module),
        execution_profile: ExecutionProfile::Deterministic,
        execution_bounds: ExecutionBounds::default(),
    };

    let result = interpreter.execute_module(request);

    assert!(matches!(
        result,
        Err(InterpreterError::CapabilityDenied { .. })
    ));
    if let Err(InterpreterError::CapabilityDenied { capability }) = result {
        assert!(capability.contains("builtin:ObjectKeys"));
    }
}

#[test]
fn test_call_builtin_unknown_tag_denied() {
    // Test: Call to builtin with unknown capability tag should fail-closed
    let mut interpreter = create_interpreter_with_capabilities(vec![]);
    let module = create_call_builtin_module(999); // Unknown builtin index

    let request = LoadModuleRequest {
        module_source: ModuleSource::Compiled(module),
        execution_profile: ExecutionProfile::Deterministic,
        execution_bounds: ExecutionBounds::default(),
    };

    let result = interpreter.execute_module(request);

    // Should fail with FunctionNotFound since 999 doesn't map to any builtin
    assert!(matches!(
        result,
        Err(InterpreterError::FunctionNotFound { .. })
    ));
}

#[test]
fn test_call_builtin_correct_capability_allowed() {
    // Test: Call to builtin with correct capability should succeed
    use frankenengine_engine::baseline_interpreter::DETERMINISTIC_PROFILE_LABEL;

    let mut interpreter = create_interpreter_with_capabilities(vec![
        RuntimeCapability::ObjectManipulation, // Correct capability for Object.keys
    ]);
    let module = create_call_builtin_module(0); // Object.keys

    let request = LoadModuleRequest {
        module_source: ModuleSource::Compiled(module),
        execution_profile: ExecutionProfile::Deterministic,
        execution_bounds: ExecutionBounds::default(),
    };

    // This should not fail with CapabilityDenied
    let result = interpreter.execute_module(request);

    // May fail for other reasons (e.g., missing arguments) but not capability denial
    if let Err(ref error) = result {
        assert!(!matches!(error, InterpreterError::CapabilityDenied { .. }));
    }
}

#[test]
fn test_call_regular_function_unaffected() {
    // Test: Call to regular JS function should be unaffected by capability gates
    use frankenengine_engine::ir3::{FunctionDefinition, Ir3Instruction, RegisterId};

    let regular_func = FunctionDefinition {
        name: "regular_func".to_string(),
        parameters: vec![],
        body: vec![
            Ir3Instruction::LoadConstant {
                dst: RegisterId(0),
                value: 42.into(), // Assuming Value::from supports i32
            },
            Ir3Instruction::Return {
                value: Some(RegisterId(0)),
            },
        ],
        local_count: 1,
        captures: vec![],
    };

    let instructions = vec![
        Ir3Instruction::Call {
            function_index: 0, // Index into function_table, not builtin
            args: vec![],
            dst: RegisterId(0),
        },
        Ir3Instruction::Return {
            value: Some(RegisterId(0)),
        },
    ];

    let module = Module {
        instructions,
        function_table: vec![regular_func], // Non-empty function table
        string_table: vec!["test".to_string()],
        specifier: "test://call-regular".to_string(),
        source_text: "function regular_func() { return 42; }".to_string(),
        exports: Vec::new(),
        imports: Vec::new(),
        witness_events: Vec::new(),
        hostcall_decisions: Vec::new(),
        metadata: Default::default(),
    };

    let mut interpreter = create_interpreter_with_capabilities(vec![]); // No capabilities

    let request = LoadModuleRequest {
        module_source: ModuleSource::Compiled(module),
        execution_profile: ExecutionProfile::Deterministic,
        execution_bounds: ExecutionBounds::default(),
    };

    let result = interpreter.execute_module(request);

    // Should NOT fail with CapabilityDenied - regular functions bypass capability gate
    if let Err(ref error) = result {
        assert!(!matches!(error, InterpreterError::CapabilityDenied { .. }));
    }
}

#[test]
fn test_call_capability_witness_events_recorded() {
    // Test: Capability denial should record proper witness events
    let mut interpreter = create_interpreter_with_capabilities(vec![]);
    let module = create_call_builtin_module(0); // Object.keys without capability

    let request = LoadModuleRequest {
        module_source: ModuleSource::Compiled(module),
        execution_profile: ExecutionProfile::Deterministic,
        execution_bounds: ExecutionBounds::default(),
    };

    let _ = interpreter.execute_module(request); // Expected to fail

    // Verify witness events were recorded for the capability check
    let witness_events = interpreter.get_witness_events();
    let capability_events: Vec<_> = witness_events
        .iter()
        .filter(|event| {
            matches!(
                event.kind,
                frankenengine_engine::capability_witness::WitnessEventKind::CapabilityChecked
            )
        })
        .collect();

    assert!(
        !capability_events.is_empty(),
        "Capability check should generate witness events"
    );

    // Verify hostcall decision records were created
    let decisions = interpreter.get_hostcall_decisions();
    let denied_decisions: Vec<_> = decisions
        .iter()
        .filter(|decision| !decision.allowed)
        .collect();

    assert!(
        !denied_decisions.is_empty(),
        "Denied capability should create decision record"
    );
}

#[test]
fn test_call_different_builtin_types() {
    // Test: Different builtin types (Object, Array, String) all subject to capability gate
    let test_cases = vec![
        (0, "Object.keys"),    // Object builtin
        (10, "Array.isArray"), // Array builtin
        (30, "String.charAt"), // String builtin
    ];

    for (builtin_idx, builtin_name) in test_cases {
        let mut interpreter = create_interpreter_with_capabilities(vec![]);
        let module = create_call_builtin_module(builtin_idx);

        let request = LoadModuleRequest {
            module_source: ModuleSource::Compiled(module),
            execution_profile: ExecutionProfile::Deterministic,
            execution_bounds: ExecutionBounds::default(),
        };

        let result = interpreter.execute_module(request);

        assert!(
            matches!(result, Err(InterpreterError::CapabilityDenied { .. })),
            "Builtin {} should be denied without capabilities",
            builtin_name
        );
    }
}

#[test]
fn test_call_capability_consistency_with_hostcall() {
    // Test: Call instruction capability behavior should match HostCall instruction
    use frankenengine_engine::ir3::{Ir3Instruction, RegisterId, RuntimeCapabilityTag};

    // Create modules with equivalent Call vs HostCall
    let call_module = create_call_builtin_module(0); // Object.keys via Call

    let hostcall_module = Module {
        instructions: vec![
            Ir3Instruction::HostCall {
                capability: RuntimeCapabilityTag("builtin:ObjectKeys".to_string()),
                args: vec![],
                dst: RegisterId(0),
            },
            Ir3Instruction::Return {
                value: Some(RegisterId(0)),
            },
        ],
        function_table: Vec::new(),
        string_table: vec!["test".to_string()],
        specifier: "test://hostcall-builtin".to_string(),
        source_text: "// test hostcall to builtin".to_string(),
        exports: Vec::new(),
        imports: Vec::new(),
        witness_events: Vec::new(),
        hostcall_decisions: Vec::new(),
        metadata: Default::default(),
    };

    // Test both without capabilities - should both fail
    let mut call_interpreter = create_interpreter_with_capabilities(vec![]);
    let mut hostcall_interpreter = create_interpreter_with_capabilities(vec![]);

    let call_request = LoadModuleRequest {
        module_source: ModuleSource::Compiled(call_module),
        execution_profile: ExecutionProfile::Deterministic,
        execution_bounds: ExecutionBounds::default(),
    };

    let hostcall_request = LoadModuleRequest {
        module_source: ModuleSource::Compiled(hostcall_module),
        execution_profile: ExecutionProfile::Deterministic,
        execution_bounds: ExecutionBounds::default(),
    };

    let call_result = call_interpreter.execute_module(call_request);
    let hostcall_result = hostcall_interpreter.execute_module(hostcall_request);

    // Both should fail with CapabilityDenied
    assert!(matches!(
        call_result,
        Err(InterpreterError::CapabilityDenied { .. })
    ));
    assert!(matches!(
        hostcall_result,
        Err(InterpreterError::CapabilityDenied { .. })
    ));

    // Error messages should reference the same capability
    if let (
        Err(InterpreterError::CapabilityDenied {
            capability: call_cap,
        }),
        Err(InterpreterError::CapabilityDenied {
            capability: hostcall_cap,
        }),
    ) = (call_result, hostcall_result)
    {
        assert_eq!(
            call_cap, hostcall_cap,
            "Call and HostCall should deny same capability"
        );
    }
}
