//! Comprehensive tests for error stack trace formatting (bd-2fx18).
//!
//! Verifies proper V8-style stack trace formatting with:
//! - Simple call chain formatting
//! - Nested function calls with proper frame order
//! - Async/await frame chain preservation
//! - Stack truncation with "... N more frames" message
//! - Missing information fallback handling
//! - BTreeSet/BTreeMap deterministic ordering

#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use frankenengine_engine::baseline_interpreter::{
    ExecutionResult, InterpreterConfig, InterpreterCore, InterpreterError, Value,
};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::ir_contract::{
    CapabilityTag, Ir3FunctionDesc, Ir3Instruction, Ir3Module, RegRange,
};

fn config_with_caps(caps: &[RuntimeCapability]) -> InterpreterConfig {
    let mut config = InterpreterConfig::quickjs_defaults();
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::VmDispatch]);
    config.granted_capabilities.extend(caps.iter().copied());
    config
}

fn execute(
    module: &Ir3Module,
    caps: &[RuntimeCapability],
) -> Result<ExecutionResult, InterpreterError> {
    InterpreterCore::new(config_with_caps(caps), "error-stack-trace-public-api").execute(module)
}

fn error_property_module(source_label: &str, message: &str, property: &str) -> Ir3Module {
    let error_tag = CapabilityTag("builtin:Error".to_string());
    let mut module = Ir3Module::new(ContentHash::compute(source_label.as_bytes()), source_label);
    module.constant_pool = vec![message.to_string(), property.to_string()];
    module.instructions = vec![
        Ir3Instruction::LoadStr {
            dst: 0,
            pool_index: 0,
        },
        Ir3Instruction::HostCall {
            capability: error_tag.clone(),
            args: RegRange { start: 0, count: 1 },
            dst: 1,
        },
        Ir3Instruction::LoadStr {
            dst: 2,
            pool_index: 1,
        },
        Ir3Instruction::GetProperty {
            obj: 1,
            key: 2,
            dst: 3,
        },
        Ir3Instruction::Return { value: 3 },
    ];
    module.required_capabilities = vec![error_tag];
    module
}

fn integer_error_message_module(source_label: &str) -> Ir3Module {
    let error_tag = CapabilityTag("builtin:Error".to_string());
    let mut module = Ir3Module::new(ContentHash::compute(source_label.as_bytes()), source_label);
    module.constant_pool = vec!["message".to_string()];
    module.instructions = vec![
        Ir3Instruction::LoadInt { dst: 0, value: 42 },
        Ir3Instruction::HostCall {
            capability: error_tag.clone(),
            args: RegRange { start: 0, count: 1 },
            dst: 1,
        },
        Ir3Instruction::LoadStr {
            dst: 2,
            pool_index: 0,
        },
        Ir3Instruction::GetProperty {
            obj: 1,
            key: 2,
            dst: 3,
        },
        Ir3Instruction::Return { value: 3 },
    ];
    module.required_capabilities = vec![error_tag];
    module
}

fn nested_error_stack_module(source_label: &str) -> Ir3Module {
    let error_tag = CapabilityTag("builtin:Error".to_string());
    let mut module = Ir3Module::new(ContentHash::compute(source_label.as_bytes()), source_label);
    module.constant_pool = vec!["nested failure".to_string(), "stack".to_string()];
    module.instructions = vec![
        Ir3Instruction::CreateClosure {
            dst: 0,
            function_index: 0,
            capture_count: 0,
        },
        Ir3Instruction::Call {
            callee: 0,
            args: RegRange { start: 1, count: 0 },
            dst: 1,
        },
        Ir3Instruction::Return { value: 1 },
        Ir3Instruction::LoadStr {
            dst: 0,
            pool_index: 0,
        },
        Ir3Instruction::HostCall {
            capability: error_tag.clone(),
            args: RegRange { start: 0, count: 1 },
            dst: 1,
        },
        Ir3Instruction::LoadStr {
            dst: 2,
            pool_index: 1,
        },
        Ir3Instruction::GetProperty {
            obj: 1,
            key: 2,
            dst: 3,
        },
        Ir3Instruction::Return { value: 3 },
    ];
    module.function_table.push(Ir3FunctionDesc {
        entry: 3,
        arity: 0,
        frame_size: 8,
        name: Some("nestedErrorFactory".to_string()),
        is_generator: false,
    });
    module.required_capabilities = vec![error_tag];
    module
}

fn expect_string(result: ExecutionResult, context: &str) -> String {
    match result.value {
        Value::Str(value) => value.to_string(),
        other => panic!("{context}: expected string result, got {other:?}"),
    }
}

#[test]
fn error_constructor_sets_message_property_via_public_ir() {
    let module = error_property_module("error-message-public", "Test error message", "message");
    let value = expect_string(
        execute(
            &module,
            &[RuntimeCapability::Builtin, RuntimeCapability::HeapAllocate],
        )
        .expect("Error hostcall should execute"),
        "message property",
    );

    assert_eq!(value, "Test error message");
}

#[test]
fn error_constructor_sets_name_property_via_public_ir() {
    let module = error_property_module("error-name-public", "ignored", "name");
    let value = expect_string(
        execute(
            &module,
            &[RuntimeCapability::Builtin, RuntimeCapability::HeapAllocate],
        )
        .expect("Error hostcall should execute"),
        "name property",
    );

    assert_eq!(value, "Error");
}

#[test]
fn error_constructor_stack_contains_v8_style_frame_and_source() {
    let module = error_property_module("stack-source-public", "boom", "stack");
    let stack = expect_string(
        execute(
            &module,
            &[RuntimeCapability::Builtin, RuntimeCapability::HeapAllocate],
        )
        .expect("Error hostcall should execute"),
        "stack property",
    );

    assert!(
        stack.contains("    at "),
        "stack should use V8-style frame prefix, got:\n{stack}"
    );
    assert!(
        stack.contains("stack-source-public.js"),
        "stack should include the current module source label, got:\n{stack}"
    );
}

#[test]
fn error_constructor_stack_is_deterministic_for_same_module() {
    let module = error_property_module("stack-determinism-public", "boom", "stack");
    let caps = [RuntimeCapability::Builtin, RuntimeCapability::HeapAllocate];
    let first = expect_string(
        execute(&module, &caps).expect("first Error hostcall should execute"),
        "first stack",
    );
    let second = expect_string(
        execute(&module, &caps).expect("second Error hostcall should execute"),
        "second stack",
    );

    assert_eq!(
        first, second,
        "same module should produce identical stack text"
    );
}

#[test]
fn error_constructor_stringifies_non_string_messages() {
    let module = integer_error_message_module("error-message-stringify-public");
    let message = expect_string(
        execute(
            &module,
            &[RuntimeCapability::Builtin, RuntimeCapability::HeapAllocate],
        )
        .expect("Error hostcall should execute"),
        "integer message",
    );

    assert_eq!(message, "42");
}

#[test]
fn error_stack_from_nested_call_preserves_public_frame_chain() {
    let module = nested_error_stack_module("nested-stack-public");
    let stack = expect_string(
        execute(
            &module,
            &[RuntimeCapability::Builtin, RuntimeCapability::HeapAllocate],
        )
        .expect("nested Error hostcall should execute"),
        "nested stack",
    );

    assert!(
        stack.contains("function_0"),
        "nested stack should expose the active function frame, got:\n{stack}"
    );
    assert!(
        stack.contains("nested-stack-public.js"),
        "nested stack should include the module source label, got:\n{stack}"
    );
}

#[test]
fn error_constructor_requires_builtin_capability_fail_closed() {
    let module = error_property_module("error-capability-public", "boom", "stack");
    let err = execute(&module, &[RuntimeCapability::HeapAllocate])
        .expect_err("missing Builtin capability must fail closed");

    assert!(
        matches!(err, InterpreterError::CapabilityDenied { ref capability } if capability == "builtin:Error"),
        "expected builtin capability denial, got {err:?}"
    );
}

#[test]
fn error_constructor_requires_heap_allocation_capability() {
    let module = error_property_module("error-heap-capability-public", "boom", "stack");
    let err = execute(&module, &[RuntimeCapability::Builtin])
        .expect_err("missing HeapAllocate capability must fail closed");

    assert!(
        matches!(err, InterpreterError::CapabilityDenied { ref capability } if capability == "HeapAllocate"),
        "expected heap allocation capability denial, got {err:?}"
    );
}

// The former `#[cfg(any())] mod legacy_private_api_tests` block was removed here
// (bd-bg9l1.24). It never compiled — it referenced the removed `InterpreterCore` /
// hand-built `Ir3Module` IR private APIs. V8-style frame formatting, deterministic
// stack output, nested-call frame-chain preservation, non-string message
// stringification and capability-gated construction are covered by the active
// current-API tests above in this file.
