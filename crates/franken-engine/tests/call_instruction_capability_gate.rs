//! Regression tests for the `Call` instruction capability gate.
//!
//! `Call` can dispatch opaque `Value::Function(idx)` handles for builtins when
//! the current module function table has no matching local function. That path
//! must use the same fail-closed capability gate as `HostCall`; otherwise a
//! module could bypass hostcall policy by calling a privileged builtin handle.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use frankenengine_engine::baseline_interpreter::{
    InterpreterConfig, InterpreterCore, InterpreterError, Value,
};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::ir_contract::{
    CapabilityTag, Ir3FunctionDesc, Ir3Instruction, Ir3Module, RegRange, WitnessEventKind,
};

fn config_with_caps(caps: &[RuntimeCapability]) -> InterpreterConfig {
    let mut config = InterpreterConfig::quickjs_defaults();
    config.granted_capabilities = BTreeSet::from([
        RuntimeCapability::VmDispatch,
        RuntimeCapability::HeapAllocate,
    ]);
    config.granted_capabilities.extend(caps.iter().copied());
    config
}

fn interpreter_with_caps(caps: &[RuntimeCapability], trace_id: &str) -> InterpreterCore {
    InterpreterCore::new(config_with_caps(caps), trace_id)
}

fn test_module(source_label: &str, instructions: Vec<Ir3Instruction>) -> Ir3Module {
    let mut module = Ir3Module::new(ContentHash::compute(source_label.as_bytes()), source_label);
    module.instructions = instructions;
    module
}

fn call_seeded_function_module(source_label: &str) -> Ir3Module {
    test_module(
        source_label,
        vec![
            Ir3Instruction::Call {
                callee: 0,
                args: RegRange { start: 1, count: 0 },
                dst: 2,
            },
            Ir3Instruction::Halt,
        ],
    )
}

fn call_console_log_module() -> Ir3Module {
    let mut module = test_module(
        "call-builtin-console-log",
        vec![
            Ir3Instruction::LoadStr {
                dst: 1,
                pool_index: 0,
            },
            Ir3Instruction::Call {
                callee: 0,
                args: RegRange { start: 1, count: 1 },
                dst: 2,
            },
            Ir3Instruction::Halt,
        ],
    );
    module.constant_pool.push("call gate audit".to_string());
    module
}

fn module_with_hostcall(capability: &str) -> Ir3Module {
    let tag = CapabilityTag(capability.to_string());
    let mut module = test_module(
        "hostcall-builtin-capability",
        vec![
            Ir3Instruction::HostCall {
                capability: tag.clone(),
                args: RegRange { start: 1, count: 0 },
                dst: 2,
            },
            Ir3Instruction::Halt,
        ],
    );
    module.required_capabilities = vec![tag];
    module
}

fn execute_seeded_function_call(
    function_index: u32,
    caps: &[RuntimeCapability],
) -> Result<frankenengine_engine::baseline_interpreter::ExecutionResult, InterpreterError> {
    let mut core = interpreter_with_caps(caps, "call-builtin-gate");
    core.seed_register(0, Value::Function(function_index))
        .expect("register 0 should be seedable in quickjs defaults");
    core.execute(&call_seeded_function_module("call-builtin-gate"))
}

#[test]
fn call_builtin_without_builtin_capability_is_denied() {
    let result = execute_seeded_function_call(0, &[]);

    assert!(
        matches!(result, Err(InterpreterError::CapabilityDenied { ref capability }) if capability == "builtin:ObjectKeys"),
        "Object.keys builtin call should require the builtin capability, got {result:?}"
    );
}

#[test]
fn call_builtin_with_wrong_capability_is_denied() {
    let result = execute_seeded_function_call(0, &[RuntimeCapability::FsRead]);

    assert!(
        matches!(result, Err(InterpreterError::CapabilityDenied { ref capability }) if capability == "builtin:ObjectKeys"),
        "Object.keys builtin call should not accept unrelated capabilities, got {result:?}"
    );
}

#[test]
fn call_unknown_function_index_fails_closed_as_function_not_found() {
    let result = execute_seeded_function_call(999, &[RuntimeCapability::Builtin]);

    assert!(
        matches!(
            result,
            Err(InterpreterError::FunctionNotFound { index: 999, .. })
        ),
        "unknown builtin index should not dispatch as an ambient-authority builtin, got {result:?}"
    );
}

#[test]
fn call_builtin_with_builtin_capability_records_audit_trail() {
    let mut core = interpreter_with_caps(&[RuntimeCapability::Builtin], "call-console-log");
    core.seed_register(0, Value::Function(100))
        .expect("register 0 should be seedable in quickjs defaults");

    let result = core
        .execute(&call_console_log_module())
        .expect("builtin:ConsoleLog should execute when Builtin is granted");

    assert_eq!(result.hostcall_decisions.len(), 1);
    assert_eq!(
        result.hostcall_decisions[0].capability,
        CapabilityTag("builtin:ConsoleLog".to_string())
    );
    assert!(result.hostcall_decisions[0].allowed);
    assert!(
        result
            .witness_events
            .iter()
            .any(|event| event.kind == WitnessEventKind::CapabilityChecked),
        "allowed builtin call should emit a capability witness event"
    );
    assert_eq!(result.console_output.len(), 1);
    assert_eq!(result.console_output[0].message, "call gate audit");
}

#[test]
fn regular_closure_call_does_not_require_builtin_capability() {
    let mut module = test_module(
        "regular-closure-call",
        vec![
            Ir3Instruction::CreateClosure {
                dst: 0,
                function_index: 0,
                capture_count: 0,
            },
            Ir3Instruction::Call {
                callee: 0,
                args: RegRange { start: 1, count: 0 },
                dst: 2,
            },
            Ir3Instruction::Move { dst: 0, src: 2 },
            Ir3Instruction::Halt,
            Ir3Instruction::LoadInt { dst: 0, value: 42 },
            Ir3Instruction::Return { value: 0 },
        ],
    );
    module.function_table = vec![Ir3FunctionDesc {
        entry: 4,
        arity: 0,
        frame_size: 2,
        name: Some("regular".to_string()),
        is_generator: false,
    }];

    let mut core = interpreter_with_caps(&[], "regular-closure-call");
    let result = core
        .execute(&module)
        .expect("regular closure calls should not require Builtin capability");

    assert_eq!(result.value, Value::Int(42));
    assert!(
        result.hostcall_decisions.is_empty(),
        "regular closure calls should not create hostcall decisions"
    );
}

#[test]
fn multiple_builtin_families_are_gated_by_call_dispatch() {
    for (function_index, capability) in [
        (0, "builtin:ObjectKeys"),
        (10, "builtin:ArrayIsArray"),
        (30, "builtin:StringPrototypeCharAt"),
    ] {
        let result = execute_seeded_function_call(function_index, &[]);

        assert!(
            matches!(result, Err(InterpreterError::CapabilityDenied { capability: ref denied }) if denied == capability),
            "{capability} should be denied without Builtin grant, got {result:?}"
        );
    }
}

#[test]
fn call_and_hostcall_deny_the_same_builtin_capability() {
    let call_result = execute_seeded_function_call(0, &[]);

    let mut hostcall_core = interpreter_with_caps(&[], "hostcall-builtin-gate");
    let hostcall_result = hostcall_core.execute(&module_with_hostcall("builtin:ObjectKeys"));

    let call_capability = match call_result {
        Err(InterpreterError::CapabilityDenied { capability }) => capability,
        other => panic!("expected Call capability denial, got {other:?}"),
    };
    let hostcall_capability = match hostcall_result {
        Err(InterpreterError::CapabilityDenied { capability }) => capability,
        other => panic!("expected HostCall capability denial, got {other:?}"),
    };

    assert_eq!(call_capability, hostcall_capability);
}
