//! Regression tests for Array callback invocation (bd-2gd4b bd-1rs5t bd-cvu18)
//!
//! These tests verify that Array callback methods properly invoke callback functions,
//! including argument validation, empty arrays, side effects, and deterministic behavior.

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

fn create_interpreter() -> InterpreterCore {
    let mut config = InterpreterConfig::quickjs_defaults();
    config.granted_capabilities = BTreeSet::from([
        RuntimeCapability::VmDispatch,
        RuntimeCapability::HeapAllocate,
        RuntimeCapability::Builtin,
    ]);
    InterpreterCore::new(config, "array-every-map-callbacks")
}

fn builtin(name: &str) -> CapabilityTag {
    CapabilityTag(format!("builtin:{name}"))
}

fn module(
    source_label: &str,
    pool: Vec<&str>,
    instructions: Vec<Ir3Instruction>,
    function_table: Vec<Ir3FunctionDesc>,
) -> Ir3Module {
    let mut module = Ir3Module::new(ContentHash::compute(source_label.as_bytes()), source_label);
    module.constant_pool = pool.into_iter().map(str::to_string).collect();
    module.required_capabilities = instructions
        .iter()
        .filter_map(|instruction| match instruction {
            Ir3Instruction::HostCall { capability, .. } => Some(capability.clone()),
            _ => None,
        })
        .collect();
    module.instructions = instructions;
    module.function_table = function_table;
    module
}

fn callback_desc(entry: u32) -> Ir3FunctionDesc {
    Ir3FunctionDesc {
        entry,
        arity: 3,
        frame_size: 4,
        name: Some("callback".to_string()),
        is_generator: false,
    }
}

fn execute(module: &Ir3Module) -> Result<ExecutionResult, InterpreterError> {
    create_interpreter().execute(module)
}

fn empty_array_callback_module(source_label: &str, builtin_name: &str) -> Ir3Module {
    module(
        source_label,
        vec!["length"],
        vec![
            Ir3Instruction::NewArray { dst: 0 },
            Ir3Instruction::LoadStr {
                dst: 1,
                pool_index: 0,
            },
            Ir3Instruction::LoadInt { dst: 2, value: 0 },
            Ir3Instruction::SetProperty {
                obj: 0,
                key: 1,
                val: 2,
            },
            Ir3Instruction::CreateClosure {
                dst: 1,
                function_index: 0,
                capture_count: 0,
            },
            Ir3Instruction::HostCall {
                capability: builtin(builtin_name),
                args: RegRange { start: 0, count: 2 },
                dst: 4,
            },
            Ir3Instruction::Return { value: 4 },
            Ir3Instruction::LoadBool {
                dst: 0,
                value: true,
            },
            Ir3Instruction::Return { value: 0 },
        ],
        vec![callback_desc(7)],
    )
}

fn missing_callback_module(source_label: &str, builtin_name: &str) -> Ir3Module {
    module(
        source_label,
        vec![],
        vec![
            Ir3Instruction::NewArray { dst: 0 },
            Ir3Instruction::HostCall {
                capability: builtin(builtin_name),
                args: RegRange { start: 0, count: 1 },
                dst: 1,
            },
            Ir3Instruction::Return { value: 1 },
        ],
        vec![],
    )
}

fn non_function_callback_module(
    source_label: &str,
    builtin_name: &str,
    callback_instruction: Ir3Instruction,
) -> Ir3Module {
    module(
        source_label,
        vec!["not-a-function"],
        vec![
            Ir3Instruction::NewArray { dst: 0 },
            callback_instruction,
            Ir3Instruction::HostCall {
                capability: builtin(builtin_name),
                args: RegRange { start: 0, count: 2 },
                dst: 2,
            },
            Ir3Instruction::Return { value: 2 },
        ],
        vec![],
    )
}

fn find_by_index_callback_module(source_label: &str, builtin_name: &str) -> Ir3Module {
    module(
        source_label,
        vec!["length", "0", "1", "wrong", "target"],
        vec![
            Ir3Instruction::NewArray { dst: 0 },
            Ir3Instruction::LoadStr {
                dst: 1,
                pool_index: 0,
            },
            Ir3Instruction::LoadInt { dst: 2, value: 2 },
            Ir3Instruction::SetProperty {
                obj: 0,
                key: 1,
                val: 2,
            },
            Ir3Instruction::LoadStr {
                dst: 3,
                pool_index: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 4,
                pool_index: 3,
            },
            Ir3Instruction::SetProperty {
                obj: 0,
                key: 3,
                val: 4,
            },
            Ir3Instruction::LoadStr {
                dst: 5,
                pool_index: 2,
            },
            Ir3Instruction::LoadStr {
                dst: 6,
                pool_index: 4,
            },
            Ir3Instruction::SetProperty {
                obj: 0,
                key: 5,
                val: 6,
            },
            Ir3Instruction::CreateClosure {
                dst: 1,
                function_index: 0,
                capture_count: 0,
            },
            Ir3Instruction::HostCall {
                capability: builtin(builtin_name),
                args: RegRange { start: 0, count: 2 },
                dst: 7,
            },
            Ir3Instruction::Return { value: 7 },
            Ir3Instruction::LoadInt { dst: 3, value: 1 },
            Ir3Instruction::StrictEq {
                dst: 4,
                lhs: 1,
                rhs: 3,
            },
            Ir3Instruction::Return { value: 4 },
        ],
        vec![callback_desc(13)],
    )
}

#[test]
fn array_every_empty_array_returns_true() {
    let result = execute(&empty_array_callback_module(
        "array-every-empty",
        "ArrayPrototypeEvery",
    ))
    .expect("Array.every should execute on empty arrays");

    assert_eq!(result.value, Value::Bool(true));
}

#[test]
fn array_map_empty_array_returns_array_object() {
    let result = execute(&empty_array_callback_module(
        "array-map-empty",
        "ArrayPrototypeMap",
    ))
    .expect("Array.map should execute on empty arrays");

    assert!(
        matches!(result.value, Value::Object(_)),
        "Array.map should return a result array object, got {:?}",
        result.value
    );
}

#[test]
fn array_every_missing_callback_fails_closed() {
    let err = execute(&missing_callback_module(
        "array-every-missing-callback",
        "ArrayPrototypeEvery",
    ))
    .expect_err("Array.every without callback must fail");

    assert!(matches!(err, InterpreterError::TypeError { .. }));
}

#[test]
fn array_map_missing_callback_fails_closed() {
    let err = execute(&missing_callback_module(
        "array-map-missing-callback",
        "ArrayPrototypeMap",
    ))
    .expect_err("Array.map without callback must fail");

    assert!(matches!(err, InterpreterError::TypeError { .. }));
}

#[test]
fn array_every_rejects_non_function_callback() {
    let err = execute(&non_function_callback_module(
        "array-every-bad-callback",
        "ArrayPrototypeEvery",
        Ir3Instruction::LoadStr {
            dst: 1,
            pool_index: 0,
        },
    ))
    .expect_err("Array.every with non-function callback must fail");

    assert!(matches!(err, InterpreterError::TypeError { .. }));
}

#[test]
fn array_map_rejects_non_function_callback() {
    let err = execute(&non_function_callback_module(
        "array-map-bad-callback",
        "ArrayPrototypeMap",
        Ir3Instruction::LoadInt { dst: 1, value: 123 },
    ))
    .expect_err("Array.map with non-function callback must fail");

    assert!(matches!(err, InterpreterError::TypeError { .. }));
}

#[test]
fn array_every_uses_callback_result_not_element_truthiness() {
    let result = execute(&module(
        "array-every-callback-result",
        vec!["length", "0"],
        vec![
            Ir3Instruction::NewArray { dst: 0 },
            Ir3Instruction::LoadStr {
                dst: 1,
                pool_index: 0,
            },
            Ir3Instruction::LoadInt { dst: 2, value: 1 },
            Ir3Instruction::SetProperty {
                obj: 0,
                key: 1,
                val: 2,
            },
            Ir3Instruction::LoadStr {
                dst: 3,
                pool_index: 1,
            },
            Ir3Instruction::LoadBool {
                dst: 4,
                value: true,
            },
            Ir3Instruction::SetProperty {
                obj: 0,
                key: 3,
                val: 4,
            },
            Ir3Instruction::CreateClosure {
                dst: 1,
                function_index: 0,
                capture_count: 0,
            },
            Ir3Instruction::HostCall {
                capability: builtin("ArrayPrototypeEvery"),
                args: RegRange { start: 0, count: 2 },
                dst: 6,
            },
            Ir3Instruction::Return { value: 6 },
            Ir3Instruction::LoadBool {
                dst: 0,
                value: false,
            },
            Ir3Instruction::Return { value: 0 },
        ],
        vec![callback_desc(10)],
    ))
    .expect("Array.every should invoke callback");

    assert_eq!(result.value, Value::Bool(false));
}

#[test]
fn array_map_uses_callback_result_not_identity() {
    let result = execute(&module(
        "array-map-callback-result",
        vec!["length", "0", "source", "mapped"],
        vec![
            Ir3Instruction::NewArray { dst: 0 },
            Ir3Instruction::LoadStr {
                dst: 1,
                pool_index: 0,
            },
            Ir3Instruction::LoadInt { dst: 2, value: 1 },
            Ir3Instruction::SetProperty {
                obj: 0,
                key: 1,
                val: 2,
            },
            Ir3Instruction::LoadStr {
                dst: 3,
                pool_index: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 4,
                pool_index: 2,
            },
            Ir3Instruction::SetProperty {
                obj: 0,
                key: 3,
                val: 4,
            },
            Ir3Instruction::CreateClosure {
                dst: 1,
                function_index: 0,
                capture_count: 0,
            },
            Ir3Instruction::HostCall {
                capability: builtin("ArrayPrototypeMap"),
                args: RegRange { start: 0, count: 2 },
                dst: 6,
            },
            Ir3Instruction::GetProperty {
                obj: 6,
                key: 3,
                dst: 7,
            },
            Ir3Instruction::Return { value: 7 },
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 3,
            },
            Ir3Instruction::Return { value: 0 },
        ],
        vec![callback_desc(11)],
    ))
    .expect("Array.map should invoke callback");

    assert_eq!(result.value, Value::str("mapped"));
}

#[test]
fn array_some_uses_callback_result_not_element_truthiness() {
    let result = execute(&module(
        "array-some-callback-result",
        vec!["length", "0"],
        vec![
            Ir3Instruction::NewArray { dst: 0 },
            Ir3Instruction::LoadStr {
                dst: 1,
                pool_index: 0,
            },
            Ir3Instruction::LoadInt { dst: 2, value: 1 },
            Ir3Instruction::SetProperty {
                obj: 0,
                key: 1,
                val: 2,
            },
            Ir3Instruction::LoadStr {
                dst: 3,
                pool_index: 1,
            },
            Ir3Instruction::LoadBool {
                dst: 4,
                value: false,
            },
            Ir3Instruction::SetProperty {
                obj: 0,
                key: 3,
                val: 4,
            },
            Ir3Instruction::CreateClosure {
                dst: 1,
                function_index: 0,
                capture_count: 0,
            },
            Ir3Instruction::HostCall {
                capability: builtin("ArrayPrototypeSome"),
                args: RegRange { start: 0, count: 2 },
                dst: 6,
            },
            Ir3Instruction::Return { value: 6 },
            Ir3Instruction::LoadBool {
                dst: 0,
                value: true,
            },
            Ir3Instruction::Return { value: 0 },
        ],
        vec![callback_desc(10)],
    ))
    .expect("Array.some should invoke callback");

    assert_eq!(result.value, Value::Bool(true));
}

#[test]
fn array_for_each_invokes_callback_side_effect() {
    let result = execute(&module(
        "array-foreach-side-effect",
        vec!["length", "0", "seen"],
        vec![
            Ir3Instruction::NewArray { dst: 0 },
            Ir3Instruction::LoadStr {
                dst: 1,
                pool_index: 0,
            },
            Ir3Instruction::LoadInt { dst: 2, value: 1 },
            Ir3Instruction::SetProperty {
                obj: 0,
                key: 1,
                val: 2,
            },
            Ir3Instruction::LoadStr {
                dst: 3,
                pool_index: 1,
            },
            Ir3Instruction::LoadInt { dst: 4, value: 7 },
            Ir3Instruction::SetProperty {
                obj: 0,
                key: 3,
                val: 4,
            },
            Ir3Instruction::CreateClosure {
                dst: 1,
                function_index: 0,
                capture_count: 0,
            },
            Ir3Instruction::HostCall {
                capability: builtin("ArrayPrototypeForEach"),
                args: RegRange { start: 0, count: 2 },
                dst: 5,
            },
            Ir3Instruction::LoadStr {
                dst: 6,
                pool_index: 2,
            },
            Ir3Instruction::GetProperty {
                obj: 0,
                key: 6,
                dst: 7,
            },
            Ir3Instruction::Return { value: 7 },
            Ir3Instruction::LoadStr {
                dst: 3,
                pool_index: 2,
            },
            Ir3Instruction::SetProperty {
                obj: 2,
                key: 3,
                val: 0,
            },
            Ir3Instruction::LoadUndefined { dst: 4 },
            Ir3Instruction::Return { value: 4 },
        ],
        vec![callback_desc(12)],
    ))
    .expect("Array.forEach should invoke callback");

    assert_eq!(result.value, Value::Int(7));
}

#[test]
fn array_find_uses_callback_result_not_first_truthy_element() {
    let result = execute(&find_by_index_callback_module(
        "array-find-callback-result",
        "ArrayPrototypeFind",
    ))
    .expect("Array.find should invoke callback");

    assert_eq!(result.value, Value::str("target"));
}

#[test]
fn array_find_index_uses_callback_result() {
    let result = execute(&find_by_index_callback_module(
        "array-find-index-callback-result",
        "ArrayPrototypeFindIndex",
    ))
    .expect("Array.findIndex should invoke callback");

    assert_eq!(result.value, Value::Int(1));
}

#[test]
fn array_methods_are_deterministic_on_empty_arrays() {
    for builtin_name in ["ArrayPrototypeEvery", "ArrayPrototypeMap"] {
        for iteration in 0..3 {
            let result = execute(&empty_array_callback_module(
                &format!("array-callback-determinism-{builtin_name}-{iteration}"),
                builtin_name,
            ));
            assert!(
                result.is_ok(),
                "{builtin_name} should execute deterministically on iteration {iteration}: {result:?}"
            );
        }
    }
}

#[test]
fn array_every_non_object_receiver_fails_closed() {
    let err = execute(&module(
        "array-every-non-object",
        vec![],
        vec![
            Ir3Instruction::LoadInt { dst: 0, value: 42 },
            Ir3Instruction::CreateClosure {
                dst: 1,
                function_index: 0,
                capture_count: 0,
            },
            Ir3Instruction::HostCall {
                capability: builtin("ArrayPrototypeEvery"),
                args: RegRange { start: 0, count: 2 },
                dst: 2,
            },
            Ir3Instruction::Return { value: 2 },
            Ir3Instruction::LoadBool {
                dst: 0,
                value: true,
            },
            Ir3Instruction::Return { value: 0 },
        ],
        vec![callback_desc(4)],
    ))
    .expect_err("Array.every should reject non-object receivers");

    assert!(matches!(err, InterpreterError::TypeError { .. }));
}

// The former `#[cfg(any())] mod legacy_pre_current_interpreter_api_tests` block was
// removed here (bd-bg9l1.24). It never compiled — it referenced the removed
// `BaselineInterpreter` / hand-built `ir_contract` IR private APIs — so it was dark
// code, never even reported as `ignored`. Array.every/map/some/forEach/find callback
// semantics (empty arrays, missing & non-function callbacks, callback-result vs element
// truthiness, non-object receiver fail-closed, determinism) are covered by the active
// current-API tests above in this file.
