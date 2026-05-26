//! Tests for Object.freeze property enforcement.
//!
//! This test module verifies that Object.freeze() properly enforces property
//! immutability according to ECMAScript semantics:
//! - Frozen objects cannot have properties added, deleted, or modified
//! - In strict mode, attempts to modify frozen objects should throw TypeError
//! - In sloppy mode, attempts to modify frozen objects should silently fail
//! - Object.isFrozen() should correctly report frozen state
//! - Freezing is not transitive (nested objects remain mutable unless separately frozen)

#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use frankenengine_engine::baseline_interpreter::{
    ExecutionResult, InterpreterConfig, InterpreterCore, InterpreterError, Value,
};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::ir_contract::{CapabilityTag, Ir3Instruction, Ir3Module, RegRange};

fn config_with_caps(caps: &[RuntimeCapability]) -> InterpreterConfig {
    let mut config = InterpreterConfig::quickjs_defaults();
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::VmDispatch]);
    config.granted_capabilities.extend(caps.iter().copied());
    config
}

fn module(source_label: &str, pool: Vec<&str>, instructions: Vec<Ir3Instruction>) -> Ir3Module {
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
    module
}

fn execute(
    module: &Ir3Module,
    caps: &[RuntimeCapability],
) -> Result<ExecutionResult, InterpreterError> {
    InterpreterCore::new(config_with_caps(caps), "object-freeze-public-api").execute(module)
}

fn standard_caps() -> [RuntimeCapability; 2] {
    [RuntimeCapability::HeapAllocate, RuntimeCapability::Builtin]
}

fn builtin(name: &str) -> CapabilityTag {
    CapabilityTag(format!("builtin:{name}"))
}

fn new_object_is_frozen_module(source_label: &str, freeze_first: bool) -> Ir3Module {
    let mut instructions = vec![Ir3Instruction::NewObject { dst: 0 }];
    if freeze_first {
        instructions.push(Ir3Instruction::HostCall {
            capability: builtin("ObjectFreeze"),
            args: RegRange { start: 0, count: 1 },
            dst: 1,
        });
    }
    instructions.push(Ir3Instruction::HostCall {
        capability: builtin("ObjectIsFrozen"),
        args: RegRange { start: 0, count: 1 },
        dst: 2,
    });
    instructions.push(Ir3Instruction::Return { value: 2 });
    module(source_label, vec![], instructions)
}

fn frozen_write_module() -> Ir3Module {
    module(
        "object-freeze-write",
        vec!["prop", "original", "modified"],
        vec![
            Ir3Instruction::NewObject { dst: 0 },
            Ir3Instruction::LoadStr {
                dst: 1,
                pool_index: 0,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::SetProperty {
                obj: 0,
                key: 1,
                val: 2,
            },
            Ir3Instruction::HostCall {
                capability: builtin("ObjectFreeze"),
                args: RegRange { start: 0, count: 1 },
                dst: 3,
            },
            Ir3Instruction::LoadStr {
                dst: 4,
                pool_index: 2,
            },
            Ir3Instruction::SetProperty {
                obj: 0,
                key: 1,
                val: 4,
            },
            Ir3Instruction::Return { value: 4 },
        ],
    )
}

fn frozen_delete_then_get_module() -> Ir3Module {
    module(
        "object-freeze-delete",
        vec!["prop", "original"],
        vec![
            Ir3Instruction::NewObject { dst: 0 },
            Ir3Instruction::LoadStr {
                dst: 1,
                pool_index: 0,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::SetProperty {
                obj: 0,
                key: 1,
                val: 2,
            },
            Ir3Instruction::HostCall {
                capability: builtin("ObjectFreeze"),
                args: RegRange { start: 0, count: 1 },
                dst: 3,
            },
            Ir3Instruction::DeleteProperty {
                obj: 0,
                key: 1,
                dst: 4,
            },
            Ir3Instruction::GetProperty {
                obj: 0,
                key: 1,
                dst: 5,
            },
            Ir3Instruction::Return { value: 5 },
        ],
    )
}

fn frozen_delete_result_module() -> Ir3Module {
    module(
        "object-freeze-delete-result",
        vec!["prop", "original"],
        vec![
            Ir3Instruction::NewObject { dst: 0 },
            Ir3Instruction::LoadStr {
                dst: 1,
                pool_index: 0,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::SetProperty {
                obj: 0,
                key: 1,
                val: 2,
            },
            Ir3Instruction::HostCall {
                capability: builtin("ObjectFreeze"),
                args: RegRange { start: 0, count: 1 },
                dst: 3,
            },
            Ir3Instruction::DeleteProperty {
                obj: 0,
                key: 1,
                dst: 4,
            },
            Ir3Instruction::Return { value: 4 },
        ],
    )
}

fn non_transitive_freeze_module() -> Ir3Module {
    module(
        "object-freeze-non-transitive",
        vec!["innerProp", "innerValue", "nested", "modifiedInnerValue"],
        vec![
            Ir3Instruction::NewObject { dst: 0 },
            Ir3Instruction::LoadStr {
                dst: 1,
                pool_index: 0,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::SetProperty {
                obj: 0,
                key: 1,
                val: 2,
            },
            Ir3Instruction::NewObject { dst: 3 },
            Ir3Instruction::LoadStr {
                dst: 4,
                pool_index: 2,
            },
            Ir3Instruction::SetProperty {
                obj: 3,
                key: 4,
                val: 0,
            },
            Ir3Instruction::HostCall {
                capability: builtin("ObjectFreeze"),
                args: RegRange { start: 3, count: 1 },
                dst: 5,
            },
            Ir3Instruction::LoadStr {
                dst: 6,
                pool_index: 3,
            },
            Ir3Instruction::SetProperty {
                obj: 0,
                key: 1,
                val: 6,
            },
            Ir3Instruction::GetProperty {
                obj: 0,
                key: 1,
                dst: 7,
            },
            Ir3Instruction::Return { value: 7 },
        ],
    )
}

#[test]
fn object_is_frozen_reports_false_for_fresh_objects() {
    let result = execute(
        &new_object_is_frozen_module("object-is-frozen-fresh", false),
        &standard_caps(),
    )
    .expect("Object.isFrozen should execute");

    assert_eq!(result.value, Value::Bool(false));
}

#[test]
fn object_freeze_marks_objects_as_frozen() {
    let result = execute(
        &new_object_is_frozen_module("object-is-frozen-after-freeze", true),
        &standard_caps(),
    )
    .expect("Object.freeze and Object.isFrozen should execute");

    assert_eq!(result.value, Value::Bool(true));
}

#[test]
fn object_freeze_prevents_property_assignment() {
    let err = execute(&frozen_write_module(), &standard_caps())
        .expect_err("writing to a frozen object must fail");

    assert!(
        matches!(err, InterpreterError::TypeError { ref got, .. } if got == "frozen object"),
        "expected frozen-object TypeError, got {err:?}"
    );
}

#[test]
fn object_freeze_prevents_property_deletion_and_preserves_value() {
    let result = execute(&frozen_delete_then_get_module(), &standard_caps())
        .expect("delete on a frozen object should be a false no-op, not a mutation");

    assert_eq!(result.value, Value::str("original"));
}

#[test]
fn delete_property_reports_false_for_frozen_objects() {
    let result = execute(&frozen_delete_result_module(), &standard_caps())
        .expect("delete on a frozen object should complete");

    assert_eq!(result.value, Value::Bool(false));
}

#[test]
fn object_freeze_is_not_transitive() {
    let result = execute(&non_transitive_freeze_module(), &standard_caps())
        .expect("freezing an outer object should not freeze nested object values");

    assert_eq!(result.value, Value::str("modifiedInnerValue"));
}

#[test]
fn object_freeze_returns_primitives_unchanged() {
    let result = execute(
        &module(
            "object-freeze-primitive",
            vec![],
            vec![
                Ir3Instruction::LoadInt { dst: 0, value: 42 },
                Ir3Instruction::HostCall {
                    capability: builtin("ObjectFreeze"),
                    args: RegRange { start: 0, count: 1 },
                    dst: 1,
                },
                Ir3Instruction::Return { value: 1 },
            ],
        ),
        &standard_caps(),
    )
    .expect("Object.freeze primitive path should execute");

    assert_eq!(result.value, Value::Int(42));
}

#[test]
fn object_is_frozen_treats_primitives_as_frozen() {
    let result = execute(
        &module(
            "object-is-frozen-primitive",
            vec!["hello"],
            vec![
                Ir3Instruction::LoadStr {
                    dst: 0,
                    pool_index: 0,
                },
                Ir3Instruction::HostCall {
                    capability: builtin("ObjectIsFrozen"),
                    args: RegRange { start: 0, count: 1 },
                    dst: 1,
                },
                Ir3Instruction::Return { value: 1 },
            ],
        ),
        &standard_caps(),
    )
    .expect("Object.isFrozen primitive path should execute");

    assert_eq!(result.value, Value::Bool(true));
}

#[test]
fn object_freeze_with_no_arguments_returns_undefined() {
    let result = execute(
        &module(
            "object-freeze-no-args",
            vec![],
            vec![
                Ir3Instruction::HostCall {
                    capability: builtin("ObjectFreeze"),
                    args: RegRange { start: 0, count: 0 },
                    dst: 0,
                },
                Ir3Instruction::Return { value: 0 },
            ],
        ),
        &standard_caps(),
    )
    .expect("Object.freeze no-arg path should execute");

    assert_eq!(result.value, Value::Undefined);
}

#[test]
fn object_freeze_requires_builtin_capability_fail_closed() {
    let err = execute(
        &new_object_is_frozen_module("object-freeze-capability-denied", true),
        &[RuntimeCapability::HeapAllocate],
    )
    .expect_err("Object.freeze should require Builtin capability");

    assert!(
        matches!(err, InterpreterError::CapabilityDenied { ref capability } if capability == "builtin:ObjectFreeze"),
        "expected ObjectFreeze capability denial, got {err:?}"
    );
}

// The tests below port the freeze-integrity coverage that previously lived in a
// `#[cfg(any())]`-gated `legacy_private_object_model_tests` module. That module
// was compiled out (silently dark) and written against a removed private-heap
// API (`core.heap.define_property`/`freeze`, `object_model::PropertyDescriptor`).
// Its descriptor-flag and accessor-property cases have no surface in the current
// public IR3 API and are intentionally not resurrected; the genuinely portable
// invariants it covered are exercised here against the real interpreter via IR3.

/// Adding a brand-new property (a key the object never had) to a frozen object
/// must fail-closed, not only writes to an existing key. Frozen objects are
/// non-extensible: `set_object_property` rejects any mutation on a frozen object
/// regardless of whether the key already exists.
#[test]
fn object_freeze_prevents_new_property_addition() {
    let err = execute(
        &module(
            "object-freeze-new-property",
            vec!["newKey", "newValue"],
            vec![
                Ir3Instruction::NewObject { dst: 0 },
                Ir3Instruction::HostCall {
                    capability: builtin("ObjectFreeze"),
                    args: RegRange { start: 0, count: 1 },
                    dst: 1,
                },
                Ir3Instruction::LoadStr {
                    dst: 2,
                    pool_index: 0,
                },
                Ir3Instruction::LoadStr {
                    dst: 3,
                    pool_index: 1,
                },
                Ir3Instruction::SetProperty {
                    obj: 0,
                    key: 2,
                    val: 3,
                },
                Ir3Instruction::Return { value: 0 },
            ],
        ),
        &standard_caps(),
    )
    .expect_err("adding a new property to a frozen object must fail");

    assert!(
        matches!(err, InterpreterError::TypeError { ref got, .. } if got == "frozen object"),
        "expected frozen-object TypeError on new-property addition, got {err:?}"
    );
}

/// Freezing an already-frozen object is an idempotent no-op: it must not error
/// and the object must remain frozen afterwards.
#[test]
fn object_freeze_is_idempotent_on_already_frozen_object() {
    let result = execute(
        &module(
            "object-freeze-idempotent",
            vec![],
            vec![
                Ir3Instruction::NewObject { dst: 0 },
                Ir3Instruction::HostCall {
                    capability: builtin("ObjectFreeze"),
                    args: RegRange { start: 0, count: 1 },
                    dst: 1,
                },
                Ir3Instruction::HostCall {
                    capability: builtin("ObjectFreeze"),
                    args: RegRange { start: 0, count: 1 },
                    dst: 2,
                },
                Ir3Instruction::HostCall {
                    capability: builtin("ObjectIsFrozen"),
                    args: RegRange { start: 0, count: 1 },
                    dst: 3,
                },
                Ir3Instruction::Return { value: 3 },
            ],
        ),
        &standard_caps(),
    )
    .expect("double-freeze should be an idempotent no-op");

    assert_eq!(result.value, Value::Bool(true));
}

/// `Object.freeze(obj)` returns the same object handle it was given (not
/// undefined), so the frozen object stays usable for reads. We read a property
/// that was set before freezing back through the *returned* handle: if freeze
/// returned anything other than the object, the read would not yield the value.
#[test]
fn object_freeze_returns_the_same_object() {
    let result = execute(
        &module(
            "object-freeze-returns-object",
            vec!["k", "v"],
            vec![
                Ir3Instruction::NewObject { dst: 0 },
                Ir3Instruction::LoadStr {
                    dst: 1,
                    pool_index: 0,
                },
                Ir3Instruction::LoadStr {
                    dst: 2,
                    pool_index: 1,
                },
                Ir3Instruction::SetProperty {
                    obj: 0,
                    key: 1,
                    val: 2,
                },
                Ir3Instruction::HostCall {
                    capability: builtin("ObjectFreeze"),
                    args: RegRange { start: 0, count: 1 },
                    dst: 3,
                },
                // Read "k" back through the handle Object.freeze returned (reg 3).
                Ir3Instruction::GetProperty {
                    obj: 3,
                    key: 1,
                    dst: 4,
                },
                Ir3Instruction::Return { value: 4 },
            ],
        ),
        &standard_caps(),
    )
    .expect("Object.freeze should return the frozen object handle");

    assert_eq!(result.value, Value::str("v"));
}

/// `Object.isFrozen()` with no arguments reports `true`: per spec a missing /
/// non-object argument is always considered frozen.
#[test]
fn object_is_frozen_with_no_arguments_returns_true() {
    let result = execute(
        &module(
            "object-is-frozen-no-args",
            vec![],
            vec![
                Ir3Instruction::HostCall {
                    capability: builtin("ObjectIsFrozen"),
                    args: RegRange { start: 0, count: 0 },
                    dst: 0,
                },
                Ir3Instruction::Return { value: 0 },
            ],
        ),
        &standard_caps(),
    )
    .expect("Object.isFrozen no-arg path should execute");

    assert_eq!(result.value, Value::Bool(true));
}
