//! Tests for WeakMap weak reference semantics.
//!
//! This test module verifies that WeakMap properly implements weak references
//! according to ECMAScript semantics:
//! - Object keys are held as weak references only
//! - WeakMap entries don't prevent garbage collection of their keys
//! - When a key object is collected, the corresponding entry is automatically removed
//! - Only objects can be used as keys (primitive values are rejected)

use std::collections::BTreeSet;

use frankenengine_engine::baseline_interpreter::{
    ExecutionResult, InterpreterConfig, InterpreterCore, InterpreterError, Value, WeakMapStorage,
};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::ir_contract::{CapabilityTag, Ir3Instruction, Ir3Module, RegRange};

fn weakmap_test_config() -> InterpreterConfig {
    let mut config = InterpreterConfig::quickjs_defaults();
    config.granted_capabilities = BTreeSet::from([
        RuntimeCapability::VmDispatch,
        RuntimeCapability::HeapAllocate,
        RuntimeCapability::Builtin,
    ]);
    config
}

fn module(label: &str, instructions: Vec<Ir3Instruction>, pool: Vec<&str>) -> Ir3Module {
    let mut module = Ir3Module::new(ContentHash::compute(label.as_bytes()), label);
    module.instructions = instructions;
    module.constant_pool = pool.into_iter().map(str::to_string).collect();
    module.required_capabilities = vec![
        CapabilityTag("builtin:WeakMap".to_string()),
        CapabilityTag("builtin:WeakMapPrototypeHas".to_string()),
        CapabilityTag("builtin:WeakMapPrototypeGet".to_string()),
    ];
    module
}

fn execute(module: &Ir3Module) -> Result<ExecutionResult, InterpreterError> {
    InterpreterCore::new(weakmap_test_config(), module.header.source_label.clone()).execute(module)
}

fn weakmap_with_fresh_object_key_then(capability: &str) -> Ir3Module {
    module(
        capability,
        vec![
            Ir3Instruction::HostCall {
                capability: CapabilityTag("builtin:WeakMap".to_string()),
                args: RegRange { start: 0, count: 0 },
                dst: 0,
            },
            Ir3Instruction::NewObject { dst: 1 },
            Ir3Instruction::HostCall {
                capability: CapabilityTag(capability.to_string()),
                args: RegRange { start: 0, count: 2 },
                dst: 2,
            },
            Ir3Instruction::Move { dst: 0, src: 2 },
            Ir3Instruction::Halt,
        ],
        Vec::new(),
    )
}

fn weakmap_with_primitive_key_then(capability: &str, key_load: Ir3Instruction) -> Ir3Module {
    module(
        capability,
        vec![
            Ir3Instruction::HostCall {
                capability: CapabilityTag("builtin:WeakMap".to_string()),
                args: RegRange { start: 0, count: 0 },
                dst: 0,
            },
            key_load,
            Ir3Instruction::HostCall {
                capability: CapabilityTag(capability.to_string()),
                args: RegRange { start: 0, count: 2 },
                dst: 2,
            },
            Ir3Instruction::Move { dst: 0, src: 2 },
            Ir3Instruction::Halt,
        ],
        vec!["primitive"],
    )
}

fn weakmap_seeded_from_iterable_get_key(key_register: u32) -> Ir3Module {
    let mut instructions = vec![
        Ir3Instruction::NewObject { dst: 1 },
        Ir3Instruction::NewObject { dst: 2 },
        Ir3Instruction::NewArray { dst: 3 },
        Ir3Instruction::ArrayPush {
            array: 3,
            element: 1,
        },
        Ir3Instruction::LoadStr {
            dst: 4,
            pool_index: 0,
        },
        Ir3Instruction::ArrayPush {
            array: 3,
            element: 4,
        },
        Ir3Instruction::NewArray { dst: 5 },
        Ir3Instruction::ArrayPush {
            array: 5,
            element: 2,
        },
        Ir3Instruction::LoadStr {
            dst: 6,
            pool_index: 1,
        },
        Ir3Instruction::ArrayPush {
            array: 5,
            element: 6,
        },
        Ir3Instruction::NewArray { dst: 7 },
        Ir3Instruction::ArrayPush {
            array: 7,
            element: 3,
        },
        Ir3Instruction::ArrayPush {
            array: 7,
            element: 5,
        },
        Ir3Instruction::HostCall {
            capability: CapabilityTag("builtin:WeakMap".to_string()),
            args: RegRange { start: 7, count: 1 },
            dst: 0,
        },
    ];

    if key_register != 1 {
        instructions.push(Ir3Instruction::Move {
            dst: 1,
            src: key_register,
        });
    }

    instructions.extend([
        Ir3Instruction::HostCall {
            capability: CapabilityTag("builtin:WeakMapPrototypeGet".to_string()),
            args: RegRange { start: 0, count: 2 },
            dst: 8,
        },
        Ir3Instruction::Move { dst: 0, src: 8 },
        Ir3Instruction::Halt,
    ]);

    module(
        "weakmap-iterable-seed",
        instructions,
        vec!["value1", "value2"],
    )
}

#[test]
fn weakmap_has_and_get_report_absent_object_key() {
    let has = execute(&weakmap_with_fresh_object_key_then(
        "builtin:WeakMapPrototypeHas",
    ))
    .expect("WeakMap.prototype.has should execute");
    assert_eq!(has.value, Value::Bool(false));

    let get = execute(&weakmap_with_fresh_object_key_then(
        "builtin:WeakMapPrototypeGet",
    ))
    .expect("WeakMap.prototype.get should execute");
    assert_eq!(get.value, Value::Undefined);
}

#[test]
fn weakmap_has_and_get_reject_primitive_keys_without_throwing() {
    let primitive_loaders = [
        Ir3Instruction::LoadInt { dst: 1, value: 42 },
        Ir3Instruction::LoadStr {
            dst: 1,
            pool_index: 0,
        },
        Ir3Instruction::LoadBool {
            dst: 1,
            value: true,
        },
        Ir3Instruction::LoadNull { dst: 1 },
        Ir3Instruction::LoadUndefined { dst: 1 },
    ];

    for loader in primitive_loaders {
        let has = execute(&weakmap_with_primitive_key_then(
            "builtin:WeakMapPrototypeHas",
            loader.clone(),
        ))
        .expect("WeakMap.prototype.has should accept primitive keys as misses");
        assert_eq!(has.value, Value::Bool(false));

        let get = execute(&weakmap_with_primitive_key_then(
            "builtin:WeakMapPrototypeGet",
            loader,
        ))
        .expect("WeakMap.prototype.get should accept primitive keys as misses");
        assert_eq!(get.value, Value::Undefined);
    }
}

#[test]
fn weakmap_constructor_seeds_object_key_entries_from_iterable() {
    let first = execute(&weakmap_seeded_from_iterable_get_key(1))
        .expect("WeakMap constructor should seed first iterable entry");
    assert_eq!(first.value, Value::str("value1"));

    let second = execute(&weakmap_seeded_from_iterable_get_key(2))
        .expect("WeakMap constructor should seed second iterable entry");
    assert_eq!(second.value, Value::str("value2"));
}

#[test]
fn weakmap_prototype_methods_reject_non_weakmap_receivers() {
    let bad_receiver = module(
        "weakmap-bad-receiver",
        vec![
            Ir3Instruction::NewObject { dst: 0 },
            Ir3Instruction::NewObject { dst: 1 },
            Ir3Instruction::HostCall {
                capability: CapabilityTag("builtin:WeakMapPrototypeHas".to_string()),
                args: RegRange { start: 0, count: 2 },
                dst: 2,
            },
            Ir3Instruction::Halt,
        ],
        Vec::new(),
    );

    let err = execute(&bad_receiver).expect_err("plain object receiver must fail");
    assert!(matches!(
        err,
        InterpreterError::TypeError { expected, got }
            if expected == "WeakMap" && got == "object"
    ));
}

#[test]
fn weakmap_storage_tracks_weak_keys_and_cleans_collected_objects() {
    let mut storage = WeakMapStorage::new();
    storage.set(1, Value::str("value1"));
    storage.set(2, Value::str("value2"));
    storage.set(3, Value::str("value3"));

    assert_eq!(storage.get_weak_key_objects().len(), 3);
    assert!(storage.has(1));
    assert_eq!(storage.get(2), Some(&Value::str("value2")));

    let collected = BTreeSet::from([1, 3]);
    storage.cleanup_collected_objects(&collected);

    assert!(!storage.has(1));
    assert!(storage.has(2));
    assert!(!storage.has(3));
    assert_eq!(storage.get(1), None);
    assert_eq!(storage.get(2), Some(&Value::str("value2")));
    assert_eq!(storage.get(3), None);
    assert_eq!(storage.get_weak_key_objects(), &BTreeSet::from([2]));
}

// The former `#[cfg(any())] mod legacy_private_api_tests` block was removed here
// (bd-bg9l1.24). It never compiled — it referenced the removed `CoreInterpreter`
// private API. WeakMap basics, primitive-key rejection, iterable seeding, weak-key
// storage and collected-object cleanup are covered by the active current-API tests above.
