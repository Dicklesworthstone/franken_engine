use super::*;
use crate::ir_contract::{
    CapabilityTag, Ir3FunctionDesc, IrHeader, IrLevel, IrSchemaVersion, RegRange,
};
use frankenengine_extension_host::host_io::{HostIoError, HostIoOutcome, HostIoRequest};

fn test_module_with_functions(
    instructions: Vec<Ir3Instruction>,
    functions: Vec<Ir3FunctionDesc>,
) -> Ir3Module {
    Ir3Module {
        header: IrHeader {
            schema_version: IrSchemaVersion::CURRENT,
            level: IrLevel::Ir3,
            source_hash: None,
            source_label: "async-runtime-test".to_string(),
        },
        instructions,
        constant_pool: Vec::new(),
        function_table: functions,
        specialization: None,
        required_capabilities: Vec::new(),
        function_lengths: Default::default(),
        function_sources: Default::default(),
        sloppy_functions: Default::default(),
    }
}

fn test_interpreter() -> InterpreterCore {
    let mut config = InterpreterConfig::quickjs_defaults();
    config.granted_capabilities = std::collections::BTreeSet::from([
        RuntimeCapability::VmDispatch,
        RuntimeCapability::HeapAllocate,
    ]);
    InterpreterCore::new(config, "async-runtime-test")
}

#[derive(Debug)]
struct UnknownFsErrorProvider;

impl HostIoProvider for UnknownFsErrorProvider {
    fn name(&self) -> &str {
        "unknown-fs-error-provider"
    }

    fn perform(
        &self,
        _request: &frankenengine_extension_host::host_io::HostIoRequest,
        _granted: &[frankenengine_extension_host::host_io::HostIoCapability],
    ) -> frankenengine_extension_host::host_io::HostIoOutcome {
        Err(frankenengine_extension_host::host_io::HostIoError::Fs {
            code: "ENOENT".to_string(),
            detail: "provider-owned missing path".to_string(),
        })
    }
}

#[derive(Debug)]
struct UnknownFsReplayRecorder;

impl HostIoRecorder for UnknownFsReplayRecorder {
    fn begin_execution(&self) -> Result<(), HostIoError> {
        Ok(())
    }

    fn replay(&self, _request: &HostIoRequest) -> Option<HostIoOutcome> {
        Some(Err(HostIoError::Fs {
            code: "ENOENT".to_string(),
            detail: "replay-owned missing path".to_string(),
        }))
    }

    fn record(&self, _request: &HostIoRequest, _outcome: &HostIoOutcome) {}

    fn finish_execution(&self) -> Result<Vec<(HostIoRequest, HostIoOutcome)>, HostIoError> {
        Ok(Vec::new())
    }
}

fn calibrate_readable_memory_ceiling<T, F, O>(fixture: F, operation: O) -> u64
where
    T: std::fmt::Debug,
    F: Fn() -> (InterpreterCore, ObjectId),
    O: Fn(&mut InterpreterCore, ObjectId) -> Result<T, InterpreterError>,
{
    let (baseline, _) = fixture();
    let mut ceiling = baseline.estimated_memory_bytes();
    drop(baseline);

    for attempt in 0..32 {
        let (mut core, readable) = fixture();
        core.config.max_total_memory_bytes = ceiling;
        match operation(&mut core, readable) {
            Ok(_) => return ceiling,
            Err(InterpreterError::MemoryBudgetExceeded {
                requested_bytes, ..
            }) if requested_bytes > ceiling => {
                ceiling = requested_bytes;
            }
            other => panic!(
                "Readable ceiling calibration attempt {attempt} stalled at {ceiling}: {other:?}"
            ),
        }
    }
    panic!("Readable ceiling calibration did not converge from {ceiling}");
}

fn async_label_test_module(
    call: Ir3Instruction,
    body: Vec<Ir3Instruction>,
    arity: u32,
    name: &str,
) -> Ir3Module {
    let mut instructions = vec![call, Ir3Instruction::Halt];
    instructions.extend(body);
    test_module_with_functions(
        instructions,
        vec![Ir3FunctionDesc {
            entry: 2,
            arity,
            frame_size: arity.max(1),
            name: Some(name.to_string()),
            is_generator: false,
            rest_param_index: None,
        }],
    )
}

fn install_async_label_test_closure(core: &mut InterpreterCore) {
    core.closures.push(ClosureValue {
        function_index: 0,
        captured_env: Vec::new(),
    });
    core.mutate_registers(|registers| {
        registers[3] = Value::AsyncFunction(0);
    });
}

fn async_label_test_result_handle(core: &InterpreterCore) -> crate::promise_model::PromiseHandle {
    match core.registers.get(1) {
        Some(Value::Promise(handle)) => crate::promise_model::PromiseHandle(*handle),
        other => panic!("async call should leave result Promise in r1, got {other:?}"),
    }
}

fn shared_payload_values_bd_6pdka() -> [Value; 3] {
    let bigint = Value::BigInt(Arc::from("9".repeat(257)));
    let builtin =
        Value::BuiltinFunction(BuiltinFunction::require("shared-builtin-owner/".repeat(19)));
    let accessor = Value::Accessor {
        get: Some(Arc::new(bigint.clone())),
        set: Some(Arc::new(builtin.clone())),
    };
    [bigint, builtin, accessor]
}

fn assert_payload_clone_is_shared_bd_6pdka(original: &Value, cloned: &Value) {
    match (original, cloned) {
        (Value::BigInt(left), Value::BigInt(right)) => assert!(Arc::ptr_eq(left, right)),
        (Value::BuiltinFunction(left), Value::BuiltinFunction(right)) => {
            match (&left.module_specifier.0, &right.module_specifier.0) {
                (Some(left), Some(right)) => assert!(Arc::ptr_eq(left, right)),
                (None, None) => {}
                other => panic!("builtin provenance clone diverged: {other:?}"),
            }
        }
        (
            Value::Accessor {
                get: left_get,
                set: left_set,
            },
            Value::Accessor {
                get: right_get,
                set: right_set,
            },
        ) => {
            assert!(Arc::ptr_eq(
                left_get.as_ref().expect("source getter"),
                right_get.as_ref().expect("cloned getter")
            ));
            assert!(Arc::ptr_eq(
                left_set.as_ref().expect("source setter"),
                right_set.as_ref().expect("cloned setter")
            ));
        }
        _ => panic!("payload variants must match"),
    }
}

fn writable_order_module(markers: &[&str]) -> Ir3Module {
    let mut instructions = Vec::new();
    let mut functions = Vec::new();
    for (index, marker) in markers.iter().enumerate() {
        let entry = u32::try_from(instructions.len()).expect("test instruction index");
        instructions.extend([
            Ir3Instruction::LoadScoped {
                dst: 0,
                name_pool_index: 0,
            },
            Ir3Instruction::LoadStr {
                dst: 1,
                pool_index: u32::try_from(index + 1).expect("test marker pool index"),
            },
            Ir3Instruction::ArrayPush {
                array: 0,
                element: 1,
            },
            Ir3Instruction::Return { value: 1 },
        ]);
        functions.push(Ir3FunctionDesc {
            entry,
            arity: 0,
            frame_size: 2,
            name: Some(format!("record_{marker}")),
            is_generator: false,
            rest_param_index: None,
        });
    }
    let mut module = test_module_with_functions(instructions, functions);
    module.constant_pool.push("log".into());
    module
        .constant_pool
        .extend(markers.iter().map(|marker| (*marker).into()));
    module
}

fn install_writable_order_log(core: &mut InterpreterCore) -> ObjectId {
    let log = core
        .alloc_array_from_values(&[])
        .expect("Writable order log array");
    core.scope_chain
        .current_mut()
        .expect("global scope")
        .insert_binding(
            "log".to_string(),
            ScopeBinding::with_state(BindingKind::Var, Value::Object(log), true),
        );
    core.sync_estimated_memory_bytes()
        .expect("Writable order log accounting");
    log
}

fn writable_order_entries(core: &InterpreterCore, log: ObjectId) -> Vec<String> {
    let object = &core.heap[log.0 as usize];
    let length = object
        .properties
        .get("length")
        .and_then(|value| match value {
            Value::Int(length) => usize::try_from(*length).ok(),
            _ => None,
        })
        .expect("Writable order log length");
    (0..length)
        .map(|index| match object.properties.get(&index.to_string()) {
            Some(Value::Str(value)) => value.to_string(),
            other => panic!("Writable order entry {index}: {other:?}"),
        })
        .collect()
}

fn promise_state_for_register(
    core: &InterpreterCore,
    register: usize,
) -> crate::promise_model::PromiseState {
    let promise_id = match &core.registers[register] {
        Value::Promise(promise_id) => *promise_id,
        other => {
            panic!("expected promise in r{register}, got {other:?}");
        }
    };
    core.promise_store
        .get(crate::promise_model::PromiseHandle(promise_id))
        .expect("promise should exist")
        .state
        .clone()
}

#[test]
fn proxy_and_reflect_builtins_reach_baseline_heap() {
    let mut core = test_interpreter();
    let target = core
        .alloc_object_with_prototype(None)
        .expect("target allocation should succeed");
    let handler = core
        .alloc_object_with_prototype(None)
        .expect("handler allocation should succeed");
    core.set_object_property(target, "answer".to_string(), Value::Int(41))
        .expect("target property write should succeed");

    core.mutate_registers(|r| {
        r[0] = Value::Object(target);
        r[1] = Value::str("answer");
    });
    assert_eq!(
            core.dispatch_builtin_hostcall(
                "builtin:ReflectGet",
                RegRange { start: 0, count: 2 },
                None,
            )
            .expect("Reflect.get should read ordinary target"),
            Value::Int(41)
        );

    core.mutate_registers(|r| {
        r[0] = Value::Object(target);
        r[1] = Value::Object(handler);
    });
    let proxy = core
        .dispatch_builtin_hostcall("builtin:Proxy", RegRange { start: 0, count: 2 }, None)
        .expect("Proxy constructor should allocate baseline proxy");
    let Value::Object(proxy_id) = proxy else {
        panic!("Proxy constructor should return object");
    };

    core.mutate_registers(|r| {
        r[0] = Value::Object(proxy_id);
        r[1] = Value::str("answer");
        r[2] = Value::Int(42);
    });
    assert_eq!(
            core.dispatch_builtin_hostcall(
                "builtin:ReflectSet",
                RegRange { start: 0, count: 3 },
                None,
            )
            .expect("Reflect.set should forward through proxy"),
            Value::Bool(true)
        );
    assert_eq!(
        core.prototype_chain_get(target, "answer")
            .expect("target read should succeed"),
        Value::Int(42)
    );

    assert_eq!(
            core.dispatch_builtin_hostcall(
                "builtin:ReflectHas",
                RegRange { start: 0, count: 2 },
                None,
            )
            .expect("Reflect.has should forward through proxy"),
            Value::Bool(true)
        );
    assert_eq!(
        core.dispatch_builtin_hostcall(
            "builtin:ReflectDeleteProperty",
            RegRange { start: 0, count: 2 },
            None,
        )
        .expect("Reflect.deleteProperty should forward through proxy"),
        Value::Bool(true)
    );
    assert_eq!(
            core.dispatch_builtin_hostcall(
                "builtin:ReflectHas",
                RegRange { start: 0, count: 2 },
                None,
            )
            .expect("Reflect.has should observe deleted target property"),
            Value::Bool(false)
        );
}

fn construct_weakmap_for_current_test(core: &mut InterpreterCore) -> ObjectId {
    let result = core
        .dispatch_builtin_hostcall("builtin:WeakMap", RegRange { start: 0, count: 0 }, None)
        .expect("WeakMap constructor should allocate receiver and entries");
    let Value::Object(weakmap_id) = result else {
        panic!("WeakMap constructor should return object, got {result:?}");
    };
    assert_eq!(core.heap[weakmap_id.0 as usize].brand(), Some("WeakMap"));
    weakmap_id
}

fn weakmap_storage_for_current_test(
    core: &mut InterpreterCore,
    weakmap_id: ObjectId,
) -> &mut WeakMapStorage {
    core.weakmap_storage
        .get_mut(&weakmap_id)
        .expect("WeakMap constructor should initialize weak storage")
}

#[test]
fn weakmap_get_has_use_constructor_entries_storage_current() {
    let mut core = test_interpreter();
    let weakmap_id = construct_weakmap_for_current_test(&mut core);

    let key_id = core
        .alloc_object_with_prototype(None)
        .expect("object key allocation should succeed");
    weakmap_storage_for_current_test(&mut core, weakmap_id).set(key_id.0, Value::Int(41));

    core.mutate_registers(|r| {
        r[0] = Value::Object(weakmap_id);
        r[1] = Value::Object(key_id);
    });
    assert_eq!(
        core.dispatch_builtin_hostcall(
            "builtin:WeakMapPrototypeHas",
            RegRange { start: 0, count: 2 },
            None,
        )
        .expect("WeakMap.prototype.has should execute"),
        Value::Bool(true)
    );
    assert_eq!(
        core.dispatch_builtin_hostcall(
            "builtin:WeakMapPrototypeGet",
            RegRange { start: 0, count: 2 },
            None,
        )
        .expect("WeakMap.prototype.get should execute"),
        Value::Int(41)
    );

    let missing_key_id = core
        .alloc_object_with_prototype(None)
        .expect("missing object key allocation should succeed");
    core.mutate_registers(|r| {
        r[1] = Value::Object(missing_key_id);
    });
    assert_eq!(
        core.dispatch_builtin_hostcall(
            "builtin:WeakMapPrototypeHas",
            RegRange { start: 0, count: 2 },
            None,
        )
        .expect("WeakMap.prototype.has should execute for missing key"),
        Value::Bool(false)
    );
    assert_eq!(
        core.dispatch_builtin_hostcall(
            "builtin:WeakMapPrototypeGet",
            RegRange { start: 0, count: 2 },
            None,
        )
        .expect("WeakMap.prototype.get should execute for missing key"),
        Value::Undefined
    );
}

#[test]
fn weakmap_get_has_reject_plain_object_receivers_current() {
    let mut core = test_interpreter();
    let receiver_id = core
        .alloc_object_with_prototype(None)
        .expect("plain receiver allocation should succeed");
    let key_id = core
        .alloc_object_with_prototype(None)
        .expect("object key allocation should succeed");
    core.set_object_property(receiver_id, format!("o:{}", key_id.0), Value::Int(9))
        .expect("test setup should write fake direct receiver key");

    for capability in ["builtin:WeakMapPrototypeHas", "builtin:WeakMapPrototypeGet"] {
        core.mutate_registers(|r| {
            r[0] = Value::Object(receiver_id);
            r[1] = Value::Object(key_id);
        });
        let err = core
            .dispatch_builtin_hostcall(capability, RegRange { start: 0, count: 2 }, None)
            .expect_err("WeakMap prototype method should reject non-WeakMap receiver");
        assert!(matches!(
            err,
            InterpreterError::TypeError { expected, got }
                if expected == "WeakMap" && got == "object"
        ));
    }
}

#[test]
fn weakmap_get_has_ignore_primitive_keys_even_when_entries_match_current() {
    let mut core = test_interpreter();
    let weakmap_id = construct_weakmap_for_current_test(&mut core);
    let object_key_id = core
        .alloc_object_with_prototype(None)
        .expect("object key allocation should succeed");
    weakmap_storage_for_current_test(&mut core, weakmap_id).set(object_key_id.0, Value::Int(7));

    core.mutate_registers(|r| {
        r[0] = Value::Object(weakmap_id);
        r[1] = Value::str("primitive");
    });
    assert_eq!(
        core.dispatch_builtin_hostcall(
            "builtin:WeakMapPrototypeHas",
            RegRange { start: 0, count: 2 },
            None,
        )
        .expect("WeakMap.prototype.has should execute for primitive key"),
        Value::Bool(false)
    );
    assert_eq!(
        core.dispatch_builtin_hostcall(
            "builtin:WeakMapPrototypeGet",
            RegRange { start: 0, count: 2 },
            None,
        )
        .expect("WeakMap.prototype.get should execute for primitive key"),
        Value::Undefined
    );
}

#[test]
fn proxy_traps_execute_via_baseline_call_path() {
    let mut module = test_module_with_functions(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::Return { value: 0 },
        ],
        vec![Ir3FunctionDesc {
            entry: 0,
            arity: 3,
            frame_size: 1,
            name: Some("proxy_get_trap".to_string()),
            is_generator: false,
            rest_param_index: None,
        }],
    );
    module.constant_pool.push("from-get-trap".into());

    let mut core = test_interpreter();
    let target = core
        .alloc_object_with_prototype(None)
        .expect("target allocation should succeed");
    let handler = core
        .alloc_object_with_prototype(None)
        .expect("handler allocation should succeed");
    core.set_object_property(handler, "get".to_string(), Value::Function(0))
        .expect("handler trap write should succeed");

    core.mutate_registers(|r| {
        r[0] = Value::Object(target);
        r[1] = Value::Object(handler);
    });
    let proxy = core
        .dispatch_builtin_hostcall("builtin:Proxy", RegRange { start: 0, count: 2 }, None)
        .expect("Proxy constructor should allocate proxy");
    let Value::Object(proxy_id) = proxy else {
        panic!("Proxy constructor should return object");
    };

    core.mutate_registers(|r| {
        r[0] = Value::Object(proxy_id);
        r[1] = Value::str("anything");
    });
    assert_eq!(
        core.dispatch_builtin_hostcall(
            "builtin:ReflectGet",
            RegRange { start: 0, count: 2 },
            Some(&module),
        )
        .expect("Reflect.get should execute get trap"),
        Value::str("from-get-trap")
    );
}

#[test]
fn reflect_own_keys_executes_proxy_own_keys_trap() {
    let mut module = test_module_with_functions(
        vec![
            Ir3Instruction::NewArray { dst: 0 },
            Ir3Instruction::LoadStr {
                dst: 1,
                pool_index: 0,
            },
            Ir3Instruction::ArrayPush {
                array: 0,
                element: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 1,
                pool_index: 1,
            },
            Ir3Instruction::ArrayPush {
                array: 0,
                element: 1,
            },
            Ir3Instruction::Return { value: 0 },
        ],
        vec![Ir3FunctionDesc {
            entry: 0,
            arity: 1,
            frame_size: 2,
            name: Some("proxy_own_keys_trap".to_string()),
            is_generator: false,
            rest_param_index: None,
        }],
    );
    module.constant_pool.push("trap-b".into());
    module.constant_pool.push("trap-a".into());

    let mut core = test_interpreter();
    let target = core
        .alloc_object_with_prototype(None)
        .expect("target allocation should succeed");
    let handler = core
        .alloc_object_with_prototype(None)
        .expect("handler allocation should succeed");
    core.set_object_property(target, "target-only".to_string(), Value::Int(1))
        .expect("target setup should succeed");
    core.set_object_property(handler, "ownKeys".to_string(), Value::Function(0))
        .expect("handler ownKeys trap write should succeed");

    core.mutate_registers(|r| {
        r[0] = Value::Object(target);
        r[1] = Value::Object(handler);
    });
    let proxy = core
        .dispatch_builtin_hostcall("builtin:Proxy", RegRange { start: 0, count: 2 }, None)
        .expect("Proxy constructor should allocate proxy");
    let Value::Object(proxy_id) = proxy else {
        panic!("Proxy constructor should return object");
    };

    core.mutate_registers(|r| {
        r[0] = Value::Object(proxy_id);
    });
    let keys = core
        .dispatch_builtin_hostcall(
            "builtin:ReflectOwnKeys",
            RegRange { start: 0, count: 1 },
            Some(&module),
        )
        .expect("Reflect.ownKeys should execute ownKeys trap");
    let Value::Object(keys_id) = keys else {
        panic!("Reflect.ownKeys should return an array object");
    };

    assert_eq!(
        core.read_array_like_values(keys_id),
        vec![Value::str("trap-b"), Value::str("trap-a")]
    );
}

#[test]
fn proxy_own_keys_duplicate_identity_is_exact_bd_b12xs_6() {
    let make_module = |keys: Vec<JsString>| {
        let mut instructions = vec![Ir3Instruction::NewArray { dst: 0 }];
        for pool_index in 0..keys.len() {
            instructions.push(Ir3Instruction::LoadStr {
                dst: 1,
                pool_index: pool_index as u32,
            });
            instructions.push(Ir3Instruction::ArrayPush {
                array: 0,
                element: 1,
            });
        }
        instructions.push(Ir3Instruction::Return { value: 0 });
        let mut module = test_module_with_functions(
            instructions,
            vec![Ir3FunctionDesc {
                entry: 0,
                arity: 1,
                frame_size: 2,
                name: Some("proxy_exact_own_keys_trap".to_string()),
                is_generator: false,
                rest_param_index: None,
            }],
        );
        module.constant_pool.extend(keys);
        module
    };

    let d800 = JsString::from_code_units(&[0xD800]);
    let d801 = JsString::from_code_units(&[0xD801]);
    let replacement = JsString::from("\u{FFFD}");
    let distinct_module = make_module(vec![d800.clone(), d801.clone(), replacement.clone()]);
    let duplicate_module = make_module(vec![d800.clone(), d800.clone()]);

    let mut core = test_interpreter();
    let target = core.alloc_object_with_prototype(None).unwrap();
    let handler = core.alloc_object_with_prototype(None).unwrap();
    core.set_object_property(handler, "ownKeys".to_string(), Value::Function(0))
        .unwrap();
    core.set_reg(0, Value::Object(target));
    core.set_reg(1, Value::Object(handler));
    let proxy = core
        .dispatch_builtin_hostcall("builtin:Proxy", RegRange { start: 0, count: 2 }, None)
        .unwrap();
    let Value::Object(proxy) = proxy else {
        panic!("Proxy constructor must return an object");
    };

    core.set_reg(0, Value::Object(proxy));
    let keys = core
        .dispatch_builtin_hostcall(
            "builtin:ReflectOwnKeys",
            RegRange { start: 0, count: 1 },
            Some(&distinct_module),
        )
        .expect("D800, D801, and U+FFFD are distinct Proxy ownKeys results");
    let Value::Object(keys) = keys else {
        panic!("Reflect.ownKeys must return an array");
    };
    assert_eq!(
        core.read_array_like_values(keys),
        vec![
            Value::Str(d800.clone()),
            Value::Str(d801),
            Value::Str(replacement),
        ]
    );

    core.set_reg(0, Value::Object(proxy));
    assert!(matches!(
        core.dispatch_builtin_hostcall(
            "builtin:ReflectOwnKeys",
            RegRange { start: 0, count: 1 },
            Some(&duplicate_module),
        ),
        Err(InterpreterError::TypeError { .. })
    ));
}

#[test]
fn proxy_get_property_instruction_executes_get_trap() {
    let mut module = test_module_with_functions(
        vec![
            Ir3Instruction::GetProperty {
                obj: 5,
                key: 6,
                dst: 7,
            },
            Ir3Instruction::Return { value: 7 },
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::Return { value: 0 },
        ],
        vec![Ir3FunctionDesc {
            entry: 2,
            arity: 3,
            frame_size: 1,
            name: Some("proxy_instruction_get_trap".to_string()),
            is_generator: false,
            rest_param_index: None,
        }],
    );
    module.constant_pool.push("from-instruction-trap".into());

    let mut core = test_interpreter();
    let target = core
        .alloc_object_with_prototype(None)
        .expect("target allocation should succeed");
    let handler = core
        .alloc_object_with_prototype(None)
        .expect("handler allocation should succeed");
    core.set_object_property(handler, "get".to_string(), Value::Function(0))
        .expect("handler get trap write should succeed");

    core.mutate_registers(|r| {
        r[0] = Value::Object(target);
        r[1] = Value::Object(handler);
    });
    let proxy = core
        .dispatch_builtin_hostcall("builtin:Proxy", RegRange { start: 0, count: 2 }, None)
        .expect("Proxy constructor should allocate proxy");
    let Value::Object(proxy_id) = proxy else {
        panic!("Proxy constructor should return object");
    };

    core.mutate_registers(|r| {
        r[5] = Value::Object(proxy_id);
        r[6] = Value::str("viaInstruction");
    });
    assert_eq!(
        core.run_loop(&module)
            .expect("GetProperty should execute Proxy get trap"),
        Value::str("from-instruction-trap")
    );
}

#[test]
fn proxy_revocation_and_reflect_call_construct_are_executable() {
    let module = test_module_with_functions(
        vec![
            Ir3Instruction::LoadInt { dst: 0, value: 99 },
            Ir3Instruction::Return { value: 0 },
            Ir3Instruction::LoadInt { dst: 0, value: 5 },
            Ir3Instruction::Return { value: 0 },
        ],
        vec![
            Ir3FunctionDesc {
                entry: 0,
                arity: 0,
                frame_size: 1,
                name: Some("call_target".to_string()),
                is_generator: false,
                rest_param_index: None,
            },
            Ir3FunctionDesc {
                entry: 2,
                arity: 0,
                frame_size: 1,
                name: Some("construct_target".to_string()),
                is_generator: false,
                rest_param_index: None,
            },
        ],
    );

    let mut core = test_interpreter();
    let empty_args = core
        .alloc_array_from_values(&[])
        .expect("arguments array allocation should succeed");
    core.write_reg(0, Value::Function(0)).expect("apply target");
    core.write_reg(1, Value::Undefined).expect("apply receiver");
    core.write_reg(2, Value::Object(empty_args))
        .expect("apply arguments");
    assert_eq!(
        core.dispatch_builtin_hostcall(
            "builtin:ReflectApply",
            RegRange { start: 0, count: 3 },
            Some(&module),
        )
        .expect("Reflect.apply should call target function"),
        Value::Int(99)
    );

    core.write_reg(0, Value::Function(1))
        .expect("construct target");
    core.write_reg(1, Value::Object(empty_args))
        .expect("construct arguments");
    let constructed = core
        .dispatch_builtin_hostcall(
            "builtin:ReflectConstruct",
            RegRange { start: 0, count: 2 },
            Some(&module),
        )
        .expect("Reflect.construct should construct target");
    let Value::Object(constructed_id) = constructed else {
        panic!("Reflect.construct should return constructed object");
    };
    assert_eq!(
        core.heap[constructed_id.0 as usize].constructor_function,
        Some(1)
    );

    let target = core
        .alloc_object_with_prototype(None)
        .expect("target allocation should succeed");
    let handler = core
        .alloc_object_with_prototype(None)
        .expect("handler allocation should succeed");
    core.set_object_property(target, "x".to_string(), Value::Int(23))
        .expect("proxy target property");
    core.write_reg(0, Value::Object(target))
        .expect("proxy target");
    core.write_reg(1, Value::Object(handler))
        .expect("proxy handler");
    let revocable = core
        .dispatch_builtin_hostcall(
            "builtin:ProxyRevocable",
            RegRange { start: 0, count: 2 },
            None,
        )
        .expect("Proxy.revocable should return pair object");
    let Value::Object(revocable_id) = revocable else {
        panic!("Proxy.revocable should return object");
    };
    let proxy = core
        .prototype_chain_get(revocable_id, "proxy")
        .expect("revocable proxy field should exist");
    let revoker = core
        .prototype_chain_get(revocable_id, "revoke")
        .expect("revocable revoke field should exist");
    let Value::BuiltinFunction(revoker) = revoker else {
        panic!("revoke field should be callable");
    };
    let Value::Object(proxy_id) = proxy else {
        panic!("proxy field should be object");
    };
    core.write_reg(0, Value::Object(proxy_id))
        .expect("live proxy");
    core.write_reg(1, Value::str("x")).expect("live proxy key");
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes(),
        "fixture writes must be charged before observing the proxy"
    );
    assert_eq!(
            core.dispatch_builtin_hostcall(
                "builtin:ReflectGet",
                RegRange { start: 0, count: 2 },
                None,
            )
            .expect("the same proxy access before revocation must succeed"),
            Value::Int(23)
        );
    assert!(core.pending_exception.is_none());
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );

    core.dispatch_builtin_function(
        &module,
        &revoker,
        RegRange { start: 0, count: 0 },
        None,
        None,
    )
    .expect("revoker should execute");
    core.write_reg(0, Value::Object(proxy_id))
        .expect("revoked proxy");
    core.write_reg(1, Value::str("x"))
        .expect("revoked proxy key");
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
    let err = core
        .dispatch_builtin_hostcall("builtin:ReflectGet", RegRange { start: 0, count: 2 }, None)
        .expect_err("revoked proxy access must fail closed");
    assert!(
        matches!(err, InterpreterError::UncaughtException { .. }),
        "revocation must transport a guest language error: {err:?}"
    );
    let Some(Value::Object(error_id)) = core.pending_exception.as_ref() else {
        panic!("revoked access must retain its guest TypeError");
    };
    assert_eq!(
        core.chain_data_property(*error_id, "name"),
        Some(&Value::str("TypeError"))
    );
    assert!(matches!(
        core.chain_data_property(*error_id, "message"),
        Some(Value::Str(message)) if message.contains("revoked Proxy")
    ));
    assert_eq!(core.pending_exception_label, Label::Public);
    assert!(core.active_inline_callback_context_label.is_none());
    assert_eq!(core.json_parse_temporary_bytes, 0);
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn promise_witness_eviction_releases_its_projected_charge_bd_9vouw_71() {
    // then/fulfill charge their projected bytes before mutating. Each
    // round appends at least two witness events to the Promise store, so
    // 1,500 rounds cross its 2,048-event bound, where a push drops the
    // oldest 1,024 events instead of growing the log. The estimate must
    // track the full walk after every operation: ignoring the eviction
    // left 64 KiB charged per eviction, and a 24,000-await loop failed
    // its 2 MiB budget.
    let mut core = test_interpreter();
    let entry_drift = core.memory_walk_drift();
    for round in 0..1_500i64 {
        let promise = core.create_promise().expect("create");
        core.register_promise_then(promise, None, None, crate::ifc_artifacts::Label::Public)
            .expect("then");
        core.fulfill_promise(
            promise,
            crate::object_model::JsValue::Int(round),
            crate::ifc_artifacts::Label::Public,
        )
        .expect("fulfill");
        assert_eq!(core.memory_walk_drift(), entry_drift, "round {round}");
    }
    assert!(
        core.promise_store.witness_log().len() < 2_048,
        "the Promise witness log must have dropped events (the case under test)"
    );
}

#[test]
fn async_function_call_executes_body_and_fulfills_promise() {
    let module = test_module_with_functions(
        vec![
            Ir3Instruction::Call {
                callee: 3,
                args: RegRange { start: 8, count: 0 },
                dst: 0,
            },
            Ir3Instruction::Halt,
            Ir3Instruction::LoadInt { dst: 0, value: 42 },
            Ir3Instruction::Return { value: 0 },
        ],
        vec![Ir3FunctionDesc {
            entry: 2,
            arity: 0,
            frame_size: 1,
            name: Some("async_value".to_string()),
            is_generator: false,
            rest_param_index: None,
        }],
    );

    let mut core = test_interpreter();
    core.closures.push(ClosureValue {
        function_index: 0,
        captured_env: Vec::new(),
    });
    core.mutate_registers(|r| {
        r[3] = Value::AsyncFunction(0);
    });

    let result = core
        .execute(&module)
        .expect("async function call should execute");
    let Value::Promise(promise_id) = result.value else {
        panic!("expected promise result, got {:?}", result.value);
    };
    let promise = core
        .promise_store
        .get(crate::promise_model::PromiseHandle(promise_id))
        .expect("async result promise should exist");
    assert_eq!(
        promise.state,
        crate::promise_model::PromiseState::Fulfilled(crate::object_model::JsValue::Int(42))
    );
    assert!(matches!(
        core.async_functions[0].phase,
        AsyncFunctionPhase::Completed
    ));
}

#[test]
fn async_function_throw_rejects_promise_instead_of_aborting_execution() {
    let mut module = test_module_with_functions(
        vec![
            Ir3Instruction::Call {
                callee: 3,
                args: RegRange { start: 8, count: 0 },
                dst: 0,
            },
            Ir3Instruction::Halt,
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::Throw { value: 0 },
        ],
        vec![Ir3FunctionDesc {
            entry: 2,
            arity: 0,
            frame_size: 1,
            name: Some("async_throw".to_string()),
            is_generator: false,
            rest_param_index: None,
        }],
    );
    module.constant_pool.push("boom".into());

    let mut core = test_interpreter();
    core.closures.push(ClosureValue {
        function_index: 0,
        captured_env: Vec::new(),
    });
    core.mutate_registers(|r| {
        r[3] = Value::AsyncFunction(0);
    });

    let result = core
        .execute(&module)
        .expect("async throw should reject promise instead of aborting");
    let Value::Promise(promise_id) = result.value else {
        panic!("expected promise result, got {:?}", result.value);
    };
    let promise = core
        .promise_store
        .get(crate::promise_model::PromiseHandle(promise_id))
        .expect("async result promise should exist");
    assert_eq!(
        promise.state,
        crate::promise_model::PromiseState::Rejected(crate::object_model::JsValue::Str(
            "boom".to_string(),
        ))
    );
}

#[test]
fn await_resolved_promise_overwrites_register_and_returns_value() {
    let module = test_module_with_functions(
        vec![
            Ir3Instruction::Call {
                callee: 3,
                args: RegRange { start: 1, count: 1 },
                dst: 0,
            },
            Ir3Instruction::Halt,
            Ir3Instruction::AwaitValue { promise_reg: 0 },
            Ir3Instruction::Return { value: 0 },
        ],
        vec![Ir3FunctionDesc {
            entry: 2,
            arity: 1,
            frame_size: 1,
            name: Some("await_now".to_string()),
            is_generator: false,
            rest_param_index: None,
        }],
    );

    let mut core = test_interpreter();
    core.closures.push(ClosureValue {
        function_index: 0,
        captured_env: Vec::new(),
    });
    core.mutate_registers(|r| {
        r[3] = Value::AsyncFunction(0);
    });

    let handle = core.promise_store.create();
    let label = crate::ifc_artifacts::Label::Public;
    core.promise_store
        .fulfill(
            handle,
            crate::object_model::JsValue::Int(99),
            label,
            &mut core.event_loop.microtasks,
        )
        .expect("seed promise should be fulfillable");
    core.mutate_registers(|r| {
        r[1] = Value::Promise(handle.0);
    });

    let result = core
        .execute(&module)
        .expect("fulfilled await should execute synchronously");
    let Value::Promise(promise_id) = result.value else {
        panic!("expected promise result, got {:?}", result.value);
    };
    let promise = core
        .promise_store
        .get(crate::promise_model::PromiseHandle(promise_id))
        .expect("async result promise should exist");
    assert_eq!(
        promise.state,
        crate::promise_model::PromiseState::Fulfilled(crate::object_model::JsValue::Int(99))
    );
}

#[test]
fn pending_await_fulfillment_resumes_async_result_promise_bd_oswo2() {
    let module = test_module_with_functions(
        vec![
            Ir3Instruction::Call {
                callee: 3,
                args: RegRange { start: 1, count: 1 },
                dst: 0,
            },
            Ir3Instruction::Halt,
            Ir3Instruction::AwaitValue { promise_reg: 0 },
            Ir3Instruction::Return { value: 0 },
        ],
        vec![Ir3FunctionDesc {
            entry: 2,
            arity: 1,
            frame_size: 1,
            name: Some("await_pending_then_return".to_string()),
            is_generator: false,
            rest_param_index: None,
        }],
    );

    let mut core = test_interpreter();
    core.closures.push(ClosureValue {
        function_index: 0,
        captured_env: Vec::new(),
    });
    let awaited = core.promise_store.create();
    core.mutate_registers(|r| {
        r[1] = Value::Promise(awaited.0);
        r[3] = Value::AsyncFunction(0);
    });

    let result = core
        .execute(&module)
        .expect("pending await should suspend without aborting");
    // The caller continues past the call with the async function's result
    // Promise and halts with it (bd-9vouw.26); the suspended await used to
    // abort the whole program with Undefined.
    let async_result_promise = core.async_functions[0].result_promise;
    assert_eq!(result.value, Value::Promise(async_result_promise));

    core.fulfill_promise(
        awaited,
        crate::object_model::JsValue::Int(42),
        crate::ifc_artifacts::Label::Public,
    )
    .expect("awaited promise should be fulfillable");
    core.drain_microtasks(Some(&module))
        .expect("microtask drain fits test budget");

    let promise = core
        .promise_store
        .get(crate::promise_model::PromiseHandle(async_result_promise))
        .expect("async result promise should exist");
    assert_eq!(
        promise.state,
        crate::promise_model::PromiseState::Fulfilled(crate::object_model::JsValue::Int(42))
    );
}

#[test]
fn pending_await_rejection_rejects_async_result_promise_bd_oswo2() {
    let module = test_module_with_functions(
        vec![
            Ir3Instruction::Call {
                callee: 3,
                args: RegRange { start: 1, count: 1 },
                dst: 0,
            },
            Ir3Instruction::Halt,
            Ir3Instruction::AwaitValue { promise_reg: 0 },
            Ir3Instruction::Return { value: 0 },
        ],
        vec![Ir3FunctionDesc {
            entry: 2,
            arity: 1,
            frame_size: 1,
            name: Some("await_pending_then_reject".to_string()),
            is_generator: false,
            rest_param_index: None,
        }],
    );

    let mut core = test_interpreter();
    core.closures.push(ClosureValue {
        function_index: 0,
        captured_env: Vec::new(),
    });
    let awaited = core.promise_store.create();
    core.mutate_registers(|r| {
        r[1] = Value::Promise(awaited.0);
        r[3] = Value::AsyncFunction(0);
    });

    let result = core
        .execute(&module)
        .expect("pending await should suspend without aborting");
    // The caller continues past the call with the async function's result
    // Promise and halts with it (bd-9vouw.26); the suspended await used to
    // abort the whole program with Undefined.
    let async_result_promise = core.async_functions[0].result_promise;
    assert_eq!(result.value, Value::Promise(async_result_promise));

    core.reject_promise(
        awaited,
        crate::object_model::JsValue::Str("boom".to_string()),
        crate::ifc_artifacts::Label::Public,
    )
    .expect("awaited promise should be rejectable");
    core.drain_microtasks(Some(&module))
        .expect("microtask drain fits test budget");

    let promise = core
        .promise_store
        .get(crate::promise_model::PromiseHandle(async_result_promise))
        .expect("async result promise should exist");
    assert_eq!(
        promise.state,
        crate::promise_model::PromiseState::Rejected(crate::object_model::JsValue::Str(
            "boom".to_string()
        ))
    );
}

#[test]
fn pending_await_rejection_enters_async_catch_bd_oswo2() {
    let module = test_module_with_functions(
        vec![
            Ir3Instruction::Call {
                callee: 3,
                args: RegRange { start: 1, count: 1 },
                dst: 0,
            },
            Ir3Instruction::Halt,
            Ir3Instruction::BeginTry {
                catch_target: 6,
                finally_target: None,
            },
            Ir3Instruction::AwaitValue { promise_reg: 0 },
            Ir3Instruction::EndTry,
            Ir3Instruction::Return { value: 0 },
            Ir3Instruction::EnterCatch { dst: 0 },
            Ir3Instruction::Return { value: 0 },
        ],
        vec![Ir3FunctionDesc {
            entry: 2,
            arity: 1,
            frame_size: 1,
            name: Some("await_pending_then_catch".to_string()),
            is_generator: false,
            rest_param_index: None,
        }],
    );

    let mut core = test_interpreter();
    core.closures.push(ClosureValue {
        function_index: 0,
        captured_env: Vec::new(),
    });
    let awaited = core.promise_store.create();
    core.mutate_registers(|r| {
        r[1] = Value::Promise(awaited.0);
        r[3] = Value::AsyncFunction(0);
    });

    let result = core
        .execute(&module)
        .expect("pending await should suspend without aborting");
    // The caller continues past the call with the async function's result
    // Promise and halts with it (bd-9vouw.26); the suspended await used to
    // abort the whole program with Undefined.
    let async_result_promise = core.async_functions[0].result_promise;
    assert_eq!(result.value, Value::Promise(async_result_promise));

    core.reject_promise(
        awaited,
        crate::object_model::JsValue::Str("caught".to_string()),
        crate::ifc_artifacts::Label::Public,
    )
    .expect("awaited promise should be rejectable");
    core.drain_microtasks(Some(&module))
        .expect("microtask drain fits test budget");

    let promise = core
        .promise_store
        .get(crate::promise_model::PromiseHandle(async_result_promise))
        .expect("async result promise should exist");
    assert_eq!(
        promise.state,
        crate::promise_model::PromiseState::Fulfilled(crate::object_model::JsValue::Str(
            "caught".to_string()
        ))
    );
}

#[test]
fn await_non_promise_preserves_register_label() {
    // `return await secretSeven` in an async function: Await always
    // resumes from a Promise job (bd-9vouw.26), and both the synthetic
    // Promise wrapping the non-Promise operand and the async result keep
    // the operand's Secret label across that resumption. (This test used
    // a top-level AwaitValue with no async frame, which only ran through
    // the removed synchronous fast path; lowering never emits it.)
    let module = test_module_with_functions(
        vec![
            Ir3Instruction::Call {
                callee: 3,
                args: RegRange { start: 1, count: 1 },
                dst: 0,
            },
            Ir3Instruction::Halt,
            Ir3Instruction::AwaitValue { promise_reg: 0 },
            Ir3Instruction::Return { value: 0 },
        ],
        vec![Ir3FunctionDesc {
            entry: 2,
            arity: 1,
            frame_size: 1,
            name: Some("await_secret_value".to_string()),
            is_generator: false,
            rest_param_index: None,
        }],
    );

    let mut core = test_interpreter();
    core.closures.push(ClosureValue {
        function_index: 0,
        captured_env: Vec::new(),
    });
    core.mutate_registers(|r| {
        r[1] = Value::Int(7);
        r[3] = Value::AsyncFunction(0);
    });
    core.set_register_label(1, crate::ifc_artifacts::Label::Secret)
        .expect("test register label should be settable");

    let result = core
        .execute(&module)
        .expect("awaiting a non-promise suspends and resumes from a Promise job");
    let result_promise = core.async_functions[0].result_promise;
    assert_eq!(result.value, Value::Promise(result_promise));
    let settled = core
        .promise_store
        .get(crate::promise_model::PromiseHandle(result_promise))
        .expect("async result promise should exist");
    assert_eq!(
        settled.state,
        crate::promise_model::PromiseState::Fulfilled(crate::object_model::JsValue::Int(7))
    );
    assert!(
        settled.label >= crate::ifc_artifacts::Label::Secret,
        "the awaited Secret value must keep its label through resumption, got {:?}",
        settled.label
    );
    let synthetic_await_promise_labels: Vec<_> = (0..u32::MAX)
        .map(crate::promise_model::PromiseHandle)
        .map_while(|handle| {
            core.promise_store
                .get(handle)
                .ok()
                .map(|record| record.label.clone())
        })
        .collect();
    assert!(
        synthetic_await_promise_labels.contains(&crate::ifc_artifacts::Label::Secret),
        "the synthetic Promise for the awaited non-Promise must carry its Secret label, got {synthetic_await_promise_labels:?}"
    );
}

/// bd-oswo2: awaiting a PENDING promise that later FULFILLS must resume
/// the async function and run its continuation, settling the async
/// function's result promise with the returned value.
#[test]
fn await_pending_then_fulfill_resumes_with_value_oswo2() {
    let module = test_module_with_functions(
        vec![
            Ir3Instruction::Call {
                callee: 3,
                args: RegRange { start: 1, count: 1 },
                dst: 0,
            },
            Ir3Instruction::Halt,
            // async fn body @entry 2: `return await arg`
            Ir3Instruction::AwaitValue { promise_reg: 0 },
            Ir3Instruction::Return { value: 0 },
        ],
        vec![Ir3FunctionDesc {
            entry: 2,
            arity: 1,
            frame_size: 1,
            name: Some("await_pending_fulfill".to_string()),
            is_generator: false,
            rest_param_index: None,
        }],
    );

    let mut core = test_interpreter();
    core.closures.push(ClosureValue {
        function_index: 0,
        captured_env: Vec::new(),
    });
    core.mutate_registers(|r| {
        r[3] = Value::AsyncFunction(0);
    });

    let awaited = core.promise_store.create();
    core.mutate_registers(|r| {
        r[1] = Value::Promise(awaited.0);
    });

    core.execute(&module).expect("suspends on pending await");
    let async_result = crate::promise_model::PromiseHandle(core.async_functions[0].result_promise);
    assert_eq!(
        core.promise_store.get(async_result).unwrap().state,
        crate::promise_model::PromiseState::Pending,
        "async result promise pending while awaited promise unsettled"
    );

    core.promise_store
        .fulfill(
            awaited,
            crate::object_model::JsValue::Int(7),
            Label::Public,
            &mut core.event_loop.microtasks,
        )
        .expect("fulfill seed promise");
    core.drain_microtasks(Some(&module))
        .expect("fulfilled await continuation drains successfully");

    let state = core.promise_store.get(async_result).unwrap().state.clone();
    assert_eq!(
        state,
        crate::promise_model::PromiseState::Fulfilled(crate::object_model::JsValue::Int(7)),
        "await of a fulfilled promise must resume and fulfill the async \
             result promise with the value, got {state:?}"
    );
}

/// bd-oswo2: awaiting a PENDING promise that later REJECTS must throw the
/// rejection reason into the async function (rejecting its result promise),
/// NOT resume as if it were a fulfillment value.
#[test]
fn await_pending_then_reject_throws_into_async_frame_oswo2() {
    let module = test_module_with_functions(
        vec![
            Ir3Instruction::Call {
                callee: 3,
                args: RegRange { start: 1, count: 1 },
                dst: 0,
            },
            Ir3Instruction::Halt,
            // async fn body @entry 2: `return await arg`
            Ir3Instruction::AwaitValue { promise_reg: 0 },
            Ir3Instruction::Return { value: 0 },
        ],
        vec![Ir3FunctionDesc {
            entry: 2,
            arity: 1,
            frame_size: 1,
            name: Some("await_pending_reject".to_string()),
            is_generator: false,
            rest_param_index: None,
        }],
    );

    let mut core = test_interpreter();
    core.closures.push(ClosureValue {
        function_index: 0,
        captured_env: Vec::new(),
    });
    core.mutate_registers(|r| {
        r[3] = Value::AsyncFunction(0);
    });

    let awaited = core.promise_store.create();
    core.mutate_registers(|r| {
        r[1] = Value::Promise(awaited.0);
    });

    core.execute(&module).expect("suspends on pending await");
    let async_result = crate::promise_model::PromiseHandle(core.async_functions[0].result_promise);
    assert_eq!(
        core.promise_store.get(async_result).unwrap().state,
        crate::promise_model::PromiseState::Pending,
        "async result promise pending while awaited promise unsettled"
    );

    core.promise_store
        .reject(
            awaited,
            crate::object_model::JsValue::Str("boom".into()),
            Label::Public,
            &mut core.event_loop.microtasks,
        )
        .expect("reject seed promise");
    core.drain_microtasks(Some(&module))
        .expect("rejected await continuation drains successfully");

    let state = core.promise_store.get(async_result).unwrap().state.clone();
    assert_eq!(
        state,
        crate::promise_model::PromiseState::Rejected(crate::object_model::JsValue::Str(
            "boom".into()
        )),
        "await of a rejected promise must reject the async result promise \
             (throw), not fulfill it; got {state:?}"
    );
}

#[test]
fn async_direct_return_preserves_argument_label_bd_ur3tk_18() {
    let module = async_label_test_module(
        Ir3Instruction::Call {
            callee: 3,
            args: RegRange {
                start: 10,
                count: 1,
            },
            dst: 1,
        },
        vec![Ir3Instruction::AsyncReturn { value_reg: 0 }],
        1,
        "direct_async_return_label",
    );
    let mut core = test_interpreter();
    install_async_label_test_closure(&mut core);
    core.write_reg_with_label(10, Value::str("secret-return"), Label::Secret)
        .expect("async argument should be writable");

    core.execute(&module)
        .expect("direct async return should resolve");

    let record = core
        .promise_store
        .get(async_label_test_result_handle(&core))
        .expect("result Promise should exist");
    assert_eq!(record.label, Label::Secret);
    assert!(matches!(
        &record.state,
        crate::promise_model::PromiseState::Fulfilled(
            crate::object_model::JsValue::Str(value)
        ) if value == "secret-return"
    ));
}

#[test]
fn async_direct_throw_preserves_argument_label_bd_ur3tk_18() {
    let module = async_label_test_module(
        Ir3Instruction::Call {
            callee: 3,
            args: RegRange {
                start: 10,
                count: 1,
            },
            dst: 1,
        },
        vec![Ir3Instruction::AsyncThrow { error_reg: 0 }],
        1,
        "direct_async_throw_label",
    );
    let mut core = test_interpreter();
    install_async_label_test_closure(&mut core);
    core.write_reg_with_label(10, Value::str("secret-rejection"), Label::Secret)
        .expect("async rejection argument should be writable");

    core.execute(&module)
        .expect("direct async throw should reject its Promise");

    let record = core
        .promise_store
        .get(async_label_test_result_handle(&core))
        .expect("result Promise should exist");
    assert_eq!(record.label, Label::Secret);
    assert!(matches!(
        &record.state,
        crate::promise_model::PromiseState::Rejected(
            crate::object_model::JsValue::Str(value)
        ) if value == "secret-rejection"
    ));
}

#[test]
fn async_method_preserves_receiver_label_bd_ur3tk_18() {
    let module = async_label_test_module(
        Ir3Instruction::CallMethod {
            receiver: 2,
            callee: 3,
            args: RegRange {
                start: 10,
                count: 0,
            },
            dst: 1,
        },
        vec![
            Ir3Instruction::LoadThis { dst: 0 },
            Ir3Instruction::AsyncReturn { value_reg: 0 },
        ],
        0,
        "async_method_receiver_label",
    );
    let mut core = test_interpreter();
    install_async_label_test_closure(&mut core);
    core.write_reg_with_label(2, Value::str("secret-receiver"), Label::Secret)
        .expect("method receiver should be writable");

    core.execute(&module).expect("async method should resolve");

    let record = core
        .promise_store
        .get(async_label_test_result_handle(&core))
        .expect("result Promise should exist");
    assert_eq!(record.label, Label::Secret);
    assert!(matches!(
        &record.state,
        crate::promise_model::PromiseState::Fulfilled(
            crate::object_model::JsValue::Str(value)
        ) if value == "secret-receiver"
    ));
}

#[test]
fn async_method_preserves_argument_label_bd_ur3tk_18() {
    let module = async_label_test_module(
        Ir3Instruction::CallMethod {
            receiver: 2,
            callee: 3,
            args: RegRange {
                start: 10,
                count: 1,
            },
            dst: 1,
        },
        vec![Ir3Instruction::AsyncReturn { value_reg: 0 }],
        1,
        "async_method_argument_label",
    );
    let mut core = test_interpreter();
    install_async_label_test_closure(&mut core);
    core.write_reg_with_label(10, Value::str("secret-argument"), Label::Secret)
        .expect("method argument should be writable");

    core.execute(&module)
        .expect("async method should preserve its argument label");

    let record = core
        .promise_store
        .get(async_label_test_result_handle(&core))
        .expect("result Promise should exist");
    assert_eq!(record.label, Label::Secret);
    assert!(matches!(
        &record.state,
        crate::promise_model::PromiseState::Fulfilled(
            crate::object_model::JsValue::Str(value)
        ) if value == "secret-argument"
    ));
}

#[test]
fn async_immediate_await_joins_handle_and_settlement_labels_bd_ur3tk_18() {
    let module = async_label_test_module(
        Ir3Instruction::Call {
            callee: 3,
            args: RegRange {
                start: 10,
                count: 1,
            },
            dst: 1,
        },
        vec![
            Ir3Instruction::AwaitValue { promise_reg: 0 },
            Ir3Instruction::AsyncReturn { value_reg: 0 },
        ],
        1,
        "immediate_await_label_join",
    );
    let mut core = test_interpreter();
    install_async_label_test_closure(&mut core);
    let awaited = core.promise_store.create();
    core.promise_store
        .fulfill(
            awaited,
            crate::object_model::JsValue::Str("public-payload".to_string()),
            Label::Public,
            &mut core.event_loop.microtasks,
        )
        .expect("awaited Promise should be fulfillable");
    core.write_reg_with_label(10, Value::Promise(awaited.0), Label::Secret)
        .expect("awaited handle should be writable");

    core.execute(&module)
        .expect("immediate fulfilled await should resolve");

    let record = core
        .promise_store
        .get(async_label_test_result_handle(&core))
        .expect("result Promise should exist");
    assert_eq!(record.label, Label::Secret);
    assert!(matches!(
        &record.state,
        crate::promise_model::PromiseState::Fulfilled(
            crate::object_model::JsValue::Str(value)
        ) if value == "public-payload"
    ));
}

#[test]
fn async_immediate_rejection_joins_handle_label_bd_ur3tk_18() {
    let module = async_label_test_module(
        Ir3Instruction::Call {
            callee: 3,
            args: RegRange {
                start: 10,
                count: 1,
            },
            dst: 1,
        },
        vec![
            Ir3Instruction::AwaitValue { promise_reg: 0 },
            Ir3Instruction::AsyncReturn { value_reg: 0 },
        ],
        1,
        "immediate_await_rejection_label_join",
    );
    let mut core = test_interpreter();
    install_async_label_test_closure(&mut core);
    let awaited = core.promise_store.create();
    core.promise_store
        .reject(
            awaited,
            crate::object_model::JsValue::Str("public-reason".to_string()),
            Label::Public,
            &mut core.event_loop.microtasks,
        )
        .expect("awaited Promise should be rejectable");
    core.write_reg_with_label(10, Value::Promise(awaited.0), Label::Secret)
        .expect("awaited handle should be writable");

    core.execute(&module)
        .expect("immediate rejected await should reject its result Promise");

    let record = core
        .promise_store
        .get(async_label_test_result_handle(&core))
        .expect("result Promise should exist");
    assert_eq!(record.label, Label::Secret);
    assert!(matches!(
        &record.state,
        crate::promise_model::PromiseState::Rejected(
            crate::object_model::JsValue::Str(value)
        ) if value == "public-reason"
    ));
}

#[test]
fn async_pending_await_restores_labels_and_joins_fulfillment_bd_ur3tk_18() {
    let module = async_label_test_module(
        Ir3Instruction::Call {
            callee: 3,
            args: RegRange {
                start: 10,
                count: 2,
            },
            dst: 1,
        },
        vec![
            Ir3Instruction::AwaitValue { promise_reg: 0 },
            Ir3Instruction::AsyncReturn { value_reg: 0 },
        ],
        2,
        "pending_await_fulfillment_label_join",
    );
    let mut core = test_interpreter();
    install_async_label_test_closure(&mut core);
    let awaited = core.promise_store.create();
    core.write_reg_with_label(10, Value::Promise(awaited.0), Label::Confidential)
        .expect("awaited handle should be writable");
    core.write_reg_with_label(11, Value::str("preserved-local"), Label::Internal)
        .expect("unrelated local should be writable");

    core.execute(&module).expect("pending await should suspend");
    let async_result = async_label_test_result_handle(&core);
    let suspended = &core.async_functions[0];
    assert_eq!(
        suspended.saved_registers.len(),
        suspended.saved_register_labels.len(),
        "value and label snapshots must remain parallel"
    );
    assert_eq!(suspended.saved_registers[1], Value::str("preserved-local"));
    assert_eq!(suspended.saved_register_labels[1], Label::Internal);

    core.fulfill_promise(awaited, crate::object_model::JsValue::Int(7), Label::Secret)
        .expect("awaited Promise should be fulfillable");
    core.drain_microtasks(Some(&module))
        .expect("pending fulfillment should resume");

    let record = core
        .promise_store
        .get(async_result)
        .expect("result Promise should exist");
    assert_eq!(record.label, Label::Secret);
    assert_eq!(
        record.state,
        crate::promise_model::PromiseState::Fulfilled(crate::object_model::JsValue::Int(7))
    );
    assert!(core.async_functions[0].saved_registers.is_empty());
    assert!(core.async_functions[0].saved_register_labels.is_empty());
}

/// A pending await saves the live prefix of its register window, through
/// its last live register, not the whole `max_registers` window; resume
/// puts the prefix back and clears the rest of the window, as the frame
/// had it (bd-9vouw.167).
#[test]
fn pending_await_saves_the_live_register_prefix_bd_9vouw_167() {
    let mut instructions = vec![
        Ir3Instruction::Call {
            callee: 3,
            args: RegRange {
                start: 10,
                count: 2,
            },
            dst: 1,
        },
        Ir3Instruction::Halt,
    ];
    instructions.extend([
        Ir3Instruction::Move { dst: 40, src: 1 },
        Ir3Instruction::AwaitValue { promise_reg: 0 },
        Ir3Instruction::AsyncReturn { value_reg: 40 },
    ]);
    let module = test_module_with_functions(
        instructions,
        vec![Ir3FunctionDesc {
            entry: 2,
            arity: 2,
            frame_size: 64,
            name: Some("pending_await_live_prefix".to_string()),
            is_generator: false,
            rest_param_index: None,
        }],
    );
    let mut core = test_interpreter();
    install_async_label_test_closure(&mut core);
    let awaited = core.promise_store.create();
    core.write_reg_with_label(10, Value::Promise(awaited.0), Label::Public)
        .expect("awaited handle should be writable");
    core.write_reg_with_label(11, Value::str("kept-local"), Label::Internal)
        .expect("local should be writable");

    core.execute(&module).expect("pending await should suspend");
    let async_result = async_label_test_result_handle(&core);
    let suspended = &core.async_functions[0];
    // r40 is the last live register: the prefix is r0..=r40.
    assert_eq!(suspended.saved_registers.len(), 41);
    assert_eq!(suspended.saved_register_labels.len(), 41);
    assert!(41 < core.config.max_registers as usize);
    assert_eq!(suspended.saved_registers[40], Value::str("kept-local"));
    assert_eq!(suspended.saved_register_labels[40], Label::Internal);
    // No estimate check here: this hand-built program's estimate is 208
    // bytes below the walk after it parks, on main's code before this
    // change too (bd-9vouw.173). The accounting of this change is checked
    // on lowered programs by a_pending_async_call_holds_its_live_registers.

    core.fulfill_promise(awaited, crate::object_model::JsValue::Int(7), Label::Public)
        .expect("awaited Promise should be fulfillable");
    core.drain_microtasks(Some(&module))
        .expect("pending fulfillment should resume");
    let record = core
        .promise_store
        .get(async_result)
        .expect("result Promise should exist");
    assert_eq!(
        record.state,
        crate::promise_model::PromiseState::Fulfilled(crate::object_model::JsValue::Str(
            "kept-local".into()
        ))
    );
    assert!(core.async_functions[0].saved_registers.is_empty());
}

#[test]
fn async_pending_rejection_joins_handle_and_settlement_labels_bd_ur3tk_18() {
    let module = async_label_test_module(
        Ir3Instruction::Call {
            callee: 3,
            args: RegRange {
                start: 10,
                count: 1,
            },
            dst: 1,
        },
        vec![
            Ir3Instruction::AwaitValue { promise_reg: 0 },
            Ir3Instruction::AsyncReturn { value_reg: 0 },
        ],
        1,
        "pending_await_rejection_label_join",
    );
    let mut core = test_interpreter();
    install_async_label_test_closure(&mut core);
    let awaited = core.promise_store.create();
    core.write_reg_with_label(10, Value::Promise(awaited.0), Label::Confidential)
        .expect("awaited handle should be writable");

    core.execute(&module).expect("pending await should suspend");
    let async_result = async_label_test_result_handle(&core);
    core.reject_promise(
        awaited,
        crate::object_model::JsValue::Str("secret-reason".to_string()),
        Label::Secret,
    )
    .expect("awaited Promise should be rejectable");
    core.drain_microtasks(Some(&module))
        .expect("pending rejection should resume");

    let record = core
        .promise_store
        .get(async_result)
        .expect("result Promise should exist");
    assert_eq!(record.label, Label::Secret);
    assert!(matches!(
        &record.state,
        crate::promise_model::PromiseState::Rejected(
            crate::object_model::JsValue::Str(value)
        ) if value == "secret-reason"
    ));
}

/// bd-n2mjy: a HostCall whose arg register carries a Secret label must
/// re-stamp the dst register's label with the join of the arg labels, so
/// information flowing INTO the hostcall taints its return value.
/// Previously `write_reg(dst, result)` left `register_labels[dst]`
/// whatever it was before — an under-tainting hole on every hostcall.
#[test]
fn hostcall_propagates_arg_label_join_to_dst() {
    let module = test_module_with_functions(
        vec![
            Ir3Instruction::HostCall {
                capability: CapabilityTag("promise:resolve".to_string()),
                args: RegRange { start: 0, count: 1 },
                dst: 1,
            },
            Ir3Instruction::Halt,
        ],
        vec![],
    );

    let mut core = test_interpreter();
    core.mutate_registers(|r| {
        r[0] = Value::Int(42);
    });
    core.set_register_label(0, crate::ifc_artifacts::Label::Secret)
        .expect("arg label should be settable");
    // Seed dst with a label strictly below Secret to prove the helper
    // overwrites it. If propagation were a no-op the dst label would
    // stay `Public` after dispatch (the bug bd-n2mjy describes).
    core.set_register_label(1, crate::ifc_artifacts::Label::Public)
        .expect("dst label should be settable");

    core.execute(&module)
        .expect("promise:resolve hostcall should dispatch");

    assert_eq!(
        core.get_register_label(1)
            .expect("dst register label should exist"),
        &crate::ifc_artifacts::Label::Secret,
        "hostcall dst register must inherit join(args' labels)"
    );
}

/// An explicitly label-preserving HostCall with zero operands resets stale
/// destination provenance to `Public`. Source-producing capabilities use
/// their own contract floor instead (bd-z1peg).
#[test]
fn label_preserving_hostcall_with_zero_args_resets_dst_to_public() {
    let module = test_module_with_functions(
        vec![
            Ir3Instruction::HostCall {
                capability: CapabilityTag("promise:resolve".to_string()),
                args: RegRange { start: 0, count: 0 },
                dst: 1,
            },
            Ir3Instruction::Halt,
        ],
        vec![],
    );

    let mut core = test_interpreter();
    // Prior content of dst was Confidential. promise:resolve is an exact
    // operand-preserving route, so an empty operand set is Public.
    core.set_register_label(1, crate::ifc_artifacts::Label::Confidential)
        .expect("dst label should be settable");

    core.execute(&module)
        .expect("zero-arg promise:resolve hostcall should dispatch");

    assert_eq!(
        core.get_register_label(1)
            .expect("dst register label should exist"),
        &crate::ifc_artifacts::Label::Public,
        "zero-arg label-preserving result must reset to Public"
    );
}

#[test]
fn unmatched_engine_local_hostcall_families_return_undefined_bd_z1peg() {
    let mut core = test_interpreter();
    let no_args = RegRange { start: 0, count: 0 };

    assert_eq!(
            core.dispatch_builtin_hostcall_inner(
                "builtin:FutureDeterministicOperation",
                no_args,
                None,
            )
            .expect("unknown builtin family route"),
            Value::Undefined
        );
    assert_eq!(
        core.dispatch_number_hostcall_inner("number:future-deterministic-operation", no_args,)
            .expect("unknown number family route"),
        Value::Undefined
    );
    assert_eq!(
        core.dispatch_console_hostcall_inner("console:future-acknowledgement", no_args, None)
            .expect("unknown console family route"),
        Value::Undefined
    );
    assert_eq!(
        core.dispatch_timer_hostcall_inner("timer:future-local-handle", no_args)
            .expect("unknown timer family route"),
        Value::Undefined
    );
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes(),
        "unmatched engine-local routes must not retain hidden state"
    );
}

#[test]
fn zero_argument_entropy_hostcall_result_is_secret_bd_z1peg() {
    use frankenengine_extension_host::host_io::{
        FsMetaResult, HostIoCapability, HostIoError, HostIoOutcome, HostIoRequest, HostIoResponse,
    };

    #[derive(Debug)]
    struct DeterministicEntropy;

    impl HostIoProvider for DeterministicEntropy {
        fn name(&self) -> &str {
            "bd-z1peg-deterministic-entropy"
        }

        fn perform(&self, request: &HostIoRequest, _granted: &[HostIoCapability]) -> HostIoOutcome {
            match request {
                HostIoRequest::RandomRead { byte_len } => Ok(HostIoResponse::RandomRead {
                    bytes: (0..*byte_len).map(|index| index as u8).collect(),
                }),
                HostIoRequest::FsRead { .. } => Ok(HostIoResponse::FsRead { bytes: Vec::new() }),
                HostIoRequest::FsWrite { .. } => Ok(HostIoResponse::FsWrite { bytes_written: 0 }),
                HostIoRequest::FsMeta { .. } => Ok(HostIoResponse::FsMeta {
                    result: FsMetaResult::Unit,
                }),
                HostIoRequest::NetworkSend { .. }
                | HostIoRequest::NetworkRecv { .. }
                | HostIoRequest::NetworkRequest { .. }
                | HostIoRequest::EnvRead { .. } => Err(HostIoError::Denied {
                    reason: "network and environment are outside the entropy fixture".to_string(),
                }),
            }
        }
    }

    let module = test_module_with_functions(
        vec![
            Ir3Instruction::HostCall {
                capability: CapabilityTag("builtin:CryptoRandomUUID".to_string()),
                args: RegRange { start: 0, count: 0 },
                dst: 1,
            },
            Ir3Instruction::Halt,
        ],
        Vec::new(),
    );
    let mut core = test_interpreter();
    core.config
        .granted_capabilities
        .insert(RuntimeCapability::RandomRead);
    core.set_host_io(Arc::new(DeterministicEntropy), None);
    core.set_register_label(1, Label::Public)
        .expect("destination label seed");

    core.execute(&module)
        .expect("zero-argument randomUUID should dispatch");

    assert!(matches!(core.read_reg(1), Ok(Value::Str(value)) if value.len() == 36));
    assert_eq!(
        core.get_register_label(1).expect("randomUUID result label"),
        &Label::Secret
    );
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );

    // The outer HostCall destination is not the only entropy-bearing
    // surface. Deferred callbacks must execute under the source floor,
    // and randomBytes must retain that floor on its Buffer backing.
    let mut bytes_core = test_interpreter();
    bytes_core
        .config
        .granted_capabilities
        .insert(RuntimeCapability::RandomRead);
    bytes_core.set_host_io(Arc::new(DeterministicEntropy), None);
    bytes_core
        .write_reg_with_label(4, Value::Int(4), Label::Public)
        .expect("randomBytes size");
    bytes_core
        .write_reg_with_label(5, Value::Closure(77), Label::Public)
        .expect("randomBytes callback");
    assert_eq!(
        bytes_core
            .crypto_random_bytes(RegRange { start: 4, count: 2 })
            .expect("callback randomBytes"),
        Value::Undefined
    );
    assert_eq!(bytes_core.pending_hostcall_result_label, None);
    assert_eq!(
        bytes_core.estimated_memory_bytes(),
        bytes_core.recompute_estimated_memory_bytes()
    );
    let bytes_task = bytes_core
        .event_loop
        .turn()
        .macrotask
        .expect("randomBytes callback task");
    assert_eq!(bytes_task.label, Label::Secret);
    let bytes_args = bytes_core
        .pending_io_callbacks
        .get(&bytes_task.registration_seq)
        .expect("randomBytes callback arguments");
    let Some(Value::Object(bytes_buffer)) = bytes_args.get(1) else {
        panic!("randomBytes callback must receive a Buffer")
    };
    assert_eq!(
        bytes_core.binary_storage_label(*bytes_buffer),
        Label::Secret
    );

    // Use a separate core because manually dequeuing the callback task is
    // an inspection seam, not the normal interpreter callback-drain path.
    // This keeps that probe from contaminating the randomInt accounting.
    let mut int_core = test_interpreter();
    int_core
        .config
        .granted_capabilities
        .insert(RuntimeCapability::RandomRead);
    int_core.set_host_io(Arc::new(DeterministicEntropy), None);
    int_core
        .write_reg_with_label(6, Value::Int(3), Label::Public)
        .expect("randomInt bound");
    int_core
        .write_reg_with_label(7, Value::Closure(78), Label::Public)
        .expect("randomInt callback");
    assert_eq!(
        int_core
            .crypto_random_int(RegRange { start: 6, count: 2 })
            .expect("callback randomInt"),
        Value::Undefined
    );
    assert_eq!(int_core.pending_hostcall_result_label, None);
    assert_eq!(
        int_core.estimated_memory_bytes(),
        int_core.recompute_estimated_memory_bytes()
    );
    let int_task = int_core
        .event_loop
        .turn()
        .macrotask
        .expect("randomInt callback task");
    assert_eq!(int_task.label, Label::Secret);

    // The synchronous form returns the sampled value through the HostCall
    // destination rather than a callback. Freeze the deterministic sample
    // and its source floor here so the public integration test does
    // not need to leak entropy through console merely to inspect shape.
    let mut sync_int_core = test_interpreter();
    sync_int_core
        .config
        .granted_capabilities
        .insert(RuntimeCapability::RandomRead);
    sync_int_core.set_host_io(Arc::new(DeterministicEntropy), None);
    sync_int_core
        .write_reg_with_label(6, Value::Int(10), Label::Public)
        .expect("synchronous randomInt bound");
    assert_eq!(
        sync_int_core
            .crypto_random_int(RegRange { start: 6, count: 1 })
            .expect("synchronous randomInt"),
        Value::Int(5)
    );
    assert_eq!(
        sync_int_core.take_pending_hostcall_result_label(),
        Some(Label::Secret)
    );
    assert_eq!(
        sync_int_core.estimated_memory_bytes(),
        sync_int_core.recompute_estimated_memory_bytes()
    );

    // randomFillSync mutates an existing Buffer. Both the returned alias
    // and the backing storage must retain the entropy source floor.
    let mut fill_core = test_interpreter();
    fill_core
        .config
        .granted_capabilities
        .insert(RuntimeCapability::RandomRead);
    fill_core.set_host_io(Arc::new(DeterministicEntropy), None);
    let fill_buffer = fill_core
        .alloc_buffer_from_bytes(&[0; 4])
        .expect("randomFillSync Buffer");
    fill_core
        .write_reg_with_label(8, Value::Object(fill_buffer), Label::Public)
        .expect("randomFillSync target");
    assert_eq!(
        fill_core
            .crypto_random_fill_sync(RegRange { start: 8, count: 1 })
            .expect("randomFillSync"),
        Value::Object(fill_buffer)
    );
    assert_eq!(fill_core.binary_storage_label(fill_buffer), Label::Secret);
    assert_eq!(
        fill_core.take_pending_hostcall_result_label(),
        Some(Label::Secret)
    );
    assert_eq!(
        fill_core.estimated_memory_bytes(),
        fill_core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn pending_child_process_wait_retains_its_payload_charge() {
    let mut core = test_interpreter();
    let before = core.estimated_memory_bytes();
    core.schedule_child_process_wait(PendingChildProcessTask {
        child: ObjectId(0),
        handle: "charged-process-wait".to_string(),
        callback: Some(46),
        callback_label: Label::Secret,
        callback_encoding: Some("utf8".to_string()),
        options: ProcessCallOptions::default(),
    })
    .expect("pending process wait must fit the ordinary budget");

    assert_eq!(core.pending_child_process_tasks.len(), 1);
    assert_eq!(
        core.pending_child_process_tasks
            .values()
            .next()
            .expect("retained process wait")
            .callback_label,
        Label::Secret
    );
    assert!(core.event_loop.has_pending_work());
    assert!(core.estimated_memory_bytes() > before);
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn pending_child_process_wait_budget_refusals_preserve_memory_and_queue() {
    for (refuse_task_payload, existing_task) in
        [(true, false), (false, false), (true, true), (false, true)]
    {
        let mut core = test_interpreter();
        let existing_sequence = if existing_task {
            let previous_promise_bytes = core.promise_runtime_memory_bytes();
            let sequence = core
                .event_loop
                .schedule_io_completion(crate::closure_model::ClosureHandle(47), Label::Internal);
            core.apply_promise_runtime_memory_delta(previous_promise_bytes)
                .expect("unrelated callback fixture must fit");
            Some(sequence)
        } else {
            None
        };
        let task = PendingChildProcessTask {
            child: ObjectId(0),
            handle: "refused-process-wait".to_string(),
            callback: Some(46),
            callback_label: Label::Secret,
            callback_encoding: Some("utf8".to_string()),
            options: ProcessCallOptions::default(),
        };
        let before = core.estimated_memory_bytes();
        let retained_bytes = InterpreterCore::pending_child_process_task_bytes(&task);
        assert!(retained_bytes > 0);
        // First refuse the task itself. Then admit exactly that payload,
        // forcing the event-loop allocation to exercise charge rollback.
        let limit = if refuse_task_payload {
            before + retained_bytes - 1
        } else {
            before + retained_bytes
        };
        core.config.max_total_memory_bytes = limit;
        let result = core.schedule_child_process_wait(task);
        assert!(
            matches!(
                &result,
                Err(InterpreterError::MemoryBudgetExceeded {
                    requested_bytes,
                    max_bytes,
                    ..
                }) if requested_bytes > max_bytes && *max_bytes == limit
            ),
            "refuse_task_payload={refuse_task_payload}: {result:?}"
        );
        assert!(core.pending_child_process_tasks.is_empty());
        assert_eq!(core.event_loop.has_pending_work(), existing_task);
        assert_eq!(core.estimated_memory_bytes(), before);
        assert_eq!(core.recompute_estimated_memory_bytes(), before);
        if let Some(sequence) = existing_sequence {
            let preserved = core
                .event_loop
                .turn()
                .macrotask
                .expect("unrelated callback must survive refusal");
            assert_eq!(preserved.registration_seq, sequence);
            assert_eq!(preserved.handler, crate::closure_model::ClosureHandle(47));
            assert_eq!(preserved.label, Label::Internal);
            assert!(!core.event_loop.has_pending_work());
        }
    }
}

#[test]
fn external_source_callbacks_and_backings_keep_contract_floors_bd_z1peg() {
    use frankenengine_extension_host::host_io::{
        FsMetaResult, HostIoCapability, HostIoOutcome, HostIoRequest, HostIoResponse,
    };

    #[derive(Debug)]
    struct SuccessfulUnknownFs;

    impl HostIoProvider for SuccessfulUnknownFs {
        fn name(&self) -> &str {
            "bd-z1peg-successful-unknown-fs"
        }

        fn perform(&self, request: &HostIoRequest, _granted: &[HostIoCapability]) -> HostIoOutcome {
            match request {
                HostIoRequest::FsRead { .. } => Ok(HostIoResponse::FsRead {
                    bytes: b"host bytes".to_vec(),
                }),
                HostIoRequest::FsWrite { data, .. } => Ok(HostIoResponse::FsWrite {
                    bytes_written: data.len() as u64,
                }),
                HostIoRequest::FsMeta { .. } => Ok(HostIoResponse::FsMeta {
                    result: FsMetaResult::Unit,
                }),
                HostIoRequest::RandomRead { byte_len } => Ok(HostIoResponse::RandomRead {
                    bytes: vec![0; *byte_len as usize],
                }),
                HostIoRequest::NetworkSend { payload, .. } => Ok(HostIoResponse::NetworkSend {
                    bytes_sent: payload.len() as u64,
                }),
                HostIoRequest::NetworkRecv { .. } => {
                    Ok(HostIoResponse::NetworkRecv { bytes: Vec::new() })
                }
                HostIoRequest::NetworkRequest { .. } => Ok(HostIoResponse::NetworkRequest {
                    response: Vec::new(),
                }),
                HostIoRequest::EnvRead { .. } => Err(HostIoError::Denied {
                    reason: "environment is outside the filesystem fixture".to_string(),
                }),
            }
        }
    }

    // A successful read from a provider with fail-high exception
    // provenance is still an Internal result, not a TopSecret exception.
    let mut read_core = test_interpreter();
    read_core.set_host_io(Arc::new(SuccessfulUnknownFs), None);
    read_core
        .write_reg_with_label(0, Value::str("read.txt"), Label::Public)
        .expect("read path");
    read_core
        .write_reg_with_label(1, Value::Closure(41), Label::Public)
        .expect("read callback");
    assert_eq!(
        read_core
            .dispatch_host_io_hostcall("fs:read", RegRange { start: 0, count: 2 })
            .expect("successful asynchronous fs read"),
        Value::Undefined
    );
    assert_eq!(
        read_core.estimated_memory_bytes(),
        read_core.recompute_estimated_memory_bytes()
    );
    let read_task = read_core
        .event_loop
        .turn()
        .macrotask
        .expect("fs read callback task");
    assert_eq!(read_task.label, Label::Internal);
    let read_args = read_core
        .pending_io_callbacks
        .get(&read_task.registration_seq)
        .expect("fs read callback arguments");
    let Some(Value::Object(read_buffer)) = read_args.get(1) else {
        panic!("fs read callback must receive a Buffer")
    };
    assert_eq!(
        read_core.binary_storage_label(*read_buffer),
        Label::Internal
    );

    // A write acknowledgement introduces no host source above its inputs.
    let mut write_core = test_interpreter();
    write_core.set_host_io(Arc::new(SuccessfulUnknownFs), None);
    write_core
        .write_reg_with_label(0, Value::str("write.txt"), Label::Public)
        .expect("write path");
    write_core
        .write_reg_with_label(1, Value::str("classified"), Label::Secret)
        .expect("write content");
    write_core
        .write_reg_with_label(2, Value::Closure(42), Label::Public)
        .expect("write callback");
    assert_eq!(
        write_core
            .dispatch_host_io_hostcall("fs:write", RegRange { start: 0, count: 3 })
            .expect("successful asynchronous fs write"),
        Value::Undefined
    );
    assert_eq!(
        write_core.estimated_memory_bytes(),
        write_core.recompute_estimated_memory_bytes()
    );
    let write_task = write_core
        .event_loop
        .turn()
        .macrotask
        .expect("fs write callback task");
    assert_eq!(write_task.label, Label::Secret);

    // Process-provider outputs have an Internal floor on callback context,
    // stream events, and any returned Buffer backing.
    let mut process_core = test_interpreter();
    process_core
        .schedule_child_process_callback(43, Vec::new(), &Label::Public)
        .expect("process callback scheduling");
    process_core
        .schedule_child_process_callback(44, Vec::new(), &Label::Secret)
        .expect("classified process callback scheduling");
    assert_eq!(
        process_core.estimated_memory_bytes(),
        process_core.recompute_estimated_memory_bytes()
    );
    let process_task = process_core
        .event_loop
        .turn()
        .macrotask
        .expect("process callback task");
    assert_eq!(process_task.label, Label::Internal);
    let classified_process_task = process_core
        .event_loop
        .turn()
        .macrotask
        .expect("classified process callback task");
    assert_eq!(classified_process_task.label, Label::Secret);

    #[derive(Debug)]
    struct DenyingLifecycleProcess {
        seen: Arc<std::sync::atomic::AtomicBool>,
    }

    impl ProcessSpawnProvider for DenyingLifecycleProcess {
        fn name(&self) -> &str {
            "bd-z1peg-lifecycle-process"
        }

        fn preflight_request(
            &self,
            request: &ProcessSpawnRequest,
        ) -> Result<(), ProcessSpawnError> {
            assert!(matches!(request, ProcessSpawnRequest::Spawn { .. }));
            self.seen.store(true, std::sync::atomic::Ordering::SeqCst);
            Err(ProcessSpawnError::Denied {
                reason: "deliberate callback-provenance fixture denial".to_string(),
            })
        }

        fn perform(
            &self,
            _request: &ProcessSpawnRequest,
            _granted: &[frankenengine_extension_host::process_spawn::ProcessSpawnCapability],
        ) -> Result<ProcessSpawnResponse, ProcessSpawnError> {
            panic!("preflight denial must prevent live process dispatch")
        }

        fn cleanup_handle(&self, _handle: &str) -> Result<ProcessSpawnResponse, ProcessSpawnError> {
            Ok(ProcessSpawnResponse::Cleaned { was_present: false })
        }
    }

    let mut callback_registration_core = test_interpreter();
    let provider_seen = Arc::new(std::sync::atomic::AtomicBool::new(false));
    callback_registration_core.set_process_spawn(
        Arc::new(DenyingLifecycleProcess {
            seen: provider_seen.clone(),
        }),
        Arc::new(InMemoryHostEffectJournal::recording()),
    );
    callback_registration_core
        .write_reg_with_label(0, Value::str("\0processop:exec"), Label::Public)
        .expect("process operation");
    callback_registration_core
        .write_reg_with_label(1, Value::str("public-command"), Label::Public)
        .expect("public process command");
    callback_registration_core
        .write_reg_with_label(2, Value::Closure(45), Label::Secret)
        .expect("classified process callback");
    assert!(matches!(
        callback_registration_core
            .dispatch_process_spawn_hostcall(RegRange { start: 0, count: 3 })
            .expect("Public request with classified callback remains admissible"),
        Value::Object(_)
    ));
    assert!(
        provider_seen.load(std::sync::atomic::Ordering::SeqCst),
        "the Secret callback must stay outside Public provider preflight admission"
    );
    let mut denied_callback_label = None;
    for _ in 0..4 {
        let Some(macrotask) = callback_registration_core.event_loop.turn().macrotask else {
            break;
        };
        if macrotask.handler == crate::closure_model::ClosureHandle(45) {
            denied_callback_label = Some(macrotask.label);
            break;
        }
    }
    assert_eq!(
        denied_callback_label,
        Some(Label::Secret),
        "provider-denial callback must retain its independent registration label"
    );

    let mut retained_callback_core = test_interpreter();
    retained_callback_core
        .schedule_child_process_wait(PendingChildProcessTask {
            child: ObjectId(0),
            handle: "bd-z1peg-pending".to_string(),
            callback: Some(46),
            callback_label: Label::Secret,
            callback_encoding: Some("utf8".to_string()),
            options: ProcessCallOptions::default(),
        })
        .expect("retain classified callback across lifecycle wait");
    let retained_callback_label = &retained_callback_core
        .pending_child_process_tasks
        .values()
        .next()
        .expect("pending process wait")
        .callback_label;
    assert_eq!(
        retained_callback_label,
        &Label::Secret,
        "callback registration provenance must not enter egress admission or disappear"
    );
    assert_eq!(
        retained_callback_core.estimated_memory_bytes(),
        retained_callback_core.recompute_estimated_memory_bytes()
    );

    let mut event_core = test_interpreter();
    let child = event_core
        .allocate_child_process_facade(&ProcessCallOptions::default())
        .expect("child process facade");
    event_core
        .settle_child_process(
            child,
            Ok((
                ProcessExit {
                    success: true,
                    code: Some(0),
                    signal: None,
                },
                b"stdout".to_vec(),
                Vec::new(),
            )),
        )
        .expect("settled process output");
    let stdout_stream = match event_core.heap[child.0 as usize].properties.get("stdout") {
        Some(Value::Object(stream)) => *stream,
        other => panic!("child stdout stream is missing: {other:?}"),
    };
    let sequence = event_core
        .activate_completed_child_process_event(stdout_stream, "data")
        .expect("process data event scheduling")
        .expect("process data event must exist");
    let PendingHttpTask::EmitLegacyEvent {
        arguments, label, ..
    } = event_core
        .pending_http_tasks
        .get(&sequence)
        .expect("process data event task")
    else {
        panic!("process data event must use the legacy event task")
    };
    assert_eq!(label, &Label::Internal);
    let Some(Value::Object(stdout_buffer)) = arguments.first() else {
        panic!("process data event must carry a Buffer")
    };
    assert_eq!(
        event_core.binary_storage_label(*stdout_buffer),
        Label::Internal
    );
    assert_eq!(
        event_core.estimated_memory_bytes(),
        event_core.recompute_estimated_memory_bytes()
    );
}

fn fs_promise_read_test_core(
    outcome: HostIoOutcome,
) -> (InterpreterCore, Arc<std::sync::atomic::AtomicUsize>) {
    #[derive(Debug)]
    struct ReadProvider {
        outcome: HostIoOutcome,
        calls: Arc<std::sync::atomic::AtomicUsize>,
    }
    impl HostIoProvider for ReadProvider {
        fn name(&self) -> &str {
            "fs-promise-native-read-test"
        }
        fn perform(
            &self,
            request: &HostIoRequest,
            _granted: &[frankenengine_extension_host::host_io::HostIoCapability],
        ) -> HostIoOutcome {
            assert!(matches!(request, HostIoRequest::FsRead { .. }));
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.outcome.clone()
        }
    }
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut core = test_interpreter();
    core.config
        .granted_capabilities
        .insert(RuntimeCapability::FsRead);
    core.set_host_io(
        Arc::new(ReadProvider {
            outcome,
            calls: calls.clone(),
        }),
        None,
    );
    for (register, value) in [
        (0, Value::str("\0fsop:read")),
        (1, Value::str("input.txt")),
        (2, Value::str("utf8")),
    ] {
        core.write_reg_with_label(register, value, Label::Public)
            .unwrap();
    }
    (core, calls)
}

#[test]
fn fs_promise_native_completion_preserves_labels_and_collection_roots() {
    use crate::promise_model::{PromiseHandle, PromiseState};
    use frankenengine_extension_host::host_io::HostIoResponse;
    let module = test_module_with_functions(Vec::new(), Vec::new());
    for (encoding, outcome, label, rejected) in [
        (
            Value::str("utf8"),
            Ok(HostIoResponse::FsRead {
                bytes: b"native bytes".to_vec(),
            }),
            Label::Internal,
            false,
        ),
        (
            Value::Undefined,
            Ok(HostIoResponse::FsRead {
                bytes: b"native bytes".to_vec(),
            }),
            Label::Internal,
            false,
        ),
        (
            Value::str("utf8"),
            Err(HostIoError::Fs {
                code: "ENOENT".into(),
                detail: "unknown provider path".into(),
            }),
            Label::TopSecret,
            true,
        ),
    ] {
        let (mut core, calls) = fs_promise_read_test_core(outcome);
        core.write_reg_with_label(2, encoding, Label::Public)
            .unwrap();
        let Value::Promise(handle) = core
            .dispatch_fs_promise_read(RegRange { start: 0, count: 3 })
            .unwrap()
        else {
            panic!("read must return its native Promise");
        };
        let handle = PromiseHandle(handle);
        assert_eq!(
            core.promise_store.get(handle).unwrap().state,
            PromiseState::Pending
        );
        assert_eq!(core.pending_fs_promise_reads.len(), 1);
        assert_eq!(
            core.take_pending_hostcall_result_label(),
            Some(label.clone())
        );
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        // Neither the returned Promise nor the decoded Buffer/Error is in
        // a guest register. The pending completion is their sole root.
        core.set_gc_stress_interval(Some(1));
        core.gc_arm_event_loop(None);
        core.gc_event_loop_safe_point();
        core.gc_disarm_event_loop();
        assert!(core.gc_stats().collections > 0);
        assert_eq!(
            core.promise_store.get(handle).unwrap().state,
            PromiseState::Pending
        );
        let retained = core.pending_fs_promise_reads.values().next().unwrap();
        if let Ok(Value::Object(buffer)) = &retained.outcome {
            assert_eq!(core.binary_storage_label(*buffer), Label::Internal);
        }
        let previous = core.promise_runtime_memory_bytes();
        let task = core.event_loop.turn().macrotask.expect("I/O completion");
        core.apply_promise_runtime_memory_delta(previous).unwrap();
        assert_eq!(
            task.source,
            crate::promise_model::MacrotaskSource::IoCompletion
        );
        assert_eq!(task.label, label);
        core.execute_macrotask_callback(&task, Some(&module))
            .unwrap();
        assert!(core.pending_fs_promise_reads.is_empty());
        let record = core.promise_store.get(handle).unwrap();
        assert_eq!(record.label, label);
        assert_eq!(matches!(record.state, PromiseState::Rejected(_)), rejected);
        assert_eq!(
            matches!(record.state, PromiseState::Fulfilled(_)),
            !rejected
        );
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }
}

#[test]
fn fs_promise_native_validation_rejects_before_io_and_missing_provider_stays_pending() {
    use crate::promise_model::{PromiseHandle, PromiseState};
    use frankenengine_extension_host::host_io::HostIoResponse;
    for (register, value) in [(1, Value::Null), (2, Value::str("invalid-encoding"))] {
        let (mut core, calls) =
            fs_promise_read_test_core(Ok(HostIoResponse::FsRead { bytes: vec![] }));
        core.write_reg_with_label(register, value, Label::Public)
            .unwrap();
        let Value::Promise(handle) = core
            .dispatch_fs_promise_read(RegRange { start: 0, count: 3 })
            .unwrap()
        else {
            panic!("invalid arguments reject a Promise");
        };
        let record = core.promise_store.get(PromiseHandle(handle)).unwrap();
        assert!(matches!(record.state, PromiseState::Rejected(_)));
        assert_eq!(record.label, Label::Internal);
        assert!(core.pending_fs_promise_reads.is_empty());
        assert!(!core.event_loop.has_pending_work());
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }
    let (mut core, calls) = fs_promise_read_test_core(Ok(HostIoResponse::FsRead { bytes: vec![] }));
    core.host_io = None;
    let Value::Promise(handle) = core
        .dispatch_fs_promise_read(RegRange { start: 0, count: 3 })
        .unwrap()
    else {
        panic!("missing provider still returns a Promise");
    };
    assert_eq!(
        core.promise_store.get(PromiseHandle(handle)).unwrap().state,
        PromiseState::Pending
    );
    assert!(core.pending_fs_promise_reads.is_empty());
    assert!(!core.event_loop.has_pending_work());
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn fs_promise_native_route_cannot_smuggle_operations_or_classified_paths() {
    use frankenengine_extension_host::host_io::HostIoResponse;
    for operation in ["\0fsop:write", "\0fsop:open", "\0fsop:stat", "input.txt"] {
        let (mut core, calls) =
            fs_promise_read_test_core(Ok(HostIoResponse::FsRead { bytes: vec![] }));
        core.write_reg_with_label(0, Value::str(operation), Label::Public)
            .unwrap();
        let before = core.promise_store.len();
        assert!(matches!(
            core.dispatch_fs_promise_read(RegRange { start: 0, count: 3 }),
            Err(InterpreterError::CapabilityDenied { .. })
        ));
        assert_eq!(core.promise_store.len(), before);
        assert!(core.pending_fs_promise_reads.is_empty());
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    }
    let (mut core, calls) = fs_promise_read_test_core(Ok(HostIoResponse::FsRead { bytes: vec![] }));
    core.write_reg_with_label(1, Value::str("classified-path"), Label::Secret)
        .unwrap();
    let before = core.promise_store.len();
    assert!(
        core.dispatch_fs_promise_read(RegRange { start: 0, count: 3 })
            .is_err()
    );
    assert_eq!(core.promise_store.len(), before);
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert!(core.pending_fs_promise_reads.is_empty());
    assert!(!core.event_loop.has_pending_work());
}

#[test]
fn fs_promise_native_fatal_errors_do_not_become_rejections() {
    let (mut core, calls) = fs_promise_read_test_core(Err(HostIoError::Denied {
        reason: "provider policy".into(),
    }));
    let before = core.promise_store.len();
    assert!(matches!(
        core.dispatch_fs_promise_read(RegRange { start: 0, count: 3 }),
        Err(InterpreterError::InternalError { .. })
    ));
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(core.promise_store.len(), before);
    assert!(core.pending_fs_promise_reads.is_empty());
    assert!(!core.event_loop.has_pending_work());
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn fs_promise_native_task_admission_preserves_unrelated_work() {
    for (refuse_payload, unrelated) in [(true, false), (false, false), (true, true), (false, true)]
    {
        let mut core = test_interpreter();
        let promise = core.create_promise().unwrap();
        let existing = if unrelated {
            let before = core.promise_runtime_memory_bytes();
            let seq = core
                .event_loop
                .schedule_io_completion(crate::closure_model::ClosureHandle(47), Label::Internal);
            core.apply_promise_runtime_memory_delta(before).unwrap();
            Some(seq)
        } else {
            None
        };
        let task = PendingFsPromiseRead {
            promise,
            outcome: Ok(Value::str("unpublished result")),
        };
        let before = core.estimated_memory_bytes();
        let retained = InterpreterCore::pending_fs_promise_read_bytes(&task);
        core.config.max_total_memory_bytes = before + retained - u64::from(refuse_payload);
        assert!(matches!(
            core.schedule_fs_promise_read(task, Label::Internal),
            Err(InterpreterError::MemoryBudgetExceeded { .. })
        ));
        assert!(core.pending_fs_promise_reads.is_empty());
        assert_eq!(core.event_loop.has_pending_work(), unrelated);
        assert_eq!(core.estimated_memory_bytes(), before);
        assert_eq!(core.recompute_estimated_memory_bytes(), before);
        assert!(!core.gc_network_task_active());
        if let Some(existing) = existing {
            let task = core.event_loop.turn().macrotask.unwrap();
            assert_eq!(task.registration_seq, existing);
            assert_eq!(task.handler, crate::closure_model::ClosureHandle(47));
        }
    }
}

#[test]
fn fs_promise_native_direct_and_delegated_dispatch_require_live_read_authority() {
    use crate::promise_model::{PromiseHandle, PromiseState};
    use frankenengine_extension_host::host_io::HostIoResponse;
    for (delegated, granted) in [(false, false), (false, true), (true, false), (true, true)] {
        let (mut core, calls) = fs_promise_read_test_core(Ok(HostIoResponse::FsRead {
            bytes: b"mediated".to_vec(),
        }));
        if !granted {
            core.config
                .granted_capabilities
                .remove(&RuntimeCapability::FsRead);
        }
        let tag = crate::capability::FS_READ_PROMISE_CAPABILITY;
        let (capability, args) = if delegated {
            core.config
                .granted_capabilities
                .insert(RuntimeCapability::Builtin);
            let arguments = core
                .alloc_array_from_values(&[
                    Value::str("\0fsop:read"),
                    Value::str("input.txt"),
                    Value::str("utf8"),
                ])
                .unwrap();
            core.write_reg_with_label(10, Value::str(tag), Label::Public)
                .unwrap();
            core.write_reg_with_label(11, Value::Object(arguments), Label::Public)
                .unwrap();
            (
                format!("builtin:ApplyHostCall:{tag}"),
                RegRange {
                    start: 10,
                    count: 2,
                },
            )
        } else {
            (tag.to_string(), RegRange { start: 0, count: 3 })
        };
        let module = test_module_with_functions(
            vec![
                Ir3Instruction::HostCall {
                    capability: CapabilityTag(capability),
                    args,
                    dst: 3,
                },
                Ir3Instruction::Halt,
            ],
            Vec::new(),
        );
        let result = core.execute(&module);
        if granted {
            result.unwrap_or_else(|error| panic!("delegated={delegated}: {error:?}"));
            let Value::Promise(handle) = core.read_reg(3).unwrap() else {
                panic!("returned Promise")
            };
            let record = core.promise_store.get(PromiseHandle(handle)).unwrap();
            assert_eq!(record.label, Label::Internal);
            assert!(
                matches!(&record.state, PromiseState::Fulfilled(crate::object_model::JsValue::Str(value)) if value == "mediated")
            );
        } else {
            assert!(
                matches!(result, Err(InterpreterError::CapabilityDenied { ref capability }) if capability == "fs:read"),
                "delegated={delegated}: {result:?}"
            );
        }
        assert_eq!(
            calls.load(std::sync::atomic::Ordering::SeqCst),
            usize::from(granted)
        );
        assert!(core.pending_fs_promise_reads.is_empty());
        assert!(!core.event_loop.has_pending_work());
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }
}

#[test]
fn fs_promise_native_direct_and_delegated_reads_preserve_exact_policy_hook_denials() {
    use frankenengine_extension_host::host_io::HostIoResponse;
    struct DenyFsReadHook(Arc<std::sync::atomic::AtomicUsize>);
    impl InterpreterHook for DenyFsReadHook {
        fn instruction_hooks_enabled(&self) -> bool {
            false
        }
        fn pre_property_access(
            &self,
            _ctx: &HookContext,
            _target: &ObjectRef,
            _key: &PropertyKey,
        ) -> HookAction {
            HookAction::Allow
        }
        fn pre_call(
            &self,
            _ctx: &HookContext,
            _callee: &FunctionRef,
            _args: &[Value],
        ) -> HookAction {
            HookAction::Allow
        }
        fn pre_allocation(
            &self,
            _ctx: &HookContext,
            _kind: AllocKind,
            _size_hint: usize,
        ) -> HookAction {
            HookAction::Allow
        }
        fn pre_import(&self, _ctx: &HookContext, _specifier: &str) -> HookAction {
            HookAction::Allow
        }
        fn pre_hostcall(&self, _ctx: &HookContext, capability: &str, allowed: bool) -> HookAction {
            assert_ne!(
                capability,
                crate::capability::FS_READ_PROMISE_CAPABILITY,
                "the completion adapter must not rename a policy-controlled read"
            );
            if capability == "fs:read" {
                assert!(
                    allowed,
                    "the live FsRead grant precedes the independent hook denial"
                );
                self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                HookAction::Terminate("filesystem read policy".into())
            } else {
                HookAction::Allow
            }
        }
    }
    for delegated in [false, true] {
        let (mut core, calls) = fs_promise_read_test_core(Ok(HostIoResponse::FsRead {
            bytes: b"must not be read".to_vec(),
        }));
        let seen = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        core.set_hook(Arc::new(DenyFsReadHook(seen.clone())));
        let tag = crate::capability::FS_READ_PROMISE_CAPABILITY;
        let (capability, args) = if delegated {
            core.config
                .granted_capabilities
                .insert(RuntimeCapability::Builtin);
            let arguments = core
                .alloc_array_from_values(&[
                    Value::str("\0fsop:read"),
                    Value::str("input.txt"),
                    Value::str("utf8"),
                ])
                .unwrap();
            core.write_reg_with_label(10, Value::str(tag), Label::Public)
                .unwrap();
            core.write_reg_with_label(11, Value::Object(arguments), Label::Public)
                .unwrap();
            (
                format!("builtin:ApplyHostCall:{tag}"),
                RegRange {
                    start: 10,
                    count: 2,
                },
            )
        } else {
            (tag.to_string(), RegRange { start: 0, count: 3 })
        };
        let module = test_module_with_functions(
            vec![
                Ir3Instruction::HostCall {
                    capability: CapabilityTag(capability),
                    args,
                    dst: 3,
                },
                Ir3Instruction::Halt,
            ],
            Vec::new(),
        );
        let before = core.promise_store.len();
        let result = core.execute(&module);
        assert!(
            matches!(result, Err(InterpreterError::ContainmentActionRequested { ref action, ref reason })
                if action == "terminate" && reason.as_deref() == Some("filesystem read policy")),
            "delegated={delegated}: {result:?}"
        );
        assert_eq!(seen.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert_eq!(core.promise_store.len(), before);
        assert!(core.pending_fs_promise_reads.is_empty());
        assert!(!core.event_loop.has_pending_work());
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }
}

#[test]
fn fs_promise_native_budget_refusals_leave_no_dangling_promise_or_job() {
    use frankenengine_extension_host::host_io::HostIoResponse;
    let fixture = || {
        fs_promise_read_test_core(Ok(HostIoResponse::FsRead {
            bytes: b"read bytes".to_vec(),
        }))
    };
    let mut ceiling = fixture().0.estimated_memory_bytes();
    let mut refused_after_effect = false;
    let mut admitted = false;
    for _ in 0..32 {
        let (mut core, calls) = fixture();
        core.config.max_total_memory_bytes = ceiling;
        let before = core.promise_store.len();
        match core.dispatch_fs_promise_read(RegRange { start: 0, count: 3 }) {
            Err(InterpreterError::MemoryBudgetExceeded {
                requested_bytes, ..
            }) => {
                assert!(requested_bytes > ceiling);
                refused_after_effect |= calls.load(std::sync::atomic::Ordering::SeqCst) != 0;
                assert_eq!(
                    core.promise_store.len(),
                    before,
                    "fresh Promise must roll back"
                );
                assert!(
                    core.pending_fs_promise_reads.is_empty(),
                    "failed dispatch leaves no pending owner"
                );
                assert!(
                    !core.event_loop.has_pending_work(),
                    "failed dispatch leaves no queued job"
                );
                assert_eq!(
                    core.estimated_memory_bytes(),
                    core.recompute_estimated_memory_bytes()
                );
                ceiling = requested_bytes;
            }
            Ok(Value::Promise(_)) => {
                assert_eq!(core.pending_fs_promise_reads.len(), 1);
                core.clear_residual_event_state().unwrap();
                assert!(core.pending_fs_promise_reads.is_empty());
                assert!(!core.event_loop.has_pending_work());
                assert_eq!(
                    core.estimated_memory_bytes(),
                    core.recompute_estimated_memory_bytes()
                );
                admitted = true;
                break;
            }
            other => panic!("unexpected read admission result: {other:?}"),
        }
    }
    assert!(
        refused_after_effect,
        "exercise task/return-label admission after the recorded read"
    );
    assert!(admitted, "the exact read/task budget must converge");
}

fn lower_module_graph_entry_bd_yn3lv(path: &Path, source: &str) -> Ir3Module {
    let label = path.display().to_string();
    let syntax_tree = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource {
                label: label.clone(),
                text: source.to_string(),
            },
            ParseGoal::Module,
            &ParserOptions::default(),
        )
        .expect("async module-graph entry should parse");
    lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(syntax_tree, &label),
        &LoweringContext::new("bd-yn3lv", "module-graph", "async-evaluation"),
    )
    .expect("async module-graph entry should lower")
    .ir3
}

fn async_module_graph_core_bd_yn3lv(root: &Path) -> InterpreterCore {
    let mut core = test_interpreter();
    core.config
        .set_module_root(root.display().to_string())
        .expect("set async module-graph root");
    core.config
        .granted_capabilities
        .insert(RuntimeCapability::ModuleLoad);
    core.config
        .granted_capabilities
        .insert(RuntimeCapability::Builtin);
    core.config
        .granted_capabilities
        .insert(RuntimeCapability::Console);
    core
}

#[test]
fn deferred_dynamic_imports_survive_collection_and_release_task_memory() {
    let root = tempfile::tempdir().expect("dynamic import GC root");
    let entry = root.path().join("entry.mjs");
    let source = "for (let i = 0; i < 8; i++) { import('./dep.mjs'); } console.log('scheduled');";
    std::fs::write(&entry, source).expect("entry source");
    std::fs::write(
        root.path().join("dep.mjs"),
        "const live = { answer: 42 }; console.log('dependency'); export { live };",
    )
    .expect("dependency source");
    let module = lower_module_graph_entry_bd_yn3lv(&entry, source);
    let mut core = async_module_graph_core_bd_yn3lv(root.path());
    core.set_gc_stress_interval(Some(1));
    for _ in 0..2 {
        let result = core
            .execute(&module)
            .expect("dropped import Promises stay rooted");
        assert_eq!(
            result
                .console_output
                .iter()
                .map(|line| line.message.as_str())
                .collect::<Vec<_>>(),
            ["scheduled", "dependency"]
        );
        assert!(core.gc_stats().collections > 0);
        assert!(core.pending_dynamic_imports.is_empty());
        assert_eq!(core.module_snapshot_in_flight_bytes, 0);
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }
}

#[test]
fn discarded_dynamic_import_jobs_release_queue_and_retained_memory() {
    let root = tempfile::tempdir().expect("discarded import root");
    let entry = root.path().join("entry.mjs");
    let source = "import('./dep.mjs'); console.log('scheduled');";
    std::fs::write(&entry, source).expect("entry source");
    std::fs::write(
        root.path().join("dep.mjs"),
        "throw new Error('discarded dependency must not evaluate');",
    )
    .expect("dependency source");
    let module = lower_module_graph_entry_bd_yn3lv(&entry, source);
    let mut core = async_module_graph_core_bd_yn3lv(root.path());
    core.prepare_execution(&module).expect("entry preparation");
    assert!(matches!(
        core.run_loop(&module),
        Ok(_) | Err(InterpreterError::Halted)
    ));
    assert_eq!(core.pending_dynamic_imports.len(), 1);
    assert!(core.event_loop.has_pending_work());
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
    core.clear_residual_event_state()
        .expect("discard queued import");
    assert!(core.pending_dynamic_imports.is_empty());
    assert!(!core.event_loop.has_pending_work());
    core.run_event_loop_until_idle_with_module(Some(&module))
        .expect("cancelled import cannot run");
    assert_eq!(
        core.console_output()
            .iter()
            .map(|line| line.message.as_str())
            .collect::<Vec<_>>(),
        ["scheduled"]
    );
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn queued_dynamic_import_rechecks_module_load_and_releases_failed_task_memory() {
    let root = tempfile::tempdir().expect("revoked import root");
    let entry = root.path().join("entry.mjs");
    let source = "import('./dep.mjs');";
    std::fs::write(&entry, source).expect("entry source");
    std::fs::write(
        root.path().join("dep.mjs"),
        "console.log('must not execute');",
    )
    .expect("dependency source");
    let module = lower_module_graph_entry_bd_yn3lv(&entry, source);
    let mut core = async_module_graph_core_bd_yn3lv(root.path());
    core.prepare_execution(&module).expect("entry preparation");
    assert!(matches!(
        core.run_loop(&module),
        Ok(_) | Err(InterpreterError::Halted)
    ));
    assert_eq!(core.pending_dynamic_imports.len(), 1);
    core.config
        .granted_capabilities
        .remove(&RuntimeCapability::ModuleLoad);
    assert!(matches!(
        core.run_event_loop_until_idle_with_module(Some(&module)),
        Err(InterpreterError::CapabilityDenied { capability }) if capability == "module_load"
    ));
    assert!(core.console_output().is_empty());
    assert!(core.pending_dynamic_imports.is_empty());
    assert_eq!(core.module_snapshot_in_flight_bytes, 0);
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn deferred_dynamic_import_rechecks_effect_only_hostcall_hooks() {
    struct RevokedImportHook;

    impl InterpreterHook for RevokedImportHook {
        fn instruction_hooks_enabled(&self) -> bool {
            false
        }

        fn pre_property_access(
            &self,
            _ctx: &HookContext,
            _target: &ObjectRef,
            _key: &PropertyKey,
        ) -> HookAction {
            HookAction::Allow
        }

        fn pre_call(
            &self,
            _ctx: &HookContext,
            _callee: &FunctionRef,
            _args: &[Value],
        ) -> HookAction {
            HookAction::Allow
        }

        fn pre_allocation(
            &self,
            _ctx: &HookContext,
            _kind: AllocKind,
            _size_hint: usize,
        ) -> HookAction {
            HookAction::Allow
        }

        fn pre_import(&self, _ctx: &HookContext, _specifier: &str) -> HookAction {
            HookAction::Allow
        }

        fn pre_hostcall(&self, _ctx: &HookContext, capability: &str, allowed: bool) -> HookAction {
            assert!(allowed);
            assert_eq!(capability, crate::capability::DYNAMIC_IMPORT_CAPABILITY);
            HookAction::Terminate("module effect revoked".to_string())
        }
    }

    let root = tempfile::tempdir().expect("revoked hostcall root");
    let entry = root.path().join("entry.mjs");
    let source = "import('./dep.mjs');";
    std::fs::write(&entry, source).expect("entry source");
    std::fs::write(
        root.path().join("dep.mjs"),
        "console.log('must not execute');",
    )
    .expect("dependency source");
    let module = lower_module_graph_entry_bd_yn3lv(&entry, source);
    let mut core = async_module_graph_core_bd_yn3lv(root.path());
    core.prepare_execution(&module).expect("entry preparation");
    assert!(matches!(
        core.run_loop(&module),
        Ok(_) | Err(InterpreterError::Halted)
    ));
    core.set_hook(Arc::new(RevokedImportHook));
    assert!(matches!(
        core.run_event_loop_until_idle_with_module(Some(&module)),
        Err(InterpreterError::ContainmentActionRequested { action, reason })
            if action == "terminate" && reason.as_deref() == Some("module effect revoked")
    ));
    assert!(core.console_output().is_empty());
    assert!(core.pending_dynamic_imports.is_empty());
    assert_eq!(core.module_snapshot_in_flight_bytes, 0);
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn cyclic_module_import_publication_preserves_taint_and_is_atomic() {
    let mut core = test_interpreter();
    let module = lower_module_graph_entry_bd_yn3lv(Path::new("cycle.mjs"), "export const x = 1;");
    core.ensure_module_record(&module, "cycle.mjs")
        .expect("create cycle record");
    core.current_module_specifier = Some("cycle.mjs".to_string());
    let first = ScopeBinding::with_labeled_state(
        BindingKind::Const,
        Value::Undefined,
        Label::Secret,
        false,
    );
    let second = ScopeBinding::new(BindingKind::Const);
    let first_before = first.snapshot_state().expect("first import snapshot");
    let second_before = second.snapshot_state().expect("second import snapshot");
    core.scope_chain
        .current_mut()
        .expect("scope")
        .insert_binding("first".to_string(), first.clone());
    core.scope_chain
        .current_mut()
        .expect("scope")
        .insert_binding("second".to_string(), second.clone());
    core.module_state
        .modules
        .get_mut("cycle.mjs")
        .expect("cycle record")
        .import_bindings
        .insert(
            JsString::from("x"),
            vec![Rc::downgrade(&first.state), Rc::downgrade(&second.state)],
        );
    core.sync_estimated_memory_bytes().expect("fixture budget");
    let before_bytes = core.estimated_memory_bytes();

    let held = second.state.borrow();
    assert!(matches!(
        core.register_module_export_exact_labeled(
            JsString::from("x"),
            Value::Int(42),
            Label::Public,
        ),
        Err(InterpreterError::InternalError { .. })
    ));
    assert_eq!(first.snapshot_state().unwrap(), first_before);
    assert_eq!(*held, second_before);
    assert!(core.module_state.modules["cycle.mjs"].exports.is_empty());
    assert_eq!(core.estimated_memory_bytes(), before_bytes);
    drop(held);

    core.register_module_export_exact_labeled(JsString::from("x"), Value::Int(42), Label::Public)
        .expect("publish after releasing the borrowed import");
    assert_eq!(first.state().unwrap().label, Label::Secret);
    assert_eq!(second.state().unwrap().label, Label::Public);
    for binding in [&first, &second] {
        let state = binding.state().unwrap();
        assert_eq!(state.value, Value::Int(42));
        assert!(state.initialized);
    }
    // bd-1lsy.4.10.1: the importers stay registered, so a later
    // publication (a write to the exported binding) reaches them too,
    // and a cell's label stays the join of everything published to it.
    assert_eq!(
        core.module_state.modules["cycle.mjs"].import_bindings[&JsString::from("x")].len(),
        2
    );
    core.register_module_export_exact_labeled(JsString::from("x"), Value::Int(43), Label::Public)
        .expect("republish to the registered imports");
    for binding in [&first, &second] {
        assert_eq!(binding.state().unwrap().value, Value::Int(43));
    }
    assert_eq!(first.state().unwrap().label, Label::Secret);
    assert_eq!(second.state().unwrap().label, Label::Public);
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn cyclic_module_import_initializes_the_importers_shared_binding() {
    // Retain the generated module graph for diagnosis without deleting files.
    let root = tempfile::tempdir()
        .expect("cyclic module graph root")
        .keep();
    let entry = root.join("entry.mjs");
    let left = root.join("left.mjs");
    let right = root.join("right.mjs");
    let entry_source = "import { result } from './left.mjs'; console.log(result());";
    std::fs::write(&entry, entry_source).expect("write cycle entry");
    std::fs::write(
            &left,
            "import { base } from './right.mjs'; export function result() { return base() + 2; } export function seed() { return 40; }",
        )
        .expect("write cycle left");
    std::fs::write(
        &right,
        "import { seed } from './left.mjs'; export function base() { return seed(); }",
    )
    .expect("write cycle right");

    let module = lower_module_graph_entry_bd_yn3lv(&entry, entry_source);
    let mut core = async_module_graph_core_bd_yn3lv(&root);
    let result = core.execute(&module).expect("cyclic imports should settle");
    let messages: Vec<&str> = result
        .console_output
        .iter()
        .map(|entry| entry.message.as_str())
        .collect();
    assert_eq!(messages, ["42"]);
    // bd-1lsy.4.10.1: every importer cell still alive holds its export's
    // value (the cycle's late publications reached them).
    for record in core.module_state.modules.values() {
        for (name, watchers) in &record.import_bindings {
            for cell in watchers.iter().filter_map(Weak::upgrade) {
                assert_eq!(Some(&cell.borrow().value), record.exports.get(name));
            }
        }
    }
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

/// bd-1lsy.4.10.1: an import follows the exporting module's later writes
/// (through the binding, the namespace object and a closure), assigning
/// it is a TypeError, and publishing to the importer's cell keeps the
/// memory estimate exact without walking every live cell.
#[test]
fn imports_are_live_and_publication_keeps_memory_accounting_exact_bd_1lsy_4_10_1() {
    let temp = tempfile::tempdir().expect("live-binding module-graph root");
    let entry = temp.path().join("entry.mjs");
    let counter = temp.path().join("counter.mjs");
    let entry_source = "import { count, inc } from './counter.mjs'; import * as ns from './counter.mjs'; const read = () => count; inc(); inc(); console.log(count, ns.count, read()); try { count = 1; } catch (error) { console.log(error instanceof TypeError, count); }";
    std::fs::write(&entry, entry_source).expect("write live-binding entry");
    std::fs::write(
        &counter,
        "export let count = 0; export function inc() { count += 'xy'.length; }",
    )
    .expect("write live-binding counter");

    let module = lower_module_graph_entry_bd_yn3lv(&entry, entry_source);
    let mut core = async_module_graph_core_bd_yn3lv(temp.path());
    let result = core.execute(&module).expect("live imports should run");
    let messages: Vec<&str> = result
        .console_output
        .iter()
        .map(|entry| entry.message.as_str())
        .collect();
    assert_eq!(messages, ["4 4 4", "true 4"]);
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

/// bd-9vouw.471: sorting a namespace whose exports were published out of
/// order (a hoisted function before an earlier-sorting `let`) keeps its
/// @@toStringTag and releases nothing it did not take: the reorder used
/// to clear the whole property map, Symbol sidecar included, and left
/// the tag's 86 bytes charged.
#[test]
fn namespace_sort_keeps_to_string_tag_and_exact_accounting_bd_9vouw_471() {
    let temp = tempfile::tempdir().expect("namespace-sort root");
    let entry = temp.path().join("entry.mjs");
    let entry_source = "import * as ns from './m.mjs'; console.log(Object.prototype.toString.call(ns), Object.keys(ns).join(','), ns[Symbol.toStringTag]);";
    std::fs::write(&entry, entry_source).expect("write namespace-sort entry");
    std::fs::write(
        temp.path().join("m.mjs"),
        "export let count = 0; export function inc() { count++; }",
    )
    .expect("write namespace-sort module");

    let module = lower_module_graph_entry_bd_yn3lv(&entry, entry_source);
    let mut core = async_module_graph_core_bd_yn3lv(temp.path());
    let result = core.execute(&module).expect("namespace-sort graph runs");
    let messages: Vec<&str> = result
        .console_output
        .iter()
        .map(|entry| entry.message.as_str())
        .collect();
    assert_eq!(messages, ["[object Module] count,inc Module"]);
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn imported_tla_resumes_transitive_parents_with_owned_programs_bd_yn3lv() {
    let temp = tempfile::tempdir().expect("async module-graph root");
    let entry = temp.path().join("entry.mjs");
    let middle = temp.path().join("middle.mjs");
    let leaf = temp.path().join("leaf.mjs");
    let entry_source = "import { result } from './middle.mjs'; console.log('entry:' + result());";
    std::fs::write(&entry, entry_source).expect("write async graph entry");
    std::fs::write(
            &middle,
            "import { answer } from './leaf.mjs'; console.log('middle:' + answer()); export function result() { return answer() + 2; }",
        )
        .expect("write async graph middle");
    std::fs::write(
        &leaf,
        "await Promise.resolve(); console.log('leaf'); export function answer() { return 40; }",
    )
    .expect("write async graph leaf");

    let module = lower_module_graph_entry_bd_yn3lv(&entry, entry_source);
    let mut core = async_module_graph_core_bd_yn3lv(temp.path());
    let result = core
        .execute(&module)
        .expect("transitive imported top-level await should settle");

    let messages: Vec<&str> = result
        .console_output
        .iter()
        .map(|entry| entry.message.as_str())
        .collect();
    assert_eq!(messages, ["leaf", "middle:40", "entry:42"]);
    for path in [&leaf, &middle] {
        let specifier = path
            .canonicalize()
            .expect("canonical module path")
            .display()
            .to_string();
        let record = core
            .module_state
            .modules
            .get(&specifier)
            .expect("evaluated async graph module record");
        assert!(matches!(record.status, ModuleRuntimeStatus::Evaluated));
        assert!(record.compiled_module.is_some());
        assert!(record.async_execution.is_none());
    }
}

#[test]
fn imported_tla_rejection_propagates_through_parent_graph_bd_yn3lv() {
    let temp = tempfile::tempdir().expect("rejecting async module-graph root");
    let entry = temp.path().join("entry.mjs");
    let middle = temp.path().join("middle.mjs");
    let leaf = temp.path().join("leaf.mjs");
    let entry_source = "import './middle.mjs'; console.log('entry-unreachable');";
    std::fs::write(&entry, entry_source).expect("write rejecting graph entry");
    std::fs::write(
        &middle,
        "import './leaf.mjs'; console.log('middle-unreachable');",
    )
    .expect("write rejecting graph middle");
    std::fs::write(
        &leaf,
        "await Promise.reject('leaf-failed'); console.log('leaf-unreachable');",
    )
    .expect("write rejecting graph leaf");

    let module = lower_module_graph_entry_bd_yn3lv(&entry, entry_source);
    let mut core = async_module_graph_core_bd_yn3lv(temp.path());
    let error = core
        .execute(&module)
        .expect_err("dependency rejection must reject the importing module graph");

    assert!(
        error.to_string().contains("leaf-failed"),
        "unexpected module-graph rejection: {error}"
    );
    assert!(core.console_output.is_empty());
    for path in [&leaf, &middle] {
        let specifier = path
            .canonicalize()
            .expect("canonical module path")
            .display()
            .to_string();
        assert!(matches!(
            core.module_state.modules[&specifier].status,
            ModuleRuntimeStatus::Failed(_)
        ));
    }
}

#[test]
fn module_source_read_enforces_raw_byte_budget_before_utf8() {
    let root = tempfile::tempdir().expect("source root");
    let path = root.path().join("dependency.js");
    let resolved = path.display().to_string();
    let mut core = test_interpreter();
    core.config.module_parser_options.budget.max_source_bytes = 64;

    fs::write(&path, vec![b' '; 64]).expect("exact-size source");
    assert_eq!(
        core.read_module_source(&resolved)
            .expect("admitted bytes")
            .len(),
        64
    );

    fs::write(&path, vec![0xff; 65]).expect("oversized invalid UTF-8");
    assert!(matches!(
        core.read_module_source(&resolved),
        Err(InterpreterError::ModuleParseFailed { error, .. })
            if error.contains("source-byte budget")
    ));

    fs::write(&path, vec![0xff; 64]).expect("bounded invalid UTF-8");
    assert!(matches!(
        core.read_module_source(&resolved),
        Err(InterpreterError::ModuleReadFailed { .. })
    ));
}

#[test]
fn cached_commonjs_load_keeps_its_format_and_source_identity() {
    let root = tempfile::tempdir().expect("module root");
    let entry_path = root.path().join("entry.mjs");
    let dependency = root.path().join("dependency.js");
    fs::write(&entry_path, "export const marker = 0;").expect("entry");
    fs::write(&dependency, "module.exports = { answer: 42 };").expect("CommonJS source");
    let entry = lower_module_graph_entry_bd_yn3lv(&entry_path, "export const marker = 0;");
    let mut core = async_module_graph_core_bd_yn3lv(root.path());
    core.current_module_specifier = Some(entry_path.display().to_string());
    let request = JsString::from("./dependency.js");
    let first = core
        .require_module(&entry, &request)
        .expect("first require");
    let Value::Object(exports) = first else {
        panic!("CommonJS exports object");
    };
    assert_eq!(
        core.prototype_chain_get(exports, "answer").unwrap(),
        Value::Int(42)
    );

    // The cache identity survives changes to both format and source.
    // Invalid bytes prove a cache hit does not read the source again.
    fs::write(root.path().join("package.json"), r#"{"type":"module"}"#)
        .expect("changed package type");
    fs::write(&dependency, [0xff, 0xfe]).expect("changed source");
    let again = core
        .require_module(&entry, &request)
        .expect("cached require");
    assert_eq!(again, Value::Object(exports));
    assert_eq!(
        core.prototype_chain_get(exports, "answer").unwrap(),
        Value::Int(42)
    );
}

#[test]
fn module_load_paths_apply_source_floor_bd_z1peg() {
    let temp = tempfile::tempdir().expect("module source root");
    let entry = temp.path().join("entry.mjs");
    let dependency = temp.path().join("dependency.mjs");
    std::fs::write(&entry, "import './dependency.mjs';").expect("write importing entry module");
    std::fs::write(&dependency, "export const answer = 42;").expect("write imported module");

    let mut import_module = test_module_with_functions(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
                import_attributes: ImportAttributes::default(),
            },
            Ir3Instruction::Halt,
        ],
        Vec::new(),
    );
    import_module.header.source_label = entry.display().to_string();
    import_module.constant_pool = vec![JsString::from("./dependency.mjs")];

    let mut import_core = test_interpreter();
    import_core
        .config
        .set_module_root(temp.path().display().to_string())
        .expect("set import root");
    import_core.current_module_specifier = Some(entry.display().to_string());
    import_core
        .config
        .granted_capabilities
        .insert(RuntimeCapability::ModuleLoad);
    import_core
        .execute(&import_module)
        .expect("direct ImportModule execution");
    assert!(matches!(import_core.read_reg(1), Ok(Value::Object(_))));
    assert_eq!(
        import_core
            .get_register_label(1)
            .expect("import result label"),
        &Label::Internal
    );

    let mut require_core = test_interpreter();
    require_core
        .config
        .set_module_root(temp.path().display().to_string())
        .expect("set require root");
    require_core.current_module_specifier = Some(entry.display().to_string());
    require_core
        .config
        .granted_capabilities
        .insert(RuntimeCapability::ModuleLoad);
    require_core
        .write_reg_with_label(0, Value::str("./dependency.mjs"), Label::Public)
        .expect("require specifier");
    let required = require_core
        .dispatch_builtin_function(
            &import_module,
            &BuiltinFunction::require(entry.display().to_string()),
            RegRange { start: 0, count: 1 },
            None,
            None,
        )
        .expect("first-class require");
    assert!(matches!(required, Value::Object(_)));
    assert_eq!(
        require_core.take_pending_hostcall_result_label(),
        Some(Label::Internal)
    );

    let mut delegated_module = test_module_with_functions(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::NewArray { dst: 1 },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::ArrayPush {
                array: 1,
                element: 2,
            },
            Ir3Instruction::HostCall {
                capability: CapabilityTag("builtin:ApplyHostCall".to_string()),
                args: RegRange { start: 0, count: 2 },
                dst: 3,
            },
            Ir3Instruction::Halt,
        ],
        Vec::new(),
    );
    delegated_module.header.source_label = entry.display().to_string();
    delegated_module.constant_pool = vec![
        JsString::from("module_load"),
        JsString::from("./dependency.mjs"),
    ];
    let mut delegated_core = test_interpreter();
    delegated_core
        .config
        .set_module_root(temp.path().display().to_string())
        .expect("set delegated module root");
    delegated_core.current_module_specifier = Some(entry.display().to_string());
    delegated_core
        .config
        .granted_capabilities
        .extend([RuntimeCapability::Builtin, RuntimeCapability::ModuleLoad]);
    delegated_core
        .execute(&delegated_module)
        .expect("ApplyHostCall delegated module load");
    assert!(matches!(delegated_core.read_reg(3), Ok(Value::Object(_))));
    assert_eq!(
        delegated_core
            .get_register_label(3)
            .expect("delegated module result label"),
        &Label::Internal,
        "the outer ApplyHostCall contract must retain the delegated source floor"
    );
    assert_eq!(
        delegated_core.estimated_memory_bytes(),
        delegated_core.recompute_estimated_memory_bytes()
    );

    let mut label_preserving_core = test_interpreter();
    label_preserving_core
        .config
        .granted_capabilities
        .insert(RuntimeCapability::Builtin);
    let arguments = label_preserving_core
        .alloc_array_from_values(&[Value::Int(7)])
        .expect("delegated arguments array");
    label_preserving_core
        .join_object_mutation_label(arguments, &Label::Secret)
        .expect("classify delegated array contents");
    label_preserving_core
        .write_reg_with_label(0, Value::str("promise:resolve"), Label::Public)
        .expect("delegated target");
    label_preserving_core
        .write_reg_with_label(1, Value::Object(arguments), Label::Public)
        .expect("public register carrying classified arguments");
    let delegated_promise = label_preserving_core
        .dispatch_builtin_hostcall(
            "builtin:ApplyHostCall:promise:resolve",
            RegRange { start: 0, count: 2 },
            Some(&delegated_module),
        )
        .expect("lowering-authenticated delegated Promise.resolve");
    let Value::Promise(delegated_promise) = delegated_promise else {
        panic!("delegated Promise.resolve must return a Promise")
    };
    assert_eq!(
        label_preserving_core
            .promise_store
            .get(crate::promise_model::PromiseHandle(delegated_promise))
            .expect("delegated Promise record")
            .label,
        Label::Secret,
        "delegated async state must observe reachable argument provenance"
    );
    assert_eq!(
        label_preserving_core.take_pending_hostcall_result_label(),
        Some(Label::Secret),
        "reachable argument-array provenance must survive JoinInputs delegation"
    );
    assert_eq!(
        label_preserving_core.estimated_memory_bytes(),
        label_preserving_core.recompute_estimated_memory_bytes()
    );

    label_preserving_core
        .write_reg_with_label(0, Value::str("promise:reject"), Label::Public)
        .expect("mismatched delegated target");
    label_preserving_core
        .replace_pending_hostcall_result_label(Some(Label::Custom {
            name: "stale-prefix-publication".repeat(11),
            level: 4,
        }))
        .expect("seed stale prefix publication");
    let mismatch = label_preserving_core
        .dispatch_builtin_hostcall(
            "builtin:ApplyHostCall:promise:resolve",
            RegRange { start: 0, count: 2 },
            Some(&delegated_module),
        )
        .expect_err("encoded and runtime targets must match");
    assert!(matches!(mismatch, InterpreterError::TypeError { .. }));
    assert_eq!(
        label_preserving_core.take_pending_hostcall_result_label(),
        None
    );

    label_preserving_core
        .write_reg_with_label(0, Value::str("builtin:PathJoin"), Label::Public)
        .expect("throwing delegated target");
    let throwing_arguments = label_preserving_core
        .alloc_array_from_values(&[Value::Int(7)])
        .expect("throwing arguments array");
    label_preserving_core
        .join_object_mutation_label(throwing_arguments, &Label::Secret)
        .expect("classify throwing delegated arguments");
    label_preserving_core
        .write_reg_with_label(1, Value::Object(throwing_arguments), Label::Public)
        .expect("public register carrying throwing arguments");
    let thrown = label_preserving_core
        .dispatch_builtin_hostcall(
            "builtin:ApplyHostCall:builtin:PathJoin",
            RegRange { start: 0, count: 2 },
            Some(&delegated_module),
        )
        .expect_err("delegated invalid path input must throw");
    assert!(matches!(thrown, InterpreterError::UncaughtException { .. }));
    assert_eq!(
        label_preserving_core.pending_exception_label,
        Label::Secret,
        "delegated explicit throws must retain reachable argument provenance"
    );
    assert_eq!(
        label_preserving_core.estimated_memory_bytes(),
        label_preserving_core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn apply_hostcall_scratch_frame_is_label_exact_and_failure_atomic_bd_z1peg_3() {
    let module = test_module_with_functions(Vec::new(), Vec::new());
    let scratch_value = Value::str("saved-scratch-value".repeat(19));
    let scratch_label = Label::Custom {
        name: "saved-scratch-label".repeat(23),
        level: 2,
    };

    let mut success = test_interpreter();
    success
        .write_reg_with_label(0, scratch_value.clone(), scratch_label.clone())
        .expect("classified scratch register");
    success
        .write_reg_with_label(1, Value::Int(99), Label::Confidential)
        .expect("second scratch register");
    let arguments = success
        .alloc_array_from_values(&[Value::Int(7), Value::Int(11)])
        .expect("delegated arguments");
    success
        .set_own_property_label(arguments, "0", &Label::Secret)
        .expect("classify only the first delegated element");
    let prepared = success
        .prepare_delegated_hostcall_arguments(Value::Object(arguments))
        .expect("account delegated argument carrier");
    assert_eq!(
        prepared.labels,
        vec![Label::Secret, Label::Public],
        "scratch labels must preserve per-element provenance instead of smearing the aggregate"
    );
    let delegated = success
        .dispatch_hostcall_with_value_args(
            "promise:resolve",
            prepared,
            Some(&module),
            &Label::Secret,
        )
        .expect("delegate Promise.resolve");
    let Value::Promise(promise) = delegated else {
        panic!("delegated Promise.resolve must return a Promise")
    };
    assert!(
        success
            .promise_store
            .get(crate::promise_model::PromiseHandle(promise))
            .is_ok(),
        "delegated Promise.resolve must retain its asynchronous state"
    );
    assert_eq!(success.read_reg(0), Ok(scratch_value.clone()));
    assert_eq!(success.get_register_label(0), Ok(&scratch_label));
    assert_eq!(success.read_reg(1), Ok(Value::Int(99)));
    assert_eq!(success.get_register_label(1), Ok(&Label::Confidential));
    assert_eq!(
        success.take_pending_hostcall_result_label(),
        Some(Label::Secret)
    );
    assert_eq!(
        success.estimated_memory_bytes(),
        success.recompute_estimated_memory_bytes()
    );

    let mut throwing = test_interpreter();
    throwing
        .write_reg_with_label(0, scratch_value.clone(), scratch_label.clone())
        .expect("throwing scratch register");
    let throwing_arguments = throwing
        .alloc_array_from_values(&[Value::Int(7)])
        .expect("throwing delegated arguments");
    let prepared = throwing
        .prepare_delegated_hostcall_arguments(Value::Object(throwing_arguments))
        .expect("account throwing arguments");
    throwing
        .replace_pending_hostcall_result_label(Some(Label::Custom {
            name: "stale-inner-publication".repeat(17),
            level: 4,
        }))
        .expect("seed stale inner publication");
    let error = throwing
        .dispatch_hostcall_with_value_args(
            "builtin:PathJoin",
            prepared,
            Some(&module),
            &Label::Secret,
        )
        .expect_err("invalid delegated path input must throw");
    assert!(matches!(error, InterpreterError::UncaughtException { .. }));
    assert_eq!(throwing.read_reg(0), Ok(scratch_value.clone()));
    assert_eq!(throwing.get_register_label(0), Ok(&scratch_label));
    assert!(
        throwing.pending_hostcall_result_label.is_none(),
        "an inner error must not leak a stale result publication"
    );
    assert_eq!(
        throwing.estimated_memory_bytes(),
        throwing.recompute_estimated_memory_bytes()
    );

    let mut one_short = test_interpreter();
    one_short
        .write_reg_with_label(0, scratch_value.clone(), scratch_label.clone())
        .expect("one-short scratch register");
    let one_short_arguments = one_short
        .alloc_array_from_values(&[Value::Int(7)])
        .expect("one-short delegated arguments");
    let invocation_label = Label::Custom {
        name: "delegated-invocation-label".repeat(31),
        level: 3,
    };
    one_short
        .set_own_property_label(one_short_arguments, "0", &invocation_label)
        .expect("classify one-short delegated element");
    let before_prepare = one_short.estimated_memory_bytes();
    let prepared = one_short
        .prepare_delegated_hostcall_arguments(Value::Object(one_short_arguments))
        .expect("reserve one-short argument carrier");
    let saved_structure_bytes =
        (std::mem::size_of::<Value>() + std::mem::size_of::<Label>()) as u64;
    one_short.config.max_total_memory_bytes = one_short
        .estimated_memory_bytes()
        .saturating_add(saved_structure_bytes)
        .saturating_sub(1);
    let refusal = one_short
        .dispatch_hostcall_with_value_args(
            "promise:resolve",
            prepared,
            Some(&module),
            &invocation_label,
        )
        .expect_err("saved scratch carrier must fit before delegation");
    assert!(matches!(
        refusal,
        InterpreterError::MemoryBudgetExceeded { .. }
    ));
    assert_eq!(one_short.read_reg(0), Ok(scratch_value));
    assert_eq!(one_short.get_register_label(0), Ok(&scratch_label));
    assert_eq!(one_short.estimated_memory_bytes(), before_prepare);
    assert_eq!(
        one_short.estimated_memory_bytes(),
        one_short.recompute_estimated_memory_bytes()
    );
}

#[test]
fn modern_http_lifecycle_retains_dynamic_and_receiver_provenance_bd_z1peg() {
    let mut construction_core = test_interpreter();
    let classified_options = construction_core
        .alloc_object_with_properties(&[
            ("host", Value::str("127.0.0.1")),
            ("port", Value::Int(42_321)),
            ("path", Value::str("/classified-options")),
        ])
        .expect("classified request options");
    construction_core
        .join_object_mutation_label(classified_options, &Label::Secret)
        .expect("classify request options");
    construction_core
        .write_reg_with_label(0, Value::Object(classified_options), Label::Public)
        .expect("public register carrying classified options");
    let Value::Object(classified_request) = construction_core
        .construct_http_client_request(RegRange { start: 0, count: 1 }, false)
        .expect("request from dynamically classified options")
    else {
        panic!("expected classified request object")
    };
    assert_eq!(
        construction_core.http_client_requests[&classified_request].lifecycle_label,
        Label::Secret,
        "reachable options provenance must seed the request lifecycle"
    );
    assert_eq!(
        construction_core.estimated_memory_bytes(),
        construction_core.recompute_estimated_memory_bytes()
    );

    let mut alias_core = test_interpreter();
    alias_core
        .loopback_ports
        .insert(42_322, LoopbackPortState::Closed { generation: 1 });
    alias_core
        .sync_estimated_memory_bytes()
        .expect("account closed loopback fixture");
    let public_options = alias_core
        .alloc_object_with_properties(&[
            ("host", Value::str("127.0.0.1")),
            ("port", Value::Int(42_322)),
            ("path", Value::str("/classified-alias")),
        ])
        .expect("public request options");
    alias_core
        .write_reg_with_label(0, Value::Object(public_options), Label::Public)
        .expect("public request options register");
    let Value::Object(request) = alias_core
        .construct_http_client_request(RegRange { start: 0, count: 1 }, false)
        .expect("public request")
    else {
        panic!("expected public request object")
    };
    assert_eq!(
        alias_core.http_client_requests[&request].lifecycle_label,
        Label::Public
    );

    alias_core
        .write_reg_with_label(3, Value::Object(request), Label::Secret)
        .expect("classified request alias");
    alias_core
        .write_reg_with_label(1, Value::str("X-Provenance"), Label::Public)
        .expect("public header name");
    alias_core
        .write_reg_with_label(2, Value::str("public"), Label::Public)
        .expect("public header value");
    let module = test_module_with_functions(Vec::new(), Vec::new());
    alias_core
        .dispatch_builtin_function(
            &module,
            &BuiltinFunction::new_kind(BuiltinFunctionKind::HttpClientRequestSetHeader),
            RegRange { start: 1, count: 2 },
            Some(Value::Object(request)),
            Some(3),
        )
        .expect("dispatch setHeader through classified alias");
    assert_eq!(
        alias_core.http_client_requests[&request].lifecycle_label,
        Label::Secret,
        "receiver provenance must survive a public setHeader mutation"
    );

    alias_core
        .write_reg_with_label(4, Value::Object(request), Label::Public)
        .expect("public request alias");
    alias_core
        .dispatch_builtin_function(
            &module,
            &BuiltinFunction::new_kind(BuiltinFunctionKind::HttpClientRequestEnd),
            RegRange { start: 5, count: 0 },
            Some(Value::Object(request)),
            Some(4),
        )
        .expect("dispatch end through public alias");
    let queued_error_label = alias_core
        .pending_http_tasks
        .values()
        .find_map(|task| match task {
            PendingHttpTask::ClientError {
                request: queued,
                label,
                ..
            } if *queued == request => Some(label),
            _ => None,
        })
        .expect("closed loopback request must schedule a client error");
    assert_eq!(queued_error_label, &Label::Secret);
    assert_eq!(
        alias_core.estimated_memory_bytes(),
        alias_core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn filesystem_operation_discriminators_cannot_broaden_hostcall_authority() {
    use frankenengine_extension_host::host_io::{InMemoryHostIoTranscript, SandboxedHostIo};

    let root = tempfile::tempdir().expect("sandbox");
    let path = root.path().join("keep.txt");
    std::fs::write(&path, b"unchanged").expect("input");
    for (tag, operation, expected_denial) in [
        ("fs:read", "write", "fs:write"),
        ("fs:read", "open", "fs:write"),
        ("fs:write", "read", "fs:read"),
        ("fs:read", "unknown", "fs:unknown_operation"),
        ("fs:write", "unknown", "fs:unknown_operation"),
    ] {
        let recorder = Arc::new(InMemoryHostIoTranscript::recording());
        let mut core = test_interpreter();
        core.config
            .granted_capabilities
            .insert(if tag == "fs:read" {
                RuntimeCapability::FsRead
            } else {
                RuntimeCapability::FsWrite
            });
        core.set_host_io(
            Arc::new(SandboxedHostIo::with_root(root.path()).expect("provider")),
            Some(recorder.clone()),
        );
        core.write_reg(0, Value::str(format!("\0fsop:{operation}")))
            .unwrap();
        core.write_reg(1, Value::str("keep.txt")).unwrap();
        core.write_reg(2, Value::str("must not reach the provider"))
            .unwrap();
        let module = test_module_with_functions(
            vec![
                Ir3Instruction::HostCall {
                    capability: CapabilityTag(tag.to_string()),
                    args: RegRange { start: 0, count: 3 },
                    dst: 3,
                },
                Ir3Instruction::Halt,
            ],
            Vec::new(),
        );
        let error = core
            .execute(&module)
            .expect_err("malformed operation must fail closed");
        assert!(
            matches!(error, InterpreterError::CapabilityDenied { ref capability }
                    if capability == expected_denial),
            "{tag} / {operation}: {error:?}"
        );
        assert!(
            recorder.is_empty(),
            "malformed operation reached the host seam"
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"unchanged");
    }

    // A valid discriminator still crosses the real provider under only
    // its matching grant. The positive controls prevent a blanket refusal
    // from satisfying the malformed-IR assertions above.
    for (tag, operation, argument, capability) in [
        ("fs:read", "read", "utf8", RuntimeCapability::FsRead),
        ("fs:write", "write", "written", RuntimeCapability::FsWrite),
    ] {
        let recorder = Arc::new(InMemoryHostIoTranscript::recording());
        let mut core = test_interpreter();
        core.config.granted_capabilities.insert(capability);
        core.set_host_io(
            Arc::new(SandboxedHostIo::with_root(root.path()).expect("provider")),
            Some(recorder.clone()),
        );
        core.write_reg(0, Value::str(format!("\0fsop:{operation}")))
            .unwrap();
        core.write_reg(1, Value::str("keep.txt")).unwrap();
        core.write_reg(2, Value::str(argument)).unwrap();
        let module = test_module_with_functions(
            vec![
                Ir3Instruction::HostCall {
                    capability: CapabilityTag(tag.to_string()),
                    args: RegRange { start: 0, count: 3 },
                    dst: 3,
                },
                Ir3Instruction::Halt,
            ],
            Vec::new(),
        );
        core.execute(&module).expect("matching operation and grant");
        assert_eq!(recorder.len(), 1);
        if operation == "read" {
            assert_eq!(core.read_reg(3).unwrap(), Value::str("unchanged"));
        } else {
            assert_eq!(std::fs::read(&path).unwrap(), b"written");
        }
    }
}

/// bd-f5b04.2.7: when a sandboxed host-I/O provider is installed, the
/// interpreter's `fs:` hostcall dispatch performs and records a REAL host
/// effect (bytes hit disk) and returns the real result; with no provider it
/// stays fail-closed (undefined).
#[test]
fn hostcall_fs_dispatch_performs_real_io_through_provider_bd_f5b04_2_7() {
    use frankenengine_extension_host::host_io::{InMemoryHostIoTranscript, SandboxedHostIo};

    let mut root = std::env::temp_dir();
    root.push(format!(
        "frankenengine_interp_hostio_{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).expect("scratch root");

    let provider = Arc::new(SandboxedHostIo::with_root(&root).expect("sandboxed provider"));
    let recorder = Arc::new(InMemoryHostIoTranscript::recording());

    let mut core = test_interpreter();
    let recorder_dyn: Arc<dyn HostIoRecorder> = recorder.clone();
    core.set_host_io(provider, Some(recorder_dyn));
    // reg0 = relative path, reg1 = content (string operands).
    core.mutate_registers(|r| {
        r[0] = Value::Str(JsString::from("report.txt"));
        r[1] = Value::Str(JsString::from("real effect bytes"));
    });

    // fs:write through the interpreter dispatch performs a real write and —
    // matching Node's `writeFileSync` — returns `undefined` (bd-1xl17.d). The
    // byte count still lives in the recorded transcript, not the JS value.
    let write_result = core
        .dispatch_host_io_hostcall("fs:write", RegRange { start: 0, count: 2 })
        .expect("fs:write dispatch");
    assert_eq!(
        write_result,
        Value::Undefined,
        "fs:write must return undefined to match Node's writeFileSync"
    );
    assert_eq!(
        std::fs::read(root.join("report.txt")).expect("written file on disk"),
        b"real effect bytes",
        "the interpreter must have produced a real file"
    );

    // bd-1xl17.d: fs:read WITHOUT an encoding (arity 1) yields a Buffer
    // (Uint8Array-backed) carrying the real bytes, matching `readFileSync(path)`.
    let read_buffer = core
        .dispatch_host_io_hostcall("fs:read", RegRange { start: 0, count: 1 })
        .expect("fs:read (no encoding) dispatch");
    let Value::Object(buffer_id) = read_buffer else {
        panic!("readFileSync without an encoding must return a Buffer object, got {read_buffer:?}");
    };
    let buffer_bytes: Vec<u8> = core
        .read_array_like_values(buffer_id)
        .iter()
        .map(|value| match value {
            Value::Int(byte) => u8::try_from(*byte).expect("Uint8Array element in 0..=255"),
            other => panic!("Uint8Array element must be an Int byte, got {other:?}"),
        })
        .collect();
    assert_eq!(
        buffer_bytes, b"real effect bytes",
        "the no-encoding read Buffer must contain the real file bytes"
    );

    // bd-1xl17.d: fs:read WITH a recognized encoding ('utf8' in arg[1]) yields
    // the decoded JS string, matching `readFileSync(path, 'utf8')`.
    core.mutate_registers(|r| {
        r[1] = Value::Str(JsString::from("utf8"));
    });
    let read_string = core
        .dispatch_host_io_hostcall("fs:read", RegRange { start: 0, count: 2 })
        .expect("fs:read (utf8) dispatch");
    assert_eq!(
        read_string,
        Value::Str(JsString::from("real effect bytes")),
        "the utf8 read must surface the real file contents as a string"
    );

    // bd-rul7k: the OPTIONS-OBJECT form readFileSync(path, { encoding: 'utf8' })
    // resolves the encoding from the object's own `encoding` property (the
    // object itself stringifies to a type name and would never match an
    // encoding), so it decodes identically to the bare-string form.
    let options_id = core.mutate_heap(|h| {
        let id = ObjectId(h.len() as u32);
        let mut options = HeapObject::new();
        options
            .properties
            .insert("encoding".to_string(), Value::str("utf8"));
        h.push(options);
        id
    });
    core.mutate_registers(|r| {
        r[1] = Value::Object(options_id);
    });
    let read_via_options = core
        .dispatch_host_io_hostcall("fs:read", RegRange { start: 0, count: 2 })
        .expect("fs:read (options-object) dispatch");
    assert_eq!(
        read_via_options,
        Value::Str(JsString::from("real effect bytes")),
        "the options-object encoding form must decode like the bare-string form"
    );

    // bd-rul7k: an options object with no (or null) `encoding` falls back to a
    // Buffer, matching Node.
    let bufferish_id = core.mutate_heap(|h| {
        let id = ObjectId(h.len() as u32);
        let mut options = HeapObject::new();
        options
            .properties
            .insert("flag".to_string(), Value::str("r"));
        h.push(options);
        id
    });
    core.mutate_registers(|r| {
        r[1] = Value::Object(bufferish_id);
    });
    let read_no_encoding_option = core
        .dispatch_host_io_hostcall("fs:read", RegRange { start: 0, count: 2 })
        .expect("fs:read (options-object without encoding) dispatch");
    assert!(
        matches!(read_no_encoding_option, Value::Object(_)),
        "an options object without an encoding must fall back to a Buffer"
    );

    // All five real effects (one write + four reads: no-encoding, utf8,
    // options-object utf8, and options-object-without-encoding) were captured
    // in the replay transcript — the ledger source for bd-5r99w.12. The
    // JS-visible return shape (undefined / Buffer / string) is orthogonal to
    // what gets recorded: every dispatched fs effect still lands in the
    // transcript.
    assert_eq!(
        recorder.entries().len(),
        5,
        "all dispatched fs effects (one write + four reads) must be recorded"
    );

    // bd-rul7k item 3: an explicit UNKNOWN encoding throws a JS-catchable
    // TypeError BEFORE the read runs — Node parity — so NO spurious read effect
    // is recorded (the transcript count stays at 5).
    core.mutate_registers(|r| {
        r[0] = Value::Str(JsString::from("real.txt"));
        r[1] = Value::Str(JsString::from("bogus-encoding"));
    });
    let bad_encoding = core.dispatch_host_io_hostcall("fs:read", RegRange { start: 0, count: 2 });
    assert!(
        matches!(bad_encoding, Err(InterpreterError::TypeError { .. })),
        "fs:read with an unknown encoding must throw TypeError, got {bad_encoding:?}"
    );
    assert_eq!(
        recorder.entries().len(),
        5,
        "an unknown encoding must be rejected BEFORE the read — no extra effect recorded"
    );

    // With no provider installed, fs hostcalls stay fail-closed (undefined).
    let mut bare = test_interpreter();
    bare.mutate_registers(|r| {
        r[0] = Value::Str(JsString::from("nope.txt"));
    });
    let bare_result = bare
        .dispatch_host_io_hostcall("fs:read", RegRange { start: 0, count: 1 })
        .expect("no-provider dispatch is infallible");
    assert_eq!(
        bare_result,
        Value::Undefined,
        "no provider installed => fail-closed undefined"
    );

    // bd-z1peg: the real HostCall instruction applies the shared
    // filesystem source floor after provider dispatch. A Public path does
    // not make provider-originated file contents Public.
    let source_module = test_module_with_functions(
        vec![
            Ir3Instruction::HostCall {
                capability: CapabilityTag("fs:read".to_string()),
                args: RegRange { start: 0, count: 2 },
                dst: 3,
            },
            Ir3Instruction::Halt,
        ],
        Vec::new(),
    );
    let mut labeled = test_interpreter();
    labeled
        .config
        .granted_capabilities
        .insert(RuntimeCapability::FsRead);
    labeled.set_host_io(
        Arc::new(SandboxedHostIo::with_root(&root).expect("source-label provider")),
        None,
    );
    labeled
        .write_reg_with_label(0, Value::str("report.txt"), Label::Public)
        .expect("public read path");
    labeled
        .write_reg_with_label(1, Value::str("utf8"), Label::Public)
        .expect("public read encoding");
    labeled
        .execute(&source_module)
        .expect("source-labeled fs read");
    assert_eq!(
        labeled.get_register_label(3).expect("fs read result label"),
        &Label::Internal
    );

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn filesystem_provider_error_label_reaches_sync_catch_binding_bd_padqo() {
    use frankenengine_extension_host::host_io::SandboxedHostIo;

    fn caught_label(
        provider: Arc<dyn HostIoProvider>,
        recorder: Option<Arc<dyn HostIoRecorder>>,
        path_label: Label,
    ) -> (Value, Label) {
        let module = test_module_with_functions(
            vec![
                Ir3Instruction::BeginTry {
                    catch_target: 2,
                    finally_target: None,
                },
                Ir3Instruction::HostCall {
                    capability: CapabilityTag("fs:read".to_string()),
                    args: RegRange { start: 8, count: 1 },
                    dst: 3,
                },
                Ir3Instruction::EnterCatch { dst: 1 },
                Ir3Instruction::Halt,
            ],
            vec![],
        );
        let mut core = test_interpreter();
        core.config
            .granted_capabilities
            .insert(RuntimeCapability::FsRead);
        core.set_host_io(provider, recorder);
        core.write_reg_with_label(8, Value::str("missing"), path_label)
            .expect("path register");
        core.execute(&module)
            .expect("provider filesystem error should reach the catch handler");
        (
            core.read_reg(1).expect("caught error value"),
            core.get_register_label(1)
                .expect("caught error label")
                .clone(),
        )
    }

    let scratch = tempfile::tempdir().expect("sandbox root");
    let sandbox =
        Arc::new(SandboxedHostIo::with_root(scratch.path()).expect("canonical sandbox provider"));
    let (caught, label) = caught_label(sandbox.clone(), None, Label::Public);
    assert!(
        matches!(caught, Value::Object(_)),
        "caught value is an Error object"
    );
    assert_eq!(
        label,
        Label::Internal,
        "a public request joins with the canonical provider's Internal state"
    );

    // bd-9vouw.8: an fs operand above the sink's Internal clearance is
    // refused before dispatch, so a Secret path never reaches the
    // provider (it used to, and its error carried the Secret label to
    // the catch binding).
    let refused_read = test_module_with_functions(
        vec![
            Ir3Instruction::HostCall {
                capability: CapabilityTag("fs:read".to_string()),
                args: RegRange { start: 8, count: 1 },
                dst: 3,
            },
            Ir3Instruction::Halt,
        ],
        vec![],
    );
    let mut core = test_interpreter();
    core.config
        .granted_capabilities
        .insert(RuntimeCapability::FsRead);
    core.set_host_io(sandbox.clone(), None);
    core.write_reg_with_label(8, Value::str("missing"), Label::Secret)
        .expect("path register");
    assert!(
        matches!(
            core.execute(&refused_read),
            Err(InterpreterError::CapabilityDenied { ref capability })
                if capability == "fs:read:confidentiality"
        ),
        "a Secret path must be refused before the provider"
    );

    let module = test_module_with_functions(
        vec![
            Ir3Instruction::BeginTry {
                catch_target: 2,
                finally_target: None,
            },
            Ir3Instruction::HostCall {
                capability: CapabilityTag("fs:write".to_string()),
                args: RegRange { start: 8, count: 2 },
                dst: 3,
            },
            Ir3Instruction::EnterCatch { dst: 1 },
            Ir3Instruction::Halt,
        ],
        vec![],
    );
    let mut core = test_interpreter();
    core.config
        .granted_capabilities
        .insert(RuntimeCapability::FsWrite);
    core.set_host_io(sandbox.clone(), None);
    core.write_reg_with_label(8, Value::str("missing-parent/output.txt"), Label::Public)
        .expect("write path register");
    core.write_reg_with_label(9, Value::str("payload"), Label::Secret)
        .expect("write content register");
    assert!(
        matches!(
            core.execute(&module),
            Err(InterpreterError::CapabilityDenied { ref capability })
                if capability == "fs:write:confidentiality"
        ),
        "Secret write content must be refused before the provider"
    );
    assert!(
        !scratch.path().join("missing-parent").exists(),
        "nothing was written"
    );

    let (_, label) = caught_label(Arc::new(UnknownFsErrorProvider), None, Label::Public);
    assert_eq!(
        label,
        Label::TopSecret,
        "a custom provider that does not authenticate provenance must fail high"
    );

    let (_, label) = caught_label(
        sandbox,
        Some(Arc::new(UnknownFsReplayRecorder)),
        Label::Public,
    );
    assert_eq!(
        label,
        Label::TopSecret,
        "a replay source that can replace the provider outcome must fail high"
    );
}

#[test]
fn filesystem_provider_error_labels_deferred_callback_bd_padqo() {
    use frankenengine_extension_host::host_io::SandboxedHostIo;

    let scratch = tempfile::tempdir().expect("sandbox root");
    let provider =
        Arc::new(SandboxedHostIo::with_root(scratch.path()).expect("canonical sandbox provider"));
    let mut core = test_interpreter();
    core.set_host_io(provider, None);
    core.write_reg_with_label(0, Value::str("secret-token"), Label::Secret)
        .expect("secret path register");
    core.write_reg_with_label(1, Value::Closure(77), Label::Public)
        .expect("callback register");

    let result = core
        .dispatch_host_io_hostcall("fs:read", RegRange { start: 0, count: 2 })
        .expect("callback-form provider error is delivered asynchronously");
    assert_eq!(result, Value::Undefined);
    assert!(
        core.pending_hostcall_result_label.is_none(),
        "callback delivery must not leave a synchronous error label behind"
    );
    assert_eq!(
        core.event_loop
            .turn()
            .macrotask
            .expect("filesystem error callback")
            .label,
        Label::Secret,
        "the scheduled callback must inherit provider plus path provenance"
    );
}

/// bd-656a2 (http leg): when a sandboxed host-I/O provider is installed, the
/// interpreter's `net:request` hostcall dispatch (emitted by the JS
/// http.get/http.request lowering) performs and records a REAL network egress
/// host effect — it opens a TCP connection to the URL's `host:port`, writes a
/// framed HTTP/1.1 GET request, and appends the `NetworkSend` to the host-I/O
/// transcript (the ledger source). Verified against an in-process loopback
/// listener that observes the request bytes on the wire.
#[test]
fn hostcall_net_request_dispatch_performs_real_egress_bd_656a2() {
    use frankenengine_extension_host::host_io::{
        HostIoRequest, InMemoryHostIoTranscript, SandboxedHostIo,
    };
    use std::io::{Read, Write};
    use std::time::Duration;

    // A loopback listener stands in for the remote endpoint. bd-3894s slice (4):
    // the dispatch now does a single-socket request/response round trip, so the
    // server reads the (half-closed) request to EOF, then sends a response and
    // closes so the client's response read terminates. Capture the request bytes
    // so the test still proves a real, framed request crossed the socket.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().expect("listener addr");
    let server = std::thread::spawn(move || {
        let (mut stream, _peer) = listener.accept().expect("accept egress connection");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("server read timeout");
        let mut received = Vec::new();
        let _ = stream.read_to_end(&mut received);
        let _ = stream.write_all(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nhi",
        );
        let _ = stream.flush();
        received
    });

    // The sandboxed provider needs a real root for its fs arms; the network
    // arm ignores it. Use a unique scratch dir like the fs dispatch test.
    let mut root = std::env::temp_dir();
    root.push(format!("frankenengine_interp_net_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).expect("scratch root");

    let provider = Arc::new(SandboxedHostIo::with_root(&root).expect("sandboxed provider"));
    let recorder = Arc::new(InMemoryHostIoTranscript::recording());
    let mut core = test_interpreter();
    let recorder_dyn: Arc<dyn HostIoRecorder> = recorder.clone();
    core.set_host_io(provider, Some(recorder_dyn));

    // reg0 = the URL operand, exactly as the http.get(url) lowering forwards it.
    let url = format!("http://{addr}/");
    core.mutate_registers(|r| {
        r[0] = Value::Str(JsString::from(url.as_str()));
    });

    // bd-3894s slice (4): the dispatch now returns the PARSED response object
    // (status/statusText/ok/headers/body), not undefined.
    let result = core
        .dispatch_host_io_hostcall("net:request", RegRange { start: 0, count: 1 })
        .expect("net:request dispatch");
    let Value::Object(response_id) = result else {
        panic!("net:request must return a response object, got {result:?}");
    };
    let response = core
        .heap
        .get(response_id.0 as usize)
        .expect("response object on the heap");
    assert_eq!(
        response.properties.get("status"),
        Some(&Value::Int(200)),
        "the parsed response carries the numeric status code"
    );
    assert_eq!(
        response.properties.get("ok"),
        Some(&Value::Bool(true)),
        "a 2xx status reports ok = true"
    );
    assert_eq!(
        response.properties.get("body"),
        Some(&Value::str("hi")),
        "the response body is decoded back to JS"
    );
    let headers_id = match response.properties.get("headers") {
        Some(Value::Object(id)) => *id,
        other => panic!("response carries a headers object, got {other:?}"),
    };
    let headers = core
        .heap
        .get(headers_id.0 as usize)
        .expect("headers object on the heap");
    assert_eq!(
        headers.properties.get("content-type"),
        Some(&Value::str("text/plain")),
        "response header names are lower-cased and values decoded"
    );

    let received = server.join().expect("server thread");
    let wire = String::from_utf8_lossy(&received);
    assert!(
        wire.starts_with("GET / HTTP/1.1\r\n"),
        "the loopback server must have received a framed HTTP/1.1 GET, got {wire:?}"
    );
    assert!(
        wire.contains(&format!("Host: {addr}\r\n")),
        "the request must carry the Host header for the endpoint, got {wire:?}"
    );

    // The round trip landed in the host-effect transcript as a NetworkRequest
    // (the proof-carrying ledger entry the L1 http.request subject is built from).
    let entries = recorder.recorded_entries();
    assert_eq!(entries.len(), 1, "exactly one host effect recorded");
    match &entries[0].0 {
        HostIoRequest::NetworkRequest { endpoint, .. } => {
            assert_eq!(
                endpoint,
                &addr.to_string(),
                "endpoint resolves to host:port"
            );
        }
        other => panic!("expected a NetworkRequest host effect, got {other:?}"),
    }
    assert!(
        entries[0].1.is_ok(),
        "the recorded round-trip outcome must be a successful response"
    );

    let _ = std::fs::remove_dir_all(&root);
}

/// bd-3894s slice (2): a `net:request` whose SECOND argument is a
/// `fetch(url, init)` / `http.request(url, options)` options object
/// (`{ method, headers, body }`) must frame the REAL method/headers/body onto
/// the wire — and record them in the host-effect transcript — instead of the
/// hardcoded bodyless GET of slice 1. A POST-with-body proof must never be
/// recorded (or sent) as a benign GET.
#[test]
fn hostcall_net_request_dispatch_frames_post_body_from_options_bd_3894s() {
    use frankenengine_extension_host::host_io::{
        HostIoRequest, InMemoryHostIoTranscript, SandboxedHostIo,
    };
    use std::io::{Read, Write};
    use std::time::Duration;

    // A loopback listener captures the bytes the egress writes so the test
    // proves the resolved method/headers/body crossed the socket. bd-3894s
    // slice (4): the round trip reads the (half-closed) request to EOF, then
    // replies and closes so the client's response read terminates.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().expect("listener addr");
    let server = std::thread::spawn(move || {
        let (mut stream, _peer) = listener.accept().expect("accept egress connection");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("server read timeout");
        let mut buf = Vec::new();
        let _ = stream.read_to_end(&mut buf);
        let _ = stream.write_all(
                b"HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: 4\r\n\r\ndone",
            );
        let _ = stream.flush();
        buf
    });

    let mut root = std::env::temp_dir();
    root.push(format!(
        "frankenengine_interp_net_post_{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).expect("scratch root");

    let provider = Arc::new(SandboxedHostIo::with_root(&root).expect("sandboxed provider"));
    let recorder = Arc::new(InMemoryHostIoTranscript::recording());
    let mut core = test_interpreter();
    let recorder_dyn: Arc<dyn HostIoRecorder> = recorder.clone();
    core.set_host_io(provider, Some(recorder_dyn));

    // reg0 = URL operand; reg1 = the options object the lowering now forwards as
    // arg[1]: `{ method: 'post', headers: { 'Content-Type': 'text/plain' },
    // body: 'payload' }`. The lowercase method also exercises the resolver's
    // Node-parity upper-casing.
    let url = format!("http://{addr}/submit");
    let options_id = core.mutate_heap(|h| {
        let headers_id = ObjectId(h.len() as u32);
        let mut headers = HeapObject::new();
        headers
            .properties
            .insert("Content-Type".to_string(), Value::str("text/plain"));
        h.push(headers);

        let options_id = ObjectId(h.len() as u32);
        let mut options = HeapObject::new();
        options
            .properties
            .insert("method".to_string(), Value::str("post"));
        options
            .properties
            .insert("headers".to_string(), Value::Object(headers_id));
        options
            .properties
            .insert("body".to_string(), Value::str("payload"));
        h.push(options);
        options_id
    });
    core.mutate_registers(|r| {
        if r.len() < 2 {
            r.resize(2, Value::Undefined);
        }
        r[0] = Value::Str(JsString::from(url.as_str()));
        r[1] = Value::Object(options_id);
    });

    // bd-3894s slice (4): the dispatch returns the parsed response object; the
    // framed/recorded request still faithfully carries the resolved POST + body.
    let result = core
        .dispatch_host_io_hostcall("net:request", RegRange { start: 0, count: 2 })
        .expect("net:request dispatch");
    let Value::Object(response_id) = result else {
        panic!("net:request must return a response object, got {result:?}");
    };
    let response = core
        .heap
        .get(response_id.0 as usize)
        .expect("response object on the heap");
    assert_eq!(
        response.properties.get("status"),
        Some(&Value::Int(201)),
        "the parsed response carries the numeric status code"
    );
    assert_eq!(
        response.properties.get("ok"),
        Some(&Value::Bool(true)),
        "a 2xx status reports ok = true"
    );
    assert_eq!(
        response.properties.get("body"),
        Some(&Value::str("done")),
        "the response body is decoded back to JS"
    );

    let received = server.join().expect("server thread");
    let wire = String::from_utf8_lossy(&received);
    assert!(
        wire.starts_with("POST /submit HTTP/1.1\r\n"),
        "the (upper-cased) method from the options object must frame the request line, got {wire:?}"
    );
    assert!(
        wire.contains(&format!("Host: {addr}\r\n")),
        "the Host header must carry the endpoint, got {wire:?}"
    );
    assert!(
        wire.contains("Content-Type: text/plain\r\n"),
        "the headers object must be framed onto the wire, got {wire:?}"
    );
    assert!(
        wire.contains("Content-Length: 7\r\n"),
        "the body length must be framed, got {wire:?}"
    );
    assert!(
        wire.ends_with("\r\n\r\npayload"),
        "the body from the options object must follow the blank-line terminator, got {wire:?}"
    );

    // The egress with the resolved method/body landed in the host-effect
    // transcript (the proof-carrying ledger source) — faithfully, not as a GET.
    let entries = recorder.recorded_entries();
    assert_eq!(entries.len(), 1, "exactly one host effect recorded");
    match &entries[0].0 {
        HostIoRequest::NetworkRequest {
            endpoint, payload, ..
        } => {
            assert_eq!(
                endpoint,
                &addr.to_string(),
                "endpoint resolves to host:port"
            );
            let recorded = String::from_utf8_lossy(payload);
            assert!(
                recorded.starts_with("POST /submit HTTP/1.1\r\n")
                    && recorded.ends_with("\r\n\r\npayload"),
                "the recorded effect must faithfully carry the POST + body, got {recorded:?}"
            );
        }
        other => panic!("expected a NetworkRequest host effect, got {other:?}"),
    }

    let _ = std::fs::remove_dir_all(&root);
}

/// bd-3894s slice (2b): `http.request(url, { method, headers, body })` builds a
/// writable `ClientRequest` object WITHOUT egressing. It captures the request
/// target, the (Node-parity upper-cased) method, the headers (as a child object
/// captured at construction time), seeds the writable `__body` buffer from any
/// `opts.body`, and is tagged `__type: "ClientRequest"` so `.write`/`.end`
/// resolve via member access.
#[test]
fn client_request_create_builds_writable_request_object_bd_3894s() {
    let mut core = test_interpreter();
    // http.request(url, { method: 'put', headers: { 'X-Trace': 'abc' },
    //                     body: 'seed' }) — lowercase method exercises the
    // resolver's Node-parity upper-casing.
    let url = "http://127.0.0.1:9/submit";
    let options_id = core.mutate_heap(|h| {
        let headers_id = ObjectId(h.len() as u32);
        let mut headers = HeapObject::new();
        headers
            .properties
            .insert("X-Trace".to_string(), Value::str("abc"));
        h.push(headers);

        let options_id = ObjectId(h.len() as u32);
        let mut options = HeapObject::new();
        options
            .properties
            .insert("method".to_string(), Value::str("put"));
        options
            .properties
            .insert("headers".to_string(), Value::Object(headers_id));
        options
            .properties
            .insert("body".to_string(), Value::str("seed"));
        h.push(options);
        options_id
    });
    core.mutate_registers(|r| {
        if r.len() < 2 {
            r.resize(2, Value::Undefined);
        }
        r[0] = Value::str(url);
        r[1] = Value::Object(options_id);
    });

    let req = core
        .dispatch_client_request_create(RegRange { start: 0, count: 2 })
        .expect("client request creation");
    let Value::Object(req_id) = req else {
        panic!("http.request must return a ClientRequest object, got {req:?}");
    };
    let obj = core
        .heap
        .get(req_id.0 as usize)
        .expect("request object on the heap");
    assert_eq!(
        obj.brand(),
        Some("ClientRequest"),
        "the object is branded ClientRequest so `.write`/`.end` resolve by member access"
    );
    assert_eq!(
        obj.properties.get("__url"),
        Some(&Value::str(url)),
        "captures the request URL"
    );
    assert_eq!(
        obj.properties.get("__method"),
        Some(&Value::str("PUT")),
        "the method is upper-cased per Node parity"
    );
    assert_eq!(
        obj.properties.get("__body"),
        Some(&Value::str("seed")),
        "the writable body buffer is seeded from opts.body"
    );
    assert_eq!(
        obj.properties.get("__ended"),
        Some(&Value::Bool(false)),
        "a fresh ClientRequest is not yet ended"
    );
    let Some(Value::Object(headers_id)) = obj.properties.get("__headers") else {
        panic!("headers must be captured as a child object");
    };
    let headers = core
        .heap
        .get(headers_id.0 as usize)
        .expect("captured headers object");
    assert_eq!(
        headers.properties.get("X-Trace"),
        Some(&Value::str("abc")),
        "headers are captured at construction time (a later options mutation cannot change them)"
    );
}

/// bd-3894s slice (2b): the writable-stream `ClientRequest` round trip —
/// `const req = http.request(url, { method, headers }); req.write(a);
/// req.write(b); req.end(c)` — frames the request body ACCUMULATED across the
/// `write`/`end` calls and performs the egress only on `.end()`. The egress goes
/// through the same sandboxed provider + recorder as the immediate `http.get`/
/// `fetch` forms, so the body lands on the wire AND in the signed host-effect
/// transcript with identical fidelity; `.end()` returns the parsed response.
#[test]
fn client_request_write_end_frames_accumulated_body_bd_3894s() {
    use frankenengine_extension_host::host_io::{
        HostIoRequest, InMemoryHostIoTranscript, SandboxedHostIo,
    };
    use std::io::{Read, Write};
    use std::time::Duration;

    // A loopback listener captures the framed request so the test proves the
    // accumulated write/end body crossed the socket, then replies + closes so
    // the client's response read terminates (the slice-4 round trip).
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().expect("listener addr");
    let server = std::thread::spawn(move || {
        let (mut stream, _peer) = listener.accept().expect("accept egress connection");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("server read timeout");
        let mut buf = Vec::new();
        let _ = stream.read_to_end(&mut buf);
        let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
        let _ = stream.flush();
        buf
    });

    let mut root = std::env::temp_dir();
    root.push(format!(
        "frankenengine_interp_clientreq_{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).expect("scratch root");

    let provider = Arc::new(SandboxedHostIo::with_root(&root).expect("sandboxed provider"));
    let recorder = Arc::new(InMemoryHostIoTranscript::recording());
    let mut core = test_interpreter();
    core.config
        .granted_capabilities
        .insert(RuntimeCapability::NetworkEgress);
    let recorder_dyn: Arc<dyn HostIoRecorder> = recorder.clone();
    core.set_host_io(provider, Some(recorder_dyn));

    // http.request(url, { method: 'POST', headers: { 'Content-Type':
    // 'text/plain' } }) — no body in the options; the body is built by writes.
    let url = format!("http://{addr}/submit");
    let options_id = core.mutate_heap(|h| {
        let headers_id = ObjectId(h.len() as u32);
        let mut headers = HeapObject::new();
        headers
            .properties
            .insert("Content-Type".to_string(), Value::str("text/plain"));
        h.push(headers);

        let options_id = ObjectId(h.len() as u32);
        let mut options = HeapObject::new();
        options
            .properties
            .insert("method".to_string(), Value::str("POST"));
        options
            .properties
            .insert("headers".to_string(), Value::Object(headers_id));
        h.push(options);
        options_id
    });
    core.mutate_registers(|r| {
        if r.len() < 2 {
            r.resize(2, Value::Undefined);
        }
        r[0] = Value::Str(JsString::from(url.as_str()));
        r[1] = Value::Object(options_id);
    });

    let req = core
        .dispatch_client_request_create(RegRange { start: 0, count: 2 })
        .expect("client request creation");
    let Value::Object(req_id) = req else {
        panic!("http.request must return a ClientRequest object, got {req:?}");
    };
    assert!(
        recorder.recorded_entries().is_empty(),
        "creating a ClientRequest must NOT egress — the egress is deferred to .end()"
    );

    let module = test_module_with_functions(vec![], vec![]);
    let write = BuiltinFunction::client_request_write();

    // req.write('Hello, ')
    core.write_reg_with_label(0, Value::str("Hello, "), Label::Public)
        .expect("public first request chunk");
    let w1 = core
        .dispatch_builtin_function(
            &module,
            &write,
            RegRange { start: 0, count: 1 },
            Some(Value::Object(req_id)),
            None,
        )
        .expect("req.write 1");
    assert_eq!(w1, Value::Bool(true), "req.write returns the boolean true");

    // req.write('world')
    core.write_reg_with_label(0, Value::str("world"), Label::Public)
        .expect("public second request chunk");
    core.dispatch_builtin_function(
        &module,
        &write,
        RegRange { start: 0, count: 1 },
        Some(Value::Object(req_id)),
        None,
    )
    .expect("req.write 2");

    assert!(
        recorder.recorded_entries().is_empty(),
        "writes before end() must NOT egress"
    );

    // req.end('!') — append the final chunk and perform the egress.
    let end = BuiltinFunction::client_request_end();
    core.write_reg_with_label(0, Value::str("!"), Label::Public)
        .expect("public final request chunk");
    let response = core
        .dispatch_builtin_function(
            &module,
            &end,
            RegRange { start: 0, count: 1 },
            Some(Value::Object(req_id)),
            None,
        )
        .expect("req.end");
    let Value::Object(response_id) = response else {
        panic!("req.end() must return the parsed response object, got {response:?}");
    };
    assert_eq!(
        core.take_pending_hostcall_result_label(),
        Some(Label::Internal),
        "a synchronous network response must carry the host-source floor"
    );
    let resp = core
        .heap
        .get(response_id.0 as usize)
        .expect("response object on the heap");
    assert_eq!(
        resp.properties.get("status"),
        Some(&Value::Int(200)),
        "end() returns the parsed response status"
    );
    assert_eq!(
        resp.properties.get("body"),
        Some(&Value::str("ok")),
        "end() returns the parsed response body"
    );

    // A second end() is an idempotent no-op (no second egress).
    let again = core
        .dispatch_builtin_function(
            &module,
            &end,
            RegRange { start: 0, count: 0 },
            Some(Value::Object(req_id)),
            None,
        )
        .expect("second req.end");
    assert_eq!(
        again,
        Value::Undefined,
        "a second end() is an idempotent no-op"
    );

    let received = server.join().expect("server thread");
    let wire = String::from_utf8_lossy(&received);
    assert!(
        wire.starts_with("POST /submit HTTP/1.1\r\n"),
        "the method from the options object frames the request line, got {wire:?}"
    );
    assert!(
        wire.contains("Content-Type: text/plain\r\n"),
        "the captured headers are framed onto the wire, got {wire:?}"
    );
    assert!(
        wire.contains("Content-Length: 13\r\n"),
        "the accumulated write/end body length must be framed, got {wire:?}"
    );
    assert!(
        wire.ends_with("\r\n\r\nHello, world!"),
        "the body accumulated across write/end must follow the blank-line terminator, got {wire:?}"
    );

    // Exactly one egress recorded in the signed transcript, carrying the body
    // — the proof-carrying ledger source for the write/end request.
    let entries = recorder.recorded_entries();
    assert_eq!(
        entries.len(),
        1,
        "exactly one host effect recorded — the deferred .end() egress"
    );
    match &entries[0].0 {
        HostIoRequest::NetworkRequest { payload, .. } => {
            let recorded = String::from_utf8_lossy(payload);
            assert!(
                recorded.ends_with("\r\n\r\nHello, world!"),
                "the recorded effect faithfully carries the write/end body, got {recorded:?}"
            );
        }
        other => panic!("expected a NetworkRequest host effect, got {other:?}"),
    }

    let _ = std::fs::remove_dir_all(&root);
}

/// bd-3894s slice (2c) (http leg, response callback): the `http.get(url, cb)` /
/// `http.get(url, opts, cb)` form lowers to a `net:request` HostCall carrying the
/// trailing callback closure as the last argument. When the dispatch sees that
/// trailing `Value::Closure` it (a) performs + records the real egress exactly as
/// the bare `http.get(url)` form does, (b) schedules the response callback as an
/// `IoCompletion` macrotask delivering `cb(res)` on the next event-loop turn (the
/// same deferral the fs async callback form uses), and (c) evaluates the call
/// itself to `undefined` (the async model). Verified against an in-process
/// loopback listener that replies + closes the round trip.
#[test]
fn net_request_with_response_callback_schedules_delivery_bd_3894s() {
    use frankenengine_extension_host::host_io::{InMemoryHostIoTranscript, SandboxedHostIo};
    use std::io::{Read, Write};
    use std::time::Duration;

    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().expect("listener addr");
    let server = std::thread::spawn(move || {
        let (mut stream, _peer) = listener.accept().expect("accept egress connection");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("server read timeout");
        let mut received = Vec::new();
        let _ = stream.read_to_end(&mut received);
        let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
        let _ = stream.flush();
        received
    });

    let mut root = std::env::temp_dir();
    root.push(format!(
        "frankenengine_interp_net_cb_{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).expect("scratch root");

    let provider = Arc::new(SandboxedHostIo::with_root(&root).expect("sandboxed provider"));
    let recorder = Arc::new(InMemoryHostIoTranscript::recording());
    let mut core = test_interpreter();
    let recorder_dyn: Arc<dyn HostIoRecorder> = recorder.clone();
    core.set_host_io(provider, Some(recorder_dyn));

    // reg0 = URL, reg1 = the response callback closure, exactly as the
    // `http.get(url, cb)` lowering forwards them (url + trailing closure).
    let url = format!("http://{addr}/");
    core.write_reg_with_label(0, Value::Str(JsString::from(url.as_str())), Label::Public)
        .expect("account for the request URL");
    core.write_reg_with_label(1, Value::Closure(0), Label::Public)
        .expect("account for the response callback");
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes(),
        "request inputs must be accounted before egress"
    );

    let result = core
        .dispatch_host_io_hostcall("net:request", RegRange { start: 0, count: 2 })
        .expect("net:request dispatch with a response callback");
    assert_eq!(
        result,
        Value::Undefined,
        "the callback form evaluates to undefined (cb(res) is delivered async)"
    );

    // The egress still happened and was recorded exactly once — the response
    // callback does not change the recorded effect.
    assert_eq!(
        recorder.recorded_entries().len(),
        1,
        "exactly one egress recorded for the callback form"
    );

    // The response callback was scheduled with the parsed response object — the
    // proof `cb(res)` will fire on the next event-loop turn with the REAL
    // response (status/body), not undefined.
    assert_eq!(
        core.pending_io_callbacks.len(),
        1,
        "the response callback must be scheduled as a pending IoCompletion macrotask"
    );
    let args = core
        .pending_io_callbacks
        .values()
        .next()
        .expect("a scheduled callback")
        .clone();
    assert_eq!(
        args.len(),
        1,
        "the http response callback is invoked with a single response arg (NOT err-first)"
    );
    let Value::Object(resp_id) = args[0] else {
        panic!(
            "the scheduled callback arg must be the response object, got {:?}",
            args[0]
        );
    };
    let resp = core
        .heap
        .get(resp_id.0 as usize)
        .expect("response object on the heap");
    assert_eq!(
        resp.properties.get("status"),
        Some(&Value::Int(200)),
        "cb(res) receives the parsed response status"
    );
    assert_eq!(
        resp.properties.get("body"),
        Some(&Value::str("ok")),
        "cb(res) receives the parsed response body"
    );
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes(),
        "labeled callback and stream tasks must be fully accounted"
    );
    let callback_task = core
        .event_loop
        .turn()
        .macrotask
        .expect("response callback task");
    assert_eq!(callback_task.label, Label::Internal);
    let stream_task = core
        .event_loop
        .turn()
        .macrotask
        .expect("response stream task");
    assert_eq!(stream_task.label, Label::Internal);

    let _ = server.join().expect("server thread");
    let _ = std::fs::remove_dir_all(&root);
}

/// bd-3894s slice (2c) (http leg, ClientRequest response callback): the
/// `http.request(url, opts, cb)` form captures the trailing callback as the
/// ClientRequest's `__response_cb` at construction (NO egress yet). When
/// `req.end()` performs the deferred egress and reads the response, the callback
/// is delivered `cb(res)` on the next event-loop turn and `.end()` evaluates to
/// `undefined` — vs. the no-callback form, which returns the response
/// synchronously (covered by
/// `client_request_write_end_frames_accumulated_body_bd_3894s`).
#[test]
fn client_request_with_response_callback_delivers_after_end_bd_3894s() {
    use frankenengine_extension_host::host_io::{InMemoryHostIoTranscript, SandboxedHostIo};
    use std::io::{Read, Write};
    use std::time::Duration;

    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().expect("listener addr");
    let server = std::thread::spawn(move || {
        let (mut stream, _peer) = listener.accept().expect("accept egress connection");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("server read timeout");
        let mut buf = Vec::new();
        let _ = stream.read_to_end(&mut buf);
        let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
        let _ = stream.flush();
        buf
    });

    let mut root = std::env::temp_dir();
    root.push(format!(
        "frankenengine_interp_clientreq_cb_{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).expect("scratch root");

    let provider = Arc::new(SandboxedHostIo::with_root(&root).expect("sandboxed provider"));
    let recorder = Arc::new(InMemoryHostIoTranscript::recording());
    let mut core = test_interpreter();
    core.config
        .granted_capabilities
        .insert(RuntimeCapability::NetworkEgress);
    let recorder_dyn: Arc<dyn HostIoRecorder> = recorder.clone();
    core.set_host_io(provider, Some(recorder_dyn));

    // http.request(url, { method: 'POST' }, cb): reg0 = url, reg1 = options,
    // reg2 = the response callback closure (the trailing arg).
    let url = format!("http://{addr}/submit");
    let options_id = core.mutate_heap(|h| {
        let options_id = ObjectId(h.len() as u32);
        let mut options = HeapObject::new();
        options
            .properties
            .insert("method".to_string(), Value::str("POST"));
        h.push(options);
        options_id
    });
    core.mutate_registers(|r| {
        if r.len() < 3 {
            r.resize(3, Value::Undefined);
        }
        r[0] = Value::Str(JsString::from(url.as_str()));
        r[1] = Value::Object(options_id);
        r[2] = Value::Closure(0);
    });

    let req = core
        .dispatch_client_request_create(RegRange { start: 0, count: 3 })
        .expect("client request creation with a response callback");
    let Value::Object(req_id) = req else {
        panic!("http.request must return a ClientRequest object, got {req:?}");
    };
    // The response callback is captured on the ClientRequest, NOT egressed yet.
    assert_eq!(
        core.heap
            .get(req_id.0 as usize)
            .and_then(|o| o.properties.get("__response_cb"))
            .cloned(),
        Some(Value::Closure(0)),
        "the response callback is captured as __response_cb at construction"
    );
    assert!(
        recorder.recorded_entries().is_empty(),
        "creating a ClientRequest must NOT egress — even with a response callback"
    );

    let module = test_module_with_functions(vec![], vec![]);
    core.write_reg_with_label(3, Value::str("public body"), Label::Public)
        .expect("write public request body register");
    let write = BuiltinFunction::client_request_write();
    let written = core
        .dispatch_builtin_function(
            &module,
            &write,
            RegRange { start: 3, count: 1 },
            Some(Value::Object(req_id)),
            None,
        )
        .expect("req.write with a public body");
    assert_eq!(written, Value::Bool(true));
    assert!(
        !core.object_mutation_labels.contains_key(&req_id),
        "public writes need no retained request label entry"
    );

    let end = BuiltinFunction::client_request_end();
    let ended = core
        .dispatch_builtin_function(
            &module,
            &end,
            RegRange { start: 0, count: 0 },
            Some(Value::Object(req_id)),
            None,
        )
        .expect("req.end with a registered response callback");
    assert_eq!(
        ended,
        Value::Undefined,
        "with a response callback, .end() evaluates to undefined (cb(res) is async)"
    );

    // Exactly one egress recorded by the deferred .end(), and the response
    // callback scheduled with the parsed response object.
    assert_eq!(
        recorder.recorded_entries().len(),
        1,
        "the deferred .end() egress is recorded exactly once"
    );
    assert_eq!(
        core.pending_http_tasks.len(),
        1,
        "the response callback must share the deferred logical response event"
    );
    let task = core
        .pending_http_tasks
        .values()
        .next()
        .expect("a scheduled response event");
    let PendingHttpTask::EmitLegacyEvent {
        target,
        event,
        arguments: args,
        leading_callback,
        label,
    } = task
    else {
        panic!("expected a deferred response event, got {task:?}");
    };
    assert_eq!(*target, req_id);
    assert_eq!(event, "response");
    assert_eq!(*leading_callback, Some(0));
    assert_eq!(label, &Label::Internal);
    let stream_registration = *core
        .pending_stream_emissions
        .keys()
        .next()
        .expect("a deferred response stream task");
    let mut saw_internal_stream = false;
    while let Some(macrotask) = core.event_loop.turn().macrotask {
        if macrotask.registration_seq == stream_registration {
            assert_eq!(macrotask.label, Label::Internal);
            saw_internal_stream = true;
            break;
        }
    }
    assert!(
        saw_internal_stream,
        "response stream task must retain the network source floor"
    );
    assert_eq!(
        args.len(),
        1,
        "cb(res) is invoked with a single response arg"
    );
    let Value::Object(resp_id) = &args[0] else {
        panic!(
            "the scheduled callback arg must be the response object, got {:?}",
            args[0]
        );
    };
    assert_eq!(
        core.heap
            .get(resp_id.0 as usize)
            .and_then(|o| o.properties.get("status"))
            .cloned(),
        Some(Value::Int(200)),
        "cb(res) receives the parsed response status"
    );

    let _ = server.join().expect("server thread");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn client_request_receiver_label_reaches_deferred_error_bd_z1peg() {
    use frankenengine_extension_host::host_io::InMemoryHostIoTranscript;

    let mut core = test_interpreter();
    core.config
        .granted_capabilities
        .insert(RuntimeCapability::NetworkEgress);
    let recorder = Arc::new(InMemoryHostIoTranscript::recording());
    let recorder_dyn: Arc<dyn HostIoRecorder> = recorder.clone();
    core.host_io_recorder = Some(recorder_dyn);
    core.write_reg_with_label(0, Value::str("http://127.0.0.1:9/"), Label::Public)
        .expect("request URL");
    let request = core
        .dispatch_client_request_create(RegRange { start: 0, count: 1 })
        .expect("client request creation");
    let Value::Object(request_id) = request else {
        panic!("http.request must return a ClientRequest object, got {request:?}");
    };
    core.write_reg_with_label(1, Value::Object(request_id), Label::Secret)
        .expect("classified request alias");

    let module = test_module_with_functions(Vec::new(), Vec::new());
    let ended = core
        .dispatch_builtin_function(
            &module,
            &BuiltinFunction::client_request_end(),
            RegRange { start: 0, count: 0 },
            Some(Value::Object(request_id)),
            Some(1),
        )
        .expect("classified request alias end");
    assert_eq!(ended, Value::Undefined);
    assert_eq!(
        core.object_mutation_labels.get(&request_id),
        Some(&Label::Secret),
        "the receiver register must join the retained request lifecycle"
    );
    let task = core
        .pending_http_tasks
        .values()
        .next()
        .expect("provider-free end must schedule a deferred error event");
    let PendingHttpTask::EmitLegacyEvent { event, label, .. } = task else {
        panic!("expected a deferred request error, got {task:?}");
    };
    assert_eq!(event, "error");
    assert_eq!(label, &Label::Secret);
    let entries = recorder.recorded_entries();
    assert_eq!(
        entries.len(),
        1,
        "classified egress refusal must be evidenced"
    );
    assert!(matches!(entries[0].0, HostIoRequest::NetworkRequest { .. }));
    assert_eq!(
        entries[0].1,
        Err(HostIoError::Denied {
            reason: DEFERRED_NETWORK_FLOW_POLICY_DENIAL.to_string(),
        })
    );
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn legacy_client_request_body_is_bounded_and_failure_atomic_bd_z1peg_2() {
    let module = test_module_with_functions(Vec::new(), Vec::new());
    let mut core = test_interpreter();
    core.config
        .granted_capabilities
        .insert(RuntimeCapability::NetworkEgress);
    core.write_reg(0, Value::str("http://127.0.0.1:9/"))
        .expect("request URL");
    let Value::Object(request) = core
        .dispatch_client_request_create(RegRange { start: 0, count: 1 })
        .expect("empty client request")
    else {
        panic!("expected ClientRequest")
    };

    let first_chunk_len = MAX_HTTP_BODY_BYTES / 2;
    core.write_reg(1, Value::str("x".repeat(first_chunk_len)))
        .expect("first body chunk");
    assert_eq!(
        core.dispatch_builtin_function(
            &module,
            &BuiltinFunction::client_request_write(),
            RegRange { start: 1, count: 1 },
            Some(Value::Object(request)),
            None,
        ),
        Ok(Value::Bool(true))
    );
    assert_eq!(
        core.heap[request.0 as usize]
            .properties
            .get("__body")
            .and_then(|value| match value {
                Value::Str(body) => Some(body.len()),
                _ => None,
            }),
        Some(first_chunk_len)
    );
    core.write_reg(
        1,
        Value::str("x".repeat(MAX_HTTP_BODY_BYTES - first_chunk_len)),
    )
    .expect("final boundary body chunk");
    assert_eq!(
        core.dispatch_builtin_function(
            &module,
            &BuiltinFunction::client_request_write(),
            RegRange { start: 1, count: 1 },
            Some(Value::Object(request)),
            None,
        ),
        Ok(Value::Bool(true))
    );
    assert_eq!(
        core.heap[request.0 as usize]
            .properties
            .get("__body")
            .and_then(|value| match value {
                Value::Str(body) => Some(body.len()),
                _ => None,
            }),
        Some(MAX_HTTP_BODY_BYTES)
    );
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );

    core.write_reg(1, Value::str("y")).expect("overflow byte");
    let before_body = core.heap[request.0 as usize]
        .properties
        .get("__body")
        .cloned()
        .expect("request body state");
    let before_label = core.object_mutation_labels.get(&request).cloned();
    let before_memory = core.estimated_memory_bytes();
    let write_error = core
        .dispatch_builtin_function(
            &module,
            &BuiltinFunction::client_request_write(),
            RegRange { start: 1, count: 1 },
            Some(Value::Object(request)),
            None,
        )
        .expect_err("one byte beyond the body ceiling must fail");
    assert!(matches!(write_error, InterpreterError::RangeError { .. }));
    assert_eq!(
        core.heap[request.0 as usize].properties.get("__body"),
        Some(&before_body)
    );
    assert_eq!(
        core.object_mutation_labels.get(&request).cloned(),
        before_label
    );
    assert_eq!(core.estimated_memory_bytes(), before_memory);

    let end_error = core
        .dispatch_builtin_function(
            &module,
            &BuiltinFunction::client_request_end(),
            RegRange { start: 1, count: 1 },
            Some(Value::Object(request)),
            None,
        )
        .expect_err("an oversized final chunk must fail before ending");
    assert!(matches!(end_error, InterpreterError::RangeError { .. }));
    assert_eq!(
        core.heap[request.0 as usize].properties.get("__ended"),
        Some(&Value::Bool(false))
    );
    assert!(core.pending_http_tasks.is_empty());
    assert_eq!(core.estimated_memory_bytes(), before_memory);
    assert_eq!(before_memory, core.recompute_estimated_memory_bytes());

    core.set_object_property(
        request,
        "__body".to_string(),
        Value::str("z".repeat(MAX_HTTP_BODY_BYTES + 1)),
    )
    .expect("direct body mutation remains within the interpreter memory budget");
    let directly_mutated_body = core.heap[request.0 as usize]
        .properties
        .get("__body")
        .cloned()
        .expect("directly mutated request body state");
    let direct_mutation_memory = core.estimated_memory_bytes();
    let direct_mutation_error = core
        .dispatch_builtin_function(
            &module,
            &BuiltinFunction::client_request_end(),
            RegRange { start: 0, count: 0 },
            Some(Value::Object(request)),
            None,
        )
        .expect_err("direct internal-slot mutation must not bypass the body ceiling");
    assert!(matches!(
        direct_mutation_error,
        InterpreterError::RangeError { .. }
    ));
    assert_eq!(
        core.heap[request.0 as usize].properties.get("__body"),
        Some(&directly_mutated_body)
    );
    assert_eq!(
        core.heap[request.0 as usize].properties.get("__ended"),
        Some(&Value::Bool(false))
    );
    assert_eq!(core.estimated_memory_bytes(), direct_mutation_memory);
    assert_eq!(
        direct_mutation_memory,
        core.recompute_estimated_memory_bytes()
    );

    let mut memory_limited = test_interpreter();
    memory_limited
        .write_reg(0, Value::str("http://127.0.0.1:9/"))
        .expect("request URL");
    let Value::Object(limited_request) = memory_limited
        .dispatch_client_request_create(RegRange { start: 0, count: 1 })
        .expect("memory-limited client request")
    else {
        panic!("expected ClientRequest")
    };
    memory_limited
        .write_reg_with_label(1, Value::str("z"), Label::Secret)
        .expect("classified chunk");
    let limited_before = memory_limited.estimated_memory_bytes();
    let exact_temporary_peak = 2_u64
        .saturating_add(InterpreterCore::estimate_label_bytes(&Label::Public).saturating_mul(2))
        .saturating_add(InterpreterCore::estimate_label_bytes(&Label::Secret).saturating_mul(2))
        .saturating_add(64 * 1024);
    memory_limited.config.max_total_memory_bytes = limited_before
        .saturating_add(exact_temporary_peak)
        .saturating_sub(1);
    let memory_error = memory_limited
        .dispatch_builtin_function(
            &module,
            &BuiltinFunction::client_request_write(),
            RegRange { start: 1, count: 1 },
            Some(Value::Object(limited_request)),
            None,
        )
        .expect_err("temporary append peak must respect the memory budget");
    assert!(matches!(
        memory_error,
        InterpreterError::MemoryBudgetExceeded { .. }
    ));
    assert_eq!(
        memory_limited.heap[limited_request.0 as usize]
            .properties
            .get("__body"),
        Some(&Value::str(""))
    );
    assert!(
        !memory_limited
            .object_mutation_labels
            .contains_key(&limited_request)
    );
    assert_eq!(memory_limited.estimated_memory_bytes(), limited_before);
    assert_eq!(
        limited_before,
        memory_limited.recompute_estimated_memory_bytes()
    );
    memory_limited.config.max_total_memory_bytes =
        limited_before.saturating_add(exact_temporary_peak);
    assert_eq!(
        memory_limited.dispatch_builtin_function(
            &module,
            &BuiltinFunction::client_request_write(),
            RegRange { start: 1, count: 1 },
            Some(Value::Object(limited_request)),
            None,
        ),
        Ok(Value::Bool(true)),
        "the exact temporary-memory boundary must remain admissible"
    );
    assert_eq!(
        memory_limited.heap[limited_request.0 as usize]
            .properties
            .get("__body"),
        Some(&Value::str("z"))
    );
    assert_eq!(
        memory_limited.object_mutation_labels.get(&limited_request),
        Some(&Label::Secret)
    );
    assert_eq!(
        memory_limited.estimated_memory_bytes(),
        memory_limited.recompute_estimated_memory_bytes()
    );

    let mut oversized_initial = test_interpreter();
    let options = oversized_initial
        .alloc_object_with_properties(&[("body", Value::str("x".repeat(MAX_HTTP_BODY_BYTES + 1)))])
        .expect("oversized options object fits the interpreter budget");
    oversized_initial
        .write_reg(0, Value::str("http://127.0.0.1:9/"))
        .expect("request URL");
    oversized_initial
        .write_reg(1, Value::Object(options))
        .expect("request options");
    let heap_len_before = oversized_initial.heap.len();
    let initial_error = oversized_initial
        .dispatch_client_request_create(RegRange { start: 0, count: 2 })
        .expect_err("oversized opts.body must fail before request allocation");
    assert!(matches!(initial_error, InterpreterError::RangeError { .. }));
    assert_eq!(oversized_initial.heap.len(), heap_len_before);
    assert_eq!(
        oversized_initial.estimated_memory_bytes(),
        oversized_initial.recompute_estimated_memory_bytes()
    );
}

#[test]
fn legacy_client_request_end_rechecks_authority_before_mutation_or_provider() {
    use frankenengine_extension_host::host_io::{HostIoCapability, InMemoryHostIoTranscript};
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Debug)]
    struct NeverNetworkProvider(Arc<AtomicUsize>);

    impl HostIoProvider for NeverNetworkProvider {
        fn name(&self) -> &str {
            "never-network-after-authority-denial"
        }

        fn perform(
            &self,
            _request: &HostIoRequest,
            _granted: &[HostIoCapability],
        ) -> HostIoOutcome {
            self.0.fetch_add(1, Ordering::SeqCst);
            panic!("authority-denied deferred request reached the provider")
        }
    }

    for grant_at_construction in [false, true] {
        let mut core = test_interpreter();
        let calls = Arc::new(AtomicUsize::new(0));
        let recorder = Arc::new(InMemoryHostIoTranscript::recording());
        let recorder_dyn: Arc<dyn HostIoRecorder> = recorder.clone();
        core.set_host_io(
            Arc::new(NeverNetworkProvider(calls.clone())),
            Some(recorder_dyn),
        );
        if grant_at_construction {
            core.config
                .granted_capabilities
                .insert(RuntimeCapability::NetworkEgress);
            check_hostcall_capability_gate(&mut core, "net:client_request", 0)
                .expect("construction is authorized before later revocation");
        }
        core.write_reg(0, Value::str("http://127.0.0.1:9/"))
            .expect("request URL");
        // Seed the deferred state directly to cover both a withheld grant
        // and a grant revoked after authorized construction.
        let Value::Object(request) = core
            .dispatch_client_request_create(RegRange { start: 0, count: 1 })
            .expect("buffered request")
        else {
            panic!("expected ClientRequest")
        };
        let module = test_module_with_functions(Vec::new(), Vec::new());
        core.write_reg(1, Value::str("prefix"))
            .expect("buffered body prefix");
        core.dispatch_builtin_function(
            &module,
            &BuiltinFunction::client_request_write(),
            RegRange { start: 1, count: 1 },
            Some(Value::Object(request)),
            None,
        )
        .expect("buffering does not egress");
        core.config
            .granted_capabilities
            .remove(&RuntimeCapability::NetworkEgress);
        core.write_reg_with_label(1, Value::str("classified suffix"), Label::Secret)
            .expect("final chunk");
        let before_properties = core.heap[request.0 as usize].properties.clone();
        let before_label = core.object_mutation_labels.get(&request).cloned();
        let before_decisions = core.hostcall_decisions.len();
        let error = core
            .dispatch_builtin_function(
                &module,
                &BuiltinFunction::client_request_end(),
                RegRange { start: 1, count: 1 },
                Some(Value::Object(request)),
                None,
            )
            .expect_err("withheld or revoked authority must stop deferred egress");
        assert!(matches!(
            error,
            InterpreterError::CapabilityDenied { capability } if capability == "net:request"
        ));
        assert_eq!(core.heap[request.0 as usize].properties, before_properties);
        assert_eq!(
            core.object_mutation_labels.get(&request).cloned(),
            before_label
        );
        assert!(core.pending_http_tasks.is_empty());
        assert!(core.pending_stream_emissions.is_empty());
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(recorder.recorded_entries().is_empty());
        assert_eq!(core.hostcall_decisions.len(), before_decisions + 1);
        let denial = core.hostcall_decisions.last().expect("authority evidence");
        assert_eq!(denial.capability.0, "net:request");
        assert!(!denial.allowed);
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }
}

#[test]
fn legacy_client_request_ifc_denial_is_recorded_before_provider_bd_z1peg_2() {
    use frankenengine_extension_host::host_io::{
        HostIoCapability, HostIoRequest, InMemoryHostIoTranscript,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Debug)]
    struct NeverNetworkProvider {
        calls: Arc<AtomicUsize>,
    }

    impl HostIoProvider for NeverNetworkProvider {
        fn name(&self) -> &str {
            "never-network-after-ifc-denial"
        }

        fn perform(
            &self,
            _request: &HostIoRequest,
            _granted: &[HostIoCapability],
        ) -> HostIoOutcome {
            self.calls.fetch_add(1, Ordering::SeqCst);
            panic!("IFC-denied deferred request reached the live provider")
        }
    }

    let calls = Arc::new(AtomicUsize::new(0));
    let recorder = Arc::new(InMemoryHostIoTranscript::recording());
    let provider: Arc<dyn HostIoProvider> = Arc::new(NeverNetworkProvider {
        calls: calls.clone(),
    });
    let recorder_dyn: Arc<dyn HostIoRecorder> = recorder.clone();
    let mut core = test_interpreter();
    core.config
        .granted_capabilities
        .insert(RuntimeCapability::NetworkEgress);
    core.set_host_io(provider, Some(recorder_dyn));
    let module = test_module_with_functions(Vec::new(), Vec::new());

    core.write_reg(0, Value::str("http://127.0.0.1:9/body"))
        .expect("body request URL");
    let Value::Object(body_request) = core
        .dispatch_client_request_create(RegRange { start: 0, count: 1 })
        .expect("body request")
    else {
        panic!("expected ClientRequest")
    };
    core.write_reg_with_label(1, Value::str("classified"), Label::Secret)
        .expect("classified body");
    core.dispatch_builtin_function(
        &module,
        &BuiltinFunction::client_request_write(),
        RegRange { start: 1, count: 1 },
        Some(Value::Object(body_request)),
        None,
    )
    .expect("buffer classified body before deferred denial");
    assert_eq!(
        core.dispatch_builtin_function(
            &module,
            &BuiltinFunction::client_request_end(),
            RegRange { start: 0, count: 0 },
            Some(Value::Object(body_request)),
            None,
        ),
        Ok(Value::Undefined)
    );

    let captured_headers = core
        .alloc_object_with_properties(&[("X-Trace", Value::str("public"))])
        .expect("headers");
    let options = core
        .alloc_object_with_properties(&[("headers", Value::Object(captured_headers))])
        .expect("options");
    core.write_reg(0, Value::str("http://127.0.0.1:9/header"))
        .expect("header request URL");
    core.write_reg(1, Value::Object(options))
        .expect("header request options");
    let Value::Object(header_request) = core
        .dispatch_client_request_create(RegRange { start: 0, count: 2 })
        .expect("header request")
    else {
        panic!("expected ClientRequest")
    };
    let captured_headers = match core.heap[header_request.0 as usize]
        .properties
        .get("__headers")
    {
        Some(Value::Object(headers)) => *headers,
        other => panic!("expected captured headers object, got {other:?}"),
    };
    core.join_object_mutation_label(captured_headers, &Label::Secret)
        .expect("classified captured header state");
    assert_eq!(
        core.dispatch_builtin_function(
            &module,
            &BuiltinFunction::client_request_end(),
            RegRange { start: 0, count: 0 },
            Some(Value::Object(header_request)),
            None,
        ),
        Ok(Value::Undefined)
    );

    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let entries = recorder.recorded_entries();
    assert_eq!(entries.len(), 2, "both classified requests are evidenced");
    for (request, outcome) in &entries {
        assert!(matches!(request, HostIoRequest::NetworkRequest { .. }));
        assert_eq!(
            outcome,
            &Err(HostIoError::Denied {
                reason: DEFERRED_NETWORK_FLOW_POLICY_DENIAL.to_string(),
            })
        );
    }
    let HostIoRequest::NetworkRequest { payload, .. } = &entries[0].0 else {
        unreachable!()
    };
    assert!(
        payload.ends_with(b"\r\n\r\nclassified"),
        "denial evidence must bind the exact refused body"
    );
    assert_eq!(core.pending_http_tasks.len(), 2);
    assert!(core.pending_http_tasks.values().all(|task| matches!(
        task,
        PendingHttpTask::EmitLegacyEvent { event, label, .. }
            if event == "error" && label == &Label::Secret
    )));
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );

    let mut missing_evidence = test_interpreter();
    missing_evidence
        .config
        .granted_capabilities
        .insert(RuntimeCapability::NetworkEgress);
    let missing_evidence_provider: Arc<dyn HostIoProvider> = Arc::new(NeverNetworkProvider {
        calls: calls.clone(),
    });
    missing_evidence.set_host_io(missing_evidence_provider, None);
    missing_evidence
        .write_reg(0, Value::str("http://127.0.0.1:9/no-evidence"))
        .expect("request URL");
    let Value::Object(missing_evidence_request) = missing_evidence
        .dispatch_client_request_create(RegRange { start: 0, count: 1 })
        .expect("request without evidence sink")
    else {
        panic!("expected ClientRequest")
    };
    missing_evidence
        .write_reg_with_label(1, Value::str("classified"), Label::Secret)
        .expect("classified body");
    missing_evidence
        .dispatch_builtin_function(
            &module,
            &BuiltinFunction::client_request_write(),
            RegRange { start: 1, count: 1 },
            Some(Value::Object(missing_evidence_request)),
            None,
        )
        .expect("buffer classified body");
    let missing_evidence_error = missing_evidence
        .dispatch_builtin_function(
            &module,
            &BuiltinFunction::client_request_end(),
            RegRange { start: 0, count: 0 },
            Some(Value::Object(missing_evidence_request)),
            None,
        )
        .expect_err("an IFC refusal without an evidence sink must fail closed");
    assert!(matches!(
        missing_evidence_error,
        InterpreterError::InternalError { details }
            if details.contains("no host-effect evidence sink")
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        missing_evidence.heap[missing_evidence_request.0 as usize]
            .properties
            .get("__ended"),
        Some(&Value::Bool(false)),
        "a refusal that could not be evidenced must not consume the request"
    );
    assert!(missing_evidence.pending_http_tasks.is_empty());
    assert_eq!(
        missing_evidence.estimated_memory_bytes(),
        missing_evidence.recompute_estimated_memory_bytes()
    );
}

#[test]
fn native_http_client_request_ifc_denial_is_recorded_and_deferred() {
    use frankenengine_extension_host::host_io::{InMemoryHostIoTranscript, SandboxedHostIo};

    for secret_header in [false, true] {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("egress sentinel");
        listener
            .set_nonblocking(true)
            .expect("nonblocking sentinel");
        let address = listener.local_addr().expect("sentinel address");
        let root = tempfile::TempDir::new().expect("provider root");
        let recorder = Arc::new(InMemoryHostIoTranscript::recording());
        let mut core = test_interpreter();
        core.config
            .granted_capabilities
            .insert(RuntimeCapability::NetworkEgress);
        core.set_host_io(
            Arc::new(SandboxedHostIo::with_root(root.path()).expect("real provider")),
            Some(recorder.clone()),
        );
        core.write_reg_with_label(
            0,
            Value::str(format!("http://{address}/refused")),
            Label::Public,
        )
        .expect("public endpoint");
        let Value::Object(request) = core
            .construct_http_client_request(RegRange { start: 0, count: 1 }, false)
            .expect("native request")
        else {
            panic!("expected native HTTP request")
        };
        core.write_reg_with_label(1, Value::str("X-Private"), Label::Public)
            .expect("header name");
        core.write_reg_with_label(2, Value::str("classified"), Label::Secret)
            .expect("classified bytes");
        if secret_header {
            core.http_set_header(
                Some(Value::Object(request)),
                RegRange { start: 1, count: 2 },
                true,
                None,
            )
            .expect("buffer classified header");
        } else {
            core.http_client_write(
                Some(Value::Object(request)),
                RegRange { start: 2, count: 1 },
                None,
            )
            .expect("buffer classified body");
        }
        assert!(recorder.recorded_entries().is_empty());
        assert_eq!(
            core.finish_http_client_request(request),
            Ok(Value::Undefined)
        );
        assert_eq!(
            core.finish_http_client_request(request),
            Ok(Value::Undefined)
        );
        assert!(core.http_client_requests[&request].ended);
        assert!(
            matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
        );
        let entries = recorder.recorded_entries();
        assert_eq!(
            entries.len(),
            1,
            "repeated end must not repeat denial evidence"
        );
        let HostIoRequest::NetworkRequest {
            endpoint,
            payload,
            use_tls,
            ..
        } = &entries[0].0
        else {
            panic!("expected exact typed network denial")
        };
        assert_eq!(endpoint, &address.to_string());
        assert!(!use_tls);
        if secret_header {
            assert!(
                payload
                    .windows(b"X-Private: classified\r\n".len())
                    .any(|window| window == b"X-Private: classified\r\n")
            );
        } else {
            assert!(payload.ends_with(b"\r\n\r\nclassified"));
        }
        assert_eq!(
            entries[0].1,
            Err(HostIoError::Denied {
                reason: DEFERRED_NETWORK_FLOW_POLICY_DENIAL.to_string()
            })
        );
        assert_eq!(core.pending_http_tasks.len(), 1);
        assert!(
            matches!(core.pending_http_tasks.values().next(), Some(PendingHttpTask::ClientError { request: target, code, label })
                if *target == request && code == "ERR_NETWORK" && label == &Label::Secret)
        );
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }
}

#[test]
fn native_http_client_request_denial_evidence_failure_is_atomic() {
    use frankenengine_extension_host::host_io::{InMemoryHostIoTranscript, SandboxedHostIo};

    // Missing evidence, a contradictory replay outcome, and revoked authority
    // must all fail without publishing the reserved error task or ending the request.
    for failure in 0..3 {
        let root = tempfile::TempDir::new().expect("provider root");
        let mut core = test_interpreter();
        core.config
            .granted_capabilities
            .insert(RuntimeCapability::NetworkEgress);
        let recorder = if failure == 1 {
            Arc::new(InMemoryHostIoTranscript::replaying(vec![(
                create_network_host_io_request(
                    "http://127.0.0.1:9/refused",
                    "GET",
                    &[],
                    Some(b"classified"),
                ),
                Err(HostIoError::Denied {
                    reason: "different-policy".to_string(),
                }),
            )]))
        } else {
            Arc::new(InMemoryHostIoTranscript::recording())
        };
        recorder.begin_execution().expect("begin evidence session");
        let evidence: Option<Arc<dyn HostIoRecorder>> = if failure == 0 {
            None
        } else {
            Some(recorder.clone())
        };
        core.set_host_io(
            Arc::new(SandboxedHostIo::with_root(root.path()).expect("real provider")),
            evidence,
        );
        core.write_reg_with_label(0, Value::str("http://127.0.0.1:9/refused"), Label::Public)
            .expect("endpoint");
        let Value::Object(request) = core
            .construct_http_client_request(RegRange { start: 0, count: 1 }, false)
            .expect("request")
        else {
            panic!("expected native HTTP request")
        };
        core.write_reg_with_label(1, Value::str("classified"), Label::Secret)
            .expect("classified body");
        core.http_client_write(
            Some(Value::Object(request)),
            RegRange { start: 1, count: 1 },
            None,
        )
        .expect("buffer body");
        if failure == 2 {
            core.config
                .granted_capabilities
                .remove(&RuntimeCapability::NetworkEgress);
        }
        let error = core
            .finish_http_client_request(request)
            .expect_err("unevidenced or unauthorized refusal must fail closed");
        match failure {
            0 => assert!(
                matches!(error, InterpreterError::InternalError { details } if details.contains("no host-effect evidence sink"))
            ),
            1 => assert!(
                matches!(error, InterpreterError::InternalError { details } if details.contains("transcript mismatch"))
            ),
            _ => assert!(
                matches!(error, InterpreterError::CapabilityDenied { capability } if capability == "net:request")
            ),
        }
        assert!(!core.http_client_requests[&request].ended);
        assert_eq!(
            core.heap[request.0 as usize]
                .properties
                .get("writableEnded"),
            Some(&Value::Bool(false))
        );
        assert!(core.pending_http_tasks.is_empty());
        if failure != 1 {
            assert!(recorder.recorded_entries().is_empty());
        }
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }
}

#[test]
fn native_http_client_request_public_body_reaches_real_socket() {
    use frankenengine_extension_host::host_io::{InMemoryHostIoTranscript, SandboxedHostIo};
    use std::io::{Read, Write};
    use std::time::{Duration, Instant};

    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("public sink");
    listener.set_nonblocking(true).expect("bounded accept");
    let address = listener.local_addr().expect("sink address");
    let server = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        && Instant::now() < deadline =>
                {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("public request did not reach the socket: {error}"),
            }
        };
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("read bound");
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .expect("write bound");
        let mut bytes = Vec::new();
        (&mut stream)
            .take(65536)
            .read_to_end(&mut bytes)
            .expect("request bytes");
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            .expect("response bytes");
        bytes
    });
    let root = tempfile::TempDir::new().expect("provider root");
    let recorder = Arc::new(InMemoryHostIoTranscript::recording());
    let mut core = test_interpreter();
    core.config
        .granted_capabilities
        .insert(RuntimeCapability::NetworkEgress);
    core.set_host_io(
        Arc::new(SandboxedHostIo::with_root(root.path()).expect("real provider")),
        Some(recorder.clone()),
    );
    let options = core
        .alloc_object_with_properties(&[("method", Value::str("POST"))])
        .expect("POST options");
    core.write_reg_with_label(
        0,
        Value::str(format!("http://{address}/public")),
        Label::Public,
    )
    .expect("public endpoint");
    core.write_reg_with_label(1, Value::Object(options), Label::Public)
        .expect("public options");
    let Value::Object(request) = core
        .construct_http_client_request(RegRange { start: 0, count: 2 }, false)
        .expect("public native request")
    else {
        panic!("expected native HTTP request")
    };
    core.write_reg_with_label(2, Value::str("Hello, "), Label::Public)
        .expect("public first chunk");
    core.http_client_write(
        Some(Value::Object(request)),
        RegRange { start: 2, count: 1 },
        None,
    )
    .expect("first write");
    core.write_reg_with_label(2, Value::str("world!"), Label::Public)
        .expect("public final chunk");
    assert_eq!(
        core.http_client_end(
            Some(Value::Object(request)),
            RegRange { start: 2, count: 1 },
            None,
        ),
        Ok(Value::Undefined)
    );
    let bytes = server.join().expect("bounded public sink");
    assert!(bytes.starts_with(b"POST /public HTTP/1.1\r\n"));
    assert!(bytes.ends_with(b"\r\n\r\nHello, world!"));
    let entries = recorder.recorded_entries();
    assert_eq!(entries.len(), 1);
    assert!(entries[0].1.is_ok());
    assert!(core.http_client_requests[&request].ended);
    assert!(
        matches!(core.pending_http_tasks.values().next(), Some(PendingHttpTask::DeliverExternalResponse { request: target, response: Some(_) }) if *target == request)
    );
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

/// bd-656a2 (http leg, denied path): when the installed host-I/O provider
/// DENIES a `net:request` egress (the franken_node SSRF gate blocking a
/// forbidden endpoint, e.g. cloud metadata), the interpreter dispatch must NOT
/// abort the run with a fatal error — that would discard the whole host-effect
/// transcript before it is harvested into the ledger. Instead it records the
/// fail-closed denial in the transcript (the run --json denied receipt) and
/// evaluates the call to `undefined`, so the program completes and the signed
/// denial is surfaced. fs effects keep their prior fatal-on-error semantics;
/// only the guest-triggerable network paths (policy-deny, and — bd-3894s
/// slice 5 — mechanism I/O failure) are made non-fatal.
#[test]
fn hostcall_net_request_denied_records_and_continues_bd_656a2() {
    use frankenengine_extension_host::host_io::{
        HostIoCapability, HostIoError, HostIoOutcome, HostIoProvider, HostIoRequest,
        HostIoResponse, InMemoryHostIoTranscript,
    };

    /// A provider that fails every network egress closed (mirrors the SSRF
    /// gate denying a blocked endpoint) and no-ops fs.
    #[derive(Debug)]
    struct DenyNetworkHostIo;
    impl HostIoProvider for DenyNetworkHostIo {
        fn name(&self) -> &str {
            "deny-network"
        }
        fn perform(&self, request: &HostIoRequest, _granted: &[HostIoCapability]) -> HostIoOutcome {
            match request {
                HostIoRequest::NetworkSend { .. }
                | HostIoRequest::NetworkRecv { .. }
                | HostIoRequest::NetworkRequest { .. } => Err(HostIoError::Denied {
                    reason: "ssrf: endpoint blocked by policy".to_string(),
                }),
                HostIoRequest::EnvRead { .. } => Err(HostIoError::Denied {
                    reason: "environment is outside the network fixture".to_string(),
                }),
                HostIoRequest::FsRead { .. } => Ok(HostIoResponse::FsRead { bytes: Vec::new() }),
                HostIoRequest::FsWrite { .. } => Ok(HostIoResponse::FsWrite { bytes_written: 0 }),
                HostIoRequest::FsMeta { .. } => Ok(HostIoResponse::FsMeta {
                    result: FsMetaResult::Unit,
                }),
                HostIoRequest::RandomRead { byte_len } => Ok(HostIoResponse::RandomRead {
                    bytes: vec![0; *byte_len as usize],
                }),
            }
        }
    }

    let recorder = Arc::new(InMemoryHostIoTranscript::recording());
    let mut core = test_interpreter();
    let recorder_dyn: Arc<dyn HostIoRecorder> = recorder.clone();
    core.set_host_io(Arc::new(DenyNetworkHostIo), Some(recorder_dyn));

    // reg0 = a blocked endpoint (cloud metadata), as the http.get(url) lowering
    // forwards it.
    core.mutate_registers(|r| {
        r[0] = Value::Str(JsString::from("http://169.254.169.254/latest/meta-data/"));
    });

    // The denied egress must NOT fault the interpreter: the dispatch returns
    // `undefined` and the run continues so the transcript can be harvested.
    let result = core
        .dispatch_host_io_hostcall("net:request", RegRange { start: 0, count: 1 })
        .expect("a policy-denied net:request must not abort the run");
    assert_eq!(
        result,
        Value::Undefined,
        "a denied egress evaluates to undefined (no async error event modeled)"
    );

    // The denial is recorded as a fail-closed NetworkRequest Err — the source
    // of the ledger's denied receipt.
    let entries = recorder.recorded_entries();
    assert_eq!(
        entries.len(),
        1,
        "the denied egress must still be recorded for the ledger"
    );
    assert!(
        matches!(entries[0].0, HostIoRequest::NetworkRequest { .. }),
        "the recorded request is the attempted egress"
    );
    assert!(
        entries[0].1.is_err(),
        "the recorded outcome must be the fail-closed denial"
    );
}

/// bd-3894s slice (5): a network-mechanism I/O failure (TLS handshake or
/// certificate rejection, connect refused, timeout) surfaces as the
/// provider's `HostIoError::Io`. Like the policy-deny path above, it must
/// NOT abort the run — the failed outcome is already recorded in the
/// transcript (the source of the ledger's fail-closed receipt), the call
/// evaluates to `undefined` (no fabricated response), and the run completes
/// so the evidence is surfaced instead of discarded.
#[test]
fn hostcall_net_request_io_failure_records_and_continues_bd_3894s() {
    use frankenengine_extension_host::host_io::{
        HostIoCapability, HostIoError, HostIoOutcome, HostIoProvider, HostIoRequest,
        HostIoResponse, InMemoryHostIoTranscript,
    };

    /// A provider whose network mechanism fails with an I/O error (mirrors a
    /// TLS certificate-verification failure) and no-ops fs.
    #[derive(Debug)]
    struct IoFailNetworkHostIo;
    impl HostIoProvider for IoFailNetworkHostIo {
        fn name(&self) -> &str {
            "io-fail-network"
        }
        fn perform(&self, request: &HostIoRequest, _granted: &[HostIoCapability]) -> HostIoOutcome {
            match request {
                HostIoRequest::NetworkSend { .. }
                | HostIoRequest::NetworkRecv { .. }
                | HostIoRequest::NetworkRequest { .. } => Err(HostIoError::Io {
                    detail: "TLS send to 127.0.0.1:443: invalid peer certificate".to_string(),
                }),
                HostIoRequest::EnvRead { .. } => Err(HostIoError::Denied {
                    reason: "environment is outside the network fixture".to_string(),
                }),
                HostIoRequest::FsRead { .. } => Ok(HostIoResponse::FsRead { bytes: Vec::new() }),
                HostIoRequest::FsWrite { .. } => Ok(HostIoResponse::FsWrite { bytes_written: 0 }),
                HostIoRequest::FsMeta { .. } => Ok(HostIoResponse::FsMeta {
                    result: FsMetaResult::Unit,
                }),
                HostIoRequest::RandomRead { byte_len } => Ok(HostIoResponse::RandomRead {
                    bytes: vec![0; *byte_len as usize],
                }),
            }
        }
    }

    let recorder = Arc::new(InMemoryHostIoTranscript::recording());
    let mut core = test_interpreter();
    let recorder_dyn: Arc<dyn HostIoRecorder> = recorder.clone();
    core.set_host_io(Arc::new(IoFailNetworkHostIo), Some(recorder_dyn));

    core.mutate_registers(|r| {
        r[0] = Value::Str(JsString::from("https://127.0.0.1/"));
    });

    let result = core
        .dispatch_host_io_hostcall("net:request", RegRange { start: 0, count: 1 })
        .expect("a failed net:request egress must not abort the run");
    assert_eq!(
        result,
        Value::Undefined,
        "a failed egress evaluates to undefined (no fabricated response)"
    );

    let entries = recorder.recorded_entries();
    assert_eq!(
        entries.len(),
        1,
        "the failed egress must still be recorded for the ledger"
    );
    assert!(
        matches!(
            entries[0].0,
            HostIoRequest::NetworkRequest { use_tls: true, .. }
        ),
        "the recorded request is the attempted TLS egress"
    );
    assert!(
        entries[0].1.is_err(),
        "the recorded outcome must be the fail-closed I/O failure"
    );
}

/// bd-3894s slice (2d): the parsed response object is tagged `IncomingMessage` so
/// `res.on('data'|'end'|'error', …)` resolves to the shared
/// `EventEmitter.prototype.on` via the `__type` member-access path, while the own
/// data properties (`status`/`body`/`headers`/`ok`) are untouched.
#[test]
fn build_net_response_value_tags_incoming_message_bd_3894s() {
    let mut core = test_interpreter();
    let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
    let Value::Object(id) = core
        .build_net_response_value(raw, "GET")
        .expect("parse response")
    else {
        panic!("expected a response object");
    };
    let response = core.heap.get(id.0 as usize).expect("response object");
    assert_eq!(
        response.brand(),
        Some("IncomingMessage"),
        "the response is a readable-stream IncomingMessage"
    );
    // The data properties still win property resolution (the tag only adds `.on`).
    assert_eq!(response.properties.get("status"), Some(&Value::Int(200)));
    assert_eq!(response.properties.get("body"), Some(&Value::str("hello")));
    assert_eq!(response.properties.get("ok"), Some(&Value::Bool(true)));
}

/// bd-3894s slice (2d): both the readable `IncomingMessage` and the writable
/// `ClientRequest` resolve `.on` to the shared `EmitterOn` builtin via their
/// `__type` tag; an unrelated tag does not gain an `.on` method.
#[test]
fn incoming_message_and_client_request_resolve_on_method_bd_3894s() {
    for tag in ["IncomingMessage", "ClientRequest"] {
        let resolved = InterpreterCore::collection_prototype_method(tag, "on")
            .unwrap_or_else(|| panic!("{tag}.on must resolve to a builtin"));
        assert!(
            matches!(resolved.kind, BuiltinFunctionKind::EmitterOn),
            "{tag}.on resolves to the shared EventEmitter.on builtin"
        );
    }
    assert!(
        InterpreterCore::collection_prototype_method("Map", "on").is_none(),
        "a non-emitter __type tag does not gain an .on method"
    );
}

/// bd-3894s slice (2d): `emitter.on(event, listener)` registers listeners in
/// registration order (Node fires them in the order added) and returns the
/// receiver so `res.on('data', …).on('end', …)` chains. A non-string event or a
/// non-closure listener is a no-op registration.
#[test]
fn emitter_on_registers_listeners_in_order_and_returns_receiver_bd_3894s() {
    let mut core = test_interpreter();
    let module = test_module_with_functions(vec![], vec![]);
    let on = BuiltinFunction::emitter_on();
    let target_id = core.mutate_heap(|h| {
        let id = ObjectId(h.len() as u32);
        let mut obj = HeapObject::new();
        obj.brand = Some(Box::new(JsString::from("IncomingMessage")));
        h.push(obj);
        id
    });

    // res.on('data', closure#7)
    core.mutate_registers(|r| {
        if r.len() < 2 {
            r.resize(2, Value::Undefined);
        }
        r[0] = Value::str("data");
        r[1] = Value::Closure(7);
    });
    let returned = core
        .dispatch_builtin_function(
            &module,
            &on,
            RegRange { start: 0, count: 2 },
            Some(Value::Object(target_id)),
            None,
        )
        .expect("emitter.on dispatch");
    assert_eq!(
        returned,
        Value::Object(target_id),
        "emitter.on returns the receiver for chaining"
    );

    // res.on('data', closure#8) — second 'data' listener, registration order kept.
    core.mutate_registers(|r| r[1] = Value::Closure(8));
    core.dispatch_builtin_function(
        &module,
        &on,
        RegRange { start: 0, count: 2 },
        Some(Value::Object(target_id)),
        None,
    )
    .expect("second data listener");

    // res.on('end', closure#9)
    core.mutate_registers(|r| {
        r[0] = Value::str("end");
        r[1] = Value::Closure(9);
    });
    core.dispatch_builtin_function(
        &module,
        &on,
        RegRange { start: 0, count: 2 },
        Some(Value::Object(target_id)),
        None,
    )
    .expect("end listener");

    assert_eq!(
        core.event_listeners_for(target_id, "data"),
        vec![7, 8],
        "data listeners are kept in registration order"
    );
    assert_eq!(core.event_listeners_for(target_id, "end"), vec![9]);

    // A non-closure listener does not register.
    core.mutate_registers(|r| {
        r[0] = Value::str("error");
        r[1] = Value::Int(0);
    });
    core.dispatch_builtin_function(
        &module,
        &on,
        RegRange { start: 0, count: 2 },
        Some(Value::Object(target_id)),
        None,
    )
    .expect("non-closure listener is a no-op");
    assert!(
        core.event_listeners_for(target_id, "error").is_empty(),
        "a non-closure listener is not registered"
    );
}

/// bd-2dmnn: the pure-compute EventEmitter constructor tags a standalone
/// object onto the same method-resolution path used by HTTP emitters.
#[test]
fn event_emitter_constructor_exposes_shared_runtime_surface_bd_2dmnn() {
    let mut core = test_interpreter();
    let Value::Object(target_id) = core
        .dispatch_builtin_hostcall_inner(
            "builtin:EventEmitter",
            RegRange { start: 0, count: 0 },
            None,
        )
        .expect("EventEmitter construction")
    else {
        panic!("EventEmitter constructor must return an object");
    };
    let object = core.heap.get(target_id.0 as usize).expect("emitter object");
    assert_eq!(object.brand(), Some("EventEmitter"));
    assert_eq!(
        object.properties.get("__maxListeners"),
        Some(&Value::Int(10))
    );
    for method in [
        "on",
        "addListener",
        "once",
        "off",
        "removeListener",
        "removeAllListeners",
        "listenerCount",
        "eventNames",
        "prependListener",
        "prependOnceListener",
        "emit",
        "getMaxListeners",
        "setMaxListeners",
        "listeners",
        "rawListeners",
    ] {
        assert!(
            InterpreterCore::collection_prototype_method("EventEmitter", method).is_some(),
            "EventEmitter.{method} must resolve through the shared method table"
        );
    }
}

/// bd-2dmnn: listener records preserve prepend/append order, remove the most
/// recent duplicate, and retain once metadata. An unhandled `error` rethrows
/// the original error value so an enclosing JS catch observes its message.
#[test]
fn event_emitter_listener_records_and_unhandled_error_bd_2dmnn() {
    let mut core = test_interpreter();
    let module = test_module_with_functions(vec![], vec![]);
    let target_id = core
        .alloc_branded_object("EventEmitter", &[("__maxListeners", Value::Int(10))])
        .expect("emitter object");

    let dispatch_listener =
        |core: &mut InterpreterCore, kind, listener: Value| -> Result<Value, InterpreterError> {
            core.mutate_registers(|registers| {
                if registers.len() < 2 {
                    registers.resize(2, Value::Undefined);
                }
                registers[0] = Value::str("tick");
                registers[1] = listener;
            });
            core.dispatch_builtin_function(
                &module,
                &BuiltinFunction::new_kind(kind),
                RegRange { start: 0, count: 2 },
                Some(Value::Object(target_id)),
                None,
            )
        };

    dispatch_listener(&mut core, BuiltinFunctionKind::EmitterOn, Value::Closure(1))
        .expect("append listener");
    dispatch_listener(
        &mut core,
        BuiltinFunctionKind::EmitterPrependOnceListener,
        Value::Closure(2),
    )
    .expect("prepend once listener");
    dispatch_listener(&mut core, BuiltinFunctionKind::EmitterOn, Value::Closure(1))
        .expect("append duplicate listener");
    let records = core.event_listener_records_for(target_id, "tick");
    assert_eq!(records.len(), 3);
    assert!(records[0].once);
    assert!(InterpreterCore::event_once_wrapper_property_object(&records[0].listener).is_some());
    assert_eq!(
        core.exposed_event_listener(&records[0].listener),
        Value::Closure(2),
        "listeners() exposes the original callback while the record retains the raw wrapper"
    );
    assert_eq!(
        records[1..],
        [
            EventListenerRecord {
                listener: Value::Closure(1),
                once: false,
            },
            EventListenerRecord {
                listener: Value::Closure(1),
                once: false,
            },
        ]
    );

    dispatch_listener(
        &mut core,
        BuiltinFunctionKind::EmitterOff,
        Value::Closure(1),
    )
    .expect("remove most recent duplicate");
    let records = core.event_listener_records_for(target_id, "tick");
    assert_eq!(records.len(), 2);
    assert!(records[0].once);
    assert_eq!(
        core.exposed_event_listener(&records[0].listener),
        Value::Closure(2)
    );
    assert_eq!(
        records[1],
        EventListenerRecord {
            listener: Value::Closure(1),
            once: false,
        }
    );

    let error_id = core
        .alloc_object_with_properties(&[("message", Value::str("boom"))])
        .expect("error object");
    core.mutate_registers(|registers| {
        registers[0] = Value::str("error");
        registers[1] = Value::Object(error_id);
    });
    core.set_register_label(1, Label::Secret)
        .expect("error argument label");
    let err = core
        .dispatch_builtin_function(
            &module,
            &BuiltinFunction::new_kind(BuiltinFunctionKind::EmitterEmit),
            RegRange { start: 0, count: 2 },
            Some(Value::Object(target_id)),
            None,
        )
        .expect_err("an unhandled error event must throw");
    assert!(matches!(err, InterpreterError::UncaughtException { .. }));
    assert_eq!(core.pending_exception, Some(Value::Object(error_id)));
    assert_eq!(core.pending_exception_label, Label::Secret);
}

/// bd-fw7zd: stream chunks retain their IFC label through ordinary
/// EventEmitter callbacks, not only through the Promise-backed
/// `events.once` path. Isolated callback execution must also restore the
/// caller's complete register-label file after the callback throws.
#[test]
fn event_emitter_callback_arguments_preserve_labels_and_restore_caller_bd_fw7zd() {
    let module = test_module_with_functions(
        vec![Ir3Instruction::Throw { value: 0 }],
        vec![Ir3FunctionDesc {
            entry: 0,
            arity: 1,
            frame_size: 1,
            name: Some("throw_stream_chunk".to_string()),
            is_generator: false,
            rest_param_index: None,
        }],
    );
    let mut core = test_interpreter();
    let target_id = core
        .alloc_branded_object(READABLE_BRAND, &[])
        .expect("readable emitter object");
    core.insert_event_listener(
        target_id,
        "data",
        EventListenerRecord {
            listener: Value::Function(0),
            once: false,
        },
        false,
    )
    .expect("data listener registration");
    core.set_register_label(7, Label::Confidential)
        .expect("caller label seed");

    let error = core
        .emit_event_listener_records(
            &module,
            target_id,
            "data",
            vec![Value::str("secret-chunk")],
            Label::Secret,
        )
        .expect_err("throwing data listener must escape");

    assert!(matches!(error, InterpreterError::UncaughtException { .. }));
    assert_eq!(core.pending_exception, Some(Value::str("secret-chunk")));
    assert_eq!(core.pending_exception_label, Label::Secret);
    assert_eq!(
        core.get_register_label(7).expect("restored caller label"),
        &Label::Confidential
    );
}

#[test]
fn plain_call_secret_argument_returns_secret_bd_ur3tk_1() {
    let module = test_module_with_functions(
        vec![
            Ir3Instruction::Call {
                callee: 0,
                args: RegRange { start: 1, count: 1 },
                dst: 2,
            },
            Ir3Instruction::Return { value: 2 },
            Ir3Instruction::Return { value: 0 },
        ],
        vec![Ir3FunctionDesc {
            entry: 2,
            arity: 1,
            frame_size: 1,
            name: Some("identity".to_string()),
            is_generator: false,
            rest_param_index: None,
        }],
    );
    let mut core = test_interpreter();
    core.mutate_registers(|registers| {
        registers[0] = Value::Function(0);
        registers[1] = Value::str("secret-argument");
    });
    core.set_register_label(1, Label::Secret)
        .expect("secret argument label");

    assert_eq!(
        core.run_loop(&module).expect("identity call should return"),
        Value::str("secret-argument")
    );
    assert_eq!(
        core.get_register_label(2).expect("caller return label"),
        &Label::Secret
    );
}

#[test]
fn plain_call_label_frames_do_not_alias_bd_ur3tk_1() {
    let module = test_module_with_functions(
        vec![
            Ir3Instruction::Call {
                callee: 0,
                args: RegRange { start: 0, count: 0 },
                dst: 1,
            },
            Ir3Instruction::Return { value: 1 },
            Ir3Instruction::Return { value: 7 },
        ],
        vec![Ir3FunctionDesc {
            entry: 2,
            arity: 0,
            frame_size: 8,
            name: Some("return_fresh_r7".to_string()),
            is_generator: false,
            rest_param_index: None,
        }],
    );
    let mut core = test_interpreter();
    core.mutate_registers(|registers| {
        registers[0] = Value::Function(0);
        registers[7] = Value::str("caller-only");
    });
    core.set_register_label(7, Label::Confidential)
        .expect("caller frame label");
    core.set_register_label(1, Label::Secret)
        .expect("stale destination label");

    assert_eq!(
        core.run_loop(&module)
            .expect("fresh callee frame should return"),
        Value::Undefined
    );
    assert_eq!(
        core.get_register_label(1).expect("public return label"),
        &Label::Public
    );
    assert_eq!(
        core.get_register_label(7).expect("preserved caller label"),
        &Label::Confidential
    );
}

#[test]
fn nested_plain_calls_preserve_labels_across_two_physical_frames_bd_ur3tk_1() {
    let module = test_module_with_functions(
        vec![
            Ir3Instruction::Call {
                callee: 0,
                args: RegRange { start: 1, count: 2 },
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
            Ir3Instruction::Call {
                callee: 0,
                args: RegRange { start: 1, count: 1 },
                dst: 2,
            },
            Ir3Instruction::Return { value: 2 },
            Ir3Instruction::Return { value: 0 },
        ],
        vec![
            Ir3FunctionDesc {
                entry: 2,
                arity: 2,
                frame_size: 3,
                name: Some("outer_identity".to_string()),
                is_generator: false,
                rest_param_index: None,
            },
            Ir3FunctionDesc {
                entry: 4,
                arity: 1,
                frame_size: 1,
                name: Some("inner_identity".to_string()),
                is_generator: false,
                rest_param_index: None,
            },
        ],
    );
    let mut core = test_interpreter();
    core.mutate_registers(|registers| {
        registers[0] = Value::Function(0);
        registers[1] = Value::Function(1);
        registers[2] = Value::str("nested-secret");
    });
    core.set_register_label(2, Label::Secret)
        .expect("nested argument label");

    assert_eq!(
        core.run_loop(&module).expect("nested calls should return"),
        Value::str("nested-secret")
    );
    assert_eq!(
        core.get_register_label(3).expect("nested return label"),
        &Label::Secret
    );
}

#[test]
fn return_label_survives_finally_nested_call_bd_ur3tk_16() {
    let module = test_module_with_functions(
        vec![
            Ir3Instruction::Call {
                callee: 0,
                args: RegRange { start: 1, count: 2 },
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
            Ir3Instruction::BeginTry {
                catch_target: 4,
                finally_target: Some(4),
            },
            Ir3Instruction::Return { value: 0 },
            Ir3Instruction::EnterFinally,
            Ir3Instruction::Call {
                callee: 1,
                args: RegRange { start: 0, count: 0 },
                dst: 2,
            },
            Ir3Instruction::EndFinally,
            Ir3Instruction::Return { value: 0 },
        ],
        vec![
            Ir3FunctionDesc {
                entry: 2,
                arity: 2,
                frame_size: 3,
                name: Some("return_through_finally".to_string()),
                is_generator: false,
                rest_param_index: None,
            },
            Ir3FunctionDesc {
                entry: 7,
                arity: 0,
                frame_size: 1,
                name: Some("finally_helper".to_string()),
                is_generator: false,
                rest_param_index: None,
            },
        ],
    );
    let mut core = test_interpreter();
    core.write_reg(0, Value::Function(0))
        .expect("outer function should be writable");
    core.write_reg_with_label(1, Value::str("secret-through-finally"), Label::Secret)
        .expect("secret return argument should be writable");
    core.write_reg(2, Value::Function(1))
        .expect("finally helper should be writable");

    assert_eq!(
        core.run_loop(&module)
            .expect("finally return should survive nested helper call"),
        Value::str("secret-through-finally")
    );
    assert_eq!(
        core.get_register_label(3).expect("caller return label"),
        &Label::Secret
    );
}

#[test]
fn nested_finally_return_override_keeps_new_label_bd_ur3tk_16() {
    let module = test_module_with_functions(
        vec![
            Ir3Instruction::Call {
                callee: 0,
                args: RegRange { start: 1, count: 2 },
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
            Ir3Instruction::BeginTry {
                catch_target: 8,
                finally_target: Some(8),
            },
            Ir3Instruction::BeginTry {
                catch_target: 5,
                finally_target: Some(5),
            },
            Ir3Instruction::Return { value: 1 },
            Ir3Instruction::EnterFinally,
            Ir3Instruction::Return { value: 0 },
            Ir3Instruction::EndFinally,
            Ir3Instruction::EnterFinally,
            Ir3Instruction::EndFinally,
        ],
        vec![Ir3FunctionDesc {
            entry: 2,
            arity: 2,
            frame_size: 2,
            name: Some("nested_finally_override".to_string()),
            is_generator: false,
            rest_param_index: None,
        }],
    );
    let mut core = test_interpreter();
    core.write_reg(0, Value::Function(0))
        .expect("outer function should be writable");
    core.write_reg_with_label(1, Value::str("secret-override"), Label::Secret)
        .expect("secret overriding return should be writable");
    core.write_reg(2, Value::str("public-initial-return"))
        .expect("initial return should be writable");

    assert_eq!(
        core.run_loop(&module)
            .expect("inner finally return should override outer completion"),
        Value::str("secret-override")
    );
    assert_eq!(
        core.get_register_label(3).expect("overriding return label"),
        &Label::Secret
    );
}

#[test]
fn caught_throw_preserves_owned_return_label_bd_ur3tk_16_bd_bvgmr() {
    let module = test_module_with_functions(
        vec![
            Ir3Instruction::Call {
                callee: 0,
                args: RegRange { start: 1, count: 2 },
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
            Ir3Instruction::BeginTry {
                catch_target: 4,
                finally_target: Some(4),
            },
            Ir3Instruction::Return { value: 0 },
            Ir3Instruction::EnterFinally,
            Ir3Instruction::BeginTry {
                catch_target: 7,
                finally_target: None,
            },
            Ir3Instruction::Throw { value: 1 },
            Ir3Instruction::EnterCatch { dst: 2 },
            Ir3Instruction::EndFinally,
        ],
        vec![Ir3FunctionDesc {
            entry: 2,
            arity: 2,
            frame_size: 3,
            name: Some("caught_throw_during_finally".to_string()),
            is_generator: false,
            rest_param_index: None,
        }],
    );
    let mut core = test_interpreter();
    core.write_reg(0, Value::Function(0))
        .expect("outer function should be writable");
    core.write_reg_with_label(1, Value::str("secret-suspended-return"), Label::Secret)
        .expect("secret pending return should be writable");
    core.write_reg(2, Value::str("public-local-throw"))
        .expect("local throw should be writable");

    assert_eq!(
        core.run_loop(&module)
            .expect("caught throw should restore the suspended return"),
        Value::str("secret-suspended-return")
    );
    assert_eq!(
        core.get_register_label(3)
            .expect("restored suspended return label"),
        &Label::Secret
    );
    assert!(core.pending_exception.is_none());
    assert!(core.pending_return.is_none());
    assert!(core.pending_finally_entry.is_none());
    assert!(core.finally_frames.is_empty());
    assert!(core.suspended_abrupt_completions.is_empty());
}

#[test]
fn module_snapshot_round_trips_labeled_returns_bd_ur3tk_16() {
    let mut core = test_interpreter();
    let pending = LabeledReturn {
        value: Value::str("pending"),
        label: Label::Secret,
    };
    let suspended = LabeledReturn {
        value: Value::str("suspended"),
        label: Label::Custom {
            name: "tenant-return".repeat(8),
            level: 4,
        },
    };
    core.replace_pending_abrupt_slots(None, Some(pending.clone()))
        .expect("pending labeled return should fit");
    core.suspended_abrupt_completions
        .push(AbruptCompletion::Return(suspended.clone()));
    core.sync_estimated_memory_bytes()
        .expect("seeded return state should fit");
    let baseline = core.estimated_memory_bytes();

    let snapshot = core
        .snapshot_module_execution()
        .expect("module snapshot should preserve return labels");
    core.clear_pending_abrupt_slots();
    core.clear_suspended_abrupt_completions();
    core.restore_module_execution(snapshot, true);

    assert_eq!(core.pending_return, Some(pending));
    assert!(matches!(
        core.suspended_abrupt_completions.as_slice(),
        [AbruptCompletion::Return(restored)] if restored == &suspended
    ));
    assert_eq!(core.estimated_memory_bytes(), baseline);
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes(),
        "snapshot restore must account the returned value and its dynamic label exactly"
    );
}

fn execute_exception_source_with_core_bd_bvgmr(
    source: &str,
    grant_builtin: bool,
) -> (Value, InterpreterCore) {
    let syntax_tree = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource {
                label: "bd_bvgmr_runtime.js".to_string(),
                text: source.to_string(),
            },
            ParseGoal::Script,
            &ParserOptions::default(),
        )
        .expect("finally ownership regression source should parse");
    let module = lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(syntax_tree, "bd_bvgmr_runtime.js"),
        &LoweringContext::new(
            "trace-bd-bvgmr-runtime",
            "decision-bd-bvgmr-runtime",
            "policy-bd-bvgmr-runtime",
        ),
    )
    .expect("finally ownership regression source should lower")
    .ir3;
    let mut core = test_interpreter();
    if grant_builtin {
        // The concise-method identity fixture defines `[Symbol.iterator]()`;
        // keep that authority scoped to the one Symbol-specific case.
        core.config
            .granted_capabilities
            .insert(RuntimeCapability::Builtin);
    }
    let value = core
        .execute(&module)
        .expect("finally ownership regression should execute")
        .value;
    (value, core)
}

#[test]
fn concise_method_name_prototype_and_constructability_bd_gqaa4() {
    let (ordinary, ordinary_core) = execute_exception_source_with_core_bd_bvgmr(
        r#"let o={plain(){return 1;}}; o.plain.name+"|"+("prototype" in o.plain)+"|"+typeof o.plain.prototype;"#,
        false,
    );
    assert_eq!(ordinary, Value::str("plain|false|undefined"));
    assert_eq!(ordinary_core.closure_method_metadata.len(), 1);
    assert_eq!(
        ordinary_core.estimated_memory_bytes(),
        ordinary_core.recompute_estimated_memory_bytes(),
        "private method metadata must remain exactly memory-accounted"
    );

    let (computed, _) = execute_exception_source_with_core_bd_bvgmr(
        r#"let key="computed"; let o={[key](){return 2;}}; o[key].name;"#,
        false,
    );
    assert_eq!(computed, Value::str("computed"));

    let (symbol, _) = execute_exception_source_with_core_bd_bvgmr(
        r#"let o={[Symbol.iterator](){return 3;}}; o[Symbol.iterator].name;"#,
        true,
    );
    assert_eq!(symbol, Value::str("[Symbol.iterator]"));

    let (construct, _) = execute_exception_source_with_core_bd_bvgmr(
        "let o={plain(){return 1;}}; let caught=false; try { new o.plain(); } catch(e) { caught=true; } caught;",
        false,
    );
    assert_eq!(construct, Value::Bool(true));
}

#[test]
fn concise_method_super_uses_home_but_dynamic_receiver_bd_gqaa4() {
    let (value, core) = execute_exception_source_with_core_bd_bvgmr(
        r#"let key="computed"; let base={value(){return 40;}}; let owner={plain(){return super.value()+this.delta;},[key](){return super.value()+this.delta+1;}}; owner.__proto__=base; let alien={delta:2}; alien.__proto__={value(){return 100;}}; alien.plain=owner.plain; alien.computed=owner[key]; alien.plain()*100+alien.computed();"#,
        false,
    );
    assert_eq!(value, Value::Int(4243));
    assert_eq!(core.closure_method_metadata.len(), 4);
}

#[test]
fn concise_method_super_observes_home_prototype_change_during_call_bd_gqaa4() {
    let (value, _) = execute_exception_source_with_core_bd_bvgmr(
        "let a={value(){return 1;}}; let b={value(){return 9;}}; let owner={m(){owner.__proto__=b;return super.value();}}; owner.__proto__=a; owner.m();",
        false,
    );
    assert_eq!(value, Value::Int(9));
}

#[test]
fn escaped_arrow_retains_lexical_method_home_object_bd_gqaa4() {
    let (value, core) = execute_exception_source_with_core_bd_bvgmr(
        "let saved=undefined; let base={value(){return this.x;}}; let owner={m(){saved=()=>super.value();}}; owner.__proto__=base; let alien={x:7,m:owner.m}; alien.m(); saved();",
        false,
    );
    assert_eq!(value, Value::Int(7));
    assert_eq!(core.closure_lexical_super_metadata.len(), 1);
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes(),
        "escaped lexical-super metadata must remain exactly accounted"
    );
}

#[test]
fn nested_escaped_arrows_transitively_retain_lexical_super_bd_gqaa4() {
    let (value, core) = execute_exception_source_with_core_bd_bvgmr(
        "let base={value(){return this.x;}}; let owner={m(){return ()=>()=>super.value();}}; owner.__proto__=base; let alien={x:7,m:owner.m}; let outer=alien.m(); let inner=outer(); inner();",
        false,
    );
    assert_eq!(value, Value::Int(7));
    assert_eq!(core.closure_lexical_super_metadata.len(), 2);
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn lexical_super_descendant_scan_is_iterative_and_budgeted_bd_gqaa4() {
    const FUNCTION_COUNT: usize = 2_048;
    let instructions = (0..FUNCTION_COUNT)
        .map(|index| {
            if index + 1 == FUNCTION_COUNT {
                Ir3Instruction::LoadSuper { dst: 0 }
            } else {
                Ir3Instruction::CreateClosure {
                    dst: 0,
                    function_index: (index + 1) as u32,
                    capture_count: 0,
                }
            }
        })
        .collect();
    let functions = (0..FUNCTION_COUNT)
        .map(|index| Ir3FunctionDesc {
            entry: index as u32,
            arity: 0,
            frame_size: 1,
            name: None,
            is_generator: false,
            rest_param_index: None,
        })
        .collect();
    let module = test_module_with_functions(instructions, functions);
    let mut core = test_interpreter();
    assert_eq!(
        core.function_uses_lexical_super(&module, 0),
        Ok(true),
        "a long acyclic closure chain must complete without native recursion"
    );

    // bd-9vouw.159: the scan runs once per module; later questions are
    // answered from the memo and need no temporary memory.
    let baseline = core
        .sync_estimated_memory_bytes()
        .expect("descendant-scan fixture should fit before strict refusal");
    core.config.max_total_memory_bytes = baseline;
    assert_eq!(core.function_uses_lexical_super(&module, 0), Ok(true));
    assert_eq!(core.function_uses_lexical_super(&module, 1_000), Ok(true));
    assert_eq!(core.lexical_super_functions.borrow().len(), 1);
    assert_eq!(core.estimated_memory_bytes(), baseline);

    // The first scan of a module is budgeted.
    let mut fresh = test_interpreter();
    let fresh_baseline = fresh
        .sync_estimated_memory_bytes()
        .expect("an empty interpreter fits its budget");
    fresh.config.max_total_memory_bytes = fresh_baseline;
    assert!(matches!(
        fresh.function_uses_lexical_super(&module, 0),
        Err(InterpreterError::MemoryBudgetExceeded { .. })
    ));
    assert_eq!(fresh.estimated_memory_bytes(), fresh_baseline);
}

#[test]
fn escaped_async_arrow_promise_inherits_method_definition_label_bd_gqaa4() {
    for call_as_method in [false, true] {
        let async_call = if call_as_method {
            Ir3Instruction::CallMethod {
                receiver: 0,
                callee: 5,
                args: RegRange {
                    start: 11,
                    count: 0,
                },
                dst: 10,
            }
        } else {
            Ir3Instruction::Call {
                callee: 5,
                args: RegRange {
                    start: 11,
                    count: 0,
                },
                dst: 10,
            }
        };
        let mut module = test_module_with_functions(
            vec![
                Ir3Instruction::NewObject { dst: 0 },
                Ir3Instruction::CreateClosure {
                    dst: 2,
                    function_index: 0,
                    capture_count: 0,
                },
                Ir3Instruction::DefineMethod {
                    obj: 0,
                    key: 6,
                    func: 2,
                },
                Ir3Instruction::NewObject { dst: 3 },
                Ir3Instruction::SetProperty {
                    obj: 3,
                    key: 9,
                    val: 0,
                },
                Ir3Instruction::SetProperty {
                    obj: 3,
                    key: 7,
                    val: 8,
                },
                Ir3Instruction::CreateClosure {
                    dst: 2,
                    function_index: 1,
                    capture_count: 0,
                },
                Ir3Instruction::DefineMethod {
                    obj: 3,
                    key: 1,
                    func: 2,
                },
                Ir3Instruction::GetProperty {
                    obj: 3,
                    key: 1,
                    dst: 4,
                },
                Ir3Instruction::CallMethod {
                    receiver: 3,
                    callee: 4,
                    args: RegRange {
                        start: 11,
                        count: 0,
                    },
                    dst: 5,
                },
                async_call,
                Ir3Instruction::Return { value: 10 },
                Ir3Instruction::LoadThis { dst: 0 },
                Ir3Instruction::LoadStr {
                    dst: 1,
                    pool_index: 0,
                },
                Ir3Instruction::GetProperty {
                    obj: 0,
                    key: 1,
                    dst: 2,
                },
                Ir3Instruction::Return { value: 2 },
                Ir3Instruction::CreateAsyncFunction {
                    dst: 0,
                    function_index: 2,
                    capture_count: 0,
                },
                Ir3Instruction::Return { value: 0 },
                Ir3Instruction::LoadSuper { dst: 0 },
                Ir3Instruction::LoadStr {
                    dst: 1,
                    pool_index: 1,
                },
                Ir3Instruction::GetProperty {
                    obj: 0,
                    key: 1,
                    dst: 2,
                },
                Ir3Instruction::LoadThis { dst: 3 },
                Ir3Instruction::CallMethod {
                    receiver: 3,
                    callee: 2,
                    args: RegRange { start: 4, count: 0 },
                    dst: 4,
                },
                Ir3Instruction::AsyncReturn { value_reg: 4 },
            ],
            vec![
                Ir3FunctionDesc {
                    entry: 12,
                    arity: 0,
                    frame_size: 3,
                    name: Some("base_value".to_string()),
                    is_generator: false,
                    rest_param_index: None,
                },
                Ir3FunctionDesc {
                    entry: 16,
                    arity: 0,
                    frame_size: 1,
                    name: Some("secret_method".to_string()),
                    is_generator: false,
                    rest_param_index: None,
                },
                Ir3FunctionDesc {
                    entry: 18,
                    arity: 0,
                    frame_size: 5,
                    name: Some("escaped_async_arrow".to_string()),
                    is_generator: false,
                    rest_param_index: None,
                },
            ],
        );
        module.constant_pool = vec!["x".into(), "value".into()];
        let mut core = test_interpreter();
        core.write_reg_with_label(1, Value::str("m"), Label::Secret)
            .expect("secret computed method key should fit");
        for (register, value) in [
            (6, Value::str("value")),
            (7, Value::str("x")),
            (8, Value::Int(7)),
            (9, Value::str("__proto__")),
        ] {
            core.write_reg(register, value)
                .expect("async lexical-this fixture register should fit");
        }
        core.ensure_module_record(&module, &module.header.source_label)
            .expect("async lexical-this module provenance should be retained");

        let completion = core
            .run_loop_labeled(&module)
            .expect("escaped async arrow should publish its result Promise");
        let Value::Promise(promise_id) = completion.value else {
            panic!("expected escaped async result Promise");
        };
        assert_eq!(completion.label, Label::Secret);
        assert_eq!(core.get_register_label(10), Ok(&Label::Secret));
        assert_eq!(
            core.promise_store
                .get(crate::promise_model::PromiseHandle(promise_id))
                .expect("escaped async result Promise should remain recorded")
                .state,
            crate::promise_model::PromiseState::Fulfilled(crate::object_model::JsValue::Int(7))
        );
        assert_eq!(core.closure_lexical_super_metadata.len(), 1);
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }
}

fn secret_method_fixture_bd_gqaa4(
    function_body: Vec<Ir3Instruction>,
) -> (Ir3Module, InterpreterCore) {
    let function_entry = 10;
    let mut instructions = vec![
        Ir3Instruction::NewObject { dst: 0 },
        Ir3Instruction::CreateClosure {
            dst: 2,
            function_index: 0,
            capture_count: 0,
        },
        Ir3Instruction::DefineMethod {
            obj: 0,
            key: 1,
            func: 2,
        },
        Ir3Instruction::GetProperty {
            obj: 0,
            key: 1,
            dst: 3,
        },
        Ir3Instruction::BeginTry {
            catch_target: 8,
            finally_target: None,
        },
        Ir3Instruction::CallMethod {
            receiver: 0,
            callee: 3,
            args: RegRange { start: 5, count: 0 },
            dst: 4,
        },
        Ir3Instruction::EndTry,
        Ir3Instruction::Return { value: 4 },
        Ir3Instruction::EnterCatch { dst: 4 },
        Ir3Instruction::Return { value: 4 },
    ];
    instructions.extend(function_body);
    let module = test_module_with_functions(
        instructions,
        vec![Ir3FunctionDesc {
            entry: function_entry,
            arity: 0,
            frame_size: 1,
            name: Some("secret_method".to_string()),
            is_generator: false,
            rest_param_index: None,
        }],
    );
    let mut core = test_interpreter();
    core.write_reg_with_label(1, Value::str("m"), Label::Secret)
        .expect("secret computed method key should fit");
    (module, core)
}

#[test]
fn method_definition_context_taints_returns_throws_and_zero_arg_effects_bd_gqaa4() {
    let (return_module, mut return_core) = secret_method_fixture_bd_gqaa4(vec![
        Ir3Instruction::LoadInt { dst: 0, value: 11 },
        Ir3Instruction::Return { value: 0 },
    ]);
    assert_eq!(
        return_core
            .run_loop(&return_module)
            .expect("secret-selected method return should execute"),
        Value::Int(11)
    );
    assert_eq!(return_core.get_register_label(4), Ok(&Label::Secret));
    assert_eq!(
        return_core.estimated_memory_bytes(),
        return_core.recompute_estimated_memory_bytes()
    );

    let (throw_module, mut throw_core) =
        secret_method_fixture_bd_gqaa4(vec![Ir3Instruction::Throw { value: 0 }]);
    assert_eq!(
        throw_core
            .run_loop(&throw_module)
            .expect("secret-selected method throw should be caught"),
        Value::Undefined
    );
    assert_eq!(throw_core.get_register_label(4), Ok(&Label::Secret));

    let (mut native_fault_module, mut native_fault_core) = secret_method_fixture_bd_gqaa4(vec![
        Ir3Instruction::LoadNull { dst: 0 },
        Ir3Instruction::LoadStr {
            dst: 1,
            pool_index: 0,
        },
        Ir3Instruction::GetProperty {
            obj: 0,
            key: 1,
            dst: 2,
        },
    ]);
    native_fault_module.constant_pool.push("x".into());
    assert!(matches!(
        native_fault_core
            .run_loop(&native_fault_module)
            .expect("secret-selected native fault should be caught"),
        Value::Object(_)
    ));
    assert_eq!(native_fault_core.get_register_label(4), Ok(&Label::Secret));

    // An empty argument range still carries the method's execution
    // context. Console has Internal clearance; a grant is not a release
    // of a Secret-selected effect. Run identical IR at each boundary.
    for label in [Label::Public, Label::Internal, Label::Secret] {
        let (effect_module, mut effect_core) = secret_method_fixture_bd_gqaa4(vec![
            Ir3Instruction::HostCall {
                capability: CapabilityTag("console:log".to_string()),
                args: RegRange { start: 0, count: 0 },
                dst: 0,
            },
            Ir3Instruction::Return { value: 0 },
        ]);
        effect_core
            .config
            .granted_capabilities
            .insert(RuntimeCapability::Console);
        effect_core
            .write_reg_with_label(1, Value::str("m"), label.clone())
            .expect("computed method key should fit");
        let outcome = effect_core.run_loop(&effect_module);
        if label == Label::Secret {
            assert!(
                matches!(outcome, Err(InterpreterError::CapabilityDenied { ref capability })
                        if capability == "console:log:confidentiality"),
                "Secret zero-argument effect must fail at the sink: {outcome:?}"
            );
            assert!(effect_core.console_output.is_empty());
        } else {
            assert_eq!(
                outcome.expect("permitted zero-argument effect"),
                Value::Undefined
            );
            assert_eq!(effect_core.get_register_label(4), Ok(&label));
            assert_eq!(effect_core.console_output.len(), 1);
            assert_eq!(effect_core.console_output[0].message, "");
        }
        assert_eq!(
            effect_core.estimated_memory_bytes(),
            effect_core.recompute_estimated_memory_bytes()
        );
    }
}

#[test]
fn method_definition_context_crosses_plain_helper_effect_bd_gqaa4() {
    let module = test_module_with_functions(
        vec![
            Ir3Instruction::NewObject { dst: 0 },
            Ir3Instruction::CreateClosure {
                dst: 2,
                function_index: 0,
                capture_count: 0,
            },
            Ir3Instruction::DefineMethod {
                obj: 0,
                key: 1,
                func: 2,
            },
            Ir3Instruction::GetProperty {
                obj: 0,
                key: 1,
                dst: 3,
            },
            Ir3Instruction::CreateClosure {
                dst: 5,
                function_index: 1,
                capture_count: 0,
            },
            Ir3Instruction::BeginTry {
                catch_target: 9,
                finally_target: None,
            },
            Ir3Instruction::CallMethod {
                receiver: 0,
                callee: 3,
                args: RegRange { start: 5, count: 1 },
                dst: 4,
            },
            Ir3Instruction::EndTry,
            Ir3Instruction::Return { value: 4 },
            Ir3Instruction::EnterCatch { dst: 4 },
            Ir3Instruction::Return { value: 4 },
            Ir3Instruction::Call {
                callee: 0,
                args: RegRange { start: 1, count: 0 },
                dst: 1,
            },
            Ir3Instruction::Return { value: 1 },
            Ir3Instruction::HostCall {
                capability: CapabilityTag("console:log".to_string()),
                args: RegRange { start: 0, count: 0 },
                dst: 0,
            },
            Ir3Instruction::Return { value: 0 },
        ],
        vec![
            Ir3FunctionDesc {
                entry: 11,
                arity: 1,
                frame_size: 2,
                name: Some("secret_method".to_string()),
                is_generator: false,
                rest_param_index: None,
            },
            Ir3FunctionDesc {
                entry: 13,
                arity: 0,
                frame_size: 1,
                name: Some("plain_helper".to_string()),
                is_generator: false,
                rest_param_index: None,
            },
        ],
    );
    for label in [Label::Public, Label::Internal, Label::Secret] {
        let mut core = test_interpreter();
        core.config
            .granted_capabilities
            .insert(RuntimeCapability::Console);
        core.write_reg_with_label(1, Value::str("m"), label.clone())
            .expect("computed method key should fit");
        let outcome = core.run_loop(&module);
        if label == Label::Secret {
            assert!(
                matches!(outcome, Err(InterpreterError::CapabilityDenied { ref capability })
                        if capability == "console:log:confidentiality"),
                "a plain helper must not erase the Secret method context: {outcome:?}"
            );
            assert!(core.console_output.is_empty());
        } else {
            assert_eq!(
                outcome.expect("permitted plain helper effect"),
                Value::Undefined
            );
            assert_eq!(core.get_register_label(4), Ok(&label));
            assert_eq!(core.console_output.len(), 1);
            assert_eq!(core.console_output[0].message, "");
        }
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );

        // Preserve a positive return-taint witness through the same
        // method/helper call chain without attempting a forbidden sink.
        let mut return_module = module.clone();
        return_module.instructions[13] = Ir3Instruction::LoadInt { dst: 0, value: 17 };
        let mut return_core = test_interpreter();
        return_core
            .write_reg_with_label(1, Value::str("m"), label.clone())
            .expect("computed method key should fit");
        assert_eq!(
            return_core
                .run_loop(&return_module)
                .expect("plain helper return"),
            Value::Int(17)
        );
        assert_eq!(return_core.get_register_label(4), Ok(&label));
        assert!(return_core.console_output.is_empty());
        assert_eq!(
            return_core.estimated_memory_bytes(),
            return_core.recompute_estimated_memory_bytes()
        );
    }
}

#[test]
fn method_custom_label_refusal_is_atomic_and_exact_bd_gqaa4() {
    fn fixture() -> (InterpreterCore, ObjectId, u64) {
        let mut core = test_interpreter();
        let object = core
            .alloc_object_with_prototype(None)
            .expect("method owner should allocate");
        core.closures.push(ClosureValue {
            function_index: 0,
            captured_env: core.scope_chain.snapshot(),
        });
        core.write_reg_with_label(
            0,
            Value::Object(object),
            Label::Custom {
                name: "method-owner-label".repeat(256),
                level: 6,
            },
        )
        .expect("custom owner label should fit before refusal");
        core.write_reg_with_label(
            1,
            Value::str("m"),
            Label::Custom {
                name: "method-definition-label".repeat(256),
                level: 7,
            },
        )
        .expect("custom key label should fit before refusal");
        core.write_reg(2, Value::Closure(0))
            .expect("method closure register should fit");
        let baseline = core
            .sync_estimated_memory_bytes()
            .expect("seeded method fixture should fit");
        (core, object, baseline)
    }
    let module = test_module_with_functions(
        vec![Ir3Instruction::DefineMethod {
            obj: 0,
            key: 1,
            func: 2,
        }],
        Vec::new(),
    );

    let (mut control, _, _) = fixture();
    control
        .run_loop(&module)
        .expect("one dominant definition-label clone should fit");
    let exact_retained_ceiling = control.estimated_memory_bytes();
    let (mut exact, _, _) = fixture();
    exact.config.max_total_memory_bytes = exact_retained_ceiling;
    exact
        .run_loop(&module)
        .expect("two source labels must not cause two simultaneous clones");
    assert_eq!(exact.estimated_memory_bytes(), exact_retained_ceiling);

    let (mut core, object, baseline) = fixture();
    core.config.max_total_memory_bytes = baseline;

    assert!(matches!(
        core.run_loop(&module),
        Err(InterpreterError::MemoryBudgetExceeded { .. })
    ));
    assert!(
        core.heap[object.0 as usize].properties.get("m").is_none(),
        "temporary-label refusal must not publish the data property"
    );
    assert!(core.closure_method_metadata.is_empty());
    assert_eq!(core.estimated_memory_bytes(), baseline);
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn escaped_finally_completion_records_are_balanced_bd_bvgmr() {
    let (value, core) = execute_exception_source_with_core_bd_bvgmr(
        "function f(){ try { return \"outer\"; } finally { try { try { return \"inner\"; } finally { throw \"new\"; } } catch(e) {} } } f();",
        false,
    );
    assert_eq!(value, Value::str("outer"));
    assert!(core.pending_exception.is_none());
    assert!(core.pending_return.is_none());
    assert!(core.pending_finally_entry.is_none());
    assert!(core.finally_frames.is_empty());
    assert!(core.suspended_abrupt_completions.is_empty());
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes(),
        "successful nested-finally completion must leave exact accounting"
    );
}

#[test]
fn same_finally_catch_and_normal_nested_entry_preserve_owner_bd_bvgmr() {
    let (exception_value, exception_core) = execute_exception_source_with_core_bd_bvgmr(
        "let log=\"\"; try { try { throw \"outer\"; } finally { try { throw \"new\"; } catch(e) { log=e+\";\"; } log=log+\"after;\"; } } catch(e) { log=log+e; } log;",
        false,
    );
    assert_eq!(exception_value, Value::str("new;after;outer"));
    assert!(exception_core.pending_exception.is_none());
    assert!(exception_core.pending_return.is_none());
    assert!(exception_core.pending_finally_entry.is_none());
    assert!(exception_core.finally_frames.is_empty());
    assert!(exception_core.suspended_abrupt_completions.is_empty());

    let (return_value, return_core) = execute_exception_source_with_core_bd_bvgmr(
        "function f(){ try { return \"outer\"; } finally { while(true) { try {} finally { break; } } } } f();",
        false,
    );
    assert_eq!(return_value, Value::str("outer"));
    assert!(return_core.pending_exception.is_none());
    assert!(return_core.pending_return.is_none());
    assert!(return_core.pending_finally_entry.is_none());
    assert!(return_core.finally_frames.is_empty());
    assert!(return_core.suspended_abrupt_completions.is_empty());
}

#[test]
fn isolated_throw_to_explicit_finally_entry_owns_completion_bd_bvgmr() {
    let module = test_module_with_functions(
        vec![
            Ir3Instruction::BeginTry {
                catch_target: 7,
                finally_target: None,
            },
            Ir3Instruction::BeginTry {
                catch_target: 4,
                // Synthetic unwind handlers may route Throw and Return to
                // different targets even though the Throw target itself
                // starts with EnterFinally.
                finally_target: Some(6),
            },
            Ir3Instruction::HostCall {
                capability: CapabilityTag("builtin:ArrayPrototypeSome".to_string()),
                args: RegRange { start: 8, count: 2 },
                dst: 3,
            },
            Ir3Instruction::Halt,
            Ir3Instruction::EnterFinally,
            Ir3Instruction::EndFinally,
            Ir3Instruction::Halt,
            Ir3Instruction::EnterCatch { dst: 1 },
            Ir3Instruction::Move { dst: 0, src: 1 },
            Ir3Instruction::Halt,
            Ir3Instruction::Throw { value: 0 },
        ],
        vec![Ir3FunctionDesc {
            entry: 10,
            arity: 3,
            frame_size: 3,
            name: Some("isolated_explicit_finally_thrower".to_string()),
            is_generator: false,
            rest_param_index: None,
        }],
    );
    let mut core = test_interpreter();
    core.config
        .granted_capabilities
        .insert(RuntimeCapability::Builtin);
    let array = core
        .alloc_array_from_values(&[Value::Int(1)])
        .expect("isolated callback receiver should allocate");
    core.write_reg(8, Value::Object(array))
        .expect("receiver register should be writable");
    core.write_reg(9, Value::Function(0))
        .expect("callback register should be writable");

    assert_eq!(
        core.execute(&module)
            .expect("isolated throw should traverse the explicit finalizer")
            .value,
        Value::Int(1)
    );
    assert!(core.pending_exception.is_none());
    assert!(core.pending_return.is_none());
    assert!(core.pending_finally_entry.is_none());
    assert!(core.finally_frames.is_empty());
    assert!(core.suspended_abrupt_completions.is_empty());
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn discard_abrupt_completion_preserves_outer_frame_label_bd_bvgmr() {
    let module =
        test_module_with_functions(vec![Ir3Instruction::DiscardAbruptCompletion], Vec::new());
    let mut core = test_interpreter();
    let outer = AbruptCompletion::Exception(
        Value::str("outer"),
        Label::Custom {
            name: "outer-finally-label".repeat(8),
            level: 5,
        },
    );
    core.finally_frames.push(FinallyFrame {
        completion: Some(outer.clone()),
    });
    core.finally_frames.push(FinallyFrame {
        completion: Some(AbruptCompletion::Return(LabeledReturn {
            value: Value::str("inner"),
            label: Label::Public,
        })),
    });
    core.sync_estimated_memory_bytes()
        .expect("owned completion fixture should fit");
    let snapshot = core
        .snapshot_module_execution()
        .expect("snapshot should preserve finalizer ownership");
    core.clear_finally_frames();
    core.restore_module_execution(snapshot, true);

    core.run_loop(&module)
        .expect("discard should remove only the local finalizer frame");

    assert!(core.pending_exception.is_none());
    assert!(core.pending_return.is_none());
    assert!(core.pending_finally_entry.is_none());
    assert!(matches!(
        core.finally_frames.as_slice(),
        [FinallyFrame { completion: Some(restored) }]
            if matches!((restored, &outer),
                (
                    AbruptCompletion::Exception(restored_value, restored_label),
                    AbruptCompletion::Exception(expected_value, expected_label)
                ) if restored_value == expected_value && restored_label == expected_label)
    ));

    let mut normal_nested_core = test_interpreter();
    normal_nested_core.finally_frames.push(FinallyFrame {
        completion: Some(outer),
    });
    normal_nested_core
        .finally_frames
        .push(FinallyFrame { completion: None });
    normal_nested_core
        .sync_estimated_memory_bytes()
        .expect("normal nested finalizer fixture should fit");
    normal_nested_core
        .run_loop(&module)
        .expect("normal nested finally must not capture the outer completion");
    assert_eq!(normal_nested_core.finally_frames.len(), 1);
    assert_eq!(
        normal_nested_core.estimated_memory_bytes(),
        normal_nested_core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn finally_entry_survives_budget_boundary_and_snapshot_bd_bvgmr() {
    let module = test_module_with_functions(
        vec![
            Ir3Instruction::LoadInt { dst: 0, value: 7 },
            Ir3Instruction::BeginTry {
                catch_target: 3,
                finally_target: Some(3),
            },
            Ir3Instruction::Return { value: 0 },
            Ir3Instruction::EnterFinally,
            Ir3Instruction::EndFinally,
        ],
        Vec::new(),
    );
    let mut core = test_interpreter();
    core.config.instruction_budget = 3;

    assert!(matches!(
        core.run_loop(&module),
        Err(InterpreterError::BudgetExhausted {
            executed: 3,
            budget: 3,
        })
    ));
    assert_eq!(core.ip, 3);
    assert_eq!(
        core.pending_finally_entry,
        Some(PendingFinallyEntry {
            target: 3,
            mode: FinallyMode::Return,
        })
    );
    assert!(core.finally_frames.is_empty());

    let snapshot = core
        .snapshot_module_execution()
        .expect("pending finalizer entry should be snapshot-safe");
    core.pending_finally_entry = None;
    core.restore_module_execution(snapshot, true);
    core.config.instruction_budget = 10;

    assert_eq!(
        core.run_loop(&module)
            .expect("resumed finalizer should complete the owned return"),
        Value::Int(7)
    );
    assert!(core.pending_return.is_none());
    assert!(core.pending_finally_entry.is_none());
    assert!(core.finally_frames.is_empty());
}

#[test]
fn finally_entry_survives_cancellation_boundary_bd_bvgmr() {
    let module = test_module_with_functions(
        vec![
            Ir3Instruction::BeginTry {
                catch_target: 2,
                finally_target: Some(2),
            },
            Ir3Instruction::Throw { value: 0 },
            Ir3Instruction::EnterFinally,
            Ir3Instruction::EndFinally,
        ],
        Vec::new(),
    );
    let token = CancellationToken::new();
    token.cancel();
    let mut config = InterpreterConfig::quickjs_defaults();
    config.granted_capabilities = std::collections::BTreeSet::from([
        RuntimeCapability::VmDispatch,
        RuntimeCapability::HeapAllocate,
    ]);
    config.cancellation_token = Some(token.clone());
    config.checkpoint_density = 3;
    let mut core = InterpreterCore::new(config, "bd-bvgmr-cancel");
    core.write_reg_with_label(0, Value::str("boom"), Label::Secret)
        .expect("throw value should fit");

    assert_eq!(core.run_loop(&module), Err(InterpreterError::Cancelled));
    assert_eq!(core.ip, 2);
    assert_eq!(
        core.pending_finally_entry,
        Some(PendingFinallyEntry {
            target: 2,
            mode: FinallyMode::Exception,
        })
    );

    token.reset();
    assert_eq!(
        core.run_loop(&module),
        Err(InterpreterError::UncaughtException {
            value: "boom".to_string(),
        })
    );
    assert!(core.pending_finally_entry.is_none());
    assert!(core.finally_frames.is_empty());
    assert!(core.suspended_abrupt_completions.is_empty());
    assert_eq!(core.pending_exception_label, Label::Secret);
}

#[test]
fn uncaught_throw_from_finally_clears_owned_frames_bd_bvgmr() {
    let module = test_module_with_functions(
        vec![
            Ir3Instruction::LoadInt { dst: 0, value: 1 },
            Ir3Instruction::BeginTry {
                catch_target: 3,
                finally_target: Some(3),
            },
            Ir3Instruction::Return { value: 0 },
            Ir3Instruction::EnterFinally,
            Ir3Instruction::Throw { value: 1 },
        ],
        Vec::new(),
    );
    let mut core = test_interpreter();
    core.write_reg_with_label(1, Value::str("new"), Label::Secret)
        .expect("replacement throw should fit");

    assert_eq!(
        core.run_loop(&module),
        Err(InterpreterError::UncaughtException {
            value: "new".to_string(),
        })
    );
    assert!(core.pending_return.is_none());
    assert!(core.pending_finally_entry.is_none());
    assert!(core.finally_frames.is_empty());
    assert!(core.suspended_abrupt_completions.is_empty());
    assert_eq!(core.pending_exception, Some(Value::str("new")));
    assert_eq!(core.pending_exception_label, Label::Secret);
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn finally_frame_budget_refusal_preserves_pending_entry_bd_bvgmr() {
    let module = test_module_with_functions(vec![Ir3Instruction::EnterFinally], Vec::new());
    let mut core = test_interpreter();
    let pending_return = LabeledReturn {
        value: Value::str("budgeted return"),
        label: Label::Custom {
            name: "budgeted-finalizer-label".repeat(8),
            level: 4,
        },
    };
    core.replace_pending_abrupt_slots(None, Some(pending_return.clone()))
        .expect("pending return should fit before finalizer entry");
    core.pending_finally_entry = Some(PendingFinallyEntry {
        target: 0,
        mode: FinallyMode::Return,
    });
    let baseline = core
        .sync_estimated_memory_bytes()
        .expect("pending finalizer fixture should fit");
    core.config.max_total_memory_bytes = baseline
        .saturating_add(std::mem::size_of::<FinallyFrame>() as u64)
        .saturating_sub(1);

    assert!(matches!(
        core.run_loop(&module),
        Err(InterpreterError::MemoryBudgetExceeded { .. })
    ));
    assert_eq!(core.pending_return, Some(pending_return));
    assert_eq!(
        core.pending_finally_entry,
        Some(PendingFinallyEntry {
            target: 0,
            mode: FinallyMode::Return,
        })
    );
    assert!(core.finally_frames.is_empty());
    assert_eq!(core.estimated_memory_bytes(), baseline);
}

#[test]
fn timer_callback_restores_outer_labeled_return_bd_ur3tk_16() {
    let module = test_module_with_functions(
        vec![Ir3Instruction::Return { value: 0 }],
        vec![Ir3FunctionDesc {
            entry: 0,
            arity: 0,
            frame_size: 1,
            name: Some("timer_return".to_string()),
            is_generator: false,
            rest_param_index: None,
        }],
    );
    let mut core = test_interpreter();
    core.closures.push(ClosureValue {
        function_index: 0,
        captured_env: core.scope_chain.snapshot(),
    });
    let pending = LabeledReturn {
        value: Value::str("outer-pending"),
        label: Label::Custom {
            name: "timer-outer-return".repeat(8),
            level: 5,
        },
    };
    core.replace_pending_abrupt_slots(None, Some(pending.clone()))
        .expect("outer return should fit");
    core.sync_estimated_memory_bytes()
        .expect("timer fixture should fit");
    let baseline = core.estimated_memory_bytes();

    assert_eq!(
        core.execute_timer_callback(Value::Closure(0), Some(&module), Vec::new(), Label::Public,)
            .expect("timer callback should execute in an isolated snapshot"),
        Value::Undefined
    );
    assert_eq!(core.pending_return, Some(pending));
    assert_eq!(core.estimated_memory_bytes(), baseline);
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes(),
        "timer snapshot restore must retain exact labeled-return ownership"
    );
}

#[test]
fn labeled_return_custom_label_memory_is_fail_closed_bd_ur3tk_16() {
    fn pending_return() -> LabeledReturn {
        LabeledReturn {
            value: Value::str("return-payload".repeat(32)),
            label: Label::Custom {
                name: "return-label".repeat(64),
                level: 6,
            },
        }
    }

    let mut probe = test_interpreter();
    let baseline = probe
        .sync_estimated_memory_bytes()
        .expect("memory probe baseline");
    probe
        .replace_pending_abrupt_slots(None, Some(pending_return()))
        .expect("unbounded labeled-return probe");
    let delta = probe.estimated_memory_bytes().saturating_sub(baseline);
    assert!(delta > 0, "return value and custom label must be charged");
    assert_eq!(
        probe.estimated_memory_bytes(),
        probe.recompute_estimated_memory_bytes()
    );

    let mut one_short = test_interpreter();
    let one_short_baseline = one_short
        .sync_estimated_memory_bytes()
        .expect("one-short baseline");
    one_short.config.max_total_memory_bytes = one_short_baseline + delta - 1;
    assert!(matches!(
        one_short.replace_pending_abrupt_slots(None, Some(pending_return())),
        Err(InterpreterError::MemoryBudgetExceeded { .. })
    ));
    assert!(one_short.pending_return.is_none());
    assert_eq!(one_short.estimated_memory_bytes(), one_short_baseline);
}

#[test]
fn rollback_call_setup_restores_labeled_return_bd_ur3tk_16() {
    let mut core = test_interpreter();
    let saved_scope = core.scope_chain.snapshot();
    let pending = LabeledReturn {
        value: Value::str("rollback-return"),
        label: Label::Custom {
            name: "rollback-return-label".repeat(16),
            level: 3,
        },
    };
    core.scope_chain
        .push(core.config.max_scope_depth)
        .expect("callee setup scope should fit");
    let pushed_frame = CallFrame {
        return_ip: 77,
        return_reg: 0,
        register_base: 0,
        register_width: core.config.max_registers as usize,
        function_index: Some(0),
        this_value: Value::Undefined,
        this_label: Label::Public,
        new_target_value: Value::Undefined,
        new_target_label: Label::Public,
        super_value: Value::Undefined,
        super_label: Label::Public,
        super_home_object: None,
        construct_this: None,
        derived_constructor: false,
        this_initialized: true,
        initialize_derived_this_on_return: false,
        class_instance_fields: None,
        saved_pending_exception: None,
        saved_pending_exception_label: Label::Public,
        saved_pending_return: Some(pending.clone()),
        saved_suspended_abrupt_depth: 0,
        saved_finally_mode_depth: 0,
        saved_scope_depth: saved_scope.len(),
        saved_scope_chain: Some(saved_scope),
        scope_inert_virtual_scope_bytes: 0,
        async_function_id: None,
        native_boundary: false,
    };
    core.call_stack
        .push(pushed_frame, &mut core.closures.cold_cells);
    core.sync_estimated_memory_bytes()
        .expect("rollback fixture should fit");

    core.rollback_call_setup();

    assert_eq!(core.pending_return, Some(pending));
    assert!(core.call_stack.is_empty());
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes(),
        "rollback must move both the return value and its dynamic label back to pending state"
    );
}

#[test]
fn call_method_load_this_preserves_receiver_label_bd_ur3tk_1() {
    let module = test_module_with_functions(
        vec![
            Ir3Instruction::CallMethod {
                receiver: 0,
                callee: 1,
                args: RegRange { start: 2, count: 0 },
                dst: 2,
            },
            Ir3Instruction::Return { value: 2 },
            Ir3Instruction::LoadThis { dst: 0 },
            Ir3Instruction::Return { value: 0 },
        ],
        vec![Ir3FunctionDesc {
            entry: 2,
            arity: 0,
            frame_size: 1,
            name: Some("return_this".to_string()),
            is_generator: false,
            rest_param_index: None,
        }],
    );
    let mut core = test_interpreter();
    core.mutate_registers(|registers| {
        registers[0] = Value::str("secret-receiver");
        registers[1] = Value::Function(0);
    });
    core.set_register_label(0, Label::Secret)
        .expect("receiver label");

    assert_eq!(
        core.run_loop(&module).expect("method should return this"),
        Value::str("secret-receiver")
    );
    assert_eq!(
        core.get_register_label(2).expect("method return label"),
        &Label::Secret
    );
}

#[test]
fn call_method_argument_preserves_label_bd_ur3tk_1() {
    let module = test_module_with_functions(
        vec![
            Ir3Instruction::CallMethod {
                receiver: 0,
                callee: 1,
                args: RegRange { start: 2, count: 1 },
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
            Ir3Instruction::Return { value: 0 },
        ],
        vec![Ir3FunctionDesc {
            entry: 2,
            arity: 1,
            frame_size: 1,
            name: Some("return_argument".to_string()),
            is_generator: false,
            rest_param_index: None,
        }],
    );
    let mut core = test_interpreter();
    core.mutate_registers(|registers| {
        registers[0] = Value::str("public-receiver");
        registers[1] = Value::Function(0);
        registers[2] = Value::str("secret-argument");
    });
    core.set_register_label(2, Label::Secret)
        .expect("method argument label");

    assert_eq!(
        core.run_loop(&module)
            .expect("method should return argument"),
        Value::str("secret-argument")
    );
    assert_eq!(
        core.get_register_label(3).expect("method result label"),
        &Label::Secret
    );
}

/// bd-9vouw.501: `f.apply(t, list)` runs `f` as an ordinary frame only
/// while nothing in the call carries a label. The isolated call joins a
/// labelled list's label into the callee's context, so a Secret list
/// still taints the result; an unlabelled one leaves it Public, and the
/// staged overflow is gone once the call returns.
#[test]
fn apply_with_a_labelled_list_keeps_the_isolated_call_bd_9vouw_501() {
    let module = test_module_with_functions(
        vec![
            Ir3Instruction::CallMethod {
                receiver: 0,
                callee: 1,
                args: RegRange { start: 2, count: 2 },
                dst: 4,
            },
            Ir3Instruction::Return { value: 4 },
            Ir3Instruction::Return { value: 0 },
        ],
        vec![Ir3FunctionDesc {
            entry: 2,
            arity: 1,
            frame_size: 1,
            name: Some("return_argument".to_string()),
            is_generator: false,
            rest_param_index: None,
        }],
    );
    for (list_label, expected) in [
        (Label::Public, Label::Public),
        (Label::Secret, Label::Secret),
    ] {
        let mut core = test_interpreter();
        let list = core
            .alloc_array_from_values(&[Value::Int(7)])
            .expect("argument list");
        core.mutate_registers(|registers| {
            registers[0] = Value::Function(0);
            registers[1] = Value::BuiltinFunction(BuiltinFunction::new_kind(
                BuiltinFunctionKind::FunctionPrototypeApply,
            ));
            registers[2] = Value::Undefined;
            registers[3] = Value::Object(list);
        });
        core.set_register_label(3, list_label.clone())
            .expect("list label");
        assert_eq!(
            core.run_loop(&module).expect("apply returns its argument"),
            Value::Int(7),
            "{list_label:?} list"
        );
        assert_eq!(
            core.get_register_label(4).expect("apply result label"),
            &expected,
            "{list_label:?} list"
        );
        assert!(core.argument_overflow.is_empty());
    }
}

#[test]
fn rest_parameter_joins_trailing_argument_labels_bd_ur3tk_1() {
    let module = test_module_with_functions(
        vec![
            Ir3Instruction::Call {
                callee: 0,
                args: RegRange { start: 1, count: 3 },
                dst: 4,
            },
            Ir3Instruction::Return { value: 4 },
            Ir3Instruction::Return { value: 1 },
        ],
        vec![Ir3FunctionDesc {
            entry: 2,
            arity: 2,
            frame_size: 2,
            name: Some("return_rest".to_string()),
            is_generator: false,
            rest_param_index: Some(1),
        }],
    );
    let mut core = test_interpreter();
    core.mutate_registers(|registers| {
        registers[0] = Value::Function(0);
        registers[1] = Value::str("fixed");
        registers[2] = Value::str("confidential-rest");
        registers[3] = Value::str("secret-rest");
    });
    core.set_register_label(2, Label::Confidential)
        .expect("confidential rest label");
    core.set_register_label(3, Label::Secret)
        .expect("secret rest label");

    let Value::Object(rest_id) = core
        .run_loop(&module)
        .expect("rest-parameter call should return array")
    else {
        panic!("rest parameter should return an array object");
    };
    assert_eq!(
        core.read_array_like_values(rest_id),
        vec![Value::str("confidential-rest"), Value::str("secret-rest")]
    );
    assert_eq!(
        core.get_register_label(4).expect("rest result label"),
        &Label::Secret
    );
}

#[test]
fn url_state_is_memory_exact_ifc_labeled_and_seed_cleared_bd_8y0gs() {
    let mut core = test_interpreter();
    let seed = core
        .capture_execution_seed()
        .expect("test execution-seed capture must fit");
    core.write_reg(0, Value::str("http://example.com/?a=1"))
        .expect("URL source register");
    core.set_register_label(0, Label::Secret)
        .expect("URL source label");
    let Value::Object(url_id) = core
        .construct_url(RegRange { start: 0, count: 1 })
        .expect("construct authenticated URL")
    else {
        panic!("URL constructor must return an object");
    };
    let params_id = core.url_objects[&url_id].search_params;
    assert_eq!(core.url_objects[&url_id].lifecycle_label, Label::Secret);
    assert_eq!(
        core.url_search_params[&params_id].lifecycle_label,
        Label::Secret
    );
    core.write_reg(1, Value::Object(url_id))
        .expect("URL object register");
    core.set_register_label(1, Label::Secret)
        .expect("URL object label");
    let capture_sources = core.capture_heap_label_sources();
    assert_eq!(capture_sources[url_id.0 as usize], Some(1));
    assert_eq!(
        capture_sources[params_id.0 as usize],
        Some(1),
        "native URL.searchParams reachability must project the URL register label"
    );
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );

    core.reset_execution_state_from_seed(&seed)
        .expect("restore pre-URL seed");
    assert!(core.url_objects.is_empty());
    assert!(core.url_search_params.is_empty());
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn url_constructor_and_linked_mutation_refusals_are_atomic_bd_8y0gs() {
    let mut refused = test_interpreter();
    refused
        .write_reg(0, Value::str("http://example.com/?a=1"))
        .expect("URL source register");
    let baseline_heap_len = refused.heap.len();
    let baseline_bytes = refused.estimated_memory_bytes();
    refused.config.max_total_memory_bytes = baseline_bytes;
    assert!(matches!(
        refused.construct_url(RegRange { start: 0, count: 1 }),
        Err(InterpreterError::MemoryBudgetExceeded { .. })
    ));
    assert_eq!(refused.heap.len(), baseline_heap_len);
    assert!(refused.url_objects.is_empty());
    assert!(refused.url_search_params.is_empty());
    assert_eq!(refused.estimated_memory_bytes(), baseline_bytes);

    let mut second_allocation_refused = test_interpreter();
    second_allocation_refused
        .write_reg(0, Value::str("http://example.com/?a=1"))
        .expect("URL source register");
    let baseline_heap_len = second_allocation_refused.heap.len();
    let baseline_bytes = second_allocation_refused.estimated_memory_bytes();
    second_allocation_refused.config.max_heap_objects = u32::try_from(baseline_heap_len)
        .unwrap_or(u32::MAX)
        .saturating_add(1);
    assert!(matches!(
        second_allocation_refused.construct_url(RegRange { start: 0, count: 1 }),
        Err(InterpreterError::MemoryBudgetExceeded { .. })
    ));
    assert_eq!(second_allocation_refused.heap.len(), baseline_heap_len);
    assert!(second_allocation_refused.url_objects.is_empty());
    assert!(second_allocation_refused.url_search_params.is_empty());
    assert_eq!(
        second_allocation_refused.estimated_memory_bytes(),
        baseline_bytes
    );

    let mut pair_amplification_refused = test_interpreter();
    let tiny_pairs = "a=&".repeat(64);
    pair_amplification_refused
        .write_reg(0, Value::str(&tiny_pairs))
        .expect("URLSearchParams source register");
    let baseline_heap_len = pair_amplification_refused.heap.len();
    let baseline_bytes = pair_amplification_refused.estimated_memory_bytes();
    let former_three_x_check =
        InterpreterCore::estimate_string_bytes(&tiny_pairs).saturating_mul(3);
    pair_amplification_refused.config.max_total_memory_bytes =
        baseline_bytes.saturating_add(former_three_x_check);
    assert!(matches!(
        pair_amplification_refused
            .construct_url_search_params(None, RegRange { start: 0, count: 1 }),
        Err(InterpreterError::MemoryBudgetExceeded { .. })
    ));
    assert_eq!(pair_amplification_refused.heap.len(), baseline_heap_len);
    assert!(pair_amplification_refused.url_search_params.is_empty());
    assert_eq!(
        pair_amplification_refused.estimated_memory_bytes(),
        baseline_bytes
    );

    let mut core = test_interpreter();
    core.write_reg(0, Value::str("http://example.com/?a=1"))
        .expect("URL source register");
    let Value::Object(url_id) = core
        .construct_url(RegRange { start: 0, count: 1 })
        .expect("construct URL before mutation")
    else {
        panic!("URL constructor must return an object");
    };
    let params_id = core.url_objects[&url_id].search_params;
    let before_params = core.url_search_params[&params_id].clone();
    let before_url = core.url_objects[&url_id].clone();
    let before_bytes = core.estimated_memory_bytes();
    let former_clone_only_check =
        InterpreterCore::estimate_url_search_params_state_bytes(&before_params)
            .saturating_add(InterpreterCore::estimate_url_state_bytes(&before_url))
            .saturating_mul(2);
    core.config.max_total_memory_bytes = before_bytes.saturating_add(former_clone_only_check);
    assert!(matches!(
        core.mutate_url_search_params(
            params_id,
            UrlSearchParamsMutation::Append("large".to_string(), "value".repeat(64)),
            &Label::Public,
        ),
        Err(InterpreterError::MemoryBudgetExceeded { .. })
    ));
    assert_eq!(core.url_search_params[&params_id], before_params);
    assert_eq!(core.url_objects[&url_id], before_url);
    assert_eq!(core.estimated_memory_bytes(), before_bytes);
    assert_eq!(before_bytes, core.recompute_estimated_memory_bytes());
}

/// bd-fw7zd: the engine-owned finite stream queue must participate in both
/// incremental and recomputed memory totals, and terminal close must
/// replace its live charge exactly once.
#[test]
fn readable_from_state_is_memory_accounted_and_released_bd_fw7zd() {
    let module = test_module_with_functions(Vec::new(), Vec::new());
    let mut core = test_interpreter();
    let source = core
        .alloc_array_from_values(&[])
        .expect("empty source array");
    core.mutate_registers(|registers| registers[0] = Value::Object(source));

    let Value::Object(readable_id) = core
        .construct_readable_from(RegRange { start: 0, count: 1 })
        .expect("construct finite readable")
    else {
        panic!("Readable.from must return an object");
    };
    assert!(core.readable_from_streams.contains_key(&readable_id));
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );

    core.set_object_property(
        readable_id,
        "readableFlowing".to_string(),
        Value::str("guest-forged-flow-state"),
    )
    .expect("guest flowing mirror mutation");
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
    core.activate_readable_from_data_flow(readable_id, "data")
        .expect("flow activation");
    assert_eq!(
        core.heap
            .get(readable_id.0 as usize)
            .and_then(|object| object.properties.get("readableFlowing")),
        Some(&Value::Bool(true))
    );
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
    core.run_event_loop_until_idle_with_module(Some(&module))
        .expect("readable event loop");

    assert!(!core.readable_from_streams.contains_key(&readable_id));
    assert!(core.pending_readable_from_pumps.is_empty());
    assert!(!core.event_loop.has_pending_work());
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn readable_pump_registration_is_atomic_and_exact_bd_6vh2s_bd_rgx1b() {
    let mut core = test_interpreter();
    let Value::Object(readable) = core
        .construct_stream_readable(RegRange { start: 0, count: 0 })
        .expect("unscheduled generic Readable")
    else {
        panic!("Readable constructor must return an object");
    };
    assert!(core.pending_readable_from_pumps.is_empty());
    let baseline_bytes = core.estimated_memory_bytes();
    let baseline_event_loop_bytes = core.event_loop.estimated_memory_bytes();
    let registration_bytes = core.readable_pump_registration_bytes();
    let pump_bytes = core.readable_pump_retained_bytes();
    assert_eq!(
        pump_bytes,
        registration_bytes.saturating_add(MEMORY_ESTIMATE_MAP_ENTRY_BYTES)
    );

    core.config.max_total_memory_bytes =
        baseline_bytes.saturating_add(pump_bytes).saturating_sub(1);
    let error = core
        .schedule_readable_from_pump(readable)
        .expect_err("one-byte-short pump registration must fail");
    assert!(matches!(
        error,
        InterpreterError::MemoryBudgetExceeded { .. }
    ));
    assert!(core.pending_readable_from_pumps.is_empty());
    assert_eq!(
        core.event_loop.estimated_memory_bytes(),
        baseline_event_loop_bytes
    );
    assert_eq!(core.estimated_memory_bytes(), baseline_bytes);
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );

    core.config.max_total_memory_bytes = baseline_bytes.saturating_add(pump_bytes);
    assert!(
        core.schedule_readable_from_pump(readable)
            .expect("exact pump ceiling")
    );
    let scheduled_bytes = core.estimated_memory_bytes();
    assert_eq!(scheduled_bytes, baseline_bytes.saturating_add(pump_bytes));
    assert_eq!(
        core.event_loop.estimated_memory_bytes(),
        baseline_event_loop_bytes.saturating_add(registration_bytes)
    );
    assert_eq!(
        core.pending_readable_pumps_memory_bytes(),
        MEMORY_ESTIMATE_MAP_ENTRY_BYTES
    );
    assert_eq!(scheduled_bytes, core.recompute_estimated_memory_bytes());
    assert!(
        !core
            .schedule_readable_from_pump(readable)
            .expect("duplicate suppression is infallible")
    );
    assert_eq!(core.estimated_memory_bytes(), scheduled_bytes);
}

#[test]
fn readable_pump_side_table_charges_scale_per_entry_bd_rgx1b() {
    let mut pending = test_interpreter();
    let Value::Object(first_pending) = pending
        .construct_stream_readable(RegRange { start: 0, count: 0 })
        .expect("first unscheduled generic Readable")
    else {
        panic!("Readable constructor must return an object");
    };
    let Value::Object(second_pending) = pending
        .construct_stream_readable(RegRange { start: 0, count: 0 })
        .expect("second unscheduled generic Readable")
    else {
        panic!("Readable constructor must return an object");
    };
    let pending_baseline = pending.estimated_memory_bytes();
    let event_loop_baseline = pending.event_loop.estimated_memory_bytes();
    let registration_bytes = pending.readable_pump_registration_bytes();
    let retained_bytes = pending.readable_pump_retained_bytes();

    assert!(
        pending
            .schedule_readable_from_pump(first_pending)
            .expect("first pending pump")
    );
    assert!(
        pending
            .schedule_readable_from_pump(second_pending)
            .expect("second pending pump")
    );
    assert_eq!(pending.pending_readable_from_pumps.len(), 2);
    assert_eq!(
        pending.pending_readable_pumps_memory_bytes(),
        MEMORY_ESTIMATE_MAP_ENTRY_BYTES.saturating_mul(2)
    );
    assert_eq!(
        pending.event_loop.estimated_memory_bytes(),
        event_loop_baseline.saturating_add(registration_bytes.saturating_mul(2))
    );
    assert_eq!(
        pending.estimated_memory_bytes(),
        pending_baseline.saturating_add(retained_bytes.saturating_mul(2))
    );
    assert_eq!(
        pending.estimated_memory_bytes(),
        pending.recompute_estimated_memory_bytes()
    );

    let mut reservations = test_interpreter();
    let Value::Object(first_reserved) = reservations
        .construct_stream_readable(RegRange { start: 0, count: 0 })
        .expect("first reservation Readable")
    else {
        panic!("Readable constructor must return an object");
    };
    let Value::Object(second_reserved) = reservations
        .construct_stream_readable(RegRange { start: 0, count: 0 })
        .expect("second reservation Readable")
    else {
        panic!("Readable constructor must return an object");
    };
    let reservation_baseline = reservations.estimated_memory_bytes();
    let reservation_bytes = reservations.readable_pump_retained_bytes();

    assert!(
        reservations
            .reserve_readable_pump(first_reserved)
            .expect("first pump reservation")
    );
    assert!(
        reservations
            .reserve_readable_pump(second_reserved)
            .expect("second pump reservation")
    );
    assert_eq!(reservations.readable_pump_reservations.len(), 2);
    assert_eq!(
        reservations.readable_pump_reservations_memory_bytes(),
        reservation_bytes.saturating_mul(2)
    );
    assert_eq!(
        reservations.estimated_memory_bytes(),
        reservation_baseline.saturating_add(reservation_bytes.saturating_mul(2))
    );
    assert_eq!(
        reservations.estimated_memory_bytes(),
        reservations.recompute_estimated_memory_bytes()
    );

    reservations.release_readable_pump_reservation(first_reserved);
    assert_eq!(
        reservations.readable_pump_reservations_memory_bytes(),
        reservation_bytes
    );
    assert_eq!(
        reservations.estimated_memory_bytes(),
        reservation_baseline.saturating_add(reservation_bytes)
    );
    reservations.release_readable_pump_reservation(second_reserved);
    assert!(reservations.readable_pump_reservations.is_empty());
    assert_eq!(reservations.estimated_memory_bytes(), reservation_baseline);
    assert_eq!(
        reservations.estimated_memory_bytes(),
        reservations.recompute_estimated_memory_bytes()
    );
}

#[test]
fn readable_pipe_link_is_authenticated_memory_exact_and_atomic_bd_7h43f() {
    let module = test_module_with_functions(Vec::new(), Vec::new());
    let make_streams = || {
        let mut core = test_interpreter();
        let Value::Object(source) = core
            .construct_stream_readable(RegRange { start: 0, count: 0 })
            .expect("unscheduled generic Readable")
        else {
            panic!("Readable constructor must return an object");
        };
        let Value::Object(destination) = core
            .construct_stream_writable(RegRange { start: 0, count: 0 })
            .expect("generic Writable")
        else {
            panic!("Writable constructor must return an object");
        };
        core.mutate_registers(|registers| registers[0] = Value::Object(destination));
        (core, source, destination)
    };

    let (mut accepted, source, destination) = make_streams();
    accepted
        .set_register_label(0, Label::Secret)
        .expect("secret destination argument label");
    let returned = accepted
        .readable_pipe(
            &module,
            Value::Object(source),
            RegRange { start: 0, count: 1 },
        )
        .expect("bounded pipe registration");
    assert_eq!(returned, Value::Object(destination));
    assert_eq!(accepted.next_readable_pipe_token, 1);
    assert_eq!(
        accepted.readable_pipe_links.get(&source),
        Some(&ReadablePipeLink {
            destination,
            token: 0,
        })
    );
    assert_eq!(
        accepted.readable_pipe_sources.get(&destination),
        Some(&source)
    );
    assert_eq!(accepted.event_listener_records_for(source, "data").len(), 1);
    assert_eq!(accepted.event_listener_records_for(source, "end").len(), 1);
    assert_eq!(
        accepted.readable_from_streams[&source].lifecycle_label,
        Label::Secret,
        "pipe invocation provenance must reach later write/end callbacks"
    );
    assert!(accepted.readable_from_streams[&source].flowing);
    assert_eq!(accepted.pending_readable_from_pumps.len(), 1);
    assert_eq!(
        accepted.estimated_memory_bytes(),
        accepted.recompute_estimated_memory_bytes()
    );

    let data_builtin = match &accepted.event_listener_records_for(source, "data")[0].listener {
        Value::BuiltinFunction(builtin) => builtin.clone(),
        other => panic!("pipe data listener must be a builtin, got {other:?}"),
    };
    accepted.clear_readable_pipe_links();
    assert!(accepted.readable_pipe_links.is_empty());
    assert!(accepted.readable_pipe_sources.is_empty());
    assert!(
        accepted
            .event_listener_records_for(source, "data")
            .is_empty()
    );
    assert!(
        accepted
            .event_listener_records_for(source, "end")
            .is_empty()
    );
    assert_eq!(
        accepted.readable_pipe_data(
            &module,
            Value::Object(source),
            &data_builtin,
            RegRange { start: 1, count: 0 },
        ),
        Ok(Value::Undefined),
        "a removed callback from an in-flight EventEmitter snapshot is a no-op"
    );
    assert_eq!(
        accepted.estimated_memory_bytes(),
        accepted.recompute_estimated_memory_bytes()
    );

    let (mut ended, ended_source, _) = make_streams();
    ended
        .readable_pipe(
            &module,
            Value::Object(ended_source),
            RegRange { start: 0, count: 1 },
        )
        .expect("pipe for manual end-listener cleanup");
    let end_builtin = match &ended.event_listener_records_for(ended_source, "end")[0].listener {
        Value::BuiltinFunction(builtin) => builtin.clone(),
        other => panic!("pipe end listener must be a builtin, got {other:?}"),
    };
    ended
        .readable_pipe_end(
            &module,
            Value::Object(ended_source),
            &end_builtin,
            RegRange { start: 1, count: 0 },
        )
        .expect("manual internal end invocation");
    assert!(ended.readable_pipe_links.is_empty());
    assert!(
        ended
            .event_listener_records_for(ended_source, "data")
            .is_empty()
    );
    assert!(
        ended
            .event_listener_records_for(ended_source, "end")
            .is_empty()
    );
    assert_eq!(
        ended.readable_pipe_end(
            &module,
            Value::Object(ended_source),
            &end_builtin,
            RegRange { start: 1, count: 0 },
        ),
        Ok(Value::Undefined)
    );
    assert_eq!(
        ended.estimated_memory_bytes(),
        ended.recompute_estimated_memory_bytes()
    );

    let (mut isolated, isolated_source, isolated_destination) = make_streams();
    isolated
        .readable_pipe(
            &module,
            Value::Object(isolated_source),
            RegRange { start: 0, count: 1 },
        )
        .expect("pipe for internal-listener isolation");
    assert!(
        isolated
            .guest_event_listener_records_for(isolated_source, "data")
            .is_empty(),
        "listeners() must not export the authenticated internal callback"
    );
    isolated.detach_readable_pipe(isolated_source, isolated_destination, 0);
    assert!(
        isolated
            .event_listener_records_for(isolated_source, "data")
            .is_empty(),
        "internal teardown removes the hidden authenticated record"
    );
    assert_eq!(
        isolated.estimated_memory_bytes(),
        isolated.recompute_estimated_memory_bytes()
    );

    let (mut destroyed, destroyed_source, destroyed_destination) = make_streams();
    destroyed
        .readable_pipe(
            &module,
            Value::Object(destroyed_source),
            RegRange { start: 0, count: 1 },
        )
        .expect("pipe before destination destroy");
    let stale_data =
        match &destroyed.event_listener_records_for(destroyed_source, "data")[0].listener {
            Value::BuiltinFunction(builtin) => builtin.clone(),
            other => panic!("pipe data listener must be a builtin, got {other:?}"),
        };
    destroyed
        .writable_destroy(
            Value::Object(destroyed_destination),
            RegRange { start: 1, count: 0 },
        )
        .expect("destroy pipe destination");
    assert!(destroyed.readable_pipe_links.is_empty());
    assert!(
        destroyed
            .event_listener_records_for(destroyed_source, "data")
            .is_empty()
    );
    assert!(
        destroyed
            .event_listener_records_for(destroyed_source, "end")
            .is_empty()
    );
    assert_eq!(
        destroyed.readable_pipe_data(
            &module,
            Value::Object(destroyed_source),
            &stale_data,
            RegRange { start: 1, count: 0 },
        ),
        Ok(Value::Undefined)
    );
    assert_eq!(
        destroyed.estimated_memory_bytes(),
        destroyed.recompute_estimated_memory_bytes()
    );

    let (mut listener_tight, tight_source, _) = make_streams();
    let tight_baseline = listener_tight.estimated_memory_bytes();
    let listener_value_bytes = InterpreterCore::estimate_string_bytes("").saturating_mul(2);
    listener_tight.config.max_total_memory_bytes = tight_baseline
        .saturating_add(listener_value_bytes)
        .saturating_sub(1);
    assert!(matches!(
        listener_tight.readable_pipe(
            &module,
            Value::Object(tight_source),
            RegRange { start: 0, count: 1 },
        ),
        Err(InterpreterError::MemoryBudgetExceeded { .. })
    ));
    assert_eq!(listener_tight.next_readable_pipe_token, 0);
    assert!(listener_tight.readable_pipe_links.is_empty());
    assert!(listener_tight.readable_pipe_sources.is_empty());
    assert_eq!(listener_tight.estimated_memory_bytes(), tight_baseline);

    let (mut instruction_tight, instruction_source, _) = make_streams();
    let instructions_before = instruction_tight.instructions_executed;
    instruction_tight.config.instruction_budget = instructions_before.saturating_add(3);
    assert!(matches!(
        instruction_tight.readable_pipe(
            &module,
            Value::Object(instruction_source),
            RegRange { start: 0, count: 1 },
        ),
        Err(InterpreterError::BudgetExhausted { .. })
    ));
    assert_eq!(instruction_tight.instructions_executed, instructions_before);
    assert!(instruction_tight.readable_pipe_links.is_empty());
    assert!(instruction_tight.readable_pipe_sources.is_empty());

    let (mut custom, custom_source, _) = make_streams();
    let custom_label = Label::Custom {
        name: "pipe-physical-peak".repeat(512),
        level: 7,
    };
    custom
        .set_register_label(0, custom_label.clone())
        .expect("large pipe argument label");
    let custom_baseline = custom.estimated_memory_bytes();
    let projection_bytes = InterpreterCore::estimate_readable_from_state_bytes(
        &custom.readable_from_streams[&custom_source],
    );
    let label_bytes = InterpreterCore::estimate_label_bytes(&custom_label);
    let custom_before = custom.readable_from_streams[&custom_source].clone();
    custom.config.max_total_memory_bytes = custom_baseline
        .saturating_add(projection_bytes)
        .saturating_add(label_bytes)
        .saturating_sub(1);
    assert!(matches!(
        custom.readable_pipe(
            &module,
            Value::Object(custom_source),
            RegRange { start: 0, count: 1 },
        ),
        Err(InterpreterError::MemoryBudgetExceeded { .. })
    ));
    assert_eq!(custom.readable_from_streams[&custom_source], custom_before);
    assert!(custom.readable_pipe_links.is_empty());
    assert_eq!(custom.estimated_memory_bytes(), custom_baseline);
    assert_eq!(
        custom.estimated_memory_bytes(),
        custom.recompute_estimated_memory_bytes()
    );

    let (mut calibrated, calibrated_source, _) = make_streams();
    let baseline = calibrated.estimated_memory_bytes();
    let baseline_state = calibrated.readable_from_streams[&calibrated_source].clone();
    calibrated
        .readable_pipe(
            &module,
            Value::Object(calibrated_source),
            RegRange { start: 0, count: 1 },
        )
        .expect("calibrate exact resident pipe bytes");
    let exact = calibrated.estimated_memory_bytes();
    assert!(exact > baseline);

    let (mut refused, refused_source, _) = make_streams();
    let refused_baseline = refused.estimated_memory_bytes();
    assert_eq!(refused_baseline, baseline);
    refused.config.max_total_memory_bytes = exact.saturating_sub(1);
    let error = refused
        .readable_pipe(
            &module,
            Value::Object(refused_source),
            RegRange { start: 0, count: 1 },
        )
        .expect_err("one byte below retained total must refuse the aggregate peak");
    let InterpreterError::MemoryBudgetExceeded {
        requested_bytes: exact_peak,
        ..
    } = error
    else {
        panic!("aggregate pipe preflight must report its exact peak");
    };
    assert!(exact_peak > exact);
    assert_eq!(refused.next_readable_pipe_token, 0);
    assert!(refused.readable_pipe_links.is_empty());
    assert!(
        refused
            .event_listener_records_for(refused_source, "data")
            .is_empty()
    );
    assert!(
        refused
            .event_listener_records_for(refused_source, "end")
            .is_empty()
    );
    assert!(refused.pending_readable_from_pumps.is_empty());
    assert!(refused.readable_pump_reservations.is_empty());
    assert_eq!(
        refused.readable_from_streams[&refused_source],
        baseline_state
    );
    assert_eq!(refused.estimated_memory_bytes(), refused_baseline);
    assert_eq!(
        refused.estimated_memory_bytes(),
        refused.recompute_estimated_memory_bytes()
    );

    let (mut boundary, boundary_source, _) = make_streams();
    boundary.config.max_total_memory_bytes = exact_peak;
    boundary
        .readable_pipe(
            &module,
            Value::Object(boundary_source),
            RegRange { start: 0, count: 1 },
        )
        .expect("exact aggregate pipe peak must succeed");
    assert!(boundary.estimated_memory_bytes() <= exact_peak);
    assert_eq!(
        boundary.estimated_memory_bytes(),
        boundary.recompute_estimated_memory_bytes()
    );
}

#[test]
fn readable_pipe_backpressure_detaches_and_pauses_bd_7h43f() {
    let module = test_module_with_functions(Vec::new(), Vec::new());
    let mut core = test_interpreter();
    let Value::Object(source) = core
        .construct_stream_readable(RegRange { start: 0, count: 0 })
        .expect("unscheduled generic Readable")
    else {
        panic!("Readable constructor must return an object");
    };
    let Value::Object(destination) = core
        .construct_stream_writable(RegRange { start: 0, count: 0 })
        .expect("generic Writable")
    else {
        panic!("Writable constructor must return an object");
    };
    let destination_state = core
        .writable_streams
        .get_mut(&destination)
        .expect("live Writable");
    destination_state.high_water_mark = 1;
    destination_state.cork_depth = 1;
    core.mutate_registers(|registers| {
        registers[0] = Value::Object(destination);
        registers[1] = Value::str("x");
    });
    core.sync_estimated_memory_bytes()
        .expect("backpressure Writable and register accounting");
    core.readable_pipe(
        &module,
        Value::Object(source),
        RegRange { start: 0, count: 1 },
    )
    .expect("pipe registration");
    let data_builtin = match &core.event_listener_records_for(source, "data")[0].listener {
        Value::BuiltinFunction(builtin) => builtin.clone(),
        other => panic!("pipe data listener must be a builtin, got {other:?}"),
    };

    let error = core
        .readable_pipe_data(
            &module,
            Value::Object(source),
            &data_builtin,
            RegRange { start: 1, count: 1 },
        )
        .expect_err("write(false) must fail closed until drain is modeled");
    assert!(matches!(error, InterpreterError::TypeError { .. }));
    assert!(core.readable_pipe_links.is_empty());
    assert!(core.event_listener_records_for(source, "data").is_empty());
    assert!(core.event_listener_records_for(source, "end").is_empty());
    assert!(!core.readable_from_streams[&source].flowing);
    assert!(core.readable_from_streams[&source].paused);
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn readable_pump_reservation_converts_without_reordering_charge_bd_6vh2s_bd_rgx1b() {
    let mut core = test_interpreter();
    let Value::Object(readable) = core
        .construct_stream_readable(RegRange { start: 0, count: 0 })
        .expect("unscheduled generic Readable")
    else {
        panic!("Readable constructor must return an object");
    };
    let baseline_bytes = core.estimated_memory_bytes();
    let registration_bytes = core.readable_pump_registration_bytes();
    let pump_bytes = core.readable_pump_retained_bytes();

    core.config.max_total_memory_bytes =
        baseline_bytes.saturating_add(pump_bytes).saturating_sub(1);
    let error = core
        .reserve_readable_pump(readable)
        .expect_err("one-byte-short reservation must fail");
    assert!(matches!(
        error,
        InterpreterError::MemoryBudgetExceeded { .. }
    ));
    assert!(core.readable_pump_reservations.is_empty());
    assert_eq!(core.estimated_memory_bytes(), baseline_bytes);

    core.config.max_total_memory_bytes = baseline_bytes.saturating_add(pump_bytes);
    assert!(
        core.reserve_readable_pump(readable)
            .expect("exact reservation ceiling")
    );
    assert_eq!(
        core.readable_pump_reservations
            .get(&readable)
            .map(|reservation| reservation.bytes),
        Some(registration_bytes)
    );
    assert_eq!(core.readable_pump_reservations_memory_bytes(), pump_bytes);
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
    assert!(
        !core
            .schedule_readable_from_pump(readable)
            .expect("reservation suppresses re-entrant duplicates")
    );
    assert!(
        core.readable_pump_reservations[&readable].requested,
        "suppressed re-entrant scheduling must survive until reservation conversion"
    );
    core.config.max_total_memory_bytes = u64::MAX;
    let previous_promise_bytes = core.promise_runtime_memory_bytes();
    let callback_timer_sequence =
        core.event_loop
            .set_timeout(crate::closure_model::ClosureHandle(9), 0, Label::Public);
    core.apply_promise_runtime_memory_delta(previous_promise_bytes)
        .expect("simulated callback timer charge");
    let reserved_total = core.estimated_memory_bytes();
    assert!(
        core.convert_readable_pump_reservation(readable)
            .expect("reservation conversion")
    );
    assert!(core.readable_pump_reservations.is_empty());
    assert_eq!(core.pending_readable_from_pumps.len(), 1);
    assert_eq!(
        core.pending_readable_pumps_memory_bytes(),
        MEMORY_ESTIMATE_MAP_ENTRY_BYTES
    );
    let pump_sequence = *core
        .pending_readable_from_pumps
        .keys()
        .next()
        .expect("converted pump sequence");
    assert!(
        callback_timer_sequence < pump_sequence,
        "callback-created work must retain its registration order ahead of the pump"
    );
    assert_eq!(core.estimated_memory_bytes(), reserved_total);
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );

    let mut activation_core = test_interpreter();
    let Value::Object(activation_readable) = activation_core
        .construct_stream_readable(RegRange { start: 0, count: 0 })
        .expect("activation Readable")
    else {
        panic!("Readable constructor must return an object");
    };
    let activation_reserved = activation_core
        .reserve_readable_activation_pump(activation_readable, "data")
        .expect("activation reservation");
    assert!(activation_reserved);
    assert!(
        !activation_core
            .schedule_readable_from_pump(activation_readable)
            .expect("re-entrant callback pump request")
    );
    activation_core
        .readable_from_streams
        .get_mut(&activation_readable)
        .expect("live activation Readable")
        .paused = true;
    activation_core
        .activate_readable_from_data_flow_with_reservation(
            activation_readable,
            "data",
            activation_reserved,
        )
        .expect("no-longer-applicable activation preserves callback request");
    assert_eq!(activation_core.pending_readable_from_pumps.len(), 1);
    assert!(activation_core.readable_pump_reservations.is_empty());
    assert_eq!(
        activation_core.estimated_memory_bytes(),
        activation_core.recompute_estimated_memory_bytes()
    );

    let mut error_core = test_interpreter();
    let Value::Object(error_readable) = error_core
        .construct_stream_readable(RegRange { start: 0, count: 0 })
        .expect("error-path Readable")
    else {
        panic!("Readable constructor must return an object");
    };
    let error_reserved = error_core
        .reserve_readable_pump(error_readable)
        .expect("error-path reservation");
    assert!(error_reserved);
    assert!(
        !error_core
            .schedule_readable_from_pump(error_readable)
            .expect("error-path callback request")
    );
    let result: Result<(), InterpreterError> = error_core.readable_error_after_reservation(
        error_readable,
        error_reserved,
        InterpreterError::TypeError {
            expected: "sentinel".to_string(),
            got: "error".to_string(),
        },
    );
    assert!(matches!(result, Err(InterpreterError::TypeError { .. })));
    assert_eq!(error_core.pending_readable_from_pumps.len(), 1);
    assert!(error_core.readable_pump_reservations.is_empty());
    assert_eq!(
        error_core.estimated_memory_bytes(),
        error_core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn readable_state_and_pump_commit_rolls_back_one_byte_short_bd_6vh2s() {
    let make_projected = |mut projected: ReadableFromState| {
        projected.buffer.push_back(ReadableBufferedChunk {
            value: Value::str("x"),
            label: Label::Secret,
            units: 1,
        });
        projected.buffered_length = 1;
        projected.data_readable_pending = true;
        projected.lifecycle_label = Label::Secret;
        projected
    };

    let mut core = test_interpreter();
    let Value::Object(readable) = core
        .construct_stream_readable(RegRange { start: 0, count: 0 })
        .expect("unscheduled generic Readable")
    else {
        panic!("Readable constructor must return an object");
    };
    core.set_object_property(
        readable,
        "readableLength".to_string(),
        Value::str("sentinel"),
    )
    .expect("forge length mirror");
    let baseline_bytes = core.estimated_memory_bytes();
    let previous = core.readable_from_streams[&readable].clone();
    let projected = make_projected(previous.clone());
    let state_only_bytes = baseline_bytes
        .saturating_sub(InterpreterCore::estimate_readable_from_state_bytes(
            &previous,
        ))
        .saturating_add(InterpreterCore::estimate_readable_from_state_bytes(
            &projected,
        ));

    core.config.max_total_memory_bytes = state_only_bytes;
    let calibration_error = core
        .commit_readable_state_and_schedule(readable, make_projected(previous.clone()))
        .expect_err("state-only ceiling must expose the exact pump peak");
    let InterpreterError::MemoryBudgetExceeded {
        requested_bytes: exact_bytes,
        max_bytes,
        ..
    } = calibration_error
    else {
        panic!("state-only ceiling must fail on the pump registration");
    };
    assert_eq!(max_bytes, state_only_bytes);
    assert!(exact_bytes > state_only_bytes);
    assert_eq!(core.readable_from_streams[&readable], previous);
    assert!(core.pending_readable_from_pumps.is_empty());
    assert_eq!(core.estimated_memory_bytes(), baseline_bytes);

    core.config.max_total_memory_bytes = exact_bytes.saturating_sub(1);
    let error = core
        .commit_readable_state_and_schedule(readable, make_projected(previous.clone()))
        .expect_err("one-byte-short state and pump transaction must fail");
    assert!(matches!(
        error,
        InterpreterError::MemoryBudgetExceeded { .. }
    ));
    assert_eq!(core.readable_from_streams[&readable], previous);
    assert!(core.pending_readable_from_pumps.is_empty());
    assert_eq!(
        core.heap[readable.0 as usize]
            .properties
            .get("readableLength"),
        Some(&Value::str("sentinel")),
        "refused transaction must preserve the exact guest-forged mirror"
    );
    assert_eq!(core.estimated_memory_bytes(), baseline_bytes);
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );

    core.config.max_total_memory_bytes = exact_bytes;
    core.commit_readable_state_and_schedule(readable, make_projected(previous.clone()))
        .expect("exact state and pump ceiling");
    assert_eq!(core.readable_from_streams[&readable].buffered_length, 1);
    assert_eq!(core.pending_readable_from_pumps.len(), 1);
    assert!(core.estimated_memory_bytes() <= exact_bytes);
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn readable_paused_pull_defers_successor_sequence_until_after_callback_bd_6vh2s() {
    let mut core = test_interpreter();
    let source = core
        .alloc_array_from_values(&[Value::Int(7)])
        .expect("finite source");
    let Value::Object(readable) = core
        .construct_stream_readable(RegRange { start: 0, count: 0 })
        .expect("unscheduled generic Readable")
    else {
        panic!("Readable constructor must return an object");
    };
    let mut finite = core.readable_from_streams[&readable].clone();
    finite.source = Value::Object(source);
    finite.push_only = false;
    core.commit_readable_state(readable, finite)
        .expect("install finite paused state");

    assert!(
        core.reserve_readable_pump(readable)
            .expect("reserve before paused source pull")
    );
    assert!(
        core.readable_pull_source_chunk(readable)
            .expect("pull first finite chunk")
    );
    assert!(core.pending_readable_from_pumps.is_empty());
    assert!(core.readable_pump_reservations[&readable].requested);

    let previous_promise_bytes = core.promise_runtime_memory_bytes();
    let callback_io_sequence = core
        .event_loop
        .schedule_io_completion(crate::closure_model::ClosureHandle(9), Label::Public);
    core.apply_promise_runtime_memory_delta(previous_promise_bytes)
        .expect("simulated readable-listener I/O charge");
    assert!(
        core.convert_readable_pump_reservation(readable)
            .expect("convert successor after callback")
    );
    let successor_sequence = *core
        .pending_readable_from_pumps
        .keys()
        .next()
        .expect("successor pump sequence");
    assert!(callback_io_sequence < successor_sequence);
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn readable_close_preserves_deleted_terminal_mirrors_at_ceiling_bd_6vh2s() {
    let module = test_module_with_functions(Vec::new(), Vec::new());
    let mut core = test_interpreter();
    let Value::Object(readable) = core
        .construct_stream_readable(RegRange { start: 0, count: 0 })
        .expect("generic Readable")
    else {
        panic!("Readable constructor must return an object");
    };
    core.readable_from_streams
        .get_mut(&readable)
        .expect("live Readable")
        .phase = ReadableFromPumpPhase::Close;
    assert!(
        core.remove_object_property(readable, "destroyed")
            .expect("delete destroyed mirror")
    );
    assert!(
        core.remove_object_property(readable, "closed")
            .expect("delete closed mirror")
    );
    core.config.max_total_memory_bytes = core.estimated_memory_bytes();

    core.drive_readable_from_pump(readable, Some(&module))
        .expect("terminal cleanup must not reinsert deleted mirrors");
    assert!(!core.readable_from_streams.contains_key(&readable));
    assert!(core.readable_terminal_states.contains_key(&readable));
    assert!(
        !core.heap[readable.0 as usize]
            .properties
            .contains_key("destroyed")
    );
    assert!(
        !core.heap[readable.0 as usize]
            .properties
            .contains_key("closed")
    );
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn readable_from_precharges_fixed_state_before_heap_side_effects_bd_fw7zd() {
    let mut core = test_interpreter();
    let source = core
        .alloc_array_from_values(&[])
        .expect("empty source array");
    core.mutate_registers(|registers| registers[0] = Value::Object(source));
    let baseline_bytes = core.estimated_memory_bytes();
    let baseline_heap_len = core.heap.len();
    let state = ReadableFromState {
        source: Value::Object(source),
        push_only: false,
        object_mode: true,
        high_water_mark: 1,
        read_callback: None,
        buffer: VecDeque::new(),
        buffered_length: 0,
        eof_requested: false,
        data_readable_pending: false,
        eof_readable_pending: false,
        read_callback_active: false,
        decode_utf8: false,
        utf8_pending: Vec::new(),
        destroy_requested: false,
        destroy_error: None,
        next_index: 0,
        phase: ReadableFromPumpPhase::Data,
        flowing: false,
        paused: false,
        nonflowing_read_consumed: false,
        lifecycle_label: Label::Public,
        to_array_waiter: None,
    };
    let state_bytes = InterpreterCore::estimate_readable_from_state_bytes(&state);
    core.config.max_total_memory_bytes =
        baseline_bytes.saturating_add(state_bytes).saturating_sub(1);

    let error = core
        .construct_readable_from(RegRange { start: 0, count: 1 })
        .expect_err("state charge above the memory budget must fail first");
    assert!(matches!(
        error,
        InterpreterError::MemoryBudgetExceeded { .. }
    ));
    assert_eq!(core.heap.len(), baseline_heap_len);
    assert!(core.readable_from_streams.is_empty());
    assert!(core.pending_readable_from_pumps.is_empty());
    assert_eq!(core.estimated_memory_bytes(), baseline_bytes);
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );

    let properties = InterpreterCore::readable_object_properties(true, 1);
    let mut projected_object = HeapObject::new();
    for (key, value) in properties {
        projected_object.properties.insert(key.to_string(), value);
    }
    projected_object.brand = Some(Box::new(JsString::from(READABLE_BRAND)));
    let object_bytes = InterpreterCore::estimate_heap_object_bytes(&projected_object);
    core.config.max_total_memory_bytes = baseline_bytes
        .saturating_add(state_bytes)
        .saturating_add(object_bytes)
        .saturating_sub(1);

    let error = core
        .construct_readable_from(RegRange { start: 0, count: 1 })
        .expect_err("full Readable object charge must be preflighted atomically");
    assert!(matches!(
        error,
        InterpreterError::MemoryBudgetExceeded { .. }
    ));
    assert_eq!(core.heap.len(), baseline_heap_len);
    assert!(core.readable_from_streams.is_empty());
    assert!(core.pending_readable_from_pumps.is_empty());
    assert_eq!(core.estimated_memory_bytes(), baseline_bytes);
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );

    let pump_bytes = core.readable_pump_retained_bytes();
    let exact_bytes = baseline_bytes
        .saturating_add(state_bytes)
        .saturating_add(object_bytes)
        .saturating_add(pump_bytes);
    core.config.max_total_memory_bytes = exact_bytes.saturating_sub(1);
    let error = core
        .construct_readable_from(RegRange { start: 0, count: 1 })
        .expect_err("successor pump charge must be part of constructor preflight");
    assert!(matches!(
        error,
        InterpreterError::MemoryBudgetExceeded { .. }
    ));
    assert_eq!(core.heap.len(), baseline_heap_len);
    assert!(core.readable_from_streams.is_empty());
    assert!(core.pending_readable_from_pumps.is_empty());
    assert_eq!(core.estimated_memory_bytes(), baseline_bytes);

    core.config.max_total_memory_bytes = exact_bytes;
    let Value::Object(readable) = core
        .construct_readable_from(RegRange { start: 0, count: 1 })
        .expect("exact state, object, and pump ceiling must succeed")
    else {
        panic!("Readable.from must return an object");
    };
    assert!(core.readable_from_streams.contains_key(&readable));
    assert_eq!(core.pending_readable_from_pumps.len(), 1);
    assert_eq!(core.estimated_memory_bytes(), exact_bytes);
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn stream_constructor_high_water_marks_and_validation_bd_fw7zd() {
    let mut core = test_interpreter();
    let readable_options = core
        .alloc_object_with_properties(&[("highWaterMark", Value::Int(4))])
        .expect("readable options");
    core.write_reg(0, Value::Object(readable_options))
        .expect("readable options register");
    let Value::Object(readable) = core
        .construct_stream_readable(RegRange { start: 0, count: 1 })
        .expect("configured Readable")
    else {
        panic!("Readable constructor must return an object");
    };
    assert_eq!(
        core.heap[readable.0 as usize]
            .properties
            .get("readableHighWaterMark"),
        Some(&Value::Int(4))
    );

    let writable_options = core
        .alloc_object_with_properties(&[("highWaterMark", Value::Int(8))])
        .expect("writable options");
    core.write_reg(0, Value::Object(writable_options))
        .expect("writable options register");
    let Value::Object(writable) = core
        .construct_stream_writable(RegRange { start: 0, count: 1 })
        .expect("configured Writable")
    else {
        panic!("Writable constructor must return an object");
    };
    assert_eq!(
        core.heap[writable.0 as usize]
            .properties
            .get("writableHighWaterMark"),
        Some(&Value::Int(8))
    );

    let object_options = core
        .alloc_object_with_properties(&[("objectMode", Value::Bool(true))])
        .expect("object-mode options");
    core.write_reg(0, Value::Object(object_options))
        .expect("object-mode options register");
    let Value::Object(objects) = core
        .construct_stream_readable(RegRange { start: 0, count: 1 })
        .expect("object-mode Readable")
    else {
        panic!("Readable constructor must return an object");
    };
    assert_eq!(
        core.heap[objects.0 as usize]
            .properties
            .get("readableHighWaterMark"),
        Some(&Value::Int(16))
    );
    assert_eq!(
        core.heap[objects.0 as usize]
            .properties
            .get("readableObjectMode"),
        Some(&Value::Bool(true))
    );

    let zero_options = core
        .alloc_object_with_properties(&[("highWaterMark", Value::Int(0))])
        .expect("zero-HWM options");
    core.write_reg(0, Value::Object(zero_options))
        .expect("zero-HWM options register");
    let Value::Object(zero) = core
        .construct_stream_readable(RegRange { start: 0, count: 1 })
        .expect("zero-HWM Readable")
    else {
        panic!("Readable constructor must return an object");
    };
    assert_eq!(
        core.heap[zero.0 as usize]
            .properties
            .get("readableHighWaterMark"),
        Some(&Value::Int(0))
    );

    for invalid in [
        Value::Int(-1),
        Value::Float(Float64::new(1.5)),
        Value::Float(Float64::new(f64::NAN)),
        Value::Float(Float64::new(f64::INFINITY)),
        Value::str("4"),
    ] {
        let mut invalid_core = test_interpreter();
        let options = invalid_core
            .alloc_object_with_properties(&[("highWaterMark", invalid)])
            .expect("invalid options object");
        invalid_core
            .write_reg(0, Value::Object(options))
            .expect("invalid options register");
        assert!(matches!(
            invalid_core.construct_stream_readable(RegRange { start: 0, count: 1 }),
            Err(InterpreterError::RangeError { .. })
        ));
        assert!(invalid_core.readable_from_streams.is_empty());
    }
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn writable_completion_progresses_at_ceiling_and_releases_exactly_bd_fw7zd() {
    let module = test_module_with_functions(Vec::new(), Vec::new());
    let mut core = test_interpreter();
    let Value::Object(writable) = core
        .construct_stream_writable(RegRange { start: 0, count: 0 })
        .expect("generic Writable")
    else {
        panic!("Writable constructor must return an object");
    };
    let callback = WritableCallbackRecord {
        value: Value::BuiltinFunction(BuiltinFunction::new_kind(BuiltinFunctionKind::ArrayIsArray)),
        label: Label::Secret,
        module_specifier: None,
    };
    core.writable_enqueue(
        writable,
        Value::str("classified"),
        Label::Secret,
        Some(callback),
    )
    .expect("engine-owned write enqueue");
    {
        let state = core
            .writable_streams
            .get_mut(&writable)
            .expect("live Writable state");
        state.writes[0].status = WritableWriteStatus::Active(7);
    }
    core.next_writable_completion_token = 8;
    assert_eq!(
        core.writable_streams[&writable].writes[0]
            .callback
            .as_ref()
            .expect("retained callback")
            .label,
        Label::Secret,
        "callback registration labels must not collapse into a bare Value"
    );
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );

    core.config.max_total_memory_bytes = core.estimated_memory_bytes();
    let completion = BuiltinFunction::writable_completion(
        BuiltinFunctionKind::StreamWritableWriteDone,
        writable,
        7,
    );
    core.writable_write_done(&module, &completion, RegRange { start: 0, count: 0 })
        .expect("retained completion must progress at the exact memory ceiling");
    let state = &core.writable_streams[&writable];
    assert_eq!(state.writes[0].status, WritableWriteStatus::Completed);
    assert_eq!(state.buffered_length, 0);
    assert!(state.tick_sequence.is_some());
    assert_eq!(state.lifecycle_label, Label::Secret);

    // A duplicated retained callback is token-checked and cannot complete
    // another write or perturb the already-completed record.
    core.writable_write_done(&module, &completion, RegRange { start: 0, count: 0 })
        .expect("duplicate completion is an idempotent no-op");
    {
        let state = core
            .writable_streams
            .get_mut(&writable)
            .expect("live Writable state");
        state.end_requested = true;
        state.final_status = WritableFinalStatus::Done;
    }
    core.config.max_total_memory_bytes = u64::MAX;
    core.drain_runtime_checkpoint(Some(&module))
        .expect("successful Writable checkpoint");
    assert!(!core.writable_streams.contains_key(&writable));
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes(),
        "destructive callback drain and close must release exact state memory"
    );
}

#[test]
fn value_payload_estimator_is_complete_and_clone_shallow_bd_6pdka() {
    let [bigint, builtin, accessor] = shared_payload_values_bd_6pdka();
    let bigint_bytes = InterpreterCore::estimate_string_bytes(match &bigint {
        Value::BigInt(digits) => digits,
        _ => unreachable!("fixture is a BigInt"),
    });
    let builtin_bytes = InterpreterCore::estimate_string_bytes(match &builtin {
        Value::BuiltinFunction(builtin) => &builtin.module_specifier,
        _ => unreachable!("fixture is a builtin"),
    });
    let arc_value_bytes = u64::try_from(std::mem::size_of::<Value>())
        .expect("Value size fits u64")
        .saturating_add(
            u64::try_from(2usize.saturating_mul(std::mem::size_of::<usize>()))
                .expect("Arc header size fits u64"),
        );

    assert_eq!(InterpreterCore::estimate_value_bytes(&bigint), bigint_bytes);
    assert_eq!(
        InterpreterCore::estimate_value_bytes(&builtin),
        builtin_bytes
    );
    assert_eq!(
        InterpreterCore::estimate_value_bytes(&accessor),
        2u64.saturating_mul(arc_value_bytes)
            .saturating_add(bigint_bytes)
            .saturating_add(builtin_bytes)
    );
    assert_eq!(
        InterpreterCore::estimate_value_bytes(&Value::BuiltinFunction(BuiltinFunction::new_kind(
            BuiltinFunctionKind::ArrayIsArray
        ))),
        InterpreterCore::estimate_string_bytes(""),
        "empty provenance keeps a conservative logical owner charge"
    );

    let malformed = JsString::from_code_units(&[0xD800]);
    assert_eq!(
        InterpreterCore::estimate_js_string_bytes(&malformed),
        InterpreterCore::estimate_string_bytes(&malformed)
            .saturating_add(MEMORY_ESTIMATE_STRING_BASE_BYTES)
            .saturating_add(2),
        "a malformed JsString owns both UTF-8 projection and UTF-16 Arc allocations"
    );

    for value in [&bigint, &builtin, &accessor] {
        assert_eq!(
            InterpreterCore::estimate_value_bytes(value),
            InterpreterCore::estimate_writable_value_bytes(value)
        );
        let cloned = value.clone();
        assert_payload_clone_is_shared_bd_6pdka(value, &cloned);
        assert_eq!(cloned, *value);
    }

    assert_eq!(
        serde_json::to_value(Value::BigInt(Arc::from("123"))).expect("shared BigInt serialization"),
        serde_json::json!({"BigInt": "123"})
    );
    for value in [bigint, builtin, accessor] {
        let encoded = serde_json::to_vec(&value).expect("shared Value serialization");
        let decoded: Value =
            serde_json::from_slice(&encoded).expect("shared Value deserialization");
        assert_eq!(decoded, value);
    }
}

#[test]
fn register_payloads_refuse_one_short_and_clone_at_ceiling_bd_6pdka() {
    for value in shared_payload_values_bd_6pdka() {
        let mut core = test_interpreter();
        let baseline = core
            .sync_estimated_memory_bytes()
            .expect("payload register baseline");
        let value_bytes = InterpreterCore::estimate_value_bytes(&value);
        assert!(value_bytes > 0);

        core.config.max_total_memory_bytes = baseline.saturating_add(value_bytes).saturating_sub(1);
        assert!(matches!(
            core.write_reg(3, value.clone()),
            Err(InterpreterError::MemoryBudgetExceeded {
                requested_bytes,
                max_bytes,
                ..
            }) if requested_bytes == baseline + value_bytes
                && max_bytes == baseline + value_bytes - 1
        ));
        assert_eq!(core.registers[3], Value::Undefined);
        assert_eq!(core.estimated_memory_bytes(), baseline);

        core.config.max_total_memory_bytes = baseline.saturating_add(value_bytes);
        core.write_reg(3, value.clone())
            .expect("exact logical payload ceiling");
        let resident = core.estimated_memory_bytes();
        assert_eq!(resident, baseline + value_bytes);
        assert_eq!(resident, core.recompute_estimated_memory_bytes());

        // `read_reg` and `builtin_arg` return owned Values. Their dynamic
        // payload clones must stay allocation-free at the resident ceiling.
        core.config.max_total_memory_bytes = resident;
        let read = core.read_reg(3).expect("shallow register clone at ceiling");
        assert_payload_clone_is_shared_bd_6pdka(&core.registers[3], &read);
        let argument = core
            .builtin_arg(RegRange { start: 3, count: 1 }, 0)
            .expect("shallow builtin argument clone at ceiling")
            .expect("one argument exists");
        assert_payload_clone_is_shared_bd_6pdka(&core.registers[3], &argument);
        assert_eq!(core.estimated_memory_bytes(), resident);

        core.clear_current_register_frame();
        assert_eq!(core.estimated_memory_bytes(), baseline);
        assert_eq!(baseline, core.recompute_estimated_memory_bytes());
    }
}

#[test]
fn accessor_estimator_is_iterative_memoized_and_saturating_bd_6pdka() {
    let arc_value_bytes = u64::try_from(std::mem::size_of::<Value>())
        .expect("Value size fits u64")
        .saturating_add(
            u64::try_from(2usize.saturating_mul(std::mem::size_of::<usize>()))
                .expect("Arc header size fits u64"),
        );

    let mut chain = Value::BigInt(Arc::from("17"));
    let mut chain_bytes = InterpreterCore::estimate_string_bytes("17");
    for _ in 0..1_024 {
        chain = Value::Accessor {
            get: Some(Arc::new(chain)),
            set: None,
        };
        chain_bytes = chain_bytes.saturating_add(arc_value_bytes);
    }
    assert_eq!(InterpreterCore::estimate_value_bytes(&chain), chain_bytes);

    // Reusing the prior node from both slots creates only 129 physical
    // Values but an exponential number of logical owner paths. The
    // estimator must memoize node work while retaining saturating owner
    // accounting.
    let mut dag = Value::BigInt(Arc::from("23"));
    let mut dag_bytes = InterpreterCore::estimate_string_bytes("23");
    for _ in 0..128 {
        let shared = Arc::new(dag);
        dag = Value::Accessor {
            get: Some(shared.clone()),
            set: Some(shared),
        };
        dag_bytes = 2u64.saturating_mul(arc_value_bytes.saturating_add(dag_bytes));
    }
    assert_eq!(dag_bytes, u64::MAX);
    assert_eq!(InterpreterCore::estimate_value_bytes(&dag), u64::MAX);

    let mut core = test_interpreter();
    let baseline = core
        .sync_estimated_memory_bytes()
        .expect("DAG refusal baseline");
    core.config.max_total_memory_bytes = u64::MAX;
    assert!(matches!(
        core.write_reg(0, dag.clone()),
        Err(InterpreterError::MemoryBudgetExceeded {
            requested_bytes: u64::MAX,
            max_bytes,
            ..
        }) if max_bytes == u64::MAX
    ));
    assert_eq!(core.estimated_memory_bytes(), baseline);
    assert_eq!(core.registers[0], Value::Undefined);

    core.mutate_registers(|registers| {
        registers[0] = dag;
        registers[1] = Value::BigInt(Arc::from("another-owner"));
    });
    assert_eq!(
        core.recompute_estimated_memory_bytes(),
        u64::MAX,
        "aggregate recomputation must saturate instead of overflowing"
    );
}

#[test]
fn writable_payloads_refuse_one_short_and_fit_exactly_bd_6pdka() {
    for value in shared_payload_values_bd_6pdka() {
        let mut core = test_interpreter();
        let Value::Object(writable) = core
            .construct_stream_writable(RegRange { start: 0, count: 0 })
            .expect("object-mode Writable")
        else {
            panic!("Writable constructor must return an object");
        };
        core.writable_streams
            .get_mut(&writable)
            .expect("live Writable")
            .object_mode = true;
        let record = WritableWriteRecord {
            value: value.clone(),
            label: Label::Public,
            units: 1,
            callback: None,
            status: WritableWriteStatus::Pending,
            completion_failed: false,
        };
        let required = InterpreterCore::estimate_writable_write_record_bytes(&record);
        let baseline = core
            .sync_estimated_memory_bytes()
            .expect("Writable payload baseline");

        core.config.max_total_memory_bytes = baseline.saturating_add(required - 1);
        assert!(matches!(
            core.writable_enqueue(writable, value.clone(), Label::Public, None),
            Err(InterpreterError::MemoryBudgetExceeded { .. })
        ));
        assert!(core.writable_streams[&writable].writes.is_empty());
        assert_eq!(core.estimated_memory_bytes(), baseline);
        assert_eq!(baseline, core.recompute_estimated_memory_bytes());

        core.config.max_total_memory_bytes = baseline.saturating_add(required);
        assert!(
            core.writable_enqueue(writable, value, Label::Public, None)
                .expect("exact Writable payload ceiling")
        );
        assert_eq!(core.writable_streams[&writable].writes.len(), 1);
        assert_eq!(core.estimated_memory_bytes(), baseline + required);
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }
}

#[test]
fn call_frame_super_and_timer_iterator_payloads_are_eagerly_counted_bd_6pdka_bd_ppfz7() {
    let mut core = test_interpreter();
    let baseline = core
        .sync_estimated_memory_bytes()
        .expect("eager ownership baseline");
    let super_value = Value::BigInt(Arc::from("8".repeat(311)));
    let new_target_label = Label::Custom {
        name: "new-target-label".repeat(19),
        level: 4,
    };
    let super_label = Label::Custom {
        name: "super-binding-label".repeat(17),
        level: 4,
    };
    let frame = CallFrame {
        return_ip: 0,
        return_reg: 0,
        register_base: 0,
        register_width: core.config.max_registers as usize,
        function_index: None,
        this_value: Value::Undefined,
        this_label: Label::Public,
        new_target_value: Value::Undefined,
        new_target_label: new_target_label.clone(),
        super_value,
        super_label: super_label.clone(),
        super_home_object: None,
        construct_this: None,
        derived_constructor: false,
        this_initialized: true,
        initialize_derived_this_on_return: false,
        class_instance_fields: None,
        saved_pending_exception: None,
        saved_pending_exception_label: Label::Public,
        saved_pending_return: None,
        saved_suspended_abrupt_depth: 0,
        saved_finally_mode_depth: 0,
        saved_scope_depth: core.scope_chain.depth(),
        saved_scope_chain: None,
        scope_inert_virtual_scope_bytes: 0,
        async_function_id: None,
        native_boundary: false,
    };
    let frame_bytes = InterpreterCore::estimate_call_frame_bytes(&frame);
    let snapshot_bytes = InterpreterCore::estimate_call_frame_snapshot_clone_bytes(&frame);
    let virtual_scope_bytes = 137;
    let mut virtual_scope_frame = frame.clone();
    virtual_scope_frame.scope_inert_virtual_scope_bytes = virtual_scope_bytes;
    assert_eq!(
        InterpreterCore::estimate_call_frame_bytes(&virtual_scope_frame),
        frame_bytes + virtual_scope_bytes,
        "verified scope-inert activation must retain its exact logical live charge"
    );
    assert_eq!(
        InterpreterCore::estimate_call_frame_snapshot_clone_bytes(&virtual_scope_frame),
        snapshot_bytes + virtual_scope_bytes,
        "capturing an optimized frame must retain its exact logical scope charge"
    );
    let mut public_labels = frame.clone();
    public_labels.new_target_label = Label::Public;
    public_labels.super_label = Label::Public;
    let expected_label_bytes = InterpreterCore::estimate_label_bytes(&new_target_label)
        .saturating_add(InterpreterCore::estimate_label_bytes(&super_label));
    assert_eq!(
        frame_bytes.saturating_sub(InterpreterCore::estimate_call_frame_bytes(&public_labels)),
        expected_label_bytes,
        "live call-frame accounting must retain new.target and super labels"
    );
    assert_eq!(
        snapshot_bytes.saturating_sub(InterpreterCore::estimate_call_frame_snapshot_clone_bytes(
            &public_labels
        )),
        expected_label_bytes,
        "snapshot call-frame accounting must retain new.target and super labels"
    );
    core.call_stack.push(frame, &mut core.closures.cold_cells);
    core.sync_estimated_memory_bytes()
        .expect("super payload accounting");
    assert_eq!(core.estimated_memory_bytes(), baseline + frame_bytes);

    let iterator = RuntimeIteratorState::ForOf(RuntimeForOfState {
        values: Vec::new(),
        next_index: 0,
        array: None,
        typed_array: None,
        collection: None,
        iterator_receiver: None,
        next_method: None,
        timers_interval: Some((
            7,
            Value::BuiltinFunction(BuiltinFunction::require("timer-interval-owner/".repeat(17))),
        )),
        done: false,
        closed: false,
        return_called: false,
        trace_index: 0,
    });
    let iterator_bytes = InterpreterCore::estimate_iterator_bytes(&iterator);
    core.iterators.push(iterator);
    core.sync_estimated_memory_bytes()
        .expect("timer iterator payload accounting");
    assert_eq!(
        core.estimated_memory_bytes(),
        baseline + frame_bytes + iterator_bytes
    );
}

#[test]
fn abrupt_side_tables_refuse_one_short_transfer_and_release_exactly_bd_zpn45() {
    let value = Value::BigInt(Arc::from("abrupt-owner".repeat(31)));
    let label = Label::Custom {
        name: "abrupt-label".repeat(19),
        level: 4,
    };
    let mut probe = test_interpreter();
    let baseline = probe
        .sync_estimated_memory_bytes()
        .expect("abrupt probe baseline");
    probe
        .replace_pending_abrupt_slots(Some((value.clone(), label.clone())), None)
        .expect("unbounded pending exception probe");
    let pending_delta = probe.estimated_memory_bytes().saturating_sub(baseline);
    assert!(pending_delta > 0);
    assert_eq!(
        probe.estimated_memory_bytes(),
        probe.recompute_estimated_memory_bytes()
    );

    let mut one_short = test_interpreter();
    let one_short_baseline = one_short
        .sync_estimated_memory_bytes()
        .expect("pending exception refusal baseline");
    one_short.config.max_total_memory_bytes = one_short_baseline + pending_delta - 1;
    assert!(matches!(
        one_short.replace_pending_abrupt_slots(Some((value.clone(), label.clone())), None),
        Err(InterpreterError::MemoryBudgetExceeded { .. })
    ));
    assert!(one_short.pending_exception.is_none());
    assert_eq!(one_short.estimated_memory_bytes(), one_short_baseline);

    let mut exact = test_interpreter();
    let exact_baseline = exact
        .sync_estimated_memory_bytes()
        .expect("pending exception exact baseline");
    exact.config.max_total_memory_bytes = exact_baseline + pending_delta;
    exact
        .replace_pending_abrupt_slots(Some((value.clone(), label.clone())), None)
        .expect("pending exception fits exact ceiling");
    assert_eq!(
        exact.estimated_memory_bytes(),
        exact_baseline + pending_delta
    );
    assert_eq!(
        exact.estimated_memory_bytes(),
        exact.recompute_estimated_memory_bytes()
    );
    exact.clear_pending_abrupt_slots();
    assert_eq!(exact.estimated_memory_bytes(), exact_baseline);

    let mut suspended_probe = test_interpreter();
    let suspended_baseline = suspended_probe
        .sync_estimated_memory_bytes()
        .expect("suspended completion probe baseline");
    suspended_probe
        .suspend_abrupt_completion(Some((value.clone(), label.clone())), None)
        .expect("unbounded suspended completion probe");
    let suspended_delta = suspended_probe
        .estimated_memory_bytes()
        .saturating_sub(suspended_baseline);
    assert!(suspended_delta > pending_delta);

    let mut suspended_one_short = test_interpreter();
    let suspended_one_short_baseline = suspended_one_short
        .sync_estimated_memory_bytes()
        .expect("suspended completion refusal baseline");
    suspended_one_short.config.max_total_memory_bytes =
        suspended_one_short_baseline + suspended_delta - 1;
    assert!(matches!(
        suspended_one_short.suspend_abrupt_completion(Some((value.clone(), label.clone())), None),
        Err(InterpreterError::MemoryBudgetExceeded { .. })
    ));
    assert!(suspended_one_short.suspended_abrupt_completions.is_empty());
    assert_eq!(
        suspended_one_short.estimated_memory_bytes(),
        suspended_one_short_baseline
    );

    let mut suspended_exact = test_interpreter();
    let suspended_exact_baseline = suspended_exact
        .sync_estimated_memory_bytes()
        .expect("suspended completion exact baseline");
    suspended_exact.config.max_total_memory_bytes = suspended_exact_baseline + suspended_delta;
    suspended_exact
        .suspend_abrupt_completion(Some((value, label.clone())), None)
        .expect("suspended completion fits exact ceiling");
    assert_eq!(
        suspended_exact.estimated_memory_bytes(),
        suspended_exact.recompute_estimated_memory_bytes()
    );
    suspended_exact.clear_suspended_abrupt_completions();
    assert_eq!(
        suspended_exact.estimated_memory_bytes(),
        suspended_exact_baseline
    );

    let mut hostcall_label = test_interpreter();
    let hostcall_baseline = hostcall_label
        .sync_estimated_memory_bytes()
        .expect("hostcall label baseline");
    let label_bytes = InterpreterCore::estimate_label_bytes(&label);
    hostcall_label.config.max_total_memory_bytes = hostcall_baseline + label_bytes - 1;
    assert!(matches!(
        hostcall_label.replace_pending_hostcall_result_label(Some(label.clone())),
        Err(InterpreterError::MemoryBudgetExceeded { .. })
    ));
    assert!(hostcall_label.pending_hostcall_result_label.is_none());
    hostcall_label.config.max_total_memory_bytes = hostcall_baseline + label_bytes;
    hostcall_label
        .replace_pending_hostcall_result_label(Some(label))
        .expect("hostcall label fits exact ceiling");
    assert_eq!(
        hostcall_label.estimated_memory_bytes(),
        hostcall_label.recompute_estimated_memory_bytes()
    );
    assert!(
        hostcall_label
            .take_pending_hostcall_result_label()
            .is_some()
    );
    assert_eq!(hostcall_label.estimated_memory_bytes(), hostcall_baseline);

    let tla_value = LabeledReturn {
        value: Value::BigInt(Arc::from("top-level-await".repeat(31))),
        label: Label::Public,
    };
    let mut tla_probe = test_interpreter();
    let tla_baseline = tla_probe
        .sync_estimated_memory_bytes()
        .expect("top-level await outcome probe baseline");
    tla_probe.replace_top_level_await_outcome(Ok(tla_value.clone()));
    let tla_delta = tla_probe
        .estimated_memory_bytes()
        .saturating_sub(tla_baseline);
    assert!(tla_delta > 0);

    let mut tla_one_short = test_interpreter();
    let tla_one_short_baseline = tla_one_short
        .sync_estimated_memory_bytes()
        .expect("top-level await outcome refusal baseline");
    tla_one_short.config.max_total_memory_bytes = tla_one_short_baseline + tla_delta - 1;
    tla_one_short.replace_top_level_await_outcome(Ok(tla_value.clone()));
    assert!(matches!(
        tla_one_short.top_level_await_outcome,
        Some(Err(InterpreterError::MemoryBudgetExceeded { .. }))
    ));
    assert_eq!(
        tla_one_short.estimated_memory_bytes(),
        tla_one_short.recompute_estimated_memory_bytes()
    );

    let mut tla_exact = test_interpreter();
    let tla_exact_baseline = tla_exact
        .sync_estimated_memory_bytes()
        .expect("top-level await outcome exact baseline");
    tla_exact.config.max_total_memory_bytes = tla_exact_baseline + tla_delta;
    tla_exact.replace_top_level_await_outcome(Ok(tla_value));
    assert!(matches!(tla_exact.top_level_await_outcome, Some(Ok(_))));
    assert_eq!(
        tla_exact.estimated_memory_bytes(),
        tla_exact.recompute_estimated_memory_bytes()
    );
    assert!(matches!(
        tla_exact.take_top_level_await_outcome(),
        Some(Ok(_))
    ));
    assert_eq!(tla_exact.estimated_memory_bytes(), tla_exact_baseline);
}

#[test]
fn async_saved_register_stores_refuse_one_short_and_release_exactly_bd_zpn45() {
    let saved = vec![Value::BigInt(Arc::from("async-register".repeat(37)))];
    let owner_module = Arc::new(test_module_with_functions(Vec::new(), Vec::new()));
    let function = AsyncFunctionObject {
        owner_module: Arc::clone(&owner_module),
        isolated_execution: None,
        function_index: 2,
        closure_index: Some(3),
        saved_ip: 5,
        saved_registers: saved.clone(),
        saved_register_labels: vec![Label::Custom {
            name: "async-register-label".repeat(37),
            level: 3,
        }],
        saved_register_base: 0,
        phase: AsyncFunctionPhase::SuspendedAwait,
        result_promise: 7,
    };
    let generator = AsyncGeneratorObject {
        awaited_kind: async_generator::AwaitKind::Body,
        delegation: None,
        generator_id: 0,
        requests: VecDeque::new(),
        awaited: Some(LabeledReturn {
            value: saved[0].clone(),
            label: Label::Custom {
                name: "async-generator-register-label".repeat(29),
                level: 4,
            },
        }),
        phase: AsyncGeneratorPhase::SuspendedYield,
    };

    let mut function_probe = test_interpreter();
    let function_baseline = function_probe
        .sync_estimated_memory_bytes()
        .expect("async function probe baseline");
    function_probe
        .push_async_function_object(function.clone())
        .expect("unbounded async function probe");
    let function_delta = function_probe
        .estimated_memory_bytes()
        .saturating_sub(function_baseline);
    assert!(function_delta > 0);

    let mut function_one_short = test_interpreter();
    let function_one_short_baseline = function_one_short
        .sync_estimated_memory_bytes()
        .expect("async function refusal baseline");
    function_one_short.config.max_total_memory_bytes =
        function_one_short_baseline + function_delta - 1;
    assert!(matches!(
        function_one_short.push_async_function_object(function.clone()),
        Err(InterpreterError::MemoryBudgetExceeded { .. })
    ));
    assert!(function_one_short.async_functions.is_empty());
    assert_eq!(
        function_one_short.estimated_memory_bytes(),
        function_one_short_baseline
    );

    let mut function_exact = test_interpreter();
    let function_exact_baseline = function_exact
        .sync_estimated_memory_bytes()
        .expect("async function exact baseline");
    function_exact.config.max_total_memory_bytes = function_exact_baseline + function_delta;
    function_exact
        .push_async_function_object(function)
        .expect("async function fits exact ceiling");
    assert_eq!(
        function_exact.estimated_memory_bytes(),
        function_exact.recompute_estimated_memory_bytes()
    );
    function_exact.pop_async_function_object_and_release();
    assert_eq!(
        function_exact.estimated_memory_bytes(),
        function_exact_baseline
    );

    let mut generator_probe = test_interpreter();
    let generator_baseline = generator_probe
        .sync_estimated_memory_bytes()
        .expect("async generator probe baseline");
    generator_probe
        .push_async_generator_object(generator.clone())
        .expect("unbounded async generator probe");
    let generator_delta = generator_probe
        .estimated_memory_bytes()
        .saturating_sub(generator_baseline);
    assert!(generator_delta > 0);

    let mut generator_one_short = test_interpreter();
    let generator_one_short_baseline = generator_one_short
        .sync_estimated_memory_bytes()
        .expect("async generator refusal baseline");
    generator_one_short.config.max_total_memory_bytes =
        generator_one_short_baseline + generator_delta - 1;
    assert!(matches!(
        generator_one_short.push_async_generator_object(generator.clone()),
        Err(InterpreterError::MemoryBudgetExceeded { .. })
    ));
    assert!(generator_one_short.async_generators.is_empty());

    let mut generator_exact = test_interpreter();
    let generator_exact_baseline = generator_exact
        .sync_estimated_memory_bytes()
        .expect("async generator exact baseline");
    generator_exact.config.max_total_memory_bytes = generator_exact_baseline + generator_delta;
    generator_exact
        .push_async_generator_object(generator)
        .expect("async generator fits exact ceiling");
    assert_eq!(
        generator_exact.estimated_memory_bytes(),
        generator_exact.recompute_estimated_memory_bytes()
    );
    generator_exact.pop_async_generator_object_and_release();
    assert_eq!(
        generator_exact.estimated_memory_bytes(),
        generator_exact_baseline
    );
}

#[test]
fn pending_io_and_timer_payloads_are_atomic_and_exact_bd_zpn45() {
    let callback_args = vec![Value::BigInt(Arc::from("io-argument".repeat(41)))];
    let mut io_probe = test_interpreter();
    let io_baseline = io_probe
        .sync_estimated_memory_bytes()
        .expect("I/O callback probe baseline");
    io_probe
        .schedule_io_callback_with_label(77, callback_args.clone(), Label::Public)
        .expect("unbounded I/O callback probe");
    let io_delta = io_probe
        .estimated_memory_bytes()
        .saturating_sub(io_baseline);
    assert!(io_delta > 0);
    assert_eq!(
        io_probe.estimated_memory_bytes(),
        io_probe.recompute_estimated_memory_bytes()
    );

    let mut io_one_short = test_interpreter();
    let io_one_short_baseline = io_one_short
        .sync_estimated_memory_bytes()
        .expect("I/O callback refusal baseline");
    io_one_short.config.max_total_memory_bytes = io_one_short_baseline + io_delta - 1;
    assert!(matches!(
        io_one_short.schedule_io_callback_with_label(77, callback_args.clone(), Label::Public,),
        Err(InterpreterError::MemoryBudgetExceeded { .. })
    ));
    assert!(io_one_short.pending_io_callbacks.is_empty());
    assert!(!io_one_short.event_loop.has_pending_work());
    assert_eq!(io_one_short.estimated_memory_bytes(), io_one_short_baseline);

    let mut io_exact = test_interpreter();
    let io_exact_baseline = io_exact
        .sync_estimated_memory_bytes()
        .expect("I/O callback exact baseline");
    io_exact.config.max_total_memory_bytes = io_exact_baseline + io_delta;
    io_exact
        .schedule_io_callback_with_label(77, callback_args, Label::Public)
        .expect("I/O callback fits exact ceiling");
    assert_eq!(
        io_exact.estimated_memory_bytes(),
        io_exact.recompute_estimated_memory_bytes()
    );

    let timer_task = PendingTimerTask {
        timer_id: 9,
        kind: PendingTimerTaskKind::Callback {
            callback: Value::Closure(88),
            args: vec![Value::BigInt(Arc::from("timer-argument".repeat(43)))],
            repeating: false,
            delay_ms: 1,
            label: Label::Public,
        },
    };
    let mut timer_probe = test_interpreter();
    let timer_baseline = timer_probe
        .sync_estimated_memory_bytes()
        .expect("timer callback probe baseline");
    let probe_sequence = timer_probe
        .schedule_pending_timer_task(timer_task.clone(), false, 1)
        .expect("unbounded timer callback probe");
    let timer_delta = timer_probe
        .estimated_memory_bytes()
        .saturating_sub(timer_baseline);
    assert!(timer_delta > 0);
    assert_eq!(
        timer_probe.estimated_memory_bytes(),
        timer_probe.recompute_estimated_memory_bytes()
    );
    timer_probe.cancel_pending_timer_registration(probe_sequence);
    assert_eq!(timer_probe.estimated_memory_bytes(), timer_baseline);

    let mut timer_one_short = test_interpreter();
    let timer_one_short_baseline = timer_one_short
        .sync_estimated_memory_bytes()
        .expect("timer callback refusal baseline");
    timer_one_short.config.max_total_memory_bytes = timer_one_short_baseline + timer_delta - 1;
    assert!(matches!(
        timer_one_short.schedule_pending_timer_task(timer_task.clone(), false, 1),
        Err(InterpreterError::MemoryBudgetExceeded { .. })
    ));
    assert!(timer_one_short.pending_timer_tasks.is_empty());
    assert!(!timer_one_short.event_loop.has_pending_work());
    assert_eq!(
        timer_one_short.estimated_memory_bytes(),
        timer_one_short_baseline
    );

    let mut timer_exact = test_interpreter();
    let timer_exact_baseline = timer_exact
        .sync_estimated_memory_bytes()
        .expect("timer callback exact baseline");
    timer_exact.config.max_total_memory_bytes = timer_exact_baseline + timer_delta;
    let exact_sequence = timer_exact
        .schedule_pending_timer_task(timer_task, false, 1)
        .expect("timer callback fits exact ceiling");
    assert_eq!(
        timer_exact.estimated_memory_bytes(),
        timer_exact.recompute_estimated_memory_bytes()
    );
    timer_exact.cancel_pending_timer_registration(exact_sequence);
    assert_eq!(timer_exact.estimated_memory_bytes(), timer_exact_baseline);

    let production_args = vec![Value::BigInt(Arc::from(
        "production-timer-argument".repeat(37),
    ))];
    let mut production_probe = test_interpreter();
    production_probe
        .config
        .granted_capabilities
        .insert(RuntimeCapability::Timer);
    let production_baseline = production_probe
        .sync_estimated_memory_bytes()
        .expect("production timer probe baseline");
    production_probe
        .timer_schedule_from_values(
            Value::Closure(88),
            Some(Value::Int(1)),
            production_args.clone(),
            false,
            false,
            Label::Public,
        )
        .expect("unbounded production timer probe");
    let production_delta = production_probe
        .estimated_memory_bytes()
        .saturating_sub(production_baseline);
    assert!(production_delta > timer_delta);

    let mut production_one_short = test_interpreter();
    production_one_short
        .config
        .granted_capabilities
        .insert(RuntimeCapability::Timer);
    let production_one_short_baseline = production_one_short
        .sync_estimated_memory_bytes()
        .expect("production timer refusal baseline");
    let production_heap_len = production_one_short.heap.len();
    let production_timer_id = production_one_short.next_timer_id;
    production_one_short.config.max_total_memory_bytes =
        production_one_short_baseline + production_delta - 1;
    assert!(matches!(
        production_one_short.timer_schedule_from_values(
            Value::Closure(88),
            Some(Value::Int(1)),
            production_args.clone(),
            false,
            false,
            Label::Public,
        ),
        Err(InterpreterError::MemoryBudgetExceeded { .. })
    ));
    assert_eq!(production_one_short.heap.len(), production_heap_len);
    assert_eq!(production_one_short.next_timer_id, production_timer_id);
    assert!(production_one_short.active_timers.is_empty());
    assert!(production_one_short.pending_timer_tasks.is_empty());
    assert!(!production_one_short.event_loop.has_pending_work());
    assert_eq!(
        production_one_short.estimated_memory_bytes(),
        production_one_short_baseline
    );
    assert_eq!(
        production_one_short.estimated_memory_bytes(),
        production_one_short.recompute_estimated_memory_bytes()
    );

    let mut production_exact = test_interpreter();
    production_exact
        .config
        .granted_capabilities
        .insert(RuntimeCapability::Timer);
    let production_exact_baseline = production_exact
        .sync_estimated_memory_bytes()
        .expect("production timer exact baseline");
    production_exact.config.max_total_memory_bytes = production_exact_baseline + production_delta;
    let handle = production_exact
        .timer_schedule_from_values(
            Value::Closure(88),
            Some(Value::Int(1)),
            production_args,
            false,
            false,
            Label::Public,
        )
        .expect("production timer fits exact ceiling");
    assert_eq!(
        production_exact.estimated_memory_bytes(),
        production_exact.recompute_estimated_memory_bytes()
    );
    production_exact
        .timer_clear_from_value(
            &handle,
            "test:clearTimeout",
            Some(TimerOperation::ClearTimeout),
            Label::Public,
        )
        .expect("timer cancellation releases side tables");
    assert!(production_exact.active_timers.is_empty());
    assert!(production_exact.pending_timer_tasks.is_empty());
    assert!(!production_exact.event_loop.has_pending_work());
    assert_eq!(
        production_exact.estimated_memory_bytes(),
        production_exact.recompute_estimated_memory_bytes()
    );

    let firing_fixture = |repeating| {
        let mut core = test_interpreter();
        core.closures.push(ClosureValue {
            function_index: 0,
            captured_env: Vec::new(),
        });
        let timer_id = 41;
        core.active_timers.insert(
            timer_id,
            ActiveTimer {
                handler: Some(0),
                delay_ms: 1,
                repeating,
            },
        );
        let task = PendingTimerTask {
            timer_id,
            kind: PendingTimerTaskKind::Callback {
                callback: Value::Closure(0),
                args: vec![Value::BigInt(Arc::from("firing-argument".repeat(71)))],
                repeating,
                delay_ms: 1,
                label: Label::Public,
            },
        };
        core.sync_estimated_memory_bytes()
            .expect("timer firing fixture baseline");
        let retained_bytes = InterpreterCore::estimate_pending_timer_task_bytes(&task);
        core.apply_memory_component_delta(0, retained_bytes)
            .expect("model dequeued task remains charged while firing");
        (core, task, retained_bytes)
    };

    let (mut repeating_one_short, repeating_task, retained_bytes) = firing_fixture(true);
    let repeating_charged_baseline = repeating_one_short.estimated_memory_bytes();
    let clone_bytes = match &repeating_task.kind {
        PendingTimerTaskKind::Callback { args, .. } => {
            InterpreterCore::estimate_value_vec_bytes(args)
        }
        PendingTimerTaskKind::PromiseResolve { .. } => unreachable!(),
    };
    repeating_one_short.config.max_total_memory_bytes =
        repeating_charged_baseline + clone_bytes - 1;
    assert!(matches!(
        repeating_one_short.execute_pending_timer_task(repeating_task, None),
        Err(InterpreterError::MemoryBudgetExceeded { .. })
    ));
    assert!(repeating_one_short.active_timers.is_empty());
    assert_eq!(
        repeating_one_short.estimated_memory_bytes(),
        repeating_charged_baseline - retained_bytes
    );

    let (mut repeating_exact, repeating_task, _) = firing_fixture(true);
    let repeating_exact_baseline = repeating_exact.estimated_memory_bytes();
    repeating_exact.config.max_total_memory_bytes = repeating_exact_baseline + clone_bytes;
    repeating_exact
        .execute_pending_timer_task(repeating_task, None)
        .expect("repeating timer callback copy fits exact physical ceiling");
    assert_eq!(repeating_exact.pending_timer_tasks.len(), 1);
    assert!(repeating_exact.event_loop.has_pending_work());
    assert_eq!(
        repeating_exact.estimated_memory_bytes(),
        repeating_exact.recompute_estimated_memory_bytes()
    );

    let (mut one_shot_exact, one_shot_task, _) = firing_fixture(false);
    let one_shot_ceiling = one_shot_exact.estimated_memory_bytes();
    one_shot_exact.config.max_total_memory_bytes = one_shot_ceiling;
    one_shot_exact
        .execute_pending_timer_task(one_shot_task, None)
        .expect("one-shot timer moves arguments without a callback copy");
    assert!(one_shot_exact.active_timers.is_empty());
    assert_eq!(
        one_shot_exact.estimated_memory_bytes(),
        one_shot_exact.recompute_estimated_memory_bytes()
    );
}

#[test]
fn weakmap_and_module_export_duplicates_are_atomic_and_exact_bd_zpn45() {
    let weakmap_fixture = || {
        let mut core = test_interpreter();
        let weakmap = construct_weakmap_for_current_test(&mut core);
        let key = core
            .alloc_object_with_properties(&[])
            .expect("WeakMap object key");
        let pair = core
            .alloc_array_from_values(&[
                Value::Object(key),
                Value::BigInt(Arc::from("weakmap-value".repeat(47))),
            ])
            .expect("WeakMap pair");
        let iterable = core
            .alloc_array_from_values(&[Value::Object(pair)])
            .expect("WeakMap iterable");
        core.sync_estimated_memory_bytes()
            .expect("WeakMap fixture baseline");
        (core, weakmap, key, iterable)
    };

    let (mut weakmap_probe, weakmap_id, _key_id, iterable_id) = weakmap_fixture();
    let weakmap_baseline = weakmap_probe.estimated_memory_bytes();
    weakmap_probe
        .seed_weakmap_from_iterable(None, weakmap_id, Value::Object(iterable_id))
        .expect("unbounded WeakMap seed probe");
    let weakmap_delta = weakmap_probe
        .estimated_memory_bytes()
        .saturating_sub(weakmap_baseline);
    assert!(weakmap_delta > 0);
    assert_eq!(
        weakmap_probe.estimated_memory_bytes(),
        weakmap_probe.recompute_estimated_memory_bytes()
    );

    let (mut weakmap_one_short, weakmap_id, key_id, iterable_id) = weakmap_fixture();
    let weakmap_one_short_baseline = weakmap_one_short.estimated_memory_bytes();
    weakmap_one_short.config.max_total_memory_bytes =
        weakmap_one_short_baseline + weakmap_delta - 1;
    assert!(matches!(
        weakmap_one_short.seed_weakmap_from_iterable(None, weakmap_id, Value::Object(iterable_id)),
        Err(InterpreterError::MemoryBudgetExceeded { .. })
    ));
    assert!(
        weakmap_one_short.weakmap_storage[&weakmap_id]
            .get(key_id.0)
            .is_none()
    );
    assert_eq!(
        weakmap_one_short.estimated_memory_bytes(),
        weakmap_one_short_baseline
    );

    let (mut weakmap_exact, weakmap_id, key_id, iterable_id) = weakmap_fixture();
    let weakmap_exact_baseline = weakmap_exact.estimated_memory_bytes();
    weakmap_exact.config.max_total_memory_bytes = weakmap_exact_baseline + weakmap_delta;
    weakmap_exact
        .seed_weakmap_from_iterable(None, weakmap_id, Value::Object(iterable_id))
        .expect("WeakMap value fits exact ceiling");
    assert!(
        weakmap_exact.weakmap_storage[&weakmap_id]
            .get(key_id.0)
            .is_some()
    );
    assert_eq!(
        weakmap_exact.estimated_memory_bytes(),
        weakmap_exact.recompute_estimated_memory_bytes()
    );

    let export_fixture = || {
        let mut core = test_interpreter();
        let namespace = core
            .alloc_object_with_properties(&[])
            .expect("module namespace object");
        let specifier = "memory-owner.mjs".to_string();
        core.module_state.modules.insert(
            specifier.clone(),
            ModuleRuntimeRecord {
                status: ModuleRuntimeStatus::Evaluating,
                namespace_object: namespace,
                import_meta_object: None,
                exports: BTreeMap::new(),
                star_exports: BTreeMap::new(),
                flow_label_ceiling: None,
                resolved_source_hash: None,
                import_bindings: BTreeMap::new(),
                star_reexporters: BTreeSet::new(),
                cjs_module_object: None,
                compiled_module: None,
                evaluation_promise: None,
                async_execution: None,
            },
        );
        core.current_module_specifier = Some(specifier.clone());
        core.sync_estimated_memory_bytes()
            .expect("module export fixture baseline");
        (core, specifier, namespace)
    };
    let export_value = Value::BigInt(Arc::from("module-export".repeat(53)));
    let (mut export_probe, _, _) = export_fixture();
    let export_baseline = export_probe.estimated_memory_bytes();
    export_probe
        .register_module_export("answer", export_value.clone())
        .expect("unbounded module export probe");
    let export_delta = export_probe
        .estimated_memory_bytes()
        .saturating_sub(export_baseline);
    assert!(export_delta > 0);
    assert_eq!(
        export_probe.estimated_memory_bytes(),
        export_probe.recompute_estimated_memory_bytes()
    );

    let (mut export_one_short, specifier, namespace) = export_fixture();
    let export_one_short_baseline = export_one_short.estimated_memory_bytes();
    export_one_short.config.max_total_memory_bytes = export_one_short_baseline + export_delta - 1;
    assert!(matches!(
        export_one_short.register_module_export("answer", export_value.clone()),
        Err(InterpreterError::MemoryBudgetExceeded { .. })
    ));
    assert!(
        export_one_short.module_state.modules[&specifier]
            .exports
            .is_empty()
    );
    assert!(
        !export_one_short.heap[namespace.0 as usize]
            .properties
            .contains_key("answer")
    );
    assert_eq!(
        export_one_short.estimated_memory_bytes(),
        export_one_short_baseline
    );

    let (mut export_exact, specifier, namespace) = export_fixture();
    let export_exact_baseline = export_exact.estimated_memory_bytes();
    export_exact.config.max_total_memory_bytes = export_exact_baseline + export_delta;
    export_exact
        .register_module_export("answer", export_value)
        .expect("module export fits exact ceiling");
    assert!(
        export_exact.module_state.modules[&specifier]
            .exports
            .contains_key(&JsString::from("answer"))
    );
    assert!(
        export_exact.heap[namespace.0 as usize]
            .properties
            .contains_key("answer")
    );
    assert_eq!(
        export_exact.estimated_memory_bytes(),
        export_exact.recompute_estimated_memory_bytes()
    );

    let mut missing_export = test_interpreter();
    missing_export.current_module_specifier = Some("missing-record.mjs".to_string());
    let missing_export_baseline = missing_export
        .sync_estimated_memory_bytes()
        .expect("missing export record baseline");
    assert!(matches!(
        missing_export.register_module_export(
            "answer",
            Value::BigInt(Arc::from("unretained-export".repeat(31)))
        ),
        Err(InterpreterError::ExportOutsideModule { .. })
    ));
    assert_eq!(
        missing_export.estimated_memory_bytes(),
        missing_export_baseline
    );
    assert_eq!(
        missing_export.estimated_memory_bytes(),
        missing_export.recompute_estimated_memory_bytes()
    );
}

#[test]
fn heap_transaction_rollback_prunes_only_discarded_remembered_ids_bd_zpn45() {
    let mut core = test_interpreter();
    let retained = core
        .alloc_object_with_properties(&[("retained", Value::Int(1))])
        .expect("retained heap object");
    let previous_heap_len = core.heap.len();
    let discarded = core
        .alloc_object_with_properties(&[("discarded", Value::Int(2))])
        .expect("transaction-owned heap object");
    assert!(core.gc_remembered_set.contains(&retained));
    assert!(core.gc_remembered_set.contains(&discarded));

    core.rollback_heap_to_len(previous_heap_len);

    assert!(core.gc_remembered_set.contains(&retained));
    assert!(!core.gc_remembered_set.contains(&discarded));
    assert!(
        core.gc_remembered_set
            .iter()
            .all(|object_id| (object_id.0 as usize) < core.heap.len())
    );
    core.sync_estimated_memory_bytes()
        .expect("heap rollback accounting resync");
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn state_capture_and_promise_store_are_atomic_exact_and_released_bd_zpn45() {
    let capture_fixture = || {
        let mut core = test_interpreter();
        let child = core
            .alloc_object_with_properties(&[(
                "payload",
                Value::BigInt(Arc::from("captured-heap".repeat(29))),
            )])
            .expect("captured child object");
        let object = core
            .alloc_object_with_properties(&[("child", Value::Object(child))])
            .expect("captured root object");
        for index in 0..48 {
            core.set_object_property(object, format!("duplicate-{index}"), Value::Object(child))
                .expect("duplicate reachability edge");
        }
        core.write_reg(3, Value::Object(object))
            .expect("captured object register");
        core.set_register_label(3, Label::TopSecret)
            .expect("captured named register label");
        core.write_reg(4, Value::Object(object))
            .expect("second captured object register");
        core.set_register_label(
            4,
            Label::Custom {
                name: "capture-label".repeat(23),
                level: 4,
            },
        )
        .expect("captured same-level custom register label");
        core.sync_estimated_memory_bytes()
            .expect("state capture fixture baseline");
        core.arm_state_capture_at_tick(0);
        core
    };

    let mut capture_probe = capture_fixture();
    let capture_baseline = capture_probe.estimated_memory_bytes();
    capture_probe.check_state_capture_boundary();
    let capture_delta = capture_probe
        .estimated_memory_bytes()
        .saturating_sub(capture_baseline);
    let capture_peak_delta =
        capture_delta.saturating_add(capture_probe.capture_label_projection_working_bytes());
    assert!(capture_delta > 0);
    assert!(capture_probe.state_capture_result.is_some());
    assert_eq!(
        capture_probe.estimated_memory_bytes(),
        capture_probe.recompute_estimated_memory_bytes()
    );
    let captured = capture_probe
        .state_capture_result
        .as_ref()
        .expect("capture probe produced state");
    let expected_label = Label::Custom {
        name: "capture-label".repeat(23),
        level: 4,
    };
    assert_eq!(captured.heap[0].label, expected_label);
    assert_eq!(captured.heap[1].label, expected_label);

    let mut capture_one_short = capture_fixture();
    let capture_one_short_baseline = capture_one_short.estimated_memory_bytes();
    capture_one_short.config.max_total_memory_bytes =
        capture_one_short_baseline + capture_peak_delta - 1;
    capture_one_short.check_state_capture_boundary();
    assert!(capture_one_short.state_capture_result.is_none());
    assert_eq!(
        capture_one_short.estimated_memory_bytes(),
        capture_one_short_baseline
    );

    let mut capture_exact = capture_fixture();
    let capture_exact_baseline = capture_exact.estimated_memory_bytes();
    capture_exact.config.max_total_memory_bytes = capture_exact_baseline + capture_peak_delta;
    capture_exact.check_state_capture_boundary();
    assert!(capture_exact.state_capture_result.is_some());
    assert_eq!(
        capture_exact.estimated_memory_bytes(),
        capture_exact.recompute_estimated_memory_bytes()
    );
    assert!(capture_exact.take_captured_state().is_some());
    assert_eq!(
        capture_exact.estimated_memory_bytes(),
        capture_exact_baseline
    );

    let snapshot_fixture = || {
        let mut core = test_interpreter();
        core.write_reg(
            2,
            Value::BigInt(Arc::from("module-snapshot-register".repeat(23))),
        )
        .expect("module snapshot register");
        core.set_register_label(
            2,
            Label::Custom {
                name: "module-snapshot-label".repeat(19),
                level: 3,
            },
        )
        .expect("module snapshot label");
        core.sync_estimated_memory_bytes()
            .expect("module snapshot fixture baseline");
        core
    };
    let mut snapshot_probe = snapshot_fixture();
    let snapshot_baseline = snapshot_probe.estimated_memory_bytes();
    let probe_snapshot = snapshot_probe
        .snapshot_module_execution()
        .expect("unbounded module snapshot probe");
    let snapshot_delta = snapshot_probe
        .estimated_memory_bytes()
        .saturating_sub(snapshot_baseline);
    assert!(snapshot_delta > 0);
    assert_eq!(
        snapshot_probe.estimated_memory_bytes(),
        snapshot_probe.recompute_estimated_memory_bytes()
    );
    snapshot_probe
        .write_reg(2, Value::Int(7))
        .expect("nested execution replaces snapshotted register");
    snapshot_probe
        .set_register_label(2, Label::Public)
        .expect("nested execution replaces snapshotted label");
    snapshot_probe.restore_module_execution(probe_snapshot, true);
    assert_eq!(snapshot_probe.estimated_memory_bytes(), snapshot_baseline);

    let mut snapshot_one_short = snapshot_fixture();
    let snapshot_one_short_baseline = snapshot_one_short.estimated_memory_bytes();
    snapshot_one_short.config.max_total_memory_bytes =
        snapshot_one_short_baseline + snapshot_delta - 1;
    assert!(matches!(
        snapshot_one_short.snapshot_module_execution(),
        Err(InterpreterError::MemoryBudgetExceeded { .. })
    ));
    assert_eq!(snapshot_one_short.module_snapshot_in_flight_bytes, 0);
    assert_eq!(
        snapshot_one_short.estimated_memory_bytes(),
        snapshot_one_short_baseline
    );

    let mut snapshot_exact = snapshot_fixture();
    let snapshot_exact_baseline = snapshot_exact.estimated_memory_bytes();
    snapshot_exact.config.max_total_memory_bytes = snapshot_exact_baseline + snapshot_delta;
    let exact_snapshot = snapshot_exact
        .snapshot_module_execution()
        .expect("module snapshot fits exact ceiling");
    assert_eq!(
        snapshot_exact.estimated_memory_bytes(),
        snapshot_exact.recompute_estimated_memory_bytes()
    );
    snapshot_exact.restore_module_execution(exact_snapshot, true);
    assert_eq!(
        snapshot_exact.estimated_memory_bytes(),
        snapshot_exact_baseline
    );

    let mut promise_probe = test_interpreter();
    let promise_baseline = promise_probe
        .sync_estimated_memory_bytes()
        .expect("Promise creation probe baseline");
    let probe_handle = promise_probe
        .create_promise()
        .expect("unbounded Promise creation probe");
    let promise_delta = promise_probe
        .estimated_memory_bytes()
        .saturating_sub(promise_baseline);
    assert!(promise_delta > 0);
    assert_eq!(
        promise_probe.estimated_memory_bytes(),
        promise_probe.recompute_estimated_memory_bytes()
    );
    promise_probe.rollback_fresh_promise(probe_handle);
    assert_eq!(promise_probe.estimated_memory_bytes(), promise_baseline);

    let mut promise_one_short = test_interpreter();
    let promise_one_short_baseline = promise_one_short
        .sync_estimated_memory_bytes()
        .expect("Promise creation refusal baseline");
    promise_one_short.config.max_total_memory_bytes =
        promise_one_short_baseline + promise_delta - 1;
    assert!(matches!(
        promise_one_short.create_promise(),
        Err(InterpreterError::MemoryBudgetExceeded { .. })
    ));
    assert_eq!(promise_one_short.promise_store.len(), 0);
    assert_eq!(
        promise_one_short.estimated_memory_bytes(),
        promise_one_short_baseline
    );

    let mut promise_exact = test_interpreter();
    let promise_exact_baseline = promise_exact
        .sync_estimated_memory_bytes()
        .expect("Promise creation exact baseline");
    promise_exact.config.max_total_memory_bytes = promise_exact_baseline + promise_delta;
    let exact_handle = promise_exact
        .create_promise()
        .expect("Promise creation fits exact ceiling");
    assert_eq!(
        promise_exact.estimated_memory_bytes(),
        promise_exact.recompute_estimated_memory_bytes()
    );
    promise_exact.rollback_fresh_promise(exact_handle);
    assert_eq!(
        promise_exact.estimated_memory_bytes(),
        promise_exact_baseline
    );

    let settlement_fixture = || {
        let mut core = test_interpreter();
        let handle = core.create_promise().expect("settlement source Promise");
        core.sync_estimated_memory_bytes()
            .expect("settlement fixture baseline");
        (core, handle)
    };
    let settlement_value = crate::object_model::JsValue::Str("settled-value".repeat(31));
    let settlement_label = Label::Custom {
        name: "settled-label".repeat(17),
        level: 3,
    };
    let (mut settlement_probe, handle) = settlement_fixture();
    let settlement_baseline = settlement_probe.estimated_memory_bytes();
    settlement_probe
        .fulfill_promise(handle, settlement_value.clone(), settlement_label.clone())
        .expect("unbounded Promise settlement probe");
    let settlement_delta = settlement_probe
        .estimated_memory_bytes()
        .saturating_sub(settlement_baseline);
    assert!(settlement_delta > 0);
    assert_eq!(
        settlement_probe.estimated_memory_bytes(),
        settlement_probe.recompute_estimated_memory_bytes()
    );

    let (mut settlement_one_short, handle) = settlement_fixture();
    let settlement_one_short_baseline = settlement_one_short.estimated_memory_bytes();
    settlement_one_short.config.max_total_memory_bytes =
        settlement_one_short_baseline + settlement_delta - 1;
    assert!(matches!(
        settlement_one_short.fulfill_promise(
            handle,
            settlement_value.clone(),
            settlement_label.clone()
        ),
        Err(InterpreterError::MemoryBudgetExceeded { .. })
    ));
    assert!(matches!(
        settlement_one_short
            .promise_store
            .get(handle)
            .expect("source Promise survives refusal")
            .state,
        crate::promise_model::PromiseState::Pending
    ));
    assert_eq!(
        settlement_one_short.estimated_memory_bytes(),
        settlement_one_short_baseline
    );

    let (mut settlement_exact, handle) = settlement_fixture();
    let settlement_exact_baseline = settlement_exact.estimated_memory_bytes();
    settlement_exact.config.max_total_memory_bytes = settlement_exact_baseline + settlement_delta;
    settlement_exact
        .fulfill_promise(handle, settlement_value, settlement_label)
        .expect("Promise settlement fits exact ceiling");
    assert!(
        settlement_exact
            .promise_store
            .get(handle)
            .expect("settled Promise exists")
            .state
            .is_fulfilled()
    );
    assert_eq!(
        settlement_exact.estimated_memory_bytes(),
        settlement_exact.recompute_estimated_memory_bytes()
    );

    let reaction_fixture = || {
        let mut core = test_interpreter();
        let handle = core.create_promise().expect("reaction source Promise");
        core.sync_estimated_memory_bytes()
            .expect("reaction fixture baseline");
        (core, handle)
    };
    let reaction_label = Label::Custom {
        name: "reaction-label".repeat(29),
        level: 2,
    };
    let (mut reaction_probe, handle) = reaction_fixture();
    let reaction_baseline = reaction_probe.estimated_memory_bytes();
    reaction_probe
        .register_promise_then(handle, None, None, reaction_label.clone())
        .expect("unbounded Promise reaction probe");
    let reaction_delta = reaction_probe
        .estimated_memory_bytes()
        .saturating_sub(reaction_baseline);
    assert!(reaction_delta > 0);

    let (mut reaction_one_short, handle) = reaction_fixture();
    let reaction_one_short_baseline = reaction_one_short.estimated_memory_bytes();
    reaction_one_short.config.max_total_memory_bytes =
        reaction_one_short_baseline + reaction_delta - 1;
    assert!(matches!(
        reaction_one_short.register_promise_then(handle, None, None, reaction_label.clone()),
        Err(InterpreterError::MemoryBudgetExceeded { .. })
    ));
    assert_eq!(reaction_one_short.promise_store.len(), 1);
    assert!(
        reaction_one_short
            .promise_store
            .get(handle)
            .expect("source Promise survives reaction refusal")
            .reactions
            .is_empty()
    );
    assert_eq!(
        reaction_one_short.estimated_memory_bytes(),
        reaction_one_short_baseline
    );

    let (mut reaction_exact, handle) = reaction_fixture();
    let reaction_exact_baseline = reaction_exact.estimated_memory_bytes();
    reaction_exact.config.max_total_memory_bytes = reaction_exact_baseline + reaction_delta;
    reaction_exact
        .register_promise_then(handle, None, None, reaction_label)
        .expect("Promise reaction fits exact ceiling");
    assert_eq!(reaction_exact.promise_store.len(), 2);
    assert_eq!(
        reaction_exact
            .promise_store
            .get(handle)
            .expect("source Promise after reaction")
            .reactions
            .len(),
        2
    );
    assert_eq!(
        reaction_exact.estimated_memory_bytes(),
        reaction_exact.recompute_estimated_memory_bytes()
    );
}

/// The register file's cached byte sum follows every write, and an
/// isolated callback's snapshot takes the caller's files whole: the
/// callback starts on a fresh file, the caller gets its own back, and the
/// estimate matches a full walk throughout.
#[test]
fn register_bytes_cache_follows_writes_and_isolated_callbacks() {
    let walk = |core: &InterpreterCore| {
        InterpreterCore::saturating_sum(
            core.registers
                .iter()
                .map(InterpreterCore::estimate_value_bytes),
        )
    };
    let payload = Value::BigInt(Arc::from("cached-register-bytes".repeat(16)));
    let payload_bytes = InterpreterCore::estimate_value_bytes(&payload);
    assert!(payload_bytes > 0);
    let caller_label = Label::Custom {
        name: "caller-register-label".to_string(),
        level: 2,
    };

    let mut core = test_interpreter();
    assert_eq!(core.registers_memory_bytes(), 0);
    // The sum above is now cached; a write that did not clear it would
    // leave it at 0.
    core.write_reg(2, payload.clone()).expect("caller register");
    assert_eq!(core.registers_memory_bytes(), payload_bytes);
    assert_eq!(core.registers_memory_bytes(), walk(&core));
    core.set_register_label(2, caller_label.clone())
        .expect("caller label");
    core.sync_estimated_memory_bytes()
        .expect("caller state baseline");
    let baseline = core.estimated_memory_bytes();
    let caller_label_count = core.register_labels.len();

    let previous_register_bytes = core.registers_memory_bytes();
    let previous_label_bytes = core.register_context_labels_memory_bytes();
    let snapshot = core
        .isolate_module_execution()
        .expect("isolated snapshot fits");
    assert_eq!(snapshot.register_bytes, payload_bytes);
    assert_eq!(snapshot.registers[2], payload);
    assert_eq!(snapshot.register_labels[2], caller_label);
    assert_eq!(core.registers.len(), core.config.max_registers as usize);
    assert!(
        core.registers
            .iter()
            .all(|value| *value == Value::Undefined)
    );
    assert_eq!(core.register_labels.len(), caller_label_count);
    assert!(
        core.register_labels
            .iter()
            .all(|label| *label == Label::Public)
    );
    assert_eq!(core.registers_memory_bytes(), 0);
    assert_eq!(walk(&core), 0);

    let previous_scope_bytes = core.scope_chain_memory_bytes();
    let previous_call_stack_bytes = core.call_stack_memory_bytes();
    core.apply_register_context_scope_call_stack_memory_delta(
        previous_register_bytes,
        previous_label_bytes,
        previous_scope_bytes,
        previous_call_stack_bytes,
    )
    .expect("callback setup fits");
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );

    core.write_reg(3, payload.clone())
        .expect("callback register");
    assert_eq!(core.registers_memory_bytes(), payload_bytes);
    assert_eq!(core.registers_memory_bytes(), walk(&core));
    core.restore_module_execution(snapshot, true);
    assert_eq!(core.read_reg(2).expect("caller register"), payload);
    assert_eq!(core.read_reg(3).expect("caller register"), Value::Undefined);
    assert_eq!(
        core.get_register_label(2).expect("caller label"),
        &caller_label
    );
    assert_eq!(core.registers_memory_bytes(), payload_bytes);
    assert_eq!(core.registers_memory_bytes(), walk(&core));
    assert_eq!(core.module_snapshot_in_flight_bytes, 0);
    assert_eq!(core.estimated_memory_bytes(), baseline);
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

/// The hot register writes keep the cached byte sum rather than dropping
/// it: an accounted write moves it by the value's delta, a static write
/// leaves it, and clearing a frame subtracts what the frame held. Each
/// step compares the cache with a full walk; dropping it instead would
/// leave `None` behind.
#[test]
fn register_bytes_cache_survives_hot_register_writes() {
    let walk = |core: &InterpreterCore| {
        InterpreterCore::saturating_sum(
            core.registers
                .iter()
                .map(InterpreterCore::estimate_value_bytes),
        )
    };
    let cached = |core: &InterpreterCore| {
        let bytes = core.registers_value_bytes.get();
        assert_eq!(bytes, Some(walk(core)));
        bytes.expect("cache kept")
    };
    let long = Value::str("register-cache-delta".repeat(8));
    let short = Value::str("short");
    let mut core = test_interpreter();
    assert_eq!(core.registers_memory_bytes(), 0);

    core.write_reg(1, long.clone()).expect("accounted write");
    let after_long = cached(&core);
    assert_eq!(after_long, InterpreterCore::estimate_value_bytes(&long));
    core.write_reg(1, short.clone())
        .expect("accounted overwrite");
    assert_eq!(cached(&core), InterpreterCore::estimate_value_bytes(&short));
    core.write_reg(2, Value::Int(7)).expect("static write");
    core.write_reg(2, Value::Bool(true))
        .expect("static overwrite");
    assert_eq!(cached(&core), InterpreterCore::estimate_value_bytes(&short));
    core.write_reg_with_label(3, long.clone(), Label::Public)
        .expect("labelled accounted write");
    core.write_reg_with_label(4, Value::Null, Label::Public)
        .expect("labelled static write");
    let both = cached(&core);
    assert_eq!(
        both,
        InterpreterCore::estimate_value_bytes(&short)
            + InterpreterCore::estimate_value_bytes(&long)
    );

    // Registers 0-2: the short string goes, the long one in 3 stays.
    core.clear_current_register_frame_width(3);
    assert_eq!(cached(&core), InterpreterCore::estimate_value_bytes(&long));
    core.clear_current_register_frame_width(5);
    assert_eq!(cached(&core), 0);
}

#[test]
fn composed_promise_owners_rollback_and_drain_exactly_bd_zpn45() {
    let once_fixture = || {
        let mut core = test_interpreter();
        let emitter = core
            .alloc_object_with_properties(&[])
            .expect("events.once emitter");
        core.write_reg(0, Value::Object(emitter))
            .expect("events.once target register");
        core.write_reg(1, Value::str("payload-event".repeat(31)))
            .expect("events.once event register");
        core.sync_estimated_memory_bytes()
            .expect("events.once fixture baseline");
        core
    };
    let once_args = RegRange { start: 0, count: 2 };
    let mut once_probe = once_fixture();
    let once_baseline = once_probe.estimated_memory_bytes();
    once_probe
        .register_event_promise_once(once_args)
        .expect("unbounded events.once probe");
    let once_delta = once_probe
        .estimated_memory_bytes()
        .saturating_sub(once_baseline);
    assert!(once_delta > 0);

    let mut once_one_short = once_fixture();
    let once_one_short_baseline = once_one_short.estimated_memory_bytes();
    once_one_short.config.max_total_memory_bytes = once_one_short_baseline + once_delta - 1;
    assert!(matches!(
        once_one_short.register_event_promise_once(once_args),
        Err(InterpreterError::MemoryBudgetExceeded { .. })
    ));
    assert_eq!(once_one_short.promise_store.len(), 0);
    assert!(once_one_short.event_promise_waiters.is_empty());
    assert_eq!(once_one_short.next_event_promise_waiter_id, 0);
    assert_eq!(
        once_one_short.estimated_memory_bytes(),
        once_one_short_baseline
    );

    let mut once_exact = once_fixture();
    let once_exact_baseline = once_exact.estimated_memory_bytes();
    once_exact.config.max_total_memory_bytes = once_exact_baseline + once_delta;
    once_exact
        .register_event_promise_once(once_args)
        .expect("events.once fits exact ceiling");
    assert_eq!(once_exact.promise_store.len(), 1);
    assert_eq!(once_exact.next_event_promise_waiter_id, 1);
    assert_eq!(
        once_exact.estimated_memory_bytes(),
        once_exact.recompute_estimated_memory_bytes()
    );

    let combinator_fixture = || {
        let mut core = test_interpreter();
        let first = core.create_promise().expect("first Promise.all input");
        let second = core.create_promise().expect("second Promise.all input");
        core.write_reg(0, Value::Promise(first.0))
            .expect("first Promise.all register");
        core.write_reg(1, Value::Promise(second.0))
            .expect("second Promise.all register");
        core.sync_estimated_memory_bytes()
            .expect("Promise.all fixture baseline");
        (core, first, second)
    };
    let combinator_args = RegRange { start: 0, count: 2 };
    let mut combinator_probe = combinator_fixture().0;
    let combinator_baseline = combinator_probe.estimated_memory_bytes();
    let combinator_snapshot_bytes = combinator_probe.promise_runtime_memory_bytes();
    combinator_probe
        .dispatch_promise_combinator(PromiseCombinatorKind::All, combinator_args, None)
        .expect("unbounded Promise.all probe");
    let combinator_delta = combinator_probe
        .estimated_memory_bytes()
        .saturating_sub(combinator_baseline);
    let combinator_peak_delta = combinator_snapshot_bytes.saturating_add(combinator_delta);
    assert!(combinator_delta > 0);

    let (mut combinator_one_short, _, _) = combinator_fixture();
    let combinator_one_short_baseline = combinator_one_short.estimated_memory_bytes();
    combinator_one_short.config.max_total_memory_bytes =
        combinator_one_short_baseline + combinator_peak_delta - 1;
    assert!(matches!(
        combinator_one_short.dispatch_promise_combinator(
            PromiseCombinatorKind::All,
            combinator_args,
            None
        ),
        Err(InterpreterError::MemoryBudgetExceeded { .. })
    ));
    assert_eq!(combinator_one_short.promise_store.len(), 2);
    assert!(combinator_one_short.promise_combinators.is_empty());
    assert!(combinator_one_short.promise_combinator_watchers.is_empty());
    assert_eq!(combinator_one_short.next_promise_combinator_id, 0);
    assert_eq!(
        combinator_one_short.estimated_memory_bytes(),
        combinator_one_short_baseline
    );

    let (mut combinator_exact, first, second) = combinator_fixture();
    let combinator_exact_baseline = combinator_exact.estimated_memory_bytes();
    combinator_exact.config.max_total_memory_bytes =
        combinator_exact_baseline + combinator_peak_delta;
    combinator_exact
        .dispatch_promise_combinator(PromiseCombinatorKind::All, combinator_args, None)
        .expect("Promise.all fits exact physical ceiling");
    assert_eq!(combinator_exact.promise_store.len(), 3);
    assert_eq!(combinator_exact.promise_combinators.len(), 1);
    assert_eq!(
        combinator_exact
            .promise_combinator_watchers
            .get(&first)
            .map_or(0, Vec::len),
        1
    );
    assert_eq!(
        combinator_exact
            .promise_combinator_watchers
            .get(&second)
            .map_or(0, Vec::len),
        1
    );
    assert_eq!(
        combinator_exact.estimated_memory_bytes(),
        combinator_exact.recompute_estimated_memory_bytes()
    );

    let mut drain = test_interpreter();
    let source = drain.create_promise().expect("microtask source Promise");
    let result = drain
        .register_promise_then(source, None, None, Label::Public)
        .expect("microtask result Promise");
    drain
        .fulfill_promise(
            source,
            crate::object_model::JsValue::Str("drained-value".repeat(17)),
            Label::Public,
        )
        .expect("enqueue identity reaction");
    assert_eq!(drain.event_loop.microtasks.pending_count(), 1);
    drain
        .drain_microtasks(None)
        .expect("microtask drain propagates settlement success");
    assert!(
        drain
            .promise_store
            .get(result)
            .expect("reaction result Promise remains live")
            .state
            .is_fulfilled()
    );
    assert!(drain.event_loop.microtasks.is_empty());
    assert_eq!(drain.promise_in_flight_task_bytes, 0);
    assert_eq!(
        drain.estimated_memory_bytes(),
        drain.recompute_estimated_memory_bytes()
    );
}

#[test]
fn writable_terminal_callback_fifo_is_exact_accounted_and_atomic_bd_fw7zd_1() {
    assert!(
        usize::try_from(MEMORY_ESTIMATE_WRITABLE_END_CALLBACK_BYTES)
            .expect("terminal callback node charge fits usize")
            >= std::mem::size_of::<WritableEndCallbackRecord>()
                .saturating_add(2 * std::mem::size_of::<usize>()),
        "the conservative node charge must cover the record and both linked-list pointers"
    );
    let mut core = test_interpreter();
    let Value::Object(writable) = core
        .construct_stream_writable(RegRange { start: 0, count: 0 })
        .expect("generic Writable")
    else {
        panic!("Writable constructor must return an object");
    };
    let callback = WritableCallbackRecord {
        value: Value::BuiltinFunction(BuiltinFunction::new_kind(BuiltinFunctionKind::ArrayIsArray)),
        label: Label::Custom {
            name: "terminal-registration".to_string(),
            level: 3,
        },
        module_specifier: Some("callback-owner.mjs".to_string()),
    };

    let initial_bytes = core.estimated_memory_bytes();
    core.writable_streams
        .get_mut(&writable)
        .expect("live Writable state")
        .end_callbacks
        .push_back(WritableEndCallbackRecord {
            callback: callback.clone(),
            registered_after_end: false,
        });
    let first_state_bytes =
        InterpreterCore::estimate_writable_state_bytes(&core.writable_streams[&writable]);
    core.sync_estimated_memory_bytes()
        .expect("first FIFO callback accounting");
    assert_eq!(
        core.estimated_memory_bytes(),
        initial_bytes + first_state_bytes - MEMORY_ESTIMATE_WRITABLE_BASE_BYTES
    );
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );

    let before_second_bytes = core.estimated_memory_bytes();
    let before_second_state_bytes =
        InterpreterCore::estimate_writable_state_bytes(&core.writable_streams[&writable]);
    {
        let state = core
            .writable_streams
            .get_mut(&writable)
            .expect("live Writable FIFO");
        state.end_callbacks.push_back(WritableEndCallbackRecord {
            callback: callback.clone(),
            registered_after_end: true,
        });
    }
    let after_second_state_bytes =
        InterpreterCore::estimate_writable_state_bytes(&core.writable_streams[&writable]);
    core.sync_estimated_memory_bytes()
        .expect("second FIFO callback accounting");
    assert_eq!(
        core.estimated_memory_bytes(),
        before_second_bytes + after_second_state_bytes - before_second_state_bytes
    );

    let before_pop = core.estimated_memory_bytes();
    let (popped, mut invocation_charge) = core
        .take_writable_end_callback(writable)
        .expect("one callback remains queued");
    assert_eq!(
        core.estimated_memory_bytes(),
        before_pop - MEMORY_ESTIMATE_WRITABLE_END_CALLBACK_BYTES,
        "destructive pop releases only the exact FIFO node while its payload is live"
    );
    assert_eq!(
        invocation_charge,
        InterpreterCore::estimate_writable_callback_bytes(&callback)
    );
    assert_eq!(core.writable_in_flight_callback_bytes, invocation_charge);
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
    drop(popped);
    let remaining_charge = invocation_charge;
    core.release_writable_in_flight_charge(&mut invocation_charge, remaining_charge);
    assert_eq!(invocation_charge, 0);
    assert_eq!(core.writable_in_flight_callback_bytes, 0);
    assert_eq!(
        core.estimated_memory_bytes(),
        before_pop
            - InterpreterCore::estimate_writable_callback_bytes(&callback)
            - MEMORY_ESTIMATE_WRITABLE_END_CALLBACK_BYTES
    );

    core.release_writable_state_storage(writable);
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes(),
        "terminal release must subtract every retained FIFO node and payload"
    );
}

#[test]
fn writable_write_fifo_is_exact_accounted_and_atomic_bd_fw7zd_3() {
    assert!(
        usize::try_from(MEMORY_ESTIMATE_WRITABLE_WRITE_NODE_BYTES)
            .expect("write node charge fits usize")
            >= std::mem::size_of::<WritableWriteRecord>()
                .saturating_add(2 * std::mem::size_of::<usize>()),
        "the conservative write charge must cover the record and both linked-list pointers"
    );
    let mut core = test_interpreter();
    let Value::Object(writable) = core
        .construct_stream_writable(RegRange { start: 0, count: 0 })
        .expect("atomic write Writable")
    else {
        panic!("Writable constructor must return an object");
    };
    core.writable_streams
        .get_mut(&writable)
        .expect("live Writable")
        .object_mode = true;
    let label = Label::Custom {
        name: "write-transaction-label".repeat(8),
        level: 3,
    };
    let callback = WritableCallbackRecord {
        value: Value::BuiltinFunction(BuiltinFunction::require(
            "retained-require-specifier".repeat(8),
        )),
        label: label.clone(),
        module_specifier: Some("write-owner.mjs".to_string()),
    };
    let value = Value::BigInt(Arc::from("9".repeat(256)));
    let record = WritableWriteRecord {
        value: value.clone(),
        label: label.clone(),
        units: 1,
        callback: Some(callback.clone()),
        status: WritableWriteStatus::Pending,
        completion_failed: false,
    };
    let previous_state_bytes =
        InterpreterCore::estimate_writable_state_bytes(&core.writable_streams[&writable]);
    let next_state_bytes = previous_state_bytes
        .saturating_add(InterpreterCore::estimate_writable_write_record_bytes(
            &record,
        ))
        .saturating_add(InterpreterCore::estimate_label_bytes(&label));
    let required_delta = next_state_bytes.saturating_sub(previous_state_bytes);
    let before_bytes = core.estimated_memory_bytes();
    let before_state = format!("{:?}", core.writable_streams[&writable]);

    core.config.max_total_memory_bytes = before_bytes.saturating_add(required_delta - 1);
    assert!(matches!(
        core.writable_enqueue(
            writable,
            value.clone(),
            label.clone(),
            Some(callback.clone()),
        ),
        Err(InterpreterError::MemoryBudgetExceeded { .. })
    ));
    assert_eq!(
        format!("{:?}", core.writable_streams[&writable]),
        before_state
    );
    assert_eq!(core.estimated_memory_bytes(), before_bytes);
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );

    core.config.max_total_memory_bytes = before_bytes.saturating_add(required_delta);
    assert!(
        core.writable_enqueue(writable, value, label.clone(), Some(callback))
            .expect("the exact node and payload charge must fit")
    );
    let state = &core.writable_streams[&writable];
    assert_eq!(state.writes.len(), 1);
    assert_eq!(state.lifecycle_label, label);
    assert_eq!(core.estimated_memory_bytes(), before_bytes + required_delta);
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn writable_synchronous_burst_uses_linear_fifo_steps_bd_zl516() {
    const BURST: usize = 2_048;
    let module = test_module_with_functions(
        vec![
            Ir3Instruction::Call {
                callee: 2,
                args: RegRange { start: 3, count: 0 },
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec![Ir3FunctionDesc {
            entry: 0,
            arity: 3,
            frame_size: 4,
            name: Some("synchronous_write_completion".to_string()),
            is_generator: false,
            rest_param_index: None,
        }],
    );
    let mut core = test_interpreter();
    let options = core
        .alloc_object_with_properties(&[("write", Value::Function(0))])
        .expect("synchronous Writable options");
    core.write_reg(0, Value::Object(options))
        .expect("synchronous Writable options register");
    let Value::Object(writable) = core
        .construct_stream_writable(RegRange { start: 0, count: 1 })
        .expect("synchronous Writable")
    else {
        panic!("Writable constructor must return an object");
    };

    for sequence in 0..BURST {
        core.write_reg(1, Value::str(sequence.to_string()))
            .expect("burst chunk register");
        assert_eq!(
            core.writable_write(
                &module,
                Value::Object(writable),
                RegRange { start: 1, count: 1 },
            ),
            Ok(Value::Bool(true))
        );
    }

    let state = &core.writable_streams[&writable];
    assert!(state.writes.ready.is_empty());
    assert_eq!(state.writes.completed.len(), BURST);
    assert_eq!(state.writes.pending_len(), 0);
    assert_eq!(
        state.writes.scheduler_steps(),
        3 * u64::try_from(BURST).expect("burst length fits u64"),
        "enqueue, front activation, and front completion must each cost one queue step"
    );
    assert_eq!(
        state.writes.retained_bytes(),
        state.writes.recompute_retained_bytes(),
        "cached hot-path accounting must match an independent full traversal"
    );
    for (sequence, record) in state.writes.iter().enumerate() {
        assert_eq!(record.value, Value::str(sequence.to_string()));
        assert_eq!(record.status, WritableWriteStatus::Completed);
    }

    let steps_before_stale_completion = state.writes.scheduler_steps();
    let stale_completion = BuiltinFunction::writable_completion(
        BuiltinFunctionKind::StreamWritableWriteDone,
        writable,
        0,
    );
    assert_eq!(
        core.writable_write_done(&module, &stale_completion, RegRange { start: 0, count: 0 },),
        Ok(Value::Undefined)
    );
    assert_eq!(
        core.writable_streams[&writable].writes.scheduler_steps(),
        steps_before_stale_completion,
        "a stale completion lookup must be a constant-time no-op"
    );

    core.drain_runtime_checkpoint(Some(&module))
        .expect("burst callback checkpoint");
    let state = &core.writable_streams[&writable];
    assert!(state.writes.is_empty());
    assert_eq!(
        state.writes.scheduler_steps(),
        4 * u64::try_from(BURST).expect("burst length fits u64"),
        "deferred FIFO drainage must add exactly one queue step per record"
    );
    assert_eq!(state.writes.retained_bytes(), 0);
    assert_eq!(state.buffered_length, 0);
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn writable_destroy_cancels_long_pending_fifo_exactly_bd_zl516() {
    const PENDING: usize = 1_024;
    let module = test_module_with_functions(
        vec![Ir3Instruction::Return { value: 0 }],
        vec![Ir3FunctionDesc {
            entry: 0,
            arity: 3,
            frame_size: 3,
            name: Some("pending_write".to_string()),
            is_generator: false,
            rest_param_index: None,
        }],
    );
    let mut core = test_interpreter();
    let options = core
        .alloc_object_with_properties(&[("write", Value::Function(0))])
        .expect("pending Writable options");
    core.write_reg(0, Value::Object(options))
        .expect("pending Writable options register");
    let Value::Object(writable) = core
        .construct_stream_writable(RegRange { start: 0, count: 1 })
        .expect("pending Writable")
    else {
        panic!("Writable constructor must return an object");
    };
    core.writable_cork(Value::Object(writable), RegRange { start: 1, count: 0 })
        .expect("cork pending Writable");

    for _ in 0..PENDING {
        core.write_reg(1, Value::str("queued"))
            .expect("pending chunk register");
        core.writable_write(
            &module,
            Value::Object(writable),
            RegRange { start: 1, count: 1 },
        )
        .expect("corked pending write");
    }
    let state = &core.writable_streams[&writable];
    assert_eq!(state.writes.pending_len(), PENDING);
    assert_eq!(state.writes.scheduler_steps(), PENDING as u64);
    assert_eq!(
        state.writes.retained_bytes(),
        state.writes.recompute_retained_bytes()
    );

    core.writable_destroy(Value::Object(writable), RegRange { start: 2, count: 0 })
        .expect("destroy cancels pending writes");
    let state = &core.writable_streams[&writable];
    assert!(state.writes.is_empty());
    assert_eq!(state.buffered_length, 0);
    assert!(state.destroy_requested);
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes(),
        "cancellation must release every cached queue byte exactly"
    );
}

#[test]
fn writable_end_chunk_and_cork_labels_refuse_atomically_bd_fw7zd_3() {
    let module = test_module_with_functions(Vec::new(), Vec::new());
    let mut core = test_interpreter();
    let Value::Object(writable) = core
        .construct_stream_writable(RegRange { start: 0, count: 0 })
        .expect("atomic end Writable")
    else {
        panic!("Writable constructor must return an object");
    };
    core.writable_streams
        .get_mut(&writable)
        .expect("live Writable")
        .write_callback = Some(Value::BuiltinFunction(BuiltinFunction::new_kind(
        BuiltinFunctionKind::ArrayIsArray,
    )));
    core.sync_estimated_memory_bytes()
        .expect("write implementation accounting");
    let label = Label::Custom {
        name: "end-transaction-label".repeat(8),
        level: 3,
    };
    core.write_reg(0, Value::Int(1)).expect("cork label value");
    core.set_register_label(0, label.clone())
        .expect("cork label");
    let before_cork_bytes = core.estimated_memory_bytes();
    let label_bytes = InterpreterCore::estimate_label_bytes(&label);
    core.config.max_total_memory_bytes = before_cork_bytes
        .saturating_add(label_bytes)
        .saturating_sub(1);
    assert!(matches!(
        core.writable_cork(Value::Object(writable), RegRange { start: 0, count: 1 }),
        Err(InterpreterError::MemoryBudgetExceeded { .. })
    ));
    assert_eq!(core.writable_streams[&writable].cork_depth, 0);
    assert_eq!(
        core.writable_streams[&writable].lifecycle_label,
        Label::Public
    );

    core.config.max_total_memory_bytes = before_cork_bytes.saturating_add(label_bytes);
    core.writable_cork(Value::Object(writable), RegRange { start: 0, count: 1 })
        .expect("exact cork label replacement");
    assert_eq!(core.writable_streams[&writable].cork_depth, 1);
    assert_eq!(core.writable_streams[&writable].lifecycle_label, label);

    core.config.max_total_memory_bytes = u64::MAX;
    let chunk = Value::str("tail");
    let callback =
        Value::BuiltinFunction(BuiltinFunction::new_kind(BuiltinFunctionKind::ArrayIsArray));
    core.write_reg(0, chunk.clone()).expect("end chunk");
    core.write_reg(1, callback.clone()).expect("end callback");
    core.set_register_label(0, label.clone())
        .expect("end chunk label");
    core.set_register_label(1, label.clone())
        .expect("end callback label");
    let callback_record = WritableCallbackRecord {
        value: callback,
        label: label.clone(),
        module_specifier: None,
    };
    let write_record = WritableWriteRecord {
        value: chunk,
        label: label.clone(),
        units: "tail".len(),
        callback: None,
        status: WritableWriteStatus::Pending,
        completion_failed: false,
    };
    let required_delta = InterpreterCore::estimate_writable_write_record_bytes(&write_record)
        .saturating_add(MEMORY_ESTIMATE_WRITABLE_END_CALLBACK_BYTES)
        .saturating_add(InterpreterCore::estimate_writable_callback_bytes(
            &callback_record,
        ));
    let before_end_bytes = core.estimated_memory_bytes();
    let before_end_state = format!("{:?}", core.writable_streams[&writable]);
    core.config.max_total_memory_bytes = before_end_bytes
        .saturating_add(required_delta)
        .saturating_sub(1);
    assert!(matches!(
        core.writable_end(
            &module,
            Value::Object(writable),
            RegRange { start: 0, count: 2 },
        ),
        Err(InterpreterError::MemoryBudgetExceeded { .. })
    ));
    assert_eq!(
        format!("{:?}", core.writable_streams[&writable]),
        before_end_state
    );
    assert_eq!(core.estimated_memory_bytes(), before_end_bytes);

    core.config.max_total_memory_bytes = before_end_bytes.saturating_add(required_delta);
    core.append_writable_write(
        writable,
        write_record.value,
        write_record.label,
        None,
        Some(callback_record),
        true,
    )
    .expect("exact combined write and terminal-callback charge");
    let state = &core.writable_streams[&writable];
    assert_eq!(state.writes.len(), 1);
    assert_eq!(state.end_callbacks.len(), 1);
    assert_eq!(state.cork_depth, 0);
    assert!(state.end_requested);
    assert_eq!(state.lifecycle_label, label);
    assert_eq!(
        core.estimated_memory_bytes(),
        before_end_bytes + required_delta
    );
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn writable_transactions_use_full_same_level_ifc_order_bd_fw7zd_3() {
    let mut core = test_interpreter();
    let Value::Object(writable) = core
        .construct_stream_writable(RegRange { start: 0, count: 0 })
        .expect("same-level IFC Writable")
    else {
        panic!("Writable constructor must return an object");
    };
    core.writable_streams
        .get_mut(&writable)
        .expect("live Writable")
        .lifecycle_label = Label::Custom {
        name: "same-level-a".to_string(),
        level: 3,
    };
    core.sync_estimated_memory_bytes()
        .expect("initial same-level label accounting");
    let dominant = Label::Custom {
        name: "same-level-z".to_string(),
        level: 3,
    };
    core.write_reg(0, Value::Int(1)).expect("same-level arg");
    core.set_register_label(0, dominant.clone())
        .expect("same-level arg label");
    core.writable_cork(Value::Object(writable), RegRange { start: 0, count: 1 })
        .expect("full-Ord same-level join");
    assert_eq!(core.writable_streams[&writable].lifecycle_label, dominant);
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn register_and_callback_context_labels_are_exact_and_atomic_bd_8hv4e() {
    let mut core = test_interpreter();
    core.sync_estimated_memory_bytes()
        .expect("initial register accounting");

    let direct = Label::Custom {
        name: "direct-register-label".repeat(12),
        level: 7,
    };
    let direct_bytes = InterpreterCore::estimate_label_bytes(&direct);
    let before_direct = core.estimated_memory_bytes();
    core.config.max_total_memory_bytes = before_direct.saturating_add(direct_bytes - 1);
    assert!(matches!(
        core.set_register_label(0, direct.clone()),
        Err(InterpreterError::MemoryBudgetExceeded { .. })
    ));
    assert_eq!(
        core.get_register_label(0).expect("r0 label"),
        &Label::Public
    );
    assert_eq!(core.estimated_memory_bytes(), before_direct);

    core.config.max_total_memory_bytes = before_direct.saturating_add(direct_bytes);
    core.set_register_label(0, direct.clone())
        .expect("exact direct-label ceiling");
    assert_eq!(core.get_register_label(0).expect("r0 label"), &direct);
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );

    core.config.max_total_memory_bytes = u64::MAX;
    let lower = Label::Custom {
        name: "same-level-a".repeat(4),
        level: 11,
    };
    let context = Label::Custom {
        name: "same-level-z-context".repeat(10),
        level: 11,
    };
    core.set_register_label(1, lower.clone())
        .expect("lower same-level destination");
    core.active_inline_callback_context_label = Some(context.clone());
    core.sync_estimated_memory_bytes()
        .expect("active callback-context accounting");
    let before_context_join = core.estimated_memory_bytes();
    let context_delta = InterpreterCore::estimate_label_bytes(&context)
        .saturating_sub(InterpreterCore::estimate_label_bytes(&lower));
    assert!(context_delta > 0);

    core.config.max_total_memory_bytes = before_context_join
        .saturating_add(context_delta)
        .saturating_sub(1);
    assert!(matches!(
        core.set_register_label(1, lower.clone()),
        Err(InterpreterError::MemoryBudgetExceeded { .. })
    ));
    assert_eq!(core.get_register_label(1).expect("r1 label"), &lower);
    assert_eq!(core.estimated_memory_bytes(), before_context_join);

    core.config.max_total_memory_bytes = before_context_join.saturating_add(context_delta);
    core.set_register_label(1, lower)
        .expect("exact same-level context join");
    assert_eq!(core.get_register_label(1).expect("r1 label"), &context);
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );

    core.config.max_total_memory_bytes = u64::MAX;
    let value = Value::str("combined-value-and-label".repeat(12));
    let write_delta = InterpreterCore::estimate_value_bytes(&value)
        .saturating_add(InterpreterCore::estimate_label_bytes(&context));
    let before_write = core.estimated_memory_bytes();
    core.config.max_total_memory_bytes = before_write.saturating_add(write_delta - 1);
    assert!(matches!(
        core.write_reg(2, value.clone()),
        Err(InterpreterError::MemoryBudgetExceeded { .. })
    ));
    assert_eq!(core.read_reg(2).expect("r2 value"), Value::Undefined);
    assert_eq!(
        core.get_register_label(2).expect("r2 label"),
        &Label::Public
    );
    assert_eq!(core.estimated_memory_bytes(), before_write);

    core.config.max_total_memory_bytes = before_write.saturating_add(write_delta);
    core.write_reg(2, value.clone())
        .expect("exact combined value and context-label ceiling");
    assert_eq!(core.read_reg(2).expect("r2 value"), value);
    assert_eq!(core.get_register_label(2).expect("r2 label"), &context);
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn inline_callback_context_uses_full_custom_order_and_restores_bd_8hv4e() {
    let module = test_module_with_functions(
        vec![Ir3Instruction::Return { value: 0 }],
        vec![Ir3FunctionDesc {
            entry: 0,
            arity: 1,
            frame_size: 2,
            name: Some("custom_context_identity".to_string()),
            is_generator: false,
            rest_param_index: None,
        }],
    );
    let cases = [
        (
            Label::Custom {
                name: "same-level-z-inherited".to_string(),
                level: 13,
            },
            Label::Custom {
                name: "same-level-a-argument".to_string(),
                level: 13,
            },
        ),
        (
            Label::Custom {
                name: "same-level-a-inherited".to_string(),
                level: 13,
            },
            Label::Custom {
                name: "same-level-z-argument".to_string(),
                level: 13,
            },
        ),
    ];

    for (inherited, argument) in cases {
        let expected = if inherited >= argument {
            inherited.clone()
        } else {
            argument.clone()
        };
        let mut core = test_interpreter();
        core.active_inline_callback_context_label = Some(inherited.clone());
        core.sync_estimated_memory_bytes()
            .expect("outer callback-context accounting");
        let (value, label) = core
            .invoke_inline_method_call_with_argument_label(
                Some(&module),
                Value::Function(0),
                Value::Undefined,
                vec![Value::Int(29)],
                Some(argument),
            )
            .expect("same-level Custom callback invocation");
        assert_eq!(value, Value::Int(29));
        assert_eq!(label, expected);
        assert_eq!(
            core.active_inline_callback_context_label,
            Some(inherited),
            "the outer callback context must be restored after the isolated call"
        );
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }
}

#[test]
fn arg_label_join_temporary_has_an_exact_transient_ceiling_bd_8hv4e() {
    let mut core = test_interpreter();
    let Value::Object(writable) = core
        .construct_stream_writable(RegRange { start: 0, count: 0 })
        .expect("transient-label Writable")
    else {
        panic!("Writable constructor must return an object");
    };
    let label = Label::Custom {
        name: "transient-only-join-label".repeat(12),
        level: 15,
    };
    core.writable_streams
        .get_mut(&writable)
        .expect("live Writable")
        .lifecycle_label = label.clone();
    core.write_reg_with_label(0, Value::Int(1), label.clone())
        .expect("labeled cork argument");
    core.sync_estimated_memory_bytes()
        .expect("dominant lifecycle accounting");
    let before = core.estimated_memory_bytes();
    let temporary_bytes = InterpreterCore::estimate_label_bytes(&label);

    core.config.max_total_memory_bytes = before.saturating_add(temporary_bytes - 1);
    assert!(matches!(
        core.writable_cork(Value::Object(writable), RegRange { start: 0, count: 1 }),
        Err(InterpreterError::MemoryBudgetExceeded { .. })
    ));
    assert_eq!(core.writable_streams[&writable].cork_depth, 0);
    assert_eq!(core.writable_streams[&writable].lifecycle_label, label);
    assert_eq!(core.estimated_memory_bytes(), before);

    core.config.max_total_memory_bytes = before.saturating_add(temporary_bytes);
    core.writable_cork(Value::Object(writable), RegRange { start: 0, count: 1 })
        .expect("exact transient label clone ceiling");
    assert_eq!(core.writable_streams[&writable].cork_depth, 1);
    assert_eq!(core.writable_streams[&writable].lifecycle_label, label);
    assert_eq!(
        core.estimated_memory_bytes(),
        before,
        "the joined label was temporary because lifecycle already retained the winner"
    );
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );

    core.config.max_total_memory_bytes = u64::MAX;
    core.terminalize_writable_state_storage(writable)
        .expect("terminalize dominant-label Writable");
    let before_terminal = core.estimated_memory_bytes();
    core.config.max_total_memory_bytes = before_terminal.saturating_add(temporary_bytes - 1);
    assert!(matches!(
        core.writable_cork(Value::Object(writable), RegRange { start: 0, count: 1 }),
        Err(InterpreterError::MemoryBudgetExceeded { .. })
    ));
    assert_eq!(
        core.writable_terminal_states[&writable].lifecycle_label,
        label
    );
    assert_eq!(core.estimated_memory_bytes(), before_terminal);

    core.config.max_total_memory_bytes = before_terminal.saturating_add(temporary_bytes);
    core.writable_cork(Value::Object(writable), RegRange { start: 0, count: 1 })
        .expect("exact terminal transient-label ceiling");
    assert_eq!(
        core.writable_terminal_states[&writable].lifecycle_label,
        label
    );
    assert_eq!(core.estimated_memory_bytes(), before_terminal);
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn ordinary_ir_label_commits_are_exact_and_atomic_bd_8hv4e() {
    let label = Label::Custom {
        name: "ordinary-ir-register-label".repeat(12),
        level: 17,
    };
    let label_bytes = InterpreterCore::estimate_label_bytes(&label);

    let unary_module = test_module_with_functions(
        vec![
            Ir3Instruction::TypeOf { dst: 1, src: 0 },
            Ir3Instruction::Halt,
        ],
        Vec::new(),
    );
    let mut unary_core = test_interpreter();
    unary_core
        .write_reg_with_label(0, Value::Int(1), label.clone())
        .expect("labeled unary source");
    unary_core
        .write_reg(1, Value::Int(99))
        .expect("sentinel unary destination");
    unary_core
        .sync_estimated_memory_bytes()
        .expect("initial unary accounting");
    let before_unary = unary_core.estimated_memory_bytes();
    let unary_result = Value::str("number");
    let unary_delta =
        label_bytes.saturating_add(InterpreterCore::estimate_value_bytes(&unary_result));
    assert!(unary_delta > label_bytes);
    unary_core.config.max_total_memory_bytes = before_unary.saturating_add(unary_delta - 1);
    assert!(matches!(
        unary_core.run_loop(&unary_module),
        Err(InterpreterError::MemoryBudgetExceeded { .. })
    ));
    assert_eq!(unary_core.read_reg(1).expect("r1 sentinel"), Value::Int(99));
    assert_eq!(
        unary_core.get_register_label(1).expect("r1 label"),
        &Label::Public
    );
    assert_eq!(unary_core.estimated_memory_bytes(), before_unary);

    unary_core.config.max_total_memory_bytes = before_unary.saturating_add(unary_delta);
    assert_eq!(
        unary_core.run_loop(&unary_module),
        Err(InterpreterError::Halted)
    );
    assert_eq!(unary_core.read_reg(1).expect("r1 result"), unary_result);
    assert_eq!(unary_core.get_register_label(1).expect("r1 label"), &label);
    assert_eq!(
        unary_core.estimated_memory_bytes(),
        unary_core.recompute_estimated_memory_bytes()
    );

    let property_module = test_module_with_functions(
        vec![
            Ir3Instruction::GetProperty {
                obj: 0,
                key: 1,
                dst: 2,
            },
            Ir3Instruction::Halt,
        ],
        Vec::new(),
    );
    let mut property_core = test_interpreter();
    let object = property_core
        .alloc_object_with_prototype(None)
        .expect("property source object");
    let property_result = Value::str("property-result-value".repeat(12));
    property_core
        .set_object_property(object, "answer".to_string(), property_result.clone())
        .expect("property source value");
    property_core
        .write_reg_with_label(0, Value::Object(object), label.clone())
        .expect("labeled property receiver");
    property_core
        .write_reg(1, Value::str("answer"))
        .expect("property key");
    property_core
        .write_reg(2, Value::Int(99))
        .expect("sentinel property destination");
    property_core
        .sync_estimated_memory_bytes()
        .expect("initial property accounting");
    let before_property = property_core.estimated_memory_bytes();
    let property_delta =
        label_bytes.saturating_add(InterpreterCore::estimate_value_bytes(&property_result));
    assert!(property_delta > label_bytes);
    property_core.config.max_total_memory_bytes =
        before_property.saturating_add(property_delta - 1);
    assert!(matches!(
        property_core.run_loop(&property_module),
        Err(InterpreterError::MemoryBudgetExceeded { .. })
    ));
    assert_eq!(
        property_core.read_reg(2).expect("r2 sentinel"),
        Value::Int(99)
    );
    assert_eq!(
        property_core.get_register_label(2).expect("r2 label"),
        &Label::Public
    );
    assert_eq!(property_core.estimated_memory_bytes(), before_property);

    property_core.config.max_total_memory_bytes = before_property.saturating_add(property_delta);
    assert_eq!(
        property_core.run_loop(&property_module),
        Err(InterpreterError::Halted)
    );
    assert_eq!(
        property_core.read_reg(2).expect("r2 result"),
        property_result
    );
    assert_eq!(
        property_core.get_register_label(2).expect("r2 label"),
        &label
    );
    assert_eq!(
        property_core.estimated_memory_bytes(),
        property_core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn spread_direct_sources_are_failure_atomic_at_exact_ceiling_bd_kvq09() {
    #[derive(Clone, Copy, Debug)]
    enum SourceKind {
        IndexedObject,
        TypedArray,
        String,
    }

    let module = test_module_with_functions(
        vec![
            Ir3Instruction::SpreadIntoArray {
                array: 0,
                iterable: 1,
            },
            Ir3Instruction::Halt,
        ],
        Vec::new(),
    );
    let target_label = Label::Custom {
        name: "same-level-a-target".repeat(4),
        level: 41,
    };
    let iterable_label = Label::Custom {
        name: "same-level-m-iterable".repeat(6),
        level: 41,
    };
    let context_label = Label::Custom {
        name: "same-level-z-context".repeat(8),
        level: 41,
    };

    let attempt = |kind: SourceKind, budget: u64| {
        let mut core = test_interpreter();
        let target = core
            .alloc_array_from_values(&[Value::str("seed")])
            .expect("spread target allocation");
        let source = match kind {
            SourceKind::IndexedObject => Value::Object(
                core.alloc_array_from_values(&[
                    Value::Int(7),
                    Value::str("indexed-object-payload"),
                ])
                .expect("indexed spread source"),
            ),
            SourceKind::TypedArray => Value::Object(
                core.alloc_typed_array_from_values(
                    TypedArrayKind::Uint8,
                    &[Value::Int(7), Value::Int(8)],
                )
                .expect("typed-array spread source"),
            ),
            SourceKind::String => Value::str("A\u{1f4a5}"),
        };
        core.write_reg_with_label(0, Value::Object(target), target_label.clone())
            .expect("labeled spread target register");
        core.write_reg_with_label(1, source, iterable_label.clone())
            .expect("labeled spread source register");
        core.active_inline_callback_context_label = Some(context_label.clone());
        core.gc_remembered_set.remove(&target);
        let baseline = core
            .sync_estimated_memory_bytes()
            .expect("initial spread transaction accounting");
        let heap_snapshot = core.heap.iter().cloned().collect::<Vec<_>>();
        let label_snapshot = core.register_labels.clone();
        let remembered_snapshot = core.gc_remembered_set.clone();
        core.config.max_total_memory_bytes = budget;
        let result = core.run_loop(&module);
        (
            core,
            target,
            baseline,
            heap_snapshot,
            label_snapshot,
            remembered_snapshot,
            result,
        )
    };

    for kind in [
        SourceKind::IndexedObject,
        SourceKind::TypedArray,
        SourceKind::String,
    ] {
        let baseline = attempt(kind, u64::MAX).2;
        let mut distance = 1u64;
        let mut upper = loop {
            let budget = baseline.saturating_add(distance);
            if matches!(attempt(kind, budget).6, Err(InterpreterError::Halted)) {
                break budget;
            }
            distance = distance
                .checked_mul(2)
                .expect("spread ceiling search remains bounded");
            assert!(distance <= (1 << 32), "spread ceiling is implausible");
        };
        let mut lower = baseline;
        while lower < upper {
            let midpoint = lower + (upper - lower) / 2;
            if matches!(attempt(kind, midpoint).6, Err(InterpreterError::Halted)) {
                upper = midpoint;
            } else {
                lower = midpoint + 1;
            }
        }
        let exact_ceiling = lower;

        let (
            refused_core,
            target,
            refused_baseline,
            heap_snapshot,
            label_snapshot,
            remembered_snapshot,
            refusal,
        ) = attempt(kind, exact_ceiling - 1);
        assert!(matches!(
            refusal,
            Err(InterpreterError::MemoryBudgetExceeded {
                requested_bytes,
                max_bytes,
                ..
            }) if requested_bytes == exact_ceiling && max_bytes == exact_ceiling - 1
        ));
        assert_eq!(refused_core.ip, 0, "failed {kind:?} spread must retry");
        assert_eq!(
            &*refused_core.heap, &heap_snapshot,
            "failed {kind:?} spread must restore the full heap object, including caches"
        );
        assert_eq!(refused_core.register_labels, label_snapshot);
        assert_eq!(refused_core.gc_remembered_set, remembered_snapshot);
        assert!(!refused_core.gc_is_remembered(target));
        assert_eq!(refused_core.estimated_memory_bytes(), refused_baseline);
        assert_eq!(
            refused_core.estimated_memory_bytes(),
            refused_core.recompute_estimated_memory_bytes()
        );

        let (exact_core, target, _, _, _, _, exact_result) = attempt(kind, exact_ceiling);
        assert_eq!(exact_result, Err(InterpreterError::Halted));
        let expected = match kind {
            SourceKind::IndexedObject => vec![
                Value::str("seed"),
                Value::Int(7),
                Value::str("indexed-object-payload"),
            ],
            SourceKind::TypedArray => {
                vec![Value::str("seed"), Value::Int(7), Value::Int(8)]
            }
            SourceKind::String => {
                vec![Value::str("seed"), Value::str("A"), Value::str("\u{1f4a5}")]
            }
        };
        assert_eq!(exact_core.read_array_like_values(target), expected);
        assert_eq!(
            exact_core
                .get_register_label(0)
                .expect("spread target label"),
            &context_label,
            "full Label ordering must select the same-level context winner"
        );
        assert!(exact_core.gc_is_remembered(target));
        assert_eq!(
            exact_core.estimated_memory_bytes(),
            exact_core.recompute_estimated_memory_bytes()
        );
    }
}

#[test]
fn spread_iterator_refusal_restores_target_but_consumes_iterator_bd_kvq09() {
    let module = test_module_with_functions(
        vec![
            Ir3Instruction::SpreadIntoArray {
                array: 0,
                iterable: 1,
            },
            Ir3Instruction::Halt,
        ],
        Vec::new(),
    );
    let target_label = Label::Custom {
        name: "iterator-target".repeat(4),
        level: 43,
    };
    let iterable_label = Label::Custom {
        name: "iterator-source".repeat(8),
        level: 44,
    };

    let attempt = |budget: u64| {
        let mut core = test_interpreter();
        let target = core
            .alloc_array_from_values(&[Value::str("seed")])
            .expect("iterator-spread target");
        let source = core
            .alloc_array_from_values(&[Value::str("first"), Value::str("second-longer-value")])
            .expect("iterator-spread source");
        let iterator = core
            .init_for_of_iterator(None, Value::Object(source))
            .expect("runtime iterator initialization");
        let Value::Iterator(handle) = iterator else {
            panic!("for-of initialization must return an iterator handle");
        };
        core.write_reg_with_label(0, Value::Object(target), target_label.clone())
            .expect("labeled iterator-spread target");
        core.write_reg_with_label(1, Value::Iterator(handle), iterable_label.clone())
            .expect("labeled iterator-spread source");
        core.gc_remembered_set.remove(&target);
        let baseline = core
            .sync_estimated_memory_bytes()
            .expect("initial iterator-spread accounting");
        let target_snapshot = core.heap[target.0 as usize].clone();
        core.config.max_total_memory_bytes = budget;
        let result = core.run_loop(&module);
        (core, target, handle, baseline, target_snapshot, result)
    };

    let baseline = attempt(u64::MAX).3;
    let mut distance = 1u64;
    let mut upper = loop {
        let budget = baseline.saturating_add(distance);
        if matches!(attempt(budget).5, Err(InterpreterError::Halted)) {
            break budget;
        }
        distance = distance
            .checked_mul(2)
            .expect("iterator-spread ceiling search remains bounded");
        assert!(
            distance <= (1 << 32),
            "iterator-spread ceiling is implausible"
        );
    };
    let mut lower = baseline;
    while lower < upper {
        let midpoint = lower + (upper - lower) / 2;
        if matches!(attempt(midpoint).5, Err(InterpreterError::Halted)) {
            upper = midpoint;
        } else {
            lower = midpoint + 1;
        }
    }
    let exact_ceiling = lower;

    let (refused_core, target, handle, baseline, target_snapshot, refusal) =
        attempt(exact_ceiling - 1);
    assert!(matches!(
        refusal,
        Err(InterpreterError::MemoryBudgetExceeded {
            requested_bytes,
            max_bytes,
            ..
        }) if requested_bytes == exact_ceiling && max_bytes == exact_ceiling - 1
    ));
    assert_eq!(refused_core.heap[target.0 as usize], target_snapshot);
    assert_eq!(
        refused_core
            .get_register_label(0)
            .expect("restored iterator-spread target label"),
        &target_label
    );
    assert!(!refused_core.gc_is_remembered(target));
    let RuntimeIteratorState::ForOf(iterator_state) = &refused_core.iterators[handle as usize]
    else {
        panic!("spread source must remain a for-of iterator");
    };
    assert!(
        iterator_state.next_index > 0,
        "iterator consumption and guest next() effects are intentionally not rolled back"
    );
    assert_eq!(refused_core.estimated_memory_bytes(), baseline);
    assert_eq!(
        refused_core.estimated_memory_bytes(),
        refused_core.recompute_estimated_memory_bytes()
    );

    let (exact_core, target, _, _, _, exact_result) = attempt(exact_ceiling);
    assert_eq!(exact_result, Err(InterpreterError::Halted));
    assert_eq!(
        exact_core.read_array_like_values(target),
        vec![
            Value::str("seed"),
            Value::str("first"),
            Value::str("second-longer-value"),
        ]
    );
    assert_eq!(
        exact_core
            .get_register_label(0)
            .expect("joined target label"),
        &iterable_label
    );
}

#[test]
fn spread_into_itself_uses_finite_pre_transaction_view_bd_kvq09() {
    let module = test_module_with_functions(
        vec![
            Ir3Instruction::SpreadIntoArray {
                array: 0,
                iterable: 1,
            },
            Ir3Instruction::Halt,
        ],
        Vec::new(),
    );
    let mut core = test_interpreter();
    let target = core
        .alloc_array_from_values(&[Value::Int(1), Value::Int(2)])
        .expect("self-spread target");
    core.write_reg(0, Value::Object(target))
        .expect("self-spread target register");
    core.write_reg(1, Value::Object(target))
        .expect("self-spread iterable register");
    core.sync_estimated_memory_bytes()
        .expect("self-spread accounting");

    assert_eq!(core.run_loop(&module), Err(InterpreterError::Halted));
    assert_eq!(
        core.read_array_like_values(target),
        vec![Value::Int(1), Value::Int(2), Value::Int(1), Value::Int(2),]
    );
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[path = "tests_async_runtime_part2.rs"]
mod part2;
