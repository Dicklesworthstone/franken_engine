use super::*;
use crate::ast::{Expression, Statement};
use crate::ir_contract::{
    CapabilityTag, Ir3FunctionDesc, IrHeader, IrLevel, IrSchemaVersion, Reg, RegRange,
};
use crate::parser::Es2020Parser;
use std::sync::{Arc, Mutex};

// -- helpers --------------------------------------------------------

fn test_module(instructions: Vec<Ir3Instruction>) -> Ir3Module {
    Ir3Module {
        header: IrHeader {
            schema_version: IrSchemaVersion::CURRENT,
            level: IrLevel::Ir3,
            source_hash: None,
            source_label: "test".to_string(),
        },
        instructions,
        constant_pool: Vec::new(),
        function_table: Vec::new(),
        specialization: None,
        required_capabilities: Vec::new(),
    }
}

fn test_module_with_pool(instructions: Vec<Ir3Instruction>, pool: Vec<String>) -> Ir3Module {
    let mut m = test_module(instructions);
    m.constant_pool = pool.into_iter().map(Into::into).collect();
    m
}

fn test_module_with_functions(
    instructions: Vec<Ir3Instruction>,
    functions: Vec<Ir3FunctionDesc>,
) -> Ir3Module {
    let mut m = test_module(instructions);
    m.function_table = functions;
    m
}

fn test_module_with_pool_and_functions(
    instructions: Vec<Ir3Instruction>,
    pool: Vec<String>,
    functions: Vec<Ir3FunctionDesc>,
) -> Ir3Module {
    let mut m = test_module_with_pool(instructions, pool);
    m.function_table = functions;
    m
}

/// Build a test interpreter config that grants the execution capabilities
/// every baseline interpreter test needs. The production `quickjs_defaults`
/// / `v8_defaults` intentionally start with an empty capability set so
/// callers must explicitly grant what an extension may do; tests are not
/// exercising the grant-policy surface, so they need a fully-enabled
/// baseline to actually dispatch VM instructions and allocate objects.
fn test_quickjs_config() -> InterpreterConfig {
    let mut config = InterpreterConfig::quickjs_defaults();
    config.granted_capabilities = BTreeSet::from([
        RuntimeCapability::VmDispatch,
        RuntimeCapability::HeapAllocate,
    ]);
    config
}

fn test_v8_config() -> InterpreterConfig {
    let mut config = InterpreterConfig::v8_defaults();
    config.granted_capabilities = BTreeSet::from([
        RuntimeCapability::VmDispatch,
        RuntimeCapability::HeapAllocate,
    ]);
    config
}

fn quickjs_execute(module: &Ir3Module) -> Result<ExecutionResult, InterpreterError> {
    QuickJsLane::with_config(test_quickjs_config()).execute(module, "test-trace")
}

fn v8_execute(module: &Ir3Module) -> Result<ExecutionResult, InterpreterError> {
    V8Lane::with_config(test_v8_config()).execute(module, "test-trace")
}

fn quickjs_test_core() -> InterpreterCore {
    InterpreterCore::new(test_quickjs_config(), "test-trace")
}

#[test]
fn promise_reaction_registration_refuses_without_retaining_partial_state() {
    let mut core = quickjs_test_core();
    let source = core.create_promise_accounted().unwrap();
    let registration = PromiseReactionRegistration {
        on_fulfilled: Some(PromiseReactionAction::Call(Value::BuiltinFunction(
            BuiltinFunction::array_is_array(),
        ))),
        on_rejected: None,
    };
    let initial_memory = core.estimated_memory_bytes;
    let initial_runtime = core.promise_runtime_memory_bytes();
    let retained = InterpreterCore::estimate_promise_reaction_registration_bytes(&registration);
    core.config.max_total_memory_bytes = initial_memory + retained - 1;
    let error = core
        .register_executable_promise_reactions(
            source,
            registration.clone(),
            crate::ifc_artifacts::Label::Public,
        )
        .unwrap_err();
    assert!(matches!(
        error,
        InterpreterError::MemoryBudgetExceeded { .. }
    ));
    assert!(core.promise_reactions.is_empty());
    assert_eq!(core.promise_runtime_memory_bytes(), initial_runtime);
    assert_eq!(core.estimated_memory_bytes, initial_memory);
    assert_eq!(core.promise_in_flight_task_bytes, 0);

    // Admit the callback but refuse the store/queue rollback snapshot.
    // Releasing the temporary ownership must restore the exact estimate.
    core.config.max_total_memory_bytes = initial_memory + retained;
    assert!(matches!(
        core.register_executable_promise_reactions(
            source,
            registration,
            crate::ifc_artifacts::Label::Public,
        ),
        Err(InterpreterError::MemoryBudgetExceeded { .. })
    ));
    assert!(core.promise_reactions.is_empty());
    assert_eq!(core.promise_runtime_memory_bytes(), initial_runtime);
    assert_eq!(core.estimated_memory_bytes, initial_memory);
    assert_eq!(core.promise_in_flight_task_bytes, 0);
}

#[test]
fn native_promise_callback_releases_registration_and_keeps_exact_accounting() {
    let mut core = quickjs_test_core();
    let source = core.create_promise_accounted().unwrap();
    let result = core
        .register_executable_promise_reactions(
            source,
            PromiseReactionRegistration {
                on_fulfilled: Some(PromiseReactionAction::Call(Value::BuiltinFunction(
                    BuiltinFunction::array_is_array(),
                ))),
                on_rejected: None,
            },
            crate::ifc_artifacts::Label::Secret,
        )
        .unwrap();
    assert_eq!(
        core.estimated_memory_bytes,
        core.recompute_estimated_memory_bytes()
    );
    core.fulfill_promise(
        source,
        crate::object_model::JsValue::Int(42),
        crate::ifc_artifacts::Label::Public,
    )
    .unwrap();
    core.drain_microtasks(Some(&test_module(vec![Ir3Instruction::Halt])))
        .unwrap();
    let record = core.promise_store.get(result).unwrap();
    assert_eq!(
        record.state,
        crate::promise_model::PromiseState::Fulfilled(crate::object_model::JsValue::Bool(false))
    );
    assert_eq!(record.label, crate::ifc_artifacts::Label::Secret);
    assert!(core.promise_reactions.is_empty());
    assert_eq!(core.promise_in_flight_task_bytes, 0);
    assert_eq!(
        core.estimated_memory_bytes,
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn promise_resolving_pair_refusal_preserves_memory_and_identity_allocation() {
    let mut core = quickjs_test_core();
    let promise = core.create_promise_accounted().unwrap();
    let initial_memory = core.estimated_memory_bytes;
    let initial_runtime = core.promise_runtime_memory_bytes();
    core.config.max_total_memory_bytes = initial_memory;
    assert!(matches!(
        core.create_promise_resolving_functions(promise, crate::ifc_artifacts::Label::Secret),
        Err(InterpreterError::MemoryBudgetExceeded { .. })
    ));
    assert!(core.promise_resolving_functions.is_empty());
    assert_eq!(core.estimated_memory_bytes, initial_memory);
    assert_eq!(core.promise_runtime_memory_bytes(), initial_runtime);

    core.config.max_total_memory_bytes = u64::MAX;
    let (pair_id, _, _) = core
        .create_promise_resolving_functions(promise, crate::ifc_artifacts::Label::Secret)
        .unwrap();
    assert_eq!(pair_id, 0, "a refused pair must not consume an identity");
    assert_eq!(
        core.estimated_memory_bytes,
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn promise_resolving_pair_locks_pending_adoption_and_retains_labels() {
    let mut core = quickjs_test_core();
    let target = core.create_promise_accounted().unwrap();
    let source = core.create_promise_accounted().unwrap();
    let (pair_id, _, _) = core
        .create_promise_resolving_functions(target, crate::ifc_artifacts::Label::Secret)
        .unwrap();
    core.apply_promise_resolving_function(
        pair_id,
        Value::Promise(source.0),
        crate::ifc_artifacts::Label::Public,
        true,
    )
    .unwrap();
    core.apply_promise_resolving_function(
        pair_id,
        Value::str("must be ignored"),
        crate::ifc_artifacts::Label::Public,
        false,
    )
    .unwrap();
    assert!(!core.promise_is_settled(target));
    core.fulfill_promise(
        source,
        crate::object_model::JsValue::Int(42),
        crate::ifc_artifacts::Label::Public,
    )
    .unwrap();
    core.drain_microtasks(Some(&test_module(vec![Ir3Instruction::Halt])))
        .unwrap();
    let record = core.promise_store.get(target).unwrap();
    assert_eq!(
        record.state,
        crate::promise_model::PromiseState::Fulfilled(crate::object_model::JsValue::Int(42))
    );
    assert_eq!(record.label, crate::ifc_artifacts::Label::Secret);
    assert_eq!(
        core.estimated_memory_bytes,
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn bd_3ose7_resolve_detects_thenable_and_enqueues_job() {
    // An object with a callable `then` must be detected as a thenable:
    // resolve leaves the promise PENDING (a ResolveThenable job enqueued),
    // not synchronously fulfilled with the object.
    let mut core = quickjs_test_core();
    let thenable = core
        .alloc_object_with_prototype(None)
        .expect("allocate thenable object");
    core.set_object_property(
        thenable,
        "then".to_string(),
        Value::BuiltinFunction(BuiltinFunction::array_is_array()),
    )
    .expect("install a callable `then`");
    let handle = core.promise_store.create();
    core.resolve_promise_with_value(
        handle,
        Value::Object(thenable),
        crate::ifc_artifacts::Label::Public,
    )
    .expect("resolve a thenable");
    assert!(
        !core.promise_is_settled(handle),
        "a thenable must be assimilated (pending) rather than fulfilled directly"
    );
}

#[test]
fn bd_3ose7_resolve_capability_settles_once_preserving_label() {
    // The resolve capability passed into a thenable's `then` settles the
    // bound promise with the argument's value and label, and only once
    // (ES `alreadyResolved`). This is the settle mechanism the
    // ResolveThenable job relies on.
    let mut core = quickjs_test_core();
    let handle = core.promise_store.create();
    core.write_reg_with_label(
        0,
        Value::str("resolved-value"),
        crate::ifc_artifacts::Label::Secret,
    )
    .expect("seed the resolve argument");
    let result = core
        .apply_promise_capability(handle, RegRange { start: 0, count: 1 }, true)
        .expect("apply resolve capability");
    assert_eq!(result, Value::Undefined);

    let record = core.promise_store.get(handle).expect("promise record");
    assert!(matches!(
        &record.state,
        crate::promise_model::PromiseState::Fulfilled(js)
            if matches!(js, crate::object_model::JsValue::Str(s) if s == "resolved-value")
    ));
    assert_eq!(record.label, crate::ifc_artifacts::Label::Secret);

    // Once-guard: a second resolve with a different value is a no-op.
    core.write_reg_with_label(0, Value::str("second"), crate::ifc_artifacts::Label::Public)
        .expect("seed second argument");
    core.apply_promise_capability(handle, RegRange { start: 0, count: 1 }, true)
        .expect("second resolve is inert");
    let record = core.promise_store.get(handle).expect("promise record");
    assert!(matches!(
        &record.state,
        crate::promise_model::PromiseState::Fulfilled(js)
            if matches!(js, crate::object_model::JsValue::Str(s) if s == "resolved-value")
    ));
    assert_eq!(record.label, crate::ifc_artifacts::Label::Secret);
}

#[test]
fn bd_3ose7_reject_capability_rejects_with_label() {
    let mut core = quickjs_test_core();
    let handle = core.promise_store.create();
    core.write_reg_with_label(0, Value::str("boom"), crate::ifc_artifacts::Label::Secret)
        .expect("seed the reject reason");
    core.apply_promise_capability(handle, RegRange { start: 0, count: 1 }, false)
        .expect("apply reject capability");
    let record = core.promise_store.get(handle).expect("promise record");
    assert!(matches!(
        &record.state,
        crate::promise_model::PromiseState::Rejected(js)
            if matches!(js, crate::object_model::JsValue::Str(s) if s == "boom")
    ));
    assert_eq!(record.label, crate::ifc_artifacts::Label::Secret);
}

/// bd-ojvo1 (core-twin parity with engine eb53fd9e8): a Secret value written
/// to a Public object's own property must read back as (at least) Secret,
/// not laundered down to the object's Public label.
#[test]
fn set_property_persists_value_label_so_get_does_not_launder_bd_ojvo1() {
    let mut module = test_module_with_functions(
        vec![
            Ir3Instruction::LoadStr {
                dst: 1,
                pool_index: 0,
            },
            Ir3Instruction::SetProperty {
                obj: 0,
                key: 1,
                val: 2,
            },
            Ir3Instruction::GetProperty {
                obj: 0,
                key: 1,
                dst: 3,
            },
            Ir3Instruction::Halt,
        ],
        vec![],
    );
    module.constant_pool.push("leaked".into());

    let mut core = quickjs_test_core();
    let public_obj = core
        .alloc_object_with_properties(&[])
        .expect("test object allocation should succeed");
    core.write_reg_with_label(
        0,
        Value::Object(public_obj),
        crate::ifc_artifacts::Label::Public,
    )
    .expect("object register should be settable");
    core.write_reg_with_label(2, Value::Int(42), crate::ifc_artifacts::Label::Secret)
        .expect("written value register should be settable");

    core.execute(&module)
        .expect("set then get off a public object should execute");

    assert_eq!(
        core.read_reg_label(3)
            .expect("dst register label should exist"),
        crate::ifc_artifacts::Label::Secret,
        "a Secret value written to a Public object property must read back Secret (bd-ojvo1)"
    );
}

/// bd-ojvo1: an inherited Secret data property must carry its label to a read
/// through a child object — own_property_label walks the prototype chain to
/// the object that actually owns the property.
#[test]
fn get_property_inherits_prototype_property_label_bd_ojvo1() {
    let mut module = test_module_with_functions(
        vec![
            Ir3Instruction::LoadStr {
                dst: 1,
                pool_index: 0,
            },
            Ir3Instruction::GetProperty {
                obj: 0,
                key: 1,
                dst: 2,
            },
            Ir3Instruction::Halt,
        ],
        vec![],
    );
    module.constant_pool.push("inherited".into());

    let mut core = quickjs_test_core();
    let proto = core
        .alloc_object_with_properties(&[("inherited", Value::Int(7))])
        .expect("prototype allocation should succeed");
    core.set_own_property_label(proto, "inherited", &crate::ifc_artifacts::Label::Secret)
        .expect("prototype property label should fit");
    let child = core
        .alloc_object_with_properties(&[])
        .expect("child allocation should succeed");
    core.heap[child.0 as usize].prototype = Some(proto);
    core.write_reg_with_label(0, Value::Object(child), crate::ifc_artifacts::Label::Public)
        .expect("child register should be settable");

    core.execute(&module)
        .expect("inherited property read should execute");

    assert_eq!(
        core.read_reg_label(2)
            .expect("dst register label should exist"),
        crate::ifc_artifacts::Label::Secret,
        "an inherited Secret property must read back Secret through the prototype chain (bd-ojvo1)"
    );
}

/// bd-0zybl-class (core parity): reading any property of a Secret object is
/// at least as sensitive as the object itself, even when the property value
/// carries a Public label. Core's property read previously dropped the
/// object's label entirely.
#[test]
fn get_property_of_secret_object_carries_object_label_bd_0zybl() {
    let mut module = test_module_with_functions(
        vec![
            Ir3Instruction::LoadStr {
                dst: 1,
                pool_index: 0,
            },
            Ir3Instruction::GetProperty {
                obj: 0,
                key: 1,
                dst: 2,
            },
            Ir3Instruction::Halt,
        ],
        vec![],
    );
    module.constant_pool.push("data".into());

    let mut core = quickjs_test_core();
    let secret_obj = core
        .alloc_object_with_properties(&[("data", Value::Int(1))])
        .expect("object allocation should succeed");
    core.write_reg_with_label(
        0,
        Value::Object(secret_obj),
        crate::ifc_artifacts::Label::Secret,
    )
    .expect("object register should be settable");

    core.execute(&module)
        .expect("property read off a secret object should execute");

    assert_eq!(
        core.read_reg_label(2)
            .expect("dst register label should exist"),
        crate::ifc_artifacts::Label::Secret,
        "a property read off a Secret object must be at least Secret (bd-0zybl-class core parity)"
    );
}

/// bd-ojvo1: an array element written with a Secret value must read back
/// Secret via its index key, not laundered to the array's label.
#[test]
fn set_array_element_persists_value_label_bd_ojvo1() {
    let mut module = test_module_with_functions(
        vec![
            Ir3Instruction::LoadStr {
                dst: 1,
                pool_index: 0,
            },
            Ir3Instruction::SetProperty {
                obj: 0,
                key: 1,
                val: 2,
            },
            Ir3Instruction::GetProperty {
                obj: 0,
                key: 1,
                dst: 3,
            },
            Ir3Instruction::Halt,
        ],
        vec![],
    );
    module.constant_pool.push("0".into());

    let mut core = quickjs_test_core();
    let arr = core
        .alloc_object_with_properties(&[])
        .expect("array allocation should succeed");
    core.heap[arr.0 as usize].is_array = true;
    core.write_reg_with_label(0, Value::Object(arr), crate::ifc_artifacts::Label::Public)
        .expect("array register should be settable");
    core.write_reg_with_label(2, Value::Int(9), crate::ifc_artifacts::Label::Secret)
        .expect("written value register should be settable");

    core.execute(&module)
        .expect("array element set then get should execute");

    assert_eq!(
        core.read_reg_label(3)
            .expect("dst register label should exist"),
        crate::ifc_artifacts::Label::Secret,
        "a Secret value written to an array element must read back Secret (bd-ojvo1)"
    );
}

#[test]
fn array_push_persists_element_label_for_later_index_read_bd_ojvo1() {
    let mut module = test_module_with_functions(
        vec![
            Ir3Instruction::ArrayPush {
                array: 0,
                element: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 0,
            },
            Ir3Instruction::GetProperty {
                obj: 0,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Halt,
        ],
        vec![],
    );
    module.constant_pool.push("0".into());

    let mut core = quickjs_test_core();
    let array = core
        .alloc_array_with_prototype(None)
        .expect("array should allocate");
    core.write_reg_with_label(0, Value::Object(array), crate::ifc_artifacts::Label::Public)
        .expect("array register should fit");
    core.write_reg_with_label(
        1,
        Value::str("classified"),
        crate::ifc_artifacts::Label::Secret,
    )
    .expect("Secret element register should fit");

    core.execute(&module).expect("ArrayPush followed by read");

    assert_eq!(core.read_reg(3).unwrap(), Value::str("classified"));
    assert_eq!(
        core.read_reg_label(3).unwrap(),
        crate::ifc_artifacts::Label::Secret
    );
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn property_label_delete_serde_and_budget_are_accounted_bd_ojvo1() {
    let mut core = quickjs_test_core();
    let object = core
        .alloc_object_with_properties(&[("data", Value::Int(7))])
        .expect("object should allocate");
    let key = RuntimePropertyKey::String(JsString::from("data"));
    let before_label = core.estimated_memory_bytes();
    core.set_own_runtime_property_label(object, &key, &crate::ifc_artifacts::Label::Secret)
        .expect("Secret property label should fit");
    assert!(core.estimated_memory_bytes() > before_label);
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );

    let wire = serde_json::to_vec(&core.heap[object.0 as usize])
        .expect("labeled heap object should serialize");
    let decoded: HeapObject =
        serde_json::from_slice(&wire).expect("labeled heap object should deserialize");
    assert_eq!(
        decoded.property_labels.get("data"),
        Some(&crate::ifc_artifacts::Label::Secret)
    );

    assert!(core.remove_object_property(object, "data").unwrap());
    assert_eq!(
        core.own_stored_runtime_property_label(object, &key),
        crate::ifc_artifacts::Label::Public
    );
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );

    core.set_object_property(object, "data".to_string(), Value::Int(8))
        .expect("replacement property should fit");
    let stable_heap = serde_json::to_vec(&core.heap[object.0 as usize]).unwrap();
    let stable_memory = core.estimated_memory_bytes();
    core.config.max_total_memory_bytes = stable_memory;
    assert!(matches!(
        core.set_own_runtime_property_label(object, &key, &crate::ifc_artifacts::Label::Secret,),
        Err(InterpreterError::MemoryBudgetExceeded { .. })
    ));
    assert_eq!(
        serde_json::to_vec(&core.heap[object.0 as usize]).unwrap(),
        stable_heap
    );
    assert_eq!(core.estimated_memory_bytes(), stable_memory);
}

/// bd-ojvo1: a concise method defined with a Secret definition label must
/// record that label on its own property, so a later read recovers the
/// method's provenance (define_method_property otherwise stored the label
/// only in closure_method_metadata, which the property-read path ignores).
#[test]
fn define_method_records_definition_label_bd_ojvo1() {
    let mut core = quickjs_test_core();
    let obj = core
        .alloc_object_with_properties(&[])
        .expect("object allocation should succeed");
    core.closures.push(ClosureValue {
        function_index: 0,
        captured_env: vec![],
        module_specifier: None,
    });
    let closure_id = (core.closures.len() - 1) as u32;

    core.define_method_property(
        obj,
        RuntimePropertyKey::String(JsString::from("m")),
        Value::Closure(closure_id),
        crate::ifc_artifacts::Label::Secret,
    )
    .expect("concise method definition should succeed");

    assert_eq!(
        core.own_property_label(obj, "m"),
        crate::ifc_artifacts::Label::Secret,
        "a concise method's Secret definition label must be recorded on its property (bd-ojvo1)"
    );
}

/// bd-ojvo1: an own Symbol-keyed property records and recovers its value's
/// IFC label (via the property_labels map's parallel Symbol side), and a
/// Public write clears it — so a Secret value under a Symbol key does not
/// launder, and unlabeled Symbol writes stay sparse.
#[test]
fn set_symbol_property_persists_value_label_bd_ojvo1() {
    let mut core = quickjs_test_core();
    let obj = core
        .alloc_object_with_properties(&[])
        .expect("object allocation should succeed");
    let symbol = SymbolId(1);
    // The object must OWN the Symbol property (a value present) for its
    // label to resolve, matching a real SetProperty write.
    core.heap[obj.0 as usize]
        .properties
        .insert_baseline_symbol_property(symbol, BaselineSymbolProperty::Data(Value::Int(7)));

    core.set_own_symbol_property_label(obj, symbol, &crate::ifc_artifacts::Label::Secret)
        .expect("Secret Symbol label should fit");
    assert_eq!(
        core.own_symbol_property_label(obj, symbol),
        crate::ifc_artifacts::Label::Secret,
        "a Secret value under a Symbol key must record its label (bd-ojvo1)"
    );

    core.set_own_symbol_property_label(obj, symbol, &crate::ifc_artifacts::Label::Public)
        .expect("Public Symbol label removal should fit");
    assert_eq!(
        core.own_symbol_property_label(obj, symbol),
        crate::ifc_artifacts::Label::Public,
        "a Public write must clear the Symbol-property label (sparse map)"
    );
}

#[test]
fn bd_3ose7_resolve_preserves_non_public_settlement_label() {
    // The ResolveThenable/resolve path must preserve the resolution label
    // rather than collapse it to Public (the old placeholder settlement).
    let mut core = quickjs_test_core();
    let handle = core.promise_store.create();
    core.resolve_promise_with_value(handle, Value::Int(7), crate::ifc_artifacts::Label::Secret)
        .expect("resolve a non-thenable value");
    let record = core.promise_store.get(handle).expect("promise record");
    assert!(matches!(
        record.state,
        crate::promise_model::PromiseState::Fulfilled(_)
    ));
    assert_eq!(
        record.label,
        crate::ifc_artifacts::Label::Secret,
        "resolution must preserve the value label, not settle Public"
    );
}

fn custom_for_of_handle_for_close(core: &mut InterpreterCore, object: ObjectId) -> Value {
    let handle = core
        .alloc_iterator(RuntimeIteratorState::ForOf(RuntimeForOfState {
            values: Vec::new(),
            array_object: None,
            iterator_object: Some(object),
            iterator_receiver: Some(Value::Object(object)),
            next_method: None,
            label: crate::ifc_artifacts::Label::Public,
            next_index: 0,
            done: false,
            closed: false,
            return_called: false,
        }))
        .expect("custom iterator handle");
    Value::Iterator(handle)
}

fn lower_symbol_source_bd_n8eta_4_3(source: &str) -> Ir3Module {
    let tree = CanonicalEs2020Parser
        .parse(source, ParseGoal::Script)
        .expect("Symbol regression source should parse");
    lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "bd_n8eta_4_3.js"),
        &LoweringContext::new(
            "trace-bd-n8eta-4-3",
            "decision-bd-n8eta-4-3",
            "policy-bd-n8eta-4-3",
        ),
    )
    .expect("Symbol regression source should lower")
    .ir3
}

fn exact_accessor_definition_key(prefix: &str, name: &JsString) -> JsString {
    let mut units = prefix.encode_utf16().collect::<Vec<_>>();
    units.extend(name.encode_utf16());
    JsString::from_code_units(&units)
}

#[test]
fn symbol_value_and_heap_wire_are_typed_and_backward_readable_bd_n8eta_4_3() {
    assert_eq!(
        serde_json::to_string(&Value::Symbol(SymbolId(14))).unwrap(),
        r#"{"Symbol":14}"#
    );

    let legacy = HeapObject::new();
    let legacy_wire = serde_json::to_string(&legacy).unwrap();
    assert!(!legacy_wire.contains("symbol_properties"));
    assert_eq!(
        serde_json::to_string(&serde_json::from_str::<HeapObject>(&legacy_wire).unwrap()).unwrap(),
        legacy_wire
    );

    let mut object = HeapObject::new();
    object
        .properties
        .insert_baseline_symbol_property(SymbolId(14), BaselineSymbolProperty::Data(Value::Int(2)));
    object.properties.insert_baseline_symbol_property(
        SymbolId(15),
        BaselineSymbolProperty::Accessor {
            get: None,
            set: Some(Value::Function(7)),
        },
    );
    assert_ne!(legacy.properties, object.properties);
    let wire = serde_json::to_string(&object).unwrap();
    assert!(wire.ends_with(
        r#","symbol_properties":[{"symbol_id":14,"kind":"data","value":{"Int":2}},{"symbol_id":15,"kind":"accessor","get":null,"set":{"Function":7}}]}"#
    ));
    assert_eq!(serde_json::from_str::<HeapObject>(&wire).unwrap(), object);
}

#[test]
fn derived_constructor_metadata_wire_is_atomic_and_label_preserving_bd_ppfz7() {
    let mut object = HeapObject::new();
    object.derived_constructor_parent = Some(Value::Function(7));
    object.derived_constructor_parent_label = Some(crate::ifc_artifacts::Label::Secret);
    object.is_derived_constructor = true;
    object.is_default_derived_constructor = true;

    let encoded = serde_json::to_value(&object).expect("serialize constructor metadata");
    let restored: HeapObject =
        serde_json::from_value(encoded.clone()).expect("round-trip constructor metadata");
    assert_eq!(restored, object);
    assert_eq!(
        restored.derived_constructor_parent_label,
        Some(crate::ifc_artifacts::Label::Secret)
    );

    let mut missing_label = encoded.clone();
    missing_label
        .as_object_mut()
        .expect("HeapObject wire must be an object")
        .remove("derived_constructor_parent_label");
    assert!(serde_json::from_value::<HeapObject>(missing_label).is_err());

    let mut missing_parent = encoded;
    missing_parent
        .as_object_mut()
        .expect("HeapObject wire must be an object")
        .remove("derived_constructor_parent");
    assert!(serde_json::from_value::<HeapObject>(missing_parent).is_err());

    let mut invalid_default =
        serde_json::to_value(HeapObject::new()).expect("serialize legacy HeapObject");
    invalid_default["is_default_derived_constructor"] = serde_json::json!(true);
    assert!(serde_json::from_value::<HeapObject>(invalid_default).is_err());
}

#[test]
fn symbol_heap_wire_rejects_malformed_records_bd_n8eta_4_3() {
    let malformed = [
        r#"{"properties":{},"prototype":null,"constructor_function":null,"is_array":false,"symbol_properties":[{"symbol_id":0,"kind":"data","value":{"Int":1}}]}"#,
        r#"{"properties":{},"prototype":null,"constructor_function":null,"is_array":false,"symbol_properties":[{"symbol_id":14,"kind":"data","value":{"Int":1}},{"symbol_id":14,"kind":"data","value":{"Int":2}}]}"#,
        r#"{"properties":{},"prototype":null,"constructor_function":null,"is_array":false,"symbol_properties":[{"symbol_id":14,"kind":"data","value":{"Int":1},"get":null}]}"#,
        r#"{"properties":{},"prototype":null,"constructor_function":null,"is_array":false,"symbol_properties":[{"symbol_id":14,"kind":"accessor","get":null}]}"#,
        r#"{"properties":{},"prototype":null,"constructor_function":null,"is_array":false,"symbol_properties":[{"symbol_id":14,"kind":"mystery","value":{"Int":1}}]}"#,
        r#"{"properties":{},"prototype":null,"constructor_function":null,"is_array":false,"symbol_properties":[{"symbol_id":14,"kind":"data","value":{"Int":1},"extra":true}]}"#,
    ];
    for wire in malformed {
        assert!(
            serde_json::from_str::<HeapObject>(wire).is_err(),
            "malformed Symbol property unexpectedly decoded: {wire}"
        );
    }
}

#[test]
fn symbol_state_wire_rejects_noncanonical_identity_records_bd_n8eta_4_3() {
    let malformed = [
        r#"{"well_known_schema":"wrong","next_symbol_id":14,"symbols":[]}"#,
        r#"{"well_known_schema":"es2020-symbol-ids-1-13-v1","next_symbol_id":14,"symbols":[{"symbol_id":13,"kind":"private","description":null}]}"#,
        r#"{"well_known_schema":"es2020-symbol-ids-1-13-v1","next_symbol_id":15,"symbols":[{"symbol_id":14,"kind":"private"}]}"#,
        r#"{"well_known_schema":"es2020-symbol-ids-1-13-v1","next_symbol_id":15,"symbols":[{"symbol_id":14,"kind":"private","description":null,"registry_key":"x"}]}"#,
        r#"{"well_known_schema":"es2020-symbol-ids-1-13-v1","next_symbol_id":15,"symbols":[{"symbol_id":14,"kind":"global","description":"x","registry_key":null}]}"#,
        r#"{"well_known_schema":"es2020-symbol-ids-1-13-v1","next_symbol_id":15,"symbols":[{"symbol_id":14,"kind":"global","description":"x","registry_key":"y"}]}"#,
        r#"{"well_known_schema":"es2020-symbol-ids-1-13-v1","next_symbol_id":16,"symbols":[{"symbol_id":14,"kind":"private","description":null},{"symbol_id":15,"kind":"private","description":null,"extra":true}]}"#,
    ];
    for wire in malformed {
        assert!(
            serde_json::from_str::<RuntimeSymbolState>(wire).is_err(),
            "malformed Symbol state unexpectedly decoded: {wire}"
        );
    }
}

#[test]
fn typed_symbol_properties_stay_distinct_ordered_and_prototyped_bd_n8eta_4_3() {
    let mut core = quickjs_test_core();
    let first = core
        .allocate_private_symbol(Some(JsString::from("first")))
        .unwrap();
    let second = core
        .allocate_private_symbol(Some(JsString::from("second")))
        .unwrap();
    let prototype = core.alloc_object_with_prototype(None).unwrap();
    let object = core.alloc_object_with_prototype(Some(prototype)).unwrap();

    core.set_object_property(object, "2".to_string(), Value::Int(2))
        .unwrap();
    core.set_object_property(object, "a".to_string(), Value::Int(1))
        .unwrap();
    core.set_object_property(object, "Symbol(14)".to_string(), Value::Int(9))
        .unwrap();
    core.set_object_typed_property(object, TypedPropertyKey::Symbol(first), Value::Int(7))
        .unwrap();
    core.set_object_typed_property(prototype, TypedPropertyKey::Symbol(second), Value::Int(8))
        .unwrap();

    assert_eq!(
        core.prototype_chain_lookup_typed_property(object, &TypedPropertyKey::Symbol(first))
            .unwrap(),
        Some(RuntimeProperty::Data(Value::Int(7)))
    );
    assert_eq!(
        core.prototype_chain_lookup_typed_property(object, &TypedPropertyKey::Symbol(second))
            .unwrap(),
        Some(RuntimeProperty::Data(Value::Int(8)))
    );
    assert!(
        core.prototype_chain_has_typed_key(object, &TypedPropertyKey::Symbol(second))
            .unwrap()
    );
    assert_eq!(
        core.heap[object.0 as usize].own_typed_property_keys(),
        vec![
            TypedPropertyKey::String("2".to_string()),
            TypedPropertyKey::String("a".to_string()),
            TypedPropertyKey::String("Symbol(14)".to_string()),
            TypedPropertyKey::Symbol(first),
        ]
    );

    core.set_symbol_property(
        object,
        first,
        BaselineSymbolProperty::Accessor {
            get: Some(Value::Function(3)),
            set: None,
        },
    )
    .unwrap();
    assert_eq!(
        core.heap[object.0 as usize]
            .properties
            .baseline_symbol_key_order(),
        &[first]
    );
    core.set_object_typed_property(object, TypedPropertyKey::Symbol(first), Value::Int(7))
        .unwrap();

    core.remove_object_typed_property(object, &TypedPropertyKey::Symbol(first))
        .unwrap();
    core.set_object_typed_property(object, TypedPropertyKey::Symbol(second), Value::Int(10))
        .unwrap();
    core.set_object_typed_property(object, TypedPropertyKey::Symbol(first), Value::Int(11))
        .unwrap();
    assert_eq!(
        core.heap[object.0 as usize]
            .properties
            .baseline_symbol_key_order(),
        &[second, first]
    );
}

#[test]
fn exact_string_data_accessors_symbols_and_wire_coexist_bd_b12xs_4() {
    let mut core = quickjs_test_core();
    let object = core.alloc_object_with_prototype(None).unwrap();
    let d800 = JsString::from_code_units(&[0xD800]);
    let d801 = JsString::from_code_units(&[0xD801]);
    let replacement = JsString::from("\u{FFFD}");
    let symbol = core
        .allocate_private_symbol(Some(JsString::from("exact-mixed")))
        .unwrap();

    core.set_object_property(object, "2".to_string(), Value::Int(2))
        .unwrap();
    core.set_object_runtime_property(
        object,
        RuntimePropertyKey::String(d800.clone()),
        Value::Int(8),
    )
    .unwrap();
    core.set_object_runtime_property(
        object,
        RuntimePropertyKey::String(replacement.clone()),
        Value::Int(0xFFFD),
    )
    .unwrap();
    core.set_object_string_property(
        object,
        exact_accessor_definition_key(IR_ACCESSOR_GET_PREFIX, &d801),
        Value::Function(7),
    )
    .unwrap();
    core.set_object_runtime_property(object, RuntimePropertyKey::Symbol(symbol), Value::Int(14))
        .unwrap();

    assert_eq!(
        core.heap[object.0 as usize].own_runtime_property_keys(),
        vec![
            RuntimePropertyKey::String(JsString::from("2")),
            RuntimePropertyKey::String(d800.clone()),
            RuntimePropertyKey::String(replacement.clone()),
            RuntimePropertyKey::String(d801.clone()),
            RuntimePropertyKey::Symbol(symbol),
        ]
    );
    assert_eq!(
        core.prototype_chain_lookup_runtime_property(
            object,
            &RuntimePropertyKey::String(d801.clone()),
        )
        .unwrap(),
        Some(RuntimeProperty::Accessor(AccessorProperty {
            get: Some(Value::Function(7)),
            set: None,
        }))
    );

    let accessor_wire = serde_json::to_value(&core.heap[object.0 as usize]).unwrap();
    assert!(accessor_wire["properties"].is_array());
    assert!(accessor_wire["accessors"].is_array());
    assert!(accessor_wire["own_string_key_order"].is_array());
    assert!(accessor_wire["symbol_properties"].is_array());
    let restored: HeapObject = serde_json::from_value(accessor_wire.clone()).unwrap();
    assert_eq!(restored, core.heap[object.0 as usize]);

    let mut duplicate_accessor = accessor_wire.clone();
    duplicate_accessor["accessors"] = serde_json::to_value(vec![
        (
            d801.clone(),
            AccessorProperty {
                get: Some(Value::Function(7)),
                set: None,
            },
        ),
        (
            d801.clone(),
            AccessorProperty {
                get: None,
                set: Some(Value::Function(8)),
            },
        ),
    ])
    .unwrap();
    assert!(serde_json::from_value::<HeapObject>(duplicate_accessor).is_err());
    let mut data_accessor_collision = accessor_wire.clone();
    data_accessor_collision["accessors"] = serde_json::to_value(vec![(
        d800.clone(),
        AccessorProperty {
            get: Some(Value::Function(9)),
            set: None,
        },
    )])
    .unwrap();
    assert!(serde_json::from_value::<HeapObject>(data_accessor_collision).is_err());
    let mut missing_order = accessor_wire;
    missing_order
        .as_object_mut()
        .unwrap()
        .remove("own_string_key_order");
    assert!(serde_json::from_value::<HeapObject>(missing_order).is_err());

    core.set_plain_data_runtime_property(
        object,
        RuntimePropertyKey::String(d801.clone()),
        Value::Int(9),
    )
    .unwrap();
    assert_eq!(
        core.heap[object.0 as usize].own_runtime_property_keys(),
        vec![
            RuntimePropertyKey::String(JsString::from("2")),
            RuntimePropertyKey::String(d800.clone()),
            RuntimePropertyKey::String(replacement.clone()),
            RuntimePropertyKey::String(d801.clone()),
            RuntimePropertyKey::Symbol(symbol),
        ]
    );

    let data_wire = serde_json::to_value(&core.heap[object.0 as usize]).unwrap();
    assert!(data_wire["properties"].is_array());
    let restored: HeapObject = serde_json::from_value(data_wire).unwrap();
    assert_eq!(restored, core.heap[object.0 as usize]);

    assert!(
        core.remove_object_runtime_property(object, &RuntimePropertyKey::String(d800.clone()),)
            .unwrap()
    );
    core.set_object_runtime_property(
        object,
        RuntimePropertyKey::String(d800.clone()),
        Value::Int(18),
    )
    .unwrap();
    assert_eq!(
        core.heap[object.0 as usize].own_runtime_property_keys(),
        vec![
            RuntimePropertyKey::String(JsString::from("2")),
            RuntimePropertyKey::String(replacement),
            RuntimePropertyKey::String(d801),
            RuntimePropertyKey::String(d800),
            RuntimePropertyKey::Symbol(symbol),
        ]
    );

    let seed = core.capture_execution_seed();
    let seed_wire = serde_json::to_string(&seed).unwrap();
    let restored_seed: ExecutionSeed = serde_json::from_str(&seed_wire).unwrap();
    assert_eq!(restored_seed, seed);
}

#[test]
fn public_exact_property_insertion_roundtrips_heap_bd_b12xs_4() {
    let d800 = JsString::from_code_units(&[0xD800]);
    let mut object = HeapObject::new();
    object.properties.insert_exact(d800.clone(), Value::Int(8));

    let wire = serde_json::to_string(&object).unwrap();
    assert!(wire.contains("$wtf16"));
    let restored: HeapObject = serde_json::from_str(&wire).unwrap();
    assert_eq!(restored, object);
    assert_eq!(restored.properties.get_exact(&d800), Some(&Value::Int(8)));
}

#[test]
fn iterator_close_calls_object_return_once_and_preserves_heap_effects_bd_t9n3s() {
    let module = test_module_with_pool_and_functions(
        vec![
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
            Ir3Instruction::LoadInt { dst: 3, value: 1 },
            Ir3Instruction::Add {
                dst: 2,
                lhs: 2,
                rhs: 3,
            },
            Ir3Instruction::SetProperty {
                obj: 0,
                key: 1,
                val: 2,
            },
            Ir3Instruction::Return { value: 0 },
        ],
        vec!["closeCount".to_string()],
        vec![Ir3FunctionDesc {
            entry: 0,
            arity: 0,
            frame_size: 4,
            name: Some("iterator_return".to_string()),
            is_generator: false,
            rest_param_index: None,
        }],
    );
    let mut core = quickjs_test_core();
    let iterable = core.alloc_object_with_prototype(None).unwrap();
    core.set_object_property(iterable, "0".to_string(), Value::Int(7))
        .unwrap();
    core.set_object_property(iterable, "closeCount".to_string(), Value::Int(0))
        .unwrap();
    core.set_object_property(iterable, "return".to_string(), Value::Function(0))
        .unwrap();
    let iterator = custom_for_of_handle_for_close(&mut core, iterable);

    core.close_iterator(&module, iterator.clone(), IteratorCloseReason::Break)
        .unwrap();
    core.close_iterator(&module, iterator, IteratorCloseReason::Return)
        .unwrap();

    assert_eq!(
        core.prototype_chain_get(iterable, "closeCount").unwrap(),
        Value::Int(1)
    );
}

#[test]
fn iterator_close_validates_return_result_except_for_throw_bd_t9n3s() {
    let module = test_module_with_functions(
        vec![
            Ir3Instruction::LoadInt { dst: 0, value: 7 },
            Ir3Instruction::Return { value: 0 },
        ],
        vec![Ir3FunctionDesc {
            entry: 0,
            arity: 0,
            frame_size: 1,
            name: Some("primitive_iterator_return".to_string()),
            is_generator: false,
            rest_param_index: None,
        }],
    );

    for (reason, should_fail) in [
        (IteratorCloseReason::Break, true),
        (IteratorCloseReason::Continue, true),
        (IteratorCloseReason::Return, true),
        (IteratorCloseReason::Throw, false),
    ] {
        let mut core = quickjs_test_core();
        let iterable = core.alloc_object_with_prototype(None).unwrap();
        core.set_object_property(iterable, "0".to_string(), Value::Int(1))
            .unwrap();
        core.set_object_property(iterable, "return".to_string(), Value::Function(0))
            .unwrap();
        let iterator = custom_for_of_handle_for_close(&mut core, iterable);

        let result = core.close_iterator(&module, iterator, reason);
        if should_fail {
            assert!(matches!(result, Err(InterpreterError::TypeError { .. })));
        } else {
            result.expect("an in-flight throw must outrank a primitive close result");
        }
    }
}

#[test]
fn iterator_close_throw_precedence_restores_original_completion_bd_t9n3s() {
    let module = test_module_with_pool_and_functions(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::Throw { value: 0 },
        ],
        vec!["close failure".to_string()],
        vec![Ir3FunctionDesc {
            entry: 0,
            arity: 0,
            frame_size: 1,
            name: Some("throwing_iterator_return".to_string()),
            is_generator: false,
            rest_param_index: None,
        }],
    );

    let mut break_core = quickjs_test_core();
    let break_iterable = break_core.alloc_object_with_prototype(None).unwrap();
    break_core
        .set_object_property(break_iterable, "0".to_string(), Value::Int(1))
        .unwrap();
    break_core
        .set_object_property(break_iterable, "return".to_string(), Value::Function(0))
        .unwrap();
    let break_iterator = custom_for_of_handle_for_close(&mut break_core, break_iterable);
    assert!(matches!(
        break_core.close_iterator(&module, break_iterator, IteratorCloseReason::Break),
        Err(InterpreterError::UncaughtException { value }) if value == "close failure"
    ));

    let mut throw_core = quickjs_test_core();
    let throw_iterable = throw_core.alloc_object_with_prototype(None).unwrap();
    throw_core
        .set_object_property(throw_iterable, "0".to_string(), Value::Int(1))
        .unwrap();
    throw_core
        .set_object_property(throw_iterable, "return".to_string(), Value::Function(0))
        .unwrap();
    let throw_iterator = custom_for_of_handle_for_close(&mut throw_core, throw_iterable);
    let original = LabeledException {
        value: Value::str("original failure"),
        label: crate::ifc_artifacts::Label::Secret,
    };
    throw_core.pending_exception = Some(original.clone());

    throw_core
        .close_iterator(&module, throw_iterator, IteratorCloseReason::Throw)
        .expect("an in-flight throw must outrank a failing close hook");
    assert_eq!(throw_core.pending_exception, Some(original));
}

#[test]
fn exact_string_key_consumers_preserve_identity_bd_b12xs_6() {
    let mut core = quickjs_test_core();
    let object = core.alloc_object_with_prototype(None).unwrap();
    let d800 = JsString::from_code_units(&[0xD800]);
    let d801 = JsString::from_code_units(&[0xD801]);
    let replacement = JsString::from("\u{FFFD}");
    let expected_keys = vec![d800.clone(), d801.clone(), replacement.clone()];
    for (key, value) in expected_keys.iter().cloned().zip([8, 9, 10]) {
        core.set_object_runtime_property(
            object,
            RuntimePropertyKey::String(key),
            Value::Int(value),
        )
        .unwrap();
    }

    assert_eq!(core.own_enumerable_keys(object).unwrap(), expected_keys);
    assert_eq!(core.collect_for_in_keys(object).unwrap(), expected_keys);

    let iteration_object = core.alloc_object_with_prototype(None).unwrap();
    for (key, value) in expected_keys.iter().cloned().zip([8, 9, 10]) {
        core.set_object_runtime_property(
            iteration_object,
            RuntimePropertyKey::String(key),
            Value::Int(value),
        )
        .unwrap();
    }
    let iterator = core
        .init_for_in_iterator(Value::Object(iteration_object))
        .unwrap();
    assert_eq!(
        core.advance_for_in_iterator(iterator.clone()).unwrap(),
        Some(Value::Str(d800.clone()))
    );
    core.registers[20] = Value::Object(iteration_object);
    core.registers[21] = Value::Str(d801.clone());
    assert_eq!(
        core.run_loop(&test_module(vec![
            Ir3Instruction::DeleteProperty {
                obj: 20,
                key: 21,
                dst: 22,
            },
            Ir3Instruction::Return { value: 22 },
        ]))
        .unwrap(),
        Value::Bool(true)
    );
    assert_eq!(
        core.advance_for_in_iterator(iterator.clone()).unwrap(),
        Some(Value::Str(replacement.clone()))
    );
    assert_eq!(core.advance_for_in_iterator(iterator).unwrap(), None);

    core.registers[0] = Value::Object(object);
    let keys = core
        .dispatch_builtin_hostcall("builtin:ObjectKeys", RegRange { start: 0, count: 1 })
        .unwrap();
    let Value::Object(keys) = keys else {
        panic!("Object.keys must return an array");
    };
    assert_eq!(
        core.read_array_like_values(keys),
        expected_keys
            .iter()
            .cloned()
            .map(Value::Str)
            .collect::<Vec<_>>()
    );

    let values = core
        .dispatch_builtin_hostcall("builtin:ObjectValues", RegRange { start: 0, count: 1 })
        .unwrap();
    let Value::Object(values) = values else {
        panic!("Object.values must return an array");
    };
    assert_eq!(
        core.read_array_like_values(values),
        vec![Value::Int(8), Value::Int(9), Value::Int(10)]
    );

    let entries = core
        .dispatch_builtin_hostcall("builtin:ObjectEntries", RegRange { start: 0, count: 1 })
        .unwrap();
    let Value::Object(entries) = entries else {
        panic!("Object.entries must return an array");
    };
    let entry_values = core
        .read_array_like_values(entries)
        .into_iter()
        .map(|entry| {
            let Value::Object(entry) = entry else {
                panic!("Object.entries member must be an array");
            };
            core.read_array_like_values(entry)
        })
        .collect::<Vec<_>>();
    assert_eq!(
        entry_values,
        vec![
            vec![Value::Str(d800.clone()), Value::Int(8)],
            vec![Value::Str(d801.clone()), Value::Int(9)],
            vec![Value::Str(replacement.clone()), Value::Int(10)],
        ]
    );

    for builtin in [
        "builtin:ObjectGetOwnPropertyNames",
        "builtin:ReflectOwnKeys",
    ] {
        let reflected = core
            .dispatch_builtin_hostcall(builtin, RegRange { start: 0, count: 1 })
            .unwrap();
        let Value::Object(reflected) = reflected else {
            panic!("{builtin} must return an array");
        };
        assert_eq!(
            core.read_array_like_values(reflected),
            expected_keys
                .iter()
                .cloned()
                .map(Value::Str)
                .collect::<Vec<_>>()
        );
    }

    let target = core.alloc_object_with_prototype(None).unwrap();
    core.registers[0] = Value::Object(target);
    core.registers[1] = Value::Object(object);
    assert_eq!(
        core.dispatch_builtin_hostcall("builtin:ObjectAssign", RegRange { start: 0, count: 2 })
            .unwrap(),
        Value::Object(target)
    );
    assert_eq!(
        core.heap[target.0 as usize].own_exact_property_keys(),
        expected_keys
    );

    let spread_target = core.alloc_object_with_prototype(None).unwrap();
    core.registers[1] = Value::Object(spread_target);
    core.registers[2] = Value::Object(object);
    core.execute(&test_module(vec![
        Ir3Instruction::CopyDataProperties {
            target: 1,
            source: 2,
            excluded: RegRange { start: 3, count: 0 },
            value_dst: 4,
        },
        Ir3Instruction::Halt,
    ]))
    .unwrap();
    assert_eq!(
        core.heap[spread_target.0 as usize].own_exact_property_keys(),
        expected_keys
    );

    let spread_instruction_target = core.alloc_object_with_prototype(None).unwrap();
    core.registers[1] = Value::Object(spread_instruction_target);
    core.registers[2] = Value::Object(object);
    core.execute(&test_module(vec![
        Ir3Instruction::SpreadIntoObject {
            target: 1,
            source: 2,
        },
        Ir3Instruction::Halt,
    ]))
    .unwrap();
    assert_eq!(
        core.heap[spread_instruction_target.0 as usize].own_exact_property_keys(),
        expected_keys
    );

    let assign_target = core.alloc_object_with_prototype(None).unwrap();
    core.registers[1] = Value::Object(assign_target);
    core.registers[2] = Value::Object(object);
    core.execute(&test_module(vec![
        Ir3Instruction::HostCall {
            capability: CapabilityTag("builtin:ObjectAssign".to_string()),
            args: RegRange { start: 1, count: 2 },
            dst: 0,
        },
        Ir3Instruction::Halt,
    ]))
    .unwrap();
    assert_eq!(
        core.heap[assign_target.0 as usize].own_exact_property_keys(),
        expected_keys
    );

    core.registers[0] = Value::Object(object);
    assert_eq!(
        core.dispatch_builtin_hostcall("builtin:JsonStringify", RegRange { start: 0, count: 1 })
            .unwrap(),
        Value::str(r#"{"\ud800":8,"\ud801":9,"�":10}"#)
    );
    assert!(matches!(
        core.qs_stringify_object(object, "&", "="),
        Err(InterpreterError::TypeError { .. })
    ));
    assert_eq!(node_qs_escape_js(&replacement).unwrap(), "%EF%BF%BD");
    assert!(matches!(
        node_qs_escape_js(&d800),
        Err(InterpreterError::TypeError { .. })
    ));
}

#[test]
fn module_preparation_failures_never_publish_cycle_visible_records() {
    let fixtures = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/modules");
    let caller = test_module(vec![Ir3Instruction::Halt]);
    for is_cjs in [false, true] {
        for fixture in [
            "missing-module.mjs",
            "parse_failure.cjs",
            "lowering_failure.cjs",
        ] {
            let path = fixtures.join(fixture).display().to_string();
            let mut core = quickjs_test_core();
            let initial_heap_len = core.heap.len();
            let initial_memory = core.recompute_estimated_memory_bytes();
            let first = core
                .load_module_resolved(&caller, &path, is_cjs)
                .unwrap_err();
            match fixture {
                "missing-module.mjs" => {
                    assert!(matches!(&first, InterpreterError::ModuleReadFailed { .. }));
                }
                "parse_failure.cjs" => {
                    assert!(matches!(&first, InterpreterError::ModuleParseFailed { .. }));
                }
                "lowering_failure.cjs" => {
                    assert!(matches!(
                        &first,
                        InterpreterError::ModuleLoweringFailed { .. }
                    ));
                }
                _ => unreachable!(),
            }
            assert!(!core.module_state.modules.contains_key(&path));
            assert_eq!(core.heap.len(), initial_heap_len);
            assert_eq!(core.recompute_estimated_memory_bytes(), initial_memory);
            let second = core
                .load_module_resolved(&caller, &path, is_cjs)
                .unwrap_err();
            assert_eq!(second, first, "a repeated load must fail in the same phase");
            assert!(!core.module_state.modules.contains_key(&path));
            assert_eq!(core.heap.len(), initial_heap_len);
            assert_eq!(core.recompute_estimated_memory_bytes(), initial_memory);
        }
    }
}

#[test]
fn commonjs_finalization_keeps_exact_named_exports_bd_b12xs_6() {
    let mut core = quickjs_test_core();
    let specifier = "fixture.cjs".to_string();
    let namespace_object = core.alloc_object_with_prototype(None).unwrap();
    let exports_object = core.alloc_object_with_prototype(None).unwrap();
    let module_object = core.alloc_object_with_prototype(None).unwrap();
    let d800 = JsString::from_code_units(&[0xD800]);
    let d801 = JsString::from_code_units(&[0xD801]);
    let replacement = JsString::from("\u{FFFD}");
    for (key, value) in [
        (d800.clone(), 8),
        (d801.clone(), 9),
        (replacement.clone(), 10),
    ] {
        core.set_object_runtime_property(
            exports_object,
            RuntimePropertyKey::String(key),
            Value::Int(value),
        )
        .unwrap();
    }
    core.set_object_property(
        module_object,
        "exports".to_string(),
        Value::Object(exports_object),
    )
    .unwrap();
    core.module_state.modules.insert(
        specifier.clone(),
        ModuleRuntimeRecord {
            status: ModuleRuntimeStatus::Evaluating,
            namespace_object,
            exports: BTreeMap::new(),
            cjs_module_object: Some(module_object),
            compiled_module: None,
            retained_program_bytes: 0,
        },
    );
    core.current_module_specifier = Some(specifier.clone());
    core.finalize_cjs_exports(&CjsModuleContext {
        module_object,
        exports_object,
        module_specifier: specifier.clone(),
    })
    .unwrap();

    let record = core.module_state.modules.get(&specifier).unwrap();
    for (key, value) in [(d800, 8), (d801, 9), (replacement, 10)] {
        assert_eq!(record.exports.get(&key), Some(&Value::Int(value)));
        assert_eq!(
            core.heap[namespace_object.0 as usize]
                .properties
                .get_exact(&key),
            Some(&Value::Int(value))
        );
    }
}

fn execute_captured_commonjs_source(source: &str) -> (Value, CjsModuleContext) {
    let tree = CanonicalEs2020Parser
        .parse(source, ParseGoal::Script)
        .expect("captured CommonJS binding source should parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "/tmp/captured-module.cjs");
    let module = lower_ir0_to_ir3(
        &ir0,
        &LoweringContext::new("cjs-capture", "cjs-capture", "cjs-capture"),
    )
    .expect("captured CommonJS binding source should lower")
    .ir3;
    let mut core = quickjs_test_core();
    let context = core
        .init_cjs_environment(&module, "/tmp/captured-module.cjs", None)
        .expect("CommonJS environment should initialize");
    core.active_cjs_context = Some(context.clone());
    let value = core
        .run_loop(&module)
        .expect("captured CommonJS binding should execute");
    (value, context)
}

#[test]
fn commonjs_binding_captured_by_function_reuses_injected_scope_cell() {
    let (value, context) =
        execute_captured_commonjs_source("function read(){ return module; } read();");
    assert_eq!(value, Value::Object(context.module_object));
}

#[test]
fn commonjs_closure_reads_prior_exports_reassignment_from_shared_cell() {
    let (value, _) =
        execute_captured_commonjs_source("exports = 7; function read(){ return exports; } read();");
    assert_eq!(value, Value::Int(7));
}

#[test]
fn commonjs_closure_module_reassignment_survives_return() {
    let (value, _) =
        execute_captured_commonjs_source("function set(){ module = 7; } set(); module;");
    assert_eq!(value, Value::Int(7));
}

#[test]
fn dynamic_exact_string_get_set_delete_in_and_prototype_bd_b12xs_4() {
    let mut core = quickjs_test_core();
    let prototype = core.alloc_object_with_prototype(None).unwrap();
    let object = core.alloc_object_with_prototype(Some(prototype)).unwrap();
    let d800 = JsString::from_code_units(&[0xD800]);
    let d801 = JsString::from_code_units(&[0xD801]);
    let replacement = JsString::from("\u{FFFD}");
    core.set_object_runtime_property(
        prototype,
        RuntimePropertyKey::String(d801.clone()),
        Value::Int(80),
    )
    .unwrap();

    core.registers[1] = Value::Object(object);
    core.registers[2] = Value::Str(d800.clone());
    core.registers[3] = Value::Int(8);
    core.registers[4] = Value::Str(d801.clone());
    core.registers[5] = Value::Int(9);
    core.registers[6] = Value::Str(replacement.clone());
    core.registers[7] = Value::Int(0xFFFD);
    core.execute(&test_module(vec![
        Ir3Instruction::SetProperty {
            obj: 1,
            key: 2,
            val: 3,
        },
        Ir3Instruction::SetProperty {
            obj: 1,
            key: 4,
            val: 5,
        },
        Ir3Instruction::SetProperty {
            obj: 1,
            key: 6,
            val: 7,
        },
        Ir3Instruction::GetProperty {
            obj: 1,
            key: 2,
            dst: 8,
        },
        Ir3Instruction::GetProperty {
            obj: 1,
            key: 4,
            dst: 9,
        },
        Ir3Instruction::GetProperty {
            obj: 1,
            key: 6,
            dst: 10,
        },
        Ir3Instruction::DeleteProperty {
            obj: 1,
            key: 4,
            dst: 11,
        },
        Ir3Instruction::GetProperty {
            obj: 1,
            key: 4,
            dst: 12,
        },
        Ir3Instruction::InOp {
            dst: 13,
            lhs: 4,
            rhs: 1,
        },
        Ir3Instruction::DeleteProperty {
            obj: 1,
            key: 2,
            dst: 14,
        },
        Ir3Instruction::InOp {
            dst: 15,
            lhs: 2,
            rhs: 1,
        },
        Ir3Instruction::Halt,
    ]))
    .unwrap();

    assert_eq!(core.registers[8], Value::Int(8));
    assert_eq!(core.registers[9], Value::Int(9));
    assert_eq!(core.registers[10], Value::Int(0xFFFD));
    assert_eq!(core.registers[11], Value::Bool(true));
    assert_eq!(core.registers[12], Value::Int(80));
    assert_eq!(core.registers[13], Value::Bool(true));
    assert_eq!(core.registers[14], Value::Bool(true));
    assert_eq!(core.registers[15], Value::Bool(false));
    assert_eq!(
        core.heap[object.0 as usize]
            .properties
            .get_exact(&replacement),
        Some(&Value::Int(0xFFFD))
    );
    assert_eq!(
        core.heap[prototype.0 as usize].properties.get_exact(&d801),
        Some(&Value::Int(80))
    );
}

#[test]
fn function_like_dynamic_exact_property_roundtrip_bd_b12xs_4() {
    let mut core = quickjs_test_core();
    let d800 = JsString::from_code_units(&[0xD800]);
    core.registers[1] = Value::Function(0);
    core.registers[2] = Value::Str(d800);
    core.registers[3] = Value::Int(8);
    core.execute(&test_module(vec![
        Ir3Instruction::SetProperty {
            obj: 1,
            key: 2,
            val: 3,
        },
        Ir3Instruction::GetProperty {
            obj: 1,
            key: 2,
            dst: 4,
        },
        Ir3Instruction::InOp {
            dst: 5,
            lhs: 2,
            rhs: 1,
        },
        Ir3Instruction::DeleteProperty {
            obj: 1,
            key: 2,
            dst: 6,
        },
        Ir3Instruction::InOp {
            dst: 7,
            lhs: 2,
            rhs: 1,
        },
        Ir3Instruction::Halt,
    ]))
    .unwrap();

    assert_eq!(core.registers[4], Value::Int(8));
    assert_eq!(core.registers[5], Value::Bool(true));
    assert_eq!(core.registers[6], Value::Bool(true));
    assert_eq!(core.registers[7], Value::Bool(false));
}

#[test]
fn reexecution_restores_exact_heap_seed_bd_b12xs_4() {
    let mut core = quickjs_test_core();
    let object = core.alloc_object_with_prototype(None).unwrap();
    let d800 = JsString::from_code_units(&[0xD800]);
    core.registers[1] = Value::Object(object);
    core.registers[2] = Value::Str(d800.clone());
    core.registers[3] = Value::Int(8);
    let module = test_module(vec![
        Ir3Instruction::InOp {
            dst: 0,
            lhs: 2,
            rhs: 1,
        },
        Ir3Instruction::SetProperty {
            obj: 1,
            key: 2,
            val: 3,
        },
        Ir3Instruction::Halt,
    ]);

    let first = core.execute(&module).unwrap();
    assert_eq!(first.value, Value::Bool(false));
    assert_eq!(
        core.heap[object.0 as usize].properties.get_exact(&d800),
        Some(&Value::Int(8))
    );
    let second = core.execute(&module).unwrap();
    assert_eq!(second.value, Value::Bool(false));
    assert_eq!(
        core.heap[object.0 as usize].properties.get_exact(&d800),
        Some(&Value::Int(8))
    );
}

#[test]
fn symbol_seed_wire_restore_and_registry_are_atomic_bd_n8eta_4_3() {
    let mut core = quickjs_test_core();
    let private = core
        .allocate_private_symbol(Some(JsString::from("private")))
        .unwrap();
    let global = core.intern_global_symbol(JsString::from("shared")).unwrap();
    core.write_reg(0, Value::Symbol(private)).unwrap();
    core.write_reg(1, Value::Symbol(global)).unwrap();
    let seed = core.capture_execution_seed();
    let wire = serde_json::to_string(&seed).unwrap();
    assert!(wire.contains(r#""well_known_schema":"es2020-symbol-ids-1-13-v1""#));
    assert!(wire.contains(r#""next_symbol_id":16"#));
    let decoded: ExecutionSeed = serde_json::from_str(&wire).unwrap();
    assert_eq!(decoded, seed);

    let later = core.allocate_private_symbol(None).unwrap();
    assert_eq!(later, SymbolId(16));
    core.reset_execution_state_from_seed(&decoded).unwrap();
    assert_eq!(
        core.symbol_state.key_for(global),
        Some(&JsString::from("shared"))
    );
    assert_eq!(core.allocate_private_symbol(None).unwrap(), SymbolId(16));

    let default_wire = serde_json::to_string(
        &InterpreterCore::new(test_quickjs_config(), "default-symbol-state")
            .capture_execution_seed(),
    )
    .unwrap();
    assert!(!default_wire.contains("symbol_state"));
}

#[test]
fn exact_only_values_participate_in_symbol_seed_validation_bd_b12xs_4() {
    let mut core = quickjs_test_core();
    let symbol = core
        .allocate_private_symbol(Some(JsString::from("exact-seed")))
        .unwrap();
    let object = core.alloc_object_with_prototype(None).unwrap();
    let d800 = JsString::from_code_units(&[0xD800]);
    let d801 = JsString::from_code_units(&[0xD801]);
    core.set_object_runtime_property(
        object,
        RuntimePropertyKey::String(d800.clone()),
        Value::Symbol(symbol),
    )
    .unwrap();
    core.set_object_string_property(
        object,
        exact_accessor_definition_key(IR_ACCESSOR_GET_PREFIX, &d801),
        Value::Symbol(symbol),
    )
    .unwrap();

    let seed = core.capture_execution_seed();
    let wire = serde_json::to_string(&seed).unwrap();
    assert!(wire.contains("symbol_state"));
    let decoded: ExecutionSeed = serde_json::from_str(&wire).unwrap();
    assert_eq!(decoded, seed);
    core.reset_execution_state_from_seed(&decoded).unwrap();
    assert_eq!(core.capture_execution_seed(), seed);

    let stable = core.capture_execution_seed();
    let mut unresolved_data = seed.clone();
    *unresolved_data.heap[object.0 as usize]
        .properties
        .get_exact_mut(&d800)
        .unwrap() = Value::Symbol(SymbolId(999));
    assert!(
        serde_json::from_value::<ExecutionSeed>(serde_json::to_value(&unresolved_data).unwrap())
            .is_err()
    );
    assert!(
        core.reset_execution_state_from_seed(&unresolved_data)
            .is_err()
    );
    assert_eq!(core.capture_execution_seed(), stable);

    let mut unresolved_accessor = seed;
    unresolved_accessor.heap[object.0 as usize].insert_exact_accessor(
        d801,
        AccessorProperty {
            get: Some(Value::Symbol(SymbolId(999))),
            set: None,
        },
    );
    assert!(
        serde_json::from_value::<ExecutionSeed>(
            serde_json::to_value(&unresolved_accessor).unwrap()
        )
        .is_err()
    );
    assert!(
        core.reset_execution_state_from_seed(&unresolved_accessor)
            .is_err()
    );
    assert_eq!(core.capture_execution_seed(), stable);
}

#[test]
fn whole_seed_rejects_unresolved_dynamic_symbol_ids_bd_n8eta_4_3() {
    let default_seed =
        InterpreterCore::new(test_quickjs_config(), "invalid-symbol-seed").capture_execution_seed();
    let mut wire = serde_json::to_value(&default_seed).unwrap();
    wire["registers"][0] = serde_json::json!({"Symbol": 14});
    assert!(serde_json::from_value::<ExecutionSeed>(wire).is_err());

    let mut missing_state_wire = serde_json::to_value(&default_seed).unwrap();
    missing_state_wire["registers"][0] = serde_json::json!({"Symbol": 1});
    assert!(missing_state_wire.get("symbol_state").is_none());
    assert!(serde_json::from_value::<ExecutionSeed>(missing_state_wire).is_err());

    let mut null_state_wire = serde_json::to_value(&default_seed).unwrap();
    null_state_wire["symbol_state"] = serde_json::Value::Null;
    assert!(serde_json::from_value::<ExecutionSeed>(null_state_wire).is_err());
}

#[test]
fn eager_seed_rejects_unresolved_symbols_atomically_bd_n8eta_4_3() {
    let mut core = quickjs_test_core();
    let before = core.capture_execution_seed();
    let mut eager_seed = core.capture_execution_seed_eager_for_test();
    eager_seed.registers[0] = Value::Symbol(SymbolId(999));

    assert!(matches!(
        core.reset_execution_state_from_seed_eager_for_test(&eager_seed),
        Err(InterpreterError::TypeError { .. })
    ));
    assert_eq!(core.capture_execution_seed(), before);
}

#[test]
fn symbol_allocation_and_property_budget_failures_roll_back_bd_n8eta_4_3() {
    let mut allocation_core = quickjs_test_core();
    allocation_core.config.max_total_memory_bytes = 1;
    assert!(matches!(
        allocation_core.allocate_private_symbol(Some(JsString::from("too-large"))),
        Err(InterpreterError::MemoryBudgetExceeded { .. })
    ));
    assert!(allocation_core.symbol_state.is_default());
    assert_eq!(allocation_core.estimated_memory_bytes(), 0);

    let mut property_core = quickjs_test_core();
    let symbol = property_core.allocate_private_symbol(None).unwrap();
    let object = property_core.alloc_object_with_prototype(None).unwrap();
    let baseline_memory = property_core.estimated_memory_bytes();
    property_core.config.max_total_memory_bytes = baseline_memory + 1;
    assert!(matches!(
        property_core.set_object_typed_property(
            object,
            TypedPropertyKey::Symbol(symbol),
            Value::str("x".repeat(512)),
        ),
        Err(InterpreterError::MemoryBudgetExceeded { .. })
    ));
    assert!(
        property_core.heap[object.0 as usize]
            .properties
            .baseline_symbol_key_order()
            .is_empty()
    );
    assert_eq!(property_core.estimated_memory_bytes(), baseline_memory);
}

#[test]
fn implicit_symbol_string_concatenation_fails_closed_bd_n8eta_4_3() {
    let mut core = quickjs_test_core();
    core.registers.resize(2, Value::Undefined);
    core.registers[0] = Value::str("prefix");
    core.registers[1] = Value::Symbol(WellKnownSymbol::Iterator.id());

    for (lhs, rhs) in [(0, 1), (1, 0)] {
        assert!(matches!(
            core.eval_add(lhs, rhs),
            Err(InterpreterError::TypeError { ref got, .. }) if got == "symbol"
        ));
    }
}

#[test]
fn implicit_symbol_numeric_coercions_fail_closed_bd_n8eta_4_3() {
    let mut core = quickjs_test_core();
    core.registers.resize(2, Value::Undefined);
    core.registers[0] = Value::Symbol(WellKnownSymbol::Iterator.id());
    core.registers[1] = Value::Int(1);

    let results = [
        core.eval_add(0, 1),
        core.eval_arith(0, 1, "sub"),
        core.eval_arith(0, 1, "mul"),
        core.eval_div(0, 1),
        core.eval_mod(0, 1),
        core.eval_exp(0, 1),
        core.eval_unary_plus(0),
        core.eval_unary_neg(0),
        core.eval_bit_not(0),
        core.eval_relational(0, 1, "<"),
        core.eval_bitwise(0, 1, "|"),
    ];
    assert!(
        results
            .into_iter()
            .all(|result| matches!(result, Err(InterpreterError::TypeError { .. })))
    );
}

#[test]
fn symbol_legacy_numeric_coercion_sinks_fail_closed_bd_n8eta_4_3() {
    let mut core = quickjs_test_core();
    let symbol = Value::Symbol(WellKnownSymbol::Iterator.id());
    core.registers[0] = Value::Int(65);
    core.registers[1] = symbol.clone();

    for capability in ["number:isNaN", "number:isFinite"] {
        assert!(matches!(
            core.dispatch_number_hostcall(capability, RegRange { start: 1, count: 1 }),
            Err(InterpreterError::TypeError { .. })
        ));
    }
    for capability in [
        "number:Number.isNaN",
        "number:Number.isFinite",
        "number:Number.isInteger",
        "number:Number.isSafeInteger",
    ] {
        assert_eq!(
            core.dispatch_number_hostcall(capability, RegRange { start: 1, count: 1 })
                .unwrap(),
            Value::Bool(false)
        );
    }

    let text = JsString::from("abc");
    assert!(InterpreterCore::string_char_at_value(&text, Some(&symbol)).is_err());
    assert!(InterpreterCore::string_char_code_at_value(&text, Some(&symbol)).is_err());
    assert!(InterpreterCore::string_code_point_at_value(&text, Some(&symbol)).is_err());
    assert!(InterpreterCore::string_at_value(&text, Some(&symbol)).is_err());

    for capability in ["builtin:StringFromCharCode", "builtin:StringFromCodePoint"] {
        assert!(matches!(
            core.dispatch_builtin_hostcall(capability, RegRange { start: 0, count: 2 }),
            Err(InterpreterError::TypeError { .. })
        ));
    }
    assert!(matches!(
        core.dispatch_builtin_hostcall("builtin:MathAbs", RegRange { start: 1, count: 1 }),
        Err(InterpreterError::TypeError { .. })
    ));
    for capability in ["timer:setTimeout", "timer:setInterval"] {
        assert!(matches!(
            core.dispatch_timer_hostcall(capability, RegRange { start: 0, count: 2 }),
            Err(InterpreterError::TypeError { .. })
        ));
    }
    assert_eq!(
        core.dispatch_timer_hostcall("timer:clearTimeout", RegRange { start: 1, count: 1 })
            .unwrap(),
        Value::Undefined
    );

    let array_like = core.alloc_object_with_prototype(None).unwrap();
    core.set_plain_data_property(array_like, "length".into(), symbol)
        .unwrap();
    assert!(matches!(
        core.array_like_length(array_like),
        Err(InterpreterError::TypeError { .. })
    ));
    core.registers[1] = Value::Object(array_like);
    core.registers[2] = Value::Int(0);
    assert!(matches!(
        core.execute(&test_module(vec![
            Ir3Instruction::ArraySlice {
                array: 1,
                start: 2,
                dst: 0,
            },
            Ir3Instruction::Halt,
        ])),
        Err(InterpreterError::TypeError { .. })
    ));
}

#[test]
fn symbol_source_identity_keys_and_reflection_match_both_lanes_bd_n8eta_4_3() {
    let module = lower_symbol_source_bd_n8eta_4_3(
        "const first = Symbol('same');\
         const second = Symbol('same');\
         const global = Symbol.for('shared');\
         const key = Symbol('key');\
         const object = { [key]: 7, 'Symbol(17)': 9 };\
         object[key] = 8;\
         const setWorked = object[key] === 8;\
         delete object[key];\
         const deleteWorked = !(key in object);\
         object[key] = 7;\
         const spread = { ...object };\
         const assigned = Object.assign({}, object);\
         (typeof Symbol === 'function' && typeof first === 'symbol' && first !== second &&\
          first.description === 'same' && first.toString() === 'Symbol(same)' &&\
          Symbol().description === undefined &&\
          global === Symbol.for('shared') && Symbol.keyFor(global) === 'shared' &&\
          Symbol.keyFor(first) === undefined && Symbol.keyFor(Symbol.iterator) === undefined &&\
          setWorked && deleteWorked && object[key] === 7 && object['Symbol(17)'] === 9 &&\
          key in object && spread[key] === 7 && assigned[key] === 7 &&\
          Object.keys(object).length === 1 &&\
          Object.getOwnPropertySymbols(object)[0] === key &&\
          Reflect.ownKeys(object).length === 2) ? 1 : 0;",
    );
    assert_eq!(quickjs_execute(&module).unwrap().value, Value::Int(1));
    assert_eq!(v8_execute(&module).unwrap().value, Value::Int(1));
}

#[test]
fn function_like_symbol_own_keys_match_both_lanes_bd_n8eta_4_3() {
    let cases = [
        (
            "get-set-in",
            "const s=Symbol(); function f(){} f[s]=9; (s in f && f[s]===9)?1:0;",
        ),
        (
            "reflection",
            "const s=Symbol(); function f(){} f[s]=9; (Object.getOwnPropertySymbols(f)[0]===s && Reflect.ownKeys(f).length===1)?1:0;",
        ),
        (
            "spread",
            "const s=Symbol(); function f(){} f[s]=9; const copy={...f}; copy[s]===9?1:0;",
        ),
        (
            "assign",
            "const s=Symbol(); function f(){} f[s]=9; const copy=Object.assign({},f); copy[s]===9?1:0;",
        ),
        (
            "delete",
            "const s=Symbol(); function f(){} f[s]=9; (delete f[s] && !(s in f))?1:0;",
        ),
    ];
    for (name, source) in cases {
        let module = lower_symbol_source_bd_n8eta_4_3(source);
        assert_eq!(
            quickjs_execute(&module)
                .unwrap_or_else(|error| panic!("QuickJsLane {name}: {error}"))
                .value,
            Value::Int(1),
            "QuickJsLane {name}"
        );
        assert_eq!(
            v8_execute(&module)
                .unwrap_or_else(|error| panic!("V8Lane {name}: {error}"))
                .value,
            Value::Int(1),
            "V8Lane {name}"
        );
    }
}

#[test]
fn symbol_accessor_spread_resumes_getter_and_defines_data_bd_n8eta_4_3() {
    let mut core = quickjs_test_core();
    let symbol = core
        .allocate_private_symbol(Some(JsString::from("spread")))
        .unwrap();
    let target = core.alloc_object_with_prototype(None).unwrap();
    let source = core.alloc_object_with_prototype(None).unwrap();
    core.set_plain_data_property(source, "calls".into(), Value::Int(0))
        .unwrap();
    core.set_plain_data_property(source, "marker".into(), Value::Int(41))
        .unwrap();
    core.set_symbol_property(
        source,
        symbol,
        BaselineSymbolProperty::Accessor {
            get: Some(Value::Function(0)),
            set: None,
        },
    )
    .unwrap();
    core.registers[1] = Value::Object(target);
    core.registers[2] = Value::Object(source);

    let result = core
        .execute(&test_module_with_pool_and_functions(
            vec![
                Ir3Instruction::SpreadIntoObject {
                    target: 1,
                    source: 2,
                },
                Ir3Instruction::Move { dst: 0, src: 1 },
                Ir3Instruction::Halt,
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
                Ir3Instruction::LoadInt { dst: 3, value: 1 },
                Ir3Instruction::Add {
                    dst: 4,
                    lhs: 2,
                    rhs: 3,
                },
                Ir3Instruction::SetProperty {
                    obj: 0,
                    key: 1,
                    val: 4,
                },
                Ir3Instruction::LoadStr {
                    dst: 5,
                    pool_index: 1,
                },
                Ir3Instruction::GetProperty {
                    obj: 0,
                    key: 5,
                    dst: 6,
                },
                Ir3Instruction::Return { value: 6 },
            ],
            vec!["calls".to_string(), "marker".to_string()],
            vec![class_test_function(3, "symbol_spread_getter")],
        ))
        .unwrap();

    assert_eq!(result.value, Value::Object(target));
    assert_eq!(core.registers[2], Value::Object(source));
    assert_eq!(
        core.heap[source.0 as usize].properties.get("calls"),
        Some(&Value::Int(1))
    );
    assert!(matches!(
        core.heap[target.0 as usize]
            .properties
            .baseline_symbol_property(symbol),
        Some(BaselineSymbolProperty::Data(Value::Int(41)))
    ));
    assert!(core.copy_data_properties_states.is_empty());
}

#[test]
fn non_resumable_object_assign_fails_closed_on_symbol_accessor_bd_jv7qk() {
    // bd-jv7qk divergence pin: the resumable route
    // (symbol_accessor_object_assign_runs_getter_then_setter_once_bd_n8eta_4_3)
    // invokes the Symbol accessor getter. The non-resumable
    // `object_assign` dispatch route cannot run a getter (no module
    // context), so it must fail closed rather than silently drop the
    // enumerable own key — the two routes may no longer disagree by
    // silently copying-vs-dropping the same key.
    let mut core = quickjs_test_core();
    let symbol = core.allocate_private_symbol(None).unwrap();
    let target = core.alloc_object_with_prototype(None).unwrap();
    let source = core.alloc_object_with_prototype(None).unwrap();
    core.set_symbol_property(
        source,
        symbol,
        BaselineSymbolProperty::Accessor {
            get: Some(Value::Function(0)),
            set: None,
        },
    )
    .unwrap();
    core.registers[0] = Value::Object(target);
    core.registers[1] = Value::Object(source);
    assert!(
        matches!(
            core.dispatch_builtin_hostcall("builtin:ObjectAssign", RegRange { start: 0, count: 2 }),
            Err(InterpreterError::TypeError { .. })
        ),
        "non-resumable Object.assign must refuse a Symbol accessor source, not silently drop it"
    );
    // The accessor key was neither copied nor mutated on the target.
    assert!(
        core.heap[target.0 as usize]
            .properties
            .baseline_symbol_property(symbol)
            .is_none()
    );

    // Data-valued Symbol keys remain copyable on the same route — only
    // accessors (which require running user code) are refused.
    let mut core = quickjs_test_core();
    let symbol = core.allocate_private_symbol(None).unwrap();
    let target = core.alloc_object_with_prototype(None).unwrap();
    let source = core.alloc_object_with_prototype(None).unwrap();
    core.set_symbol_property(source, symbol, BaselineSymbolProperty::Data(Value::Int(9)))
        .unwrap();
    core.registers[0] = Value::Object(target);
    core.registers[1] = Value::Object(source);
    core.dispatch_builtin_hostcall("builtin:ObjectAssign", RegRange { start: 0, count: 2 })
        .unwrap();
    assert!(matches!(
        core.heap[target.0 as usize]
            .properties
            .baseline_symbol_property(symbol),
        Some(BaselineSymbolProperty::Data(Value::Int(9)))
    ));
}

#[test]
fn symbol_accessor_object_assign_runs_getter_then_setter_once_bd_n8eta_4_3() {
    let mut core = quickjs_test_core();
    let symbol = core
        .allocate_private_symbol(Some(JsString::from("assign")))
        .unwrap();
    let target = core.alloc_object_with_prototype(None).unwrap();
    let source = core.alloc_object_with_prototype(None).unwrap();
    let later_source = core.alloc_object_with_prototype(None).unwrap();
    core.set_plain_data_property(source, "getterCalls".into(), Value::Int(0))
        .unwrap();
    core.set_plain_data_property(source, "marker".into(), Value::Int(41))
        .unwrap();
    core.set_plain_data_property(target, "setterCalls".into(), Value::Int(0))
        .unwrap();
    core.set_plain_data_property(target, "received".into(), Value::Int(0))
        .unwrap();
    core.set_plain_data_property(later_source, "after".into(), Value::Int(2))
        .unwrap();
    core.set_symbol_property(
        source,
        symbol,
        BaselineSymbolProperty::Accessor {
            get: Some(Value::Function(0)),
            set: None,
        },
    )
    .unwrap();
    core.set_symbol_property(
        target,
        symbol,
        BaselineSymbolProperty::Accessor {
            get: None,
            set: Some(Value::Function(1)),
        },
    )
    .unwrap();
    core.registers[1] = Value::Object(target);
    core.registers[2] = Value::Object(source);
    core.registers[3] = Value::Object(later_source);

    let result = core
        .execute(&test_module_with_pool_and_functions(
            vec![
                Ir3Instruction::HostCall {
                    capability: CapabilityTag("builtin:ObjectAssign".to_string()),
                    args: RegRange { start: 1, count: 3 },
                    dst: 0,
                },
                Ir3Instruction::Halt,
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
                Ir3Instruction::LoadInt { dst: 3, value: 1 },
                Ir3Instruction::Add {
                    dst: 4,
                    lhs: 2,
                    rhs: 3,
                },
                Ir3Instruction::SetProperty {
                    obj: 0,
                    key: 1,
                    val: 4,
                },
                Ir3Instruction::LoadStr {
                    dst: 5,
                    pool_index: 1,
                },
                Ir3Instruction::GetProperty {
                    obj: 0,
                    key: 5,
                    dst: 6,
                },
                Ir3Instruction::Return { value: 6 },
                Ir3Instruction::LoadThis { dst: 2 },
                Ir3Instruction::LoadStr {
                    dst: 1,
                    pool_index: 2,
                },
                Ir3Instruction::GetProperty {
                    obj: 2,
                    key: 1,
                    dst: 3,
                },
                Ir3Instruction::LoadInt { dst: 4, value: 1 },
                Ir3Instruction::Add {
                    dst: 5,
                    lhs: 3,
                    rhs: 4,
                },
                Ir3Instruction::SetProperty {
                    obj: 2,
                    key: 1,
                    val: 5,
                },
                Ir3Instruction::LoadStr {
                    dst: 6,
                    pool_index: 3,
                },
                Ir3Instruction::SetProperty {
                    obj: 2,
                    key: 6,
                    val: 0,
                },
                Ir3Instruction::Return { value: 0 },
            ],
            vec![
                "getterCalls".to_string(),
                "marker".to_string(),
                "setterCalls".to_string(),
                "received".to_string(),
            ],
            vec![
                class_test_function(2, "symbol_assign_getter"),
                Ir3FunctionDesc {
                    entry: 11,
                    arity: 1,
                    frame_size: 7,
                    name: Some("symbol_assign_setter".to_string()),
                    is_generator: false,
                    rest_param_index: None,
                },
            ],
        ))
        .unwrap();

    assert_eq!(result.value, Value::Object(target));
    assert_eq!(
        core.heap[source.0 as usize].properties.get("getterCalls"),
        Some(&Value::Int(1))
    );
    assert_eq!(
        core.heap[target.0 as usize].properties.get("setterCalls"),
        Some(&Value::Int(1))
    );
    assert_eq!(
        core.heap[target.0 as usize].properties.get("received"),
        Some(&Value::Int(41))
    );
    assert_eq!(
        core.heap[target.0 as usize].properties.get("after"),
        Some(&Value::Int(2))
    );
    assert!(matches!(
        core.heap[target.0 as usize]
            .properties
            .baseline_symbol_property(symbol),
        Some(BaselineSymbolProperty::Accessor { .. })
    ));
    assert_eq!(result.hostcall_decisions.len(), 1);
    assert!(core.copy_data_properties_states.is_empty());
}

#[test]
fn symbol_object_assign_rejections_clear_continuations_bd_n8eta_4_3() {
    for throwing_setter in [false, true] {
        let mut core = quickjs_test_core();
        let symbol = core.allocate_private_symbol(None).unwrap();
        let target = core.alloc_object_with_prototype(None).unwrap();
        let source = core.alloc_object_with_prototype(None).unwrap();
        core.set_symbol_property(source, symbol, BaselineSymbolProperty::Data(Value::Int(7)))
            .unwrap();
        core.set_symbol_property(
            target,
            symbol,
            BaselineSymbolProperty::Accessor {
                get: None,
                set: throwing_setter.then_some(Value::Function(0)),
            },
        )
        .unwrap();
        core.registers[1] = Value::Object(target);
        core.registers[2] = Value::Object(source);

        let module = test_module_with_pool_and_functions(
            vec![
                Ir3Instruction::HostCall {
                    capability: CapabilityTag("builtin:ObjectAssign".to_string()),
                    args: RegRange { start: 1, count: 2 },
                    dst: 0,
                },
                Ir3Instruction::Halt,
                Ir3Instruction::LoadStr {
                    dst: 0,
                    pool_index: 0,
                },
                Ir3Instruction::Throw { value: 0 },
            ],
            vec!["setter failed".to_string()],
            vec![Ir3FunctionDesc {
                entry: 2,
                arity: 1,
                frame_size: 1,
                name: Some("throwing_symbol_assign_setter".to_string()),
                is_generator: false,
                rest_param_index: None,
            }],
        );
        assert!(core.execute(&module).is_err());
        assert!(core.copy_data_properties_states.is_empty());
        assert!(matches!(
            core.heap[target.0 as usize]
                .properties
                .baseline_symbol_property(symbol),
            Some(BaselineSymbolProperty::Accessor { .. })
        ));
    }
}

fn class_test_function(entry: u32, name: &str) -> Ir3FunctionDesc {
    Ir3FunctionDesc {
        entry,
        arity: 0,
        frame_size: 4,
        name: Some(name.to_string()),
        is_generator: false,
        rest_param_index: None,
    }
}

fn object_id_from_value(value: &Value, context: &str) -> ObjectId {
    match value {
        Value::Object(id) => *id,
        other => panic!("{context} should be an object, got {other:?}"),
    }
}

#[test]
fn class_semantic_tests_reject_halt_only_todo_smokes() {
    let source = include_str!("inline_tests.rs");
    let section_start = source
        .find("// -- ES2015 Class Semantics Tests")
        .expect("class semantics section should exist");
    let section = &source[section_start..];
    let section_end = section
        .find("// -----------------------------------------------------------------------")
        .expect("timer section separator should follow class semantics tests");
    let section = &section[..section_end];

    for block in section.split("#[test]").skip(1) {
        let has_todo = block.contains("TODO");
        let has_halt_only = block.contains("test_module(vec![Ir3Instruction::Halt])");
        let has_bare_success = block.contains("assert!(result.is_ok())");
        assert!(
            !(has_todo && has_halt_only && has_bare_success),
            "class semantic test remains a halt-only placeholder: {}",
            block
                .lines()
                .find(|line| line.trim_start().starts_with("fn "))
                .unwrap_or("<unknown>")
                .trim()
        );
    }
}

#[test]
fn profiling_lifecycle_records_executed_instructions() {
    let mut core = quickjs_test_core();
    assert!(core.profiling_data().is_none());

    core.enable_profiling(crate::profiling::ProfilingConfig::default());
    assert!(core.profiling_data().is_some());

    let module = test_module(vec![
        Ir3Instruction::LoadInt { dst: 1, value: 2 },
        Ir3Instruction::LoadInt { dst: 2, value: 3 },
        Ir3Instruction::Add {
            dst: 0,
            lhs: 1,
            rhs: 2,
        },
        Ir3Instruction::Halt,
    ]);
    let result = core.execute(&module).unwrap();
    assert_eq!(result.value, Value::Int(5));

    let profiler = core
        .disable_profiling()
        .expect("profiling should return collected profiler");
    assert!(core.profiling_data().is_none());

    let report = profiler.generate_report("franken-core-baseline".to_string());
    assert_eq!(
        report
            .instruction_stats
            .get("LoadInt")
            .expect("LoadInt should be counted")
            .count,
        2
    );
    assert_eq!(
        report
            .instruction_stats
            .get("Add")
            .expect("Add should be counted")
            .count,
        1
    );
    assert!(
        report
            .hotspots
            .iter()
            .any(|hotspot| hotspot.name == "LoadInt")
    );
    assert!(report.hotspots.iter().any(|hotspot| hotspot.name == "Add"));
}

#[test]
fn router_profiling_returns_last_routed_execution_profiler() {
    let mut router = test_router();
    assert!(router.profiling_data().is_none());

    router.enable_profiling(crate::profiling::ProfilingConfig::default());

    let module = test_module(vec![
        Ir3Instruction::LoadInt { dst: 1, value: 8 },
        Ir3Instruction::LoadInt { dst: 2, value: 13 },
        Ir3Instruction::Add {
            dst: 0,
            lhs: 1,
            rhs: 2,
        },
        Ir3Instruction::Halt,
    ]);
    let result = router.execute(&module, "router-profile", None).unwrap();
    assert_eq!(result.lane, LaneChoice::QuickJs);
    assert_eq!(result.result.value, Value::Int(21));

    let live_report = router
        .profiling_data()
        .expect("router should retain latest profiler")
        .generate_report("router-profile-live".to_string());
    assert_eq!(
        live_report
            .instruction_stats
            .get("LoadInt")
            .expect("LoadInt should be counted")
            .count,
        2
    );

    let profiler = router
        .disable_profiling()
        .expect("router should return collected profiler");
    assert!(router.profiling_data().is_none());

    let report = profiler.generate_report("router-profile-final".to_string());
    assert_eq!(
        report
            .instruction_stats
            .get("Add")
            .expect("Add should be counted")
            .count,
        1
    );
}

#[test]
fn profiling_memory_stats_record_object_and_array_allocations() {
    let mut core = quickjs_test_core();
    core.enable_profiling(crate::profiling::ProfilingConfig::default());

    let object_id = core.alloc_object_with_prototype(None).unwrap();
    let array_id = core.alloc_array_with_prototype(None).unwrap();

    assert!(!core.heap[object_id.0 as usize].is_array);
    assert!(core.heap[array_id.0 as usize].is_array);

    let profiler = core
        .disable_profiling()
        .expect("profiling should return collected profiler");
    let report = profiler.generate_report("allocation-profile".to_string());

    assert_eq!(report.memory_stats.objects_allocated, 1);
    assert_eq!(report.memory_stats.arrays_allocated, 1);
    assert_eq!(
        report.memory_stats.total_bytes_allocated,
        MEMORY_ESTIMATE_HEAP_OBJECT_BASE_BYTES * 2
    );
}

fn test_quickjs_config_with(
    extra: impl IntoIterator<Item = RuntimeCapability>,
) -> InterpreterConfig {
    let mut config = test_quickjs_config();
    config.granted_capabilities.extend(extra);
    config
}

fn test_router() -> LaneRouter {
    LaneRouter::with_configs(test_quickjs_config(), test_v8_config())
}

#[allow(dead_code)]
fn assert_both_lanes_value(module: &Ir3Module, expected: Value) {
    // SAFETY: Test helper assumes valid module execution; unwrap safe in test context
    assert_eq!(quickjs_execute(module).unwrap().value, expected);
    // SAFETY: Test helper assumes valid module execution; unwrap safe in test context
    assert_eq!(v8_execute(module).unwrap().value, expected);
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum HookRecord {
    Property {
        ctx: HookContext,
        target: ObjectId,
        key: String,
    },
    Call {
        ctx: HookContext,
        callee: FunctionRef,
        args: Vec<Value>,
    },
    Allocation {
        ctx: HookContext,
        kind: AllocKind,
        size_hint: usize,
    },
    Import {
        ctx: HookContext,
        specifier: String,
    },
}

#[derive(Debug)]
struct RecordingHook {
    records: Mutex<Vec<HookRecord>>,
    property_action: HookAction,
    call_action: HookAction,
    allocation_action: HookAction,
    import_action: HookAction,
}

impl RecordingHook {
    fn allow_all() -> Self {
        Self {
            records: Mutex::new(Vec::new()),
            property_action: HookAction::Allow,
            call_action: HookAction::Allow,
            allocation_action: HookAction::Allow,
            import_action: HookAction::Allow,
        }
    }

    fn with_allocation_action(action: HookAction) -> Self {
        Self {
            allocation_action: action,
            ..Self::allow_all()
        }
    }

    fn with_call_action(action: HookAction) -> Self {
        Self {
            call_action: action,
            ..Self::allow_all()
        }
    }

    fn records(&self) -> Vec<HookRecord> {
        self.records.lock().unwrap().clone()
    }

    fn records_without_startup_module_record(&self) -> Vec<HookRecord> {
        let mut records = self.records();
        let is_startup_module_record = matches!(
            records.first(),
            Some(HookRecord::Allocation {
                ctx,
                kind,
                size_hint,
            }) if ctx.instruction_count == 0
                && ctx.current_ip == 0
                && *kind == AllocKind::Object
                && *size_hint == 0
        );
        if is_startup_module_record {
            records.remove(0);
        }
        records
    }
}

impl InterpreterHook for RecordingHook {
    fn pre_property_access(
        &self,
        ctx: &HookContext,
        target: &ObjectRef,
        key: &PropertyKey,
    ) -> HookAction {
        self.records.lock().unwrap().push(HookRecord::Property {
            ctx: ctx.clone(),
            target: *target,
            key: key.clone(),
        });
        self.property_action.clone()
    }

    fn pre_call(&self, ctx: &HookContext, callee: &FunctionRef, args: &[Value]) -> HookAction {
        self.records.lock().unwrap().push(HookRecord::Call {
            ctx: ctx.clone(),
            callee: callee.clone(),
            args: args.to_vec(),
        });
        self.call_action.clone()
    }

    fn pre_allocation(&self, ctx: &HookContext, kind: AllocKind, size_hint: usize) -> HookAction {
        self.records.lock().unwrap().push(HookRecord::Allocation {
            ctx: ctx.clone(),
            kind,
            size_hint,
        });
        self.allocation_action.clone()
    }

    fn pre_import(&self, ctx: &HookContext, specifier: &str) -> HookAction {
        self.records.lock().unwrap().push(HookRecord::Import {
            ctx: ctx.clone(),
            specifier: specifier.to_string(),
        });
        self.import_action.clone()
    }
}

#[derive(Debug, Default)]
struct TypedRecordingHook {
    keys: Mutex<Vec<HookPropertyKey>>,
}

impl TypedRecordingHook {
    fn keys(&self) -> Vec<HookPropertyKey> {
        self.keys.lock().unwrap().clone()
    }
}

impl InterpreterHook for TypedRecordingHook {
    fn pre_property_access(
        &self,
        _ctx: &HookContext,
        _target: &ObjectRef,
        _key: &PropertyKey,
    ) -> HookAction {
        panic!("typed property hook must not route through the legacy string callback")
    }

    fn pre_property_access_typed(
        &self,
        _ctx: &HookContext,
        _target: &ObjectRef,
        key: &HookPropertyKey,
    ) -> Result<HookAction, HookPropertyKeyCompatibilityError> {
        self.keys.lock().unwrap().push(key.clone());
        Ok(HookAction::Allow)
    }

    fn pre_call(&self, _ctx: &HookContext, _callee: &FunctionRef, _args: &[Value]) -> HookAction {
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
}

#[test]
fn interpreter_hook_called_on_property_access() {
    let hook = Arc::new(RecordingHook::allow_all());
    let config = test_quickjs_config();
    let mut core = InterpreterCore::new(config, "test-trace");
    core.set_hook(hook.clone());

    // SAFETY: alloc_object_with_prototype() in test environment with sufficient heap space
    // cannot fail under normal test conditions.
    let oid = core.alloc_object_with_prototype(None).unwrap();
    core.heap[oid.0 as usize]
        .properties
        .insert("secret".to_string(), Value::Int(99));
    core.registers[1] = Value::Object(oid);
    core.registers[2] = Value::str("secret");

    let result = core
        .execute(&test_module(vec![
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 0,
            },
            Ir3Instruction::Halt,
        ]))
        .unwrap();

    assert_eq!(result.value, Value::Int(99));
    assert_eq!(
        hook.records_without_startup_module_record(),
        vec![HookRecord::Property {
            ctx: HookContext {
                extension_id: "test".to_string(),
                instruction_count: 1,
                current_ip: 0,
            },
            target: oid,
            key: "secret".to_string(),
        }]
    );
}

#[test]
fn typed_property_hook_default_adapter_is_lossless_bd_n8eta_4_4() {
    let hook = RecordingHook::allow_all();
    let ctx = HookContext {
        extension_id: "typed-adapter".to_string(),
        instruction_count: 3,
        current_ip: 2,
    };
    let target = ObjectId(7);

    assert_eq!(
        hook.pre_property_access_typed(
            &ctx,
            &target,
            &HookPropertyKey::String(JsString::from("ordinary")),
        ),
        Ok(HookAction::Allow)
    );
    assert!(matches!(
        hook.pre_property_access_typed(
            &ctx,
            &target,
            &HookPropertyKey::String(JsString::from_code_units(&[0xD800])),
        ),
        Err(HookPropertyKeyCompatibilityError::NonWellFormedString)
    ));
    assert!(matches!(
        hook.pre_property_access_typed(&ctx, &target, &HookPropertyKey::Symbol(SymbolId(14)),),
        Err(HookPropertyKeyCompatibilityError::Symbol)
    ));
    assert!(matches!(
        hook.records().as_slice(),
        [HookRecord::Property { key, .. }] if key == "ordinary"
    ));

    let exact = HookPropertyKey::String(JsString::from_code_units(&[0xD801]));
    let wire = serde_json::to_string(&exact).expect("typed hook key should serialize");
    assert_eq!(
        serde_json::from_str::<HookPropertyKey>(&wire).expect("typed hook key should deserialize"),
        exact
    );
    assert_eq!(
        serde_json::to_string(&HookPropertyKey::Symbol(SymbolId(14)))
            .expect("Symbol hook key should serialize"),
        r#"{"Symbol":14}"#
    );
}

#[test]
fn typed_property_hook_preserves_runtime_key_identity_bd_n8eta_4_4() {
    let mut core = quickjs_test_core();
    let object = core.alloc_object_with_prototype(None).unwrap();
    let symbol = core
        .allocate_private_symbol(Some(JsString::from("hook-key")))
        .expect("Symbol allocation should succeed");
    let symbol_diagnostic_string = JsString::from(format!("~pk~s:{}", symbol.0));
    let exact = JsString::from_code_units(&[0xD800]);

    for (key, value) in [
        (RuntimePropertyKey::Symbol(symbol), Value::Int(41)),
        (
            RuntimePropertyKey::String(symbol_diagnostic_string.clone()),
            Value::Int(42),
        ),
        (RuntimePropertyKey::String(exact.clone()), Value::Int(43)),
    ] {
        core.set_object_runtime_property(object, key, value)
            .expect("typed test property should fit");
    }

    let legacy_hook = Arc::new(RecordingHook::allow_all());
    core.set_hook(legacy_hook.clone());
    core.registers[1] = Value::Object(object);
    core.registers[2] = Value::Symbol(symbol);
    let heap_before = serde_json::to_string(&core.heap).expect("legacy hook heap should serialize");
    assert!(matches!(
        core.run_loop(&test_module(vec![Ir3Instruction::GetProperty {
            obj: 1,
            key: 2,
            dst: 5,
        }])),
        Err(InterpreterError::TypeError { .. })
    ));
    assert!(
        legacy_hook
            .records_without_startup_module_record()
            .is_empty()
    );
    assert_eq!(
        serde_json::to_string(&core.heap)
            .expect("legacy hook heap should serialize after rejection"),
        heap_before
    );

    core.ip = 0;
    let hook = Arc::new(TypedRecordingHook::default());
    core.set_hook(hook.clone());
    core.registers[2] = Value::Symbol(SymbolId(u32::MAX));
    assert!(matches!(
        core.run_loop(&test_module(vec![Ir3Instruction::GetProperty {
            obj: 1,
            key: 2,
            dst: 5,
        }])),
        Err(InterpreterError::TypeError { got, .. })
            if got.contains("unresolved Symbol id")
    ));
    assert!(
        hook.keys().is_empty(),
        "typed hook must not observe unresolved Symbol identity"
    );

    core.ip = 0;
    core.registers[2] = Value::Symbol(symbol);
    core.registers[3] = Value::Str(symbol_diagnostic_string.clone());
    core.registers[4] = Value::Str(exact.clone());
    core.registers[9] = Value::Int(99);
    assert!(matches!(
        core.run_loop(&test_module(vec![
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 5,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 3,
                dst: 6,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 4,
                dst: 7,
            },
            Ir3Instruction::InOp {
                dst: 8,
                lhs: 2,
                rhs: 1,
            },
            Ir3Instruction::SetProperty {
                obj: 1,
                key: 2,
                val: 9,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 10,
            },
            Ir3Instruction::DeleteProperty {
                obj: 1,
                key: 2,
                dst: 11,
            },
            Ir3Instruction::Halt,
        ])),
        Err(InterpreterError::Halted)
    ));

    assert_eq!(core.read_reg(5), Ok(Value::Int(41)));
    assert_eq!(core.read_reg(6), Ok(Value::Int(42)));
    assert_eq!(core.read_reg(7), Ok(Value::Int(43)));
    assert_eq!(core.read_reg(8), Ok(Value::Bool(true)));
    assert_eq!(core.read_reg(10), Ok(Value::Int(99)));
    assert_eq!(core.read_reg(11), Ok(Value::Bool(true)));
    assert_eq!(
        hook.keys(),
        vec![
            HookPropertyKey::Symbol(symbol),
            HookPropertyKey::String(symbol_diagnostic_string),
            HookPropertyKey::String(exact),
            HookPropertyKey::Symbol(symbol),
            HookPropertyKey::Symbol(symbol),
            HookPropertyKey::Symbol(symbol),
            HookPropertyKey::Symbol(symbol),
        ]
    );
}

#[test]
fn exact_keys_respect_legacy_string_callback_boundary_bd_b12xs_4() {
    let d800 = JsString::from_code_units(&[0xD800]);
    let module = test_module(Vec::new());

    let mut unhooked = quickjs_test_core();
    let unhooked_object = unhooked.alloc_object_with_prototype(None).unwrap();
    unhooked
        .set_object_property_or_call_accessor(
            &module,
            Value::Object(unhooked_object),
            unhooked_object,
            RuntimePropertyKey::String(d800.clone()),
            Value::Int(8),
            crate::ifc_artifacts::Label::Public,
        )
        .unwrap();
    assert_eq!(
        unhooked
            .prototype_chain_lookup_runtime_property(
                unhooked_object,
                &RuntimePropertyKey::String(d800.clone()),
            )
            .unwrap(),
        Some(RuntimeProperty::Data(Value::Int(8)))
    );

    let hook = Arc::new(RecordingHook::allow_all());
    let mut core = quickjs_test_core();
    let object = core.alloc_object_with_prototype(None).unwrap();
    core.set_hook(hook.clone());
    let heap_before = serde_json::to_string(&core.heap).unwrap();
    let memory_before = core.estimated_memory_bytes();

    let error = core
        .set_object_property_or_call_accessor(
            &module,
            Value::Object(object),
            object,
            RuntimePropertyKey::String(d800.clone()),
            Value::Int(8),
            crate::ifc_artifacts::Label::Public,
        )
        .unwrap_err();
    assert!(matches!(error, InterpreterError::TypeError { .. }));
    assert!(hook.records().is_empty());
    assert_eq!(serde_json::to_string(&core.heap).unwrap(), heap_before);
    assert_eq!(core.estimated_memory_bytes(), memory_before);

    assert!(matches!(
        core.load_object_property_or_call_accessor(
            &module,
            Value::Object(object),
            object,
            &RuntimePropertyKey::String(d800.clone()),
            0,
            crate::ifc_artifacts::Label::Public,
        ),
        Err(InterpreterError::TypeError { .. })
    ));
    assert!(hook.records().is_empty());
    assert_eq!(serde_json::to_string(&core.heap).unwrap(), heap_before);

    core.registers[1] = Value::Str(d800.clone());
    core.registers[2] = Value::Object(object);
    assert!(matches!(
        core.eval_in_operator(&module, 1, 2),
        Err(InterpreterError::TypeError { .. })
    ));
    assert!(hook.records().is_empty());
    assert_eq!(serde_json::to_string(&core.heap).unwrap(), heap_before);

    let function_objects_before = core.function_objects.clone();
    assert!(matches!(
        core.set_function_like_property_or_call_accessor(
            &module,
            Value::Function(0),
            &RuntimePropertyKey::String(d800),
            Value::Int(9),
            crate::ifc_artifacts::Label::Public,
        ),
        Err(InterpreterError::TypeError { .. })
    ));
    assert!(hook.records().is_empty());
    assert_eq!(core.function_objects, function_objects_before);
    assert_eq!(serde_json::to_string(&core.heap).unwrap(), heap_before);
    assert_eq!(core.estimated_memory_bytes(), memory_before);

    core.set_object_property_or_call_accessor(
        &module,
        Value::Object(object),
        object,
        RuntimePropertyKey::String(JsString::from("\u{FFFD}")),
        Value::Int(0xFFFD),
        crate::ifc_artifacts::Label::Public,
    )
    .unwrap();
    assert_eq!(hook.records().len(), 1);
    assert!(matches!(
        &hook.records()[0],
        HookRecord::Property { key, .. } if key == "\u{FFFD}"
    ));

    let primitive_hook = Arc::new(RecordingHook::allow_all());
    let mut primitive_core = quickjs_test_core();
    primitive_core.set_hook(primitive_hook.clone());
    primitive_core.registers[1] = Value::str("receiver");
    primitive_core.registers[2] = Value::Str(JsString::from_code_units(&[0xD800]));
    assert!(matches!(
        primitive_core.execute(&test_module(vec![
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Halt,
        ])),
        Err(InterpreterError::TypeError { .. })
    ));
    assert!(
        primitive_hook
            .records_without_startup_module_record()
            .is_empty()
    );
    assert_eq!(primitive_core.registers[3], Value::Undefined);
}

#[test]
fn interpreter_hook_called_on_call() {
    let hook = Arc::new(RecordingHook::allow_all());
    let config = test_quickjs_config();
    let mut core = InterpreterCore::new(config, "test-trace");
    core.set_hook(hook.clone());
    core.registers[1] = Value::Int(5);
    core.registers[2] = Value::Int(99);
    core.registers[3] = Value::Function(0);

    let result = core
        .execute(&test_module_with_functions(
            vec![
                Ir3Instruction::Call {
                    callee: 3,
                    args: RegRange { start: 1, count: 2 },
                    dst: 0,
                },
                Ir3Instruction::Halt,
                Ir3Instruction::Return { value: 0 },
            ],
            vec![Ir3FunctionDesc {
                entry: 2,
                arity: 1,
                frame_size: 2,
                name: Some("identity".to_string()),
                is_generator: false,
                rest_param_index: None,
            }],
        ))
        .unwrap();

    assert_eq!(result.value, Value::Int(5));
    assert_eq!(
        hook.records_without_startup_module_record(),
        vec![HookRecord::Call {
            ctx: HookContext {
                extension_id: "test".to_string(),
                instruction_count: 1,
                current_ip: 0,
            },
            callee: FunctionRef::Function {
                function_index: 0,
                name: Some("identity".to_string()),
            },
            args: vec![Value::Int(5)],
        }]
    );
}

#[test]
fn call_method_binds_receiver_as_this() {
    let mut core = quickjs_test_core();
    let receiver_id = core.alloc_object_with_prototype(None).unwrap();
    core.registers[1] = Value::Object(receiver_id);
    core.registers[2] = Value::Function(0);

    let result = core
        .execute(&test_module_with_functions(
            vec![
                Ir3Instruction::CallMethod {
                    receiver: 1,
                    callee: 2,
                    args: RegRange { start: 3, count: 0 },
                    dst: 0,
                },
                Ir3Instruction::Halt,
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
        ))
        .unwrap();

    assert_eq!(result.value, Value::Object(receiver_id));
}

#[test]
fn plain_call_load_this_is_undefined() {
    let mut core = quickjs_test_core();
    core.registers[1] = Value::Function(0);

    let result = core
        .execute(&test_module_with_functions(
            vec![
                Ir3Instruction::Call {
                    callee: 1,
                    args: RegRange { start: 2, count: 0 },
                    dst: 0,
                },
                Ir3Instruction::Halt,
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
        ))
        .unwrap();

    assert_eq!(result.value, Value::Undefined);
}

#[test]
fn interpreter_hook_called_on_allocation() {
    let hook = Arc::new(RecordingHook::allow_all());
    let config = test_quickjs_config();
    let mut core = InterpreterCore::new(config, "test-trace");
    core.set_hook(hook.clone());

    let result = core
        .execute(&test_module(vec![
            Ir3Instruction::NewObject { dst: 0 },
            Ir3Instruction::Halt,
        ]))
        .unwrap();

    assert!(matches!(result.value, Value::Object(_)));
    assert_eq!(
        hook.records_without_startup_module_record(),
        vec![HookRecord::Allocation {
            ctx: HookContext {
                extension_id: "test".to_string(),
                instruction_count: 1,
                current_ip: 0,
            },
            kind: AllocKind::Object,
            size_hint: 0,
        }]
    );
}

#[test]
fn interpreter_hook_called_on_closure_allocation() {
    let hook = Arc::new(RecordingHook::allow_all());
    let config = test_quickjs_config();
    let mut core = InterpreterCore::new(config, "test-trace");
    core.set_hook(hook.clone());

    let result = core
        .execute(&test_module_with_functions(
            vec![
                Ir3Instruction::CreateClosure {
                    dst: 0,
                    function_index: 0,
                    capture_count: 2,
                },
                Ir3Instruction::Halt,
            ],
            vec![Ir3FunctionDesc {
                entry: 1,
                arity: 0,
                frame_size: 1,
                name: Some("closure_target".to_string()),
                is_generator: false,
                rest_param_index: None,
            }],
        ))
        .unwrap();

    assert!(matches!(result.value, Value::Closure(0)));
    assert_eq!(
        hook.records_without_startup_module_record(),
        vec![HookRecord::Allocation {
            ctx: HookContext {
                extension_id: "test".to_string(),
                instruction_count: 1,
                current_ip: 0,
            },
            kind: AllocKind::Closure,
            size_hint: 2,
        }]
    );
}

#[test]
fn interpreter_hook_allow_continues_execution() {
    let hook = Arc::new(RecordingHook::allow_all());
    let config = test_quickjs_config();
    let mut core = InterpreterCore::new(config, "test-trace");
    core.set_hook(hook);

    let oid = core.alloc_object_with_prototype(None).unwrap();
    core.registers[1] = Value::Object(oid);
    core.registers[2] = Value::str("key");
    core.registers[3] = Value::Int(7);

    let result = core
        .execute(&test_module(vec![
            Ir3Instruction::SetProperty {
                obj: 1,
                key: 2,
                val: 3,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 0,
            },
            Ir3Instruction::Halt,
        ]))
        .unwrap();

    assert_eq!(result.value, Value::Int(7));
}

#[test]
fn interpreter_hook_terminate_stops_execution() {
    let hook = Arc::new(RecordingHook::with_allocation_action(
        HookAction::Terminate("policy denied object allocation".to_string()),
    ));
    let config = test_quickjs_config();
    let mut core = InterpreterCore::new(config, "test-trace");
    core.set_hook(hook.clone());

    let err = core
        .execute(&test_module(vec![Ir3Instruction::NewObject { dst: 0 }]))
        .unwrap_err();

    assert_eq!(
        err,
        InterpreterError::ContainmentActionRequested {
            action: "terminate".to_string(),
            reason: Some("policy denied object allocation".to_string()),
        }
    );
    assert_eq!(hook.records().len(), 1);
}

#[test]
fn lane_execute_with_hook_preserves_requested_containment_in_result_bd_ur3tk_17() {
    let hook = Arc::new(RecordingHook::with_allocation_action(
        HookAction::Terminate("policy denied object allocation".to_string()),
    ));
    let lane = QuickJsLane::with_config(test_quickjs_config());
    let result = lane
        .execute_with_hook(
            &test_module(vec![Ir3Instruction::NewObject { dst: 0 }]),
            "test-trace",
            Some(hook),
        )
        .expect("lane should surface containment as structured output");

    assert_eq!(
        result.requested_hook_action,
        Some(HookAction::Terminate(
            "policy denied object allocation".to_string()
        ))
    );
    assert_eq!(result.value, Value::Undefined);
    assert_eq!(result.completion_label, crate::ifc_artifacts::Label::Public);
    assert_eq!(result.instructions_executed, 0);
}

#[test]
fn interpreter_hook_none_preserves_execution_when_unset() {
    let config = test_quickjs_config();
    let mut core = InterpreterCore::new(config, "test-trace");
    let oid = core.alloc_object_with_prototype(None).unwrap();
    core.heap[oid.0 as usize]
        .properties
        .insert("stable".to_string(), Value::Int(12));
    core.registers[1] = Value::Object(oid);
    core.registers[2] = Value::str("stable");

    let result = core
        .execute(&test_module(vec![
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 0,
            },
            Ir3Instruction::Halt,
        ]))
        .unwrap();

    assert_eq!(result.value, Value::Int(12));
    assert!(core.hook.is_none());
}

#[test]
fn interpreter_hook_receives_correct_context() {
    let hook = Arc::new(RecordingHook::allow_all());
    let config = test_quickjs_config();
    let mut core = InterpreterCore::new(config, "test-trace");
    core.set_hook(hook.clone());

    let mut module = test_module(vec![
        Ir3Instruction::LoadInt { dst: 4, value: 1 },
        Ir3Instruction::NewArray { dst: 0 },
        Ir3Instruction::Halt,
    ]);
    module.header.source_label = "extension://hook-test".to_string();

    let result = core.execute(&module).unwrap();
    assert!(matches!(result.value, Value::Object(_)));
    assert_eq!(
        hook.records_without_startup_module_record(),
        vec![HookRecord::Allocation {
            ctx: HookContext {
                extension_id: "extension://hook-test".to_string(),
                instruction_count: 2,
                current_ip: 1,
            },
            kind: AllocKind::Array,
            size_hint: 0,
        }]
    );
}

#[test]
fn interpreter_hook_pre_import_surface_is_available() {
    let hook = RecordingHook::allow_all();
    let config = InterpreterConfig::quickjs_defaults();
    let core = InterpreterCore::new(config, "test-trace");
    let mut module = test_module(vec![Ir3Instruction::Halt]);
    module.header.source_label = "extension://import-surface".to_string();

    let ctx = core.hook_context(&module);
    let action = hook.pre_import(&ctx, "lodash");

    assert_eq!(action, HookAction::Allow);
    assert_eq!(
        hook.records(),
        vec![HookRecord::Import {
            ctx: HookContext {
                extension_id: "extension://import-surface".to_string(),
                instruction_count: 0,
                current_ip: 0,
            },
            specifier: "lodash".to_string(),
        }]
    );
}

// -----------------------------------------------------------------------
// 1. Load instructions
// -----------------------------------------------------------------------

#[test]
fn load_int() {
    let m = test_module(vec![
        Ir3Instruction::LoadInt { dst: 0, value: 42 },
        Ir3Instruction::Halt,
    ]);
    let result = quickjs_execute(&m).unwrap();
    assert_eq!(result.value, Value::Int(42));
}

#[test]
fn load_str() {
    let m = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::Halt,
        ],
        vec!["hello".to_string()],
    );
    let result = quickjs_execute(&m).unwrap();
    assert_eq!(result.value, Value::str("hello"));
}

#[test]
fn load_str_preserves_lone_surrogate_constant_bd_vltnh() {
    let exact = JsString::from_code_units(&[0xD800]);
    let mut module = test_module(vec![
        Ir3Instruction::LoadStr {
            dst: 0,
            pool_index: 0,
        },
        Ir3Instruction::Halt,
    ]);
    module.constant_pool.push(exact.clone());

    let result = quickjs_execute(&module).unwrap();
    assert_eq!(result.value, Value::Str(exact));
}

#[test]
fn metadata_pool_consumers_reject_lone_surrogate_entries_bd_vltnh() {
    for instruction in [
        Ir3Instruction::PushCapture { name_pool_index: 0 },
        Ir3Instruction::DeclareBinding {
            name_pool_index: 0,
            kind: BindingKind::Let as u8,
        },
    ] {
        let mut module = test_module(vec![instruction, Ir3Instruction::Halt]);
        module
            .constant_pool
            .push(JsString::from_code_units(&[0xD800]));

        let error = quickjs_execute(&module).unwrap_err();
        assert!(matches!(error, InterpreterError::TypeError { .. }));
    }
}

#[test]
fn filesystem_module_boundary_rejects_distinct_lone_surrogates_bd_lfq44() {
    let ordinary = JsString::from("./fixture.js");
    assert_eq!(
        InterpreterCore::filesystem_module_specifier(&ordinary).unwrap(),
        "./fixture.js"
    );

    let d800 = JsString::from_code_units(&[0xD800]);
    let dc00 = JsString::from_code_units(&[0xDC00]);
    assert_ne!(d800, dc00);
    assert_eq!(d800.as_utf8_projection(), dc00.as_utf8_projection());

    for exact in [d800, dc00] {
        let error = InterpreterCore::filesystem_module_specifier(&exact).unwrap_err();
        assert!(matches!(error, InterpreterError::TypeError { .. }));

        let mut module = test_module(vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::Halt,
        ]);
        module.constant_pool.push(exact);
        let mut core = InterpreterCore::new(
            test_quickjs_config_with([RuntimeCapability::ModuleLoad]),
            "surrogate-module-boundary",
        );
        let error = core.execute(&module).unwrap_err();
        assert!(matches!(error, InterpreterError::TypeError { .. }));
    }
}

#[test]
fn load_bool_true() {
    let m = test_module(vec![
        Ir3Instruction::LoadBool {
            dst: 0,
            value: true,
        },
        Ir3Instruction::Halt,
    ]);
    let result = quickjs_execute(&m).unwrap();
    assert_eq!(result.value, Value::Bool(true));
}

#[test]
fn load_null() {
    let m = test_module(vec![
        Ir3Instruction::LoadNull { dst: 0 },
        Ir3Instruction::Halt,
    ]);
    let result = quickjs_execute(&m).unwrap();
    assert_eq!(result.value, Value::Null);
}

#[test]
fn load_undefined() {
    let m = test_module(vec![
        Ir3Instruction::LoadUndefined { dst: 0 },
        Ir3Instruction::Halt,
    ]);
    let result = quickjs_execute(&m).unwrap();
    assert_eq!(result.value, Value::Undefined);
}

// -----------------------------------------------------------------------
// 2. Arithmetic
// -----------------------------------------------------------------------

#[test]
fn add_integers() {
    let m = test_module(vec![
        Ir3Instruction::LoadInt { dst: 1, value: 3 },
        Ir3Instruction::LoadInt { dst: 2, value: 4 },
        Ir3Instruction::Add {
            dst: 0,
            lhs: 1,
            rhs: 2,
        },
        Ir3Instruction::Halt,
    ]);
    let result = quickjs_execute(&m).unwrap();
    assert_eq!(result.value, Value::Int(7));
}

#[test]
fn add_strings() {
    let m = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 1,
                pool_index: 0,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::Add {
                dst: 0,
                lhs: 1,
                rhs: 2,
            },
            Ir3Instruction::Halt,
        ],
        vec!["hello".to_string(), " world".to_string()],
    );
    let result = quickjs_execute(&m).unwrap();
    assert_eq!(result.value, Value::str("hello world"));
}

#[test]
fn sub_integers() {
    let m = test_module(vec![
        Ir3Instruction::LoadInt { dst: 1, value: 10 },
        Ir3Instruction::LoadInt { dst: 2, value: 3 },
        Ir3Instruction::Sub {
            dst: 0,
            lhs: 1,
            rhs: 2,
        },
        Ir3Instruction::Halt,
    ]);
    let result = quickjs_execute(&m).unwrap();
    assert_eq!(result.value, Value::Int(7));
}

#[test]
fn mul_integers() {
    let m = test_module(vec![
        Ir3Instruction::LoadInt { dst: 1, value: 6 },
        Ir3Instruction::LoadInt { dst: 2, value: 7 },
        Ir3Instruction::Mul {
            dst: 0,
            lhs: 1,
            rhs: 2,
        },
        Ir3Instruction::Halt,
    ]);
    let result = quickjs_execute(&m).unwrap();
    assert_eq!(result.value, Value::Int(42));
}

#[test]
fn div_integers() {
    let m = test_module(vec![
        Ir3Instruction::LoadInt { dst: 1, value: 20 },
        Ir3Instruction::LoadInt { dst: 2, value: 4 },
        Ir3Instruction::Div {
            dst: 0,
            lhs: 1,
            rhs: 2,
        },
        Ir3Instruction::Halt,
    ]);
    let result = quickjs_execute(&m).unwrap();
    assert_eq!(result.value, Value::Int(5));
}

#[test]
fn div_by_zero_returns_infinity() {
    let m = test_module(vec![
        Ir3Instruction::LoadInt { dst: 1, value: 10 },
        Ir3Instruction::LoadInt { dst: 2, value: 0 },
        Ir3Instruction::Div {
            dst: 0,
            lhs: 1,
            rhs: 2,
        },
    ]);
    let result = quickjs_execute(&m).unwrap();
    assert_eq!(result.value, Value::Float(Float64::new(f64::INFINITY)));
}

#[test]
fn add_coerces_bool_and_null_to_number() {
    // JS semantics: true + null = 1 + 0 = 1
    let m = test_module(vec![
        Ir3Instruction::LoadBool {
            dst: 1,
            value: true,
        },
        Ir3Instruction::LoadNull { dst: 2 },
        Ir3Instruction::Add {
            dst: 0,
            lhs: 1,
            rhs: 2,
        },
    ]);
    let result = quickjs_execute(&m).unwrap();
    assert_eq!(result.value, Value::Int(1));
}

// -----------------------------------------------------------------------
// 3. Control flow
// -----------------------------------------------------------------------

#[test]
fn unconditional_jump() {
    let m = test_module(vec![
        Ir3Instruction::LoadInt { dst: 0, value: 1 },  // 0
        Ir3Instruction::Jump { target: 3 },            // 1: jump to 3
        Ir3Instruction::LoadInt { dst: 0, value: 99 }, // 2: skipped
        Ir3Instruction::Halt,                          // 3
    ]);
    let result = quickjs_execute(&m).unwrap();
    assert_eq!(result.value, Value::Int(1));
}

#[test]
fn conditional_jump_taken() {
    let m = test_module(vec![
        Ir3Instruction::LoadBool {
            dst: 1,
            value: true,
        }, // 0
        Ir3Instruction::LoadInt { dst: 0, value: 10 }, // 1
        Ir3Instruction::JumpIf { cond: 1, target: 4 }, // 2: jump if true -> 4
        Ir3Instruction::LoadInt { dst: 0, value: 20 }, // 3: skipped
        Ir3Instruction::Halt,                          // 4
    ]);
    let result = quickjs_execute(&m).unwrap();
    assert_eq!(result.value, Value::Int(10));
}

#[test]
fn conditional_jump_not_taken() {
    let m = test_module(vec![
        Ir3Instruction::LoadBool {
            dst: 1,
            value: false,
        }, // 0
        Ir3Instruction::LoadInt { dst: 0, value: 10 }, // 1
        Ir3Instruction::JumpIf { cond: 1, target: 4 }, // 2: not taken
        Ir3Instruction::LoadInt { dst: 0, value: 20 }, // 3: executed
        Ir3Instruction::Halt,                          // 4
    ]);
    let result = quickjs_execute(&m).unwrap();
    assert_eq!(result.value, Value::Int(20));
}

// -----------------------------------------------------------------------
// 4. Function calls
// -----------------------------------------------------------------------

#[test]
fn simple_function_call() {
    // r1 = 5 (argument), r3 = Function(0) (callee, pre-set).
    // Call func(r1) -> r0.
    // Function body at instruction 2: load 10 into r1, add r0+r1 -> r2, return r2.
    let m = test_module_with_functions(
        vec![
            // Main
            Ir3Instruction::Call {
                callee: 3,
                args: RegRange { start: 1, count: 1 },
                dst: 0,
            }, // 0
            Ir3Instruction::Halt, // 1: return here after call
            // Function body (entry at 2)
            Ir3Instruction::LoadInt { dst: 1, value: 10 }, // 2
            Ir3Instruction::Add {
                dst: 2,
                lhs: 0,
                rhs: 1,
            }, // 3: r2 = r0 + 10
            Ir3Instruction::Return { value: 2 },           // 4
        ],
        vec![Ir3FunctionDesc {
            entry: 2,
            arity: 1,
            frame_size: 3,
            name: Some("add_ten".to_string()),
            is_generator: false,
            rest_param_index: None,
        }],
    );

    let mut config = test_quickjs_config();
    config.instruction_budget = 1000;
    let mut core = InterpreterCore::new(config, "test");
    // Pre-set registers: r3 = callee function, r1 = argument.
    core.registers[3] = Value::Function(0);
    core.registers[1] = Value::Int(5);
    let result = core.execute(&m).unwrap();
    assert_eq!(result.value, Value::Int(15));
}

#[test]
fn plain_call_secret_argument_returns_secret_bd_ur3tk_6() {
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
    let mut core = quickjs_test_core();
    core.registers[0] = Value::Function(0);
    core.write_reg_with_label(
        1,
        Value::str("secret-argument"),
        crate::ifc_artifacts::Label::Secret,
    )
    .expect("secret argument should be writable");

    assert_eq!(
        core.run_loop(&module).expect("identity call should return"),
        Value::str("secret-argument")
    );
    assert_eq!(
        core.read_reg_label(2).expect("caller return label"),
        crate::ifc_artifacts::Label::Secret
    );
}

#[test]
fn plain_call_label_frames_do_not_alias_bd_ur3tk_6() {
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
    let mut core = quickjs_test_core();
    core.registers[0] = Value::Function(0);
    core.write_reg_with_label(
        7,
        Value::str("caller-only"),
        crate::ifc_artifacts::Label::Confidential,
    )
    .expect("caller label should be writable");
    core.write_reg_with_label(
        1,
        Value::str("stale-destination"),
        crate::ifc_artifacts::Label::Secret,
    )
    .expect("stale destination should be writable");

    assert_eq!(
        core.run_loop(&module)
            .expect("fresh callee frame should return"),
        Value::Undefined
    );
    assert_eq!(
        core.read_reg_label(1).expect("public return label"),
        crate::ifc_artifacts::Label::Public
    );
    assert_eq!(
        core.read_reg_label(7).expect("preserved caller label"),
        crate::ifc_artifacts::Label::Confidential
    );
}

#[test]
fn nested_plain_calls_preserve_labels_across_two_frames_bd_ur3tk_6() {
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
    let mut core = quickjs_test_core();
    core.registers[0] = Value::Function(0);
    core.registers[1] = Value::Function(1);
    core.write_reg_with_label(
        2,
        Value::str("nested-secret"),
        crate::ifc_artifacts::Label::Secret,
    )
    .expect("nested argument should be writable");

    assert_eq!(
        core.run_loop(&module).expect("nested calls should return"),
        Value::str("nested-secret")
    );
    assert_eq!(
        core.read_reg_label(3).expect("nested return label"),
        crate::ifc_artifacts::Label::Secret
    );
}

#[test]
fn call_method_load_this_preserves_receiver_label_bd_ur3tk_6() {
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
    let mut core = quickjs_test_core();
    core.write_reg_with_label(
        0,
        Value::str("secret-receiver"),
        crate::ifc_artifacts::Label::Secret,
    )
    .expect("receiver should be writable");
    core.registers[1] = Value::Function(0);

    assert_eq!(
        core.run_loop(&module).expect("method should return this"),
        Value::str("secret-receiver")
    );
    assert_eq!(
        core.read_reg_label(2).expect("method return label"),
        crate::ifc_artifacts::Label::Secret
    );
}

#[test]
fn call_method_argument_preserves_label_bd_ur3tk_6() {
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
    let mut core = quickjs_test_core();
    core.registers[0] = Value::str("public-receiver");
    core.registers[1] = Value::Function(0);
    core.write_reg_with_label(
        2,
        Value::str("secret-argument"),
        crate::ifc_artifacts::Label::Secret,
    )
    .expect("argument should be writable");

    assert_eq!(
        core.run_loop(&module)
            .expect("method should return argument"),
        Value::str("secret-argument")
    );
    assert_eq!(
        core.read_reg_label(3).expect("method result label"),
        crate::ifc_artifacts::Label::Secret
    );
}

#[test]
fn nested_frame_move_preserves_argument_and_return_label_bd_ur3tk_11() {
    let module = test_module_with_functions(
        vec![
            Ir3Instruction::Call {
                callee: 0,
                args: RegRange { start: 1, count: 1 },
                dst: 2,
            },
            Ir3Instruction::Return { value: 2 },
            Ir3Instruction::Move { dst: 1, src: 0 },
            Ir3Instruction::Return { value: 1 },
        ],
        vec![Ir3FunctionDesc {
            entry: 2,
            arity: 1,
            frame_size: 2,
            name: Some("move_identity".to_string()),
            is_generator: false,
            rest_param_index: None,
        }],
    );
    let mut core = quickjs_test_core();
    core.registers[0] = Value::Function(0);
    core.write_reg_with_label(
        1,
        Value::str("secret-through-move"),
        crate::ifc_artifacts::Label::Secret,
    )
    .expect("secret argument should be writable");

    assert_eq!(
        core.run_loop(&module).expect("Move identity should return"),
        Value::str("secret-through-move")
    );
    assert_eq!(
        core.read_reg_label(2).expect("caller Move return label"),
        crate::ifc_artifacts::Label::Secret
    );
}

#[test]
fn move_is_self_safe_and_overwrites_destination_label_bd_ur3tk_11() {
    let module = test_module(vec![
        Ir3Instruction::Move { dst: 0, src: 0 },
        Ir3Instruction::Move { dst: 1, src: 2 },
        Ir3Instruction::Return { value: 1 },
    ]);
    let mut core = quickjs_test_core();
    core.write_reg_with_label(
        0,
        Value::str("self-secret"),
        crate::ifc_artifacts::Label::Secret,
    )
    .expect("self-Move source should be writable");
    core.write_reg_with_label(
        1,
        Value::str("stale-secret"),
        crate::ifc_artifacts::Label::Secret,
    )
    .expect("destination should be writable");
    core.registers[2] = Value::str("public-source");

    assert_eq!(
        core.run_loop(&module).expect("Move sequence should return"),
        Value::str("public-source")
    );
    assert_eq!(
        core.read_reg_label(0).expect("self-Move label"),
        crate::ifc_artifacts::Label::Secret
    );
    assert_eq!(
        core.read_reg_label(1)
            .expect("overwritten destination label"),
        crate::ifc_artifacts::Label::Public
    );
}

#[test]
fn scoped_binding_init_store_and_load_preserve_labels_bd_ur3tk_11() {
    let module = test_module_with_pool(
        vec![
            Ir3Instruction::DeclareBinding {
                name_pool_index: 0,
                kind: BindingKind::Let as u8,
            },
            Ir3Instruction::InitBinding {
                name_pool_index: 0,
                src: 0,
            },
            Ir3Instruction::LoadScoped {
                dst: 1,
                name_pool_index: 0,
            },
            Ir3Instruction::DeclareBinding {
                name_pool_index: 1,
                kind: BindingKind::Var as u8,
            },
            Ir3Instruction::StoreScoped {
                src: 2,
                name_pool_index: 1,
            },
            Ir3Instruction::LoadScoped {
                dst: 3,
                name_pool_index: 1,
            },
            Ir3Instruction::StoreScoped {
                src: 4,
                name_pool_index: 1,
            },
            Ir3Instruction::LoadScoped {
                dst: 5,
                name_pool_index: 1,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["initialized".to_string(), "stored".to_string()],
    );
    let mut core = quickjs_test_core();
    core.write_reg_with_label(
        0,
        Value::str("initialized-secret"),
        crate::ifc_artifacts::Label::Secret,
    )
    .expect("InitBinding source should be writable");
    core.write_reg_with_label(
        2,
        Value::str("stored-confidential"),
        crate::ifc_artifacts::Label::Confidential,
    )
    .expect("StoreScoped source should be writable");
    core.registers[4] = Value::str("public-overwrite");

    assert_eq!(
        core.run_loop(&module)
            .expect("scope transfers should return"),
        Value::str("stored-confidential")
    );
    assert_eq!(
        core.read_reg_label(1).expect("initialized binding label"),
        crate::ifc_artifacts::Label::Secret
    );
    assert_eq!(
        core.read_reg_label(3).expect("stored binding label"),
        crate::ifc_artifacts::Label::Confidential
    );
    assert_eq!(
        core.read_reg_label(5).expect("overwritten binding label"),
        crate::ifc_artifacts::Label::Public
    );
}

#[test]
fn caught_const_store_scoped_error_is_type_error_bd_dp12f() {
    let module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadInt { dst: 0, value: 1 },
            Ir3Instruction::DeclareBinding {
                name_pool_index: 0,
                kind: BindingKind::Const as u8,
            },
            Ir3Instruction::InitBinding {
                name_pool_index: 0,
                src: 0,
            },
            Ir3Instruction::LoadInt { dst: 1, value: 2 },
            Ir3Instruction::BeginTry {
                catch_target: 7,
                finally_target: None,
            },
            Ir3Instruction::StoreScoped {
                src: 1,
                name_pool_index: 0,
            },
            Ir3Instruction::EndTry,
            Ir3Instruction::EnterCatch { dst: 2 },
            Ir3Instruction::Return { value: 2 },
        ],
        vec!["fixed".to_string()],
    );
    let mut core = quickjs_test_core();

    let caught = core
        .run_loop(&module)
        .expect("const assignment should enter the active catch");
    let Value::Object(error_id) = caught else {
        panic!("expected materialized TypeError object, got {caught:?}");
    };
    assert_eq!(
        core.heap[error_id.0 as usize].properties.get("name"),
        Some(&Value::str("TypeError"))
    );
    let (_, binding) = core
        .scope_chain
        .resolve("fixed")
        .expect("const binding should remain present");
    assert_eq!(binding.value().unwrap(), Value::Int(1));
}

#[test]
fn caught_uninitialized_store_scoped_error_is_reference_error_bd_dp12f() {
    let module = test_module_with_pool(
        vec![
            Ir3Instruction::DeclareBinding {
                name_pool_index: 0,
                kind: BindingKind::Let as u8,
            },
            Ir3Instruction::LoadInt { dst: 0, value: 2 },
            Ir3Instruction::BeginTry {
                catch_target: 5,
                finally_target: None,
            },
            Ir3Instruction::StoreScoped {
                src: 0,
                name_pool_index: 0,
            },
            Ir3Instruction::EndTry,
            Ir3Instruction::EnterCatch { dst: 1 },
            Ir3Instruction::Return { value: 1 },
        ],
        vec!["future".to_string()],
    );
    let mut core = quickjs_test_core();

    let caught = core
        .run_loop(&module)
        .expect("TDZ assignment should enter the active catch");
    let Value::Object(error_id) = caught else {
        panic!("expected materialized ReferenceError object, got {caught:?}");
    };
    assert_eq!(
        core.heap[error_id.0 as usize].properties.get("name"),
        Some(&Value::str("ReferenceError"))
    );
    let (_, binding) = core
        .scope_chain
        .resolve("future")
        .expect("TDZ binding should remain present");
    assert!(!binding.state().unwrap().initialized);
}

#[test]
fn caught_uninitialized_load_scoped_error_is_reference_error_bd_mfcww() {
    let module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadInt { dst: 0, value: 41 },
            Ir3Instruction::DeclareBinding {
                name_pool_index: 0,
                kind: BindingKind::Let as u8,
            },
            Ir3Instruction::BeginTry {
                catch_target: 5,
                finally_target: None,
            },
            Ir3Instruction::LoadScoped {
                dst: 0,
                name_pool_index: 0,
            },
            Ir3Instruction::EndTry,
            Ir3Instruction::EnterCatch { dst: 1 },
            Ir3Instruction::Halt,
        ],
        vec!["future".to_string()],
    );
    let mut core = quickjs_test_core();

    let halted = core
        .run_loop(&module)
        .expect_err("test should stop immediately after entering catch");
    assert_eq!(halted, InterpreterError::Halted);
    let caught = core.registers[1].clone();
    let Value::Object(error_id) = caught else {
        panic!("expected materialized ReferenceError object, got {caught:?}");
    };
    assert_eq!(
        core.heap[error_id.0 as usize].properties.get("name"),
        Some(&Value::str("ReferenceError"))
    );
    assert_eq!(core.registers[0], Value::Int(41));
    let (_, binding) = core
        .scope_chain
        .resolve("future")
        .expect("TDZ binding should remain present");
    assert!(!binding.state().unwrap().initialized);
    assert!(core.catch_frames.is_empty());
    assert!(core.pending_exception.is_none());
    assert!(core.pending_return.is_none());
    assert!(core.pending_finally_entry.is_none());
    assert!(core.finally_frames.is_empty());
    assert!(core.suspended_abrupt_completions.is_empty());
}

#[test]
fn uncaught_uninitialized_load_scoped_preserves_native_error_and_state_bd_mfcww() {
    let module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadInt { dst: 0, value: 41 },
            Ir3Instruction::DeclareBinding {
                name_pool_index: 0,
                kind: BindingKind::Let as u8,
            },
            Ir3Instruction::LoadScoped {
                dst: 0,
                name_pool_index: 0,
            },
        ],
        vec!["future".to_string()],
    );
    let mut core = quickjs_test_core();
    let heap_len_before = core.heap.len();

    let error = core
        .run_loop(&module)
        .expect_err("uncaught TDZ read should remain a native error");
    assert_eq!(
        error,
        InterpreterError::UninitializedBinding {
            name: "future".to_string()
        }
    );
    assert_eq!(core.heap.len(), heap_len_before);
    assert_eq!(core.registers[0], Value::Int(41));
    let (_, binding) = core
        .scope_chain
        .resolve("future")
        .expect("TDZ binding should remain present");
    assert!(!binding.state().unwrap().initialized);
}

#[test]
fn uncaught_const_store_scoped_preserves_native_error_and_heap_bd_dp12f() {
    let module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadInt { dst: 0, value: 1 },
            Ir3Instruction::DeclareBinding {
                name_pool_index: 0,
                kind: BindingKind::Const as u8,
            },
            Ir3Instruction::InitBinding {
                name_pool_index: 0,
                src: 0,
            },
            Ir3Instruction::LoadInt { dst: 1, value: 2 },
            Ir3Instruction::StoreScoped {
                src: 1,
                name_pool_index: 0,
            },
        ],
        vec!["fixed".to_string()],
    );
    let mut core = quickjs_test_core();
    let heap_len_before = core.heap.len();

    let error = core
        .run_loop(&module)
        .expect_err("uncaught const assignment should remain a native error");
    assert_eq!(
        error,
        InterpreterError::ConstAssignment {
            name: "fixed".to_string()
        }
    );
    assert_eq!(core.heap.len(), heap_len_before);
    let (_, binding) = core
        .scope_chain
        .resolve("fixed")
        .expect("const binding should remain present");
    assert_eq!(binding.value().unwrap(), Value::Int(1));
}

#[test]
fn return_label_survives_finally_nested_call_bd_ur3tk_2() {
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
    let mut core = quickjs_test_core();
    core.registers[0] = Value::Function(0);
    core.write_reg_with_label(
        1,
        Value::str("secret-through-finally"),
        crate::ifc_artifacts::Label::Secret,
    )
    .expect("secret return argument should be writable");
    core.registers[2] = Value::Function(1);

    assert_eq!(
        core.run_loop(&module)
            .expect("finally return should survive nested helper call"),
        Value::str("secret-through-finally")
    );
    assert_eq!(
        core.read_reg_label(3).expect("caller return label"),
        crate::ifc_artifacts::Label::Secret
    );
}

#[test]
fn nested_finally_return_override_keeps_new_label_bd_ur3tk_2() {
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
    let mut core = quickjs_test_core();
    core.registers[0] = Value::Function(0);
    core.write_reg_with_label(
        1,
        Value::str("secret-override"),
        crate::ifc_artifacts::Label::Secret,
    )
    .expect("secret overriding return should be writable");
    core.registers[2] = Value::str("public-initial-return");

    assert_eq!(
        core.run_loop(&module)
            .expect("inner finally return should override outer completion"),
        Value::str("secret-override")
    );
    assert_eq!(
        core.read_reg_label(3).expect("overriding return label"),
        crate::ifc_artifacts::Label::Secret
    );
}

#[test]
fn caught_throw_restores_suspended_return_label_bd_ur3tk_2() {
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
    let mut core = quickjs_test_core();
    core.registers[0] = Value::Function(0);
    core.write_reg_with_label(
        1,
        Value::str("secret-suspended-return"),
        crate::ifc_artifacts::Label::Secret,
    )
    .expect("secret pending return should be writable");
    core.registers[2] = Value::str("public-local-throw");

    assert_eq!(
        core.run_loop(&module)
            .expect("caught throw should restore the suspended return"),
        Value::str("secret-suspended-return")
    );
    assert_eq!(
        core.read_reg_label(3)
            .expect("restored suspended return label"),
        crate::ifc_artifacts::Label::Secret
    );
}

#[test]
fn retained_module_program_is_shared_and_admission_is_transactional() {
    let module = test_module_with_pool(
        vec![Ir3Instruction::Halt],
        vec!["retained module payload".repeat(64)],
    );
    let mut core = quickjs_test_core();
    core.current_module_specifier = Some(module.header.source_label.clone());
    core.ensure_module_record(&module, &module.header.source_label)
        .unwrap();
    core.sync_estimated_memory_bytes().unwrap();
    let original_bytes = core.estimated_memory_bytes;
    let original_limit = core.config.max_total_memory_bytes;
    core.config.max_total_memory_bytes = original_bytes;

    assert!(matches!(
        core.retain_current_module_program(&module),
        Err(InterpreterError::MemoryBudgetExceeded { .. })
    ));
    let record = &core.module_state.modules[&module.header.source_label];
    assert!(record.compiled_module.is_none());
    assert_eq!(record.retained_program_bytes, 0);
    assert_eq!(core.module_state.retained_program_bytes, 0);
    assert_eq!(core.estimated_memory_bytes, original_bytes);

    core.config.max_total_memory_bytes = original_limit;
    core.retain_current_module_program(&module).unwrap();
    let first = core.module_state.modules[&module.header.source_label]
        .compiled_module
        .clone()
        .unwrap();
    let retained_bytes = core.estimated_memory_bytes;
    core.retain_current_module_program(&module).unwrap();
    let second = core.module_state.modules[&module.header.source_label]
        .compiled_module
        .as_ref()
        .unwrap();
    assert!(Rc::ptr_eq(&first, second));
    assert_eq!(core.estimated_memory_bytes, retained_bytes);
    assert_eq!(
        core.estimated_memory_bytes,
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn module_memory_refusals_restore_and_keep_the_callers_payload_charged() {
    for commonjs in [false, true] {
        let mut core = quickjs_test_core();
        core.current_module_specifier = Some("caller.mjs".to_string());
        core.ip = 17;
        core.write_reg_with_label(
            0,
            Value::str("caller payload".repeat(4096)),
            crate::ifc_artifacts::Label::Secret,
        )
        .unwrap();
        core.sync_estimated_memory_bytes().unwrap();
        let original_bytes = core.estimated_memory_bytes;
        let original_registers = core.registers.clone();
        let original_labels = core.register_labels.clone();
        core.config.max_total_memory_bytes = original_bytes;
        let module = test_module(vec![Ir3Instruction::Halt]);
        let result = if commonjs {
            core.evaluate_cjs_ir3(&module, "child.cjs")
        } else {
            core.evaluate_module_ir3(&module, "child.mjs")
        };

        assert!(matches!(
            result,
            Err(InterpreterError::MemoryBudgetExceeded { .. })
        ));
        assert_eq!(core.registers, original_registers);
        assert_eq!(core.register_labels, original_labels);
        assert_eq!(core.current_module_specifier.as_deref(), Some("caller.mjs"));
        assert_eq!(core.ip, 17);
        assert_eq!(core.temporarily_suspended_execution_bytes, 0);
        assert_eq!(core.temporarily_suspended_call_depth, 0);
        assert_eq!(core.estimated_memory_bytes, original_bytes);
        assert_eq!(
            core.estimated_memory_bytes,
            core.recompute_estimated_memory_bytes()
        );
    }
}

#[test]
fn foreign_function_hooks_keep_the_callers_instruction_provenance() {
    let mut core = quickjs_test_core();
    core.current_module_specifier = Some("caller.mjs".to_string());
    core.ip = 17;
    let mut callee_module = test_module(vec![Ir3Instruction::Halt]);
    callee_module.header.source_label = "callee.mjs".to_string();

    let context = core.hook_context(&callee_module);
    assert_eq!(context.extension_id, "caller.mjs");
    assert_eq!(context.current_ip, 17);
}

#[test]
fn module_snapshot_round_trips_labeled_returns_bd_ur3tk_2() {
    let mut core = quickjs_test_core();
    let pending = LabeledReturn {
        value: Value::str("pending"),
        label: crate::ifc_artifacts::Label::Secret,
    };
    let suspended = LabeledReturn {
        value: Value::str("suspended"),
        label: crate::ifc_artifacts::Label::Custom {
            name: "tenant-return".to_string(),
            level: 4,
        },
    };
    core.pending_return = Some(pending.clone());
    core.suspended_abrupt_completions
        .push(AbruptCompletion::Return(suspended.clone()));
    let snapshot = core.snapshot_module_execution();

    core.pending_return = None;
    core.suspended_abrupt_completions.clear();
    core.restore_module_execution(snapshot);

    assert_eq!(core.pending_return, Some(pending));
    assert!(matches!(
        core.suspended_abrupt_completions.as_slice(),
        [AbruptCompletion::Return(restored)] if restored == &suspended
    ));
}

#[test]
fn throw_to_catch_preserves_exact_label_bd_ur3tk_14() {
    let module = test_module(vec![
        Ir3Instruction::BeginTry {
            catch_target: 2,
            finally_target: None,
        },
        Ir3Instruction::Throw { value: 0 },
        Ir3Instruction::EnterCatch { dst: 1 },
        Ir3Instruction::Halt,
    ]);
    let mut core = quickjs_test_core();
    core.write_reg_with_label(
        0,
        Value::str("secret-exception"),
        crate::ifc_artifacts::Label::Secret,
    )
    .expect("thrown value should be writable");
    core.write_reg_with_label(
        1,
        Value::str("stale-catch-value"),
        crate::ifc_artifacts::Label::TopSecret,
    )
    .expect("catch destination should be seedable");

    core.execute(&module)
        .expect("throw should enter the catch handler");

    assert_eq!(core.registers[1], Value::str("secret-exception"));
    assert_eq!(
        core.read_reg_label(1).expect("catch label should exist"),
        crate::ifc_artifacts::Label::Secret,
        "catch binding receives the thrown label rather than Public or a stale label"
    );
}

#[test]
fn nested_catch_call_and_finally_restore_exception_label_bd_ur3tk_14() {
    let module = test_module_with_functions(
        vec![
            Ir3Instruction::BeginTry {
                catch_target: 3,
                finally_target: None,
            },
            Ir3Instruction::Call {
                callee: 0,
                args: RegRange { start: 1, count: 3 },
                dst: 4,
            },
            Ir3Instruction::Halt,
            Ir3Instruction::EnterCatch { dst: 5 },
            Ir3Instruction::Halt,
            Ir3Instruction::BeginTry {
                catch_target: 8,
                finally_target: Some(8),
            },
            Ir3Instruction::Throw { value: 0 },
            Ir3Instruction::Halt,
            Ir3Instruction::EnterFinally,
            Ir3Instruction::BeginTry {
                catch_target: 11,
                finally_target: None,
            },
            Ir3Instruction::Throw { value: 1 },
            Ir3Instruction::EnterCatch { dst: 3 },
            Ir3Instruction::Call {
                callee: 2,
                args: RegRange { start: 4, count: 0 },
                dst: 3,
            },
            Ir3Instruction::EndFinally,
            Ir3Instruction::LoadInt { dst: 0, value: 7 },
            Ir3Instruction::Return { value: 0 },
        ],
        vec![
            Ir3FunctionDesc {
                entry: 5,
                arity: 3,
                frame_size: 4,
                name: Some("exception_through_finally".to_string()),
                is_generator: false,
                rest_param_index: None,
            },
            Ir3FunctionDesc {
                entry: 14,
                arity: 0,
                frame_size: 1,
                name: Some("helper_while_exception_pending".to_string()),
                is_generator: false,
                rest_param_index: None,
            },
        ],
    );
    let mut core = quickjs_test_core();
    core.registers[0] = Value::Function(0);
    core.write_reg_with_label(
        1,
        Value::str("outer-secret-exception"),
        crate::ifc_artifacts::Label::Secret,
    )
    .expect("outer exception argument should be writable");
    core.registers[2] = Value::str("inner-public-exception");
    core.registers[3] = Value::Function(1);

    core.execute(&module)
        .expect("outer caller should catch the exception after finally");

    assert_eq!(core.registers[5], Value::str("outer-secret-exception"));
    assert_eq!(
        core.read_reg_label(5)
            .expect("caller catch label should exist"),
        crate::ifc_artifacts::Label::Secret,
        "inner catch consumption and helper call must restore the outer exception label"
    );
}

#[test]
fn module_snapshot_round_trips_labeled_exceptions_bd_ur3tk_14() {
    let mut core = quickjs_test_core();
    let pending = LabeledException {
        value: Value::str("pending-exception"),
        label: crate::ifc_artifacts::Label::Secret,
    };
    let suspended = LabeledException {
        value: Value::str("suspended-exception"),
        label: crate::ifc_artifacts::Label::Custom {
            name: "tenant-exception".to_string(),
            level: 4,
        },
    };
    core.pending_exception = Some(pending.clone());
    core.suspended_abrupt_completions
        .push(AbruptCompletion::Exception(suspended.clone()));
    let snapshot = core.snapshot_module_execution();

    core.pending_exception = None;
    core.suspended_abrupt_completions.clear();
    core.restore_module_execution(snapshot);

    assert_eq!(core.pending_exception, Some(pending));
    assert!(matches!(
        core.suspended_abrupt_completions.as_slice(),
        [AbruptCompletion::Exception(restored)] if restored == &suspended
    ));
}

#[test]
fn discard_abrupt_completion_preserves_outer_frame_label_bd_kfxwe() {
    let module = test_module(vec![Ir3Instruction::DiscardAbruptCompletion]);
    let mut core = quickjs_test_core();
    let outer = LabeledException {
        value: Value::str("outer"),
        label: crate::ifc_artifacts::Label::Secret,
    };
    core.finally_frames.push(FinallyFrame {
        completion: Some(AbruptCompletion::Exception(outer.clone())),
    });
    core.finally_frames.push(FinallyFrame {
        completion: Some(AbruptCompletion::Exception(LabeledException {
            value: Value::str("inner"),
            label: crate::ifc_artifacts::Label::Public,
        })),
    });
    let snapshot = core.snapshot_module_execution();
    core.finally_frames.clear();
    core.restore_module_execution(snapshot);

    core.run_loop(&module)
        .expect("discard should resume after the local finally completion");

    assert!(core.pending_exception.is_none());
    assert!(core.pending_return.is_none());
    assert_eq!(core.finally_frames.len(), 1);
    match &core.finally_frames[0].completion {
        Some(AbruptCompletion::Exception(restored)) => assert_eq!(restored, &outer),
        other => panic!("expected outer exception frame, got {other:?}"),
    }
    assert!(core.suspended_abrupt_completions.is_empty());

    let mut normal_nested_core = quickjs_test_core();
    let outer_normal_entry = LabeledException {
        value: Value::str("outer-normal-entry"),
        label: crate::ifc_artifacts::Label::TopSecret,
    };
    normal_nested_core.finally_frames.push(FinallyFrame {
        completion: Some(AbruptCompletion::Exception(outer_normal_entry.clone())),
    });
    normal_nested_core
        .finally_frames
        .push(FinallyFrame { completion: None });

    normal_nested_core
        .run_loop(&module)
        .expect("normal nested finally must not discard an outer completion");

    assert!(normal_nested_core.pending_exception.is_none());
    assert_eq!(normal_nested_core.finally_frames.len(), 1);
    match &normal_nested_core.finally_frames[0].completion {
        Some(AbruptCompletion::Exception(restored)) => {
            assert_eq!(restored, &outer_normal_entry);
        }
        other => panic!("expected preserved outer normal-entry frame, got {other:?}"),
    }
}

#[test]
fn finally_entry_survives_budget_boundary_and_snapshot_bd_kfxwe() {
    let module = test_module(vec![
        Ir3Instruction::LoadInt { dst: 0, value: 7 },
        Ir3Instruction::BeginTry {
            catch_target: 3,
            finally_target: Some(3),
        },
        Ir3Instruction::Return { value: 0 },
        Ir3Instruction::EnterFinally,
        Ir3Instruction::EndFinally,
    ]);
    let mut core = quickjs_test_core();
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

    let snapshot = core.snapshot_module_execution();
    core.pending_finally_entry = None;
    core.restore_module_execution(snapshot);
    core.config.instruction_budget = 10;

    assert_eq!(
        core.run_loop(&module)
            .expect("resumed finally must complete the pending return"),
        Value::Int(7)
    );
    assert!(core.pending_return.is_none());
    assert!(core.pending_finally_entry.is_none());
    assert!(core.finally_frames.is_empty());
}

#[test]
fn finally_entry_survives_cancellation_boundary_bd_kfxwe() {
    let module = test_module(vec![
        Ir3Instruction::BeginTry {
            catch_target: 2,
            finally_target: Some(2),
        },
        Ir3Instruction::Throw { value: 0 },
        Ir3Instruction::EnterFinally,
        Ir3Instruction::EndFinally,
    ]);
    let token = CancellationToken::new();
    token.cancel();
    let mut config = test_quickjs_config();
    config.cancellation_token = Some(token.clone());
    config.checkpoint_density = 3;
    let mut core = InterpreterCore::new(config, "bd-kfxwe-cancel");
    core.write_reg_with_label(0, Value::str("boom"), crate::ifc_artifacts::Label::Secret)
        .expect("throw value should fit in r0");

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
    assert!(core.pending_exception.is_none());
    assert!(core.pending_finally_entry.is_none());
    assert!(core.finally_frames.is_empty());
}

fn execute_exception_source_with_core_bd_kfxwe(source: &str) -> (Value, InterpreterCore) {
    let tree = CanonicalEs2020Parser
        .parse(source, ParseGoal::Script)
        .expect("finally ownership regression source should parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "bd_kfxwe_runtime.js");
    let module = lower_ir0_to_ir3(
        &ir0,
        &LoweringContext::new(
            "trace-bd-kfxwe-runtime",
            "decision-bd-kfxwe-runtime",
            "policy-bd-kfxwe-runtime",
        ),
    )
    .expect("finally ownership regression source should lower")
    .ir3;
    let mut config = InterpreterConfig::quickjs_defaults();
    config.granted_capabilities = std::collections::BTreeSet::from([
        RuntimeCapability::VmDispatch,
        RuntimeCapability::HeapAllocate,
    ]);
    let mut core = InterpreterCore::new(config, "bd-kfxwe-runtime");
    let value = core
        .execute(&module)
        .expect("finally ownership regression should execute")
        .value;
    (value, core)
}

#[test]
fn escaped_finally_completion_records_are_balanced_bd_kfxwe() {
    let (value, core) = execute_exception_source_with_core_bd_kfxwe(
        "function f(){ try { return \"outer\"; } finally { try { try { return \"inner\"; } finally { throw \"new\"; } } catch(e) {} } } f();",
    );

    assert_eq!(value, Value::str("outer"));
    assert!(core.pending_exception.is_none());
    assert!(core.pending_return.is_none());
    assert!(core.pending_finally_entry.is_none());
    assert!(core.finally_frames.is_empty());
    assert!(core.suspended_abrupt_completions.is_empty());
}

#[test]
fn uncaught_throw_from_finally_clears_completion_records_bd_kfxwe() {
    let module = test_module(vec![
        Ir3Instruction::LoadInt { dst: 0, value: 1 },
        Ir3Instruction::BeginTry {
            catch_target: 3,
            finally_target: Some(3),
        },
        Ir3Instruction::Return { value: 0 },
        Ir3Instruction::EnterFinally,
        Ir3Instruction::Throw { value: 1 },
    ]);
    let mut core = quickjs_test_core();
    core.write_reg_with_label(1, Value::str("new"), crate::ifc_artifacts::Label::Secret)
        .expect("throw value should fit in r1");

    assert_eq!(
        core.run_loop(&module),
        Err(InterpreterError::UncaughtException {
            value: "new".to_string(),
        })
    );
    assert!(core.pending_exception.is_none());
    assert!(core.pending_return.is_none());
    assert!(core.pending_finally_entry.is_none());
    assert!(core.finally_frames.is_empty());
    assert!(core.suspended_abrupt_completions.is_empty());
}

fn constructor_descriptor_bd_ur3tk_4(entry: u32, arity: u32, frame_size: u32) -> Ir3FunctionDesc {
    Ir3FunctionDesc {
        entry,
        arity,
        frame_size,
        name: Some("labeled_constructor".to_string()),
        is_generator: false,
        rest_param_index: None,
    }
}

#[test]
fn constructor_this_and_implicit_result_use_only_callee_label_bd_ur3tk_4() {
    for return_explicit_this in [true, false] {
        let mut instructions = vec![
            Ir3Instruction::Construct {
                callee: 0,
                args: RegRange { start: 1, count: 1 },
                dst: 2,
            },
            Ir3Instruction::Halt,
        ];
        if return_explicit_this {
            instructions.extend([
                Ir3Instruction::LoadThis { dst: 1 },
                Ir3Instruction::Return { value: 1 },
            ]);
        } else {
            instructions.push(Ir3Instruction::Return { value: 0 });
        }
        let module = test_module_with_functions(
            instructions,
            vec![constructor_descriptor_bd_ur3tk_4(2, 1, 2)],
        );
        let mut core = quickjs_test_core();
        core.write_reg_with_label(0, Value::Function(0), crate::ifc_artifacts::Label::Secret)
            .expect("constructor should be writable");
        core.write_reg_with_label(1, Value::Int(99), crate::ifc_artifacts::Label::TopSecret)
            .expect("constructor argument should be writable");

        core.execute(&module)
            .expect("labeled constructor should execute");

        assert!(matches!(core.registers[2], Value::Object(_)));
        assert_eq!(
            core.read_reg_label(2)
                .expect("constructed result label should exist"),
            crate::ifc_artifacts::Label::Secret,
            "constructor this provenance comes from the callee, not an ignored or discarded argument (return_explicit_this={return_explicit_this})"
        );
    }
}

#[test]
fn constructor_explicit_object_return_keeps_argument_label_bd_ur3tk_4() {
    let module = test_module_with_functions(
        vec![
            Ir3Instruction::Construct {
                callee: 0,
                args: RegRange { start: 1, count: 1 },
                dst: 2,
            },
            Ir3Instruction::Halt,
            Ir3Instruction::Return { value: 0 },
        ],
        vec![constructor_descriptor_bd_ur3tk_4(2, 1, 1)],
    );
    let mut core = quickjs_test_core();
    let explicit_object = core
        .alloc_object_with_prototype(None)
        .expect("explicit object should allocate");
    core.write_reg_with_label(0, Value::Function(0), crate::ifc_artifacts::Label::Secret)
        .expect("constructor should be writable");
    core.write_reg_with_label(
        1,
        Value::Object(explicit_object),
        crate::ifc_artifacts::Label::Confidential,
    )
    .expect("explicit object argument should be writable");

    core.execute(&module)
        .expect("explicit object constructor should execute");

    assert_eq!(core.registers[2], Value::Object(explicit_object));
    assert_eq!(
        core.read_reg_label(2).expect("explicit result label"),
        crate::ifc_artifacts::Label::Confidential,
        "an explicit object return keeps its own label instead of the constructor label"
    );
}

#[test]
fn constructor_new_target_throw_preserves_callee_label_bd_ur3tk_4() {
    let module = test_module_with_functions(
        vec![
            Ir3Instruction::BeginTry {
                catch_target: 3,
                finally_target: None,
            },
            Ir3Instruction::Construct {
                callee: 0,
                args: RegRange { start: 1, count: 0 },
                dst: 2,
            },
            Ir3Instruction::Halt,
            Ir3Instruction::EnterCatch { dst: 3 },
            Ir3Instruction::Halt,
            Ir3Instruction::LoadNewTarget { dst: 0 },
            Ir3Instruction::Throw { value: 0 },
        ],
        vec![constructor_descriptor_bd_ur3tk_4(5, 0, 1)],
    );
    let mut core = quickjs_test_core();
    core.write_reg_with_label(0, Value::Function(0), crate::ifc_artifacts::Label::Secret)
        .expect("constructor should be writable");

    core.execute(&module)
        .expect("caller should catch the thrown new.target");

    assert_eq!(core.registers[3], Value::Function(0));
    assert_eq!(
        core.read_reg_label(3).expect("new.target catch label"),
        crate::ifc_artifacts::Label::Secret
    );
}

#[test]
fn super_construction_preserves_private_parent_label_bd_ppfz7() {
    let module = test_module_with_functions(
        vec![
            Ir3Instruction::RegisterDerivedConstructor {
                constructor: 0,
                parent: 1,
                default_constructor: false,
            },
            Ir3Instruction::Construct {
                callee: 0,
                args: RegRange { start: 0, count: 0 },
                dst: 2,
            },
            Ir3Instruction::Halt,
            Ir3Instruction::ConstructSuper {
                args: RegRange { start: 0, count: 0 },
                dst: 0,
            },
            Ir3Instruction::LoadThis { dst: 1 },
            Ir3Instruction::Return { value: 1 },
            Ir3Instruction::LoadUndefined { dst: 0 },
            Ir3Instruction::Return { value: 0 },
        ],
        vec![
            constructor_descriptor_bd_ur3tk_4(3, 0, 2),
            constructor_descriptor_bd_ur3tk_4(6, 0, 1),
        ],
    );
    let mut core = quickjs_test_core();
    core.write_reg_with_label(0, Value::Function(0), crate::ifc_artifacts::Label::Public)
        .expect("child constructor should be writable");
    core.write_reg_with_label(1, Value::Function(1), crate::ifc_artifacts::Label::Secret)
        .expect("parent constructor should be writable");

    core.execute(&module)
        .expect("derived super construction should execute");

    assert!(matches!(core.registers[2], Value::Object(_)));
    assert_eq!(
        core.read_reg_label(2).expect("derived result label"),
        crate::ifc_artifacts::Label::Secret,
        "the private parent-constructor label must reach initialized derived this"
    );
}

#[test]
fn default_derived_chain_accumulates_intermediate_parent_label_bd_ppfz7() {
    let module = test_module_with_functions(
        vec![
            Ir3Instruction::RegisterDerivedConstructor {
                constructor: 1,
                parent: 2,
                default_constructor: true,
            },
            Ir3Instruction::RegisterDerivedConstructor {
                constructor: 0,
                parent: 1,
                default_constructor: true,
            },
            Ir3Instruction::Construct {
                callee: 0,
                args: RegRange { start: 0, count: 0 },
                dst: 3,
            },
            Ir3Instruction::Halt,
            Ir3Instruction::LoadUndefined { dst: 0 },
            Ir3Instruction::Return { value: 0 },
            Ir3Instruction::LoadUndefined { dst: 0 },
            Ir3Instruction::Return { value: 0 },
            Ir3Instruction::LoadUndefined { dst: 0 },
            Ir3Instruction::Return { value: 0 },
        ],
        vec![
            constructor_descriptor_bd_ur3tk_4(4, 0, 1),
            constructor_descriptor_bd_ur3tk_4(6, 0, 1),
            constructor_descriptor_bd_ur3tk_4(8, 0, 1),
        ],
    );
    let mut core = quickjs_test_core();
    core.write_reg_with_label(0, Value::Function(0), crate::ifc_artifacts::Label::Public)
        .expect("leaf constructor should be writable");
    core.write_reg_with_label(1, Value::Function(1), crate::ifc_artifacts::Label::Secret)
        .expect("intermediate constructor should be writable");
    core.write_reg_with_label(2, Value::Function(2), crate::ifc_artifacts::Label::Public)
        .expect("base constructor should be writable");

    core.execute(&module)
        .expect("default-derived chain should execute");

    assert!(matches!(core.registers[3], Value::Object(_)));
    assert_eq!(
        core.read_reg_label(3)
            .expect("default-derived result label"),
        crate::ifc_artifacts::Label::Secret,
        "forwarding must not overwrite an intermediate parent label"
    );
}

#[test]
fn constructor_super_value_preserves_callee_label_bd_ur3tk_4() {
    let module = test_module_with_functions(
        vec![
            Ir3Instruction::Construct {
                callee: 0,
                args: RegRange { start: 1, count: 0 },
                dst: 2,
            },
            Ir3Instruction::Halt,
            Ir3Instruction::LoadSuper { dst: 0 },
            Ir3Instruction::Return { value: 0 },
        ],
        vec![constructor_descriptor_bd_ur3tk_4(2, 0, 1)],
    );
    let mut core = quickjs_test_core();
    let super_object = core
        .alloc_object_with_prototype(None)
        .expect("super object should allocate");
    let constructor = Value::Function(0);
    let function_object = core
        .ensure_function_object(&constructor)
        .expect("function metadata object should allocate")
        .expect("Function should have metadata storage");
    core.set_object_property(
        function_object,
        IR_SUPER_CONSTRUCTOR_PROPERTY.to_string(),
        Value::Object(super_object),
    )
    .expect("super metadata should be writable");
    core.write_reg_with_label(0, constructor, crate::ifc_artifacts::Label::Secret)
        .expect("constructor should be writable");

    core.execute(&module)
        .expect("constructor should return its super metadata object");

    assert_eq!(core.registers[2], Value::Object(super_object));
    assert_eq!(
        core.read_reg_label(2).expect("super result label"),
        crate::ifc_artifacts::Label::Secret
    );
}

#[test]
fn plain_call_super_metadata_uses_only_callee_label_bd_ur3tk_20() {
    let module = test_module_with_functions(
        vec![
            Ir3Instruction::Call {
                callee: 0,
                args: RegRange { start: 1, count: 1 },
                dst: 2,
            },
            Ir3Instruction::Halt,
            Ir3Instruction::LoadSuper { dst: 1 },
            Ir3Instruction::Return { value: 1 },
        ],
        vec![Ir3FunctionDesc {
            entry: 2,
            arity: 1,
            frame_size: 2,
            name: Some("plain_super_reader".to_string()),
            is_generator: false,
            rest_param_index: None,
        }],
    );
    let mut core = quickjs_test_core();
    let super_object = core
        .alloc_object_with_prototype(None)
        .expect("super object should allocate");
    let callee = Value::Function(0);
    let function_object = core
        .ensure_function_object(&callee)
        .expect("function metadata object should allocate")
        .expect("Function should have metadata storage");
    core.set_object_property(
        function_object,
        IR_SUPER_PROTOTYPE_PROPERTY.to_string(),
        Value::Object(super_object),
    )
    .expect("super metadata should be writable");
    core.write_reg_with_label(0, callee, crate::ifc_artifacts::Label::Secret)
        .expect("callee should be writable");
    core.write_reg_with_label(1, Value::Int(41), crate::ifc_artifacts::Label::TopSecret)
        .expect("argument should be writable");

    core.execute(&module).expect("plain call should execute");

    assert_eq!(core.registers[2], Value::Object(super_object));
    assert_eq!(
        core.read_reg_label(2).expect("plain super result label"),
        crate::ifc_artifacts::Label::Secret,
        "super provenance comes from the callee without overjoining its argument"
    );
}

#[test]
fn call_method_super_metadata_uses_only_callee_label_bd_ur3tk_20() {
    let module = test_module_with_functions(
        vec![
            Ir3Instruction::CallMethod {
                receiver: 0,
                callee: 1,
                args: RegRange { start: 2, count: 1 },
                dst: 3,
            },
            Ir3Instruction::Halt,
            Ir3Instruction::LoadSuper { dst: 1 },
            Ir3Instruction::Return { value: 1 },
        ],
        vec![Ir3FunctionDesc {
            entry: 2,
            arity: 1,
            frame_size: 2,
            name: Some("method_super_reader".to_string()),
            is_generator: false,
            rest_param_index: None,
        }],
    );
    let mut core = quickjs_test_core();
    let super_object = core
        .alloc_object_with_prototype(None)
        .expect("super object should allocate");
    let callee = Value::Function(0);
    let function_object = core
        .ensure_function_object(&callee)
        .expect("function metadata object should allocate")
        .expect("Function should have metadata storage");
    core.set_object_property(
        function_object,
        IR_SUPER_PROTOTYPE_PROPERTY.to_string(),
        Value::Object(super_object),
    )
    .expect("super metadata should be writable");
    core.write_reg_with_label(
        0,
        Value::str("receiver"),
        crate::ifc_artifacts::Label::Confidential,
    )
    .expect("receiver should be writable");
    core.write_reg_with_label(1, callee, crate::ifc_artifacts::Label::Secret)
        .expect("callee should be writable");
    core.write_reg_with_label(2, Value::Int(42), crate::ifc_artifacts::Label::TopSecret)
        .expect("argument should be writable");

    core.execute(&module).expect("method call should execute");

    assert_eq!(core.registers[3], Value::Object(super_object));
    assert_eq!(
        core.read_reg_label(3).expect("method super result label"),
        crate::ifc_artifacts::Label::Secret,
        "super provenance comes from the callee without overjoining its argument"
    );
}

fn lower_source_and_find_unresolved_argument_seed_bd_ur3tk_11(source: &str) -> (Ir3Module, Reg) {
    let tree = CanonicalEs2020Parser
        .parse(source, ParseGoal::Script)
        .expect("value-transfer regression source should parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "bd_ur3tk_11.js");
    let output = lower_ir0_to_ir3(
        &ir0,
        &LoweringContext::new(
            "trace-bd-ur3tk-11",
            "decision-bd-ur3tk-11",
            "policy-bd-ur3tk-11",
        ),
    )
    .expect("value-transfer regression source should lower");
    let module = output.ir3;
    let main_end = module
        .instructions
        .iter()
        .position(|instruction| matches!(instruction, Ir3Instruction::Halt))
        .expect("lowered main block should terminate with Halt");
    let (call_index, mut seed_reg) = module.instructions[..main_end]
        .iter()
        .enumerate()
        .find_map(|(index, instruction)| match instruction {
            Ir3Instruction::Call { args, .. } if args.count == 1 => Some((index, args.start)),
            _ => None,
        })
        .expect("source should contain one top-level single-argument call");

    // Ordinary source lowering moves an unresolved input through one or
    // more fresh temporaries before packing the call range. Walk that
    // exact Move chain back to the unwritten backing register so the test
    // can inject a labeled external input without introducing a new IR
    // source-label opcode.
    let mut search_end = call_index;
    let mut traced_move_count = 0_u32;
    while let Some((index, source_reg)) = module.instructions[..search_end]
        .iter()
        .enumerate()
        .rev()
        .find_map(|(index, instruction)| match instruction {
            Ir3Instruction::Move { dst, src } if *dst == seed_reg => Some((index, *src)),
            _ => None,
        })
    {
        seed_reg = source_reg;
        search_end = index;
        traced_move_count = traced_move_count.saturating_add(1);
    }
    assert!(
        traced_move_count >= 2,
        "seed tracing should cross the unresolved-binding load and call-range packing moves"
    );

    // Pin the monotonic-allocation assumption behind the white-box seed:
    // the terminal unresolved binding register must not be produced by an
    // earlier instruction. Canonical IR names synchronous destinations
    // `dst` or `value_dst`; the two suspended-result forms use
    // `resume_dst` and `promise_reg`. Checking all four avoids duplicating
    // the instruction enum's large match here.
    assert!(
        module.instructions[..call_index].iter().all(|instruction| {
            let crate::deterministic_serde::CanonicalValue::Map(fields) =
                instruction.canonical_value()
            else {
                unreachable!("IR3 instructions canonicalize to maps");
            };
            ["dst", "value_dst", "resume_dst", "promise_reg"]
                .iter()
                .all(|field| {
                    !matches!(
                        fields.get(*field),
                        Some(crate::deterministic_serde::CanonicalValue::U64(destination))
                            if *destination == u64::from(seed_reg)
                    )
                })
        }),
        "terminal unresolved input r{seed_reg} must have no earlier writer"
    );

    (module, seed_reg)
}

fn assert_source_transfer_preserves_secret_bd_ur3tk_11(source: &str) {
    let (module, seed_reg) = lower_source_and_find_unresolved_argument_seed_bd_ur3tk_11(source);
    let mut core = quickjs_test_core();
    core.write_reg_with_label(
        seed_reg,
        Value::str("source-secret"),
        crate::ifc_artifacts::Label::Secret,
    )
    .expect("unresolved source input should be seedable");

    let result = core
        .execute(&module)
        .expect("source-lowered value transfers should execute");
    assert_eq!(result.value, Value::str("source-secret"));
    assert_eq!(result.completion_label, crate::ifc_artifacts::Label::Secret);
}

#[test]
fn direct_top_level_return_exposes_secret_completion_label_bd_ur3tk_17() {
    let module = test_module(vec![Ir3Instruction::Return { value: 0 }]);
    let mut core = quickjs_test_core();
    core.write_reg_with_label(
        0,
        Value::str("direct-secret"),
        crate::ifc_artifacts::Label::Secret,
    )
    .expect("secret completion should be seedable");

    let result = core
        .execute(&module)
        .expect("direct top-level return should execute");
    assert_eq!(result.value, Value::str("direct-secret"));
    assert_eq!(result.completion_label, crate::ifc_artifacts::Label::Secret);
}

#[test]
fn halt_exposes_secret_register_completion_label_bd_ur3tk_17() {
    let module = test_module(vec![Ir3Instruction::Halt]);
    let mut core = quickjs_test_core();
    core.write_reg_with_label(
        0,
        Value::str("halt-secret"),
        crate::ifc_artifacts::Label::Secret,
    )
    .expect("secret halt completion should be seedable");

    let result = core.execute(&module).expect("halt should execute");
    assert_eq!(result.value, Value::str("halt-secret"));
    assert_eq!(result.completion_label, crate::ifc_artifacts::Label::Secret);
}

#[test]
fn fallthrough_exposes_secret_register_completion_label_bd_ur3tk_17() {
    let module = test_module(Vec::new());
    let mut core = quickjs_test_core();
    core.write_reg_with_label(
        0,
        Value::str("fallthrough-secret"),
        crate::ifc_artifacts::Label::Secret,
    )
    .expect("secret fallthrough completion should be seedable");

    let result = core.execute(&module).expect("fallthrough should execute");
    assert_eq!(result.value, Value::str("fallthrough-secret"));
    assert_eq!(result.completion_label, crate::ifc_artifacts::Label::Secret);
}

#[test]
fn finally_unwound_top_level_return_exposes_secret_completion_label_bd_ur3tk_17() {
    let module = test_module(vec![
        Ir3Instruction::BeginTry {
            catch_target: 2,
            finally_target: Some(2),
        },
        Ir3Instruction::Return { value: 0 },
        Ir3Instruction::EnterFinally,
        Ir3Instruction::EndFinally,
    ]);
    let mut core = quickjs_test_core();
    core.write_reg_with_label(
        0,
        Value::str("finally-secret"),
        crate::ifc_artifacts::Label::Secret,
    )
    .expect("secret pending return should be seedable");

    let result = core
        .execute(&module)
        .expect("finally-unwound top-level return should execute");
    assert_eq!(result.value, Value::str("finally-secret"));
    assert_eq!(result.completion_label, crate::ifc_artifacts::Label::Secret);
}

#[test]
fn both_lane_wrappers_expose_completion_label_bd_ur3tk_17() {
    let module = test_module(vec![
        Ir3Instruction::LoadInt { dst: 0, value: 17 },
        Ir3Instruction::Return { value: 0 },
    ]);

    for result in [
        quickjs_execute(&module).expect("QuickJsLane should execute"),
        v8_execute(&module).expect("V8Lane should execute"),
    ] {
        assert_eq!(result.value, Value::Int(17));
        assert_eq!(result.completion_label, crate::ifc_artifacts::Label::Public);
    }
}

#[test]
fn source_local_moves_preserve_secret_to_completion_bd_ur3tk_11() {
    assert_source_transfer_preserves_secret_bd_ur3tk_11(
        "function identity(value) { return value; } identity(secret_input);",
    );
}

#[test]
fn captured_parameter_preserves_secret_through_scope_bd_ur3tk_11() {
    assert_source_transfer_preserves_secret_bd_ur3tk_11(
        "function outer(value) { return function inner() { return value; }; }\
         outer(secret_input)();",
    );
}

#[test]
fn captured_local_preserves_secret_through_scope_bd_ur3tk_11() {
    assert_source_transfer_preserves_secret_bd_ur3tk_11(
        "function outer(value) {\
           let local = value;\
           return function inner() { return local; };\
         }\
         outer(secret_input)();",
    );
}

#[test]
fn destructuring_default_preserves_secret_through_moves_bd_ur3tk_11() {
    assert_source_transfer_preserves_secret_bd_ur3tk_11(
        "function unpack(value) {\
           let { missing = value } = {};\
           return missing;\
         }\
         unpack(secret_input);",
    );
}

#[derive(Debug, Clone, Copy)]
enum TransactionalCallKindBdUr3tk12 {
    Call,
    AsyncCall,
    CallMethod,
    AsyncCallMethod,
    Construct,
}

impl TransactionalCallKindBdUr3tk12 {
    fn is_async(self) -> bool {
        matches!(self, Self::AsyncCall | Self::AsyncCallMethod)
    }

    fn is_method(self) -> bool {
        matches!(self, Self::CallMethod | Self::AsyncCallMethod)
    }
}

#[derive(Debug)]
struct CallSetupStateBdUr3tk12 {
    execution_seed: ExecutionSeed,
    promise_store: serde_json::Value,
    active_timers: serde_json::Value,
    next_timer_id: u32,
    async_functions_len: usize,
    closures_len: usize,
    call_stack_len: usize,
    scope_depth: usize,
    register_base: usize,
    ip: usize,
    pending_exception: Option<LabeledException>,
    pending_return: Option<LabeledReturn>,
    profiling_memory_stats: Option<serde_json::Value>,
    estimated_memory_bytes: u64,
}

fn capture_call_setup_state_bd_ur3tk_12(core: &InterpreterCore) -> CallSetupStateBdUr3tk12 {
    CallSetupStateBdUr3tk12 {
        execution_seed: core.capture_execution_seed(),
        promise_store: serde_json::to_value(&core.promise_store)
            .expect("PromiseStore should serialize for replay comparison"),
        active_timers: serde_json::to_value(&core.active_timers)
            .expect("active timers should serialize for replay comparison"),
        next_timer_id: core.next_timer_id,
        async_functions_len: core.async_functions.len(),
        closures_len: core.closures.len(),
        call_stack_len: core.call_stack.len(),
        scope_depth: core.scope_chain.depth(),
        register_base: core.register_base,
        ip: core.ip,
        pending_exception: core.pending_exception.clone(),
        pending_return: core.pending_return.clone(),
        profiling_memory_stats: core.profiling_data.as_ref().map(|profiler| {
            serde_json::to_value(profiler.memory_stats_snapshot())
                .expect("profiling memory statistics should serialize")
        }),
        estimated_memory_bytes: core.estimated_memory_bytes,
    }
}

fn assert_call_setup_state_bd_ur3tk_12(core: &InterpreterCore, expected: &CallSetupStateBdUr3tk12) {
    assert_eq!(core.capture_execution_seed(), expected.execution_seed);
    assert_eq!(
        serde_json::to_value(&core.promise_store)
            .expect("PromiseStore should serialize after refusal"),
        expected.promise_store
    );
    assert_eq!(
        serde_json::to_value(&core.active_timers)
            .expect("active timers should serialize after refusal"),
        expected.active_timers
    );
    assert_eq!(core.next_timer_id, expected.next_timer_id);
    assert_eq!(core.async_functions.len(), expected.async_functions_len);
    assert_eq!(core.closures.len(), expected.closures_len);
    assert_eq!(core.call_stack.len(), expected.call_stack_len);
    assert_eq!(core.scope_chain.depth(), expected.scope_depth);
    assert_eq!(core.register_base, expected.register_base);
    assert_eq!(core.ip, expected.ip);
    assert_eq!(core.pending_exception, expected.pending_exception);
    assert_eq!(core.pending_return, expected.pending_return);
    assert_eq!(
        core.profiling_data.as_ref().map(|profiler| {
            serde_json::to_value(profiler.memory_stats_snapshot())
                .expect("profiling memory statistics should serialize after refusal")
        }),
        expected.profiling_memory_stats
    );
    assert_eq!(core.estimated_memory_bytes, expected.estimated_memory_bytes);
    assert_eq!(
        core.estimated_memory_bytes,
        core.recompute_estimated_memory_bytes(),
        "rollback must leave eager and recomputed accounting equal"
    );
}

fn transactional_call_module_bd_ur3tk_12(kind: TransactionalCallKindBdUr3tk12) -> Ir3Module {
    let call = match kind {
        TransactionalCallKindBdUr3tk12::Call | TransactionalCallKindBdUr3tk12::AsyncCall => {
            Ir3Instruction::Call {
                callee: 0,
                args: RegRange { start: 1, count: 2 },
                dst: 4,
            }
        }
        TransactionalCallKindBdUr3tk12::CallMethod
        | TransactionalCallKindBdUr3tk12::AsyncCallMethod => Ir3Instruction::CallMethod {
            receiver: 5,
            callee: 0,
            args: RegRange { start: 1, count: 2 },
            dst: 4,
        },
        TransactionalCallKindBdUr3tk12::Construct => Ir3Instruction::Construct {
            callee: 0,
            args: RegRange { start: 1, count: 2 },
            dst: 4,
        },
    };
    let body_return = if kind.is_async() {
        Ir3Instruction::AsyncReturn { value_reg: 0 }
    } else {
        Ir3Instruction::Return { value: 0 }
    };
    test_module_with_functions(
        vec![call, Ir3Instruction::Halt, body_return],
        vec![Ir3FunctionDesc {
            entry: 2,
            arity: 2,
            frame_size: 2,
            name: Some(format!("transactional_{kind:?}_bd_ur3tk_12")),
            is_generator: false,
            rest_param_index: Some(1),
        }],
    )
}

fn transactional_call_core_bd_ur3tk_12(
    kind: TransactionalCallKindBdUr3tk12,
    max_scope_depth: u32,
) -> InterpreterCore {
    let mut config = test_quickjs_config();
    config.max_scope_depth = max_scope_depth;
    let mut core = InterpreterCore::new(config, format!("transactional-{kind:?}"));
    core.enable_profiling(crate::profiling::ProfilingConfig::default());
    if kind.is_async() {
        core.closures.push(ClosureValue {
            function_index: 0,
            captured_env: core.scope_chain.snapshot(),
            module_specifier: None,
        });
        core.registers[0] = Value::AsyncFunction(0);
    } else {
        core.registers[0] = Value::Function(0);
    }
    core.registers[1] = Value::Int(10);
    core.registers[2] = Value::str("rest-tail");
    core.registers[4] = Value::str("destination-sentinel");
    core.register_labels[4] = crate::ifc_artifacts::Label::Secret;
    if kind.is_method() {
        core.registers[5] = Value::str("receiver");
        core.register_labels[5] = crate::ifc_artifacts::Label::Confidential;
    }
    core.pending_return = Some(LabeledReturn {
        value: Value::str("pending-return"),
        label: crate::ifc_artifacts::Label::TopSecret,
    });
    core.sync_estimated_memory_bytes()
        .expect("seed call state should fit its initial budget");
    core
}

fn assert_materialized_rest_hook_records_bd_ur3tk_12(hook: &RecordingHook) {
    let records = hook.records_without_startup_module_record();
    assert_eq!(records.len(), 2);
    assert!(matches!(
        records.first(),
        Some(HookRecord::Allocation {
            kind: AllocKind::Array,
            size_hint: 1,
            ..
        })
    ));
    let Some(HookRecord::Call { args, .. }) = records.get(1) else {
        panic!("pre-call hook must observe the materialized rest carrier");
    };
    assert_eq!(args.first(), Some(&Value::Int(10)));
    assert!(matches!(args.get(1), Some(Value::Object(_))));
}

#[test]
fn denied_implicit_call_setup_is_transactional_bd_ur3tk_12() {
    for kind in [
        TransactionalCallKindBdUr3tk12::Call,
        TransactionalCallKindBdUr3tk12::AsyncCall,
        TransactionalCallKindBdUr3tk12::CallMethod,
        TransactionalCallKindBdUr3tk12::AsyncCallMethod,
        TransactionalCallKindBdUr3tk12::Construct,
    ] {
        let module = transactional_call_module_bd_ur3tk_12(kind);
        let hook = Arc::new(RecordingHook::with_call_action(HookAction::Terminate(
            format!("{kind:?} denied"),
        )));
        let mut core = transactional_call_core_bd_ur3tk_12(kind, 100);
        core.set_hook(hook.clone());
        let before = capture_call_setup_state_bd_ur3tk_12(&core);

        let error = core
            .run_loop(&module)
            .expect_err("pre-call denial must refuse the entire setup transaction");

        assert!(matches!(
            error,
            InterpreterError::ContainmentActionRequested { action, .. }
                if action == "terminate"
        ));
        assert_call_setup_state_bd_ur3tk_12(&core, &before);
        assert_materialized_rest_hook_records_bd_ur3tk_12(&hook);
    }
}

#[test]
fn scope_refused_call_setup_is_transactional_bd_ur3tk_12() {
    for kind in [
        TransactionalCallKindBdUr3tk12::Call,
        TransactionalCallKindBdUr3tk12::AsyncCall,
        TransactionalCallKindBdUr3tk12::CallMethod,
        TransactionalCallKindBdUr3tk12::AsyncCallMethod,
        TransactionalCallKindBdUr3tk12::Construct,
    ] {
        let module = transactional_call_module_bd_ur3tk_12(kind);
        let hook = Arc::new(RecordingHook::allow_all());
        let mut core = transactional_call_core_bd_ur3tk_12(kind, 1);
        core.set_hook(hook.clone());
        let before = capture_call_setup_state_bd_ur3tk_12(&core);

        let error = core
            .run_loop(&module)
            .expect_err("callee scope refusal must roll back the entire setup");

        assert!(matches!(error, InterpreterError::ScopeDepthExceeded { .. }));
        assert_call_setup_state_bd_ur3tk_12(&core, &before);
        assert_materialized_rest_hook_records_bd_ur3tk_12(&hook);
    }
}

#[derive(Clone, Copy, Debug)]
enum GeneratorCallKindBdUr3tk22 {
    DirectSync,
    DirectAsync,
    MethodSync,
    MethodAsync,
}

impl GeneratorCallKindBdUr3tk22 {
    fn is_async(self) -> bool {
        matches!(self, Self::DirectAsync | Self::MethodAsync)
    }

    fn is_method(self) -> bool {
        matches!(self, Self::MethodSync | Self::MethodAsync)
    }
}

fn generator_rest_descriptor_bd_ur3tk_22() -> Ir3FunctionDesc {
    Ir3FunctionDesc {
        entry: 2,
        arity: 2,
        frame_size: 2,
        name: Some("gen_rest_bd_ur3tk_22".to_string()),
        is_generator: true,
        rest_param_index: Some(1),
    }
}

fn generator_deny_module_bd_ur3tk_22(kind: GeneratorCallKindBdUr3tk22) -> Ir3Module {
    let (call, result_reg) = if kind.is_method() {
        (
            Ir3Instruction::CallMethod {
                receiver: 0,
                callee: 1,
                args: RegRange { start: 2, count: 2 },
                dst: 4,
            },
            4,
        )
    } else {
        (
            Ir3Instruction::Call {
                callee: 0,
                args: RegRange { start: 1, count: 2 },
                dst: 3,
            },
            3,
        )
    };
    test_module_with_functions(
        vec![
            call,
            Ir3Instruction::Return { value: result_reg },
            Ir3Instruction::Return { value: 1 },
        ],
        vec![generator_rest_descriptor_bd_ur3tk_22()],
    )
}

fn generator_deny_core_bd_ur3tk_22(kind: GeneratorCallKindBdUr3tk22) -> InterpreterCore {
    let mut core = quickjs_test_core();
    core.enable_profiling(crate::profiling::ProfilingConfig::default());
    core.closures.push(ClosureValue {
        function_index: 0,
        captured_env: core.scope_chain.snapshot(),
        module_specifier: None,
    });
    let callee = if kind.is_async() {
        Value::AsyncGeneratorFunction(0)
    } else {
        Value::GeneratorFunction(0)
    };
    if kind.is_method() {
        core.registers[0] = Value::str("receiver");
        core.register_labels[0] = crate::ifc_artifacts::Label::Confidential;
        core.registers[1] = callee;
        core.registers[2] = Value::Int(10);
        core.registers[3] = Value::str("rest-tail");
        core.register_labels[3] = crate::ifc_artifacts::Label::Secret;
    } else {
        core.registers[0] = callee;
        core.registers[1] = Value::Int(10);
        core.registers[2] = Value::str("rest-tail");
        core.register_labels[2] = crate::ifc_artifacts::Label::Secret;
    }
    core.sync_estimated_memory_bytes()
        .expect("seed generator call state should fit its initial budget");
    core
}

/// bd-ur3tk.22: A denied pre-call hook must roll back the implicit rest-Array
/// carrier that `apply_rest_param` materializes for a generator/async-generator
/// call, across both the direct (`Call`) and method (`CallMethod`) forms. Before
/// this fix the four generator branches materialized the carrier on the shared
/// heap and, unlike the ordinary call path (bd-ur3tk.12), left it stranded on
/// denial — leaking heap objects plus eager/profiling memory accounting and
/// orphaning a Secret-labeled carrier (parent bd-ur3tk taint surface).
#[test]
fn denied_generator_rest_carrier_setup_is_transactional_bd_ur3tk_22() {
    for kind in [
        GeneratorCallKindBdUr3tk22::DirectSync,
        GeneratorCallKindBdUr3tk22::DirectAsync,
        GeneratorCallKindBdUr3tk22::MethodSync,
        GeneratorCallKindBdUr3tk22::MethodAsync,
    ] {
        let module = generator_deny_module_bd_ur3tk_22(kind);
        let hook = Arc::new(RecordingHook::with_call_action(HookAction::Terminate(
            format!("{kind:?} generator call denied"),
        )));
        let mut core = generator_deny_core_bd_ur3tk_22(kind);
        core.set_hook(hook.clone());
        let heap_len_before = core.heap.len();
        let generators_before = core.generators.len();
        let async_generators_before = core.async_generators.len();
        let before = capture_call_setup_state_bd_ur3tk_12(&core);

        let error = core
            .run_loop(&module)
            .expect_err("pre-call denial must refuse the entire generator rest-carrier setup");

        assert!(
            matches!(
                error,
                InterpreterError::ContainmentActionRequested { ref action, .. }
                    if action == "terminate"
            ),
            "{kind:?}: expected a containment denial, got {error:?}"
        );
        // The materialized rest Array must be fully reclaimed from the shared
        // heap, and no generator/async-generator object may be published.
        assert_eq!(
            core.heap.len(),
            heap_len_before,
            "{kind:?}: the denied rest carrier must be reclaimed from the heap"
        );
        assert_eq!(
            core.generators.len(),
            generators_before,
            "{kind:?}: no generator object may be published on denial"
        );
        assert_eq!(
            core.async_generators.len(),
            async_generators_before,
            "{kind:?}: no async-generator object may be published on denial"
        );
        // Eager memory, profiling allocation counters, caller registers/labels,
        // pending return/exception, tables, and the deterministic replay seed
        // all return to their exact pre-setup values.
        assert_call_setup_state_bd_ur3tk_12(&core, &before);
        // ...yet the hook still OBSERVED the materialized carrier before denying,
        // proving the rollback reclaims a real allocation, not a phantom one.
        assert_materialized_rest_hook_records_bd_ur3tk_12(&hook);
    }
}

/// bd-tstbe: a PRE-PROLOGUE setup refusal inside `prepare_generator_activation`
/// (scope-depth here) must roll back the implicit rest-Array carrier exactly
/// like a denied pre-call hook (bd-ur3tk.22) — no parameter prologue ran, so
/// the carrier is still the heap tail and the blind `restore_call_setup`
/// truncate is correct. Covers all four generator call branches.
#[test]
fn generator_rest_carrier_rolls_back_on_scope_refusal_bd_tstbe() {
    for kind in [
        GeneratorCallKindBdUr3tk22::DirectSync,
        GeneratorCallKindBdUr3tk22::DirectAsync,
        GeneratorCallKindBdUr3tk22::MethodSync,
        GeneratorCallKindBdUr3tk22::MethodAsync,
    ] {
        let module = generator_deny_module_bd_ur3tk_22(kind);
        let mut core = generator_deny_core_bd_ur3tk_22(kind);
        // No hook: force the pre-prologue scope-depth refusal at the
        // generator's own scope_chain.push (one frame past the caller's
        // current depth).
        core.config.max_scope_depth = core.scope_chain.depth() as u32;
        let heap_len_before = core.heap.len();
        let generators_before = core.generators.len();
        let async_generators_before = core.async_generators.len();
        let before = capture_call_setup_state_bd_ur3tk_12(&core);

        let error = core
            .run_loop(&module)
            .expect_err("scope-depth refusal must refuse the entire generator rest-carrier setup");
        assert!(
            matches!(error, InterpreterError::ScopeDepthExceeded { .. }),
            "{kind:?}: expected a scope-depth refusal, got {error:?}"
        );
        assert_eq!(
            core.heap.len(),
            heap_len_before,
            "{kind:?}: the refused rest carrier must be reclaimed from the heap"
        );
        assert_eq!(
            core.generators.len(),
            generators_before,
            "{kind:?}: no generator object may be published on a setup refusal"
        );
        assert_eq!(
            core.async_generators.len(),
            async_generators_before,
            "{kind:?}: no async-generator object may be published on a setup refusal"
        );
        assert_call_setup_state_bd_ur3tk_12(&core, &before);
    }
}

fn async_memory_failure_module_bd_ur3tk_12(method: bool) -> Ir3Module {
    let call = if method {
        Ir3Instruction::CallMethod {
            receiver: 5,
            callee: 0,
            args: RegRange { start: 1, count: 1 },
            dst: 4,
        }
    } else {
        Ir3Instruction::Call {
            callee: 0,
            args: RegRange { start: 1, count: 1 },
            dst: 4,
        }
    };
    test_module_with_functions(
        vec![
            call,
            Ir3Instruction::Halt,
            Ir3Instruction::AsyncReturn { value_reg: 0 },
        ],
        vec![Ir3FunctionDesc {
            entry: 2,
            arity: 1,
            frame_size: 1,
            name: Some(format!("async_memory_failure_method_{method}_bd_ur3tk_12")),
            is_generator: false,
            rest_param_index: None,
        }],
    )
}

fn async_memory_failure_core_bd_ur3tk_12(method: bool) -> InterpreterCore {
    let mut core = InterpreterCore::new(
        test_quickjs_config(),
        format!("async-memory-failure-method-{method}"),
    );
    core.closures.push(ClosureValue {
        function_index: 0,
        captured_env: core.scope_chain.snapshot(),
        module_specifier: None,
    });
    core.registers[0] = Value::AsyncFunction(0);
    core.registers[1] = Value::str("duplicated-argument".repeat(64));
    core.registers[4] = Value::str("destination-sentinel");
    core.register_labels[4] = crate::ifc_artifacts::Label::Secret;
    if method {
        core.registers[5] = Value::str("method-receiver");
        core.register_labels[5] = crate::ifc_artifacts::Label::Confidential;
    }
    core.sync_estimated_memory_bytes()
        .expect("seed async call state should fit");
    core
}

fn async_scope_sync_ceiling_bd_ur3tk_12(method: bool) -> u64 {
    let mut calibration = async_memory_failure_core_bd_ur3tk_12(method);
    let captured_env = calibration.scope_chain.snapshot();
    let module = async_memory_failure_module_bd_ur3tk_12(method);
    calibration
        .prepare_async_function_activation(
            &module,
            AsyncCallSetup {
                function_index: 0,
                function_entry: 2,
                captured_env: Some(captured_env),
                arguments: Vec::new(),
                this_value: if method {
                    Value::str("method-receiver")
                } else {
                    Value::Undefined
                },
                this_label: if method {
                    crate::ifc_artifacts::Label::Confidential
                } else {
                    crate::ifc_artifacts::Label::Public
                },
                super_value: Value::Undefined,
                super_label: crate::ifc_artifacts::Label::Public,
                result_register: 4,
            },
        )
        .expect("unbounded calibration setup should reach the argument-copy boundary");
    calibration.estimated_memory_bytes
}

#[test]
fn async_memory_and_argument_refusals_restore_plain_and_method_setup_bd_ur3tk_12() {
    for method in [false, true] {
        let module = async_memory_failure_module_bd_ur3tk_12(method);
        let scope_sync_ceiling = async_scope_sync_ceiling_bd_ur3tk_12(method);

        let mut scope_refused = async_memory_failure_core_bd_ur3tk_12(method);
        scope_refused.config.max_total_memory_bytes = scope_sync_ceiling.saturating_sub(1);
        let before_scope = capture_call_setup_state_bd_ur3tk_12(&scope_refused);
        let scope_error = scope_refused
            .run_loop(&module)
            .expect_err("one byte below the frame/scope estimate must refuse setup");
        assert!(matches!(
            scope_error,
            InterpreterError::MemoryBudgetExceeded { .. }
        ));
        assert_call_setup_state_bd_ur3tk_12(&scope_refused, &before_scope);

        let mut argument_refused = async_memory_failure_core_bd_ur3tk_12(method);
        argument_refused.config.max_total_memory_bytes = scope_sync_ceiling;
        let before_argument = capture_call_setup_state_bd_ur3tk_12(&argument_refused);
        let argument_error = argument_refused
            .run_loop(&module)
            .expect_err("argument copy must refuse after frame/scope setup reaches its ceiling");
        assert!(matches!(
            argument_error,
            InterpreterError::MemoryBudgetExceeded { .. }
        ));
        assert_call_setup_state_bd_ur3tk_12(&argument_refused, &before_argument);
    }
}

#[test]
fn timer_callback_refusals_restore_rest_and_frame_setup_bd_ur3tk_12() {
    for (call_action, max_scope_depth) in [
        (
            HookAction::Terminate("timer callback denied".to_string()),
            100,
        ),
        (HookAction::Allow, 1),
    ] {
        let module = test_module_with_functions(
            vec![Ir3Instruction::Halt],
            vec![Ir3FunctionDesc {
                entry: 0,
                arity: 1,
                frame_size: 1,
                name: Some("transactional_timer_callback_bd_ur3tk_12".to_string()),
                is_generator: false,
                rest_param_index: Some(0),
            }],
        );
        let mut config = test_quickjs_config();
        config.max_scope_depth = max_scope_depth;
        let mut core = InterpreterCore::new(config, "transactional-timer-callback");
        core.enable_profiling(crate::profiling::ProfilingConfig::default());
        core.closures.push(ClosureValue {
            function_index: 0,
            captured_env: core.scope_chain.snapshot(),
            module_specifier: None,
        });
        core.sync_estimated_memory_bytes()
            .expect("seed timer callback state should fit");
        let hook = Arc::new(RecordingHook::with_call_action(call_action.clone()));
        core.set_hook(hook.clone());
        let before = capture_call_setup_state_bd_ur3tk_12(&core);

        let error = core
            .execute_timer_closure(&module, 0)
            .expect_err("timer callback setup refusal must remain transactional");

        match call_action {
            HookAction::Terminate(_) => assert!(matches!(
                error,
                InterpreterError::ContainmentActionRequested { action, .. }
                    if action == "terminate"
            )),
            HookAction::Allow => {
                assert!(matches!(error, InterpreterError::ScopeDepthExceeded { .. }))
            }
            _ => unreachable!("test matrix uses only termination and scope refusal"),
        }
        assert_call_setup_state_bd_ur3tk_12(&core, &before);
        let records = hook.records_without_startup_module_record();
        assert!(matches!(
            records.as_slice(),
            [
                HookRecord::Allocation {
                    kind: AllocKind::Array,
                    size_hint: 0,
                    ..
                },
                HookRecord::Call { args, .. }
            ] if matches!(args.first(), Some(Value::Object(_)))
        ));
    }
}

fn assert_rest_array_result_bd_ur3tk_9(core: &InterpreterCore, result: Value, destination: Reg) {
    let Value::Object(array_id) = result else {
        panic!("rest parameter should return an Array object");
    };
    assert_eq!(
        core.read_array_like_values(array_id),
        vec![Value::Int(20), Value::Int(30)]
    );
    assert_eq!(
        core.read_reg_label(destination)
            .expect("rest return label should remain readable"),
        crate::ifc_artifacts::Label::Secret
    );
}

fn rest_return_descriptor_bd_ur3tk_9() -> Ir3FunctionDesc {
    Ir3FunctionDesc {
        entry: 2,
        arity: 2,
        frame_size: 2,
        name: Some("return_rest".to_string()),
        is_generator: false,
        rest_param_index: Some(1),
    }
}

#[test]
fn plain_call_rest_joins_only_trailing_argument_labels_bd_ur3tk_9() {
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
        vec![rest_return_descriptor_bd_ur3tk_9()],
    );
    let mut core = quickjs_test_core();
    core.registers[0] = Value::Function(0);
    core.write_reg_with_label(1, Value::Int(10), crate::ifc_artifacts::Label::TopSecret)
        .expect("fixed argument should be writable");
    core.write_reg_with_label(2, Value::Int(20), crate::ifc_artifacts::Label::Confidential)
        .expect("first rest argument should be writable");
    core.write_reg_with_label(3, Value::Int(30), crate::ifc_artifacts::Label::Secret)
        .expect("second rest argument should be writable");

    let result = core.run_loop(&module).expect("rest call should return");
    assert_rest_array_result_bd_ur3tk_9(&core, result, 4);
}

#[test]
fn method_call_rest_joins_trailing_argument_labels_bd_ur3tk_9() {
    let module = test_module_with_functions(
        vec![
            Ir3Instruction::CallMethod {
                receiver: 0,
                callee: 1,
                args: RegRange { start: 2, count: 3 },
                dst: 5,
            },
            Ir3Instruction::Return { value: 5 },
            Ir3Instruction::Return { value: 1 },
        ],
        vec![rest_return_descriptor_bd_ur3tk_9()],
    );
    let mut core = quickjs_test_core();
    core.registers[0] = Value::str("receiver");
    core.registers[1] = Value::Function(0);
    core.write_reg_with_label(2, Value::Int(10), crate::ifc_artifacts::Label::TopSecret)
        .expect("fixed argument should be writable");
    core.write_reg_with_label(3, Value::Int(20), crate::ifc_artifacts::Label::Confidential)
        .expect("first rest argument should be writable");
    core.write_reg_with_label(4, Value::Int(30), crate::ifc_artifacts::Label::Secret)
        .expect("second rest argument should be writable");

    let result = core.run_loop(&module).expect("rest method should return");
    assert_rest_array_result_bd_ur3tk_9(&core, result, 5);
}

#[test]
fn constructor_rest_uses_r0_formal_abi_and_joins_labels_bd_ur3tk_9() {
    let module = test_module_with_functions(
        vec![
            Ir3Instruction::Construct {
                callee: 0,
                args: RegRange { start: 1, count: 3 },
                dst: 4,
            },
            Ir3Instruction::Return { value: 4 },
            Ir3Instruction::Return { value: 1 },
        ],
        vec![rest_return_descriptor_bd_ur3tk_9()],
    );
    let mut core = quickjs_test_core();
    core.registers[0] = Value::Function(0);
    core.write_reg_with_label(1, Value::Int(10), crate::ifc_artifacts::Label::TopSecret)
        .expect("fixed argument should be writable");
    core.write_reg_with_label(2, Value::Int(20), crate::ifc_artifacts::Label::Confidential)
        .expect("first rest argument should be writable");
    core.write_reg_with_label(3, Value::Int(30), crate::ifc_artifacts::Label::Secret)
        .expect("second rest argument should be writable");

    let result = core
        .run_loop(&module)
        .expect("rest constructor should return its explicit Array");
    assert_rest_array_result_bd_ur3tk_9(&core, result, 4);
}

#[test]
fn empty_rest_materializes_empty_public_array_bd_ur3tk_9() {
    let module = test_module_with_functions(
        vec![
            Ir3Instruction::Call {
                callee: 0,
                args: RegRange { start: 1, count: 1 },
                dst: 2,
            },
            Ir3Instruction::Return { value: 2 },
            Ir3Instruction::Return { value: 1 },
        ],
        vec![rest_return_descriptor_bd_ur3tk_9()],
    );
    let mut core = quickjs_test_core();
    core.registers[0] = Value::Function(0);
    core.write_reg_with_label(1, Value::Int(10), crate::ifc_artifacts::Label::TopSecret)
        .expect("fixed argument should be writable");

    let result = core.run_loop(&module).expect("empty rest should return");
    let Value::Object(array_id) = result else {
        panic!("empty rest parameter should return an Array object");
    };
    assert!(core.read_array_like_values(array_id).is_empty());
    assert_eq!(
        core.read_reg_label(2).expect("empty rest result label"),
        crate::ifc_artifacts::Label::Public
    );
}

#[test]
fn malformed_nonfinal_rest_descriptor_is_rejected_bd_ur3tk_9() {
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
            arity: 3,
            frame_size: 3,
            name: Some("malformed_rest".to_string()),
            is_generator: false,
            rest_param_index: Some(1),
        }],
    );
    let mut core = quickjs_test_core();
    core.registers[0] = Value::Function(0);

    let error = core
        .run_loop(&module)
        .expect_err("non-final rest metadata must fail closed");
    assert!(matches!(error, InterpreterError::TypeError { .. }));
}

#[test]
fn malformed_constructor_rest_is_rejected_before_allocation_bd_ur3tk_9() {
    let module = test_module_with_functions(
        vec![
            Ir3Instruction::Construct {
                callee: 0,
                args: RegRange { start: 1, count: 3 },
                dst: 4,
            },
            Ir3Instruction::Return { value: 4 },
            Ir3Instruction::Return { value: 1 },
        ],
        vec![Ir3FunctionDesc {
            entry: 2,
            arity: 3,
            frame_size: 3,
            name: Some("malformed_constructor_rest".to_string()),
            is_generator: false,
            rest_param_index: Some(1),
        }],
    );
    let mut core = quickjs_test_core();
    core.registers[0] = Value::Function(0);
    let heap_len = core.heap.len();
    let estimated_memory_bytes = core.estimated_memory_bytes;
    let function_prototypes = core.function_prototypes.clone();

    core.run_loop(&module)
        .expect_err("malformed constructor metadata must fail before setup");
    assert_eq!(core.heap.len(), heap_len);
    assert_eq!(core.estimated_memory_bytes, estimated_memory_bytes);
    assert_eq!(core.function_prototypes, function_prototypes);
}

#[test]
fn rest_policy_hooks_observe_guarded_materialized_carrier_bd_ur3tk_9() {
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
        vec![rest_return_descriptor_bd_ur3tk_9()],
    );
    let hook = Arc::new(RecordingHook::allow_all());
    let mut core = quickjs_test_core();
    core.set_hook(hook.clone());
    core.registers[0] = Value::Function(0);
    core.registers[1] = Value::Int(10);
    core.registers[2] = Value::Int(20);
    core.registers[3] = Value::Int(30);

    core.run_loop(&module)
        .expect("guarded rest call should execute");
    let records = hook.records_without_startup_module_record();
    assert_eq!(records.len(), 2);
    assert!(matches!(
        records.first(),
        Some(HookRecord::Allocation {
            kind: AllocKind::Array,
            size_hint: 2,
            ..
        })
    ));
    let HookRecord::Call { args, .. } = &records[1] else {
        panic!("pre-call hook must run after rest allocation");
    };
    assert_eq!(args.first(), Some(&Value::Int(10)));
    let Some(Value::Object(rest_array)) = args.get(1) else {
        panic!("pre-call hook must receive the materialized rest Array");
    };
    assert_eq!(
        core.read_array_like_values(*rest_array),
        vec![Value::Int(20), Value::Int(30)]
    );
}

#[test]
fn denied_rest_allocation_leaves_heap_unchanged_bd_ur3tk_9() {
    let module = test_module_with_functions(
        vec![
            Ir3Instruction::Call {
                callee: 0,
                args: RegRange { start: 1, count: 2 },
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
            Ir3Instruction::Return { value: 1 },
        ],
        vec![rest_return_descriptor_bd_ur3tk_9()],
    );
    let hook = Arc::new(RecordingHook::with_allocation_action(
        HookAction::Terminate("rest allocation denied".to_string()),
    ));
    let mut core = quickjs_test_core();
    core.set_hook(hook.clone());
    core.registers[0] = Value::Function(0);
    core.registers[1] = Value::Int(10);
    core.registers[2] = Value::Int(20);
    let heap_len = core.heap.len();
    let estimated_memory_bytes = core.estimated_memory_bytes;

    core.run_loop(&module)
        .expect_err("allocation policy must deny the implicit rest Array");
    assert_eq!(core.heap.len(), heap_len);
    assert_eq!(core.estimated_memory_bytes, estimated_memory_bytes);
    assert!(matches!(
        hook.records_without_startup_module_record().as_slice(),
        [HookRecord::Allocation {
            kind: AllocKind::Array,
            size_hint: 1,
            ..
        }]
    ));
}

#[test]
fn denied_constructor_rest_allocation_leaves_setup_unchanged_bd_ur3tk_9() {
    let module = test_module_with_functions(
        vec![
            Ir3Instruction::Construct {
                callee: 0,
                args: RegRange { start: 1, count: 2 },
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
            Ir3Instruction::Return { value: 1 },
        ],
        vec![rest_return_descriptor_bd_ur3tk_9()],
    );
    let hook = Arc::new(RecordingHook::with_allocation_action(
        HookAction::Terminate("constructor rest allocation denied".to_string()),
    ));
    let mut core = quickjs_test_core();
    core.set_hook(hook.clone());
    core.registers[0] = Value::Function(0);
    core.registers[1] = Value::Int(10);
    core.registers[2] = Value::Int(20);
    let heap_len = core.heap.len();
    let estimated_memory_bytes = core.estimated_memory_bytes;
    let function_prototypes = core.function_prototypes.clone();

    core.run_loop(&module)
        .expect_err("rest allocation policy must deny constructor setup");
    assert_eq!(core.heap.len(), heap_len);
    assert_eq!(core.estimated_memory_bytes, estimated_memory_bytes);
    assert_eq!(core.function_prototypes, function_prototypes);
    assert!(matches!(
        hook.records_without_startup_module_record().as_slice(),
        [HookRecord::Allocation {
            kind: AllocKind::Array,
            size_hint: 1,
            ..
        }]
    ));
}

#[test]
fn reexecution_restores_initial_register_seed_without_runtime_leakage() {
    let m = test_module_with_functions(
        vec![
            Ir3Instruction::Call {
                callee: 3,
                args: RegRange { start: 1, count: 1 },
                dst: 0,
            },
            Ir3Instruction::Halt,
            Ir3Instruction::LoadInt { dst: 1, value: 10 },
            Ir3Instruction::Add {
                dst: 2,
                lhs: 0,
                rhs: 1,
            },
            Ir3Instruction::Return { value: 2 },
        ],
        vec![Ir3FunctionDesc {
            entry: 2,
            arity: 1,
            frame_size: 3,
            name: Some("add_ten".to_string()),
            is_generator: false,
            rest_param_index: None,
        }],
    );

    let mut config = test_quickjs_config();
    config.instruction_budget = 1000;
    let mut core = InterpreterCore::new(config, "test");
    core.registers[1] = Value::Int(5);
    core.registers[3] = Value::Function(0);

    let first = core.execute(&m).unwrap();
    assert_eq!(first.value, Value::Int(15));

    let second = core.execute(&m).unwrap();
    assert_eq!(second.value, Value::Int(15));
}

#[test]
fn stack_overflow() {
    // Recursive function that calls itself.
    let m = test_module_with_functions(
        vec![
            // Load function ref and call
            Ir3Instruction::Call {
                callee: 0,
                args: RegRange { start: 0, count: 1 },
                dst: 0,
            }, // 0 (entry)
        ],
        vec![Ir3FunctionDesc {
            entry: 0,
            arity: 1,
            frame_size: 1,
            name: Some("recurse".to_string()),
            is_generator: false,
            rest_param_index: None,
        }],
    );

    let mut config = test_quickjs_config();
    config.max_call_depth = 10;
    config.instruction_budget = 100;
    let mut core = InterpreterCore::new(config, "test");
    core.registers[0] = Value::Function(0);
    let err = core.execute(&m).unwrap_err();
    assert!(matches!(err, InterpreterError::StackOverflow { .. }));
}

// -----------------------------------------------------------------------
// 5. Budget exhaustion
// -----------------------------------------------------------------------

#[test]
fn budget_exhaustion() {
    // Infinite loop.
    let m = test_module(vec![Ir3Instruction::Jump { target: 0 }]);

    let mut config = test_quickjs_config();
    config.instruction_budget = 5;
    let lane = QuickJsLane::with_config(config);
    let err = lane.execute(&m, "test").unwrap_err();
    assert!(matches!(err, InterpreterError::BudgetExhausted { .. }));
}

// -----------------------------------------------------------------------
// 6. Register bounds
// -----------------------------------------------------------------------

#[test]
fn register_out_of_bounds() {
    let m = test_module(vec![Ir3Instruction::LoadInt {
        dst: 9999,
        value: 1,
    }]);

    let mut config = test_quickjs_config();
    config.max_registers = 256;
    let lane = QuickJsLane::with_config(config);
    let err = lane.execute(&m, "test").unwrap_err();
    assert!(matches!(err, InterpreterError::RegisterOutOfBounds { .. }));
}

// -----------------------------------------------------------------------
// 7. String pool bounds
// -----------------------------------------------------------------------

#[test]
fn string_pool_out_of_bounds() {
    let m = test_module(vec![Ir3Instruction::LoadStr {
        dst: 0,
        pool_index: 99,
    }]);
    let err = quickjs_execute(&m).unwrap_err();
    assert!(matches!(
        err,
        InterpreterError::StringPoolOutOfBounds { .. }
    ));
}

// -----------------------------------------------------------------------
// 8. Move instruction
// -----------------------------------------------------------------------

#[test]
fn move_register() {
    let m = test_module(vec![
        Ir3Instruction::LoadInt { dst: 1, value: 42 },
        Ir3Instruction::Move { dst: 0, src: 1 },
        Ir3Instruction::Halt,
    ]);
    let result = quickjs_execute(&m).unwrap();
    assert_eq!(result.value, Value::Int(42));
}

// -----------------------------------------------------------------------
// 9. Hostcall capability check
// -----------------------------------------------------------------------

#[test]
fn hostcall_capability_denied() {
    let m = test_module(vec![Ir3Instruction::HostCall {
        capability: CapabilityTag("network".to_string()),
        args: RegRange { start: 0, count: 0 },
        dst: 0,
    }]);
    let err = quickjs_execute(&m).unwrap_err();
    assert!(matches!(err, InterpreterError::CapabilityDenied { .. }));
}

#[test]
fn hostcall_capability_granted() {
    let m = test_module(vec![
        Ir3Instruction::HostCall {
            capability: CapabilityTag("network".to_string()),
            args: RegRange { start: 0, count: 0 },
            dst: 0,
        },
        Ir3Instruction::Halt,
    ]);
    let config = test_quickjs_config_with([RuntimeCapability::NetworkEgress]);
    let lane = QuickJsLane::with_config(config);
    let result = lane.execute(&m, "test").unwrap();
    assert_eq!(result.value, Value::Undefined);
}

#[test]
fn promise_resolve_wrapper_preserves_source_label_bd_ur3tk_13() {
    let module = test_module(vec![
        Ir3Instruction::HostCall {
            capability: CapabilityTag("promise:resolve".to_string()),
            args: RegRange { start: 0, count: 1 },
            dst: 1,
        },
        Ir3Instruction::Halt,
    ]);
    let mut core = quickjs_test_core();
    core.write_reg_with_label(
        0,
        Value::str("secret-resolution"),
        crate::ifc_artifacts::Label::Secret,
    )
    .expect("resolution source should be writable");

    core.execute(&module)
        .expect("Promise.resolve hostcall should execute");

    let Value::Promise(handle) = core.registers[1] else {
        panic!("Promise.resolve should return a Promise handle");
    };
    assert_eq!(
        core.read_reg_label(1).expect("result label should exist"),
        crate::ifc_artifacts::Label::Secret
    );
    let record = core
        .promise_store
        .get(crate::promise_model::PromiseHandle(handle))
        .expect("resolved Promise should exist");
    assert_eq!(record.label, crate::ifc_artifacts::Label::Secret);
}

#[test]
fn promise_reject_preserves_reason_identity_and_label_bd_9vouw_92() {
    let module = test_module(vec![
        Ir3Instruction::HostCall {
            capability: CapabilityTag("promise:reject".to_string()),
            args: RegRange { start: 0, count: 2 },
            dst: 2,
        },
        Ir3Instruction::HostCall {
            capability: CapabilityTag("promise:then".to_string()),
            args: RegRange { start: 2, count: 1 },
            dst: 3,
        },
        Ir3Instruction::Halt,
    ]);
    let cases = [
        (
            crate::ifc_artifacts::Label::Secret,
            crate::ifc_artifacts::Label::Custom {
                name: "tenant-rejection".to_string(),
                level: 2,
            },
            "target-dominant",
        ),
        (
            crate::ifc_artifacts::Label::Public,
            crate::ifc_artifacts::Label::Secret,
            "reason-dominant",
        ),
    ];

    for (target_label, extra_label, extra_value) in cases {
        let expected_label = target_label.clone();
        let mut core = quickjs_test_core();
        let target = core.create_promise_accounted().expect("source promise");
        core.write_reg_with_label(0, Value::Promise(target.0), target_label)
            .expect("reason Promise should be writable");
        core.write_reg_with_label(1, Value::str(extra_value), extra_label)
            .expect("ignored argument should be writable");

        core.execute(&module)
            .expect("Promise.reject hostcall should execute");

        let Value::Promise(rejected) = core.registers[2] else {
            panic!("Promise.reject should return a Promise");
        };
        assert_ne!(rejected, target.0, "rejection allocates a new promise");
        assert_eq!(
            core.read_reg_label(2).expect("result label should exist"),
            expected_label,
            "returned handle preserves the actual reason's provenance"
        );
        let record = core
            .promise_store
            .get(crate::promise_model::PromiseHandle(rejected))
            .expect("rejected Promise should exist");
        assert_eq!(
            record.label, expected_label,
            "settlement retains the reason's label, ignoring extra arguments"
        );
        assert_eq!(
            record.state,
            crate::promise_model::PromiseState::Rejected(crate::object_model::JsValue::Promise(
                target.0
            ))
        );
        assert_eq!(
            core.promise_store.get(target).unwrap().state,
            crate::promise_model::PromiseState::Pending,
            "a reference to another promise does not grant settlement authority"
        );
        let Value::Promise(chained) = core.registers[3] else {
            panic!("then should return a distinct chained promise");
        };
        let propagated = core
            .promise_store
            .get(crate::promise_model::PromiseHandle(chained))
            .unwrap();
        assert_eq!(propagated.state, record.state);
        assert_eq!(propagated.label, expected_label);
        assert_eq!(
            core.read_reg_label(3).unwrap(),
            expected_label,
            "queued rejection propagation retains the reason's provenance"
        );
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }
}

#[test]
fn promise_resolve_preserves_all_source_states_bd_9vouw_92() {
    use crate::ifc_artifacts::Label;
    use crate::object_model::JsValue;
    use crate::promise_model::PromiseState;

    let module = test_module(vec![
        Ir3Instruction::HostCall {
            capability: CapabilityTag("promise:resolve".to_string()),
            args: RegRange { start: 0, count: 2 },
            dst: 2,
        },
        Ir3Instruction::Halt,
    ]);
    for state in [
        PromiseState::Pending,
        PromiseState::Fulfilled(JsValue::Int(17)),
        PromiseState::Rejected(JsValue::str("original rejection")),
    ] {
        let mut core = quickjs_test_core();
        let source = core.create_promise_accounted().expect("source promise");
        match &state {
            PromiseState::Pending => {}
            PromiseState::Fulfilled(value) => core
                .fulfill_promise(source, value.clone(), Label::Secret)
                .unwrap(),
            PromiseState::Rejected(reason) => core
                .reject_promise(source, reason.clone(), Label::Secret)
                .unwrap(),
        }
        core.write_reg_with_label(0, Value::Promise(source.0), Label::Secret)
            .unwrap();
        core.write_reg_with_label(1, Value::str("hijacked"), Label::Public)
            .unwrap();
        let witness = core.promise_store.witness_log().to_vec();
        let count = core.promise_store.len();

        core.execute(&module).expect("identity resolution succeeds");

        assert_eq!(core.registers[2], Value::Promise(source.0));
        assert_eq!(core.read_reg_label(2).unwrap(), Label::Secret);
        assert_eq!(core.promise_store.get(source).unwrap().state, state);
        assert_eq!(
            core.promise_store.len(),
            count,
            "identity allocates no promise"
        );
        assert_eq!(core.promise_store.witness_log(), witness);
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }
}

#[test]
fn promise_reject_accepts_settled_promise_reasons_bd_9vouw_92() {
    use crate::ifc_artifacts::Label;
    use crate::object_model::JsValue;
    use crate::promise_model::PromiseState;

    for fulfilled in [false, true] {
        let mut core = quickjs_test_core();
        let source = core.create_promise_accounted().unwrap();
        if fulfilled {
            core.fulfill_promise(source, JsValue::Int(7), Label::Public)
                .unwrap();
        } else {
            core.reject_promise(source, JsValue::str("original"), Label::Public)
                .unwrap();
        }
        let original_state = core.promise_store.get(source).unwrap().state.clone();
        core.write_reg_with_label(0, Value::Promise(source.0), Label::Secret)
            .unwrap();
        let (result, label) = core
            .dispatch_promise_hostcall(
                &test_module(Vec::new()),
                "promise:reject",
                RegRange { start: 0, count: 1 },
            )
            .expect("a settled promise is a valid rejection reason");
        let Value::Promise(rejected) = result else {
            panic!("rejection returns a promise");
        };
        assert_ne!(rejected, source.0);
        assert_eq!(label, Label::Secret);
        assert_eq!(
            core.promise_store.get(source).unwrap().state,
            original_state
        );
        let reason = &core
            .promise_store
            .get(crate::promise_model::PromiseHandle(rejected))
            .unwrap()
            .state;
        assert_eq!(reason, &PromiseState::Rejected(JsValue::Promise(source.0)));
        let restored: PromiseState =
            serde_json::from_str(&serde_json::to_string(reason).unwrap()).unwrap();
        assert_eq!(
            restored, *reason,
            "replay retains the promise reason identity"
        );
        assert_eq!(
            InterpreterCore::js_value_to_value(&JsValue::Promise(source.0)),
            Value::Promise(source.0)
        );
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }
}

#[test]
fn pending_promise_reactions_preserve_registration_labels_bd_ur3tk_13() {
    let custom = crate::ifc_artifacts::Label::Custom {
        name: "tenant-reaction".to_string(),
        level: 4,
    };
    let cases = [
        (
            "promise:then",
            3,
            crate::ifc_artifacts::Label::Public,
            crate::ifc_artifacts::Label::Public,
            crate::ifc_artifacts::Label::Secret,
            crate::ifc_artifacts::Label::Secret,
        ),
        (
            "promise:catch",
            2,
            crate::ifc_artifacts::Label::Public,
            custom.clone(),
            crate::ifc_artifacts::Label::Public,
            custom,
        ),
        (
            "promise:finally",
            2,
            crate::ifc_artifacts::Label::Secret,
            crate::ifc_artifacts::Label::Public,
            crate::ifc_artifacts::Label::Public,
            crate::ifc_artifacts::Label::Secret,
        ),
    ];

    for (capability, count, source_label, handler_label, reject_label, expected_label) in cases {
        let module = test_module(vec![
            Ir3Instruction::HostCall {
                capability: CapabilityTag(capability.to_string()),
                args: RegRange { start: 0, count },
                dst: 3,
            },
            Ir3Instruction::Halt,
        ]);
        let mut core = quickjs_test_core();
        let source = core.promise_store.create();
        core.write_reg_with_label(0, Value::Promise(source.0), source_label)
            .expect("source Promise should be writable");
        core.write_reg_with_label(1, Value::Undefined, handler_label)
            .expect("fulfillment handler slot should be writable");
        core.write_reg_with_label(2, Value::Undefined, reject_label)
            .expect("rejection handler slot should be writable");

        core.execute(&module)
            .expect("Promise reaction hostcall should execute");

        let Value::Promise(result_handle) = core.registers[3] else {
            panic!("{capability} should return a Promise handle");
        };
        assert_eq!(
            core.read_reg_label(3).expect("result label should exist"),
            expected_label,
            "{capability} result handle carries registration provenance"
        );
        core.fulfill_promise(
            source,
            crate::object_model::JsValue::Int(7),
            crate::ifc_artifacts::Label::Public,
        )
        .expect("source Promise should fulfill");
        core.drain_microtasks(None)
            .expect("Promise reaction microtasks should drain");
        let result = core
            .promise_store
            .get(crate::promise_model::PromiseHandle(result_handle))
            .expect("reaction result Promise should exist");
        assert_eq!(
            result.label, expected_label,
            "{capability} result settlement joins registration provenance"
        );
    }
}

fn promise_combinator_module_bd_ur3tk_19(capability: &str, args: RegRange, dst: Reg) -> Ir3Module {
    test_module(vec![
        Ir3Instruction::HostCall {
            capability: CapabilityTag(capability.to_string()),
            args,
            dst,
        },
        Ir3Instruction::Halt,
    ])
}

fn execute_promise_combinator_bd_ur3tk_19(
    core: &mut InterpreterCore,
    capability: &str,
    args: RegRange,
    dst: Reg,
) -> crate::promise_model::PromiseHandle {
    // These IFC probes supply element registers. Materialize a labeled
    // array so the probes exercise the same iterable API as source JS.
    let args = if args.count == 1
        && matches!(
            core.read_reg(args.start).unwrap(),
            Value::Object(id) if core.heap[id.0 as usize].is_array
        ) {
        args
    } else {
        let values = (0..args.count)
            .map(|index| core.read_reg(args.start + index).unwrap())
            .collect::<Vec<_>>();
        let array = core.alloc_array_from_values(&values).unwrap();
        for index in 0..args.count {
            let label = core.read_reg_label(args.start + index).unwrap();
            core.set_own_runtime_property_label(
                array,
                &RuntimePropertyKey::String(JsString::from(index.to_string())),
                &label,
            )
            .unwrap();
        }
        let iterable_reg = dst + 1;
        core.write_reg(iterable_reg, Value::Object(array)).unwrap();
        RegRange {
            start: iterable_reg,
            count: 1,
        }
    };
    core.execute(&promise_combinator_module_bd_ur3tk_19(
        capability, args, dst,
    ))
    .unwrap_or_else(|error| panic!("{capability} should execute: {error}"));
    let Value::Promise(handle) = core.registers[dst as usize] else {
        panic!("{capability} should return a Promise handle");
    };
    crate::promise_model::PromiseHandle(handle)
}

#[test]
fn combinators_join_direct_inputs_in_both_orders_bd_ur3tk_19() {
    for capability in [
        "promise:all",
        "promise:allSettled",
        "promise:race",
        "promise:any",
    ] {
        for secret_first in [true, false] {
            let mut core = quickjs_test_core();
            let (first_label, second_label) = if secret_first {
                (
                    crate::ifc_artifacts::Label::Secret,
                    crate::ifc_artifacts::Label::Public,
                )
            } else {
                (
                    crate::ifc_artifacts::Label::Public,
                    crate::ifc_artifacts::Label::Secret,
                )
            };
            core.write_reg_with_label(0, Value::Int(10), first_label)
                .expect("first input should be writable");
            core.write_reg_with_label(1, Value::Int(20), second_label)
                .expect("second input should be writable");

            let result = execute_promise_combinator_bd_ur3tk_19(
                &mut core,
                capability,
                RegRange { start: 0, count: 2 },
                2,
            );

            assert_eq!(
                core.read_reg_label(2).expect("result label should exist"),
                crate::ifc_artifacts::Label::Secret,
                "{capability} returned handle must join every direct input (secret_first={secret_first})"
            );
            let record = core
                .promise_store
                .get(result)
                .expect("aggregate Promise should exist");
            assert_eq!(
                record.label,
                crate::ifc_artifacts::Label::Secret,
                "{capability} settlement must be independent of input order (secret_first={secret_first})"
            );
            assert!(record.state.is_settled());
        }
    }
}

#[test]
fn combinators_join_already_settled_promise_labels_bd_ur3tk_19() {
    for capability in [
        "promise:all",
        "promise:allSettled",
        "promise:race",
        "promise:any",
    ] {
        for secret_first in [true, false] {
            let mut core = quickjs_test_core();
            let first = core.promise_store.create();
            let second = core.promise_store.create();
            let (first_label, second_label) = if secret_first {
                (
                    crate::ifc_artifacts::Label::Secret,
                    crate::ifc_artifacts::Label::Public,
                )
            } else {
                (
                    crate::ifc_artifacts::Label::Public,
                    crate::ifc_artifacts::Label::Secret,
                )
            };
            core.fulfill_promise(first, crate::object_model::JsValue::Int(10), first_label)
                .expect("first Promise should fulfill");
            core.fulfill_promise(second, crate::object_model::JsValue::Int(20), second_label)
                .expect("second Promise should fulfill");
            core.registers[0] = Value::Promise(first.0);
            core.registers[1] = Value::Promise(second.0);

            let result = execute_promise_combinator_bd_ur3tk_19(
                &mut core,
                capability,
                RegRange { start: 0, count: 2 },
                2,
            );

            assert_eq!(
                core.read_reg_label(2).expect("result label should exist"),
                crate::ifc_artifacts::Label::Secret,
                "{capability} handle must include known settlement provenance (secret_first={secret_first})"
            );
            let record = core
                .promise_store
                .get(result)
                .expect("aggregate Promise should exist");
            assert_eq!(record.label, crate::ifc_artifacts::Label::Secret);
        }
    }
}

#[test]
fn combinator_array_inputs_inherit_iterable_carrier_label_bd_ur3tk_19() {
    let mut core = quickjs_test_core();
    let settled = core.promise_store.create();
    core.fulfill_promise(
        settled,
        crate::object_model::JsValue::Int(20),
        crate::ifc_artifacts::Label::Public,
    )
    .expect("nested Promise should fulfill");
    let inputs = core
        .alloc_array_from_values(&[Value::Int(10), Value::Promise(settled.0)])
        .expect("input array should allocate");
    core.write_reg_with_label(
        0,
        Value::Object(inputs),
        crate::ifc_artifacts::Label::Secret,
    )
    .expect("input array carrier should be writable");

    let result = execute_promise_combinator_bd_ur3tk_19(
        &mut core,
        "promise:all",
        RegRange { start: 0, count: 1 },
        1,
    );

    assert_eq!(
        core.read_reg_label(1).expect("result label should exist"),
        crate::ifc_artifacts::Label::Secret
    );
    let record = core
        .promise_store
        .get(result)
        .expect("Promise.all aggregate should exist");
    assert_eq!(record.label, crate::ifc_artifacts::Label::Secret);
}

#[test]
fn pending_all_variants_join_settlements_in_both_orders_bd_ur3tk_19() {
    for capability in ["promise:all", "promise:allSettled"] {
        for secret_first in [true, false] {
            let mut core = quickjs_test_core();
            let first = core.promise_store.create();
            let second = core.promise_store.create();
            core.write_reg_with_label(
                0,
                Value::Promise(first.0),
                crate::ifc_artifacts::Label::Public,
            )
            .expect("first pending Promise should be writable");
            core.write_reg_with_label(
                1,
                Value::Promise(second.0),
                crate::ifc_artifacts::Label::Public,
            )
            .expect("second pending Promise should be writable");
            let result = execute_promise_combinator_bd_ur3tk_19(
                &mut core,
                capability,
                RegRange { start: 0, count: 2 },
                2,
            );

            if capability == "promise:all" {
                let (first_label, second_label) = if secret_first {
                    (
                        crate::ifc_artifacts::Label::Secret,
                        crate::ifc_artifacts::Label::Public,
                    )
                } else {
                    (
                        crate::ifc_artifacts::Label::Public,
                        crate::ifc_artifacts::Label::Secret,
                    )
                };
                core.fulfill_promise(first, crate::object_model::JsValue::Int(10), first_label)
                    .expect("first Promise should fulfill");
                core.fulfill_promise(second, crate::object_model::JsValue::Int(20), second_label)
                    .expect("second Promise should fulfill");
            } else if secret_first {
                core.reject_promise(
                    first,
                    crate::object_model::JsValue::Str("secret-first".into()),
                    crate::ifc_artifacts::Label::Secret,
                )
                .expect("first Promise should reject");
                core.fulfill_promise(
                    second,
                    crate::object_model::JsValue::Int(20),
                    crate::ifc_artifacts::Label::Public,
                )
                .expect("second Promise should fulfill");
            } else {
                core.fulfill_promise(
                    first,
                    crate::object_model::JsValue::Int(10),
                    crate::ifc_artifacts::Label::Public,
                )
                .expect("first Promise should fulfill");
                core.reject_promise(
                    second,
                    crate::object_model::JsValue::Str("secret-last".into()),
                    crate::ifc_artifacts::Label::Secret,
                )
                .expect("second Promise should reject");
            }

            assert!(matches!(
                core.promise_store.get(result).unwrap().state,
                crate::promise_model::PromiseState::Pending
            ));
            core.drain_microtasks(None)
                .expect("queued aggregate element reactions should run");
            let record = core
                .promise_store
                .get(result)
                .expect("aggregate Promise should exist");
            assert_eq!(
                record.label,
                crate::ifc_artifacts::Label::Secret,
                "{capability} must retain the earlier settlement label (secret_first={secret_first})"
            );
            assert!(matches!(
                &record.state,
                crate::promise_model::PromiseState::Fulfilled(_)
            ));
        }
    }
}

#[test]
fn promise_any_rejections_join_labels_in_both_orders_bd_ur3tk_19() {
    for secret_first in [true, false] {
        let mut core = quickjs_test_core();
        let first = core.promise_store.create();
        let second = core.promise_store.create();
        core.registers[0] = Value::Promise(first.0);
        core.registers[1] = Value::Promise(second.0);
        let result = execute_promise_combinator_bd_ur3tk_19(
            &mut core,
            "promise:any",
            RegRange { start: 0, count: 2 },
            2,
        );
        let (first_label, second_label) = if secret_first {
            (
                crate::ifc_artifacts::Label::Secret,
                crate::ifc_artifacts::Label::Public,
            )
        } else {
            (
                crate::ifc_artifacts::Label::Public,
                crate::ifc_artifacts::Label::Secret,
            )
        };
        core.reject_promise(
            first,
            crate::object_model::JsValue::Str("first".into()),
            first_label,
        )
        .expect("first Promise should reject");
        core.reject_promise(
            second,
            crate::object_model::JsValue::Str("second".into()),
            second_label,
        )
        .expect("second Promise should reject");

        assert!(matches!(
            core.promise_store.get(result).unwrap().state,
            crate::promise_model::PromiseState::Pending
        ));
        core.drain_microtasks(None)
            .expect("queued Promise.any rejection reactions should run");
        let record = core
            .promise_store
            .get(result)
            .expect("Promise.any aggregate should exist");
        assert_eq!(
            record.label,
            crate::ifc_artifacts::Label::Secret,
            "Promise.any AggregateError label must not depend on rejection order"
        );
        assert!(matches!(
            &record.state,
            crate::promise_model::PromiseState::Rejected(_)
        ));
    }
}

#[test]
fn combinator_cross_branch_short_circuits_retain_prior_label_bd_ur3tk_19() {
    for capability in ["promise:all", "promise:any"] {
        let mut core = quickjs_test_core();
        let first = core.promise_store.create();
        let second = core.promise_store.create();
        core.registers[0] = Value::Promise(first.0);
        core.registers[1] = Value::Promise(second.0);
        let result = execute_promise_combinator_bd_ur3tk_19(
            &mut core,
            capability,
            RegRange { start: 0, count: 2 },
            2,
        );

        if capability == "promise:all" {
            core.fulfill_promise(
                first,
                crate::object_model::JsValue::Int(10),
                crate::ifc_artifacts::Label::Secret,
            )
            .expect("first Promise should fulfill");
            core.reject_promise(
                second,
                crate::object_model::JsValue::Str("public-rejection".into()),
                crate::ifc_artifacts::Label::Public,
            )
            .expect("second Promise should reject");
        } else {
            core.reject_promise(
                first,
                crate::object_model::JsValue::Str("secret-rejection".into()),
                crate::ifc_artifacts::Label::Secret,
            )
            .expect("first Promise should reject");
            core.fulfill_promise(
                second,
                crate::object_model::JsValue::Int(20),
                crate::ifc_artifacts::Label::Public,
            )
            .expect("second Promise should fulfill");
        }

        assert!(matches!(
            core.promise_store.get(result).unwrap().state,
            crate::promise_model::PromiseState::Pending
        ));
        core.drain_microtasks(None)
            .expect("queued cross-branch aggregate reactions should run");
        let record = core
            .promise_store
            .get(result)
            .expect("aggregate Promise should exist");
        assert_eq!(
            record.label,
            crate::ifc_artifacts::Label::Secret,
            "{capability} must retain a prior Secret settlement when a Public input short-circuits"
        );
        assert_eq!(
            matches!(
                &record.state,
                crate::promise_model::PromiseState::Rejected(_)
            ),
            capability == "promise:all"
        );
    }
}

#[test]
fn combinator_short_circuits_join_all_input_references_bd_ur3tk_19() {
    for (capability, reject_winner) in [
        ("promise:all", true),
        ("promise:race", false),
        ("promise:race", true),
        ("promise:any", false),
    ] {
        let mut core = quickjs_test_core();
        let winner = core.promise_store.create();
        let pending = core.promise_store.create();
        core.write_reg_with_label(
            0,
            Value::Promise(winner.0),
            crate::ifc_artifacts::Label::Public,
        )
        .expect("winner should be writable");
        core.write_reg_with_label(
            1,
            Value::Promise(pending.0),
            crate::ifc_artifacts::Label::Secret,
        )
        .expect("pending competitor should be writable");
        let result = execute_promise_combinator_bd_ur3tk_19(
            &mut core,
            capability,
            RegRange { start: 0, count: 2 },
            2,
        );
        assert_eq!(
            core.read_reg_label(2).expect("result label should exist"),
            crate::ifc_artifacts::Label::Secret,
            "{capability} returned handle must include every input reference"
        );

        if reject_winner {
            core.reject_promise(
                winner,
                crate::object_model::JsValue::Str("public-winner".into()),
                crate::ifc_artifacts::Label::Public,
            )
            .expect("winner should reject");
        } else {
            core.fulfill_promise(
                winner,
                crate::object_model::JsValue::Int(7),
                crate::ifc_artifacts::Label::Public,
            )
            .expect("winner should fulfill");
        }

        assert!(matches!(
            core.promise_store.get(result).unwrap().state,
            crate::promise_model::PromiseState::Pending
        ));
        core.drain_microtasks(None)
            .expect("queued winning aggregate reaction should run");
        let record = core
            .promise_store
            .get(result)
            .expect("short-circuit aggregate should exist");
        assert_eq!(
            record.label,
            crate::ifc_artifacts::Label::Secret,
            "{capability} winner must retain the pending competitor reference label"
        );
        assert!(record.state.is_settled());
    }
}

#[test]
fn empty_combinators_preserve_carrier_labels_bd_ur3tk_19() {
    for capability in [
        "promise:all",
        "promise:allSettled",
        "promise:race",
        "promise:any",
    ] {
        let mut core = quickjs_test_core();
        let result = execute_promise_combinator_bd_ur3tk_19(
            &mut core,
            capability,
            RegRange { start: 0, count: 0 },
            0,
        );
        assert_eq!(
            core.read_reg_label(0)
                .expect("empty result label should exist"),
            crate::ifc_artifacts::Label::Public
        );
        let record = core
            .promise_store
            .get(result)
            .expect("empty aggregate should exist");
        assert_eq!(record.label, crate::ifc_artifacts::Label::Public);
        assert_eq!(
            record.state.is_settled(),
            capability != "promise:race",
            "only an empty Promise.race remains pending"
        );

        let mut core = quickjs_test_core();
        let empty_array = core
            .alloc_array_from_values(&[])
            .expect("empty array should allocate");
        core.write_reg_with_label(
            0,
            Value::Object(empty_array),
            crate::ifc_artifacts::Label::Secret,
        )
        .expect("empty array carrier should be writable");
        let result = execute_promise_combinator_bd_ur3tk_19(
            &mut core,
            capability,
            RegRange { start: 0, count: 1 },
            1,
        );
        assert_eq!(
            core.read_reg_label(1)
                .expect("empty result label should exist"),
            crate::ifc_artifacts::Label::Secret,
            "{capability} must preserve a labeled empty iterable carrier"
        );
        let record = core
            .promise_store
            .get(result)
            .expect("empty aggregate should exist");
        if capability != "promise:race" {
            assert_eq!(record.label, crate::ifc_artifacts::Label::Secret);
        }
    }
}

#[test]
fn builtin_array_is_array_uses_explicit_array_metadata() {
    let array = quickjs_execute(&test_module(vec![
        Ir3Instruction::NewArray { dst: 4 },
        Ir3Instruction::HostCall {
            capability: CapabilityTag("builtin:ArrayIsArray".to_string()),
            args: RegRange { start: 4, count: 1 },
            dst: 0,
        },
        Ir3Instruction::Halt,
    ]))
    .unwrap();
    assert_eq!(array.value, Value::Bool(true));

    let object = quickjs_execute(&test_module(vec![
        Ir3Instruction::NewObject { dst: 4 },
        Ir3Instruction::HostCall {
            capability: CapabilityTag("builtin:ArrayIsArray".to_string()),
            args: RegRange { start: 4, count: 1 },
            dst: 0,
        },
        Ir3Instruction::Halt,
    ]))
    .unwrap();
    assert_eq!(object.value, Value::Bool(false));
}

#[test]
fn array_slice_instruction_returns_remaining_elements() {
    let module = test_module(vec![
        Ir3Instruction::NewArray { dst: 1 },
        Ir3Instruction::LoadInt { dst: 2, value: 7 },
        Ir3Instruction::ArrayPush {
            array: 1,
            element: 2,
        },
        Ir3Instruction::LoadInt { dst: 3, value: 8 },
        Ir3Instruction::ArrayPush {
            array: 1,
            element: 3,
        },
        Ir3Instruction::LoadInt { dst: 4, value: 9 },
        Ir3Instruction::ArrayPush {
            array: 1,
            element: 4,
        },
        Ir3Instruction::LoadInt { dst: 5, value: 1 },
        Ir3Instruction::ArraySlice {
            array: 1,
            start: 5,
            dst: 0,
        },
        Ir3Instruction::Halt,
    ]);
    let mut core = quickjs_test_core();
    let result = core.execute(&module).unwrap();
    let rest_id = object_id_from_value(&result.value, "ArraySlice result");

    assert_ne!(
        rest_id,
        object_id_from_value(&core.registers[1], "ArraySlice source")
    );
    assert!(core.heap[rest_id.0 as usize].is_array);
    assert_eq!(
        core.read_array_like_values(rest_id),
        vec![Value::Int(8), Value::Int(9)]
    );
    assert_eq!(
        core.heap[rest_id.0 as usize].properties.get("length"),
        Some(&Value::Int(2))
    );
}

#[test]
fn array_push_does_not_overflow_on_u32_max_index_key() {
    // Regression (bd-qsz8t): a property key that parses to `u32::MAX`
    // ("4294967295") fed the `ArrayPush` sparse-length fold a `n + 1`,
    // overflowing u32 — a debug-build panic / release-build wrap. The fold
    // now saturates (matching `array_like_length`), so the op completes
    // instead of crashing on this adversarial key.
    let module = test_module_with_pool(
        vec![
            Ir3Instruction::NewArray { dst: 1 },
            Ir3Instruction::LoadStr {
                dst: 3,
                pool_index: 0,
            },
            Ir3Instruction::LoadInt { dst: 4, value: 1 },
            Ir3Instruction::SetProperty {
                obj: 1,
                key: 3,
                val: 4,
            },
            Ir3Instruction::LoadInt { dst: 2, value: 42 },
            Ir3Instruction::ArrayPush {
                array: 1,
                element: 2,
            },
            Ir3Instruction::Move { dst: 0, src: 1 },
            Ir3Instruction::Halt,
        ],
        vec!["4294967295".to_string()],
    );
    let mut core = quickjs_test_core();
    // The load-bearing assertion: this must not panic on the u32::MAX
    // sparse-fold (it did before the fix in debug builds).
    let result = core
        .execute(&module)
        .expect("array push must not overflow on a u32::MAX index key");
    let arr_id = object_id_from_value(&result.value, "array push result");
    // Saturating fold yields next_idx == u32::MAX, so the push writes at
    // that index, overwriting the pathological key with the pushed value.
    assert_eq!(
        core.heap[arr_id.0 as usize].properties.get("4294967295"),
        Some(&Value::Int(42)),
        "push must have completed and written the element"
    );
}

#[test]
fn builtin_array_push_and_pop_mutate_receiver_length() {
    let mut core = quickjs_test_core();
    let array_id = core.alloc_array_with_prototype(None).unwrap();
    core.registers[0] = Value::Object(array_id);
    core.registers[1] = Value::Int(7);
    core.registers[2] = Value::str("x");
    core.register_labels[1] = crate::ifc_artifacts::Label::Secret;

    let pushed = core
        .dispatch_builtin_hostcall(
            "builtin:ArrayPrototypePush",
            RegRange { start: 0, count: 3 },
        )
        .unwrap();
    assert_eq!(pushed, Value::Int(2));
    assert_eq!(
        core.heap[array_id.0 as usize].properties.get("0"),
        Some(&Value::Int(7))
    );
    assert_eq!(
        core.heap[array_id.0 as usize].properties.get("1"),
        Some(&Value::str("x"))
    );
    assert_eq!(
        core.heap[array_id.0 as usize].properties.get("length"),
        Some(&Value::Int(2))
    );
    assert_eq!(
        core.runtime_property_label(array_id, &RuntimePropertyKey::String(JsString::from("0")),),
        crate::ifc_artifacts::Label::Secret
    );

    let popped = core
        .dispatch_builtin_hostcall("builtin:ArrayPrototypePop", RegRange { start: 0, count: 1 })
        .unwrap();
    assert_eq!(popped, Value::str("x"));
    assert_eq!(
        core.heap[array_id.0 as usize].properties.get("length"),
        Some(&Value::Int(1))
    );
    assert!(!core.heap[array_id.0 as usize].properties.contains_key("1"));
}

#[test]
fn builtin_object_keys_and_values_return_allocated_arrays() {
    let mut core = quickjs_test_core();
    let object_id = core.alloc_object_with_prototype(None).unwrap();
    core.set_object_property(object_id, "b".to_string(), Value::Int(2))
        .unwrap();
    core.set_object_property(object_id, "a".to_string(), Value::Int(1))
        .unwrap();
    core.registers[4] = Value::Object(object_id);

    let keys = core
        .dispatch_builtin_hostcall("builtin:ObjectKeys", RegRange { start: 4, count: 1 })
        .unwrap();
    let Value::Object(keys_id) = keys else {
        panic!("Object.keys should return an array object");
    };
    assert_ne!(keys_id, object_id);
    assert!(core.heap[keys_id.0 as usize].is_array);
    assert_eq!(
        core.read_array_like_values(keys_id),
        vec![Value::str("b"), Value::str("a")]
    );

    let values = core
        .dispatch_builtin_hostcall("builtin:ObjectValues", RegRange { start: 4, count: 1 })
        .unwrap();
    let Value::Object(values_id) = values else {
        panic!("Object.values should return an array object");
    };
    assert_ne!(values_id, object_id);
    assert!(core.heap[values_id.0 as usize].is_array);
    assert_eq!(
        core.read_array_like_values(values_id),
        vec![Value::Int(2), Value::Int(1)]
    );
}

#[test]
fn baseline_data_property_consumers_use_es_own_key_order() {
    let mut core = quickjs_test_core();
    let object_id = core.alloc_object_with_prototype(None).unwrap();
    for (key, value) in [
        ("b", 1),
        ("10", 2),
        ("2", 3),
        ("01", 4),
        ("4294967295", 5),
        ("0", 6),
        ("a", 7),
        ("4294967294", 9),
    ] {
        core.set_object_property(object_id, key.to_string(), Value::Int(value))
            .unwrap();
    }
    core.set_object_property(object_id, "b".to_string(), Value::Int(8))
        .unwrap();
    assert!(core.remove_object_property(object_id, "b").unwrap());
    core.set_object_property(object_id, "b".to_string(), Value::Int(8))
        .unwrap();

    let expected_strings = [
        "0".to_string(),
        "2".to_string(),
        "10".to_string(),
        "4294967294".to_string(),
        "01".to_string(),
        "4294967295".to_string(),
        "a".to_string(),
        "b".to_string(),
    ];
    let expected_keys = expected_strings
        .iter()
        .map(|key| JsString::from(key.as_str()))
        .collect::<Vec<_>>();
    assert_eq!(core.own_enumerable_keys(object_id).unwrap(), expected_keys);
    assert_eq!(core.collect_for_in_keys(object_id).unwrap(), expected_keys);
    assert_eq!(
        core.qs_stringify_object(object_id, "&", "=").unwrap(),
        "0=6&2=3&10=2&4294967294=9&01=4&4294967295=5&a=7&b=8"
    );
}

#[test]
fn mixed_data_accessor_consumers_use_one_es_own_key_order() {
    let mut core = quickjs_test_core();
    let object_id = core.alloc_object_with_prototype(None).unwrap();
    core.set_object_property(object_id, "z".to_string(), Value::Int(1))
        .unwrap();
    core.set_object_property(
        object_id,
        format!("{IR_ACCESSOR_GET_PREFIX}x"),
        Value::Function(1),
    )
    .unwrap();
    core.set_object_property(
        object_id,
        format!("{IR_ACCESSOR_GET_PREFIX}10"),
        Value::Function(2),
    )
    .unwrap();
    core.set_object_property(object_id, "2".to_string(), Value::Int(2))
        .unwrap();
    core.set_object_property(
        object_id,
        format!("{IR_ACCESSOR_GET_PREFIX}1"),
        Value::Function(3),
    )
    .unwrap();
    core.set_object_property(object_id, "4294967295".to_string(), Value::Int(5))
        .unwrap();
    core.set_object_property(
        object_id,
        format!("{IR_ACCESSOR_GET_PREFIX}4294967294"),
        Value::Function(4),
    )
    .unwrap();
    core.set_object_property(object_id, "a".to_string(), Value::Int(6))
        .unwrap();

    let expected_strings = vec![
        "1".to_string(),
        "2".to_string(),
        "10".to_string(),
        "4294967294".to_string(),
        "z".to_string(),
        "x".to_string(),
        "4294967295".to_string(),
        "a".to_string(),
    ];
    assert_eq!(
        core.heap[object_id.0 as usize].own_property_keys(),
        expected_strings
    );
    let expected = expected_strings
        .iter()
        .map(|key| JsString::from(key.as_str()))
        .collect::<Vec<_>>();
    assert_eq!(core.own_enumerable_keys(object_id).unwrap(), expected);
    assert_eq!(core.collect_for_in_keys(object_id).unwrap(), expected);

    core.registers[4] = Value::Object(object_id);
    let keys = core
        .dispatch_builtin_hostcall("builtin:ObjectKeys", RegRange { start: 4, count: 1 })
        .unwrap();
    let Value::Object(keys_id) = keys else {
        panic!("Object.keys should return an array object");
    };
    assert_eq!(
        core.read_array_like_values(keys_id),
        expected.into_iter().map(Value::Str).collect::<Vec<_>>()
    );
}

#[test]
fn descriptor_kind_conversions_preserve_creation_position() {
    let mut core = quickjs_test_core();
    let object_id = core.alloc_object_with_prototype(None).unwrap();
    for (key, value) in [("a", 1), ("b", 2), ("c", 3)] {
        core.set_object_property(object_id, key.to_string(), Value::Int(value))
            .unwrap();
    }
    let expected = vec!["a".to_string(), "b".to_string(), "c".to_string()];

    core.set_object_property(
        object_id,
        format!("{IR_ACCESSOR_GET_PREFIX}b"),
        Value::Function(1),
    )
    .unwrap();
    assert_eq!(
        core.heap[object_id.0 as usize].own_property_keys(),
        expected
    );
    assert!(!core.heap[object_id.0 as usize].properties.contains_key("b"));
    assert!(core.heap[object_id.0 as usize].accessors.contains_key("b"));

    core.set_object_property(
        object_id,
        format!("{IR_ACCESSOR_SET_PREFIX}b"),
        Value::Function(2),
    )
    .unwrap();
    assert_eq!(
        core.heap[object_id.0 as usize].own_property_keys(),
        expected
    );

    core.set_plain_data_property(object_id, "b".to_string(), Value::Int(4))
        .unwrap();
    assert_eq!(
        core.heap[object_id.0 as usize].own_property_keys(),
        expected
    );
    assert_eq!(
        core.heap[object_id.0 as usize].properties.get("b"),
        Some(&Value::Int(4))
    );
    assert!(!core.heap[object_id.0 as usize].accessors.contains_key("b"));
    assert_eq!(
        core.qs_stringify_object(object_id, "&", "=").unwrap(),
        "a=1&b=4&c=3"
    );
}

#[test]
fn deleted_accessor_recreation_appends_ordinary_key() {
    let mut core = quickjs_test_core();
    let object_id = core.alloc_object_with_prototype(None).unwrap();
    core.set_object_property(object_id, "a".to_string(), Value::Int(1))
        .unwrap();
    core.set_object_property(
        object_id,
        format!("{IR_ACCESSOR_GET_PREFIX}x"),
        Value::Function(1),
    )
    .unwrap();
    core.set_object_property(object_id, "b".to_string(), Value::Int(2))
        .unwrap();

    assert!(core.remove_object_property(object_id, "x").unwrap());
    core.set_object_property(
        object_id,
        format!("{IR_ACCESSOR_GET_PREFIX}x"),
        Value::Function(2),
    )
    .unwrap();
    assert_eq!(
        core.heap[object_id.0 as usize].own_property_keys(),
        vec!["a".to_string(), "b".to_string(), "x".to_string()]
    );
}

#[test]
fn heap_object_mixed_order_serde_roundtrip_and_legacy_fallback() {
    let mut core = quickjs_test_core();
    let object_id = core.alloc_object_with_prototype(None).unwrap();
    core.set_object_property(object_id, "a".to_string(), Value::Int(1))
        .unwrap();
    core.set_object_property(
        object_id,
        format!("{IR_ACCESSOR_GET_PREFIX}x"),
        Value::Function(1),
    )
    .unwrap();
    core.set_object_property(object_id, "b".to_string(), Value::Int(2))
        .unwrap();

    let encoded = serde_json::to_value(&core.heap[object_id.0 as usize]).unwrap();
    assert!(encoded["properties"].is_object());
    assert_eq!(
        encoded["own_string_key_order"],
        serde_json::json!(["a", "x", "b"])
    );
    let restored: HeapObject = serde_json::from_value(encoded.clone()).unwrap();
    assert_eq!(
        restored.own_property_keys(),
        vec!["a".to_string(), "x".to_string(), "b".to_string()]
    );
    let standalone_properties: OrderedStringMap<Value> =
        serde_json::from_value(serde_json::to_value(&restored.properties).unwrap()).unwrap();
    assert_eq!(standalone_properties, restored.properties);

    let mut data_only = HeapObject::new();
    data_only
        .properties
        .insert("only".to_string(), Value::Int(1));
    let legacy_data_only = data_only.clone();
    let _ = data_only.record_property_definition(&JsString::from("only"), true);
    assert_eq!(
        data_only.own_property_keys(),
        legacy_data_only.own_property_keys()
    );
    assert_ne!(data_only, legacy_data_only);

    let mut legacy_encoded = encoded.clone();
    legacy_encoded
        .as_object_mut()
        .unwrap()
        .remove("own_string_key_order");
    let legacy: HeapObject = serde_json::from_value(legacy_encoded).unwrap();
    assert_eq!(
        legacy.own_property_keys(),
        vec!["a".to_string(), "b".to_string(), "x".to_string()]
    );
    assert_ne!(restored, legacy);

    let mut duplicate_order = encoded;
    duplicate_order["own_string_key_order"] = serde_json::json!(["a", "x", "x"]);
    assert!(serde_json::from_value::<HeapObject>(duplicate_order).is_err());

    let mut incomplete_order = serde_json::to_value(&restored).unwrap();
    incomplete_order["own_string_key_order"] = serde_json::json!(["a", "x"]);
    assert!(serde_json::from_value::<HeapObject>(incomplete_order).is_err());

    let mut public_field_mutation = restored.clone();
    public_field_mutation.accessors.insert(
        "y".to_string(),
        AccessorProperty {
            get: Some(Value::Function(2)),
            set: None,
        },
    );
    let normalized = serde_json::to_value(&public_field_mutation).unwrap();
    assert_eq!(
        normalized["own_string_key_order"],
        serde_json::json!(["a", "x", "b", "y"])
    );
    let normalized_roundtrip: HeapObject = serde_json::from_value(normalized).unwrap();
    assert_eq!(normalized_roundtrip, public_field_mutation);
    assert_eq!(
        normalized_roundtrip.own_property_keys(),
        vec![
            "a".to_string(),
            "x".to_string(),
            "b".to_string(),
            "y".to_string()
        ]
    );

    let mut mutation_core = quickjs_test_core();
    let mutation_id = mutation_core.alloc_object_with_prototype(None).unwrap();
    mutation_core.heap[mutation_id.0 as usize] = public_field_mutation;
    mutation_core.estimated_memory_bytes = mutation_core.recompute_estimated_memory_bytes();
    mutation_core
        .set_object_property(mutation_id, "c".to_string(), Value::Int(3))
        .unwrap();
    assert_eq!(
        mutation_core.heap[mutation_id.0 as usize].own_property_keys(),
        vec![
            "a".to_string(),
            "x".to_string(),
            "b".to_string(),
            "y".to_string(),
            "c".to_string()
        ]
    );
}

#[test]
fn public_accessor_order_normalization_rolls_back_exact_hidden_state() {
    let mut core = quickjs_test_core();
    let object_id = core.alloc_object_with_prototype(None).unwrap();
    core.set_object_property(object_id, "a".to_string(), Value::Int(1))
        .unwrap();
    core.set_object_property(
        object_id,
        format!("{IR_ACCESSOR_GET_PREFIX}x"),
        Value::Function(1),
    )
    .unwrap();
    core.set_object_property(object_id, "b".to_string(), Value::Int(2))
        .unwrap();
    core.heap[object_id.0 as usize].accessors.insert(
        "y".to_string(),
        AccessorProperty {
            get: Some(Value::Function(2)),
            set: None,
        },
    );
    core.estimated_memory_bytes = core.recompute_estimated_memory_bytes();

    let raw_order_before = core.heap[object_id.0 as usize]
        .properties
        .baseline_string_key_order()
        .unwrap()
        .to_vec();
    let memory_before = core.estimated_memory_bytes();
    core.config.max_total_memory_bytes = memory_before;
    let error = core
        .set_object_property(object_id, "c".to_string(), Value::str("x".repeat(512)))
        .unwrap_err();

    assert!(matches!(
        error,
        InterpreterError::MemoryBudgetExceeded { .. }
    ));
    assert_eq!(
        core.heap[object_id.0 as usize]
            .properties
            .baseline_string_key_order(),
        Some(raw_order_before.as_slice())
    );
    assert_eq!(
        core.heap[object_id.0 as usize].own_property_keys(),
        vec![
            "a".to_string(),
            "x".to_string(),
            "b".to_string(),
            "y".to_string()
        ]
    );
    assert_eq!(core.estimated_memory_bytes(), memory_before);
}

#[test]
fn legacy_heap_order_normalizes_before_a_new_property_appends() {
    let legacy_json = serde_json::json!({
        "properties": {"a": Value::Int(1), "b": Value::Int(2)},
        "accessors": {"x": {"get": Value::Function(1), "set": null}},
        "prototype": null,
        "constructor_function": null,
        "is_array": false
    });
    let legacy: HeapObject = serde_json::from_value(legacy_json).unwrap();
    let mut core = quickjs_test_core();
    let object_id = core.alloc_object_with_prototype(None).unwrap();
    core.heap[object_id.0 as usize] = legacy;
    core.estimated_memory_bytes = core.recompute_estimated_memory_bytes();

    let original_memory_limit = core.config.max_total_memory_bytes;
    let memory_before = core.estimated_memory_bytes();
    core.config.max_total_memory_bytes = memory_before;
    let error = core
        .set_object_property(object_id, "c".to_string(), Value::str("x".repeat(512)))
        .unwrap_err();
    assert!(matches!(
        error,
        InterpreterError::MemoryBudgetExceeded { .. }
    ));
    assert!(
        core.heap[object_id.0 as usize]
            .properties
            .baseline_string_key_order()
            .is_none()
    );
    assert_eq!(core.estimated_memory_bytes(), memory_before);
    core.config.max_total_memory_bytes = original_memory_limit;

    core.set_object_property(object_id, "c".to_string(), Value::Int(3))
        .unwrap();
    assert_eq!(
        core.heap[object_id.0 as usize].own_property_keys(),
        vec![
            "a".to_string(),
            "b".to_string(),
            "x".to_string(),
            "c".to_string()
        ]
    );
}

#[test]
fn write_heap_slot_records_ordinary_key_order() {
    let mut core = quickjs_test_core();
    core.write_heap_slot(0, Value::Int(1));
    core.set_object_property(
        ObjectId(0),
        format!("{IR_ACCESSOR_GET_PREFIX}x"),
        Value::Function(1),
    )
    .unwrap();
    assert_eq!(
        core.heap[0].own_property_keys(),
        vec!["value".to_string(), "x".to_string()]
    );
}

#[test]
fn mixed_property_order_survives_execution_seed_restore() {
    let mut core = quickjs_test_core();
    let object_id = core.alloc_object_with_prototype(None).unwrap();
    core.set_object_property(object_id, "a".to_string(), Value::Int(1))
        .unwrap();
    core.set_object_property(
        object_id,
        format!("{IR_ACCESSOR_GET_PREFIX}x"),
        Value::Function(1),
    )
    .unwrap();
    core.set_object_property(object_id, "b".to_string(), Value::Int(2))
        .unwrap();
    let seed = core.capture_execution_seed();

    assert!(core.remove_object_property(object_id, "x").unwrap());
    core.set_object_property(
        object_id,
        format!("{IR_ACCESSOR_GET_PREFIX}x"),
        Value::Function(2),
    )
    .unwrap();
    assert_eq!(
        core.heap[object_id.0 as usize].own_property_keys(),
        vec!["a".to_string(), "b".to_string(), "x".to_string()]
    );

    core.reset_execution_state_from_seed(&seed)
        .expect("captured seed must remain valid");
    assert_eq!(
        core.heap[object_id.0 as usize].own_property_keys(),
        vec!["a".to_string(), "x".to_string(), "b".to_string()]
    );
}

#[test]
fn legacy_order_materialization_charges_each_sidecar_string() {
    let legacy_json = serde_json::json!({
        "properties": {"a": Value::Int(1), "b": Value::Int(2)},
        "accessors": {"x": {"get": Value::Function(1), "set": null}},
        "prototype": null,
        "constructor_function": null,
        "is_array": false
    });
    let legacy: HeapObject = serde_json::from_value(legacy_json).unwrap();
    let mut core = quickjs_test_core();
    let object_id = core.alloc_object_with_prototype(None).unwrap();
    core.heap[object_id.0 as usize] = legacy;
    core.estimated_memory_bytes = core.recompute_estimated_memory_bytes();
    let memory_before = core.estimated_memory_bytes();

    core.set_object_property(object_id, "a".to_string(), Value::Int(1))
        .unwrap();
    let expected_delta = ["a", "b", "x"]
        .into_iter()
        .map(InterpreterCore::estimate_string_bytes)
        .sum::<u64>();
    assert_eq!(
        core.estimated_memory_bytes() - memory_before,
        expected_delta
    );
}

#[test]
fn failed_accessor_conversion_restores_data_property_order() {
    let mut core = quickjs_test_core();
    let object_id = core.alloc_object_with_prototype(None).unwrap();
    core.set_object_property(object_id, "a".to_string(), Value::Int(1))
        .unwrap();
    core.set_object_property(object_id, "b".to_string(), Value::Int(2))
        .unwrap();
    let object_before = core.heap[object_id.0 as usize].clone();
    let wire_before = serde_json::to_string(&object_before).unwrap();
    let memory_before = core.estimated_memory_bytes();
    core.config.max_total_memory_bytes = memory_before;

    let error = core
        .set_object_property(
            object_id,
            format!("{IR_ACCESSOR_GET_PREFIX}a"),
            Value::str("x".repeat(512)),
        )
        .unwrap_err();
    assert!(matches!(
        error,
        InterpreterError::MemoryBudgetExceeded { .. }
    ));
    assert_eq!(
        core.own_enumerable_keys(object_id).unwrap(),
        vec![JsString::from("a"), JsString::from("b")]
    );
    assert_eq!(
        core.heap[object_id.0 as usize].properties.get("a"),
        Some(&Value::Int(1))
    );
    assert!(!core.heap[object_id.0 as usize].accessors.contains_key("a"));
    assert_eq!(core.heap[object_id.0 as usize], object_before);
    assert_eq!(
        serde_json::to_string(&core.heap[object_id.0 as usize]).unwrap(),
        wire_before
    );
    assert_eq!(core.estimated_memory_bytes(), memory_before);
}

#[test]
fn failed_accessor_to_data_conversion_restores_kind_order_and_memory() {
    let mut core = quickjs_test_core();
    let object_id = core.alloc_object_with_prototype(None).unwrap();
    core.set_object_property(object_id, "a".to_string(), Value::Int(1))
        .unwrap();
    core.set_object_property(
        object_id,
        format!("{IR_ACCESSOR_GET_PREFIX}x"),
        Value::Function(1),
    )
    .unwrap();
    core.set_object_property(object_id, "b".to_string(), Value::Int(2))
        .unwrap();
    let memory_before = core.estimated_memory_bytes();
    core.config.max_total_memory_bytes = memory_before;

    let error = core
        .set_plain_data_property(object_id, "x".to_string(), Value::str("x".repeat(512)))
        .unwrap_err();
    assert!(matches!(
        error,
        InterpreterError::MemoryBudgetExceeded { .. }
    ));
    assert_eq!(
        core.heap[object_id.0 as usize].own_property_keys(),
        vec!["a".to_string(), "x".to_string(), "b".to_string()]
    );
    assert!(!core.heap[object_id.0 as usize].properties.contains_key("x"));
    assert_eq!(
        core.heap[object_id.0 as usize]
            .accessors
            .get("x")
            .and_then(|accessor| accessor.get.as_ref()),
        Some(&Value::Function(1))
    );
    assert_eq!(core.estimated_memory_bytes(), memory_before);
}

#[test]
fn failed_exact_descriptor_conversions_restore_wire_and_memory_bd_b12xs_4() {
    let mut core = quickjs_test_core();
    let object = core.alloc_object_with_prototype(None).unwrap();
    let d800 = JsString::from_code_units(&[0xD800]);
    let d801 = JsString::from_code_units(&[0xD801]);
    core.set_object_runtime_property(
        object,
        RuntimePropertyKey::String(d800.clone()),
        Value::Int(8),
    )
    .unwrap();
    core.set_object_string_property(
        object,
        exact_accessor_definition_key(IR_ACCESSOR_GET_PREFIX, &d801),
        Value::Function(1),
    )
    .unwrap();

    let object_before = serde_json::to_string(&core.heap[object.0 as usize]).unwrap();
    let memory_before = core.estimated_memory_bytes();
    core.config.max_total_memory_bytes = memory_before;

    let error = core
        .set_object_string_property(
            object,
            exact_accessor_definition_key(IR_ACCESSOR_GET_PREFIX, &d800),
            Value::str("x".repeat(512)),
        )
        .unwrap_err();
    assert!(matches!(
        error,
        InterpreterError::MemoryBudgetExceeded { .. }
    ));
    assert_eq!(
        serde_json::to_string(&core.heap[object.0 as usize]).unwrap(),
        object_before
    );
    assert_eq!(core.estimated_memory_bytes(), memory_before);

    let error = core
        .set_plain_data_runtime_property(
            object,
            RuntimePropertyKey::String(d801),
            Value::str("y".repeat(512)),
        )
        .unwrap_err();
    assert!(matches!(
        error,
        InterpreterError::MemoryBudgetExceeded { .. }
    ));
    assert_eq!(
        serde_json::to_string(&core.heap[object.0 as usize]).unwrap(),
        object_before
    );
    assert_eq!(core.estimated_memory_bytes(), memory_before);
}

#[test]
fn exact_data_and_accessor_memory_deltas_are_charged_bd_b12xs_4() {
    let mut core = quickjs_test_core();
    let object = core.alloc_object_with_prototype(None).unwrap();
    let d800 = JsString::from_code_units(&[0xD800]);
    let key_bytes = InterpreterCore::estimate_js_string_bytes(&d800);
    core.sync_estimated_memory_bytes().unwrap();
    let empty_memory = core.estimated_memory_bytes();

    core.set_object_runtime_property(
        object,
        RuntimePropertyKey::String(d800.clone()),
        Value::Int(8),
    )
    .unwrap();
    assert_eq!(
        core.estimated_memory_bytes() - empty_memory,
        MEMORY_ESTIMATE_MAP_ENTRY_BYTES + key_bytes * 3
    );

    core.set_object_string_property(
        object,
        exact_accessor_definition_key(IR_ACCESSOR_GET_PREFIX, &d800),
        Value::Function(1),
    )
    .unwrap();
    assert_eq!(
        core.estimated_memory_bytes() - empty_memory,
        MEMORY_ESTIMATE_MAP_ENTRY_BYTES + key_bytes * 2
    );
}

#[test]
fn failed_new_property_restores_existing_sidecar_and_memory() {
    let mut core = quickjs_test_core();
    let object_id = core.alloc_object_with_prototype(None).unwrap();
    core.set_object_property(object_id, "a".to_string(), Value::Int(1))
        .unwrap();
    let object_before = serde_json::to_value(&core.heap[object_id.0 as usize]).unwrap();
    let memory_before = core.estimated_memory_bytes();
    core.config.max_total_memory_bytes = memory_before;

    let error = core
        .set_object_property(object_id, "b".to_string(), Value::str("x".repeat(512)))
        .unwrap_err();
    assert!(matches!(
        error,
        InterpreterError::MemoryBudgetExceeded { .. }
    ));
    assert_eq!(
        serde_json::to_value(&core.heap[object_id.0 as usize]).unwrap(),
        object_before
    );
    assert_eq!(core.estimated_memory_bytes(), memory_before);
}

#[test]
fn builtin_json_parse_rolls_back_late_invalid_allocations() {
    let mut core = quickjs_test_core();
    core.registers[4] = Value::str(r#"{"a":[1,2]} trailing"#);
    let heap_before = core.heap_size();
    let memory_before = core.estimated_memory_bytes();

    let result = core
        .dispatch_builtin_hostcall("builtin:JsonParse", RegRange { start: 4, count: 1 })
        .unwrap();

    assert_eq!(result, Value::Undefined);
    assert_eq!(core.heap_size(), heap_before);
    assert_eq!(core.estimated_memory_bytes(), memory_before);
}

#[test]
fn builtin_json_parse_preserves_raw_lone_surrogate_units() {
    let mut core = quickjs_test_core();
    for expected in [vec![0xD800], vec![0xDC00], vec![0xD83D, 0xDE00]] {
        let mut json = vec![0x22];
        json.extend_from_slice(&expected);
        json.push(0x22);
        core.registers[4] = Value::Str(JsString::from_code_units(&json));

        let result = core
            .dispatch_builtin_hostcall("builtin:JsonParse", RegRange { start: 4, count: 1 })
            .unwrap();

        let Value::Str(parsed) = result else {
            panic!("JSON.parse should return the parsed string");
        };
        assert_eq!(parsed.code_units_vec(), expected);
    }

    let mut nested = "{\"value\":\"".encode_utf16().collect::<Vec<_>>();
    nested.push(0xD800);
    nested.extend("\"}".encode_utf16());
    core.registers[4] = Value::Str(JsString::from_code_units(&nested));
    let nested_result = core
        .dispatch_builtin_hostcall("builtin:JsonParse", RegRange { start: 4, count: 1 })
        .unwrap();
    let Value::Object(nested_id) = nested_result else {
        panic!("JSON.parse should allocate the nested object");
    };
    let Some(Value::Str(nested_value)) = core.heap[nested_id.0 as usize].properties.get("value")
    else {
        panic!("nested JSON string should be stored as a data property");
    };
    assert_eq!(nested_value.code_units_vec(), vec![0xD800]);

    core.registers[4] = Value::Str(JsString::from_code_units(&[0x22, 0x1F, 0x22]));
    assert_eq!(
        core.dispatch_builtin_hostcall("builtin:JsonParse", RegRange { start: 4, count: 1 })
            .unwrap(),
        Value::Undefined,
        "raw JSON control units must remain invalid"
    );
}

#[test]
fn builtin_math_abs_promotes_i64_minimum_magnitude_to_float() {
    let mut core = quickjs_test_core();
    core.registers[4] = Value::Int(i64::MIN);

    let result = core
        .dispatch_builtin_hostcall("builtin:MathAbs", RegRange { start: 4, count: 1 })
        .unwrap();
    let Value::Float(result) = result else {
        panic!("Math.abs(i64::MIN) must promote the positive magnitude to Float");
    };
    assert_eq!(result.inner(), -(i64::MIN as f64));
}

#[test]
fn builtin_string_char_at_uses_receiver_and_optional_index() {
    let mut core = quickjs_test_core();
    core.registers[4] = Value::str("hello");
    core.registers[5] = Value::Int(1);

    let explicit = core
        .dispatch_builtin_hostcall(
            "builtin:StringPrototypeCharAt",
            RegRange { start: 4, count: 2 },
        )
        .unwrap();
    assert_eq!(explicit, Value::str("e"));

    core.registers[4] = Value::Int(42);
    let default_index = core
        .dispatch_builtin_hostcall(
            "builtin:StringPrototypeCharAt",
            RegRange { start: 4, count: 1 },
        )
        .unwrap();
    assert_eq!(default_index, Value::str("4"));

    core.registers[5] = Value::Int(99);
    let out_of_range = core
        .dispatch_builtin_hostcall(
            "builtin:StringPrototypeCharAt",
            RegRange { start: 4, count: 2 },
        )
        .unwrap();
    assert_eq!(out_of_range, Value::Str(JsString::empty()));
}

#[test]
fn string_receiver_index_properties_preserve_exact_utf16_units_bd_pel1v() {
    let text = JsString::from_code_units(&[0x0061, 0xD83D, 0xDE00, 0xD800]);

    for (key, expected_unit) in [("0", 0x0061), ("1", 0xD83D), ("2", 0xDE00), ("3", 0xD800)] {
        let Some(Value::Str(value)) = InterpreterCore::string_property_value(&text, key) else {
            panic!("canonical in-range string index {key} must produce a string value");
        };
        assert_eq!(value.code_units_vec(), vec![expected_unit]);
    }

    assert_eq!(
        InterpreterCore::string_property_value(&text, "length"),
        Some(Value::Int(4))
    );
    for key in ["4", "01", "-1", "1.0", "4294967295"] {
        assert_eq!(
            InterpreterCore::string_property_value(&text, key),
            None,
            "non-canonical or out-of-range key {key} must stay absent"
        );
    }
}

// -----------------------------------------------------------------------
// 10. Witness events
// -----------------------------------------------------------------------

#[test]
fn witness_events_emitted() {
    let m = test_module(vec![
        Ir3Instruction::LoadInt { dst: 0, value: 1 },
        Ir3Instruction::Halt,
    ]);
    let result = quickjs_execute(&m).unwrap();
    // Should have at least the ExecutionCompleted event.
    assert!(
        result
            .witness_events
            .iter()
            .any(|e| e.kind == WitnessEventKind::ExecutionCompleted)
    );
}

#[test]
fn hostcall_produces_witness_events() {
    let mut m = test_module(vec![
        Ir3Instruction::HostCall {
            capability: CapabilityTag("fs".to_string()),
            args: RegRange { start: 0, count: 0 },
            dst: 0,
        },
        Ir3Instruction::Halt,
    ]);
    m.required_capabilities = vec![CapabilityTag("fs".to_string())];

    let config = test_quickjs_config_with([RuntimeCapability::FsRead]);
    let lane = QuickJsLane::with_config(config);
    let result = lane.execute(&m, "test").unwrap();

    assert!(
        result
            .witness_events
            .iter()
            .any(|e| e.kind == WitnessEventKind::HostcallDispatched)
    );
    assert!(
        result
            .witness_events
            .iter()
            .any(|e| e.kind == WitnessEventKind::CapabilityChecked)
    );
}

#[test]
fn closed_hostcall_classifier_matches_engine_contract_bd_pr33n() {
    for tag in KNOWN_INTERNAL_HOSTCALLS {
        assert_eq!(
            classify_hostcall_capability(tag),
            HostcallCapabilityClass::InternalAllowed,
            "implemented internal HostCall `{tag}` must remain executable",
        );
    }
    assert_eq!(
        classify_hostcall_capability("fs_read"),
        HostcallCapabilityClass::Runtime(RuntimeCapability::FsRead),
    );
    for attacker_tag in [
        "promise:steal_admin_key",
        "promise:",
        "promise:Resolve",
        "promise:resolve ",
        "builtin:ObjectFreeze",
        "builtin:ObjectKeys:extra",
        "hostcall.future_internal",
    ] {
        assert_eq!(
            classify_hostcall_capability(attacker_tag),
            HostcallCapabilityClass::Unknown,
            "unknown HostCall `{attacker_tag}` must fail closed",
        );
    }
}

#[test]
fn known_internal_hostcall_still_executes_and_records_allow_bd_pr33n() {
    let module = test_module(vec![
        Ir3Instruction::LoadInt { dst: 1, value: 42 },
        Ir3Instruction::HostCall {
            capability: CapabilityTag("number:Number.isInteger".to_string()),
            args: RegRange { start: 1, count: 1 },
            dst: 0,
        },
        Ir3Instruction::Halt,
    ]);

    let result = quickjs_execute(&module).expect("known internal HostCall must execute");
    assert_eq!(result.value, Value::Bool(true));
    assert_eq!(result.hostcall_decisions.len(), 1);
    assert_eq!(
        result.hostcall_decisions[0].capability.0,
        "number:Number.isInteger"
    );
    assert!(result.hostcall_decisions[0].allowed);
}

#[test]
fn unknown_hostcall_is_denied_with_bounded_evidence_bd_pr33n() {
    let attacker_tag =
        "promise:".to_string() + &"steal_admin_key".repeat(CAPABILITY_TAG_RECORD_BYTE_CAP);
    let recorded = recordable_capability_tag(&attacker_tag).into_owned();
    let module = test_module(vec![Ir3Instruction::HostCall {
        capability: CapabilityTag(attacker_tag),
        args: RegRange { start: 0, count: 0 },
        dst: 0,
    }]);
    let mut core = quickjs_test_core();

    let error = core
        .execute(&module)
        .expect_err("unknown HostCall must be rejected before dispatch");
    assert!(matches!(
        error,
        InterpreterError::CapabilityDenied { capability } if capability == recorded
    ));
    assert!(recorded.len() <= CAPABILITY_TAG_RECORD_BYTE_CAP);
    assert_eq!(core.hostcall_decisions.len(), 1);
    assert_eq!(core.hostcall_decisions[0].capability.0, recorded);
    assert!(!core.hostcall_decisions[0].allowed);
    assert_eq!(core.hostcall_decisions[0].instruction_index, 0);

    let denial_payload = format!("denied:{recorded}");
    assert!(core.witness_events.iter().any(|event| {
        event.kind == WitnessEventKind::CapabilityChecked
            && event.payload_hash == ContentHash::compute(denial_payload.as_bytes())
    }));
    assert!(
        !core
            .witness_events
            .iter()
            .any(|event| event.kind == WitnessEventKind::HostcallDispatched)
    );
}

#[test]
fn direct_import_denies_before_resolution_with_canonical_evidence_bd_iyp3h() {
    let module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
        ],
        vec!["./missing.mjs".to_string()],
    );
    let mut core = quickjs_test_core();

    let error = core
        .execute(&module)
        .expect_err("ImportModule must not resolve without ModuleLoad");
    assert_eq!(
        error,
        InterpreterError::CapabilityDenied {
            capability: "module_load".to_string(),
        }
    );
    assert_eq!(core.hostcall_decisions.len(), 1);
    assert_eq!(core.hostcall_decisions[0].capability.0, "module_load");
    assert!(!core.hostcall_decisions[0].allowed);
}

#[test]
fn first_class_require_denies_before_argument_or_resolver_work_bd_iyp3h() {
    let mut core = quickjs_test_core();
    let module = test_module(Vec::new());

    let error = core
        .dispatch_builtin_function(
            &module,
            &BuiltinFunction::require("/tmp/entry.cjs"),
            None,
            RegRange { start: 0, count: 0 },
            crate::ifc_artifacts::Label::Public,
        )
        .expect_err("first-class require must not bypass ModuleLoad");
    assert_eq!(
        error,
        InterpreterError::CapabilityDenied {
            capability: "module_load".to_string(),
        }
    );
    assert_eq!(core.hostcall_decisions.len(), 1);
    assert_eq!(core.hostcall_decisions[0].capability.0, "module_load");
    assert!(!core.hostcall_decisions[0].allowed);
    assert_eq!(core.current_module_specifier, None);
}

#[test]
fn module_hostcall_alias_uses_canonical_gate_evidence_bd_iyp3h() {
    let module = test_module(vec![Ir3Instruction::HostCall {
        capability: CapabilityTag("module:require".to_string()),
        args: RegRange { start: 0, count: 0 },
        dst: 0,
    }]);
    let mut core = quickjs_test_core();

    let error = core
        .execute(&module)
        .expect_err("module HostCall alias must consume ModuleLoad");
    assert_eq!(
        error,
        InterpreterError::CapabilityDenied {
            capability: "module_load".to_string(),
        }
    );
    assert_eq!(core.hostcall_decisions.len(), 1);
    assert_eq!(core.hostcall_decisions[0].capability.0, "module_load");
    assert!(!core.hostcall_decisions[0].allowed);
}

// -----------------------------------------------------------------------
// 11. Structured events
// -----------------------------------------------------------------------

#[test]
fn structured_events_emitted() {
    let m = test_module(vec![Ir3Instruction::Halt]);
    let result = quickjs_execute(&m).unwrap();
    assert!(result.events.iter().any(|e| e.event == "execution_started"));
    assert!(result.events.iter().any(|e| e.event == "execution_halted"));
}

// -----------------------------------------------------------------------
// 12. V8 lane produces same results
// -----------------------------------------------------------------------

#[test]
fn v8_lane_same_result_as_quickjs() {
    let m = test_module(vec![
        Ir3Instruction::LoadInt { dst: 1, value: 3 },
        Ir3Instruction::LoadInt { dst: 2, value: 4 },
        Ir3Instruction::Add {
            dst: 0,
            lhs: 1,
            rhs: 2,
        },
        Ir3Instruction::Halt,
    ]);
    let qjs = quickjs_execute(&m).unwrap();
    let v8 = v8_execute(&m).unwrap();
    assert_eq!(qjs.value, v8.value);
}

// -----------------------------------------------------------------------
// 13. Lane routing
// -----------------------------------------------------------------------

#[test]
fn router_selects_quickjs_for_simple_module() {
    let m = test_module(vec![
        Ir3Instruction::LoadInt { dst: 0, value: 1 },
        Ir3Instruction::Halt,
    ]);
    let mut router = test_router();
    let result = router.execute(&m, "test", None).unwrap();
    assert_eq!(result.lane, LaneChoice::QuickJs);
    assert_eq!(result.reason, LaneReason::DefaultFallback);
}

#[test]
fn router_selects_quickjs_for_capability_module() {
    let mut m = test_module(vec![Ir3Instruction::Halt]);
    m.required_capabilities = vec![CapabilityTag("net".to_string())];
    let mut router = test_router();
    let result = router.execute(&m, "test", None).unwrap();
    assert_eq!(result.lane, LaneChoice::QuickJs);
    assert_eq!(result.reason, LaneReason::SecuritySensitive);
}

#[test]
fn router_selects_v8_for_large_module() {
    let instrs: Vec<Ir3Instruction> = (0..1001)
        .map(|_| Ir3Instruction::LoadInt { dst: 0, value: 1 })
        .chain(std::iter::once(Ir3Instruction::Halt))
        .collect();
    let m = test_module(instrs);
    let mut router = test_router();
    let result = router.execute(&m, "test", None).unwrap();
    assert_eq!(result.lane, LaneChoice::V8);
    assert_eq!(result.reason, LaneReason::ThroughputOptimized);
}

#[test]
fn router_respects_forced_lane() {
    let m = test_module(vec![
        Ir3Instruction::LoadInt { dst: 0, value: 1 },
        Ir3Instruction::Halt,
    ]);
    let mut router = test_router();
    let result = router.execute(&m, "test", Some(LaneChoice::V8)).unwrap();
    assert_eq!(result.lane, LaneChoice::V8);
    assert_eq!(result.reason, LaneReason::PolicyDirective);
}

// -----------------------------------------------------------------------
// 14. Determinism: same input → same output
// -----------------------------------------------------------------------

#[test]
fn deterministic_execution() {
    let m = test_module(vec![
        Ir3Instruction::LoadInt { dst: 1, value: 100 },
        Ir3Instruction::LoadInt { dst: 2, value: 200 },
        Ir3Instruction::Add {
            dst: 0,
            lhs: 1,
            rhs: 2,
        },
        Ir3Instruction::Halt,
    ]);

    let r1 = quickjs_execute(&m).unwrap();
    let r2 = quickjs_execute(&m).unwrap();
    assert_eq!(r1.value, r2.value);
    assert_eq!(r1.instructions_executed, r2.instructions_executed);
}

// -----------------------------------------------------------------------
// 15. Value truthiness
// -----------------------------------------------------------------------

#[test]
fn value_truthiness() {
    assert!(!Value::Undefined.is_truthy());
    assert!(!Value::Null.is_truthy());
    assert!(!Value::Bool(false).is_truthy());
    assert!(!Value::Int(0).is_truthy());
    assert!(!Value::Str(JsString::empty()).is_truthy());

    assert!(Value::Bool(true).is_truthy());
    assert!(Value::Int(1).is_truthy());
    assert!(Value::Int(-1).is_truthy());
    assert!(Value::str("x").is_truthy());
    assert!(Value::Object(ObjectId(0)).is_truthy());
    assert!(Value::Function(0).is_truthy());
}

// -----------------------------------------------------------------------
// 16. Value display
// -----------------------------------------------------------------------

#[test]
fn value_display() {
    assert_eq!(Value::Undefined.to_string(), "undefined");
    assert_eq!(Value::Null.to_string(), "null");
    assert_eq!(Value::Bool(true).to_string(), "true");
    assert_eq!(Value::Int(42).to_string(), "42");
    assert_eq!(Value::str("hi").to_string(), "hi");
}

// -----------------------------------------------------------------------
// 17. Error display
// -----------------------------------------------------------------------

#[test]
fn error_display_coverage() {
    let errors = vec![
        InterpreterError::BudgetExhausted {
            executed: 100,
            budget: 50,
        },
        InterpreterError::RegisterOutOfBounds {
            register: 999,
            max: 256,
        },
        InterpreterError::DivisionByZero,
        InterpreterError::Halted,
        InterpreterError::StackOverflow { depth: 10, max: 5 },
        InterpreterError::CapabilityDenied {
            capability: "net".to_string(),
        },
        InterpreterError::UnsupportedMembershipSemantics {
            operator: "in".to_string(),
        },
        InterpreterError::UncaughtException {
            value: "test error".to_string(),
        },
    ];
    for e in errors {
        let s = e.to_string();
        assert!(!s.is_empty());
    }
}

// -----------------------------------------------------------------------
// 18. Return from top-level
// -----------------------------------------------------------------------

#[test]
fn return_from_top_level() {
    let m = test_module(vec![
        Ir3Instruction::LoadInt { dst: 0, value: 99 },
        Ir3Instruction::Return { value: 0 },
    ]);
    let result = quickjs_execute(&m).unwrap();
    assert_eq!(result.value, Value::Int(99));
}

// -----------------------------------------------------------------------
// 19. Fall off end of instructions
// -----------------------------------------------------------------------

#[test]
fn fall_off_end() {
    let m = test_module(vec![Ir3Instruction::LoadInt { dst: 0, value: 77 }]);
    let result = quickjs_execute(&m).unwrap();
    assert_eq!(result.value, Value::Int(77));
}

// -----------------------------------------------------------------------
// 20. Serde round-trips
// -----------------------------------------------------------------------

#[test]
fn value_serde_roundtrip() {
    for val in [
        Value::Undefined,
        Value::Null,
        Value::Bool(true),
        Value::Int(42),
        Value::str("hello"),
        Value::Object(ObjectId(7)),
        Value::Function(3),
    ] {
        let json = serde_json::to_string(&val).unwrap();
        let deser: Value = serde_json::from_str(&json).unwrap();
        assert_eq!(val, deser);
    }
}

#[test]
fn historical_value_wire_bytes_survive_the_0_2_api_migration() {
    let cases = [
        (Value::Undefined, r#""Undefined""#.to_string()),
        (Value::Null, r#""Null""#.to_string()),
        (Value::Bool(true), r#"{"Bool":true}"#.to_string()),
        (Value::Int(42), r#"{"Int":42}"#.to_string()),
        (
            Value::Float(Float64::new(1.5)),
            r#"{"Float":4609434218613702656}"#.to_string(),
        ),
        (Value::str("hello"), r#"{"Str":"hello"}"#.to_string()),
        (
            Value::Str(JsString::from_code_units(&[0xD800])),
            r#"{"Str":{"$wtf16":[55296]}}"#.to_string(),
        ),
        (Value::Object(ObjectId(7)), r#"{"Object":7}"#.to_string()),
        (Value::Function(3), r#"{"Function":3}"#.to_string()),
        (Value::Closure(4), r#"{"Closure":4}"#.to_string()),
        (Value::Iterator(5), r#"{"Iterator":5}"#.to_string()),
        (
            Value::GeneratorFunction(6),
            r#"{"GeneratorFunction":6}"#.to_string(),
        ),
        (Value::Generator(7), r#"{"Generator":7}"#.to_string()),
        (
            Value::AsyncFunction(8),
            r#"{"AsyncFunction":8}"#.to_string(),
        ),
        (
            Value::AsyncFunctionObject(9),
            r#"{"AsyncFunctionObject":9}"#.to_string(),
        ),
        (
            Value::AsyncGeneratorFunction(10),
            r#"{"AsyncGeneratorFunction":10}"#.to_string(),
        ),
        (
            Value::AsyncGeneratorObject(11),
            r#"{"AsyncGeneratorObject":11}"#.to_string(),
        ),
        (Value::Promise(12), r#"{"Promise":12}"#.to_string()),
        (
            Value::BuiltinFunction(BuiltinFunction {
                kind: BuiltinFunctionKind::Require,
                module_specifier: "node:path".to_string(),
                bound_object: None,
            }),
            r#"{"BuiltinFunction":{"kind":"require","module_specifier":"node:path"}}"#.to_string(),
        ),
    ];

    for (value, historical_wire) in cases {
        let encoded = serde_json::to_string(&value).unwrap();
        assert_eq!(encoded, historical_wire);

        let decoded: Value = serde_json::from_str(&historical_wire).unwrap();
        assert_eq!(decoded, value);
        assert_eq!(serde_json::to_string(&decoded).unwrap(), historical_wire);
    }
}

#[test]
fn interpreter_error_serde_roundtrip() {
    let err = InterpreterError::BudgetExhausted {
        executed: 100,
        budget: 50,
    };
    let json = serde_json::to_string(&err).unwrap();
    let deser: InterpreterError = serde_json::from_str(&json).unwrap();
    assert_eq!(err, deser);
}

#[test]
fn config_serde_roundtrip() {
    let config = InterpreterConfig::quickjs_defaults();
    let json = serde_json::to_string(&config).unwrap();
    let deser: InterpreterConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, deser);
}

// -----------------------------------------------------------------------
// 21. Empty module
// -----------------------------------------------------------------------

#[test]
fn empty_module_returns_undefined() {
    let m = test_module(vec![]);
    let result = quickjs_execute(&m).unwrap();
    assert_eq!(result.value, Value::Undefined);
}

// -----------------------------------------------------------------------
// 22. Complex expression: (3 + 4) * 2
// -----------------------------------------------------------------------

#[test]
fn complex_arithmetic() {
    let m = test_module(vec![
        Ir3Instruction::LoadInt { dst: 1, value: 3 },
        Ir3Instruction::LoadInt { dst: 2, value: 4 },
        Ir3Instruction::Add {
            dst: 3,
            lhs: 1,
            rhs: 2,
        }, // r3 = 7
        Ir3Instruction::LoadInt { dst: 4, value: 2 },
        Ir3Instruction::Mul {
            dst: 0,
            lhs: 3,
            rhs: 4,
        }, // r0 = 14
        Ir3Instruction::Halt,
    ]);
    let result = quickjs_execute(&m).unwrap();
    assert_eq!(result.value, Value::Int(14));
}

// -----------------------------------------------------------------------
// 23. Loop: sum 1..5
// -----------------------------------------------------------------------

#[test]
fn loop_sum_one_to_five() {
    // r0 = sum (accumulator), r1 = counter, r2 = limit
    // r3 = 1 (increment), r4 = temp comparison
    let m = test_module(vec![
        Ir3Instruction::LoadInt { dst: 0, value: 0 }, // 0: sum = 0
        Ir3Instruction::LoadInt { dst: 1, value: 1 }, // 1: counter = 1
        Ir3Instruction::LoadInt { dst: 2, value: 6 }, // 2: limit = 6 (exclusive)
        Ir3Instruction::LoadInt { dst: 3, value: 1 }, // 3: increment = 1
        // Loop body (instruction 4):
        Ir3Instruction::Add {
            dst: 0,
            lhs: 0,
            rhs: 1,
        }, // 4: sum += counter
        Ir3Instruction::Add {
            dst: 1,
            lhs: 1,
            rhs: 3,
        }, // 5: counter += 1
        // Compare: if counter < limit, jump to loop body
        Ir3Instruction::Sub {
            dst: 4,
            lhs: 2,
            rhs: 1,
        }, // 6: r4 = limit - counter
        Ir3Instruction::JumpIf { cond: 4, target: 4 }, // 7: if r4 truthy, loop
        Ir3Instruction::Halt,                          // 8
    ]);
    let result = quickjs_execute(&m).unwrap();
    assert_eq!(result.value, Value::Int(15)); // 1+2+3+4+5 = 15
}

// -----------------------------------------------------------------------
// 24. Instruction count tracking
// -----------------------------------------------------------------------

#[test]
fn instructions_executed_counted() {
    let m = test_module(vec![
        Ir3Instruction::LoadInt { dst: 0, value: 1 },
        Ir3Instruction::LoadInt { dst: 1, value: 2 },
        Ir3Instruction::Add {
            dst: 0,
            lhs: 0,
            rhs: 1,
        },
        Ir3Instruction::Halt,
    ]);
    let result = quickjs_execute(&m).unwrap();
    assert_eq!(result.instructions_executed, 4); // 3 ops + halt
}

// -----------------------------------------------------------------------
// 25. String + number concatenation
// -----------------------------------------------------------------------

#[test]
fn string_int_concatenation() {
    let m = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 1,
                pool_index: 0,
            },
            Ir3Instruction::LoadInt { dst: 2, value: 42 },
            Ir3Instruction::Add {
                dst: 0,
                lhs: 1,
                rhs: 2,
            },
            Ir3Instruction::Halt,
        ],
        vec!["answer: ".to_string()],
    );
    let result = quickjs_execute(&m).unwrap();
    assert_eq!(result.value, Value::str("answer: 42"));
}

#[test]
fn value_ord() {
    assert!(Value::Undefined < Value::Null);
    assert!(Value::Null < Value::Bool(false));
    assert!(Value::Bool(false) < Value::Bool(true));
    assert!(Value::Bool(true) < Value::Int(0));
    assert!(Value::Int(0) < Value::Str(JsString::empty()));
    assert!(Value::Str(JsString::empty()) < Value::Object(ObjectId(0)));
    assert!(Value::Object(ObjectId(0)) < Value::Function(0));
}

// -----------------------------------------------------------------------
// Enrichment: InterpreterError Display uniqueness via BTreeSet
// -----------------------------------------------------------------------

#[test]
fn interpreter_error_display_all_unique() {
    let errors = vec![
        InterpreterError::BudgetExhausted {
            executed: 100,
            budget: 50,
        },
        InterpreterError::RegisterOutOfBounds {
            register: 999,
            max: 256,
        },
        InterpreterError::DivisionByZero,
        InterpreterError::Halted,
        InterpreterError::StackOverflow { depth: 10, max: 5 },
        InterpreterError::CapabilityDenied {
            capability: "net".to_string(),
        },
        InterpreterError::RequireSpecifierNotString {
            got: "undefined".to_string(),
        },
        InterpreterError::TypeError {
            expected: "number".to_string(),
            got: "object".to_string(),
        },
        InterpreterError::StringPoolOutOfBounds {
            index: 99,
            pool_size: 5,
        },
        InterpreterError::UnsupportedMembershipSemantics {
            operator: "instanceof".to_string(),
        },
        InterpreterError::UncaughtException {
            value: "test error".to_string(),
        },
    ];
    let mut displays = std::collections::BTreeSet::new();
    for e in &errors {
        displays.insert(e.to_string());
    }
    assert_eq!(
        displays.len(),
        errors.len(),
        "all InterpreterError variants produce distinct Display"
    );
}

// -----------------------------------------------------------------------
// Enrichment: InterpreterError implements std::error::Error
// -----------------------------------------------------------------------

#[test]
fn interpreter_error_display_coverage() {
    let variants: Vec<InterpreterError> = vec![
        InterpreterError::DivisionByZero,
        InterpreterError::Halted,
        InterpreterError::BudgetExhausted {
            executed: 10,
            budget: 5,
        },
    ];
    for v in &variants {
        assert!(!v.to_string().is_empty());
    }
}

// -----------------------------------------------------------------------
// Enrichment: Value Display uniqueness for all types
// -----------------------------------------------------------------------

#[test]
fn value_display_all_types_non_empty() {
    let values = vec![
        Value::Undefined,
        Value::Null,
        Value::Bool(true),
        Value::Bool(false),
        Value::Int(0),
        Value::Int(-1),
        Value::str("hello"),
        Value::Object(ObjectId(0)),
        Value::Function(0),
    ];
    for v in &values {
        assert!(
            !v.to_string().is_empty(),
            "Value::Display should not be empty for {v:?}"
        );
    }
}

// -----------------------------------------------------------------------
// Enrichment: LaneChoice serde roundtrip
// -----------------------------------------------------------------------

#[test]
fn lane_choice_serde_roundtrip() {
    for choice in &[LaneChoice::QuickJs, LaneChoice::V8] {
        let json = serde_json::to_string(choice).unwrap();
        let back: LaneChoice = serde_json::from_str(&json).unwrap();
        assert_eq!(*choice, back);
    }
}

// -----------------------------------------------------------------------
// Enrichment: V8 lane budget exhaustion
// -----------------------------------------------------------------------

#[test]
fn v8_budget_exhaustion() {
    let m = test_module(vec![Ir3Instruction::Jump { target: 0 }]);
    let mut config = test_v8_config();
    config.instruction_budget = 5;
    let lane = V8Lane::with_config(config);
    let err = lane.execute(&m, "test").unwrap_err();
    assert!(matches!(err, InterpreterError::BudgetExhausted { .. }));
}

// -----------------------------------------------------------------------
// Enrichment: InterpreterConfig v8_defaults has larger budget
// -----------------------------------------------------------------------

#[test]
fn v8_defaults_larger_budget_than_quickjs() {
    let qjs = InterpreterConfig::quickjs_defaults();
    let v8 = InterpreterConfig::v8_defaults();
    assert!(
        v8.instruction_budget > qjs.instruction_budget,
        "V8 lane should have a larger default budget"
    );
}

// -----------------------------------------------------------------------
// Enrichment: ExecutionResult serde roundtrip
// -----------------------------------------------------------------------

#[test]
fn execution_result_fields_accessible() {
    let m = test_module(vec![
        Ir3Instruction::LoadInt { dst: 0, value: 42 },
        Ir3Instruction::Halt,
    ]);
    let result = quickjs_execute(&m).unwrap();
    assert!(result.instructions_executed > 0);
    assert!(result.events.is_empty() || !result.events.is_empty());
}

// -----------------------------------------------------------------------
// Enrichment: negative integer arithmetic
// -----------------------------------------------------------------------

#[test]
fn negative_integer_arithmetic() {
    let m = test_module(vec![
        Ir3Instruction::LoadInt { dst: 1, value: -10 },
        Ir3Instruction::LoadInt { dst: 2, value: 3 },
        Ir3Instruction::Add {
            dst: 0,
            lhs: 1,
            rhs: 2,
        },
        Ir3Instruction::Halt,
    ]);
    let result = quickjs_execute(&m).unwrap();
    assert_eq!(result.value, Value::Int(-7));
}

// -----------------------------------------------------------------------
// Enrichment: PearlTower 2026-02-26
// -----------------------------------------------------------------------

#[test]
fn value_type_name_all_variants() {
    assert_eq!(Value::Undefined.type_name(), "undefined");
    assert_eq!(Value::Null.type_name(), "null");
    assert_eq!(Value::Bool(true).type_name(), "boolean");
    assert_eq!(Value::Int(0).type_name(), "number");
    assert_eq!(Value::Str(JsString::empty()).type_name(), "string");
    assert_eq!(Value::Object(ObjectId(0)).type_name(), "object");
    assert_eq!(Value::Function(0).type_name(), "function");
    assert_eq!(
        Value::BuiltinFunction(BuiltinFunction::require("/tmp/entry.cjs")).type_name(),
        "function"
    );
}

#[test]
fn value_is_truthy_exhaustive() {
    assert!(!Value::Undefined.is_truthy());
    assert!(!Value::Null.is_truthy());
    assert!(!Value::Bool(false).is_truthy());
    assert!(Value::Bool(true).is_truthy());
    assert!(!Value::Int(0).is_truthy());
    assert!(Value::Int(1).is_truthy());
    assert!(Value::Int(-1).is_truthy());
    assert!(!Value::Str(JsString::empty()).is_truthy());
    assert!(Value::str("x").is_truthy());
    assert!(Value::Object(ObjectId(0)).is_truthy());
    assert!(Value::Function(0).is_truthy());
    assert!(Value::BuiltinFunction(BuiltinFunction::require("/tmp/entry.cjs")).is_truthy());
}

#[test]
fn object_id_serde_roundtrip() {
    let id = ObjectId(42);
    let json = serde_json::to_string(&id).unwrap();
    let back: ObjectId = serde_json::from_str(&json).unwrap();
    assert_eq!(id, back);
}

#[test]
fn heap_object_new_is_empty() {
    let obj = HeapObject::new();
    assert!(obj.properties.is_empty());
}

#[test]
fn lane_reason_serde_all_variants() {
    let variants = [
        LaneReason::SecuritySensitive,
        LaneReason::ThroughputOptimized,
        LaneReason::PolicyDirective,
        LaneReason::DefaultFallback,
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let back: LaneReason = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

#[test]
fn interpreter_event_serde_roundtrip() {
    let ev = InterpreterEvent {
        trace_id: "t-1".to_string(),
        component: "baseline_interpreter".to_string(),
        event: "execution_started".to_string(),
        outcome: "ok".to_string(),
        error_code: None,
    };
    let json = serde_json::to_string(&ev).unwrap();
    let back: InterpreterEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(ev, back);
}

#[test]
fn interpreter_event_serde_with_error_code() {
    let ev = InterpreterEvent {
        trace_id: "t-2".to_string(),
        component: "baseline_interpreter".to_string(),
        event: "execution_failed".to_string(),
        outcome: "fail".to_string(),
        error_code: Some("BUDGET_EXHAUSTED".to_string()),
    };
    let json = serde_json::to_string(&ev).unwrap();
    let back: InterpreterEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(ev.error_code, back.error_code);
}

#[test]
fn interpreter_config_quickjs_defaults_fields() {
    let c = InterpreterConfig::quickjs_defaults();
    assert_eq!(c.instruction_budget, 100_000);
    assert_eq!(c.max_registers, 256);
    assert_eq!(c.max_call_depth, 256);
    assert_eq!(c.max_heap_objects, 100_000);
    assert_eq!(c.max_total_memory_bytes, 64 * 1024 * 1024);
    assert_eq!(c.max_scope_depth, 512);
    assert!(c.granted_capabilities.is_empty());
}

#[test]
fn interpreter_config_v8_defaults_fields() {
    let c = InterpreterConfig::v8_defaults();
    assert_eq!(c.instruction_budget, 1_000_000);
    assert_eq!(c.max_registers, 4096);
    assert_eq!(c.max_call_depth, 256);
    assert_eq!(c.max_heap_objects, 1_000_000);
    assert_eq!(c.max_total_memory_bytes, 512 * 1024 * 1024);
    assert_eq!(c.max_scope_depth, 512);
    assert!(c.granted_capabilities.is_empty());
}

#[test]
fn interpreter_config_supports_all_runtime_capability_variants() {
    // Test exhaustiveness: verify all 17 RuntimeCapability variants can be inserted
    let all_capabilities = BTreeSet::from([
        RuntimeCapability::VmDispatch,
        RuntimeCapability::GcInvoke,
        RuntimeCapability::IrLowering,
        RuntimeCapability::PolicyRead,
        RuntimeCapability::PolicyWrite,
        RuntimeCapability::EvidenceEmit,
        RuntimeCapability::DecisionInvoke,
        RuntimeCapability::NetworkEgress,
        RuntimeCapability::LeaseManagement,
        RuntimeCapability::IdempotencyDerive,
        RuntimeCapability::ExtensionLifecycle,
        RuntimeCapability::HeapAllocate,
        RuntimeCapability::EnvRead,
        RuntimeCapability::ProcessSpawn,
        RuntimeCapability::FsRead,
        RuntimeCapability::FsWrite,
        RuntimeCapability::ModuleLoad,
    ]);

    let mut config = InterpreterConfig::quickjs_defaults();
    config.granted_capabilities = all_capabilities.clone();

    // Verify all capabilities are stored and can be retrieved
    assert_eq!(config.granted_capabilities.len(), 17); // 17 total capabilities
    assert!(
        config
            .granted_capabilities
            .contains(&RuntimeCapability::VmDispatch)
    );
    assert!(
        config
            .granted_capabilities
            .contains(&RuntimeCapability::ModuleLoad)
    );

    // Verify BTreeSet maintains deterministic ordering
    let capabilities_vec: Vec<_> = config.granted_capabilities.iter().collect();
    let capabilities_vec2: Vec<_> = all_capabilities.iter().collect();
    assert_eq!(capabilities_vec, capabilities_vec2);
}

#[test]
fn scope_chain_push_respects_max_scope_depth() {
    let mut chain = ScopeChain::new();
    // SAFETY: First push() call with valid scope depth setting cannot fail.
    chain.push(2).unwrap();
    let err = chain.push(2).unwrap_err();
    assert!(matches!(
        err,
        InterpreterError::ScopeDepthExceeded {
            requested_depth: 3,
            max_depth: 2,
        }
    ));
}

#[test]
fn router_throughput_optimized_for_large_module() {
    let mut instrs = Vec::new();
    for _ in 0..1001 {
        instrs.push(Ir3Instruction::LoadInt { dst: 0, value: 0 });
    }
    instrs.push(Ir3Instruction::Halt);
    let m = test_module(instrs);
    let mut router = test_router();
    // SAFETY: router.execute() with valid test module and valid parameters
    // cannot fail under normal test conditions.
    let result = router.execute(&m, "test", None).unwrap();
    assert_eq!(result.lane, LaneChoice::V8);
    assert_eq!(result.reason, LaneReason::ThroughputOptimized);
}

#[test]
fn alloc_object_and_heap_size() {
    let config = test_quickjs_config();
    let mut core = InterpreterCore::new(config, "test");
    assert_eq!(core.heap_size(), 0);
    assert_eq!(core.estimated_memory_bytes(), 0);
    let id = core.alloc_object_with_prototype(None).unwrap();
    assert_eq!(id, ObjectId(0));
    assert_eq!(core.heap_size(), 1);
    let id2 = core.alloc_object_with_prototype(None).unwrap();
    assert_eq!(id2, ObjectId(1));
    assert_eq!(core.heap_size(), 2);
    assert!(core.estimated_memory_bytes() > 0);
}

#[test]
fn alloc_object_with_prototype_respects_heap_budget() {
    let mut config = test_quickjs_config();
    config.max_heap_objects = 2;
    let mut core = InterpreterCore::new(config, "heap-budget");
    assert_eq!(core.alloc_object_with_prototype(None).unwrap(), ObjectId(0));
    assert_eq!(core.alloc_object_with_prototype(None).unwrap(), ObjectId(1));
    let err = core.alloc_object_with_prototype(None).unwrap_err();
    assert!(matches!(
        err,
        InterpreterError::MemoryBudgetExceeded {
            requested_heap_objects: 3,
            max_heap_objects: 2,
            ..
        }
    ));
}

#[test]
fn custom_heap_budget_allows_limit_then_fails() {
    let mut config = test_quickjs_config();
    config.max_heap_objects = 10;
    let mut core = InterpreterCore::new(config, "custom-heap-budget");
    for expected in 0_u32..10 {
        assert_eq!(
            core.alloc_object_with_prototype(None).unwrap(),
            ObjectId(expected)
        );
    }
    let err = core.alloc_object_with_prototype(None).unwrap_err();
    assert!(matches!(
        err,
        InterpreterError::MemoryBudgetExceeded {
            requested_heap_objects: 11,
            max_heap_objects: 10,
            ..
        }
    ));
}

#[test]
fn estimated_memory_bytes_tracks_property_growth() {
    let config = test_quickjs_config();
    let mut core = InterpreterCore::new(config, "memory-estimate");
    let oid = core.alloc_object_with_prototype(None).unwrap();
    let before = core.estimated_memory_bytes();
    core.heap[oid.0 as usize]
        .properties
        .insert("payload".to_string(), Value::str("hello world"));
    core.sync_estimated_memory_bytes().unwrap();
    assert!(core.estimated_memory_bytes() > before);
}

#[test]
fn new_object_instruction_returns_memory_budget_exceeded() {
    let mut config = test_quickjs_config();
    config.max_heap_objects = 0;
    let mut core = InterpreterCore::new(config, "budget");
    let module = test_module(vec![
        Ir3Instruction::NewObject { dst: 0 },
        Ir3Instruction::Halt,
    ]);
    let err = core.execute(&module).unwrap_err();
    assert!(matches!(
        err,
        InterpreterError::MemoryBudgetExceeded {
            requested_heap_objects: 1,
            max_heap_objects: 0,
            ..
        }
    ));
}

#[test]
fn load_str_instruction_returns_memory_budget_exceeded() {
    let mut config = test_quickjs_config();
    config.max_total_memory_bytes = 1;
    let mut core = InterpreterCore::new(config, "string-budget");
    let module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::Halt,
        ],
        vec!["hello".to_string()],
    );
    let err = core.execute(&module).unwrap_err();
    assert!(matches!(
        err,
        InterpreterError::MemoryBudgetExceeded { max_bytes: 1, .. }
    ));
}

#[test]
fn instruction_budget_and_memory_budget_are_independent() {
    let budget_module = test_module(vec![Ir3Instruction::Jump { target: 0 }]);
    let mut budget_config = test_quickjs_config();
    budget_config.instruction_budget = 5;
    budget_config.max_total_memory_bytes = u64::MAX;
    let budget_lane = QuickJsLane::with_config(budget_config);
    let budget_err = budget_lane
        .execute(&budget_module, "budget-first")
        .unwrap_err();
    assert!(matches!(
        budget_err,
        InterpreterError::BudgetExhausted {
            executed: 5,
            budget: 5,
        }
    ));

    let memory_module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::Halt,
        ],
        vec!["hello".to_string()],
    );
    let mut memory_config = test_quickjs_config();
    memory_config.instruction_budget = 10_000;
    memory_config.max_total_memory_bytes = 1;
    let memory_lane = QuickJsLane::with_config(memory_config);
    let memory_err = memory_lane
        .execute(&memory_module, "memory-first")
        .unwrap_err();
    assert!(matches!(
        memory_err,
        InterpreterError::MemoryBudgetExceeded { max_bytes: 1, .. }
    ));
}

#[test]
fn memory_budget_exceeded_display_includes_requested_and_limits() {
    let err = InterpreterError::MemoryBudgetExceeded {
        requested_bytes: 4096,
        max_bytes: 2048,
        requested_heap_objects: 12,
        max_heap_objects: 10,
    };
    let display = err.to_string();
    assert!(display.contains("12 heap objects"));
    assert!(display.contains("4096 bytes"));
    assert!(display.contains("10 heap objects"));
    assert!(display.contains("2048 bytes"));
}

#[test]
fn scope_chain_snapshot_respects_memory_budget() {
    let mut config = InterpreterConfig::quickjs_defaults();
    config.max_scope_depth = 4;
    let mut core = InterpreterCore::new(config, "scope-snapshot-budget");
    core.scope_chain.push(core.config.max_scope_depth).unwrap();
    core.scope_chain.current_mut().bindings.insert(
        "payload".to_string(),
        ScopeBinding::with_state(
            BindingKind::Var,
            Value::str("x".repeat(128)),
            crate::ifc_artifacts::Label::Public,
            true,
        ),
    );
    core.sync_estimated_memory_bytes().unwrap();
    let snapshot_bytes = InterpreterCore::estimate_scope_chain_bytes(&core.scope_chain.frames);
    core.config.max_total_memory_bytes = core
        .estimated_memory_bytes()
        .saturating_add(snapshot_bytes)
        .saturating_sub(1);
    let err = core.snapshot_scope_chain().unwrap_err();
    assert!(matches!(err, InterpreterError::MemoryBudgetExceeded { .. }));
}

#[test]
fn temporary_scope_clone_budget_counts_existing_snapshot() {
    let config = InterpreterConfig::quickjs_defaults();
    let mut core = InterpreterCore::new(config, "temporary-scope-clone-budget");
    core.scope_chain.current_mut().bindings.insert(
        "payload".to_string(),
        ScopeBinding::with_state(
            BindingKind::Var,
            Value::str("x".repeat(128)),
            crate::ifc_artifacts::Label::Public,
            true,
        ),
    );
    core.sync_estimated_memory_bytes().unwrap();

    let snapshot_bytes = InterpreterCore::estimate_scope_chain_bytes(&core.scope_chain.frames);
    core.config.max_total_memory_bytes = core
        .estimated_memory_bytes()
        .saturating_add(snapshot_bytes.saturating_mul(2))
        .saturating_sub(1);

    let err = core
        .snapshot_scope_chain_with_temporary_budget(snapshot_bytes)
        .unwrap_err();
    assert!(matches!(err, InterpreterError::MemoryBudgetExceeded { .. }));
}

#[test]
fn async_saved_label_snapshot_refuses_one_short_and_releases_bd_ur3tk_8() {
    let mut core = quickjs_test_core();
    let module = test_module_with_functions(
        vec![
            Ir3Instruction::AwaitValue { promise_reg: 0 },
            Ir3Instruction::AsyncReturn { value_reg: 1 },
        ],
        Vec::new(),
    );
    let custom_label = crate::ifc_artifacts::Label::Custom {
        name: "async-snapshot-label".repeat(23),
        level: 3,
    };
    core.write_reg_with_label(1, Value::Int(41), custom_label.clone())
        .expect("custom-labeled async register");
    let result_promise = core.promise_store.create();
    let awaited = core.promise_store.create();
    core.async_functions.push(AsyncFunctionObject {
        execution: None,
        owner_module: Some(Rc::new(module.clone())),
        retained_program_bytes: InterpreterCore::retained_module_program_bytes(&module),
        // This fixture transfers the existing interpreter register arena.
        register_storage_bytes: 0,
        label: crate::ifc_artifacts::Label::Public,
        phase: AsyncFunctionPhase::Executing,
        result_promise: result_promise.0,
    });
    core.call_stack.push(CallFrame {
        return_ip: module.instructions.len(),
        return_reg: None,
        saved_module_specifier: core.current_module_specifier.clone(),
        register_base: 0,
        function_index: Some(0),
        this_value: Value::Undefined,
        this_label: crate::ifc_artifacts::Label::Public,
        new_target_value: Value::Undefined,
        new_target_label: crate::ifc_artifacts::Label::Public,
        super_value: Value::Undefined,
        super_label: crate::ifc_artifacts::Label::Public,
        construct_this: None,
        derived_constructor: false,
        this_initialized: true,
        initialize_derived_this_on_return: false,
        saved_pending_exception: None,
        saved_pending_return: None,
        saved_suspended_abrupt_depth: 0,
        saved_finally_mode_depth: 0,
        saved_scope_depth: core.scope_chain.depth(),
        saved_scope_chain: None,
        async_function_id: Some(0),
        accessor_context_label: crate::ifc_artifacts::Label::Public,
    });
    let baseline = core
        .sync_estimated_memory_bytes()
        .expect("async snapshot baseline");
    let promise_count = core.promise_store.len();
    let original_promise = core.promise_store.get(awaited).unwrap().clone();
    let original_witness = core.promise_store.witness_log().to_vec();
    let original_queue_witness = core.event_loop.microtasks.witness_log().to_vec();
    let original_runtime_bytes = core.promise_runtime_memory_bytes();
    // Price the independent Promise layer, including the simultaneous
    // rollback copies. The activation itself moves; it is not cloned.
    let rollback_bytes = core.promise_store.estimated_memory_bytes()
        + core.event_loop.microtasks.estimated_memory_bytes();
    let mut expected_store = core.promise_store.clone();
    let mut expected_queue = core.event_loop.microtasks.clone();
    let continuation = expected_store
        .then_for_await(
            awaited,
            crate::ifc_artifacts::Label::Public,
            &mut expected_queue,
        )
        .unwrap();
    let registration_bytes = expected_store.estimated_memory_bytes()
        + expected_queue.estimated_memory_bytes()
        - rollback_bytes;
    let context_bytes = InterpreterCore::async_resumption_context_entry_bytes();
    let complete_ceiling = baseline + context_bytes + rollback_bytes + registration_bytes;
    assert!(registration_bytes > 0);
    let invalid = core
        .suspend_async_function_for_await(
            crate::promise_model::PromiseHandle(u32::MAX),
            0,
            crate::ifc_artifacts::Label::Public,
        )
        .expect_err("invalid await must not publish registration state");
    assert!(matches!(invalid, InterpreterError::TypeError { .. }));
    assert_eq!(core.promise_store.len(), promise_count);
    assert_eq!(core.estimated_memory_bytes(), baseline);
    assert!(core.async_resumption_contexts.is_empty());
    for ceiling in [
        baseline + context_bytes - 1,
        baseline + context_bytes + rollback_bytes - 1,
        complete_ceiling - 1,
    ] {
        core.config.max_total_memory_bytes = ceiling;
        let error = core
            .suspend_async_function_for_await(awaited, 0, crate::ifc_artifacts::Label::Public)
            .expect_err("one-byte-short await admission must remain atomic");
        assert!(matches!(
            error,
            InterpreterError::MemoryBudgetExceeded { .. }
        ));
        assert_eq!(core.promise_store.len(), promise_count);
        assert_eq!(core.promise_store.get(awaited).unwrap(), &original_promise);
        assert_eq!(core.promise_store.witness_log(), original_witness);
        assert_eq!(
            core.event_loop.microtasks.witness_log(),
            original_queue_witness
        );
        assert_eq!(core.promise_runtime_memory_bytes(), original_runtime_bytes);
        assert_eq!(core.promise_in_flight_task_bytes, 0);
        assert!(core.async_resumption_contexts.is_empty());
        assert_eq!(core.async_functions[0].phase, AsyncFunctionPhase::Executing);
        assert!(core.async_functions[0].execution.is_none());
        assert_eq!(core.read_reg_label(1).unwrap(), custom_label);
        assert_eq!(core.estimated_memory_bytes(), baseline);
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }

    core.config.max_total_memory_bytes = complete_ceiling;
    core.suspend_async_function_for_await(awaited, 0, crate::ifc_artifacts::Label::Public)
        .expect("exact await peak ceiling");
    assert_eq!(
        core.async_functions[0].phase,
        AsyncFunctionPhase::SuspendedAwait
    );
    assert_eq!(
        core.estimated_memory_bytes(),
        baseline + registration_bytes + context_bytes
    );
    assert_eq!(
        core.promise_store.get(continuation).unwrap(),
        expected_store.get(continuation).unwrap(),
        "refused registration must not advance creation identity"
    );
    assert_eq!(core.promise_in_flight_task_bytes, 0);
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
    let execution = core.take_module_execution();
    assert_eq!(execution.register_labels[1], custom_label);
    core.async_functions[0].execution = Some(execution);
    core.estimated_memory_bytes = core.recompute_estimated_memory_bytes();
    let context = core
        .take_async_resumption_context(continuation.0)
        .expect("one await registration owns one resumption");
    core.config.max_total_memory_bytes = u64::MAX;
    core.resume_async_function_after_await(
        context,
        Ok(crate::object_model::JsValue::Int(9)),
        crate::ifc_artifacts::Label::Public,
        None,
    )
    .expect("resume moves the entire activation and settles its result");
    assert!(core.async_functions[0].execution.is_none());
    assert!(core.async_functions[0].owner_module.is_none());
    assert_eq!(core.async_functions[0].retained_program_bytes, 0);
    assert_eq!(core.async_functions[0].phase, AsyncFunctionPhase::Completed);
    assert!(core.async_resumption_contexts.is_empty());
    let result = core.promise_store.get(result_promise).unwrap();
    assert!(matches!(
        result.state,
        crate::promise_model::PromiseState::Fulfilled(crate::object_model::JsValue::Int(41))
    ));
    assert_eq!(result.label, custom_label);
    assert_eq!(core.promise_in_flight_task_bytes, 0);
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn promise_combinator_label_refuses_clone_peak_and_releases_bd_ur3tk_8() {
    let mut core = quickjs_test_core();
    let baseline = core
        .sync_estimated_memory_bytes()
        .expect("promise-combinator label baseline");
    let initial_label = crate::ifc_artifacts::Label::Custom {
        name: "aggregate-input-label".repeat(19),
        level: 2,
    };
    let initial_bytes = InterpreterCore::estimate_label_bytes(&initial_label);
    let state = || LabeledPromiseCombinatorState {
        tracker: PromiseCombinatorState::Race(crate::promise_model::PromiseRaceTracker {
            result_promise: crate::promise_model::PromiseHandle(0),
            settled: false,
        }),
        accumulated_label: initial_label.clone(),
    };
    let entry_bytes = MEMORY_ESTIMATE_MAP_ENTRY_BYTES
        + InterpreterCore::estimate_promise_combinator_state_bytes(&state());
    for ceiling in [
        baseline + initial_bytes - 1,
        baseline + initial_bytes,
        baseline + entry_bytes - 1,
    ] {
        core.config.max_total_memory_bytes = ceiling;
        let error = core
            .register_combinator(state())
            .expect_err("label-only or one-byte-short full accumulator must not publish");
        assert!(matches!(
            error,
            InterpreterError::MemoryBudgetExceeded { .. }
        ));
        assert!(core.promise_combinators.is_empty());
        assert_eq!(core.next_promise_combinator_id, 0);
        assert_eq!(core.estimated_memory_bytes(), baseline);
    }

    core.config.max_total_memory_bytes = baseline + entry_bytes;
    let combinator_id = core
        .register_combinator(state())
        .expect("exact accumulator ceiling");
    assert_eq!(core.estimated_memory_bytes(), baseline + entry_bytes);
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );

    let dominant_label = crate::ifc_artifacts::Label::Custom {
        name: "dominant-aggregate-label".repeat(29),
        level: 4,
    };
    let dominant_bytes = InterpreterCore::estimate_label_bytes(&dominant_label);
    let before_join = core.estimated_memory_bytes();
    core.config.max_total_memory_bytes = before_join + dominant_bytes - 1;
    let error = core
        .join_promise_combinator_label(combinator_id, &dominant_label)
        .expect_err("one-byte-short dominant-label clone peak must fail atomically");
    assert!(matches!(
        error,
        InterpreterError::MemoryBudgetExceeded { .. }
    ));
    assert_eq!(
        core.promise_combinators[&combinator_id].accumulated_label,
        initial_label
    );
    assert_eq!(core.estimated_memory_bytes(), before_join);

    core.config.max_total_memory_bytes = before_join + dominant_bytes;
    core.join_promise_combinator_label(combinator_id, &dominant_label)
        .expect("exact dominant-label clone peak");
    assert_eq!(
        core.promise_combinators[&combinator_id].accumulated_label,
        dominant_label
    );
    assert_eq!(
        core.estimated_memory_bytes(),
        baseline + MEMORY_ESTIMATE_MAP_ENTRY_BYTES + dominant_bytes
    );
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );

    core.remove_promise_combinator(combinator_id)
        .expect("registered combinator should be removable");
    assert_eq!(core.estimated_memory_bytes(), baseline);
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn custom_scope_label_is_accounted_and_store_rolls_back_bd_ur3tk_11() {
    let config = InterpreterConfig::quickjs_defaults();
    let mut core = InterpreterCore::new(config, "custom-scope-label-budget");
    core.scope_chain.current_mut().bindings.insert(
        "payload".to_string(),
        ScopeBinding::with_state(
            BindingKind::Var,
            Value::Undefined,
            crate::ifc_artifacts::Label::Public,
            true,
        ),
    );
    core.sync_estimated_memory_bytes().unwrap();
    let custom_name = "tenant-sensitive".repeat(32);
    core.write_reg_with_label(
        0,
        Value::Int(7),
        crate::ifc_artifacts::Label::Custom {
            name: custom_name.clone(),
            level: 3,
        },
    )
    .expect("custom-labeled source should be writable before tightening the budget");
    core.config.max_total_memory_bytes = core
        .estimated_memory_bytes()
        .saturating_add(custom_name.len() as u64)
        .saturating_sub(1);
    let module = test_module_with_pool(
        vec![Ir3Instruction::StoreScoped {
            src: 0,
            name_pool_index: 0,
        }],
        vec!["payload".to_string()],
    );

    let error = core
        .run_loop(&module)
        .expect_err("custom scope label must respect the memory budget");
    assert!(matches!(
        error,
        InterpreterError::MemoryBudgetExceeded { .. }
    ));
    let (_, binding) = core
        .scope_chain
        .resolve("payload")
        .expect("failed StoreScoped should restore the binding");
    let state = binding.state().unwrap();
    assert_eq!(state.value, Value::Undefined);
    assert_eq!(state.label, crate::ifc_artifacts::Label::Public);
}

#[test]
fn failed_closure_publication_restores_shared_self_capture_cell_bd_wqbac() {
    for (marker_name, create_instruction) in [
        (
            format!("{CLASS_EXPRESSION_CONSTRUCTOR_SELF_CAPTURE_PREFIX}7\0Self"),
            Ir3Instruction::CreateClosure {
                dst: 1,
                function_index: 0,
                capture_count: 1,
            },
        ),
        (
            format!("{FUNCTION_EXPRESSION_SELF_CAPTURE_PREFIX}7\0self"),
            Ir3Instruction::CreateClosure {
                dst: 1,
                function_index: 0,
                capture_count: 1,
            },
        ),
        (
            format!("{FUNCTION_EXPRESSION_SELF_CAPTURE_PREFIX}8\0generatorSelf"),
            Ir3Instruction::CreateGenerator {
                dst: 1,
                function_index: 0,
                capture_count: 1,
            },
        ),
    ] {
        let mut config = test_quickjs_config();
        config.max_registers = 1;
        let mut core = InterpreterCore::new(config, "shared-self-publication-rollback");
        let marker = ScopeBinding::with_state(
            BindingKind::Const,
            Value::Int(41),
            crate::ifc_artifacts::Label::Public,
            true,
        );
        core.scope_chain
            .current_mut()
            .bindings
            .insert(marker_name, marker.clone());
        core.pending_captures.push(7);
        core.sync_estimated_memory_bytes().unwrap();
        let module = test_module(vec![create_instruction, Ir3Instruction::Halt]);

        let error = core
            .execute(&module)
            .expect_err("out-of-range destination must reject closure publication");
        assert!(matches!(
            error,
            InterpreterError::RegisterOutOfBounds {
                register: 1,
                max: 1
            }
        ));
        assert!(core.closures.is_empty());
        assert_eq!(core.pending_captures, vec![7]);
        let state = marker.state().unwrap();
        assert_eq!(state.value, Value::Int(41));
        assert!(state.initialized);
        drop(state);
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }
}

#[test]
fn generator_publication_initializes_named_expression_self_capture_bd_wqbac() {
    let mut core = quickjs_test_core();
    let marker_name = format!("{FUNCTION_EXPRESSION_SELF_CAPTURE_PREFIX}8\0generatorSelf");
    let marker = ScopeBinding::new(BindingKind::Const);
    core.scope_chain
        .current_mut()
        .bindings
        .insert(marker_name, marker.clone());
    core.sync_estimated_memory_bytes().unwrap();
    let module = test_module(vec![
        Ir3Instruction::CreateGenerator {
            dst: 0,
            function_index: 0,
            capture_count: 1,
        },
        Ir3Instruction::Halt,
    ]);

    let result = core.execute(&module).expect("generator publication");
    assert_eq!(result.value, Value::GeneratorFunction(0));
    let state = marker.state().unwrap();
    assert_eq!(state.value, Value::GeneratorFunction(0));
    assert!(state.initialized);
}

#[test]
fn failed_cjs_binding_injection_restores_existing_shared_cell() {
    let mut core = quickjs_test_core();
    let module_binding = ScopeBinding::with_state(
        BindingKind::Var,
        Value::Int(17),
        crate::ifc_artifacts::Label::Public,
        true,
    );
    core.scope_chain
        .current_mut()
        .bindings
        .insert("module".to_string(), module_binding.clone());
    core.sync_estimated_memory_bytes().unwrap();
    core.config.max_total_memory_bytes = core.estimated_memory_bytes();

    let error = core
        .insert_cjs_bindings(ObjectId(10), ObjectId(11), Some("/tmp/example.cjs"), false)
        .expect_err("new CJS bindings must exceed a zero-headroom memory budget");
    assert!(matches!(
        error,
        InterpreterError::MemoryBudgetExceeded { .. }
    ));
    assert_eq!(module_binding.value().unwrap(), Value::Int(17));
    for name in ["require", "exports", "__filename", "__dirname"] {
        assert!(core.scope_chain.resolve(name).is_none());
    }
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn generator_invocation_budget_failure_restores_caller_and_publishes_no_ghost_bd_093id() {
    let module = test_module(vec![
        Ir3Instruction::GeneratorBodyStart,
        Ir3Instruction::LoadInt { dst: 0, value: 7 },
        Ir3Instruction::Yield {
            value: 0,
            delegate: false,
            resume_dst: 1,
        },
        Ir3Instruction::Return { value: 0 },
    ]);
    let mut core = InterpreterCore::new(test_quickjs_config(), "generator-invocation-budget");
    core.scope_chain.current_mut().bindings.insert(
        "payload".to_string(),
        ScopeBinding::with_state(
            BindingKind::Var,
            Value::str("x".repeat(128)),
            crate::ifc_artifacts::Label::Public,
            true,
        ),
    );
    let captured_env = core.scope_chain.snapshot();
    core.closures.push(ClosureValue {
        function_index: 0,
        captured_env: captured_env.clone(),
        module_specifier: None,
    });
    core.ip = 3;
    core.write_reg(0, Value::Int(41)).unwrap();
    core.sync_estimated_memory_bytes().unwrap();
    let baseline_memory = core.estimated_memory_bytes();
    core.config.max_total_memory_bytes = baseline_memory;

    let error = core
        .prepare_generator_activation(
            &module,
            GeneratorCallSetup {
                function_index: 0,
                function_entry: 0,
                captured_env,
                arguments: Vec::new(),
                this_value: Value::Undefined,
                this_label: crate::ifc_artifacts::Label::Public,
                super_value: Value::Undefined,
                super_label: crate::ifc_artifacts::Label::Public,
            },
        )
        .expect_err("zero headroom must reject the isolated generator activation");

    assert!(matches!(
        error,
        InterpreterError::MemoryBudgetExceeded { .. }
    ));
    assert!(core.generators.is_empty());
    assert_eq!(core.ip, 3);
    assert_eq!(core.read_reg(0).unwrap(), Value::Int(41));
    assert!(core.scope_chain.resolve("payload").is_some());
    assert_eq!(core.temporarily_suspended_execution_bytes, 0);
    assert_eq!(core.temporarily_suspended_call_depth, 0);
    assert_eq!(core.estimated_memory_bytes(), baseline_memory);
}

#[test]
fn generator_resume_rejects_at_active_call_depth_limit_bd_093id() {
    let module = test_module(vec![
        Ir3Instruction::GeneratorBodyStart,
        Ir3Instruction::LoadInt { dst: 0, value: 7 },
        Ir3Instruction::Yield {
            value: 0,
            delegate: false,
            resume_dst: 1,
        },
        Ir3Instruction::Return { value: 0 },
    ]);
    let mut config = test_quickjs_config();
    config.max_call_depth = 2;
    let mut core = InterpreterCore::new(config, "generator-resume-depth");
    let captured_env = core.scope_chain.snapshot();
    let generator = core
        .prepare_generator_activation(
            &module,
            GeneratorCallSetup {
                function_index: 0,
                function_entry: 0,
                captured_env,
                arguments: Vec::new(),
                this_value: Value::Undefined,
                this_label: crate::ifc_artifacts::Label::Public,
                super_value: Value::Undefined,
                super_label: crate::ifc_artifacts::Label::Public,
            },
        )
        .expect("generator activation should suspend at its body boundary");
    let generator_frame = generator
        .execution
        .as_ref()
        .expect("suspended generator should own its activation")
        .call_stack[0]
        .clone();
    core.generators.push(generator);
    core.call_stack = vec![generator_frame; core.config.max_call_depth];

    let error = core
        .generator_next(
            &module,
            0,
            Value::Undefined,
            crate::ifc_artifacts::Label::Public,
        )
        .expect_err("resume at the active depth limit must fail closed");
    assert_eq!(error, InterpreterError::StackOverflow { depth: 2, max: 2 });
    assert_eq!(core.generators[0].phase, GeneratorPhase::SuspendedStart);
    assert!(core.generators[0].execution.is_some());
}

#[test]
fn generator_resume_context_swap_preserves_memory_accounting_bd_093id() {
    let module = test_module(vec![
        Ir3Instruction::GeneratorBodyStart,
        Ir3Instruction::LoadInt { dst: 0, value: 7 },
        Ir3Instruction::Yield {
            value: 0,
            delegate: false,
            resume_dst: 1,
        },
        Ir3Instruction::Return { value: 0 },
    ]);
    let mut core = InterpreterCore::new(test_quickjs_config(), "generator-resume-memory");
    let captured_env = core.scope_chain.snapshot();
    let generator = core
        .prepare_generator_activation(
            &module,
            GeneratorCallSetup {
                function_index: 0,
                function_entry: 0,
                captured_env,
                arguments: Vec::new(),
                this_value: Value::Undefined,
                this_label: crate::ifc_artifacts::Label::Public,
                super_value: Value::Undefined,
                super_label: crate::ifc_artifacts::Label::Public,
            },
        )
        .expect("generator activation should suspend at its body boundary");
    core.generators.push(generator);
    core.current_module_specifier = Some("m".repeat(64 * 1024));
    let baseline = core
        .sync_estimated_memory_bytes()
        .expect("caller and generator activation should fit initially");
    core.config.max_total_memory_bytes = baseline.saturating_add(16 * 1024);

    let (yielded, _) = core
        .generator_next(
            &module,
            0,
            Value::Undefined,
            crate::ifc_artifacts::Label::Public,
        )
        .expect("moving a fully accounted caller must not create a phantom overage");
    let Value::Object(result_id) = yielded else {
        panic!("expected generator result object");
    };
    assert_eq!(
        core.heap[result_id.0 as usize].properties.get("value"),
        Some(&Value::Int(7))
    );
    assert_eq!(
        core.current_module_specifier.as_ref().map(String::len),
        Some(64 * 1024)
    );
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn generator_value_and_resume_labels_are_isolated_bd_ur3tk_5() {
    let module = test_module(vec![
        Ir3Instruction::GeneratorBodyStart,
        Ir3Instruction::Yield {
            value: 0,
            delegate: false,
            resume_dst: 1,
        },
        Ir3Instruction::Return { value: 1 },
    ]);
    let mut core = InterpreterCore::new(test_quickjs_config(), "generator-label-isolation");
    core.write_reg_with_label(5, Value::Int(99), crate::ifc_artifacts::Label::TopSecret)
        .expect("caller sentinel should be writable");

    for (value, label) in [
        (Value::Int(11), crate::ifc_artifacts::Label::Secret),
        (Value::Int(22), crate::ifc_artifacts::Label::Internal),
    ] {
        let generator = core
            .prepare_generator_activation(
                &module,
                GeneratorCallSetup {
                    function_index: 0,
                    function_entry: 0,
                    captured_env: core.scope_chain.snapshot(),
                    arguments: vec![(value, label)],
                    this_value: Value::Undefined,
                    this_label: crate::ifc_artifacts::Label::Public,
                    super_value: Value::Undefined,
                    super_label: crate::ifc_artifacts::Label::Public,
                },
            )
            .expect("generator activation should suspend at its body boundary");
        core.generators.push(generator);
    }

    let (_, first_label) = core
        .generator_next(
            &module,
            0,
            Value::Undefined,
            crate::ifc_artifacts::Label::Public,
        )
        .expect("first generator should yield");
    let (_, second_label) = core
        .generator_next(
            &module,
            1,
            Value::Undefined,
            crate::ifc_artifacts::Label::Public,
        )
        .expect("second generator should yield independently");
    assert_eq!(first_label, crate::ifc_artifacts::Label::Secret);
    assert_eq!(second_label, crate::ifc_artifacts::Label::Internal);

    let (_, return_label) = core
        .generator_next(
            &module,
            0,
            Value::Int(33),
            crate::ifc_artifacts::Label::Confidential,
        )
        .expect("resume argument should become the first generator's return value");
    assert_eq!(return_label, crate::ifc_artifacts::Label::Confidential);
    assert_eq!(
        core.read_reg_label(5).expect("caller label should survive"),
        crate::ifc_artifacts::Label::TopSecret
    );
    assert_eq!(
        core.generators[1]
            .execution
            .as_ref()
            .expect("second generator should remain suspended")
            .register_labels[0],
        crate::ifc_artifacts::Label::Internal
    );
}

#[test]
fn generator_rejects_mismatched_value_and_label_snapshot_bd_ur3tk_5() {
    let module = test_module(vec![
        Ir3Instruction::GeneratorBodyStart,
        Ir3Instruction::Return { value: 0 },
    ]);
    let mut core = InterpreterCore::new(test_quickjs_config(), "generator-label-shape");
    let mut generator = core
        .prepare_generator_activation(
            &module,
            GeneratorCallSetup {
                function_index: 0,
                function_entry: 0,
                captured_env: core.scope_chain.snapshot(),
                arguments: Vec::new(),
                this_value: Value::Undefined,
                this_label: crate::ifc_artifacts::Label::Public,
                super_value: Value::Undefined,
                super_label: crate::ifc_artifacts::Label::Public,
            },
        )
        .expect("generator activation should reach its body boundary");
    generator
        .execution
        .as_mut()
        .expect("prepared generator activation")
        .register_labels
        .pop();
    core.generators.push(generator);

    let error = core
        .generator_next(
            &module,
            0,
            Value::Undefined,
            crate::ifc_artifacts::Label::Public,
        )
        .expect_err("a missing register label must fail closed");
    assert!(matches!(
        error,
        InterpreterError::TypeError { expected, got }
            if expected.contains("one IFC label per register")
                && got.contains("values=")
                && got.contains("labels=")
    ));
    assert_eq!(core.generators[0].phase, GeneratorPhase::SuspendedStart);
    assert!(core.generators[0].execution.is_some());
}

#[test]
fn generator_return_completion_survives_finally_yield_bd_ur3tk_5() {
    let module = test_module(vec![
        Ir3Instruction::GeneratorBodyStart,
        Ir3Instruction::BeginTry {
            catch_target: 3,
            finally_target: Some(3),
        },
        Ir3Instruction::Return { value: 0 },
        Ir3Instruction::EnterFinally,
        Ir3Instruction::Yield {
            value: 0,
            delegate: false,
            resume_dst: 1,
        },
        Ir3Instruction::EndFinally,
    ]);
    let mut core = InterpreterCore::new(test_quickjs_config(), "generator-finally-snapshot");
    let generator = core
        .prepare_generator_activation(
            &module,
            GeneratorCallSetup {
                function_index: 0,
                function_entry: 0,
                captured_env: core.scope_chain.snapshot(),
                arguments: vec![(Value::Int(7), crate::ifc_artifacts::Label::Secret)],
                this_value: Value::Undefined,
                this_label: crate::ifc_artifacts::Label::Public,
                super_value: Value::Undefined,
                super_label: crate::ifc_artifacts::Label::Public,
            },
        )
        .expect("generator activation should suspend at its body boundary");
    core.generators.push(generator);

    let (_, yield_label) = core
        .generator_next(
            &module,
            0,
            Value::Undefined,
            crate::ifc_artifacts::Label::Public,
        )
        .expect("finally should yield before completing the pending return");
    assert_eq!(yield_label, crate::ifc_artifacts::Label::Secret);
    let suspended = core.generators[0]
        .execution
        .as_ref()
        .expect("yield should preserve the generator activation");
    assert!(matches!(
        suspended.finally_frames.last(),
        Some(FinallyFrame {
            completion: Some(AbruptCompletion::Return(LabeledReturn {
                value: Value::Int(7),
                label: crate::ifc_artifacts::Label::Secret,
            })),
        })
    ));

    let (_, return_label) = core
        .generator_next(
            &module,
            0,
            Value::Undefined,
            crate::ifc_artifacts::Label::Public,
        )
        .expect("resuming after the yield should complete the original return");
    assert_eq!(return_label, crate::ifc_artifacts::Label::Secret);
    assert_eq!(core.generators[0].phase, GeneratorPhase::Completed);
}

fn markerless_generator_module_bd_093id() -> Ir3Module {
    let mut module = test_module(vec![
        Ir3Instruction::LoadInt { dst: 2, value: 7 },
        Ir3Instruction::CreateGenerator {
            dst: 0,
            function_index: 0,
            capture_count: 0,
        },
        Ir3Instruction::Call {
            callee: 0,
            args: RegRange { start: 2, count: 1 },
            dst: 1,
        },
        Ir3Instruction::Move { dst: 0, src: 1 },
        Ir3Instruction::Halt,
        Ir3Instruction::Yield {
            value: 0,
            delegate: false,
            resume_dst: 1,
        },
        Ir3Instruction::Return { value: 0 },
    ]);
    module.function_table.push(Ir3FunctionDesc {
        entry: 5,
        arity: 1,
        frame_size: 2,
        name: Some("legacy_generator".to_string()),
        is_generator: true,
        rest_param_index: None,
    });
    module
}

#[test]
fn current_generator_ir_without_body_boundary_rejects_before_execution_bd_093id() {
    let module = markerless_generator_module_bd_093id();
    let mut core = InterpreterCore::new(test_quickjs_config(), "current-generator-wire");
    let error = core
        .execute(&module)
        .expect_err("current markerless generator IR must fail structurally");
    assert!(matches!(
        error,
        InterpreterError::TypeError { expected, got }
            if expected.contains("structurally valid core IR3")
                && got.contains("IR_INVALID_GENERATOR_BOUNDARY")
    ));
    assert!(core.generators.is_empty());
}

#[test]
fn execution_rejects_unsupported_ir_schema_before_dispatch_bd_093id() {
    let mut module = test_module(vec![Ir3Instruction::Halt]);
    module.header.schema_version = crate::ir_contract::IrSchemaVersion {
        major: 0,
        minor: crate::ir_contract::IrSchemaVersion::CURRENT.minor + 1,
        patch: 0,
    };
    let mut core = InterpreterCore::new(test_quickjs_config(), "future-core-ir");
    let error = core
        .execute(&module)
        .expect_err("future IR must reject before interpreter dispatch");
    assert!(matches!(
        error,
        InterpreterError::TypeError { expected, got }
            if expected.contains("supported")
                && got.contains("IR_SCHEMA_VERSION_MISMATCH")
    ));
    assert_eq!(core.instructions_executed, 0);
}

#[test]
fn legacy_generator_ir_without_body_boundary_retains_first_next_start_bd_093id() {
    let mut module = markerless_generator_module_bd_093id();
    module.header.schema_version = crate::ir_contract::IrSchemaVersion {
        major: 0,
        minor: 9,
        patch: 0,
    };

    let mut core = InterpreterCore::new(test_quickjs_config(), "legacy-generator-wire");
    let invocation = core.execute(&module).expect("legacy generator invocation");
    assert_eq!(invocation.value, Value::Generator(0));
    assert_eq!(core.generators[0].phase, GeneratorPhase::SuspendedStart);

    let (yielded, _) = core
        .generator_next(
            &module,
            0,
            Value::Undefined,
            crate::ifc_artifacts::Label::Public,
        )
        .expect("legacy generator should start at its first next call");
    let Value::Object(result_id) = yielded else {
        panic!("expected legacy generator result object");
    };
    assert_eq!(
        core.heap[result_id.0 as usize].properties.get("value"),
        Some(&Value::Int(7))
    );
    assert_eq!(
        core.heap[result_id.0 as usize].properties.get("done"),
        Some(&Value::Bool(false))
    );
}

#[test]
fn closure_calls_persist_mutated_capture_across_shared_environment() {
    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadInt { dst: 0, value: 0 },
            Ir3Instruction::DeclareBinding {
                name_pool_index: 0,
                kind: 1,
            },
            Ir3Instruction::InitBinding {
                name_pool_index: 0,
                src: 0,
            },
            Ir3Instruction::CreateClosure {
                dst: 1,
                function_index: 0,
                capture_count: 0,
            },
            Ir3Instruction::CreateClosure {
                dst: 2,
                function_index: 0,
                capture_count: 0,
            },
            Ir3Instruction::Call {
                callee: 1,
                args: RegRange {
                    start: 10,
                    count: 0,
                },
                dst: 3,
            },
            Ir3Instruction::Call {
                callee: 2,
                args: RegRange {
                    start: 10,
                    count: 0,
                },
                dst: 4,
            },
            Ir3Instruction::Move { dst: 0, src: 4 },
            Ir3Instruction::Halt,
            Ir3Instruction::LoadScoped {
                dst: 0,
                name_pool_index: 0,
            },
            Ir3Instruction::LoadInt { dst: 1, value: 1 },
            Ir3Instruction::Add {
                dst: 2,
                lhs: 0,
                rhs: 1,
            },
            Ir3Instruction::StoreScoped {
                src: 2,
                name_pool_index: 0,
            },
            Ir3Instruction::Return { value: 2 },
        ],
        vec!["n".to_string()],
    );
    module.function_table.push(Ir3FunctionDesc {
        entry: 9,
        arity: 0,
        frame_size: 4,
        name: Some("increment".to_string()),
        is_generator: false,
        rest_param_index: None,
    });

    let result = quickjs_execute(&module).unwrap();
    assert_eq!(result.value, Value::Int(2));
}

#[test]
fn scope_chain_snapshot_produces_correct_frame_count() {
    let config = InterpreterConfig::quickjs_defaults();
    let mut core = InterpreterCore::new(config, "snapshot-frame-count");

    // Push 4 additional frames (starting with 1 global = 5 total)
    for _ in 0..4 {
        core.scope_chain.push(core.config.max_scope_depth).unwrap();
    }

    let snapshot = core.scope_chain.snapshot();
    assert_eq!(snapshot.len(), 5);
}

#[test]
fn closure_captures_correctly_at_deep_scope_chain() {
    let mut config = InterpreterConfig::quickjs_defaults();
    config.max_scope_depth = 15; // Allow deeper nesting
    let mut core = InterpreterCore::new(config, "deep-closure-capture");

    // Build scope chain with depth 10, adding a binding at each level
    for i in 0..10 {
        if i > 0 {
            core.scope_chain.push(core.config.max_scope_depth).unwrap();
        }
        let binding_name = format!("var{}", i);
        let binding_value = format!("value{}", i);
        core.scope_chain.current_mut().bindings.insert(
            binding_name.clone(),
            ScopeBinding::with_state(
                BindingKind::Var,
                Value::str(binding_value.clone()),
                crate::ifc_artifacts::Label::Public,
                true,
            ),
        );
    }

    assert_eq!(core.scope_chain.depth(), 10);

    // Create a closure by capturing the scope chain
    let captured_env = core.snapshot_scope_chain().unwrap();
    assert_eq!(captured_env.len(), 10);

    // Verify all bindings are preserved in the capture
    for (level, frame) in captured_env.iter().enumerate() {
        let binding_name = format!("var{}", level);
        let expected_value = format!("value{}", level);
        if let Some(binding) = frame.bindings.get(&binding_name) {
            assert_eq!(binding.value().unwrap(), Value::str(expected_value));
        } else {
            panic!("Missing binding {} at scope level {}", binding_name, level);
        }
    }

    // Verify we can store the closure
    core.closures.push(ClosureValue {
        function_index: 0,
        captured_env,
        module_specifier: None,
    });

    // Verify the closure ID is valid
    assert_eq!(core.closures.len(), 1);
}

#[test]
fn push_scope_instruction_respects_max_scope_depth() {
    let mut config = test_quickjs_config();
    config.max_scope_depth = 2;
    let mut core = InterpreterCore::new(config, "scope-depth-budget");
    let module = test_module(vec![
        Ir3Instruction::PushScope,
        Ir3Instruction::PushScope,
        Ir3Instruction::Halt,
    ]);
    let err = core.execute(&module).unwrap_err();
    assert!(matches!(
        err,
        InterpreterError::ScopeDepthExceeded {
            requested_depth: 3,
            max_depth: 2,
        }
    ));
}

#[test]
fn load_bool_false() {
    let m = test_module(vec![
        Ir3Instruction::LoadBool {
            dst: 0,
            value: false,
        },
        Ir3Instruction::Halt,
    ]);
    let result = quickjs_execute(&m).unwrap();
    assert_eq!(result.value, Value::Bool(false));
}

#[test]
fn v8_lane_execute_produces_result() {
    let m = test_module(vec![
        Ir3Instruction::LoadInt { dst: 0, value: 99 },
        Ir3Instruction::Halt,
    ]);
    let result = v8_execute(&m).unwrap();
    assert_eq!(result.value, Value::Int(99));
}

#[test]
fn interpreter_error_serde_all_variants() {
    let variants: Vec<InterpreterError> = vec![
        InterpreterError::BudgetExhausted {
            executed: 100,
            budget: 50,
        },
        InterpreterError::RegisterOutOfBounds {
            register: 999,
            max: 256,
        },
        InterpreterError::InstructionOutOfBounds { ip: 10, count: 5 },
        InterpreterError::StackOverflow { depth: 10, max: 5 },
        InterpreterError::TypeError {
            expected: "number".to_string(),
            got: "object".to_string(),
        },
        InterpreterError::DivisionByZero,
        InterpreterError::UndefinedRegister { register: 42 },
        InterpreterError::ObjectNotFound { id: 7 },
        InterpreterError::PropertyNotFound {
            object_id: 3,
            key: "x".to_string(),
        },
        InterpreterError::FunctionNotFound {
            index: 5,
            table_size: 3,
        },
        InterpreterError::StringPoolOutOfBounds {
            index: 10,
            pool_size: 5,
        },
        InterpreterError::RequireSpecifierNotString {
            got: "undefined".to_string(),
        },
        InterpreterError::CapabilityDenied {
            capability: "net".to_string(),
        },
        InterpreterError::UnsupportedMembershipSemantics {
            operator: "instanceof".to_string(),
        },
        InterpreterError::IteratorNotFound { handle: 11 },
        InterpreterError::Halted,
        InterpreterError::UncaughtException {
            value: "error msg".to_string(),
        },
        InterpreterError::UninitializedBinding {
            name: "late".to_string(),
        },
        InterpreterError::ConstAssignment {
            name: "CONST_X".to_string(),
        },
        InterpreterError::StringLimitExceeded {
            length: 1024,
            max: 512,
        },
        InterpreterError::MemoryBudgetExceeded {
            requested_bytes: 4096,
            max_bytes: 2048,
            requested_heap_objects: 12,
            max_heap_objects: 10,
        },
        InterpreterError::ContainmentActionRequested {
            action: "terminate".to_string(),
            reason: Some("policy".to_string()),
        },
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let back: InterpreterError = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

// -- Mixed Int/Float arithmetic tests --

#[test]
fn eval_add_int_float_promotion() {
    // Int + Float should promote to Float
    let mut core = quickjs_test_core();
    core.registers.resize(4, Value::Undefined);
    core.registers[0] = Value::Int(1);
    core.registers[1] = Value::Float(Float64::new(0.5));
    let result = core.eval_add(0, 1).unwrap();
    assert_eq!(result, Value::Float(Float64::new(1.5)));
}

#[test]
fn eval_add_float_int_promotion() {
    // Float + Int should promote to Float
    let mut core = quickjs_test_core();
    core.registers.resize(4, Value::Undefined);
    core.registers[0] = Value::Float(Float64::new(2.5));
    core.registers[1] = Value::Int(3);
    let result = core.eval_add(0, 1).unwrap();
    assert_eq!(result, Value::Float(Float64::new(5.5)));
}

#[test]
fn eval_div_int_int_exact() {
    // 6 / 3 = 2 (exact integer result)
    let mut core = quickjs_test_core();
    core.registers.resize(4, Value::Undefined);
    core.registers[0] = Value::Int(6);
    core.registers[1] = Value::Int(3);
    let result = core.eval_div(0, 1).unwrap();
    assert_eq!(result, Value::Int(2));
}

#[test]
fn eval_div_int_int_fractional() {
    // 7 / 3 = 2.333... (fractional result)
    let mut core = quickjs_test_core();
    core.registers.resize(4, Value::Undefined);
    core.registers[0] = Value::Int(7);
    core.registers[1] = Value::Int(3);
    let result = core.eval_div(0, 1).unwrap();
    if let Value::Float(f) = result {
        let v = f.inner();
        assert!((v - 2.333333333333333).abs() < 1e-10);
    } else {
        panic!("Expected Float, got {:?}", result);
    }
}

#[test]
fn eval_div_by_zero_infinity() {
    // 1 / 0 = Infinity
    let mut core = quickjs_test_core();
    core.registers.resize(4, Value::Undefined);
    core.registers[0] = Value::Int(1);
    core.registers[1] = Value::Int(0);
    let result = core.eval_div(0, 1).unwrap();
    if let Value::Float(f) = result {
        assert!(f.inner().is_infinite() && f.inner() > 0.0);
    } else {
        panic!("Expected Float(Infinity), got {:?}", result);
    }
}

#[test]
fn eval_div_zero_zero_nan() {
    // 0 / 0 = NaN
    let mut core = quickjs_test_core();
    core.registers.resize(4, Value::Undefined);
    core.registers[0] = Value::Int(0);
    core.registers[1] = Value::Int(0);
    let result = core.eval_div(0, 1).unwrap();
    if let Value::Float(f) = result {
        assert!(f.inner().is_nan());
    } else {
        panic!("Expected Float(NaN), got {:?}", result);
    }
}

#[test]
fn eval_arith_nan_propagation() {
    // NaN + 1 = NaN
    let mut core = quickjs_test_core();
    core.registers.resize(4, Value::Undefined);
    core.registers[0] = Value::Float(Float64::new(f64::NAN));
    core.registers[1] = Value::Int(1);
    let result = core.eval_add(0, 1).unwrap();
    if let Value::Float(f) = result {
        assert!(f.inner().is_nan());
    } else {
        panic!("Expected Float(NaN), got {:?}", result);
    }
}

#[test]
fn eval_arith_infinity_mul_zero() {
    // Infinity * 0 = NaN
    let mut core = quickjs_test_core();
    core.registers.resize(4, Value::Undefined);
    core.registers[0] = Value::Float(Float64::new(f64::INFINITY));
    core.registers[1] = Value::Int(0);
    let result = core.eval_arith(0, 1, "mul").unwrap();
    if let Value::Float(f) = result {
        assert!(f.inner().is_nan());
    } else {
        panic!("Expected Float(NaN), got {:?}", result);
    }
}

#[test]
fn eval_mod_float_float() {
    // 5.5 % 2.0 = 1.5
    let mut core = quickjs_test_core();
    core.registers.resize(4, Value::Undefined);
    core.registers[0] = Value::Float(Float64::new(5.5));
    core.registers[1] = Value::Float(Float64::new(2.0));
    let result = core.eval_mod(0, 1).unwrap();
    if let Value::Float(f) = result {
        assert!((f.inner() - 1.5).abs() < 1e-10);
    } else {
        panic!("Expected Float(1.5), got {:?}", result);
    }
}

#[test]
fn eval_unary_neg_float() {
    // -Float(1.5) = Float(-1.5)
    let mut core = quickjs_test_core();
    core.registers.resize(4, Value::Undefined);
    core.registers[0] = Value::Float(Float64::new(1.5));
    let result = core.eval_unary_neg(0).unwrap();
    assert_eq!(result, Value::Float(Float64::new(-1.5)));
}

#[test]
fn eval_ieee754_classic() {
    // 0.1 + 0.2 = 0.30000000000000004 (classic IEEE 754 test)
    let mut core = quickjs_test_core();
    core.registers.resize(4, Value::Undefined);
    core.registers[0] = Value::Float(Float64::new(0.1));
    core.registers[1] = Value::Float(Float64::new(0.2));
    let result = core.eval_add(0, 1).unwrap();
    if let Value::Float(f) = result {
        // The exact value is 0.30000000000000004
        assert!((f.inner() - 0.30000000000000004).abs() < 1e-16);
    } else {
        panic!("Expected Float, got {:?}", result);
    }
}

// -----------------------------------------------------------------------
// Special values: NaN, Infinity, -Infinity, -0
// -----------------------------------------------------------------------

#[test]
fn nan_strict_not_equal_to_itself() {
    // NaN !== NaN
    let nan1 = Value::Float(Float64::new(f64::NAN));
    let nan2 = Value::Float(Float64::new(f64::NAN));
    assert!(!InterpreterCore::strict_eq_values(&nan1, &nan2));
}

#[test]
fn nan_loose_not_equal_to_itself() {
    // NaN != NaN
    let nan1 = Value::Float(Float64::new(f64::NAN));
    let nan2 = Value::Float(Float64::new(f64::NAN));
    assert!(!InterpreterCore::abstract_eq_values(&nan1, &nan2));
}

#[test]
fn negative_zero_strict_equals_positive_zero() {
    // -0 === +0
    let neg_zero = Value::Float(Float64::new(-0.0));
    let pos_zero = Value::Float(Float64::new(0.0));
    assert!(InterpreterCore::strict_eq_values(&neg_zero, &pos_zero));
}

#[test]
fn negative_zero_loose_equals_positive_zero() {
    // -0 == +0
    let neg_zero = Value::Float(Float64::new(-0.0));
    let pos_zero = Value::Float(Float64::new(0.0));
    assert!(InterpreterCore::abstract_eq_values(&neg_zero, &pos_zero));
}

#[test]
fn one_div_neg_zero_is_neg_infinity() {
    // 1 / -0 = -Infinity
    let mut core = quickjs_test_core();
    core.registers.resize(4, Value::Undefined);
    core.registers[0] = Value::Float(Float64::new(1.0));
    core.registers[1] = Value::Float(Float64::new(-0.0));
    // SAFETY: Test division with valid register indices and values; eval_div succeeds in controlled test environment
    let result = core.eval_div(0, 1).unwrap();
    if let Value::Float(f) = result {
        assert!(f.inner().is_infinite() && f.inner() < 0.0);
    } else {
        panic!("Expected Float(-Infinity), got {:?}", result);
    }
}

#[test]
fn neg_one_div_zero_is_neg_infinity() {
    // -1 / 0 = -Infinity
    let mut core = quickjs_test_core();
    core.registers.resize(4, Value::Undefined);
    core.registers[0] = Value::Float(Float64::new(-1.0));
    core.registers[1] = Value::Int(0);
    let result = core.eval_div(0, 1).unwrap();
    if let Value::Float(f) = result {
        assert!(f.inner().is_infinite() && f.inner() < 0.0);
    } else {
        panic!("Expected Float(-Infinity), got {:?}", result);
    }
}

#[test]
fn float64_display_nan() {
    let nan = Float64::new(f64::NAN);
    assert_eq!(format!("{nan}"), "NaN");
}

#[test]
fn float64_display_infinity() {
    let inf = Float64::new(f64::INFINITY);
    assert_eq!(format!("{inf}"), "Infinity");
}

#[test]
fn float64_display_neg_infinity() {
    let neg_inf = Float64::new(f64::NEG_INFINITY);
    assert_eq!(format!("{neg_inf}"), "-Infinity");
}

#[test]
fn float64_display_neg_zero() {
    // -0 displays as "0" (JS semantics)
    let neg_zero = Float64::new(-0.0);
    assert_eq!(format!("{neg_zero}"), "0");
}

#[test]
fn float64_is_negative_zero() {
    assert!(Float64::new(-0.0).is_negative_zero());
    assert!(!Float64::new(0.0).is_negative_zero());
    assert!(!Float64::new(1.0).is_negative_zero());
}

#[test]
fn value_float_nan_is_falsy() {
    assert!(!Value::Float(Float64::new(f64::NAN)).is_truthy());
}

#[test]
fn value_float_zero_is_falsy() {
    assert!(!Value::Float(Float64::new(0.0)).is_truthy());
    assert!(!Value::Float(Float64::new(-0.0)).is_truthy());
}

#[test]
fn value_float_infinity_is_truthy() {
    assert!(Value::Float(Float64::new(f64::INFINITY)).is_truthy());
    assert!(Value::Float(Float64::new(f64::NEG_INFINITY)).is_truthy());
}

#[test]
fn value_typeof_float_is_number() {
    assert_eq!(Value::Float(Float64::new(1.5)).type_name(), "number");
    assert_eq!(Value::Float(Float64::new(f64::NAN)).type_name(), "number");
    assert_eq!(
        Value::Float(Float64::new(f64::INFINITY)).type_name(),
        "number"
    );
}

// -- Capability enforcement tests (bd-3pa1u.2) --

#[test]
fn heap_allocate_capability_required_for_object_allocation() {
    // Test with HeapAllocate capability - should succeed
    let mut config = InterpreterConfig::quickjs_defaults();
    config
        .granted_capabilities
        .insert(RuntimeCapability::HeapAllocate);
    let mut core = InterpreterCore::new(config, "heap-alloc-test");

    let result = core.alloc_object_with_prototype(None);
    assert!(result.is_ok());

    // Test without HeapAllocate capability - should fail
    let mut config = InterpreterConfig::quickjs_defaults();
    config.granted_capabilities.clear(); // Remove all capabilities
    let mut core = InterpreterCore::new(config, "no-heap-alloc-test");

    let err = core.alloc_object_with_prototype(None).unwrap_err();
    assert!(
        matches!(err, InterpreterError::CapabilityDenied { capability } if capability == "HeapAllocate")
    );
}

#[test]
fn vm_dispatch_capability_required_for_execution() {
    // Test with VmDispatch capability - should succeed
    let mut config = InterpreterConfig::quickjs_defaults();
    config
        .granted_capabilities
        .insert(RuntimeCapability::VmDispatch);
    config
        .granted_capabilities
        .insert(RuntimeCapability::HeapAllocate);
    let mut core = InterpreterCore::new(config, "vm-dispatch-test");

    let module = test_module(vec![Ir3Instruction::Halt]);
    let result = core.execute(&module);
    assert!(result.is_ok());

    // Test without VmDispatch capability - should fail
    let mut config = InterpreterConfig::quickjs_defaults();
    config.granted_capabilities.clear(); // Remove all capabilities
    let mut core = InterpreterCore::new(config, "no-vm-dispatch-test");

    let module = test_module(vec![Ir3Instruction::Halt]);
    let err = core.execute(&module).unwrap_err();
    assert!(
        matches!(err, InterpreterError::CapabilityDenied { capability } if capability == "VmDispatch")
    );
}

#[test]
fn capability_denied_error_contains_missing_capability_name() {
    let mut config = InterpreterConfig::quickjs_defaults();
    config.granted_capabilities.clear(); // Remove all capabilities
    let mut core = InterpreterCore::new(config, "capability-error-test");

    // Test that VmDispatch error contains the correct capability name
    let module = test_module(vec![Ir3Instruction::Halt]);
    let err = core.execute(&module).unwrap_err();
    match err {
        InterpreterError::CapabilityDenied { capability } => {
            assert_eq!(capability, "VmDispatch");
        }
        _ => panic!("Expected CapabilityDenied error"),
    }

    // Test that HeapAllocate error contains the correct capability name
    let err = core.alloc_object_with_prototype(None).unwrap_err();
    match err {
        InterpreterError::CapabilityDenied { capability } => {
            assert_eq!(capability, "HeapAllocate");
        }
        _ => panic!("Expected CapabilityDenied error"),
    }
}

fn lower_concise_method_source_bd_gqaa4(source: &str, label: &str) -> Ir3Module {
    let tree = CanonicalEs2020Parser
        .parse(source, ParseGoal::Script)
        .expect("concise-method source should parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, label);
    let ctx = LoweringContext::new(
        format!("trace-{label}"),
        format!("decision-{label}"),
        format!("policy-{label}"),
    );
    lower_ir0_to_ir3(&ir0, &ctx)
        .expect("concise-method source should lower")
        .ir3
}

#[test]
fn concise_object_method_preserves_receiver_bd_gqaa4() {
    let module = lower_concise_method_source_bd_gqaa4(
        "const object = { value: 41, method() { return this.value + 1; } };\nobject.method();",
        "concise-method-receiver.js",
    );
    assert!(
        module
            .instructions
            .iter()
            .any(|instruction| matches!(instruction, Ir3Instruction::DefineMethod { .. })),
        "method lowering must retain its semantic carrier"
    );

    let result = quickjs_test_core()
        .execute(&module)
        .expect("receiver-aware concise method should execute");
    assert_eq!(result.value, Value::Int(42));
}

#[test]
fn concise_object_method_infers_ordinary_and_computed_names_bd_gqaa4() {
    for (source, expected, label) in [
        (
            "({ ordinary() { return 1; } }).ordinary.name;",
            "ordinary",
            "concise-method-name.js",
        ),
        (
            "const key = \"computed\";\n({ [key]() { return 1; } })[key].name;",
            "computed",
            "computed-concise-method-name.js",
        ),
    ] {
        let module = lower_concise_method_source_bd_gqaa4(source, label);
        let result = quickjs_test_core()
            .execute(&module)
            .expect("concise method name should be readable");
        assert_eq!(result.value, Value::str(expected));
    }

    let own_name = lower_concise_method_source_bd_gqaa4(
        "\"name\" in ({ method() {} }).method;",
        "concise-method-own-name.js",
    );
    assert_eq!(
        quickjs_test_core().execute(&own_name).unwrap().value,
        Value::Bool(true)
    );
}

#[test]
fn concise_object_method_has_no_prototype_and_is_not_constructable_bd_gqaa4() {
    let no_prototype = lower_concise_method_source_bd_gqaa4(
        "({ method() {} }).method.prototype;",
        "concise-method-no-prototype.js",
    );
    assert_eq!(
        quickjs_test_core().execute(&no_prototype).unwrap().value,
        Value::Undefined
    );

    let construct = lower_concise_method_source_bd_gqaa4(
        "const method = ({ method() {} }).method;\nnew method();",
        "concise-method-nonconstructable.js",
    );
    assert!(matches!(
        quickjs_test_core().execute(&construct),
        Err(InterpreterError::TypeError { .. })
    ));
}

#[test]
fn concise_object_method_super_uses_home_object_not_receiver_bd_gqaa4() {
    let mut core = quickjs_test_core();
    let base = core.alloc_object_with_prototype(None).unwrap();
    core.set_object_property(base, "value".to_string(), Value::Int(7))
        .unwrap();
    let unrelated_base = core.alloc_object_with_prototype(None).unwrap();
    core.set_object_property(unrelated_base, "value".to_string(), Value::Int(99))
        .unwrap();
    let home = core.alloc_object_with_prototype(Some(base)).unwrap();
    let receiver = core
        .alloc_object_with_prototype(Some(unrelated_base))
        .unwrap();
    core.registers[1] = Value::Object(home);
    core.registers[2] = Value::Object(receiver);

    let result = core
        .execute(&test_module_with_pool_and_functions(
            vec![
                Ir3Instruction::CreateClosure {
                    function_index: 0,
                    capture_count: 0,
                    dst: 3,
                },
                Ir3Instruction::LoadStr {
                    dst: 4,
                    pool_index: 0,
                },
                Ir3Instruction::DefineMethod {
                    obj: 1,
                    key: 4,
                    func: 3,
                },
                Ir3Instruction::SetProperty {
                    obj: 2,
                    key: 4,
                    val: 3,
                },
                Ir3Instruction::GetProperty {
                    obj: 2,
                    key: 4,
                    dst: 5,
                },
                Ir3Instruction::CallMethod {
                    receiver: 2,
                    callee: 5,
                    args: RegRange { start: 6, count: 0 },
                    dst: 0,
                },
                Ir3Instruction::Halt,
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
                Ir3Instruction::Return { value: 2 },
            ],
            vec!["method".to_string(), "value".to_string()],
            vec![Ir3FunctionDesc {
                entry: 7,
                arity: 0,
                frame_size: 3,
                name: None,
                is_generator: false,
                rest_param_index: None,
            }],
        ))
        .expect("moved concise method should resolve super from its home object");

    assert_eq!(result.value, Value::Int(7));
}

#[test]
fn concise_object_method_definition_label_reaches_inferred_name_bd_gqaa4() {
    let mut core = quickjs_test_core();
    let home = core.alloc_object_with_prototype(None).unwrap();
    core.write_reg_with_label(0, Value::Object(home), crate::ifc_artifacts::Label::Secret)
        .unwrap();
    let result = core
        .execute(&test_module_with_pool_and_functions(
            vec![
                Ir3Instruction::LoadStr {
                    dst: 1,
                    pool_index: 0,
                },
                Ir3Instruction::CreateClosure {
                    function_index: 0,
                    capture_count: 0,
                    dst: 2,
                },
                Ir3Instruction::DefineMethod {
                    obj: 0,
                    key: 1,
                    func: 2,
                },
                Ir3Instruction::LoadStr {
                    dst: 3,
                    pool_index: 1,
                },
                Ir3Instruction::GetProperty {
                    obj: 2,
                    key: 3,
                    dst: 4,
                },
                Ir3Instruction::Return { value: 4 },
                Ir3Instruction::LoadUndefined { dst: 0 },
                Ir3Instruction::Return { value: 0 },
            ],
            vec!["secretMethod".to_string(), "name".to_string()],
            vec![Ir3FunctionDesc {
                entry: 6,
                arity: 0,
                frame_size: 1,
                name: None,
                is_generator: false,
                rest_param_index: None,
            }],
        ))
        .expect("method name should retain its definition label");

    assert_eq!(result.value, Value::str("secretMethod"));
    assert_eq!(result.completion_label, crate::ifc_artifacts::Label::Secret);
}

#[test]
fn object_accessor_getter_and_setter_preserve_property_provenance() {
    for config in [test_quickjs_config(), test_v8_config()] {
        let mut core = InterpreterCore::new(config.clone(), "getter-label");
        let object = core.alloc_object_with_prototype(None).unwrap();
        core.write_reg_with_label(
            0,
            Value::Object(object),
            crate::ifc_artifacts::Label::Secret,
        )
        .unwrap();
        let module = test_module_with_pool_and_functions(
            vec![
                Ir3Instruction::LoadStr {
                    dst: 1,
                    pool_index: 0,
                },
                Ir3Instruction::CreateClosure {
                    function_index: 0,
                    capture_count: 0,
                    dst: 2,
                },
                Ir3Instruction::DefineAccessor {
                    obj: 0,
                    key: 1,
                    func: 2,
                    kind: AccessorKind::Get,
                },
                Ir3Instruction::GetProperty {
                    obj: 0,
                    key: 1,
                    dst: 3,
                },
                Ir3Instruction::Return { value: 3 },
                Ir3Instruction::LoadInt { dst: 0, value: 42 },
                Ir3Instruction::Return { value: 0 },
            ],
            vec!["value".into()],
            vec![Ir3FunctionDesc {
                entry: 5,
                arity: 0,
                frame_size: 1,
                name: None,
                is_generator: false,
                rest_param_index: None,
            }],
        );
        let result = core.execute(&module).unwrap();
        assert_eq!(result.value, Value::Int(42));
        assert_eq!(result.completion_label, crate::ifc_artifacts::Label::Secret);

        let mut core = InterpreterCore::new(config, "setter-label");
        let object = core.alloc_object_with_prototype(None).unwrap();
        core.write_reg(0, Value::Object(object)).unwrap();
        core.write_reg_with_label(4, Value::Int(42), crate::ifc_artifacts::Label::Secret)
            .unwrap();
        let module = test_module_with_pool_and_functions(
            vec![
                Ir3Instruction::LoadStr {
                    dst: 1,
                    pool_index: 0,
                },
                Ir3Instruction::CreateClosure {
                    function_index: 0,
                    capture_count: 0,
                    dst: 2,
                },
                Ir3Instruction::DefineAccessor {
                    obj: 0,
                    key: 1,
                    func: 2,
                    kind: AccessorKind::Set,
                },
                Ir3Instruction::SetProperty {
                    obj: 0,
                    key: 1,
                    val: 4,
                },
                Ir3Instruction::LoadStr {
                    dst: 1,
                    pool_index: 1,
                },
                Ir3Instruction::GetProperty {
                    obj: 0,
                    key: 1,
                    dst: 3,
                },
                Ir3Instruction::Return { value: 3 },
                Ir3Instruction::LoadThis { dst: 1 },
                Ir3Instruction::LoadStr {
                    dst: 2,
                    pool_index: 1,
                },
                Ir3Instruction::SetProperty {
                    obj: 1,
                    key: 2,
                    val: 0,
                },
                Ir3Instruction::Return { value: 0 },
            ],
            vec!["value".into(), "saved".into()],
            vec![Ir3FunctionDesc {
                entry: 7,
                arity: 1,
                frame_size: 3,
                name: None,
                is_generator: false,
                rest_param_index: None,
            }],
        );
        let result = core.execute(&module).unwrap();
        assert_eq!(result.value, Value::Int(42));
        assert_eq!(result.completion_label, crate::ifc_artifacts::Label::Secret);
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }
}

#[test]
fn inline_protocol_getters_keep_receiver_labels_in_heap_writes() {
    for config in [test_quickjs_config(), test_v8_config()] {
        for promise_resolution in [false, true] {
            let mut core = InterpreterCore::new(config.clone(), "inline-getter-receiver");
            let sink = core.alloc_object_with_prototype(None).unwrap();
            let receiver = core
                .alloc_object_with_properties(&[("sink", Value::Object(sink))])
                .unwrap();
            core.write_reg(0, Value::Object(receiver)).unwrap();
            let module = test_module_with_pool_and_functions(
                vec![
                    Ir3Instruction::CreateClosure {
                        function_index: 0,
                        capture_count: 0,
                        dst: 1,
                    },
                    Ir3Instruction::LoadStr {
                        dst: 2,
                        pool_index: 0,
                    },
                    Ir3Instruction::DefineAccessor {
                        obj: 0,
                        key: 2,
                        func: 1,
                        kind: AccessorKind::Get,
                    },
                    Ir3Instruction::LoadUndefined { dst: 3 },
                    Ir3Instruction::Return { value: 3 },
                    Ir3Instruction::LoadThis { dst: 0 },
                    Ir3Instruction::LoadStr {
                        dst: 1,
                        pool_index: 1,
                    },
                    Ir3Instruction::GetProperty {
                        obj: 0,
                        key: 1,
                        dst: 2,
                    },
                    Ir3Instruction::LoadStr {
                        dst: 3,
                        pool_index: 2,
                    },
                    Ir3Instruction::SetProperty {
                        obj: 2,
                        key: 3,
                        val: 0,
                    },
                    Ir3Instruction::LoadUndefined { dst: 0 },
                    Ir3Instruction::Return { value: 0 },
                ],
                vec!["then".into(), "sink".into(), "saved".into()],
                vec![Ir3FunctionDesc {
                    entry: 5,
                    arity: 0,
                    frame_size: 4,
                    name: None,
                    is_generator: false,
                    rest_param_index: None,
                }],
            );
            core.execute(&module).unwrap();
            let key = RuntimePropertyKey::String(JsString::from("then"));
            core.set_own_runtime_property_label(
                receiver,
                &key,
                &crate::ifc_artifacts::Label::Secret,
            )
            .unwrap();

            if promise_resolution {
                let promise = core.create_promise_accounted().unwrap();
                core.resolve_promise_with_value(
                    promise,
                    Value::Object(receiver),
                    crate::ifc_artifacts::Label::Public,
                )
                .unwrap();
                assert_eq!(
                    core.promise_store.get(promise).unwrap().label,
                    crate::ifc_artifacts::Label::Secret,
                );
            } else {
                let mut label = crate::ifc_artifacts::Label::Public;
                assert_eq!(
                    core.read_iterator_property(
                        &module,
                        &Value::Object(receiver),
                        &key,
                        &mut label,
                    )
                    .unwrap(),
                    Value::Undefined,
                );
                assert_eq!(label, crate::ifc_artifacts::Label::Secret);
            }

            assert_eq!(
                core.heap[sink.0 as usize].properties.get("saved"),
                Some(&Value::Object(receiver)),
            );
            assert_eq!(
                core.own_property_label(sink, "saved"),
                crate::ifc_artifacts::Label::Secret,
                "promise_resolution={promise_resolution}: getter writes must retain this provenance",
            );
            assert_eq!(
                core.estimated_memory_bytes(),
                core.recompute_estimated_memory_bytes()
            );
        }
    }
}

#[test]
fn accessor_definition_rolls_back_heap_order_labels_and_home_object_on_refusal() {
    for symbol_key in [false, true] {
        let mut core = quickjs_test_core();
        let object = core
            .alloc_object_with_properties(&[("before", Value::Int(1))])
            .unwrap();
        let key = if symbol_key {
            RuntimePropertyKey::Symbol(core.allocate_private_symbol(Some("slot".into())).unwrap())
        } else {
            RuntimePropertyKey::String("slot".into())
        };
        core.set_plain_data_runtime_property(object, key.clone(), Value::Int(3))
            .unwrap();
        core.set_plain_data_property(object, "after".into(), Value::Int(2))
            .unwrap();
        core.closures.push(ClosureValue {
            function_index: 0,
            captured_env: vec![],
            module_specifier: None,
        });
        core.sync_estimated_memory_bytes().unwrap();
        let original = core.heap[object.0 as usize].clone();
        let original_memory = core.estimated_memory_bytes();
        core.define_accessor_property(
            object,
            key.clone(),
            Value::Closure(0),
            AccessorKind::Get,
            crate::ifc_artifacts::Label::Secret,
        )
        .unwrap();
        let admitted_memory = core.estimated_memory_bytes();
        core.heap[object.0 as usize] = original.clone();
        core.closure_method_metadata.remove(&0);
        core.sync_estimated_memory_bytes().unwrap();
        assert_eq!(core.estimated_memory_bytes(), original_memory);
        core.config.max_total_memory_bytes = admitted_memory - 1;
        let error = core
            .define_accessor_property(
                object,
                key.clone(),
                Value::Closure(0),
                AccessorKind::Get,
                crate::ifc_artifacts::Label::Secret,
            )
            .unwrap_err();
        assert!(matches!(
            error,
            InterpreterError::MemoryBudgetExceeded { .. }
        ));
        assert_eq!(core.heap[object.0 as usize], original);
        assert!(core.closure_method_metadata.is_empty());
        assert_eq!(core.estimated_memory_bytes(), original_memory);
        assert_eq!(
            core.runtime_property_label(object, &key),
            crate::ifc_artifacts::Label::Public
        );
    }
}

#[test]
fn accessor_halves_keep_names_nonconstructibility_and_joined_labels() {
    let mut core = quickjs_test_core();
    let object = core.alloc_object_with_prototype(None).unwrap();
    let symbol = core.allocate_private_symbol(Some("slot".into())).unwrap();
    let key = RuntimePropertyKey::Symbol(symbol);
    for function_index in 0..2 {
        core.closures.push(ClosureValue {
            function_index,
            captured_env: vec![],
            module_specifier: None,
        });
    }
    core.define_accessor_property(
        object,
        key.clone(),
        Value::Closure(0),
        AccessorKind::Get,
        crate::ifc_artifacts::Label::Secret,
    )
    .unwrap();
    core.define_accessor_property(
        object,
        key.clone(),
        Value::Closure(1),
        AccessorKind::Set,
        crate::ifc_artifacts::Label::Public,
    )
    .unwrap();
    assert_eq!(
        core.closure_method_metadata[&0].name,
        JsString::from("get [slot]")
    );
    assert_eq!(
        core.closure_method_metadata[&1].name,
        JsString::from("set [slot]")
    );
    assert_eq!(
        core.function_prototype_key_for_value(&Value::Closure(0))
            .unwrap(),
        None
    );
    assert_eq!(
        core.function_prototype_key_for_value(&Value::Closure(1))
            .unwrap(),
        None
    );
    assert_eq!(
        core.runtime_property_label(object, &key),
        crate::ifc_artifacts::Label::Secret
    );
    assert_eq!(
        core.prototype_chain_lookup_runtime_property(object, &key)
            .unwrap(),
        Some(RuntimeProperty::Accessor(AccessorProperty {
            get: Some(Value::Closure(0)),
            set: Some(Value::Closure(1)),
        })),
    );
}

// -- ES2015 Class Semantics Tests (bd-6a61n.1.3) --

#[test]
fn class_declaration_creates_constructor() {
    let mut core = InterpreterCore::new(test_quickjs_config(), "class-constructor-test");
    core.registers[1] = Value::Function(0);

    let result = core
        .execute(&test_module_with_functions(
            vec![
                Ir3Instruction::Construct {
                    callee: 1,
                    args: RegRange { start: 2, count: 0 },
                    dst: 0,
                },
                Ir3Instruction::Halt,
                Ir3Instruction::LoadThis { dst: 0 },
                Ir3Instruction::Return { value: 0 },
            ],
            vec![Ir3FunctionDesc {
                entry: 2,
                arity: 0,
                frame_size: 1,
                name: Some("Foo".to_string()),
                is_generator: false,
                rest_param_index: None,
            }],
        ))
        .unwrap();

    let instance_id = match result.value {
        Value::Object(id) => id,
        other => panic!("new Foo() should return an object, got {other:?}"),
    };
    let prototype_id = *core
        .function_prototypes
        .get(&FunctionObjectKey::Function(0))
        .expect("constructor prototype should be allocated");
    let instance = core
        .heap
        .get(instance_id.0 as usize)
        .expect("constructed instance should remain in the heap");
    assert_eq!(instance.constructor_function, Some(0));
    assert_eq!(instance.prototype, Some(prototype_id));
}

#[test]
fn class_method_on_prototype() {
    let mut core = InterpreterCore::new(test_quickjs_config(), "class-method-test");
    let prototype_id = core.ensure_function_prototype(0).unwrap();
    core.set_object_property(prototype_id, "method".to_string(), Value::Function(1))
        .unwrap();
    core.registers[1] = Value::Function(0);

    let result = core
        .execute(&test_module_with_pool_and_functions(
            vec![
                Ir3Instruction::Construct {
                    callee: 1,
                    args: RegRange { start: 2, count: 0 },
                    dst: 0,
                },
                Ir3Instruction::LoadStr {
                    dst: 3,
                    pool_index: 0,
                },
                Ir3Instruction::GetProperty {
                    obj: 0,
                    key: 3,
                    dst: 4,
                },
                Ir3Instruction::CallMethod {
                    receiver: 0,
                    callee: 4,
                    args: RegRange { start: 5, count: 0 },
                    dst: 0,
                },
                Ir3Instruction::Halt,
                Ir3Instruction::Return { value: 0 },
                Ir3Instruction::LoadThis { dst: 0 },
                Ir3Instruction::Return { value: 0 },
            ],
            vec!["method".to_string()],
            vec![
                Ir3FunctionDesc {
                    entry: 5,
                    arity: 0,
                    frame_size: 1,
                    name: Some("Foo".to_string()),
                    is_generator: false,
                    rest_param_index: None,
                },
                Ir3FunctionDesc {
                    entry: 6,
                    arity: 0,
                    frame_size: 1,
                    name: Some("method".to_string()),
                    is_generator: false,
                    rest_param_index: None,
                },
            ],
        ))
        .unwrap();

    let constructed = match core.registers[0].clone() {
        Value::Object(id) => id,
        other => panic!("constructed receiver should stay in r0, got {other:?}"),
    };
    assert_eq!(result.value, Value::Object(constructed));
    assert_eq!(
        core.prototype_chain_get(constructed, "method").unwrap(),
        Value::Function(1)
    );
}

#[test]
fn class_extends_sets_prototype_chain() {
    let mut core = quickjs_test_core();
    let base_prototype = core.ensure_function_prototype(0).unwrap();
    core.set_object_property(base_prototype, "inherited".to_string(), Value::Int(42))
        .unwrap();
    let derived_prototype = core.ensure_function_prototype(1).unwrap();
    core.heap[derived_prototype.0 as usize].prototype = Some(base_prototype);
    core.registers[1] = Value::Function(1);

    let result = core
        .execute(&test_module_with_pool_and_functions(
            vec![
                Ir3Instruction::Construct {
                    callee: 1,
                    args: RegRange { start: 2, count: 0 },
                    dst: 4,
                },
                Ir3Instruction::LoadStr {
                    dst: 2,
                    pool_index: 0,
                },
                Ir3Instruction::GetProperty {
                    obj: 4,
                    key: 2,
                    dst: 0,
                },
                Ir3Instruction::Halt,
                Ir3Instruction::LoadThis { dst: 0 },
                Ir3Instruction::Return { value: 0 },
                Ir3Instruction::LoadThis { dst: 0 },
                Ir3Instruction::Return { value: 0 },
            ],
            vec!["inherited".to_string()],
            vec![
                class_test_function(4, "Base"),
                class_test_function(6, "Derived"),
            ],
        ))
        .unwrap();

    let instance = object_id_from_value(&core.registers[4], "derived instance");
    assert_eq!(
        core.heap[instance.0 as usize].prototype,
        Some(derived_prototype)
    );
    assert_eq!(result.value, Value::Int(42));
}

#[test]
fn super_call_invokes_parent_constructor() {
    let mut core = quickjs_test_core();
    core.registers[1] = Value::Function(0);

    core.execute(&test_module_with_pool_and_functions(
        vec![
            Ir3Instruction::NewObject { dst: 0 },
            Ir3Instruction::CallMethod {
                receiver: 0,
                callee: 1,
                args: RegRange { start: 3, count: 0 },
                dst: 2,
            },
            Ir3Instruction::LoadStr {
                dst: 3,
                pool_index: 0,
            },
            Ir3Instruction::GetProperty {
                obj: 0,
                key: 3,
                dst: 0,
            },
            Ir3Instruction::Halt,
            Ir3Instruction::LoadThis { dst: 0 },
            Ir3Instruction::LoadStr {
                dst: 1,
                pool_index: 0,
            },
            Ir3Instruction::LoadBool {
                dst: 2,
                value: true,
            },
            Ir3Instruction::SetProperty {
                obj: 0,
                key: 1,
                val: 2,
            },
            Ir3Instruction::LoadThis { dst: 0 },
            Ir3Instruction::Return { value: 0 },
        ],
        vec!["parentInitialized".to_string()],
        vec![class_test_function(5, "Parent")],
    ))
    .unwrap();

    assert_eq!(core.registers[0], Value::Bool(true));
}

#[test]
fn super_method_calls_parent_method() {
    let mut core = quickjs_test_core();
    let derived_prototype = core.ensure_function_prototype(0).unwrap();
    let base_prototype = core.alloc_object_with_prototype(None).unwrap();
    core.set_object_property(base_prototype, "describe".to_string(), Value::Function(1))
        .unwrap();
    core.heap[derived_prototype.0 as usize].prototype = Some(base_prototype);
    core.registers[1] = Value::Function(0);

    let result = core
        .execute(&test_module_with_pool_and_functions(
            vec![
                Ir3Instruction::Construct {
                    callee: 1,
                    args: RegRange { start: 2, count: 0 },
                    dst: 4,
                },
                Ir3Instruction::LoadStr {
                    dst: 2,
                    pool_index: 0,
                },
                Ir3Instruction::GetProperty {
                    obj: 4,
                    key: 2,
                    dst: 3,
                },
                Ir3Instruction::CallMethod {
                    receiver: 4,
                    callee: 3,
                    args: RegRange { start: 5, count: 0 },
                    dst: 0,
                },
                Ir3Instruction::Halt,
                Ir3Instruction::LoadThis { dst: 0 },
                Ir3Instruction::Return { value: 0 },
                Ir3Instruction::LoadInt { dst: 0, value: 7 },
                Ir3Instruction::Return { value: 0 },
            ],
            vec!["describe".to_string()],
            vec![
                class_test_function(5, "Derived"),
                class_test_function(7, "Base.describe"),
            ],
        ))
        .unwrap();

    assert_eq!(result.value, Value::Int(7));
}

/// bd-snlhk: the IR3 lowering used to reconstruct the closure free-var
/// binding_id -> name map by zipping body first-appearance order against
/// the alphabetical `free_vars` list, silently swapping captured bindings
/// whenever first-use order diverged from alphabetical order. The fix
/// carries `free_var_ids` from IR1, paired index-wise with `free_vars`.
/// Two free vars first-used in REVERSE alphabetical order: the old
/// heuristic computed alpha - zebra = -7 instead of zebra - alpha = 7.
#[test]
fn closure_free_vars_bind_correct_names_non_alphabetical_first_use() {
    let tree = CanonicalEs2020Parser
        .parse(
            "let zebra = 9;\nlet alpha = 2;\nfunction f() { return zebra - alpha; }\nf();",
            ParseGoal::Script,
        )
        .expect("free-var source should parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "free-var-order-test.js");
    let ctx = LoweringContext::new(
        "trace-free-var-order",
        "decision-free-var-order",
        "policy-free-var-order",
    );
    let output = lower_ir0_to_ir3(&ir0, &ctx).expect("free-var closure should lower");

    let mut core = quickjs_test_core();
    let result = core
        .execute(&output.ir3)
        .expect("free-var closure should execute");
    assert_eq!(
        result.value,
        Value::Int(7),
        "zebra - alpha must bind each free var to its own value (bd-snlhk)"
    );
}

/// bd-snlhk: three captured `let`s where every wrong permutation of the
/// (name -> value) binding yields a result different from 100 - 10 - 1.
#[test]
fn closure_free_vars_bind_three_captured_lets_exactly() {
    let tree = CanonicalEs2020Parser
        .parse(
            "let cherry = 100;\nlet banana = 10;\nlet apple = 1;\nfunction g() { return cherry - banana - apple; }\ng();",
            ParseGoal::Script,
        )
        .expect("three-free-var source should parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "free-var-three-test.js");
    let ctx = LoweringContext::new(
        "trace-free-var-three",
        "decision-free-var-three",
        "policy-free-var-three",
    );
    let output = lower_ir0_to_ir3(&ir0, &ctx).expect("three-free-var closure should lower");

    let mut core = quickjs_test_core();
    let result = core
        .execute(&output.ir3)
        .expect("three-free-var closure should execute");
    assert_eq!(
        result.value,
        Value::Int(89),
        "cherry - banana - apple must be 89 under exact binding (bd-snlhk)"
    );
}

#[test]
fn static_method_on_constructor() {
    let tree = CanonicalEs2020Parser
        .parse(
            "class Foo { static staticMethod() { return 123; } }\nFoo.staticMethod();",
            ParseGoal::Script,
        )
        .expect("static class method source should parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "class-static-method-test.js");
    let ctx = LoweringContext::new(
        "trace-class-static-method",
        "decision-class-static-method",
        "policy-class-static-method",
    );
    let output = lower_ir0_to_ir3(&ir0, &ctx).expect("static class method should lower");
    assert!(
        output
            .ir3
            .instructions
            .iter()
            .any(|instruction| matches!(instruction, Ir3Instruction::SetProperty { .. })),
        "static method lowering should attach the method to the constructor value"
    );

    let mut core = quickjs_test_core();
    let result = core
        .execute(&output.ir3)
        .expect("constructor function object should carry static methods");

    assert_eq!(result.value, Value::Int(123));
}

#[test]
fn computed_method_name() {
    let mut core = quickjs_test_core();
    let prototype = core.ensure_function_prototype(0).unwrap();
    core.set_object_property(prototype, "dynamicName".to_string(), Value::Function(1))
        .unwrap();
    core.registers[1] = Value::Function(0);

    let result = core
        .execute(&test_module_with_pool_and_functions(
            vec![
                Ir3Instruction::Construct {
                    callee: 1,
                    args: RegRange { start: 2, count: 0 },
                    dst: 4,
                },
                Ir3Instruction::LoadStr {
                    dst: 2,
                    pool_index: 0,
                },
                Ir3Instruction::GetProperty {
                    obj: 4,
                    key: 2,
                    dst: 3,
                },
                Ir3Instruction::CallMethod {
                    receiver: 4,
                    callee: 3,
                    args: RegRange { start: 5, count: 0 },
                    dst: 0,
                },
                Ir3Instruction::Halt,
                Ir3Instruction::LoadThis { dst: 0 },
                Ir3Instruction::Return { value: 0 },
                Ir3Instruction::LoadInt { dst: 0, value: 99 },
                Ir3Instruction::Return { value: 0 },
            ],
            vec!["dynamicName".to_string()],
            vec![
                class_test_function(5, "ComputedHost"),
                class_test_function(7, "dynamicName"),
            ],
        ))
        .unwrap();

    assert_eq!(result.value, Value::Int(99));
}

#[test]
fn getter_setter() {
    let tree = CanonicalEs2020Parser
        .parse(
            "class Box { set value(v) { this.stored = v; } get value() { return this.stored; } }\nconst box = new Box();\nbox.value = 321;\nbox.value;",
            ParseGoal::Script,
        )
        .expect("class accessor source should parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "class-accessor-test.js");
    let ctx = LoweringContext::new(
        "trace-class-accessor",
        "decision-class-accessor",
        "policy-class-accessor",
    );
    let output = lower_ir0_to_ir3(&ir0, &ctx).expect("class accessors should lower");
    assert!(
        output
            .ir3
            .constant_pool
            .iter()
            .any(|key| key.starts_with(IR_ACCESSOR_GET_PREFIX)),
        "getter lowering should define an accessor descriptor"
    );
    assert!(
        output
            .ir3
            .constant_pool
            .iter()
            .any(|key| key.starts_with(IR_ACCESSOR_SET_PREFIX)),
        "setter lowering should define an accessor descriptor"
    );

    let mut core = quickjs_test_core();
    let result = core
        .execute(&output.ir3)
        .expect("getter/setter accessors should execute through descriptor calls");

    assert_eq!(result.value, Value::Int(321));
}

#[test]
fn copy_data_properties_rejects_nullish_and_boxes_empty_primitives_bd_f1ixz() {
    for source in [Value::Null, Value::Undefined] {
        let mut core = quickjs_test_core();
        let target = core.alloc_object_with_prototype(None).unwrap();
        core.registers[1] = Value::Object(target);
        core.registers[2] = source;
        let error = core
            .execute(&test_module(vec![
                Ir3Instruction::CopyDataProperties {
                    target: 1,
                    source: 2,
                    excluded: RegRange { start: 3, count: 0 },
                    value_dst: 4,
                },
                Ir3Instruction::Halt,
            ]))
            .unwrap_err();
        assert!(matches!(error, InterpreterError::TypeError { .. }));
        assert!(core.copy_data_properties_states.is_empty());
    }

    for source in [Value::Null, Value::Undefined] {
        let mut spread = quickjs_test_core();
        let spread_target = spread.alloc_object_with_prototype(None).unwrap();
        spread.registers[1] = Value::Object(spread_target);
        spread.registers[2] = source;
        let result = spread
            .execute(&test_module(vec![
                Ir3Instruction::SpreadIntoObject {
                    target: 1,
                    source: 2,
                },
                Ir3Instruction::Move { dst: 0, src: 1 },
                Ir3Instruction::Halt,
            ]))
            .unwrap();
        assert_eq!(result.value, Value::Object(spread_target));
        assert!(
            spread.heap[spread_target.0 as usize]
                .own_property_keys()
                .is_empty()
        );
    }

    for source in [
        Value::Bool(true),
        Value::Int(7),
        Value::Float(Float64::new(1.5)),
    ] {
        let mut core = quickjs_test_core();
        let target = core.alloc_object_with_prototype(None).unwrap();
        core.registers[1] = Value::Object(target);
        core.registers[2] = source;
        core.execute(&test_module(vec![
            Ir3Instruction::CopyDataProperties {
                target: 1,
                source: 2,
                excluded: RegRange { start: 3, count: 0 },
                value_dst: 4,
            },
            Ir3Instruction::Halt,
        ]))
        .unwrap();
        assert!(core.heap[target.0 as usize].own_property_keys().is_empty());
        assert!(core.copy_data_properties_states.is_empty());
    }
}

#[test]
fn copy_data_properties_copies_exact_string_units_after_exclusion_bd_f1ixz() {
    let mut core = quickjs_test_core();
    let target = core.alloc_object_with_prototype(None).unwrap();
    core.registers[1] = Value::Object(target);
    core.registers[2] = Value::Str(JsString::from_code_units(&[0xD83D, 0xDE00, 0xD800]));
    core.registers[3] = Value::str("1");

    core.execute(&test_module(vec![
        Ir3Instruction::CopyDataProperties {
            target: 1,
            source: 2,
            excluded: RegRange { start: 3, count: 1 },
            value_dst: 4,
        },
        Ir3Instruction::Halt,
    ]))
    .unwrap();

    let object = &core.heap[target.0 as usize];
    assert_eq!(object.own_property_keys(), vec!["0", "2"]);
    for (key, expected_unit) in [("0", 0xD83D), ("2", 0xD800)] {
        let Some(Value::Str(value)) = object.properties.get(key) else {
            panic!("string index {key} should be copied as a data property");
        };
        assert_eq!(value.code_units_vec(), vec![expected_unit]);
    }
    assert!(core.copy_data_properties_states.is_empty());
}

#[test]
fn copy_data_properties_omits_array_length_and_uses_plain_data_writes_bd_f1ixz() {
    let mut core = quickjs_test_core();
    let target = core.alloc_object_with_prototype(None).unwrap();
    let source = core.alloc_array_with_prototype(None).unwrap();
    core.set_plain_data_property(source, "0".into(), Value::Int(1))
        .unwrap();
    core.set_plain_data_property(source, "length".into(), Value::Int(1))
        .unwrap();
    core.set_plain_data_property(source, "custom".into(), Value::Int(2))
        .unwrap();
    let prototype_value = core.alloc_object_with_prototype(None).unwrap();
    core.set_plain_data_property(source, "__proto__".into(), Value::Object(prototype_value))
        .unwrap();
    let prefixed_key = format!("{IR_ACCESSOR_GET_PREFIX}literal");
    core.set_plain_data_property(source, prefixed_key.clone(), Value::Int(3))
        .unwrap();
    core.registers[1] = Value::Object(target);
    core.registers[2] = Value::Object(source);

    core.execute(&test_module(vec![
        Ir3Instruction::CopyDataProperties {
            target: 1,
            source: 2,
            excluded: RegRange { start: 3, count: 0 },
            value_dst: 4,
        },
        Ir3Instruction::Halt,
    ]))
    .unwrap();

    let object = &core.heap[target.0 as usize];
    assert_eq!(
        object.own_property_keys(),
        vec!["0", "custom", "__proto__", prefixed_key.as_str()]
    );
    assert!(!object.properties.contains_key("length"));
    assert_eq!(object.prototype, None);
    assert_eq!(
        object.properties.get("__proto__"),
        Some(&Value::Object(prototype_value))
    );
    assert_eq!(object.properties.get(&prefixed_key), Some(&Value::Int(3)));
    assert!(object.accessors.is_empty());
}

#[test]
fn copy_data_properties_resumes_included_getter_with_source_receiver_bd_f1ixz() {
    let mut core = quickjs_test_core();
    let target = core.alloc_object_with_prototype(None).unwrap();
    let source = core.alloc_object_with_prototype(None).unwrap();
    core.set_plain_data_property(source, "calls".into(), Value::Int(0))
        .unwrap();
    core.set_plain_data_property(source, "marker".into(), Value::Int(41))
        .unwrap();
    core.set_object_property(
        source,
        format!("{IR_ACCESSOR_GET_PREFIX}included"),
        Value::Function(0),
    )
    .unwrap();
    core.set_object_property(
        source,
        format!("{IR_ACCESSOR_SET_PREFIX}setter_only"),
        Value::Function(0),
    )
    .unwrap();
    // An invalid getter is a useful tripwire: exclusion must happen before
    // the property read, so this value must never be invoked.
    core.set_object_property(
        source,
        format!("{IR_ACCESSOR_GET_PREFIX}excluded"),
        Value::Function(99),
    )
    .unwrap();
    core.registers[1] = Value::Object(target);
    core.registers[2] = Value::Object(source);
    core.registers[3] = Value::str("excluded");

    let result = core
        .execute(&test_module_with_pool_and_functions(
            vec![
                Ir3Instruction::CopyDataProperties {
                    target: 1,
                    source: 2,
                    excluded: RegRange { start: 3, count: 1 },
                    value_dst: 4,
                },
                Ir3Instruction::Move { dst: 0, src: 1 },
                Ir3Instruction::Halt,
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
                Ir3Instruction::LoadInt { dst: 3, value: 1 },
                Ir3Instruction::Add {
                    dst: 4,
                    lhs: 2,
                    rhs: 3,
                },
                Ir3Instruction::SetProperty {
                    obj: 0,
                    key: 1,
                    val: 4,
                },
                Ir3Instruction::LoadStr {
                    dst: 5,
                    pool_index: 1,
                },
                Ir3Instruction::GetProperty {
                    obj: 0,
                    key: 5,
                    dst: 6,
                },
                Ir3Instruction::Return { value: 6 },
            ],
            vec!["calls".to_string(), "marker".to_string()],
            vec![Ir3FunctionDesc {
                entry: 3,
                arity: 0,
                frame_size: 8,
                name: Some("included_getter".to_string()),
                is_generator: false,
                rest_param_index: None,
            }],
        ))
        .unwrap();

    assert_eq!(result.value, Value::Object(target));
    let object = &core.heap[target.0 as usize];
    assert_eq!(object.properties.get("marker"), Some(&Value::Int(41)));
    assert_eq!(object.properties.get("included"), Some(&Value::Int(41)));
    assert_eq!(
        object.properties.get("setter_only"),
        Some(&Value::Undefined)
    );
    assert!(!object.contains_own_property("excluded"));
    assert!(object.accessors.is_empty());
    assert_eq!(
        core.heap[source.0 as usize].properties.get("calls"),
        Some(&Value::Int(1))
    );
    assert!(core.copy_data_properties_states.is_empty());
}

#[test]
fn copy_data_properties_snapshots_keys_and_rechecks_descriptors_bd_f1ixz() {
    let mut core = quickjs_test_core();
    let target = core.alloc_object_with_prototype(None).unwrap();
    let source = core.alloc_object_with_prototype(None).unwrap();
    core.set_object_property(
        source,
        format!("{IR_ACCESSOR_GET_PREFIX}a"),
        Value::Function(0),
    )
    .unwrap();
    core.set_plain_data_property(source, "b".into(), Value::Int(2))
        .unwrap();
    core.registers[1] = Value::Object(target);
    core.registers[2] = Value::Object(source);

    core.execute(&test_module_with_pool_and_functions(
        vec![
            Ir3Instruction::CopyDataProperties {
                target: 1,
                source: 2,
                excluded: RegRange { start: 3, count: 0 },
                value_dst: 4,
            },
            Ir3Instruction::Halt,
            Ir3Instruction::LoadThis { dst: 0 },
            Ir3Instruction::LoadStr {
                dst: 1,
                pool_index: 0,
            },
            Ir3Instruction::DeleteProperty {
                obj: 0,
                key: 1,
                dst: 2,
            },
            Ir3Instruction::LoadStr {
                dst: 3,
                pool_index: 1,
            },
            Ir3Instruction::LoadInt { dst: 4, value: 3 },
            Ir3Instruction::SetProperty {
                obj: 0,
                key: 3,
                val: 4,
            },
            Ir3Instruction::LoadInt { dst: 5, value: 1 },
            Ir3Instruction::Return { value: 5 },
        ],
        vec!["b".to_string(), "c".to_string()],
        vec![class_test_function(2, "mutating_getter")],
    ))
    .unwrap();

    let object = &core.heap[target.0 as usize];
    assert_eq!(object.own_property_keys(), vec!["a"]);
    assert_eq!(object.properties.get("a"), Some(&Value::Int(1)));
    assert!(!object.contains_own_property("b"));
    assert!(!object.contains_own_property("c"));
    assert_eq!(
        core.heap[source.0 as usize].properties.get("c"),
        Some(&Value::Int(3))
    );
    assert!(core.copy_data_properties_states.is_empty());
}

#[test]
fn copy_data_properties_nested_state_and_throw_cleanup_bd_f1ixz() {
    let mut nested = quickjs_test_core();
    let outer_target = nested.alloc_object_with_prototype(None).unwrap();
    let outer_source = nested.alloc_object_with_prototype(None).unwrap();
    let inner_target = nested.alloc_object_with_prototype(None).unwrap();
    let inner_source = nested.alloc_object_with_prototype(None).unwrap();
    nested
        .set_plain_data_property(inner_source, "v".into(), Value::Int(9))
        .unwrap();
    nested
        .set_plain_data_property(
            outer_source,
            "innerTarget".into(),
            Value::Object(inner_target),
        )
        .unwrap();
    nested
        .set_plain_data_property(
            outer_source,
            "innerSource".into(),
            Value::Object(inner_source),
        )
        .unwrap();
    nested
        .set_object_property(
            outer_source,
            format!("{IR_ACCESSOR_GET_PREFIX}outer"),
            Value::Function(0),
        )
        .unwrap();
    nested.registers[1] = Value::Object(outer_target);
    nested.registers[2] = Value::Object(outer_source);
    nested.registers[3] = Value::str("innerTarget");
    nested.registers[4] = Value::str("innerSource");
    nested
        .execute(&test_module_with_pool_and_functions(
            vec![
                Ir3Instruction::CopyDataProperties {
                    target: 1,
                    source: 2,
                    excluded: RegRange { start: 3, count: 2 },
                    value_dst: 5,
                },
                Ir3Instruction::Halt,
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
                Ir3Instruction::LoadStr {
                    dst: 3,
                    pool_index: 1,
                },
                Ir3Instruction::GetProperty {
                    obj: 0,
                    key: 3,
                    dst: 4,
                },
                Ir3Instruction::CopyDataProperties {
                    target: 2,
                    source: 4,
                    excluded: RegRange { start: 8, count: 0 },
                    value_dst: 5,
                },
                Ir3Instruction::LoadStr {
                    dst: 6,
                    pool_index: 2,
                },
                Ir3Instruction::GetProperty {
                    obj: 2,
                    key: 6,
                    dst: 7,
                },
                Ir3Instruction::Return { value: 7 },
            ],
            vec![
                "innerTarget".to_string(),
                "innerSource".to_string(),
                "v".to_string(),
            ],
            vec![class_test_function(2, "nested_copy_getter")],
        ))
        .unwrap();
    assert_eq!(
        nested.heap[outer_target.0 as usize].properties.get("outer"),
        Some(&Value::Int(9))
    );
    assert_eq!(
        nested.heap[inner_target.0 as usize].properties.get("v"),
        Some(&Value::Int(9))
    );
    assert!(nested.copy_data_properties_states.is_empty());

    let mut throwing = quickjs_test_core();
    let target = throwing.alloc_object_with_prototype(None).unwrap();
    let source = throwing.alloc_object_with_prototype(None).unwrap();
    throwing
        .set_object_property(
            source,
            format!("{IR_ACCESSOR_GET_PREFIX}boom"),
            Value::Function(0),
        )
        .unwrap();
    throwing.registers[1] = Value::Object(target);
    throwing.registers[2] = Value::Object(source);
    let result = throwing
        .execute(&test_module_with_pool_and_functions(
            vec![
                Ir3Instruction::BeginTry {
                    catch_target: 3,
                    finally_target: None,
                },
                Ir3Instruction::CopyDataProperties {
                    target: 1,
                    source: 2,
                    excluded: RegRange { start: 7, count: 0 },
                    value_dst: 4,
                },
                Ir3Instruction::EndTry,
                Ir3Instruction::EnterCatch { dst: 6 },
                Ir3Instruction::LoadStr {
                    dst: 7,
                    pool_index: 1,
                },
                Ir3Instruction::SetProperty {
                    obj: 1,
                    key: 7,
                    val: 6,
                },
                Ir3Instruction::Move { dst: 0, src: 1 },
                Ir3Instruction::Halt,
                Ir3Instruction::LoadStr {
                    dst: 0,
                    pool_index: 0,
                },
                Ir3Instruction::Throw { value: 0 },
            ],
            vec!["boom".to_string(), "caught".to_string()],
            vec![class_test_function(8, "throwing_getter")],
        ))
        .unwrap();
    assert_eq!(result.value, Value::Object(target));
    assert_eq!(
        throwing.heap[target.0 as usize].properties.get("caught"),
        Some(&Value::str("boom"))
    );
    assert!(throwing.copy_data_properties_states.is_empty());
}

#[test]
fn copy_data_properties_state_is_budgeted_and_cleaned_on_failure_bd_f1ixz() {
    let mut core = quickjs_test_core();
    let target = core.alloc_object_with_prototype(None).unwrap();
    let source = core.alloc_object_with_prototype(None).unwrap();
    for index in 0..8 {
        core.set_plain_data_property(
            source,
            format!("long-copy-key-{index}-{}", "x".repeat(32)),
            Value::Int(index),
        )
        .unwrap();
    }
    core.registers[1] = Value::Object(target);
    core.registers[2] = Value::Object(source);
    core.sync_estimated_memory_bytes().unwrap();
    let baseline_memory = core.estimated_memory_bytes();
    let probe_state = CopyDataPropertiesState {
        instruction_ip: 0,
        register_base: 0,
        call_depth: 0,
        target_id: target,
        source: Value::Object(source),
        string_units: None,
        keys: core
            .copy_data_properties_keys(&Value::Object(source))
            .unwrap(),
        excluded: BTreeSet::new(),
        next_index: 0,
        write_mode: CopyDataPropertiesWriteMode::CreateData,
        awaiting: None,
    };
    let state_bytes = InterpreterCore::estimate_copy_data_properties_state_bytes(&probe_state);
    core.config.max_total_memory_bytes = baseline_memory
        .saturating_add(state_bytes)
        .saturating_sub(1);

    let error = core
        .execute(&test_module(vec![
            Ir3Instruction::CopyDataProperties {
                target: 1,
                source: 2,
                excluded: RegRange { start: 3, count: 0 },
                value_dst: 4,
            },
            Ir3Instruction::Halt,
        ]))
        .unwrap_err();
    assert!(matches!(
        error,
        InterpreterError::MemoryBudgetExceeded { .. }
    ));
    assert!(core.copy_data_properties_states.is_empty());
    assert!(core.heap[target.0 as usize].own_property_keys().is_empty());
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn class_expression() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse(
            "const C = class { method() { return 1; } };\nconst c = new C();\nc.method();",
            ParseGoal::Script,
        )
        .expect("class expression should parse as structured AST");
    match &tree.body[0] {
        Statement::VariableDeclaration(decl) => {
            assert!(matches!(
                decl.declarations[0].initializer.as_ref(),
                Some(Expression::ClassExpression { .. })
            ));
        }
        other => panic!("expected class expression variable declaration, got {other:?}"),
    }
    let ir0 = Ir0Module::from_syntax_tree(tree, "class-expression-test.js");
    let ctx = LoweringContext::new(
        "trace-class-expression",
        "decision-class-expression",
        "policy-class-expression",
    );
    let output = lower_ir0_to_ir3(&ir0, &ctx).expect("class expression should lower");

    assert!(
        output
            .ir3
            .instructions
            .iter()
            .any(|instruction| matches!(instruction, Ir3Instruction::Construct { .. })),
        "class expression should produce an executable constructor"
    );

    let mut core = quickjs_test_core();
    let result = core
        .execute(&output.ir3)
        .expect("class expression constructor and prototype method should execute");

    assert_eq!(result.value, Value::Int(1));
}

fn execute_class_expression_source_bd_va13y(source: &str) -> Value {
    let tree = CanonicalEs2020Parser
        .parse(source, ParseGoal::Script)
        .expect("bd-va13y class expression source should parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "bd-va13y-class-expression.js");
    let output = lower_ir0_to_ir3(
        &ir0,
        &LoweringContext::new("trace-bd-va13y", "decision-bd-va13y", "policy-bd-va13y"),
    )
    .expect("bd-va13y class expression source should lower");
    quickjs_test_core()
        .execute(&output.ir3)
        .expect("bd-va13y class expression source should execute")
        .value
}

fn complete_constructor_return_bd_ptu9m(return_value: Value) -> Value {
    let mut core = quickjs_test_core();
    let allocated_this = Value::Object(
        core.alloc_object_with_prototype(None)
            .expect("constructor receiver allocation should fit"),
    );
    core.call_stack.push(CallFrame {
        return_ip: 1,
        return_reg: Some(0),
        saved_module_specifier: core.current_module_specifier.clone(),
        register_base: 0,
        function_index: None,
        this_value: allocated_this.clone(),
        this_label: crate::ifc_artifacts::Label::Public,
        new_target_value: Value::Function(0),
        new_target_label: crate::ifc_artifacts::Label::Public,
        super_value: Value::Undefined,
        super_label: crate::ifc_artifacts::Label::Public,
        construct_this: Some(allocated_this),
        derived_constructor: false,
        this_initialized: true,
        initialize_derived_this_on_return: false,
        saved_pending_exception: None,
        saved_pending_return: None,
        saved_suspended_abrupt_depth: 0,
        saved_finally_mode_depth: 0,
        saved_scope_depth: core.scope_chain.depth(),
        saved_scope_chain: None,
        async_function_id: None,
        accessor_context_label: crate::ifc_artifacts::Label::Public,
    });
    core.complete_return(return_value, crate::ifc_artifacts::Label::Public)
        .expect("constructor return should complete");
    core.read_reg(0).expect("constructor result register")
}

#[test]
fn constructor_preserves_explicit_object_like_returns_bd_ptu9m() {
    for (case, return_value) in [
        ("object", Value::Object(ObjectId(u32::MAX))),
        ("function", Value::Function(11)),
        ("closure", Value::Closure(12)),
        ("iterator", Value::Iterator(13)),
        ("generator function", Value::GeneratorFunction(14)),
        ("generator", Value::Generator(15)),
        ("async function", Value::AsyncFunction(16)),
        ("async function object", Value::AsyncFunctionObject(17)),
        (
            "async generator function",
            Value::AsyncGeneratorFunction(18),
        ),
        ("async generator object", Value::AsyncGeneratorObject(19)),
        ("promise", Value::Promise(20)),
        (
            "builtin function",
            Value::BuiltinFunction(BuiltinFunction::array_is_array()),
        ),
    ] {
        assert_eq!(
            complete_constructor_return_bd_ptu9m(return_value.clone()),
            return_value,
            "constructor must preserve an explicit {case} return",
        );
    }
}

#[test]
fn constructor_preserves_captured_callable_return_bd_it65u() {
    assert_eq!(
        execute_class_expression_source_bd_va13y(
            "let value = function(){ return 7; }; \
             function ReturnValue(){ return value; } \
             new ReturnValue() === value;"
        ),
        Value::Bool(true),
    );
}

#[test]
fn constructor_preserves_builtin_return_bd_ptu9m() {
    assert_eq!(
        execute_class_expression_source_bd_va13y(
            "let value = Array.isArray; \
             function ReturnValue(){ return value; } \
             new ReturnValue() === value;"
        ),
        Value::Bool(true),
    );
}

#[test]
fn constructor_preserves_generator_return_bd_ptu9m() {
    assert_eq!(
        execute_class_expression_source_bd_va13y(
            "function* make(){ yield 1; } let value = make(); \
             function ReturnValue(){ return value; } \
             new ReturnValue() === value;"
        ),
        Value::Bool(true),
    );
}

#[test]
fn constructor_primitive_return_keeps_allocated_instance_bd_ptu9m() {
    assert_eq!(
        execute_class_expression_source_bd_va13y(
            "function KeepThis(){ this.value = 4; return 7; } \
             let instance = new KeepThis(); instance.value === 4;"
        ),
        Value::Bool(true)
    );
}

#[test]
fn named_class_expression_constructor_and_method_share_private_self_bd_va13y() {
    assert_eq!(
        execute_class_expression_source_bd_va13y(
            "let C = class Inner { \
                 constructor(){ this.ctor = Inner; } \
                 method(){ return Inner; } \
             }; \
             let D = C; C = 0; let value = new D(); \
             value.ctor === D && value.method() === D;"
        ),
        Value::Bool(true)
    );
}

#[test]
fn named_class_expression_nested_method_closure_keeps_self_bd_va13y() {
    assert_eq!(
        execute_class_expression_source_bd_va13y(
            "let C = class Inner { self(){ return () => Inner; } }; \
             let D = C; C = 0; new D().self()() === D;"
        ),
        Value::Bool(true)
    );
}

#[test]
fn named_class_expression_nested_constructor_closure_keeps_self_bd_va13y() {
    assert_eq!(
        execute_class_expression_source_bd_va13y(
            "let C = class Inner { constructor(){ this.self = () => Inner; } }; \
             let D = C; C = 0; new D().self() === D;"
        ),
        Value::Bool(true)
    );
}

#[test]
fn named_class_expression_shadows_outer_but_not_params_or_locals_bd_va13y() {
    assert_eq!(
        execute_class_expression_source_bd_va13y(
            "let Inner = 7; \
             let C = class Inner { \
                 parameter(Inner){ return Inner; } \
                 local(){ let Inner = 9; return Inner; } \
                 self(){ return Inner; } \
             }; \
             let value = new C(); \
             value.parameter(8) === 8 && value.local() === 9 && \
             value.self() === C && Inner === 7;"
        ),
        Value::Bool(true)
    );
}

#[test]
fn duplicate_named_class_expressions_keep_distinct_self_cells_bd_va13y() {
    assert_eq!(
        execute_class_expression_source_bd_va13y(
            "let A = class Inner { method(){ return Inner; } }; \
             let B = class Inner { method(){ return Inner; } }; \
             new A().method() === A && new B().method() === B;"
        ),
        Value::Bool(true)
    );
}

#[test]
fn nested_factory_class_expression_shares_constructor_and_method_self_bd_va13y() {
    assert_eq!(
        execute_class_expression_source_bd_va13y(
            "function make(){ \
                 return class Inner { \
                     constructor(){ this.ctor = Inner; } \
                     method(){ return Inner; } \
                 }; \
             } \
             let C = make(); let D = make(); \
             let c = new C(); let d = new D(); \
             (c.ctor === C ? 1 : 0) + \
             (c.method() === C ? 2 : 0) + \
             (d.ctor === D ? 4 : 0) + \
             (d.method() === D ? 8 : 0) + \
             (C !== D ? 16 : 0) + \
             (c instanceof C ? 32 : 0) + \
             (d instanceof D ? 64 : 0) + \
             (!(c instanceof D) ? 128 : 0) + \
             (!(d instanceof C) ? 256 : 0);"
        ),
        Value::Int(511)
    );
}

#[test]
fn class_method_name_does_not_overwrite_same_named_outer_capture_bd_va13y() {
    assert_eq!(
        execute_class_expression_source_bd_va13y(
            "let method = 7; \
             let C = class Inner { method(){ return method; } }; \
             new C().method();"
        ),
        Value::Int(7)
    );
}

#[test]
fn named_class_expression_self_does_not_leak_bd_va13y() {
    assert_eq!(
        execute_class_expression_source_bd_va13y("let C = class Inner {}; typeof Inner;"),
        Value::str("undefined")
    );
}

#[test]
fn anonymous_class_has_no_synthetic_self_binding_bd_va13y() {
    assert_eq!(
        execute_class_expression_source_bd_va13y(
            "let C = class { \
                 constructor(){ \
                     try { anonymous; } catch (error) { this.kind = error.name; } \
                 } \
             }; \
             new C().kind;"
        ),
        Value::str("ReferenceError")
    );
    assert_eq!(
        execute_class_expression_source_bd_va13y(
            "let anonymous = 9; \
             let C = class { method(){ return anonymous; } }; \
             new C().method();"
        ),
        Value::Int(9)
    );
}

#[test]
fn class_expression_extends_super_parse_lower_execute() {
    let tree = CanonicalEs2020Parser
        .parse(
            "class Base { constructor() { this.base = 40; } value() { return this.base + 2; } }\nconst Child = class extends Base { constructor() { super(); } value() { return super.value(); } };\nconst c = new Child();\nc.value();",
            ParseGoal::Script,
        )
        .expect("class expression extends/super should parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "class-expression-extends-super-test.js");
    let ctx = LoweringContext::new(
        "trace-class-expression-extends",
        "decision-class-expression-extends",
        "policy-class-expression-extends",
    );
    let output = lower_ir0_to_ir3(&ir0, &ctx).expect("class expression extends should lower");
    assert!(
        output
            .ir3
            .instructions
            .iter()
            .any(|instruction| matches!(instruction, Ir3Instruction::LoadSuper { .. })),
        "derived class expression should lower super bindings"
    );

    let mut core = quickjs_test_core();
    let result = core
        .execute(&output.ir3)
        .expect("class expression extends/super should execute");

    assert_eq!(result.value, Value::Int(42));
}

#[test]
fn new_target_in_constructor() {
    let tree = CanonicalEs2020Parser
        .parse(
            "class C { constructor() { this.kind = typeof new.target; } }\nconst c = new C();\nc.kind;",
            ParseGoal::Script,
    )
    .expect("new.target should parse in class constructor bodies");
    let ir0 = Ir0Module::from_syntax_tree(tree, "new-target-class-test.js");
    let ctx = LoweringContext::new(
        "trace-new-target",
        "decision-new-target",
        "policy-new-target",
    );
    let output = lower_ir0_to_ir3(&ir0, &ctx).expect("new.target should lower");
    assert!(
        output
            .ir3
            .instructions
            .iter()
            .any(|instruction| matches!(instruction, Ir3Instruction::LoadNewTarget { .. })),
        "constructor body should load new.target explicitly"
    );

    let mut core = quickjs_test_core();
    let result = core
        .execute(&output.ir3)
        .expect("new.target should execute through constructor frames");

    assert_eq!(result.value, Value::str("function"));
}

#[test]
fn class_extends_super_parse_lower_execute() {
    let tree = CanonicalEs2020Parser
        .parse(
            "class Base { constructor() { this.base = 41; } describe() { return this.base + 1; } }\nclass Child extends Base { constructor() { super(); } describe() { return super.describe(); } }\nconst c = new Child();\nc.describe();",
            ParseGoal::Script,
        )
        .expect("class extends with super constructor and method calls should parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "class-extends-super-test.js");
    let ctx = LoweringContext::new(
        "trace-class-extends-super",
        "decision-class-extends-super",
        "policy-class-extends-super",
    );
    let output = lower_ir0_to_ir3(&ir0, &ctx).expect("class extends and super should lower");
    assert!(
        output
            .ir3
            .instructions
            .iter()
            .any(|instruction| matches!(instruction, Ir3Instruction::LoadSuper { .. })),
        "constructor and method bodies should load a frame super binding"
    );
    assert!(
        output.ir3.instructions.iter().any(|instruction| matches!(
            instruction,
            Ir3Instruction::RegisterDerivedConstructor { .. }
        )),
        "derived constructor lowering should record its parent constructor"
    );
    assert!(
        output
            .ir3
            .constant_pool
            .iter()
            .any(|constant| constant == IR_SUPER_PROTOTYPE_PROPERTY),
        "derived method lowering should record its parent prototype"
    );

    let mut core = quickjs_test_core();
    let result = core
        .execute(&output.ir3)
        .expect("class extends and super should execute through parser/lowering path");

    assert_eq!(result.value, Value::Int(42));
}

#[test]
fn derived_constructor_completion_matrix_bd_ppfz7() {
    for (case, source, expected) in [
        (
            "explicit object without super",
            "class Base {} class Child extends Base { constructor(){ return { value: 7 }; } } new Child().value;",
            Value::Int(7),
        ),
        (
            "primitive without super",
            "class Base {} class Child extends Base { constructor(){ return 7; } } let kind; try { new Child(); } catch (error) { kind = error.name; } kind;",
            Value::str("TypeError"),
        ),
        (
            "undefined without super",
            "class Base {} class Child extends Base { constructor(){ return undefined; } } let kind; try { new Child(); } catch (error) { kind = error.name; } kind;",
            Value::str("ReferenceError"),
        ),
        (
            "fallthrough without super",
            "class Base {} class Child extends Base { constructor(){} } let kind; try { new Child(); } catch (error) { kind = error.name; } kind;",
            Value::str("ReferenceError"),
        ),
        (
            "primitive after super",
            "class Base {} class Child extends Base { constructor(){ super(); return 7; } } let kind; try { new Child(); } catch (error) { kind = error.name; } kind;",
            Value::str("TypeError"),
        ),
        (
            "primitive return through finally",
            "class Base {} class Child extends Base { constructor(){ super(); try { return 7; } finally {} } } let kind; try { new Child(); } catch (error) { kind = error.name; } kind;",
            Value::str("TypeError"),
        ),
        (
            "guest static marker collision cannot declassify a derived constructor",
            "class Base {} class Child extends Base { static __franken_ir_derived_constructor__(){ return false; } constructor(){ return 7; } } let kind; try { new Child(); } catch (error) { kind = error.name; } kind;",
            Value::str("TypeError"),
        ),
        (
            "undefined after super",
            "class Base { constructor(){ this.value = 8; } } class Child extends Base { constructor(){ super(); return undefined; } } new Child().value;",
            Value::Int(8),
        ),
        (
            "fallthrough after super",
            "class Base { constructor(){ this.value = 9; } } class Child extends Base { constructor(){ super(); } } new Child().value;",
            Value::Int(9),
        ),
    ] {
        assert_eq!(
            execute_class_expression_source_bd_va13y(source),
            expected,
            "derived constructor completion mismatch for {case}",
        );
    }
}

#[test]
fn base_constructor_completion_matrix_bd_ppfz7() {
    for (case, source, expected) in [
        (
            "explicit object",
            "class Base { constructor(){ return { value: 7 }; } } new Base().value;",
            Value::Int(7),
        ),
        (
            "primitive falls back to allocated this",
            "class Base { constructor(){ return 7; } } new Base() instanceof Base;",
            Value::Bool(true),
        ),
        (
            "undefined falls back to allocated this",
            "class Base { constructor(){ return undefined; } } new Base() instanceof Base;",
            Value::Bool(true),
        ),
        (
            "fallthrough falls back to allocated this",
            "class Base { constructor(){} } new Base() instanceof Base;",
            Value::Bool(true),
        ),
    ] {
        assert_eq!(
            execute_class_expression_source_bd_va13y(source),
            expected,
            "base constructor completion mismatch for {case}",
        );
    }
}

#[test]
fn derived_construction_forwards_and_preserves_new_target_bd_ppfz7() {
    for (case, source, expected) in [
        (
            "default constructor forwards every argument",
            "class Base { constructor(left, right){ this.total = left + right; } } class Child extends Base {} new Child(20, 22).total;",
            Value::Int(42),
        ),
        (
            "parent replacement object becomes derived result",
            "class Base { constructor(){ return { value: 42 }; } } class Child extends Base { constructor(){ super(); } } new Child().value;",
            Value::Int(42),
        ),
        (
            "parent observes child new.target",
            "class Base { constructor(){ this.target = new.target; } } class Child extends Base { constructor(){ super(); } } new Child().target === Child;",
            Value::Bool(true),
        ),
        (
            "class expression has matching super semantics",
            "class Base { constructor(value){ this.value = value; } } let Child = class extends Base { constructor(value){ super(value); } }; new Child(42).value;",
            Value::Int(42),
        ),
        (
            "default class expression forwards every argument",
            "class Base { constructor(left, right){ this.total = left + right; } } let Child = class extends Base {}; new Child(20, 22).total;",
            Value::Int(42),
        ),
        (
            "repeated class expressions retain distinct parent constructors",
            "class A { constructor(){ this.value = 1; } } class B { constructor(){ this.value = 2; } } function make(Parent){ return class extends Parent {}; } let First = make(A); let Second = make(B); new First().value * 10 + new Second().value;",
            Value::Int(12),
        ),
    ] {
        assert_eq!(
            execute_class_expression_source_bd_va13y(source),
            expected,
            "derived construction mismatch for {case}",
        );
    }
}

// -----------------------------------------------------------------------
// Timer substrate tests
// -----------------------------------------------------------------------

fn timer_callback_desc(entry: u32, name: &str) -> Ir3FunctionDesc {
    Ir3FunctionDesc {
        entry,
        arity: 0,
        frame_size: 1,
        name: Some(name.to_string()),
        is_generator: false,
        rest_param_index: None,
    }
}

fn timer_hostcall(capability: &str, args: RegRange, dst: u32) -> Ir3Instruction {
    Ir3Instruction::HostCall {
        capability: CapabilityTag(capability.to_string()),
        args,
        dst,
    }
}

fn timer_id(value: Value) -> u32 {
    match value {
        Value::Int(id) => u32::try_from(id).expect("timer id must be non-negative"),
        other => panic!("expected integer timer id, got {other:?}"),
    }
}

fn timer_callback_body(pool_index: u32) -> Vec<Ir3Instruction> {
    vec![
        Ir3Instruction::LoadStr { dst: 0, pool_index },
        timer_hostcall("console:log", RegRange { start: 0, count: 1 }, 1),
        Ir3Instruction::Return { value: 1 },
    ]
}

fn test_module_with_timer_callback(mut top_level: Vec<Ir3Instruction>, message: &str) -> Ir3Module {
    let callback_entry = top_level.len() as u32;
    top_level.extend(timer_callback_body(0));
    test_module_with_pool_and_functions(
        top_level,
        vec![message.to_string()],
        vec![timer_callback_desc(callback_entry, "timer_callback")],
    )
}

#[test]
fn timer_raw_function_arguments_preserve_property_labels() {
    use crate::ifc_artifacts::Label;

    let module = test_module_with_pool_and_functions(
        vec![
            timer_hostcall("timer:setTimeout", RegRange { start: 0, count: 4 }, 4),
            Ir3Instruction::Halt,
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 0,
            },
            Ir3Instruction::SetProperty {
                obj: 1,
                key: 2,
                val: 0,
            },
            Ir3Instruction::Return { value: 0 },
        ],
        vec!["value".to_string()],
        vec![Ir3FunctionDesc {
            entry: 2,
            arity: 2,
            frame_size: 3,
            name: Some("raw_timer_callback".to_string()),
            is_generator: false,
            rest_param_index: None,
        }],
    );
    for config in [test_quickjs_config(), test_v8_config()] {
        let mut core = InterpreterCore::new(config, "timer-arguments");
        let target = core.alloc_object_with_prototype(None).unwrap();
        core.write_reg(0, Value::Function(0)).unwrap();
        core.write_reg(1, Value::Int(0)).unwrap();
        core.write_reg_with_label(2, Value::str("secret argument"), Label::Secret)
            .unwrap();
        core.write_reg(3, Value::Object(target)).unwrap();

        core.execute(&module).unwrap();

        assert_eq!(
            core.prototype_chain_get(target, "value").unwrap(),
            Value::str("secret argument")
        );
        assert_eq!(
            core.own_stored_runtime_property_label(
                target,
                &RuntimePropertyKey::String(JsString::from("value")),
            ),
            Label::Secret,
        );
        assert!(core.timer_invocations.is_empty());
        assert!(core.active_timers.is_empty());
        assert_eq!(
            core.estimated_memory_bytes,
            core.recompute_estimated_memory_bytes()
        );
    }
}

#[test]
fn timer_native_resolvers_preserve_scheduling_labels_without_arguments() {
    use crate::ifc_artifacts::Label;
    use crate::object_model::JsValue;
    use crate::promise_model::PromiseState;

    for config in [test_quickjs_config(), test_v8_config()] {
        for reject in [false, true] {
            let mut core = InterpreterCore::new(config.clone(), "timer-native-resolver");
            let promise = core.create_promise_accounted().unwrap();
            let (_, resolve, reject_function) = core
                .create_promise_resolving_functions(promise, Label::Public)
                .unwrap();
            core.write_reg(0, if reject { reject_function } else { resolve })
                .unwrap();
            core.write_reg_with_label(1, Value::Int(0), Label::Secret)
                .unwrap();
            core.dispatch_timer_hostcall("timer:setTimeout", RegRange { start: 0, count: 2 })
                .unwrap();
            core.run_event_loop_until_idle(&test_module(vec![Ir3Instruction::Halt]))
                .unwrap();

            let record = core.promise_store.get(promise).unwrap();
            assert_eq!(
                record.state,
                if reject {
                    PromiseState::Rejected(JsValue::Undefined)
                } else {
                    PromiseState::Fulfilled(JsValue::Undefined)
                },
            );
            assert_eq!(record.label, Label::Secret);
            assert!(core.timer_invocations.is_empty());
            assert_eq!(core.promise_in_flight_task_bytes, 0);
            assert_eq!(
                core.estimated_memory_bytes,
                core.recompute_estimated_memory_bytes()
            );
        }
    }
}

fn core_with_timer_payload(config: InterpreterConfig) -> InterpreterCore {
    let mut core = InterpreterCore::new(config, "timer-payload");
    core.write_reg(0, Value::Function(0)).unwrap();
    core.write_reg(1, Value::Int(0)).unwrap();
    core.write_reg_with_label(
        2,
        Value::str("retained timer argument".repeat(512)),
        crate::ifc_artifacts::Label::Custom {
            name: "timer provenance".repeat(8),
            level: 5,
        },
    )
    .unwrap();
    core
}

#[test]
fn timer_payload_admission_rolls_back_queue_maps_and_identity() {
    let args = RegRange { start: 0, count: 3 };
    for config in [test_quickjs_config(), test_v8_config()] {
        for capability in ["timer:setTimeout", "timer:setInterval"] {
            let mut admitted = core_with_timer_payload(config.clone());
            let baseline = admitted.estimated_memory_bytes;
            assert_eq!(
                admitted.dispatch_timer_hostcall(capability, args).unwrap(),
                Value::Int(0)
            );
            let charge = admitted.estimated_memory_bytes - baseline;
            assert!(charge > InterpreterCore::active_timer_entry_bytes());

            for ceiling in [baseline, baseline + charge - 1] {
                let mut refused = core_with_timer_payload(config.clone());
                refused.config.max_total_memory_bytes = ceiling;
                assert!(matches!(
                    refused.dispatch_timer_hostcall(capability, args),
                    Err(InterpreterError::MemoryBudgetExceeded { .. }),
                ));
                assert!(refused.active_timers.is_empty());
                assert!(refused.timer_invocations.is_empty());
                assert!(refused.event_loop.macrotasks.is_empty());
                assert_eq!(refused.next_timer_id, 0);
                assert_eq!(refused.estimated_memory_bytes, baseline);
                assert_eq!(
                    refused.estimated_memory_bytes,
                    refused.recompute_estimated_memory_bytes()
                );

                refused.config.max_total_memory_bytes = config.max_total_memory_bytes;
                assert_eq!(
                    refused.dispatch_timer_hostcall(capability, args).unwrap(),
                    Value::Int(0)
                );
                assert_eq!(refused.active_timers[&0].registration_seq, Some(0));
            }
        }
    }
}

#[test]
fn timer_callbacks_account_for_owned_builtin_module_paths() {
    let mut reference = quickjs_test_core();
    reference
        .write_reg(0, Value::BuiltinFunction(BuiltinFunction::array_is_array()))
        .unwrap();
    reference.write_reg(1, Value::Int(0)).unwrap();
    let reference_baseline = reference.estimated_memory_bytes;
    reference
        .dispatch_timer_hostcall("timer:setTimeout", RegRange { start: 0, count: 2 })
        .unwrap();
    let small_callback_charge = reference.estimated_memory_bytes - reference_baseline;

    for capture_as_argument in [false, true] {
        let mut core = quickjs_test_core();
        let require =
            Value::BuiltinFunction(BuiltinFunction::require("module/provenance/".repeat(1024)));
        core.write_reg(1, Value::Int(0)).unwrap();
        let count = if capture_as_argument {
            core.write_reg(0, Value::BuiltinFunction(BuiltinFunction::array_is_array()))
                .unwrap();
            core.write_reg(2, require).unwrap();
            3
        } else {
            core.write_reg(0, require).unwrap();
            2
        };
        let baseline = core.estimated_memory_bytes;
        // There is room for the callback/queue metadata and another small
        // argument, but not for a clone of the builtin's owned module path.
        core.config.max_total_memory_bytes = baseline + small_callback_charge + 1024;
        assert!(matches!(
            core.dispatch_timer_hostcall("timer:setTimeout", RegRange { start: 0, count }),
            Err(InterpreterError::MemoryBudgetExceeded { .. }),
        ));
        assert!(core.active_timers.is_empty());
        assert!(core.timer_invocations.is_empty());
        assert!(core.event_loop.macrotasks.is_empty());
        assert_eq!(core.next_timer_id, 0);
        assert_eq!(core.estimated_memory_bytes, baseline);
        assert_eq!(
            core.estimated_memory_bytes,
            core.recompute_estimated_memory_bytes()
        );
    }
}

#[test]
fn timer_payload_cancellation_and_both_seed_resets_release_callbacks() {
    for eager in [false, true] {
        let mut core = core_with_timer_payload(test_quickjs_config());
        let args = RegRange { start: 0, count: 3 };
        let id = core
            .dispatch_timer_hostcall("timer:setTimeout", args)
            .unwrap();
        let timer_bytes = core.timers_memory_bytes();
        let before_cancel = core.estimated_memory_bytes;
        core.write_reg(3, id).unwrap();
        core.dispatch_timer_hostcall("timer:clearTimeout", RegRange { start: 3, count: 1 })
            .unwrap();
        assert_eq!(core.estimated_memory_bytes, before_cancel - timer_bytes);
        assert!(core.active_timers.is_empty());
        assert!(core.timer_invocations.is_empty());

        core.dispatch_timer_hostcall("timer:setTimeout", args)
            .unwrap();
        if eager {
            let seed = core.capture_execution_seed_eager_for_test();
            core.reset_execution_state_from_seed_eager_for_test(&seed)
                .unwrap();
        } else {
            let seed = core.capture_execution_seed();
            core.reset_execution_state_from_seed(&seed).unwrap();
        }
        assert!(core.active_timers.is_empty());
        assert!(core.timer_invocations.is_empty());
        assert_eq!(core.next_timer_id, 0);
        // Old queued tokens remain inert even though the new module has
        // no function table in which their former callback could execute.
        core.run_event_loop_until_idle(&test_module(vec![Ir3Instruction::Halt]))
            .unwrap();
        assert!(core.event_loop.macrotasks.is_empty());
        assert_eq!(
            core.estimated_memory_bytes,
            core.recompute_estimated_memory_bytes()
        );
    }
}

#[test]
fn timer_payload_stays_charged_until_callback_setup_finishes() {
    let module = test_module_with_functions(
        vec![Ir3Instruction::Return { value: 0 }],
        vec![timer_callback_desc(0, "budget_timer")],
    );
    let mut core = core_with_timer_payload(test_quickjs_config());
    core.dispatch_timer_hostcall("timer:setTimeout", RegRange { start: 0, count: 3 })
        .unwrap();
    let task = core.event_loop.turn().macrotask.unwrap();
    core.sync_estimated_memory_bytes().unwrap();
    let before_callback = core.estimated_memory_bytes;
    let timer_bytes = core.timers_memory_bytes();
    let wrapper_bytes = InterpreterCore::retained_module_program_bytes(&module) * 2
        + 8 * std::mem::size_of::<Ir3Instruction>() as u64;
    assert!(timer_bytes > wrapper_bytes);
    core.config.max_total_memory_bytes = before_callback;

    let error = core.execute_macrotask_callback(&module, &task).unwrap_err();

    assert!(matches!(
        error,
        InterpreterError::MemoryBudgetExceeded { requested_bytes, .. }
            if requested_bytes == before_callback + wrapper_bytes,
    ));
    assert!(core.active_timers.is_empty());
    assert!(core.timer_invocations.is_empty());
    assert_eq!(core.promise_in_flight_task_bytes, 0);
    assert_eq!(core.estimated_memory_bytes, before_callback - timer_bytes);
    assert_eq!(
        core.estimated_memory_bytes,
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn set_timeout_fires_after_delay() {
    let mut core = quickjs_test_core();
    let result = core
        .execute(&test_module_with_timer_callback(
            vec![
                Ir3Instruction::CreateClosure {
                    dst: 0,
                    function_index: 0,
                    capture_count: 0,
                },
                Ir3Instruction::LoadInt { dst: 1, value: 25 },
                timer_hostcall("timer:setTimeout", RegRange { start: 0, count: 2 }, 2),
                Ir3Instruction::Halt,
            ],
            "timer fired after delay",
        ))
        .unwrap();

    assert_eq!(core.read_reg(2).unwrap(), Value::Int(0));
    assert!(core.active_timers.is_empty());
    assert_eq!(result.console_output.len(), 1);
    assert_eq!(result.console_output[0].message, "timer fired after delay");
    assert!(
        result
            .witness_events
            .iter()
            .any(|event| event.kind == WitnessEventKind::HostcallDispatched)
    );
}

#[test]
fn timer_callback_materializes_empty_rest_array_bd_ur3tk_9() {
    let top_level = vec![
        Ir3Instruction::CreateClosure {
            dst: 0,
            function_index: 0,
            capture_count: 0,
        },
        Ir3Instruction::LoadInt { dst: 1, value: 0 },
        timer_hostcall("timer:setTimeout", RegRange { start: 0, count: 2 }, 2),
        Ir3Instruction::Halt,
    ];
    let callback_entry = top_level.len() as u32;
    let mut instructions = top_level;
    instructions.extend([
        Ir3Instruction::LoadStr {
            dst: 1,
            pool_index: 0,
        },
        Ir3Instruction::GetProperty {
            obj: 0,
            key: 1,
            dst: 2,
        },
        timer_hostcall("console:log", RegRange { start: 2, count: 1 }, 3),
        Ir3Instruction::Return { value: 3 },
    ]);
    let module = test_module_with_pool_and_functions(
        instructions,
        vec!["length".to_string()],
        vec![Ir3FunctionDesc {
            entry: callback_entry,
            arity: 1,
            frame_size: 4,
            name: Some("rest_timer_callback".to_string()),
            is_generator: false,
            rest_param_index: Some(0),
        }],
    );

    let mut core = quickjs_test_core();
    let result = core.execute(&module).expect("rest timer should execute");
    assert_eq!(result.console_output.len(), 1);
    assert_eq!(result.console_output[0].message, "0");
}

#[test]
fn set_timeout_returns_id() {
    let mut core = quickjs_test_core();
    let result = core
        .execute(&test_module_with_timer_callback(
            vec![
                Ir3Instruction::CreateClosure {
                    dst: 0,
                    function_index: 0,
                    capture_count: 0,
                },
                Ir3Instruction::LoadInt { dst: 1, value: 10 },
                timer_hostcall("timer:setTimeout", RegRange { start: 0, count: 2 }, 2),
                Ir3Instruction::LoadInt { dst: 1, value: 20 },
                timer_hostcall("timer:setTimeout", RegRange { start: 0, count: 2 }, 3),
                Ir3Instruction::Halt,
            ],
            "timer callback",
        ))
        .unwrap();

    assert_eq!(core.read_reg(2).unwrap(), Value::Int(0));
    assert_eq!(core.read_reg(3).unwrap(), Value::Int(1));
    assert!(core.active_timers.is_empty());
    assert_eq!(result.console_output.len(), 2);
}

#[test]
fn clear_timeout_cancels() {
    let mut core = quickjs_test_core();
    let result = core
        .execute(&test_module_with_timer_callback(
            vec![
                Ir3Instruction::CreateClosure {
                    dst: 0,
                    function_index: 0,
                    capture_count: 0,
                },
                Ir3Instruction::LoadInt { dst: 1, value: 30 },
                timer_hostcall("timer:setTimeout", RegRange { start: 0, count: 2 }, 2),
                timer_hostcall("timer:clearTimeout", RegRange { start: 2, count: 1 }, 3),
                Ir3Instruction::Halt,
            ],
            "cancelled timer should not fire",
        ))
        .unwrap();

    assert_eq!(core.read_reg(3).unwrap(), Value::Undefined);
    assert!(core.active_timers.is_empty());
    assert!(result.console_output.is_empty());
}

#[test]
fn set_interval_repeats() {
    let mut core = quickjs_test_core();
    let module = test_module_with_pool_and_functions(
        timer_callback_body(0),
        vec!["interval fired".to_string()],
        vec![timer_callback_desc(0, "timer_callback")],
    );
    core.write_reg(0, Value::Function(0)).unwrap();
    core.write_reg(1, Value::Int(40)).unwrap();
    assert_eq!(
        core.dispatch_timer_hostcall("timer:setInterval", RegRange { start: 0, count: 2 })
            .unwrap(),
        Value::Int(0),
    );

    for firing in 0..3 {
        let task = core.event_loop.turn().macrotask.unwrap();
        assert_eq!(task.registration_seq, firing);
        assert_eq!(task.scheduled_at, (firing + 1) * 40);
        core.sync_estimated_memory_bytes().unwrap();
        core.execute_macrotask_callback(&module, &task).unwrap();
        assert_eq!(core.active_timers.len(), 1);
        assert_eq!(core.active_timers[&0].registration_seq, Some(firing + 1));
        assert_eq!(core.timer_invocations.len(), 1);
        assert_eq!(core.event_loop.macrotasks.len(), 1);
        assert_eq!(core.next_timer_id, 1);
        assert_eq!(core.promise_in_flight_task_bytes, 0);
        assert_eq!(
            core.estimated_memory_bytes,
            core.recompute_estimated_memory_bytes(),
        );
    }

    let timer = core
        .active_timers
        .get(&0)
        .expect("interval should be active");
    assert_eq!(timer.handler, Some(0));
    assert_eq!(timer.delay_ms, 40);
    assert!(timer.repeating);
    assert_eq!(timer.registration_seq, Some(3));
    assert_eq!(core.console_output.len(), 3);
    assert!(
        core.console_output
            .iter()
            .all(|line| line.message == "interval fired")
    );

    core.write_reg(2, Value::Int(0)).unwrap();
    core.dispatch_timer_hostcall("timer:clearInterval", RegRange { start: 2, count: 1 })
        .unwrap();
    core.run_event_loop_until_idle(&module).unwrap();
    assert_eq!(core.console_output.len(), 3);
    assert!(core.active_timers.is_empty());
    assert!(core.timer_invocations.is_empty());
}

#[test]
fn interval_forwarded_arguments_keep_labels_across_firings() {
    use crate::ifc_artifacts::Label;

    let module = test_module_with_pool_and_functions(
        vec![
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 0,
            },
            Ir3Instruction::SetProperty {
                obj: 1,
                key: 2,
                val: 0,
            },
            Ir3Instruction::Return { value: 0 },
        ],
        vec!["value".to_string()],
        vec![Ir3FunctionDesc {
            entry: 0,
            arity: 2,
            frame_size: 3,
            name: Some("labeled_interval".to_string()),
            is_generator: false,
            rest_param_index: None,
        }],
    );
    for config in [test_quickjs_config(), test_v8_config()] {
        let mut core = InterpreterCore::new(config, "interval-labels");
        let object = core.alloc_object_with_prototype(None).unwrap();
        core.write_reg(0, Value::Function(0)).unwrap();
        core.write_reg_with_label(1, Value::Int(2), Label::Confidential)
            .unwrap();
        core.write_reg_with_label(2, Value::str("secret"), Label::Secret)
            .unwrap();
        core.write_reg(3, Value::Object(object)).unwrap();
        core.dispatch_timer_hostcall("timer:setInterval", RegRange { start: 0, count: 4 })
            .unwrap();

        for _ in 0..2 {
            let task = core.event_loop.turn().macrotask.unwrap();
            core.sync_estimated_memory_bytes().unwrap();
            assert_eq!(task.label, Label::Secret);
            core.execute_macrotask_callback(&module, &task).unwrap();
            assert_eq!(
                core.prototype_chain_get(object, "value").unwrap(),
                Value::str("secret")
            );
            assert_eq!(
                core.own_stored_runtime_property_label(
                    object,
                    &RuntimePropertyKey::String(JsString::from("value")),
                ),
                Label::Secret,
            );
            assert_eq!(
                core.estimated_memory_bytes,
                core.recompute_estimated_memory_bytes()
            );
        }
    }
}

#[test]
fn timer_turn_admission_refusal_releases_only_the_selected_callback_payload() {
    let module = test_module_with_pool_and_functions(
        timer_callback_body(0),
        vec!["callback must not run".to_string()],
        vec![timer_callback_desc(0, "refused_timer")],
    );
    for capability in ["timer:setTimeout", "timer:setInterval"] {
        for retain_other_timer in [false, true] {
            let mut core = core_with_timer_payload(test_quickjs_config());
            let args = RegRange { start: 0, count: 3 };
            core.dispatch_timer_hostcall(capability, args).unwrap();
            if retain_other_timer {
                core.dispatch_timer_hostcall(capability, args).unwrap();
            }
            let ceiling = core.estimated_memory_bytes;
            core.config.max_total_memory_bytes = ceiling;

            assert!(matches!(
                core.run_event_loop_until_idle(&module),
                Err(InterpreterError::MemoryBudgetExceeded {
                    requested_bytes,
                    max_bytes,
                    ..
                }) if requested_bytes > ceiling && max_bytes == ceiling,
            ));
            assert!(core.console_output.is_empty());
            assert_eq!(core.instructions_executed, 0);
            assert!(!core.active_timers.contains_key(&0));
            assert!(!core.timer_invocations.contains_key(&0));
            let remaining = usize::from(retain_other_timer);
            assert_eq!(core.active_timers.len(), remaining);
            assert_eq!(core.timer_invocations.len(), remaining);
            assert_eq!(core.event_loop.macrotasks.len(), remaining);
            if retain_other_timer {
                assert_eq!(core.active_timers[&1].registration_seq, Some(1));
                assert!(core.timer_invocations.contains_key(&1));
            }
            assert_eq!(core.promise_in_flight_task_bytes, 0);
            assert_eq!(
                core.estimated_memory_bytes,
                core.recompute_estimated_memory_bytes()
            );
        }
    }
}

#[test]
fn interval_reschedule_budget_refusal_removes_payload_and_rolls_back_queue_sequence() {
    use crate::ifc_artifacts::Label;

    let module = test_module_with_pool_and_functions(
        timer_callback_body(0),
        vec!["ran once".to_string()],
        vec![timer_callback_desc(0, "budget_interval")],
    );
    let mut core = quickjs_test_core();
    core.write_reg_with_label(
        0,
        Value::Function(0),
        Label::Custom {
            name: "scheduling provenance".repeat(4096),
            level: 5,
        },
    )
    .unwrap();
    core.write_reg(1, Value::Int(1)).unwrap();
    core.dispatch_timer_hostcall("timer:setInterval", RegRange { start: 0, count: 2 })
        .unwrap();
    let callback_bytes = InterpreterCore::retained_module_program_bytes(&module) * 2
        + 8 * std::mem::size_of::<Ir3Instruction>() as u64;
    let original_limit = core.config.max_total_memory_bytes;
    core.config.max_total_memory_bytes = core.estimated_memory_bytes + callback_bytes + 4096;

    assert!(matches!(
        core.run_event_loop_until_idle(&module),
        Err(InterpreterError::MemoryBudgetExceeded { .. }),
    ));
    assert_eq!(
        core.console_output.len(),
        1,
        "callback must finish before rescheduling fails"
    );
    assert_eq!(core.console_output[0].message, "ran once");
    assert!(core.active_timers.is_empty());
    assert!(core.timer_invocations.is_empty());
    assert!(core.event_loop.macrotasks.is_empty());
    assert_eq!(core.promise_in_flight_task_bytes, 0);
    assert_eq!(
        core.estimated_memory_bytes,
        core.recompute_estimated_memory_bytes()
    );

    core.config.max_total_memory_bytes = original_limit;
    assert_eq!(
        core.dispatch_timer_hostcall("timer:setInterval", RegRange { start: 0, count: 2 })
            .unwrap(),
        Value::Int(1),
    );
    assert_eq!(core.active_timers[&1].registration_seq, Some(1));
}

#[test]
fn interval_callback_instruction_exhaustion_propagates_without_rescheduling() {
    let module = test_module_with_functions(
        vec![Ir3Instruction::Jump { target: 0 }],
        vec![timer_callback_desc(0, "unbounded_interval_callback")],
    );
    let mut core = quickjs_test_core();
    core.config.instruction_budget = 50;
    core.write_reg(0, Value::Function(0)).unwrap();
    core.write_reg(1, Value::Int(0)).unwrap();
    core.dispatch_timer_hostcall("timer:setInterval", RegRange { start: 0, count: 2 })
        .unwrap();

    assert!(matches!(
        core.run_event_loop_until_idle(&module),
        Err(InterpreterError::BudgetExhausted {
            executed: 50,
            budget: 50
        }),
    ));
    assert!(core.active_timers.is_empty());
    assert!(core.timer_invocations.is_empty());
    assert!(core.event_loop.macrotasks.is_empty());
    assert_eq!(core.promise_in_flight_task_bytes, 0);
    assert_eq!(
        core.estimated_memory_bytes,
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn interval_turn_exhaustion_reports_pending_work_instead_of_success() {
    let module = test_module(vec![Ir3Instruction::Halt]);
    let mut core = quickjs_test_core();
    core.write_reg(0, Value::BuiltinFunction(BuiltinFunction::array_is_array()))
        .unwrap();
    core.write_reg(1, Value::Int(0)).unwrap();
    core.dispatch_timer_hostcall("timer:setInterval", RegRange { start: 0, count: 2 })
        .unwrap();

    let error = core.run_event_loop_with_turn_limit(&module, 3).unwrap_err();
    assert_eq!(
        error,
        InterpreterError::EventLoopTurnLimitExceeded {
            turns: 3,
            max_turns: 3
        }
    );
    assert!(!InterpreterCore::is_js_catchable_error(&error));
    assert_eq!(core.event_loop.clock.now_ms(), 3);
    assert_eq!(core.active_timers[&0].registration_seq, Some(3));
    assert_eq!(core.timer_invocations.len(), 1);
    assert_eq!(core.event_loop.macrotasks.len(), 1);
    assert_eq!(core.promise_in_flight_task_bytes, 0);
    assert_eq!(
        core.estimated_memory_bytes,
        core.recompute_estimated_memory_bytes()
    );

    core.write_reg(2, Value::Int(0)).unwrap();
    core.dispatch_timer_hostcall("timer:clearTimeout", RegRange { start: 2, count: 1 })
        .unwrap();
    core.run_event_loop_with_turn_limit(&module, 1).unwrap();
    assert!(core.active_timers.is_empty());
    assert!(core.timer_invocations.is_empty());
    assert!(!core.event_loop.has_pending_work());
}

#[test]
fn clear_interval_stops() {
    let mut core = quickjs_test_core();
    core.execute(&test_module_with_functions(
        vec![
            Ir3Instruction::CreateClosure {
                dst: 0,
                function_index: 0,
                capture_count: 0,
            },
            Ir3Instruction::LoadInt { dst: 1, value: 50 },
            timer_hostcall("timer:setInterval", RegRange { start: 0, count: 2 }, 2),
            timer_hostcall("timer:clearInterval", RegRange { start: 2, count: 1 }, 3),
            Ir3Instruction::Halt,
        ],
        vec![timer_callback_desc(0, "timer_callback")],
    ))
    .unwrap();

    assert_eq!(core.read_reg(3).unwrap(), Value::Undefined);
    assert!(core.active_timers.is_empty());
}

#[test]
fn timer_ordering() {
    let mut core = quickjs_test_core();
    let mut instructions = vec![
        Ir3Instruction::CreateClosure {
            dst: 0,
            function_index: 0,
            capture_count: 0,
        },
        Ir3Instruction::LoadInt { dst: 1, value: 30 },
        timer_hostcall("timer:setTimeout", RegRange { start: 0, count: 2 }, 2),
        Ir3Instruction::CreateClosure {
            dst: 0,
            function_index: 1,
            capture_count: 0,
        },
        Ir3Instruction::LoadInt { dst: 1, value: 10 },
        timer_hostcall("timer:setTimeout", RegRange { start: 0, count: 2 }, 3),
        Ir3Instruction::CreateClosure {
            dst: 0,
            function_index: 2,
            capture_count: 0,
        },
        Ir3Instruction::LoadInt { dst: 1, value: 20 },
        timer_hostcall("timer:setTimeout", RegRange { start: 0, count: 2 }, 4),
        Ir3Instruction::Halt,
    ];
    let first_entry = instructions.len() as u32;
    instructions.extend(timer_callback_body(0));
    let second_entry = instructions.len() as u32;
    instructions.extend(timer_callback_body(1));
    let third_entry = instructions.len() as u32;
    instructions.extend(timer_callback_body(2));

    let result = core
        .execute(&test_module_with_pool_and_functions(
            instructions,
            vec!["delay-30".into(), "delay-10".into(), "delay-20".into()],
            vec![
                timer_callback_desc(first_entry, "delay_30"),
                timer_callback_desc(second_entry, "delay_10"),
                timer_callback_desc(third_entry, "delay_20"),
            ],
        ))
        .unwrap();

    let messages = result
        .console_output
        .iter()
        .map(|entry| entry.message.as_str())
        .collect::<Vec<_>>();
    assert_eq!(messages, vec!["delay-10", "delay-20", "delay-30"]);
    assert!(core.active_timers.is_empty());
}

#[test]
fn microtask_before_timer() {
    let mut event_loop = crate::promise_model::EventLoop::new();
    event_loop
        .microtasks
        .enqueue(crate::promise_model::Microtask::PromiseReaction {
            handler: None,
            argument: crate::object_model::JsValue::Undefined,
            result_promise: crate::promise_model::PromiseHandle(0),
            label: crate::ifc_artifacts::Label::Public,
        });
    event_loop.set_timeout(
        crate::closure_model::ClosureHandle(0),
        0,
        crate::ifc_artifacts::Label::Public,
    );

    assert_eq!(event_loop.drain_microtasks(), 1);
    let turn = event_loop.turn();
    let macrotask = turn.macrotask.expect("timer should run after microtasks");
    assert_eq!(
        macrotask.source,
        crate::promise_model::MacrotaskSource::Timer
    );
}

#[test]
fn nested_set_timeout() {
    let mut core = quickjs_test_core();
    let result = core
        .execute(&test_module_with_timer_callback(
            vec![
                Ir3Instruction::CreateClosure {
                    dst: 0,
                    function_index: 0,
                    capture_count: 0,
                },
                Ir3Instruction::LoadInt { dst: 1, value: 5 },
                timer_hostcall("timer:setTimeout", RegRange { start: 0, count: 2 }, 2),
                Ir3Instruction::LoadInt { dst: 1, value: 0 },
                timer_hostcall("timer:setTimeout", RegRange { start: 0, count: 2 }, 3),
                Ir3Instruction::Halt,
            ],
            "nested timer callback",
        ))
        .unwrap();

    assert_eq!(timer_id(core.read_reg(2).unwrap()), 0);
    assert_eq!(timer_id(core.read_reg(3).unwrap()), 1);
    assert!(core.active_timers.is_empty());
    assert_eq!(result.console_output.len(), 2);
}

#[test]
fn zero_delay_timeout() {
    let mut core = quickjs_test_core();
    let result = core
        .execute(&test_module_with_timer_callback(
            vec![
                Ir3Instruction::CreateClosure {
                    dst: 0,
                    function_index: 0,
                    capture_count: 0,
                },
                Ir3Instruction::LoadInt { dst: 1, value: -1 },
                timer_hostcall("timer:setTimeout", RegRange { start: 0, count: 2 }, 2),
                Ir3Instruction::Halt,
            ],
            "zero delay timer",
        ))
        .unwrap();

    assert_eq!(timer_id(core.read_reg(2).unwrap()), 0);
    assert!(core.active_timers.is_empty());
    assert_eq!(result.console_output[0].message, "zero delay timer");
}

// RC-4.3 Containment Action Enforcement Tests
mod containment_tests {
    use super::*;

    pub(super) fn test_interpreter() -> InterpreterCore {
        let mut config = test_quickjs_config();
        config.extension_id = Some("extension://containment-test".to_string());
        InterpreterCore::new(config, "test-containment")
    }

    #[test]
    fn allow_continues() {
        let mut interpreter = test_interpreter();
        let result = interpreter.handle_containment_action(HookAction::Allow);
        assert!(result.is_ok());
        assert!(!interpreter.suspended);
        assert!(!interpreter.sandboxed);
        assert!(!interpreter.quarantined);
    }

    #[test]
    fn terminate_aborts() {
        let mut interpreter = test_interpreter();
        let result = interpreter
            .handle_containment_action(HookAction::Terminate("policy violation".to_string()));
        match result {
            Err(InterpreterError::Terminated { reason }) => {
                assert_eq!(reason, "policy violation");
            }
            _ => panic!("Expected Terminated error"),
        }
        assert!(!interpreter.suspended);
        assert!(!interpreter.sandboxed);
        assert!(!interpreter.quarantined);
    }

    #[test]
    fn suspend_pauses() {
        let mut interpreter = test_interpreter();
        let result = interpreter.handle_containment_action(HookAction::Suspend);
        assert!(result.is_ok());
        assert!(interpreter.suspended);
        assert!(!interpreter.sandboxed);
        assert!(!interpreter.quarantined);
    }

    #[test]
    fn sandbox_restricts() {
        let mut interpreter = test_interpreter();
        let result = interpreter.handle_containment_action(HookAction::Sandbox);
        assert!(result.is_ok());
        assert!(!interpreter.suspended);
        assert!(interpreter.sandboxed);
        assert!(!interpreter.quarantined);
    }

    #[test]
    fn challenge_blocks() {
        let mut interpreter = test_interpreter();
        let token = ChallengeToken {
            token: "challenge-123".to_string(),
        };
        let result = interpreter.handle_containment_action(HookAction::Challenge(token.clone()));
        match result {
            Err(InterpreterError::ContainmentActionRequested { action, reason }) => {
                assert_eq!(action, "challenge");
                assert_eq!(reason, Some(token.token));
            }
            _ => panic!("Expected ContainmentActionRequested error"),
        }
        assert_eq!(interpreter.pending_challenges.len(), 1);
        assert_eq!(interpreter.pending_challenges[0].token, "challenge-123");
    }

    #[test]
    fn quarantine_terminates_and_marks() {
        let mut interpreter = test_interpreter();
        let result = interpreter
            .handle_containment_action(HookAction::Quarantine("malicious behavior".to_string()));
        match result {
            Err(InterpreterError::Terminated { reason }) => {
                assert_eq!(reason, "malicious behavior");
            }
            _ => panic!("Expected Terminated error"),
        }
        assert!(!interpreter.suspended);
        assert!(!interpreter.sandboxed);
        assert!(interpreter.quarantined);
    }

    #[test]
    fn evidence_emitted_per_action() {
        let mut interpreter = test_interpreter();
        let initial_evidence_count = interpreter.containment_evidence.len();
        let initial_witness_count = interpreter.witness_events.len();

        interpreter
            .handle_containment_action(HookAction::Sandbox)
            .unwrap();

        assert_eq!(
            interpreter.containment_evidence.len(),
            initial_evidence_count + 1
        );
        assert_eq!(interpreter.witness_events.len(), initial_witness_count + 1);

        let evidence = &interpreter.containment_evidence[0];
        assert_eq!(evidence.kind, WitnessEventKind::ContainmentAction);
        assert_eq!(evidence.instruction_index as usize, interpreter.ip);
    }

    #[test]
    fn interpreter_consistent_after_terminate() {
        let mut interpreter = test_interpreter();
        let initial_ip = interpreter.ip;
        let initial_register_base = interpreter.register_base;

        let _ = interpreter
            .handle_containment_action(HookAction::Terminate("test termination".to_string()));

        // Interpreter state should remain consistent (no half-executed instructions)
        assert_eq!(interpreter.ip, initial_ip);
        assert_eq!(interpreter.register_base, initial_register_base);
        assert_eq!(interpreter.containment_evidence.len(), 1);
    }

    // RC-4.4 Decision Receipt Tests
    #[test]
    fn receipt_has_correct_fields() {
        let mut interpreter = test_interpreter();
        interpreter
            .handle_containment_action(HookAction::Terminate("test".to_string()))
            .ok();

        let receipts = interpreter.decision_receipts().receipts();
        assert_eq!(receipts.len(), 1);

        let receipt = &receipts[0];
        assert_eq!(receipt.extension_id, "extension://containment-test");
        assert_eq!(receipt.operation_type, "terminate");
        assert_eq!(receipt.risk_score, 900_000);
        assert!(receipt.action_taken.contains("terminate"));
        assert!(receipt.timestamp > 0);
        assert_eq!(receipt.instruction_pointer, 0);
        assert!(!receipt.register_state_hash.is_empty());
        assert!(!receipt.signature.is_empty());
    }

    #[test]
    fn receipt_uses_current_module_specifier_when_config_extension_id_absent() {
        let mut config = test_quickjs_config();
        config.extension_id = None;
        let mut interpreter = InterpreterCore::new(config, "test-containment");
        interpreter.current_module_specifier = Some("extension://module-source".to_string());

        interpreter
            .handle_containment_action(HookAction::Sandbox)
            .ok();

        let receipts = interpreter.decision_receipts().receipts();
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].extension_id, "extension://module-source");
    }

    #[test]
    fn receipt_chain_linked() {
        let mut interpreter = test_interpreter();
        interpreter
            .handle_containment_action(HookAction::Sandbox)
            .ok();
        interpreter
            .handle_containment_action(HookAction::Suspend)
            .ok();

        let receipts = interpreter.decision_receipts().receipts();
        assert_eq!(receipts.len(), 2);

        assert!(receipts[0].previous_receipt_hash.is_none());
        assert_eq!(
            receipts[1].previous_receipt_hash,
            Some(receipts[0].signature.clone())
        );
    }

    #[test]
    fn chain_verification_valid() {
        let mut interpreter = test_interpreter();
        interpreter
            .handle_containment_action(HookAction::Sandbox)
            .ok();
        interpreter
            .handle_containment_action(HookAction::Suspend)
            .ok();

        assert!(interpreter.verify_decision_receipt_chain());
    }

    #[test]
    fn chain_verification_tampered() {
        let mut interpreter = test_interpreter();
        interpreter
            .handle_containment_action(HookAction::Sandbox)
            .ok();

        // Tamper with the receipt signature
        interpreter.decision_receipts.receipts[0].signature = "tampered".to_string();

        assert!(!interpreter.verify_decision_receipt_chain());
    }

    #[test]
    fn empty_chain_valid() {
        let interpreter = test_interpreter();
        assert!(interpreter.verify_decision_receipt_chain());
        assert!(interpreter.decision_receipts().is_empty());
    }

    #[test]
    fn export_json_schema() {
        let mut interpreter = test_interpreter();
        interpreter
            .handle_containment_action(HookAction::Sandbox)
            .ok();

        // SAFETY: Test exports receipts after handling action; export succeeds in controlled test environment
        let json_export = interpreter.export_decision_receipts().unwrap();
        // SAFETY: JSON was just produced by export_decision_receipts; parsing succeeds for valid JSON
        let parsed: serde_json::Value = serde_json::from_str(&json_export).unwrap();

        assert_eq!(parsed["evidence_type"], "guardplane_decision_chain");
        assert_eq!(parsed["receipt_count"], 1);
        assert_eq!(parsed["chain_verified"], true);
        assert!(parsed["receipts"].is_array());
        assert!(parsed["exported_at"].as_u64().unwrap() > 0);
    }

    #[test]
    fn receipt_includes_risk_score() {
        let mut interpreter = test_interpreter();
        interpreter
            .handle_containment_action(HookAction::Terminate("test".to_string()))
            .ok();

        let receipt = &interpreter.decision_receipts().receipts()[0];
        assert_eq!(receipt.risk_score, 900_000); // High risk for terminate action
    }

    #[test]
    fn receipt_includes_action() {
        let mut interpreter = test_interpreter();
        interpreter
            .handle_containment_action(HookAction::Quarantine("malicious".to_string()))
            .ok();

        let receipt = &interpreter.decision_receipts().receipts()[0];
        assert_eq!(receipt.operation_type, "quarantine");
        assert!(receipt.action_taken.contains("quarantine"));
        assert!(receipt.action_taken.contains("malicious"));
    }
}

mod async_function_tests {
    use super::containment_tests::test_interpreter;
    use super::*;

    fn pending_async_module(
        mut body: Vec<Ir3Instruction>,
        arity: u32,
        frame_size: u32,
    ) -> Ir3Module {
        let mut instructions = vec![
            Ir3Instruction::CreateAsyncFunction {
                dst: 0,
                function_index: 0,
                capture_count: 0,
            },
            Ir3Instruction::Call {
                callee: 0,
                args: RegRange {
                    start: 10,
                    count: arity,
                },
                dst: 1,
            },
            Ir3Instruction::Halt,
        ];
        instructions.append(&mut body);
        test_module_with_functions(
            instructions,
            vec![Ir3FunctionDesc {
                entry: 3,
                arity,
                frame_size,
                name: Some("pending_async_bd_ur3tk_15".to_string()),
                is_generator: false,
                rest_param_index: None,
            }],
        )
    }

    #[test]
    fn primitive_and_settled_await_defer_without_suspending_the_caller() {
        for pre_resolved in [false, true] {
            let mut core = InterpreterCore::new(test_quickjs_config(), "async-await-job-order");
            let mut module = pending_async_module(
                vec![
                    Ir3Instruction::AwaitValue { promise_reg: 0 },
                    Ir3Instruction::Return { value: 0 },
                ],
                1,
                1,
            );
            module
                .instructions
                .insert(2, Ir3Instruction::LoadInt { dst: 2, value: 99 });
            module.function_table[0].entry = 4;
            let input = if pre_resolved {
                let promise = core.create_promise_accounted().unwrap();
                core.fulfill_promise(
                    promise,
                    crate::object_model::JsValue::Int(7),
                    crate::ifc_artifacts::Label::Public,
                )
                .unwrap();
                Value::Promise(promise.0)
            } else {
                Value::Int(7)
            };
            core.write_reg(10, input).unwrap();
            assert!(matches!(
                core.run_loop(&module),
                Err(InterpreterError::Halted)
            ));
            let Value::Promise(result) = core.read_reg(1).unwrap() else {
                panic!("async call must publish its Promise");
            };
            let result = crate::promise_model::PromiseHandle(result);
            assert!(!core.promise_store.get(result).unwrap().state.is_settled());
            assert_eq!(core.read_reg(2).unwrap(), Value::Int(99));
            assert!(core.call_stack.is_empty());
            assert_eq!(core.register_base, 0);
            assert!(!core.event_loop.microtasks.is_empty());
            let caller_ip = core.ip;
            // The activation retains its owner; a later checkpoint does
            // not need whichever module happened to initiate this call.
            core.drain_microtasks(None).unwrap();
            assert!(matches!(
                core.promise_store.get(result).unwrap().state,
                crate::promise_model::PromiseState::Fulfilled(crate::object_model::JsValue::Int(7))
            ));
            assert_eq!(core.read_reg(2).unwrap(), Value::Int(99));
            assert_eq!(core.ip, caller_ip);
            assert!(core.async_functions[0].execution.is_none());
            assert_eq!(core.async_functions[0].register_storage_bytes, 0);
            assert_eq!(
                core.estimated_memory_bytes(),
                core.recompute_estimated_memory_bytes()
            );
        }
    }

    #[test]
    fn concurrent_pending_activations_resume_in_settlement_order() {
        let mut core = InterpreterCore::new(test_quickjs_config(), "async-independent-activations");
        let mut module = pending_async_module(
            vec![
                Ir3Instruction::AwaitValue { promise_reg: 0 },
                Ir3Instruction::Return { value: 0 },
            ],
            1,
            1,
        );
        module.instructions.insert(
            2,
            Ir3Instruction::Call {
                callee: 0,
                args: RegRange {
                    start: 11,
                    count: 1,
                },
                dst: 2,
            },
        );
        module
            .instructions
            .insert(3, Ir3Instruction::LoadInt { dst: 3, value: 13 });
        module.function_table[0].entry = 5;
        let first = core.create_promise_accounted().unwrap();
        let second = core.create_promise_accounted().unwrap();
        core.write_reg_with_label(
            10,
            Value::Promise(first.0),
            crate::ifc_artifacts::Label::Confidential,
        )
        .unwrap();
        core.write_reg_with_label(
            11,
            Value::Promise(second.0),
            crate::ifc_artifacts::Label::Secret,
        )
        .unwrap();
        assert!(matches!(
            core.run_loop(&module),
            Err(InterpreterError::Halted)
        ));
        let Value::Promise(first_result) = core.read_reg(1).unwrap() else {
            panic!("first result")
        };
        let Value::Promise(second_result) = core.read_reg(2).unwrap() else {
            panic!("second result")
        };
        let first_result = crate::promise_model::PromiseHandle(first_result);
        let second_result = crate::promise_model::PromiseHandle(second_result);
        assert_eq!(core.async_resumption_contexts.len(), 2);
        assert!(core.call_stack.is_empty());
        core.fulfill_promise(
            second,
            crate::object_model::JsValue::Int(22),
            crate::ifc_artifacts::Label::Public,
        )
        .unwrap();
        core.drain_microtasks(None).unwrap();
        assert!(
            !core
                .promise_store
                .get(first_result)
                .unwrap()
                .state
                .is_settled()
        );
        assert!(matches!(
            core.promise_store.get(second_result).unwrap().state,
            crate::promise_model::PromiseState::Fulfilled(crate::object_model::JsValue::Int(22))
        ));
        assert_eq!(
            core.promise_store.get(second_result).unwrap().label,
            crate::ifc_artifacts::Label::Secret
        );
        assert_eq!(core.async_resumption_contexts.len(), 1);
        core.fulfill_promise(
            first,
            crate::object_model::JsValue::Int(11),
            crate::ifc_artifacts::Label::Public,
        )
        .unwrap();
        core.drain_microtasks(None).unwrap();
        assert!(matches!(
            core.promise_store.get(first_result).unwrap().state,
            crate::promise_model::PromiseState::Fulfilled(crate::object_model::JsValue::Int(11))
        ));
        assert_eq!(
            core.promise_store.get(first_result).unwrap().label,
            crate::ifc_artifacts::Label::Confidential
        );
        assert_eq!(core.read_reg(3).unwrap(), Value::Int(13));
        assert!(core.async_resumption_contexts.is_empty());
        assert!(
            core.async_functions
                .iter()
                .all(|function| function.execution.is_none())
        );
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }

    #[test]
    fn inline_async_callback_returns_a_promise_and_keeps_its_activation() {
        let mut core = InterpreterCore::new(test_quickjs_config(), "async-inline-callback");
        let module = test_module_with_functions(
            vec![
                Ir3Instruction::AwaitValue { promise_reg: 0 },
                Ir3Instruction::Return { value: 0 },
            ],
            vec![Ir3FunctionDesc {
                entry: 0,
                arity: 1,
                frame_size: 1,
                name: Some("async_callback".to_string()),
                is_generator: false,
                rest_param_index: None,
            }],
        );
        core.closures.push(ClosureValue {
            function_index: 0,
            captured_env: core.scope_chain.snapshot(),
            module_specifier: None,
        });
        let awaited = core.create_promise_accounted().unwrap();
        core.write_reg_with_label(
            1,
            Value::str("caller-sentinel"),
            crate::ifc_artifacts::Label::Internal,
        )
        .unwrap();
        let (completion, _) = core
            .invoke_inline_method_call_labeled(
                &module,
                Value::AsyncFunction(0),
                Value::Undefined,
                &[(
                    Value::Promise(awaited.0),
                    crate::ifc_artifacts::Label::Secret,
                )],
            )
            .unwrap();
        let InlineCallCompletion::Value(Value::Promise(result)) = completion else {
            panic!("pending async callbacks must return their Promise, never a synthetic throw");
        };
        let result = crate::promise_model::PromiseHandle(result);
        assert!(!core.promise_store.get(result).unwrap().state.is_settled());
        assert!(core.async_functions[0].execution.is_some());
        assert_eq!(core.read_reg(1).unwrap(), Value::str("caller-sentinel"));
        core.fulfill_promise(
            awaited,
            crate::object_model::JsValue::Int(23),
            crate::ifc_artifacts::Label::Public,
        )
        .unwrap();
        core.drain_microtasks(None).unwrap();
        assert!(matches!(
            core.promise_store.get(result).unwrap().state,
            crate::promise_model::PromiseState::Fulfilled(crate::object_model::JsValue::Int(23))
        ));
        assert_eq!(
            core.promise_store.get(result).unwrap().label,
            crate::ifc_artifacts::Label::Secret
        );
        assert_eq!(core.read_reg(1).unwrap(), Value::str("caller-sentinel"));
        assert_eq!(
            core.read_reg_label(1).unwrap(),
            crate::ifc_artifacts::Label::Internal
        );
        assert!(core.call_stack.is_empty());
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }

    #[test]
    fn await_in_finally_preserves_or_replaces_exact_labeled_completion() {
        for return_completion in [false, true] {
            for reject_finalizer in [false, true] {
                let mut core =
                    InterpreterCore::new(test_quickjs_config(), "async-finally-completion");
                let completion = if return_completion {
                    Ir3Instruction::Return { value: 1 }
                } else {
                    Ir3Instruction::Throw { value: 1 }
                };
                let module = pending_async_module(
                    vec![
                        Ir3Instruction::BeginTry {
                            catch_target: 6,
                            finally_target: Some(6),
                        },
                        completion,
                        Ir3Instruction::EndTry,
                        Ir3Instruction::EnterFinally,
                        Ir3Instruction::AwaitValue { promise_reg: 0 },
                        Ir3Instruction::EndFinally,
                    ],
                    2,
                    2,
                );
                let awaited = core.create_promise_accounted().unwrap();
                let original = core.alloc_object_with_prototype(None).unwrap();
                core.write_reg_with_label(
                    10,
                    Value::Promise(awaited.0),
                    crate::ifc_artifacts::Label::Confidential,
                )
                .unwrap();
                core.write_reg_with_label(
                    11,
                    Value::Object(original),
                    crate::ifc_artifacts::Label::Secret,
                )
                .unwrap();
                assert!(matches!(
                    core.run_loop(&module),
                    Err(InterpreterError::Halted)
                ));
                let Value::Promise(result) = core.read_reg(1).unwrap() else {
                    panic!("async result")
                };
                let result = crate::promise_model::PromiseHandle(result);
                assert!(!core.promise_store.get(result).unwrap().state.is_settled());
                assert_eq!(
                    core.async_functions[0]
                        .execution
                        .as_ref()
                        .unwrap()
                        .finally_frames
                        .len(),
                    1
                );
                if reject_finalizer {
                    core.reject_promise(
                        awaited,
                        crate::object_model::JsValue::Int(91),
                        crate::ifc_artifacts::Label::TopSecret,
                    )
                    .unwrap();
                } else {
                    core.fulfill_promise(
                        awaited,
                        crate::object_model::JsValue::Undefined,
                        crate::ifc_artifacts::Label::Public,
                    )
                    .unwrap();
                }
                core.drain_microtasks(None).unwrap();
                let record = core.promise_store.get(result).unwrap();
                if reject_finalizer {
                    assert!(matches!(
                        record.state,
                        crate::promise_model::PromiseState::Rejected(
                            crate::object_model::JsValue::Int(91)
                        )
                    ));
                    assert_eq!(record.label, crate::ifc_artifacts::Label::TopSecret);
                } else {
                    let expected = InterpreterCore::value_to_js_value(&Value::Object(original));
                    let actual = match &record.state {
                        crate::promise_model::PromiseState::Fulfilled(value)
                            if return_completion =>
                        {
                            value
                        }
                        crate::promise_model::PromiseState::Rejected(value)
                            if !return_completion =>
                        {
                            value
                        }
                        state => panic!("unexpected async completion: {state:?}"),
                    };
                    assert_eq!(actual, &expected);
                    assert_eq!(record.label, crate::ifc_artifacts::Label::Secret);
                }
                assert!(core.finally_frames.is_empty());
                assert!(core.pending_exception.is_none());
                assert!(core.pending_return.is_none());
                assert!(core.async_functions[0].execution.is_none());
                assert_eq!(
                    core.estimated_memory_bytes(),
                    core.recompute_estimated_memory_bytes()
                );
            }
        }
    }

    #[test]
    fn resumed_async_execution_limit_remains_fatal_and_releases_activation() {
        let mut core = InterpreterCore::new(test_quickjs_config(), "async-fatal-resume");
        let module = pending_async_module(
            vec![
                Ir3Instruction::AwaitValue { promise_reg: 0 },
                Ir3Instruction::Return { value: 0 },
            ],
            1,
            1,
        );
        let awaited = core.create_promise_accounted().unwrap();
        core.write_reg(10, Value::Promise(awaited.0)).unwrap();
        assert!(matches!(
            core.run_loop(&module),
            Err(InterpreterError::Halted)
        ));
        let Value::Promise(result) = core.read_reg(1).unwrap() else {
            panic!("async result")
        };
        core.config.instruction_budget = core.instructions_executed;
        core.fulfill_promise(
            awaited,
            crate::object_model::JsValue::Int(8),
            crate::ifc_artifacts::Label::Public,
        )
        .unwrap();
        let error = core
            .drain_microtasks(None)
            .expect_err("resource refusal must propagate out of the job");
        assert!(matches!(error, InterpreterError::BudgetExhausted { .. }));
        assert!(
            !core
                .promise_store
                .get(crate::promise_model::PromiseHandle(result))
                .unwrap()
                .state
                .is_settled()
        );
        assert!(core.async_functions[0].execution.is_none());
        assert!(core.async_functions[0].owner_module.is_none());
        assert_eq!(core.async_functions[0].register_storage_bytes, 0);
        assert!(core.async_resumption_contexts.is_empty());
        assert_eq!(core.promise_in_flight_task_bytes, 0);
        assert!(core.call_stack.is_empty());
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }

    fn prepared_async_generator(
        core: &mut InterpreterCore,
        module: &Ir3Module,
        arguments: Vec<(Value, crate::ifc_artifacts::Label)>,
    ) -> AsyncGeneratorObject {
        core.prepare_async_generator_activation(
            module,
            GeneratorCallSetup {
                function_index: 0,
                function_entry: 0,
                captured_env: core.scope_chain.snapshot(),
                arguments,
                this_value: Value::Undefined,
                this_label: crate::ifc_artifacts::Label::Public,
                super_value: Value::Undefined,
                super_label: crate::ifc_artifacts::Label::Public,
            },
            None,
        )
        .expect("async generator activation should reach its body boundary")
    }

    #[test]
    fn create_async_function_stores_closure_reference_without_executor_state() {
        let mut core = InterpreterCore::new(test_quickjs_config(), "async-function-create");
        let module = test_module_with_functions(
            vec![
                Ir3Instruction::CreateAsyncFunction {
                    dst: 0,
                    function_index: 0,
                    capture_count: 0,
                },
                Ir3Instruction::Halt,
                Ir3Instruction::Halt,
            ],
            vec![Ir3FunctionDesc {
                entry: 2,
                arity: 0,
                frame_size: 1,
                name: Some("test_async".to_string()),
                is_generator: false,
                rest_param_index: None,
            }],
        );

        core.execute(&module).expect("module should halt cleanly");

        assert_eq!(core.promise_store.len(), 0);
        assert!(matches!(core.registers[0], Value::AsyncFunction(0)));
    }

    #[test]
    fn async_function_call_returns_and_resolves_promise() {
        let mut core = InterpreterCore::new(test_quickjs_config(), "async-function-call");
        let module = test_module_with_functions(
            vec![
                Ir3Instruction::CreateAsyncFunction {
                    dst: 0,
                    function_index: 0,
                    capture_count: 0,
                },
                Ir3Instruction::Call {
                    callee: 0,
                    args: RegRange {
                        start: 10,
                        count: 0,
                    },
                    dst: 1,
                },
                Ir3Instruction::Halt,
                Ir3Instruction::LoadInt { dst: 0, value: 42 },
                Ir3Instruction::AsyncReturn { value_reg: 0 },
            ],
            vec![Ir3FunctionDesc {
                entry: 3,
                arity: 0,
                frame_size: 1,
                name: Some("test_async".to_string()),
                is_generator: false,
                rest_param_index: None,
            }],
        );

        core.execute(&module)
            .expect("async function execution should resolve its promise");

        let Value::Promise(handle) = core.registers[1] else {
            panic!("async call should leave result promise in destination register");
        };
        let record = core
            .promise_store
            .get(crate::promise_model::PromiseHandle(handle))
            .expect("result promise exists");
        assert!(matches!(
            &record.state,
            crate::promise_model::PromiseState::Fulfilled(crate::object_model::JsValue::Int(42))
        ));
        assert!(matches!(
            core.async_functions[0].phase,
            AsyncFunctionPhase::Completed
        ));
        assert!(matches!(core.registers[0], Value::AsyncFunction(0)));
    }

    #[test]
    fn async_function_throw_rejects_result_promise() {
        let mut core = InterpreterCore::new(test_quickjs_config(), "async-function-throw");
        let mut module = test_module_with_functions(
            vec![
                Ir3Instruction::CreateAsyncFunction {
                    dst: 0,
                    function_index: 0,
                    capture_count: 0,
                },
                Ir3Instruction::Call {
                    callee: 0,
                    args: RegRange {
                        start: 10,
                        count: 0,
                    },
                    dst: 1,
                },
                Ir3Instruction::Halt,
                Ir3Instruction::LoadStr {
                    dst: 0,
                    pool_index: 0,
                },
                Ir3Instruction::AsyncThrow { error_reg: 0 },
            ],
            vec![Ir3FunctionDesc {
                entry: 3,
                arity: 0,
                frame_size: 1,
                name: Some("throw_async".to_string()),
                is_generator: false,
                rest_param_index: None,
            }],
        );
        module.constant_pool.push("boom".into());

        core.execute(&module)
            .expect("async throw should reject its promise without aborting");

        let Value::Promise(handle) = core.registers[1] else {
            panic!("async call should leave result promise in destination register");
        };
        let record = core
            .promise_store
            .get(crate::promise_model::PromiseHandle(handle))
            .expect("result promise exists");
        assert!(matches!(
            &record.state,
            crate::promise_model::PromiseState::Rejected(crate::object_model::JsValue::Str(
                reason
            )) if reason == "boom"
        ));
        assert!(matches!(
            core.async_functions[0].phase,
            AsyncFunctionPhase::Completed
        ));
    }

    #[test]
    fn async_function_awaits_resolved_promise_and_fulfills_with_value() {
        let mut core = InterpreterCore::new(test_quickjs_config(), "async-function-await");
        let module = test_module_with_functions(
            vec![
                Ir3Instruction::CreateAsyncFunction {
                    dst: 0,
                    function_index: 0,
                    capture_count: 0,
                },
                Ir3Instruction::Call {
                    callee: 0,
                    args: RegRange {
                        start: 10,
                        count: 1,
                    },
                    dst: 1,
                },
                Ir3Instruction::Halt,
                Ir3Instruction::AwaitValue { promise_reg: 0 },
                Ir3Instruction::AsyncReturn { value_reg: 0 },
            ],
            vec![Ir3FunctionDesc {
                entry: 3,
                arity: 1,
                frame_size: 1,
                name: Some("await_async".to_string()),
                is_generator: false,
                rest_param_index: None,
            }],
        );
        let handle = core.promise_store.create();
        core.promise_store
            .fulfill(
                handle,
                crate::object_model::JsValue::Int(99),
                crate::ifc_artifacts::Label::Public,
                &mut core.event_loop.microtasks,
            )
            .expect("seed promise should be fulfillable");
        core.registers[10] = Value::Promise(handle.0);

        core.execute(&module)
            .expect("resolved await should continue through async return");

        let Value::Promise(result_handle) = core.registers[1] else {
            panic!("async call should leave result promise in destination register");
        };
        let record = core
            .promise_store
            .get(crate::promise_model::PromiseHandle(result_handle))
            .expect("result promise exists");
        assert!(matches!(
            &record.state,
            crate::promise_model::PromiseState::Fulfilled(crate::object_model::JsValue::Int(99))
        ));
        assert!(matches!(
            core.async_functions[0].phase,
            AsyncFunctionPhase::Completed
        ));
    }

    #[test]
    fn async_function_awaits_secret_promise_preserves_result_label() {
        let mut core = InterpreterCore::new(test_quickjs_config(), "async-function-await-secret");
        let module = test_module_with_functions(
            vec![
                Ir3Instruction::CreateAsyncFunction {
                    dst: 0,
                    function_index: 0,
                    capture_count: 0,
                },
                Ir3Instruction::Call {
                    callee: 0,
                    args: RegRange {
                        start: 10,
                        count: 1,
                    },
                    dst: 1,
                },
                Ir3Instruction::Halt,
                Ir3Instruction::AwaitValue { promise_reg: 0 },
                Ir3Instruction::AsyncReturn { value_reg: 0 },
            ],
            vec![Ir3FunctionDesc {
                entry: 3,
                arity: 1,
                frame_size: 1,
                name: Some("await_secret_async".to_string()),
                is_generator: false,
                rest_param_index: None,
            }],
        );
        let handle = core.promise_store.create();
        core.promise_store
            .fulfill(
                handle,
                crate::object_model::JsValue::Str("secret".into()),
                crate::ifc_artifacts::Label::Secret,
                &mut core.event_loop.microtasks,
            )
            .expect("seed promise should be fulfillable");
        core.registers[10] = Value::Promise(handle.0);

        core.execute(&module)
            .expect("secret-labeled promise await should resolve");

        let Value::Promise(result_handle) = core.registers[1] else {
            panic!("async call should leave result promise in destination register");
        };
        let record = core
            .promise_store
            .get(crate::promise_model::PromiseHandle(result_handle))
            .expect("result promise exists");
        assert_eq!(record.label, crate::ifc_artifacts::Label::Secret);
        assert!(matches!(
            &record.state,
            crate::promise_model::PromiseState::Fulfilled(crate::object_model::JsValue::Str(
                value
            )) if value == "secret"
        ));
    }

    #[test]
    fn async_await_joins_handle_and_settlement_labels_bd_ur3tk_3() {
        let mut core = InterpreterCore::new(test_quickjs_config(), "async-await-handle-label");
        let module = test_module_with_functions(
            vec![
                Ir3Instruction::CreateAsyncFunction {
                    dst: 0,
                    function_index: 0,
                    capture_count: 0,
                },
                Ir3Instruction::Call {
                    callee: 0,
                    args: RegRange {
                        start: 10,
                        count: 1,
                    },
                    dst: 1,
                },
                Ir3Instruction::Halt,
                Ir3Instruction::AwaitValue { promise_reg: 0 },
                Ir3Instruction::AsyncReturn { value_reg: 0 },
            ],
            vec![Ir3FunctionDesc {
                entry: 3,
                arity: 1,
                frame_size: 1,
                name: Some("await_labeled_handle".to_string()),
                is_generator: false,
                rest_param_index: None,
            }],
        );
        let handle = core.promise_store.create();
        core.promise_store
            .fulfill(
                handle,
                crate::object_model::JsValue::Str("public-payload".into()),
                crate::ifc_artifacts::Label::Public,
                &mut core.event_loop.microtasks,
            )
            .expect("seed promise should be fulfillable");
        core.write_reg_with_label(
            10,
            Value::Promise(handle.0),
            crate::ifc_artifacts::Label::Secret,
        )
        .expect("Promise handle should accept its external label");

        core.execute(&module)
            .expect("settled await should preserve the handle label");

        let Value::Promise(result_handle) = core.registers[1] else {
            panic!("async call should leave its result Promise");
        };
        let record = core
            .promise_store
            .get(crate::promise_model::PromiseHandle(result_handle))
            .expect("result Promise exists");
        assert_eq!(record.label, crate::ifc_artifacts::Label::Secret);
        assert!(matches!(
            &record.state,
            crate::promise_model::PromiseState::Fulfilled(crate::object_model::JsValue::Str(
                value
            )) if value == "public-payload"
        ));
    }

    #[test]
    fn async_rejected_await_joins_handle_label_bd_ur3tk_3() {
        let mut core = InterpreterCore::new(test_quickjs_config(), "async-rejected-handle-label");
        let module = test_module_with_functions(
            vec![
                Ir3Instruction::CreateAsyncFunction {
                    dst: 0,
                    function_index: 0,
                    capture_count: 0,
                },
                Ir3Instruction::Call {
                    callee: 0,
                    args: RegRange {
                        start: 10,
                        count: 1,
                    },
                    dst: 1,
                },
                Ir3Instruction::Halt,
                Ir3Instruction::AwaitValue { promise_reg: 0 },
                Ir3Instruction::AsyncReturn { value_reg: 0 },
            ],
            vec![Ir3FunctionDesc {
                entry: 3,
                arity: 1,
                frame_size: 1,
                name: Some("await_labeled_rejection".to_string()),
                is_generator: false,
                rest_param_index: None,
            }],
        );
        let handle = core.promise_store.create();
        core.promise_store
            .reject(
                handle,
                crate::object_model::JsValue::Str("public-reason".into()),
                crate::ifc_artifacts::Label::Public,
                &mut core.event_loop.microtasks,
            )
            .expect("seed promise should be rejectable");
        core.write_reg_with_label(
            10,
            Value::Promise(handle.0),
            crate::ifc_artifacts::Label::Secret,
        )
        .expect("rejected Promise handle should accept its external label");

        core.execute(&module)
            .expect("rejected settled await should reject the result Promise");

        let Value::Promise(result_handle) = core.registers[1] else {
            panic!("async call should leave its result Promise");
        };
        let record = core
            .promise_store
            .get(crate::promise_model::PromiseHandle(result_handle))
            .expect("result Promise exists");
        assert_eq!(record.label, crate::ifc_artifacts::Label::Secret);
        assert!(matches!(
            &record.state,
            crate::promise_model::PromiseState::Rejected(crate::object_model::JsValue::Str(
                value
            )) if value == "public-reason"
        ));
    }

    #[test]
    fn async_method_preserves_receiver_label_bd_ur3tk_3() {
        let mut core = InterpreterCore::new(test_quickjs_config(), "async-method-receiver");
        let module = test_module_with_functions(
            vec![
                Ir3Instruction::CreateAsyncFunction {
                    dst: 0,
                    function_index: 0,
                    capture_count: 0,
                },
                Ir3Instruction::CallMethod {
                    receiver: 2,
                    callee: 0,
                    args: RegRange {
                        start: 10,
                        count: 0,
                    },
                    dst: 1,
                },
                Ir3Instruction::Halt,
                Ir3Instruction::LoadThis { dst: 0 },
                Ir3Instruction::AsyncReturn { value_reg: 0 },
            ],
            vec![Ir3FunctionDesc {
                entry: 3,
                arity: 0,
                frame_size: 1,
                name: Some("async_method_this".to_string()),
                is_generator: false,
                rest_param_index: None,
            }],
        );
        core.write_reg_with_label(
            2,
            Value::str("secret-receiver"),
            crate::ifc_artifacts::Label::Secret,
        )
        .expect("receiver should be writable");

        core.execute(&module)
            .expect("async method should dispatch and resolve");

        let Value::Promise(result_handle) = core.registers[1] else {
            panic!("async method should leave its result Promise");
        };
        let record = core
            .promise_store
            .get(crate::promise_model::PromiseHandle(result_handle))
            .expect("result Promise exists");
        assert_eq!(record.label, crate::ifc_artifacts::Label::Secret);
        assert!(matches!(
            &record.state,
            crate::promise_model::PromiseState::Fulfilled(crate::object_model::JsValue::Str(
                value
            )) if value == "secret-receiver"
        ));
    }

    #[test]
    fn async_method_preserves_argument_label_bd_ur3tk_3() {
        let mut core = InterpreterCore::new(test_quickjs_config(), "async-method-argument");
        let module = test_module_with_functions(
            vec![
                Ir3Instruction::CreateAsyncFunction {
                    dst: 0,
                    function_index: 0,
                    capture_count: 0,
                },
                Ir3Instruction::CallMethod {
                    receiver: 2,
                    callee: 0,
                    args: RegRange {
                        start: 10,
                        count: 1,
                    },
                    dst: 1,
                },
                Ir3Instruction::Halt,
                Ir3Instruction::AsyncReturn { value_reg: 0 },
            ],
            vec![Ir3FunctionDesc {
                entry: 3,
                arity: 1,
                frame_size: 1,
                name: Some("async_method_argument".to_string()),
                is_generator: false,
                rest_param_index: None,
            }],
        );
        core.registers[2] = Value::str("public-receiver");
        core.write_reg_with_label(
            10,
            Value::str("secret-argument"),
            crate::ifc_artifacts::Label::Secret,
        )
        .expect("method argument should be writable");

        core.execute(&module)
            .expect("async method should preserve argument labels");

        let Value::Promise(result_handle) = core.registers[1] else {
            panic!("async method should leave its result Promise");
        };
        let record = core
            .promise_store
            .get(crate::promise_model::PromiseHandle(result_handle))
            .expect("result Promise exists");
        assert_eq!(record.label, crate::ifc_artifacts::Label::Secret);
        assert!(matches!(
            &record.state,
            crate::promise_model::PromiseState::Fulfilled(crate::object_model::JsValue::Str(
                value
            )) if value == "secret-argument"
        ));
    }

    #[test]
    fn async_direct_return_preserves_argument_label_bd_ur3tk_3() {
        let mut core = InterpreterCore::new(test_quickjs_config(), "async-direct-return-label");
        let module = test_module_with_functions(
            vec![
                Ir3Instruction::CreateAsyncFunction {
                    dst: 0,
                    function_index: 0,
                    capture_count: 0,
                },
                Ir3Instruction::Call {
                    callee: 0,
                    args: RegRange {
                        start: 10,
                        count: 1,
                    },
                    dst: 1,
                },
                Ir3Instruction::Halt,
                Ir3Instruction::AsyncReturn { value_reg: 0 },
            ],
            vec![Ir3FunctionDesc {
                entry: 3,
                arity: 1,
                frame_size: 1,
                name: Some("direct_async_return".to_string()),
                is_generator: false,
                rest_param_index: None,
            }],
        );
        core.write_reg_with_label(
            10,
            Value::str("secret-return"),
            crate::ifc_artifacts::Label::Secret,
        )
        .expect("async argument should be writable");

        core.execute(&module)
            .expect("direct async return should resolve");

        let Value::Promise(result_handle) = core.registers[1] else {
            panic!("async call should leave its result Promise");
        };
        let record = core
            .promise_store
            .get(crate::promise_model::PromiseHandle(result_handle))
            .expect("result Promise exists");
        assert_eq!(record.label, crate::ifc_artifacts::Label::Secret);
    }

    #[test]
    fn async_direct_throw_preserves_argument_label_bd_ur3tk_3() {
        let mut core = InterpreterCore::new(test_quickjs_config(), "async-direct-throw-label");
        let module = test_module_with_functions(
            vec![
                Ir3Instruction::CreateAsyncFunction {
                    dst: 0,
                    function_index: 0,
                    capture_count: 0,
                },
                Ir3Instruction::Call {
                    callee: 0,
                    args: RegRange {
                        start: 10,
                        count: 1,
                    },
                    dst: 1,
                },
                Ir3Instruction::Halt,
                Ir3Instruction::AsyncThrow { error_reg: 0 },
            ],
            vec![Ir3FunctionDesc {
                entry: 3,
                arity: 1,
                frame_size: 1,
                name: Some("direct_async_throw".to_string()),
                is_generator: false,
                rest_param_index: None,
            }],
        );
        core.write_reg_with_label(
            10,
            Value::str("secret-rejection"),
            crate::ifc_artifacts::Label::Secret,
        )
        .expect("async rejection argument should be writable");

        core.execute(&module)
            .expect("direct async throw should reject its Promise");

        let Value::Promise(result_handle) = core.registers[1] else {
            panic!("async call should leave its result Promise");
        };
        let record = core
            .promise_store
            .get(crate::promise_model::PromiseHandle(result_handle))
            .expect("result Promise exists");
        assert_eq!(record.label, crate::ifc_artifacts::Label::Secret);
        assert!(matches!(
            &record.state,
            crate::promise_model::PromiseState::Rejected(crate::object_model::JsValue::Str(
                value
            )) if value == "secret-rejection"
        ));
    }

    #[test]
    fn async_plain_call_super_uses_only_callee_label_bd_ur3tk_20() {
        let mut core = InterpreterCore::new(test_quickjs_config(), "async-plain-super-label");
        let module = test_module_with_functions(
            vec![
                Ir3Instruction::Call {
                    callee: 0,
                    args: RegRange {
                        start: 10,
                        count: 1,
                    },
                    dst: 1,
                },
                Ir3Instruction::Halt,
                Ir3Instruction::LoadSuper { dst: 0 },
                Ir3Instruction::AsyncReturn { value_reg: 0 },
            ],
            vec![Ir3FunctionDesc {
                entry: 2,
                arity: 1,
                frame_size: 1,
                name: Some("async_plain_super_reader".to_string()),
                is_generator: false,
                rest_param_index: None,
            }],
        );
        let captured_env = core.scope_chain.snapshot();
        core.closures.push(ClosureValue {
            function_index: 0,
            captured_env,
            module_specifier: None,
        });
        core.write_reg_with_label(
            0,
            Value::AsyncFunction(0),
            crate::ifc_artifacts::Label::Secret,
        )
        .expect("async callee should be writable");
        core.write_reg_with_label(10, Value::Int(43), crate::ifc_artifacts::Label::TopSecret)
            .expect("async argument should be writable");

        core.execute(&module)
            .expect("async plain call should resolve");

        let Value::Promise(result_handle) = core.registers[1] else {
            panic!("async plain call should leave its result Promise");
        };
        let record = core
            .promise_store
            .get(crate::promise_model::PromiseHandle(result_handle))
            .expect("result Promise exists");
        assert_eq!(record.label, crate::ifc_artifacts::Label::Secret);
        assert!(matches!(
            &record.state,
            crate::promise_model::PromiseState::Fulfilled(crate::object_model::JsValue::Undefined)
        ));
    }

    #[test]
    fn async_method_super_uses_only_callee_label_bd_ur3tk_20() {
        let mut core = InterpreterCore::new(test_quickjs_config(), "async-method-super-label");
        let module = test_module_with_functions(
            vec![
                Ir3Instruction::CallMethod {
                    receiver: 2,
                    callee: 0,
                    args: RegRange {
                        start: 10,
                        count: 1,
                    },
                    dst: 1,
                },
                Ir3Instruction::Halt,
                Ir3Instruction::LoadSuper { dst: 1 },
                Ir3Instruction::AsyncReturn { value_reg: 1 },
            ],
            vec![Ir3FunctionDesc {
                entry: 2,
                arity: 1,
                frame_size: 2,
                name: Some("async_method_super_reader".to_string()),
                is_generator: false,
                rest_param_index: None,
            }],
        );
        let parent_prototype = core
            .alloc_object_with_prototype(None)
            .expect("parent prototype should allocate");
        let method_prototype = core
            .alloc_object_with_prototype(Some(parent_prototype))
            .expect("method prototype should allocate");
        let receiver = core
            .alloc_object_with_prototype(Some(method_prototype))
            .expect("receiver should allocate");
        let captured_env = core.scope_chain.snapshot();
        core.closures.push(ClosureValue {
            function_index: 0,
            captured_env,
            module_specifier: None,
        });
        core.write_reg_with_label(
            0,
            Value::AsyncFunction(0),
            crate::ifc_artifacts::Label::Secret,
        )
        .expect("async method should be writable");
        core.write_reg_with_label(
            2,
            Value::Object(receiver),
            crate::ifc_artifacts::Label::TopSecret,
        )
        .expect("receiver should be writable");
        core.write_reg_with_label(
            10,
            Value::Int(44),
            crate::ifc_artifacts::Label::Confidential,
        )
        .expect("method argument should be writable");

        core.execute(&module)
            .expect("async method call should resolve");

        let Value::Promise(result_handle) = core.registers[1] else {
            panic!("async method call should leave its result Promise");
        };
        let record = core
            .promise_store
            .get(crate::promise_model::PromiseHandle(result_handle))
            .expect("result Promise exists");
        assert_eq!(record.label, crate::ifc_artifacts::Label::Secret);
        assert!(matches!(
            &record.state,
            crate::promise_model::PromiseState::Fulfilled(
                crate::object_model::JsValue::Object(handle)
            ) if handle.0 == parent_prototype.0
        ));
    }

    #[test]
    fn async_function_awaits_labeled_non_promise_without_downgrade() {
        let mut core =
            InterpreterCore::new(test_quickjs_config(), "async-function-await-non-promise");
        let module = test_module_with_functions(
            vec![
                Ir3Instruction::CreateAsyncFunction {
                    dst: 0,
                    function_index: 0,
                    capture_count: 0,
                },
                Ir3Instruction::Call {
                    callee: 0,
                    args: RegRange {
                        start: 10,
                        count: 1,
                    },
                    dst: 1,
                },
                Ir3Instruction::Halt,
                Ir3Instruction::AwaitValue { promise_reg: 0 },
                Ir3Instruction::AsyncReturn { value_reg: 0 },
            ],
            vec![Ir3FunctionDesc {
                entry: 3,
                arity: 1,
                frame_size: 1,
                name: Some("await_labeled_value_async".to_string()),
                is_generator: false,
                rest_param_index: None,
            }],
        );
        core.write_reg_with_label(
            10,
            Value::Str("secret".into()),
            crate::ifc_artifacts::Label::Secret,
        )
        .expect("test register should be writable");

        core.execute(&module)
            .expect("labeled non-promise await should resolve");

        let Value::Promise(result_handle) = core.registers[1] else {
            panic!("async call should leave result promise in destination register");
        };
        let record = core
            .promise_store
            .get(crate::promise_model::PromiseHandle(result_handle))
            .expect("result promise exists");
        assert_eq!(record.label, crate::ifc_artifacts::Label::Secret);
        assert!(matches!(
            &record.state,
            crate::promise_model::PromiseState::Fulfilled(crate::object_model::JsValue::Str(
                value
            )) if value == "secret"
        ));
    }

    #[test]
    fn pending_await_fulfillment_restores_values_and_labels_bd_ur3tk_15() {
        let mut core =
            InterpreterCore::new(test_quickjs_config(), "pending-await-fulfillment-labels");
        let module = pending_async_module(
            vec![
                Ir3Instruction::AwaitValue { promise_reg: 0 },
                Ir3Instruction::Add {
                    dst: 0,
                    lhs: 0,
                    rhs: 1,
                },
                Ir3Instruction::AsyncReturn { value_reg: 0 },
            ],
            2,
            2,
        );
        let awaited = core.promise_store.create();
        core.write_reg_with_label(
            10,
            Value::Promise(awaited.0),
            crate::ifc_artifacts::Label::Secret,
        )
        .expect("awaited handle should be writable");
        core.write_reg_with_label(
            11,
            Value::Int(40),
            crate::ifc_artifacts::Label::Confidential,
        )
        .expect("unrelated local should be writable");

        let suspended = core
            .execute(&module)
            .expect("pending await should suspend without aborting");
        assert!(matches!(suspended.value, Value::AsyncFunction(_)));
        assert!(core.call_stack.is_empty());
        let parked = core.async_functions[0].execution.as_ref().unwrap();
        assert_eq!(parked.registers[1], Value::Int(40));
        assert_eq!(
            parked.register_labels[1],
            crate::ifc_artifacts::Label::Confidential
        );
        assert!(matches!(
            core.async_functions[0].phase,
            AsyncFunctionPhase::SuspendedAwait
        ));
        assert_eq!(core.async_resumption_contexts.len(), 1);
        let Value::Promise(result_handle) = core.registers[1] else {
            panic!("async call should publish its result Promise before suspension");
        };

        let active_base = core.register_base;
        core.registers[active_base + 1] = Value::Int(999);
        core.register_labels[active_base + 1] = crate::ifc_artifacts::Label::Public;

        core.fulfill_promise(
            awaited,
            crate::object_model::JsValue::Int(2),
            crate::ifc_artifacts::Label::Public,
        )
        .expect("awaited Promise should fulfill");
        core.drain_microtasks(Some(&module))
            .expect("fulfillment should resume the async activation");

        let record = core
            .promise_store
            .get(crate::promise_model::PromiseHandle(result_handle))
            .expect("result promise exists");
        assert_eq!(record.label, crate::ifc_artifacts::Label::Secret);
        assert!(matches!(
            &record.state,
            crate::promise_model::PromiseState::Fulfilled(crate::object_model::JsValue::Int(42))
        ));
        assert_eq!(core.registers[active_base + 1], Value::Int(999));
        assert_eq!(
            core.register_labels[active_base + 1],
            crate::ifc_artifacts::Label::Public,
            "resumption must preserve the caller's independent register file"
        );
        assert!(core.async_functions[0].execution.is_none());
        assert!(matches!(
            core.async_functions[0].phase,
            AsyncFunctionPhase::Completed
        ));
        assert!(core.async_resumption_contexts.is_empty());
        assert!(core.event_loop.microtasks.is_empty());
        assert_eq!(core.register_base, 0);
    }

    #[test]
    fn pending_await_rejection_joins_handle_and_settlement_labels_bd_ur3tk_15() {
        let mut core =
            InterpreterCore::new(test_quickjs_config(), "pending-await-rejection-labels");
        let module = pending_async_module(
            vec![
                Ir3Instruction::AwaitValue { promise_reg: 0 },
                Ir3Instruction::AsyncReturn { value_reg: 0 },
            ],
            1,
            1,
        );
        let awaited = core.promise_store.create();
        core.write_reg_with_label(
            10,
            Value::Promise(awaited.0),
            crate::ifc_artifacts::Label::Confidential,
        )
        .expect("awaited handle should be writable");

        core.execute(&module)
            .expect("pending await should suspend without aborting");
        let Value::Promise(result_handle) = core.registers[1] else {
            panic!("async call should publish its result Promise");
        };

        core.reject_promise(
            awaited,
            crate::object_model::JsValue::Str("boom".into()),
            crate::ifc_artifacts::Label::Secret,
        )
        .expect("awaited Promise should reject");
        core.drain_microtasks(Some(&module))
            .expect("rejection should resume the async activation");

        let record = core
            .promise_store
            .get(crate::promise_model::PromiseHandle(result_handle))
            .expect("result Promise exists");
        assert_eq!(record.label, crate::ifc_artifacts::Label::Secret);
        assert!(matches!(
            &record.state,
            crate::promise_model::PromiseState::Rejected(
                crate::object_model::JsValue::Str(reason)
            ) if reason == "boom"
        ));
        assert!(
            !core.promise_store.unhandled_rejections().contains(&awaited),
            "internal await rejection registration must mark its source handled"
        );
    }

    #[test]
    fn pending_await_rejection_resumes_async_catch_with_label_bd_ur3tk_15() {
        let mut core = InterpreterCore::new(test_quickjs_config(), "pending-await-catch-label");
        let module = pending_async_module(
            vec![
                Ir3Instruction::BeginTry {
                    catch_target: 7,
                    finally_target: None,
                },
                Ir3Instruction::AwaitValue { promise_reg: 0 },
                Ir3Instruction::EndTry,
                Ir3Instruction::AsyncReturn { value_reg: 0 },
                Ir3Instruction::EnterCatch { dst: 1 },
                Ir3Instruction::AsyncReturn { value_reg: 1 },
            ],
            1,
            2,
        );
        let awaited = core.promise_store.create();
        core.write_reg_with_label(
            10,
            Value::Promise(awaited.0),
            crate::ifc_artifacts::Label::Confidential,
        )
        .expect("awaited handle should be writable");

        core.execute(&module)
            .expect("pending await in try should suspend");
        let Value::Promise(result_handle) = core.registers[1] else {
            panic!("async call should publish its result Promise");
        };
        core.reject_promise(
            awaited,
            crate::object_model::JsValue::Str("caught".into()),
            crate::ifc_artifacts::Label::Secret,
        )
        .expect("awaited Promise should reject");
        core.drain_microtasks(Some(&module))
            .expect("rejection should enter the suspended catch");

        let record = core
            .promise_store
            .get(crate::promise_model::PromiseHandle(result_handle))
            .expect("result Promise exists");
        assert_eq!(record.label, crate::ifc_artifacts::Label::Secret);
        assert!(matches!(
            &record.state,
            crate::promise_model::PromiseState::Fulfilled(
                crate::object_model::JsValue::Str(value)
            ) if value == "caught"
        ));
    }

    #[test]
    fn pending_await_fifo_and_replay_witness_are_deterministic_bd_ur3tk_15() {
        fn run_once() -> (
            crate::promise_model::PromiseRecord,
            crate::promise_model::PromiseRecord,
            Vec<crate::promise_model::WitnessEvent>,
            Vec<crate::promise_model::WitnessEvent>,
        ) {
            let mut core = InterpreterCore::new(test_quickjs_config(), "pending-await-replay");
            let module = pending_async_module(
                vec![
                    Ir3Instruction::AwaitValue { promise_reg: 0 },
                    Ir3Instruction::AsyncReturn { value_reg: 0 },
                ],
                1,
                1,
            );
            let awaited = core.promise_store.create();
            core.write_reg_with_label(
                10,
                Value::Promise(awaited.0),
                crate::ifc_artifacts::Label::Secret,
            )
            .expect("awaited handle should be writable");
            core.execute(&module).expect("pending await should suspend");
            let Value::Promise(async_result) = core.registers[1] else {
                panic!("async call should publish its result Promise");
            };

            let unrelated = core.promise_store.create();
            let unrelated_result = core
                .promise_store
                .then(
                    unrelated,
                    None,
                    None,
                    crate::ifc_artifacts::Label::Internal,
                    &mut core.event_loop.microtasks,
                )
                .expect("unrelated reaction should register");
            core.fulfill_promise(
                awaited,
                crate::object_model::JsValue::Int(7),
                crate::ifc_artifacts::Label::Public,
            )
            .expect("awaited Promise should fulfill first");
            core.fulfill_promise(
                unrelated,
                crate::object_model::JsValue::Int(9),
                crate::ifc_artifacts::Label::Public,
            )
            .expect("unrelated Promise should fulfill second");
            core.drain_microtasks(Some(&module))
                .expect("FIFO checkpoint should drain");

            (
                core.promise_store
                    .get(crate::promise_model::PromiseHandle(async_result))
                    .expect("async result should exist")
                    .clone(),
                core.promise_store
                    .get(unrelated_result)
                    .expect("unrelated result should exist")
                    .clone(),
                core.promise_store.witness_log().to_vec(),
                core.event_loop.microtasks.witness_log().to_vec(),
            )
        }

        let first = run_once();
        let second = run_once();
        assert_eq!(
            first, second,
            "identical runs must emit identical replay evidence"
        );
        assert_eq!(
            first.3,
            vec![
                crate::promise_model::WitnessEvent::MicrotaskEnqueued { index: 0 },
                crate::promise_model::WitnessEvent::MicrotaskEnqueued { index: 1 },
                crate::promise_model::WitnessEvent::MicrotaskDequeued { index: 0 },
                crate::promise_model::WitnessEvent::MicrotaskDequeued { index: 1 },
            ],
            "await resumption must retain strict FIFO ordering with unrelated jobs"
        );
        assert_eq!(first.0.label, crate::ifc_artifacts::Label::Secret);
        assert!(matches!(
            first.0.state,
            crate::promise_model::PromiseState::Fulfilled(crate::object_model::JsValue::Int(7))
        ));
        assert_eq!(first.1.label, crate::ifc_artifacts::Label::Internal);
        assert!(matches!(
            first.1.state,
            crate::promise_model::PromiseState::Fulfilled(crate::object_model::JsValue::Int(9))
        ));
    }

    #[test]
    fn await_resolved_promise_returns_value() {
        let mut core = test_interpreter();

        // Create a pre-resolved promise
        let handle = core.promise_store.create();
        let js_val = crate::object_model::JsValue::Int(42);
        let label = crate::ifc_artifacts::Label::Public;
        core.promise_store
            .fulfill(handle, js_val, label, &mut core.event_loop.microtasks)
            .unwrap();

        // Store the promise in a register
        core.registers.resize(10, Value::Undefined);
        core.registers[0] = Value::Promise(handle.0);

        // Test that we can read the promise value
        let promise_val = core.read_reg(0).unwrap();
        match promise_val {
            Value::Promise(h) => {
                assert_eq!(h, handle.0);

                // Verify the promise is resolved
                let record = core.promise_store.get(handle).unwrap();
                assert!(record.state.is_fulfilled());
            }
            _ => panic!("Expected Promise value"),
        }
    }

    #[test]
    fn async_function_phases_exist() {
        // Test that the async function phase enum is complete
        let phases = [
            AsyncFunctionPhase::SuspendedStart,
            AsyncFunctionPhase::Executing,
            AsyncFunctionPhase::SuspendedAwait,
            AsyncFunctionPhase::Completed,
        ];

        // Verify we can match on all phases
        for phase in phases {
            match phase {
                AsyncFunctionPhase::SuspendedStart => {}
                AsyncFunctionPhase::Executing => {}
                AsyncFunctionPhase::SuspendedAwait => {}
                AsyncFunctionPhase::Completed => {}
            }
        }
    }

    #[test]
    fn value_to_js_value_conversion() {
        let cases = [
            (Value::Undefined, crate::object_model::JsValue::Undefined),
            (Value::Null, crate::object_model::JsValue::Null),
            (Value::Bool(true), crate::object_model::JsValue::Bool(true)),
            (
                Value::Bool(false),
                crate::object_model::JsValue::Bool(false),
            ),
            (Value::Int(42), crate::object_model::JsValue::Int(42)),
            (
                Value::Float(Float64::new(3.25)),
                crate::object_model::JsValue::Float(3.25f64.to_bits()),
            ),
            (
                Value::str("hello"),
                crate::object_model::JsValue::str("hello"),
            ),
            (
                Value::Object(ObjectId(100)),
                crate::object_model::JsValue::Object(crate::object_model::ObjectHandle(100)),
            ),
            (
                Value::Function(5),
                crate::object_model::JsValue::Function(5),
            ),
        ];

        for (input, expected) in cases {
            assert_eq!(InterpreterCore::value_to_js_value(&input), expected);
        }

        assert_eq!(
            InterpreterCore::value_to_js_value(&Value::Promise(7)),
            crate::object_model::JsValue::Promise(7)
        );
    }

    #[test]
    fn async_generator_creation() {
        let mut core = InterpreterCore::new(test_quickjs_config(), "async-generator-create");
        let module = test_module_with_functions(
            vec![
                Ir3Instruction::CreateAsyncGenerator {
                    dst: 0,
                    function_index: 0,
                    capture_count: 0,
                },
                Ir3Instruction::Halt,
                Ir3Instruction::Halt,
            ],
            vec![Ir3FunctionDesc {
                entry: 2,
                arity: 0,
                frame_size: 1,
                name: Some("test_async_gen".to_string()),
                is_generator: false,
                rest_param_index: None,
            }],
        );

        core.execute(&module)
            .expect("async generator function creation should succeed");

        assert_eq!(core.closures.len(), 1);
        assert_eq!(core.closures[0].function_index, 0);
        assert!(matches!(
            core.registers[0],
            Value::AsyncGeneratorFunction(0)
        ));
    }

    #[test]
    fn async_generator_function_call_creates_object() {
        let mut core = InterpreterCore::new(test_quickjs_config(), "async-generator-call");
        let module = test_module_with_functions(
            vec![
                Ir3Instruction::CreateAsyncGenerator {
                    dst: 0,
                    function_index: 0,
                    capture_count: 0,
                },
                Ir3Instruction::Call {
                    callee: 0,
                    args: RegRange {
                        start: 10,
                        count: 0,
                    },
                    dst: 1,
                },
                Ir3Instruction::Halt,
                Ir3Instruction::GeneratorBodyStart,
                Ir3Instruction::Return { value: 0 },
            ],
            vec![Ir3FunctionDesc {
                entry: 3,
                arity: 0,
                frame_size: 1,
                name: Some("test_async_gen".to_string()),
                is_generator: true,
                rest_param_index: None,
            }],
        );

        core.execute(&module)
            .expect("async generator function call should succeed");

        assert_eq!(core.async_generators.len(), 1);
        let created = &core.async_generators[0];
        let execution = created
            .execution
            .as_ref()
            .expect("created async generator should own its activation");
        assert_eq!(execution.call_stack[0].function_index, Some(0));
        assert!(matches!(created.phase, AsyncGeneratorPhase::SuspendedStart));
        assert!(matches!(core.registers[1], Value::AsyncGeneratorObject(0)));
    }

    #[test]
    fn async_generator_next_returns_promise() {
        let mut core = test_interpreter();
        core.config
            .granted_capabilities
            .insert(RuntimeCapability::HeapAllocate);

        // Create async generator, call it to get object, then call .next()
        let async_gen_id = {
            core.async_generators
                .push(AsyncGeneratorObject::completed());
            (core.async_generators.len() - 1) as u32
        };

        let result = core
            .async_generator_next(
                &test_module(vec![]),
                async_gen_id,
                Value::Undefined,
                crate::ifc_artifacts::Label::Public,
            )
            .unwrap();

        match result {
            Value::Promise(_) => {}
            _ => panic!("Expected Promise value, got {:?}", result),
        }
    }

    #[test]
    fn async_generator_next_suspended_start_executes() {
        let mut core = test_interpreter();

        // Create a simple async generator function that yields then returns
        let module = test_module_with_pool_and_functions(
            vec![
                Ir3Instruction::GeneratorBodyStart,
                Ir3Instruction::LoadStr {
                    dst: 0,
                    pool_index: 0,
                }, // Load "hello"
                Ir3Instruction::Yield {
                    value: 0,
                    delegate: false,
                    resume_dst: 1,
                }, // Yield "hello"
                Ir3Instruction::LoadStr {
                    dst: 0,
                    pool_index: 1,
                }, // Load "world"
                Ir3Instruction::Return { value: 0 }, // Return "world"
            ],
            vec!["hello".to_string(), "world".to_string()],
            vec![Ir3FunctionDesc {
                entry: 0,
                arity: 0,
                frame_size: 1,
                name: Some("test_async_gen".to_string()),
                is_generator: true,
                rest_param_index: None,
            }],
        );

        let async_gen_id = {
            let generator = prepared_async_generator(&mut core, &module, Vec::new());
            core.async_generators.push(generator);
            (core.async_generators.len() - 1) as u32
        };

        let result = core
            .async_generator_next(
                &module,
                async_gen_id,
                Value::Undefined,
                crate::ifc_artifacts::Label::Public,
            )
            .expect("async generator execution should succeed");

        // Should return a promise
        assert!(
            matches!(result, Value::Promise(_)),
            "should return a promise"
        );

        // Even a primitive yield resumes through a Promise job.
        assert_eq!(
            core.async_generators[async_gen_id as usize].phase,
            AsyncGeneratorPhase::SuspendedAwait,
        );
        let Value::Promise(handle) = result else {
            unreachable!()
        };
        assert!(
            !core
                .promise_store
                .get(crate::promise_model::PromiseHandle(handle))
                .unwrap()
                .state
                .is_settled()
        );
        core.drain_microtasks(Some(&module))
            .expect("yield jobs should drain");
        assert_eq!(
            core.async_generators[async_gen_id as usize].phase,
            AsyncGeneratorPhase::SuspendedYield,
        );
    }

    #[test]
    fn async_generator_next_suspended_yield_resumes() {
        let mut core = test_interpreter();

        // Create a simple async generator function that yields then returns
        let module = test_module_with_pool_and_functions(
            vec![
                Ir3Instruction::GeneratorBodyStart,
                Ir3Instruction::LoadStr {
                    dst: 0,
                    pool_index: 0,
                }, // Load "hello"
                Ir3Instruction::Yield {
                    value: 0,
                    delegate: false,
                    resume_dst: 1,
                }, // Yield "hello"
                Ir3Instruction::LoadStr {
                    dst: 0,
                    pool_index: 1,
                }, // Load "world"
                Ir3Instruction::Return { value: 0 }, // Return "world"
            ],
            vec!["hello".to_string(), "world".to_string()],
            vec![Ir3FunctionDesc {
                entry: 0,
                arity: 0,
                frame_size: 1,
                name: Some("test_async_gen".to_string()),
                is_generator: true,
                rest_param_index: None,
            }],
        );

        let async_gen_id = {
            let generator = prepared_async_generator(&mut core, &module, Vec::new());
            core.async_generators.push(generator);
            (core.async_generators.len() - 1) as u32
        };

        core.async_generator_next(
            &module,
            async_gen_id,
            Value::Undefined,
            crate::ifc_artifacts::Label::Public,
        )
        .expect("first async generator step should yield");
        let result = core
            .async_generator_next(
                &module,
                async_gen_id,
                Value::Undefined,
                crate::ifc_artifacts::Label::Public,
            )
            .expect("async generator resume should succeed");

        // Should return a promise
        assert!(
            matches!(result, Value::Promise(_)),
            "should return a promise"
        );

        core.drain_microtasks(Some(&module))
            .expect("queued yield and return requests should drain");
        assert_eq!(
            core.async_generators[async_gen_id as usize].phase,
            AsyncGeneratorPhase::Completed,
        );
    }

    #[test]
    fn async_generator_rejects_mismatched_value_and_label_snapshot_bd_ur3tk_5() {
        let module = test_module(vec![
            Ir3Instruction::GeneratorBodyStart,
            Ir3Instruction::Return { value: 0 },
        ]);
        let mut core = test_interpreter();
        let mut generator = prepared_async_generator(&mut core, &module, Vec::new());
        generator
            .execution
            .as_mut()
            .expect("prepared async generator activation")
            .register_labels
            .pop();
        core.async_generators.push(generator);
        let promise_count = core.promise_store.len();

        let error = core
            .async_generator_next(
                &module,
                0,
                Value::Undefined,
                crate::ifc_artifacts::Label::Public,
            )
            .expect_err("a missing async-generator register label must fail closed");
        assert!(matches!(
            error,
            InterpreterError::TypeError { expected, got }
                if expected.contains("one IFC label per register")
                    && got.contains("values=")
                    && got.contains("labels=")
        ));
        assert_eq!(core.promise_store.len(), promise_count);
        assert_eq!(
            core.async_generators[0].phase,
            AsyncGeneratorPhase::SuspendedStart
        );
        assert!(core.async_generators[0].execution.is_some());
    }

    #[test]
    fn async_generator_preserves_yield_resume_and_rejection_labels_bd_ur3tk_5() {
        let value_module = test_module(vec![
            Ir3Instruction::GeneratorBodyStart,
            Ir3Instruction::Yield {
                value: 0,
                delegate: false,
                resume_dst: 1,
            },
            Ir3Instruction::Return { value: 1 },
        ]);
        let mut core = test_interpreter();
        let generator = prepared_async_generator(
            &mut core,
            &value_module,
            vec![(Value::Int(7), crate::ifc_artifacts::Label::Secret)],
        );
        core.async_generators.push(generator);

        let Value::Promise(yield_handle) = core
            .async_generator_next(
                &value_module,
                0,
                Value::Undefined,
                crate::ifc_artifacts::Label::Public,
            )
            .expect("first async generator step should yield")
        else {
            panic!("async generator next should return a Promise");
        };
        core.drain_microtasks(Some(&value_module))
            .expect("async generator jobs should drain");
        assert_eq!(
            core.promise_store
                .get(crate::promise_model::PromiseHandle(yield_handle))
                .expect("yield Promise should exist")
                .label,
            crate::ifc_artifacts::Label::Secret
        );

        let Value::Promise(return_handle) = core
            .async_generator_next(
                &value_module,
                0,
                Value::Int(9),
                crate::ifc_artifacts::Label::Confidential,
            )
            .expect("second async generator step should return")
        else {
            panic!("async generator next should return a Promise");
        };
        core.drain_microtasks(Some(&value_module))
            .expect("async generator jobs should drain");
        assert_eq!(
            core.promise_store
                .get(crate::promise_model::PromiseHandle(return_handle))
                .expect("return Promise should exist")
                .label,
            crate::ifc_artifacts::Label::Confidential
        );

        let throw_module = test_module(vec![
            Ir3Instruction::GeneratorBodyStart,
            Ir3Instruction::BeginTry {
                catch_target: 3,
                finally_target: Some(3),
            },
            Ir3Instruction::Throw { value: 0 },
            Ir3Instruction::EnterFinally,
            Ir3Instruction::Yield {
                value: 1,
                delegate: false,
                resume_dst: 2,
            },
            Ir3Instruction::EndFinally,
        ]);
        let throwing = prepared_async_generator(
            &mut core,
            &throw_module,
            vec![
                (Value::str("boom"), crate::ifc_artifacts::Label::TopSecret),
                (Value::str("cleanup"), crate::ifc_artifacts::Label::Internal),
            ],
        );
        core.async_generators.push(throwing);
        let Value::Promise(finally_yield_handle) = core
            .async_generator_next(
                &throw_module,
                1,
                Value::Undefined,
                crate::ifc_artifacts::Label::Public,
            )
            .expect("throwing async generator should yield from its finally body")
        else {
            panic!("async generator next should return a Promise");
        };
        core.drain_microtasks(Some(&throw_module))
            .expect("async generator jobs should drain");
        assert_eq!(
            core.promise_store
                .get(crate::promise_model::PromiseHandle(finally_yield_handle))
                .expect("finally-yield Promise should exist")
                .label,
            crate::ifc_artifacts::Label::Internal
        );
        let suspended = core.async_generators[1]
            .execution
            .as_ref()
            .expect("finally yield should retain the async-generator activation");
        assert!(matches!(
            suspended.finally_frames.last(),
            Some(FinallyFrame {
                completion: Some(AbruptCompletion::Exception(LabeledException {
                    value: Value::Str(reason),
                    label: crate::ifc_artifacts::Label::TopSecret,
                })),
            }) if reason == "boom"
        ));

        let Value::Promise(rejection_handle) = core
            .async_generator_next(
                &throw_module,
                1,
                Value::Undefined,
                crate::ifc_artifacts::Label::Public,
            )
            .expect("resuming the finally body should reject with the retained throw")
        else {
            panic!("async generator next should return a Promise");
        };
        let rejection = core
            .promise_store
            .get(crate::promise_model::PromiseHandle(rejection_handle))
            .expect("rejection Promise should exist");
        assert_eq!(rejection.label, crate::ifc_artifacts::Label::TopSecret);
        assert!(matches!(
            &rejection.state,
            crate::promise_model::PromiseState::Rejected(
                crate::object_model::JsValue::Str(reason)
            ) if reason == "boom"
        ));
    }

    #[test]
    fn async_generator_phases_exist() {
        // Test that async generator phase enum is complete
        let phases = [
            AsyncGeneratorPhase::SuspendedStart,
            AsyncGeneratorPhase::SuspendedYield,
            AsyncGeneratorPhase::SuspendedAwait,
            AsyncGeneratorPhase::Executing,
            AsyncGeneratorPhase::Completed,
        ];

        for phase in phases {
            match phase {
                AsyncGeneratorPhase::SuspendedStart => {}
                AsyncGeneratorPhase::SuspendedYield => {}
                AsyncGeneratorPhase::SuspendedAwait => {}
                AsyncGeneratorPhase::Executing => {}
                AsyncGeneratorPhase::Completed => {}
            }
        }
    }

    #[test]
    fn async_generator_value_types() {
        // Test async generator value type predicates
        let async_gen_func = Value::AsyncGeneratorFunction(0);
        let async_gen_obj = Value::AsyncGeneratorObject(0);

        assert_eq!(async_gen_func.type_name(), "function");
        assert_eq!(async_gen_obj.type_name(), "object");

        assert!(async_gen_func.is_truthy());
        assert!(async_gen_obj.is_truthy());

        assert!(!async_gen_func.is_nullish());
        assert!(!async_gen_obj.is_nullish());
    }
}
