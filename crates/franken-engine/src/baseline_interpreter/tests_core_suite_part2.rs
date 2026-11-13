#[allow(unused_imports)]
use super::*;
#[allow(unused_imports)]
use crate::baseline_interpreter::*;
#[allow(unused_imports)]
use crate::ir_contract::{
    CapabilityTag, Ir3FunctionDesc, IrHeader, IrLevel, IrSchemaVersion, RegRange,
};
#[allow(unused_imports)]
use std::sync::{Arc, Mutex};

#[test]
fn exact_active_empty_array_length_growth_is_memory_exact_bd_b12xs_5() {
    let mut core = quickjs_test_core();
    let array = core
        .alloc_array_with_prototype(None)
        .expect("empty array allocation should succeed");
    let exact = JsString::from_code_units(&[0xD800]);
    core.set_object_runtime_property(array, RuntimePropertyKey::String(exact), Value::Int(8))
        .expect("exact array property should fit");
    core.set_object_runtime_property(
        array,
        RuntimePropertyKey::String(JsString::from("0")),
        Value::Int(1),
    )
    .expect("first array index should fit");
    core.maintain_array_index_assignment(array, 0)
        .expect("first array index should grow length");

    assert_eq!(
        core.heap[array.0 as usize].properties.get("length"),
        Some(&Value::Int(1))
    );
    assert_eq!(core.heap[array.0 as usize].cached_dense_length, None);
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes(),
        "exact-active length insertion must account both order sidecars"
    );
}

#[test]
fn exact_active_collection_backing_stays_memory_exact_bd_b12xs_5() {
    let mut core = quickjs_test_core();
    let entries = core
        .alloc_object_with_prototype(None)
        .expect("Map backing allocation should succeed");
    let map = core
        .alloc_object_with_prototype(None)
        .expect("Map allocation should succeed");
    core.set_object_brand(map, "Map")
        .expect("Map type tag should fit");
    core.set_collection_storage(map, entries)
        .expect("Map backing link should fit");
    let exact = JsString::from_code_units(&[0xD800]);
    core.set_object_runtime_property(
        entries,
        RuntimePropertyKey::String(exact.clone()),
        Value::Int(8),
    )
    .expect("exact backing property should fit");

    core.map_collection_set(map, Value::str("direct"), Value::Int(1))
        .expect("receiver-aware Map.set should fit");
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
    core.mutate_heap(|heap| heap[entries.0 as usize].is_frozen = true);
    assert!(
        !core
            .collection_delete(map, "Map", &Value::str("direct"))
            .expect("frozen backing deletion should fail closed")
    );
    assert_eq!(core.collection_size(map, "Map"), Some(1));
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
    core.mutate_heap(|heap| heap[entries.0 as usize].is_frozen = false);
    assert!(
        core.collection_delete(map, "Map", &Value::str("direct"))
            .expect("unfrozen backing deletion should succeed")
    );
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );

    core.write_reg(0, Value::Object(map))
        .expect("legacy Map receiver register should fit");
    core.write_reg(1, Value::str("legacy"))
        .expect("legacy Map key register should fit");
    core.write_reg(2, Value::Int(2))
        .expect("legacy Map value register should fit");
    core.dispatch_builtin_hostcall(
        "builtin:MapPrototypeSet",
        RegRange { start: 0, count: 3 },
        None,
    )
    .expect("legacy Map.set dispatch should share exact-aware accounting");
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
    assert_eq!(
        core.dispatch_builtin_hostcall(
            "builtin:MapPrototypeDelete",
            RegRange { start: 0, count: 2 },
            None,
        )
        .expect("legacy Map.delete dispatch should share exact-aware accounting"),
        Value::Bool(true)
    );
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );

    core.map_collection_set(map, Value::str("clear-me"), Value::Int(3))
        .expect("ordinary entry before exact-aware clear should fit");
    core.collection_clear(map, "Map")
        .expect("Map.clear should release ordinary and exact backing keys");
    assert!(core.heap[entries.0 as usize].properties.exact_is_empty());
    assert_eq!(core.collection_size(map, "Map"), Some(0));
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn exact_property_edges_participate_in_state_capture_bd_b12xs_5() {
    let mut core = quickjs_test_core();
    let root = core
        .alloc_object_with_prototype(None)
        .expect("root allocation should succeed");
    let child = core
        .alloc_object_with_prototype(None)
        .expect("child allocation should succeed");
    core.set_object_runtime_property(
        root,
        RuntimePropertyKey::String(JsString::from_code_units(&[0xD800])),
        Value::Object(child),
    )
    .expect("exact object edge should fit");
    core.write_reg(0, Value::Object(root))
        .expect("root register should fit");
    core.set_register_label(0, Label::Secret)
        .expect("root label should fit");

    let sources = core.capture_heap_label_sources();
    assert_eq!(sources[root.0 as usize], Some(0));
    assert_eq!(
        sources[child.0 as usize],
        Some(0),
        "state capture must traverse object references stored under exact-only keys"
    );
}

#[test]
fn private_collection_storage_round_trips_without_guest_properties() {
    let mut core = quickjs_test_core();
    let (map, map_storage) = core.alloc_empty_map().expect("allocate Map");
    let set = core.alloc_empty_set().expect("allocate Set");
    core.map_collection_set(map, Value::str("key"), Value::Object(set))
        .expect("insert Map entry");
    core.set_collection_add(set, Value::Object(map))
        .expect("insert Set entry");
    let set_storage = core.collection_storage_id(set, "Set").unwrap();
    let original: Vec<_> = core.heap.iter().cloned().collect();
    let encoded = serde_json::to_string(&original).expect("serialize heap");
    let restored: Vec<HeapObject> = serde_json::from_str(&encoded).expect("deserialize heap");
    assert_eq!(restored, original);
    assert_eq!(
        restored[map.0 as usize].collection_storage.as_deref(),
        Some(&map_storage)
    );
    assert_eq!(
        restored[set.0 as usize].collection_storage.as_deref(),
        Some(&set_storage)
    );
    assert!(restored[map.0 as usize].properties.is_empty());
    assert!(restored[set.0 as usize].properties.is_empty());
    assert_eq!(
        restored[map_storage.0 as usize]
            .properties
            .get(&InterpreterCore::collection_key_repr(&Value::str("key"))),
        Some(&Value::Object(set))
    );
    assert_eq!(
        restored[set_storage.0 as usize]
            .properties
            .get(&InterpreterCore::collection_key_repr(&Value::Object(map))),
        Some(&Value::Object(map))
    );
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn private_collection_storage_and_contents_restore_from_execution_seed() {
    let mut core = quickjs_test_core();
    let (map, map_storage) = core.alloc_empty_map().expect("allocate Map");
    let set = core.alloc_empty_set().expect("allocate Set");
    let replacement = core
        .alloc_object_with_prototype(None)
        .expect("allocate replacement backing");
    core.map_collection_set(map, Value::str("before"), Value::Int(11))
        .expect("insert Map entry");
    core.set_collection_add(set, Value::Int(22))
        .expect("insert Set entry");
    core.write_reg(0, Value::Object(map)).unwrap();
    core.write_reg(1, Value::Object(set)).unwrap();
    let seed = core
        .capture_execution_seed()
        .expect("capture collection seed");

    // Replacing the private edge must materialize the original seed just as
    // an ordinary property write does; mutations of either backing also roll
    // back, along with the derived size.
    core.set_collection_storage(map, replacement)
        .expect("replace private Map storage");
    core.map_collection_set(map, Value::str("after"), Value::Int(33))
        .expect("insert replacement entry");
    core.collection_clear(set, "Set").expect("clear Set");
    core.set_collection_add(set, Value::Int(44))
        .expect("insert changed Set entry");
    core.set_object_property(map, "__size".into(), Value::Int(99))
        .expect("add ordinary guest property");
    assert!(!seed.is_lazy());
    core.reset_execution_state_from_seed(&seed)
        .expect("restore collection seed");

    assert_eq!(core.collection_storage_id(map, "Map"), Some(map_storage));
    assert_eq!(core.collection_size(map, "Map"), Some(1));
    assert_eq!(core.collection_size(set, "Set"), Some(1));
    assert_eq!(
        core.collection_get(map, "Map", &Value::str("before")),
        Value::Int(11)
    );
    assert!(!core.collection_has(map, "Map", &Value::str("after")));
    assert!(core.collection_has(set, "Set", &Value::Int(22)));
    assert!(!core.collection_has(set, "Set", &Value::Int(44)));
    assert!(!core.heap[map.0 as usize].properties.contains_key("__size"));
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn private_collection_storage_refusal_preserves_heap_and_accounting() {
    let mut core = quickjs_test_core();
    let map = core.alloc_object_with_prototype(None).unwrap();
    let storage = core.alloc_object_with_prototype(None).unwrap();
    core.set_object_brand(map, "Map").unwrap();
    let previous = core.heap[map.0 as usize].clone();
    let before = core.estimated_memory_bytes();
    let limit = core.config.max_total_memory_bytes;
    core.config.max_total_memory_bytes = before + std::mem::size_of::<ObjectId>() as u64 - 1;
    assert!(matches!(
        core.set_collection_storage(map, storage),
        Err(InterpreterError::MemoryBudgetExceeded { .. })
    ));
    assert_eq!(core.heap[map.0 as usize], previous);
    assert_eq!(core.estimated_memory_bytes(), before);

    core.config.max_total_memory_bytes = limit;
    core.set_collection_storage(map, storage).unwrap();
    let installed = core.heap[map.0 as usize].clone();
    let installed_bytes = core.estimated_memory_bytes();
    assert!(core.gc_is_remembered(map));
    assert!(matches!(
        core.set_collection_storage(map, ObjectId(u32::MAX)),
        Err(InterpreterError::ObjectNotFound { .. })
    ));
    assert_eq!(core.heap[map.0 as usize], installed);
    assert_eq!(core.estimated_memory_bytes(), installed_bytes);
    assert_eq!(installed_bytes, core.recompute_estimated_memory_bytes());
}

#[test]
fn private_collection_edges_participate_in_state_capture() {
    let mut core = quickjs_test_core();
    let (map, map_storage) = core.alloc_empty_map().unwrap();
    let set = core.alloc_empty_set().unwrap();
    let value = core.alloc_object_with_prototype(None).unwrap();
    let set_storage = core.collection_storage_id(set, "Set").unwrap();
    core.map_collection_set(map, Value::str("set"), Value::Object(set))
        .unwrap();
    core.set_collection_add(set, Value::Object(value)).unwrap();
    core.write_reg(0, Value::Object(map)).unwrap();
    core.set_register_label(0, Label::Secret).unwrap();

    let sources = core.capture_heap_label_sources();
    for id in [map, map_storage, set, set_storage, value] {
        assert_eq!(
            sources[id.0 as usize],
            Some(0),
            "state capture must follow private collection edge to {id:?}"
        );
    }
}

#[test]
fn alloc_iterator_updates_memory_incrementally() {
    let config = test_quickjs_config();
    let mut core = InterpreterCore::new(config, "iterator-memory-delta");
    let iterator = RuntimeIteratorState::ForIn(RuntimeForInState {
        object_id: ObjectId(0),
        keys: vec![JsString::from("alpha"), JsString::from("beta")],
        next_index: 0,
        deleted_keys: BTreeSet::new(),
        done: false,
        closed: false,
        trace_index: 0,
    });
    let iterator_bytes = InterpreterCore::estimate_iterator_bytes(&iterator);
    let before = core.estimated_memory_bytes();
    let handle = core
        .alloc_iterator(iterator)
        .expect("iterator allocation should fit budget");
    assert_eq!(handle, 0);
    assert_eq!(
        core.estimated_memory_bytes(),
        before.saturating_add(iterator_bytes)
    );
    assert_eq!(
        core.recompute_estimated_memory_bytes(),
        core.estimated_memory_bytes(),
        "iterator allocation delta must match full recompute"
    );
}

#[test]
fn borrowed_scope_declaration_refusal_restores_unique_and_shared_maps() {
    for captured in [false, true] {
        let mut core = quickjs_test_core();
        core.scope_chain.current_mut().unwrap().insert_binding(
            "keep".to_owned(),
            ScopeBinding::with_labeled_state(
                BindingKind::Let,
                Value::str("retained payload"),
                Label::Secret,
                true,
            ),
        );
        if captured {
            core.closures.push(ClosureValue {
                function_index: 0,
                captured_env: core.scope_chain.snapshot(),
            });
        }
        core.sync_estimated_memory_bytes().expect("seed scope");
        let before = core.estimated_memory_bytes();
        let map = Rc::as_ptr(&core.scope_chain.current().unwrap().bindings);
        core.config.max_total_memory_bytes = before;
        let module = test_module_with_pool(
            vec![Ir3Instruction::DeclareBinding {
                name_pool_index: 0,
                kind: BindingKind::Let as u8,
            }],
            vec!["名_declared".to_owned()],
        );

        assert!(matches!(
            core.run_loop(&module),
            Err(InterpreterError::MemoryBudgetExceeded { .. })
        ));
        let frame = core.scope_chain.current().unwrap();
        assert_eq!(Rc::as_ptr(&frame.bindings), map);
        assert!(frame.get("名_declared").is_none());
        let retained = frame.get("keep").unwrap();
        assert_eq!(retained.value().unwrap(), Value::str("retained payload"));
        assert_eq!(retained.label().unwrap(), Label::Secret);
        assert_eq!(core.estimated_memory_bytes(), before);
        assert_eq!(core.recompute_estimated_memory_bytes(), before);
    }
}

#[test]
fn scope_chain_mutations_update_memory_incrementally() {
    let config = test_quickjs_config();
    let mut core = InterpreterCore::new(config, "scope-memory-delta");
    let initial_memory = core.estimated_memory_bytes();

    let previous_scope_bytes = core.scope_chain_memory_bytes();
    core.scope_chain
        .push(core.config.max_scope_depth)
        .expect("scope push should fit depth budget");
    core.apply_scope_chain_memory_delta(previous_scope_bytes)
        .expect("empty scope frame should fit memory budget");
    assert!(core.estimated_memory_bytes() > initial_memory);
    assert_eq!(
        core.recompute_estimated_memory_bytes(),
        core.estimated_memory_bytes(),
        "scope push delta must match full recompute"
    );

    let previous_scope_bytes = core.scope_chain_memory_bytes();
    core.scope_chain
        .current_mut()
        .expect("current scope should exist")
        .declare("payload".to_string(), BindingKind::Let);
    {
        let binding = core
            .scope_chain
            .current_mut()
            .expect("current scope should exist")
            .get_mut("payload")
            .expect("declared binding should exist");
        binding
            .set_state(Value::str("hello world"), true)
            .expect("scope binding update");
    }
    core.apply_scope_chain_memory_delta(previous_scope_bytes)
        .expect("binding growth should fit memory budget");
    assert_eq!(
        core.recompute_estimated_memory_bytes(),
        core.estimated_memory_bytes(),
        "scope binding delta must match full recompute"
    );

    let previous_scope_bytes = core.scope_chain_memory_bytes();
    let popped = core.scope_chain.pop();
    assert!(popped.is_some());
    core.apply_scope_chain_memory_delta(previous_scope_bytes)
        .expect("scope pop should lower committed memory");
    assert_eq!(core.scope_chain.depth(), 1);
    assert_eq!(
        core.recompute_estimated_memory_bytes(),
        core.estimated_memory_bytes(),
        "scope pop delta must match full recompute"
    );
}

#[test]
fn scope_capture_updates_update_memory_incrementally() {
    let config = test_quickjs_config();
    let mut core = InterpreterCore::new(config, "scope-capture-memory-delta");
    core.scope_chain
        .current_mut()
        .expect("current scope should exist")
        .declare("payload".to_string(), BindingKind::Let);
    {
        let binding = core
            .scope_chain
            .current_mut()
            .expect("current scope should exist")
            .get_mut("payload")
            .expect("declared binding should exist");
        binding
            .set_state(Value::str("short"), true)
            .expect("scope binding update");
    }
    core.sync_estimated_memory_bytes()
        .expect("seed scope binding should fit memory budget");

    core.closures.push(ClosureValue {
        function_index: 0,
        captured_env: core.scope_chain.snapshot(),
    });
    core.sync_estimated_memory_bytes()
        .expect("seed closure capture should fit memory budget");

    let previous_scope_bytes = core.scope_chain_memory_bytes();
    let previous_closure_bytes = core.closures_memory_bytes();
    let previous_call_stack_bytes = core.call_stack_memory_bytes();
    let replacement = Value::str("a longer captured payload");
    if let Some((_, binding)) = core.scope_chain.resolve("payload") {
        binding
            .set_state(replacement, true)
            .expect("scope binding update");
        core.closures.refresh_cell(&binding.state);
    }
    core.apply_scope_closure_call_stack_memory_delta(
        previous_scope_bytes,
        previous_closure_bytes,
        previous_call_stack_bytes,
    )
    .expect("scope and closure capture growth should fit memory budget");
    assert_eq!(
        core.recompute_estimated_memory_bytes(),
        core.estimated_memory_bytes(),
        "scope and closure capture deltas must match full recompute"
    );
}

#[test]
fn closure_allocation_updates_memory_incrementally() {
    let config = test_quickjs_config();
    let mut core = InterpreterCore::new(config, "closure-memory-delta");
    core.scope_chain
        .current_mut()
        .expect("current scope should exist")
        .declare("payload".to_string(), BindingKind::Let);
    {
        let binding = core
            .scope_chain
            .current_mut()
            .expect("current scope should exist")
            .get_mut("payload")
            .expect("declared binding should exist");
        binding
            .set_state(Value::str("captured payload"), true)
            .expect("scope binding update");
    }
    core.sync_estimated_memory_bytes()
        .expect("seed scope binding should fit memory budget");

    let closure = ClosureValue {
        function_index: 7,
        captured_env: core.scope_chain.snapshot(),
    };
    // The captured frames are the live chain's, already charged: the
    // closure adds its own structure (bd-9vouw.154).
    let closure_bytes = InterpreterCore::estimate_closure_alias_bytes(&closure);
    let before = core.estimated_memory_bytes();
    let previous_closure_bytes = core.closures_memory_bytes();
    core.closures.push(closure);
    core.apply_closures_memory_delta(previous_closure_bytes)
        .expect("closure allocation should fit memory budget");

    assert_eq!(
        core.estimated_memory_bytes(),
        before.saturating_add(closure_bytes)
    );
    assert_eq!(
        core.recompute_estimated_memory_bytes(),
        core.estimated_memory_bytes(),
        "closure allocation delta must match full recompute"
    );
}

#[test]
fn complete_return_updates_call_components_incrementally() {
    let config = test_quickjs_config();
    let mut core = InterpreterCore::new(config, "return-memory-delta");
    core.scope_chain
        .current_mut()
        .expect("current scope should exist")
        .declare("payload".to_string(), BindingKind::Let);
    {
        let binding = core
            .scope_chain
            .current_mut()
            .expect("current scope should exist")
            .get_mut("payload")
            .expect("declared binding should exist");
        binding
            .set_state(Value::str("short"), true)
            .expect("scope binding update");
    }
    let saved_scope = core.scope_chain.snapshot();
    core.closures.push(ClosureValue {
        function_index: 7,
        captured_env: saved_scope.clone(),
    });

    {
        let binding = core
            .scope_chain
            .current_mut()
            .expect("current scope should exist")
            .get_mut("payload")
            .expect("declared binding should exist");
        binding
            .set_state(Value::str("expanded captured payload"), true)
            .expect("scope binding update");
        core.closures.refresh_cell(&binding.state);
    }
    let pushed_frame = CallFrame {
        return_ip: 123,
        return_reg: 0,
        register_base: 0,
        register_width: core.config.max_registers as usize,
        function_index: Some(7),
        this_value: Value::str("receiver"),
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
        saved_pending_return: None,
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
        .expect("seed call-frame state should fit memory budget");

    let outcome = core
        .complete_return(None, Value::str("done"), Label::Public)
        .expect("return should complete");
    assert_eq!(outcome, None);
    assert_eq!(core.ip, 123);
    assert!(core.call_stack.is_empty());
    assert_eq!(
        core.read_reg(0).expect("return register"),
        Value::str("done")
    );
    assert_eq!(
        core.recompute_estimated_memory_bytes(),
        core.estimated_memory_bytes,
        "call return deltas must match full recompute"
    );
}

#[test]
fn bd_5ilh1_top_level_return_completion_carries_its_label() {
    // The no-call-frame `complete_return` arm must surface the return
    // label, not drop it (the pre-fix behavior returned only the Value).
    let mut core = InterpreterCore::new(test_quickjs_config(), "bd-5ilh1-return");
    let outcome = core
        .complete_return(None, Value::str("tainted"), Label::Secret)
        .expect("top-level return should complete");
    assert_eq!(
        outcome,
        Some(LabeledReturn {
            value: Value::str("tainted"),
            label: Label::Secret,
        })
    );
}

#[test]
fn bd_5ilh1_direct_return_instruction_completion_is_secret_labeled() {
    // Full dispatch path: a Return of a Secret-labeled register must
    // surface a Secret-labeled top-level completion.
    let mut core = InterpreterCore::new(test_quickjs_config(), "bd-5ilh1-dispatch");
    core.write_reg_with_label(1, Value::str("secret payload"), Label::Secret)
        .expect("seed labeled register");
    let completion = core
        .run_loop_labeled(&test_module(vec![Ir3Instruction::Return { value: 1 }]))
        .expect("return should complete");
    assert_eq!(
        completion,
        LabeledReturn {
            value: Value::str("secret payload"),
            label: Label::Secret,
        }
    );
}

#[test]
fn bd_5ilh1_fallthrough_and_halt_completions_read_r0_label() {
    // Fallthrough exit (instruction stream exhausted, no call frames)
    // reads r0 with the label it carries.
    let mut core = InterpreterCore::new(test_quickjs_config(), "bd-5ilh1-fallthrough");
    core.write_reg_with_label(0, Value::Int(7), Label::Secret)
        .expect("seed r0");
    let completion = core
        .run_loop_labeled(&test_module(Vec::new()))
        .expect("fallthrough should complete");
    assert_eq!(
        completion,
        LabeledReturn {
            value: Value::Int(7),
            label: Label::Secret,
        }
    );

    // Halt termination surfaces r0 and its label through
    // finish_execution_result into ExecutionResult.completion_label.
    let result = core
        .finish_execution_result(Err(InterpreterError::Halted))
        .expect("halt is normal termination");
    assert_eq!(result.value, Value::Int(7));
    assert_eq!(result.completion_label, Label::Secret);
}

#[test]
fn bd_5ilh1_containment_interruption_completion_is_public_placeholder() {
    // A containment-hook interruption synthesises an Undefined completion;
    // its label is Public by construction, never stale register taint.
    let mut core = InterpreterCore::new(test_quickjs_config(), "bd-5ilh1-containment");
    core.write_reg_with_label(0, Value::str("residue"), Label::TopSecret)
        .expect("seed residue");
    let result = core.take_execution_result(
        LabeledReturn {
            value: Value::Undefined,
            label: Label::Public,
        },
        None,
    );
    assert_eq!(result.value, Value::Undefined);
    assert_eq!(result.completion_label, Label::Public);
}

#[test]
fn complete_async_frame_updates_call_components_incrementally() {
    let config = test_quickjs_config();
    let mut core = InterpreterCore::new(config, "async-return-memory-delta");
    core.scope_chain
        .current_mut()
        .expect("current scope should exist")
        .declare("payload".to_string(), BindingKind::Let);
    {
        let binding = core
            .scope_chain
            .current_mut()
            .expect("current scope should exist")
            .get_mut("payload")
            .expect("declared binding should exist");
        binding
            .set_state(Value::str("short"), true)
            .expect("scope binding update");
    }
    let saved_scope = core.scope_chain.snapshot();
    core.closures.push(ClosureValue {
        function_index: 7,
        captured_env: saved_scope.clone(),
    });

    {
        let binding = core
            .scope_chain
            .current_mut()
            .expect("current scope should exist")
            .get_mut("payload")
            .expect("declared binding should exist");
        binding
            .set_state(Value::str("expanded async payload"), true)
            .expect("scope binding update");
        core.closures.refresh_cell(&binding.state);
    }
    let result_promise = core.promise_store.create().0;
    let async_function_id = core.async_functions.len() as u32;
    core.async_functions.push(AsyncFunctionObject {
        owner_module: Arc::new(test_module(vec![])),
        isolated_execution: None,
        function_index: 7,
        closure_index: Some(0),
        saved_ip: 0,
        saved_registers: Vec::new(),
        saved_register_labels: Vec::new(),
        saved_register_base: 0,
        phase: AsyncFunctionPhase::Executing,
        result_promise,
    });
    let pushed_frame = CallFrame {
        return_ip: 321,
        return_reg: 0,
        register_base: 0,
        register_width: core.config.max_registers as usize,
        function_index: Some(7),
        this_value: Value::str("receiver"),
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
        saved_pending_return: None,
        saved_suspended_abrupt_depth: 0,
        saved_finally_mode_depth: 0,
        saved_scope_depth: saved_scope.len(),
        saved_scope_chain: Some(saved_scope),
        scope_inert_virtual_scope_bytes: 0,
        async_function_id: Some(async_function_id),
        native_boundary: false,
    };
    core.call_stack
        .push(pushed_frame, &mut core.closures.cold_cells);
    core.sync_estimated_memory_bytes()
        .expect("seed async call-frame state should fit memory budget");

    let frame = core
        .call_stack
        .pop(&mut core.closures.cold_cells)
        .expect("async frame should exist");
    let outcome = core
        .complete_async_frame(None, frame, Ok(Value::str("done")), Label::Public)
        .expect("async completion should settle promise");
    assert_eq!(outcome, None);
    assert_eq!(core.ip, 321);
    assert!(core.call_stack.is_empty());
    assert!(matches!(
        core.async_functions[async_function_id as usize].phase,
        AsyncFunctionPhase::Completed
    ));
    let promise = core
        .promise_store
        .get(crate::promise_model::PromiseHandle(result_promise))
        .expect("async result promise should exist");
    assert_eq!(
        promise.state,
        crate::promise_model::PromiseState::Fulfilled(crate::object_model::JsValue::Str(
            "done".to_string(),
        ))
    );
    assert_eq!(
        core.recompute_estimated_memory_bytes(),
        core.estimated_memory_bytes,
        "async call-frame deltas must match full recompute"
    );
}

#[test]
fn truncating_finally_frames_preserves_outer_owner_and_exact_memory_bd_g73mg() {
    let config = test_quickjs_config();
    let mut core = InterpreterCore::new(config, "finally-depth-prune-memory");
    core.finally_frames = vec![
        FinallyFrame {
            completion: Some(AbruptCompletion::Exception(
                Value::str("retained exception"),
                Label::Custom {
                    name: "retained-label".repeat(8),
                    level: 3,
                },
            )),
        },
        FinallyFrame {
            completion: Some(AbruptCompletion::Return(LabeledReturn {
                value: Value::str("discarded deep return"),
                label: Label::Public,
            })),
        },
    ];
    core.sync_estimated_memory_bytes()
        .expect("seeded completion state should fit memory budget");

    core.truncate_finally_frames(1);

    assert!(matches!(
        core.finally_frames.as_slice(),
        [FinallyFrame {
            completion: Some(AbruptCompletion::Exception(value, Label::Custom { .. }))
        }]
            if value == &Value::str("retained exception")
    ));
    assert_eq!(
        core.recompute_estimated_memory_bytes(),
        core.estimated_memory_bytes,
        "depth pruning must release fixed and dynamic completion bytes exactly"
    );
}

#[test]
fn suspending_throw_moves_custom_label_without_dynamic_memory_duplication_bd_g73mg() {
    let config = test_quickjs_config();
    let mut core = InterpreterCore::new(config, "move-throw-label-memory");
    let custom_name = "iterator-close-label".repeat(64);
    let custom_name_ptr = custom_name.as_ptr();
    core.replace_pending_abrupt_slots(
        Some((
            Value::str("original throw"),
            Label::Custom {
                name: custom_name,
                level: 7,
            },
        )),
        None,
    )
    .expect("pending throw should fit memory budget");
    let before_suspend = core.estimated_memory_bytes;

    core.suspend_current_abrupt_completion()
        .expect("suspension should charge only its fixed carrier");

    assert!(core.pending_exception.is_none());
    assert!(matches!(
        core.suspended_abrupt_completions.last(),
        Some(AbruptCompletion::Exception(_, Label::Custom { name, level: 7 }))
            if name.as_ptr() == custom_name_ptr
    ));
    assert_eq!(
        core.estimated_memory_bytes,
        before_suspend + std::mem::size_of::<AbruptCompletion>() as u64,
        "moving an owned completion must not charge or allocate duplicate dynamic bytes"
    );

    core.restore_suspended_abrupt_completion();
    assert_eq!(core.estimated_memory_bytes, before_suspend);
    assert!(matches!(
        &core.pending_exception_label,
        Label::Custom { name, level: 7 } if name.as_ptr() == custom_name_ptr
    ));
    assert_eq!(
        core.recompute_estimated_memory_bytes(),
        core.estimated_memory_bytes
    );
}

#[test]
fn unwind_call_stack_updates_call_components_incrementally() {
    let config = test_quickjs_config();
    let mut core = InterpreterCore::new(config, "unwind-memory-delta");
    core.scope_chain
        .current_mut()
        .expect("current scope should exist")
        .declare("payload".to_string(), BindingKind::Let);
    {
        let binding = core
            .scope_chain
            .current_mut()
            .expect("current scope should exist")
            .get_mut("payload")
            .expect("declared binding should exist");
        binding
            .set_state(Value::str("short"), true)
            .expect("scope binding update");
    }
    let saved_scope = core.scope_chain.snapshot();
    core.closures.push(ClosureValue {
        function_index: 7,
        captured_env: saved_scope.clone(),
    });

    {
        let binding = core
            .scope_chain
            .current_mut()
            .expect("current scope should exist")
            .get_mut("payload")
            .expect("declared binding should exist");
        binding
            .set_state(Value::str("expanded unwind payload"), true)
            .expect("scope binding update");
        core.closures.refresh_cell(&binding.state);
    }
    core.suspended_abrupt_completions
        .push(AbruptCompletion::Return(LabeledReturn {
            value: Value::str("inner"),
            label: Label::Public,
        }));
    let pushed_frame = CallFrame {
        return_ip: 777,
        return_reg: 0,
        register_base: 4,
        register_width: core.config.max_registers as usize,
        function_index: Some(7),
        this_value: Value::str("receiver"),
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
        saved_pending_exception: Some(Value::str("outer error")),
        saved_pending_exception_label: Label::Public,
        saved_pending_return: None,
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
        .expect("seed unwind call-frame state should fit memory budget");

    let (restored_exception, restored_return) = core
        .unwind_call_stack_to(0)
        .expect("unwind should restore caller state");
    assert_eq!(
        restored_exception.map(|(value, _)| value),
        Some(Value::str("outer error"))
    );
    assert_eq!(restored_return, None);
    assert_eq!(core.register_base, 4);
    assert!(core.call_stack.is_empty());
    assert!(core.suspended_abrupt_completions.is_empty());
    assert_eq!(
        core.recompute_estimated_memory_bytes(),
        core.estimated_memory_bytes,
        "unwind deltas must match full recompute"
    );
}

#[test]
fn rollback_call_setup_updates_call_components_incrementally() {
    let config = test_quickjs_config();
    let mut core = InterpreterCore::new(config, "rollback-call-memory-delta");
    core.scope_chain
        .current_mut()
        .expect("current scope should exist")
        .declare("payload".to_string(), BindingKind::Let);
    {
        let binding = core
            .scope_chain
            .current_mut()
            .expect("current scope should exist")
            .get_mut("payload")
            .expect("declared binding should exist");
        binding
            .set_state(Value::str("caller payload"), true)
            .expect("scope binding update");
    }
    let saved_scope = core.scope_chain.snapshot();
    core.closures.push(ClosureValue {
        function_index: 7,
        captured_env: saved_scope.clone(),
    });

    core.scope_chain
        .push(core.config.max_scope_depth)
        .expect("callee scope should fit depth budget");
    core.scope_chain
        .current_mut()
        .expect("callee scope should exist")
        .declare("payload".to_string(), BindingKind::Let);
    {
        let binding = core
            .scope_chain
            .current_mut()
            .expect("callee scope should exist")
            .get_mut("payload")
            .expect("callee binding should exist");
        binding
            .set_state(Value::str("callee setup payload that must roll back"), true)
            .expect("scope binding update");
    }
    core.suspended_abrupt_completions
        .push(AbruptCompletion::Return(LabeledReturn {
            value: Value::str("inner"),
            label: Label::Public,
        }));
    core.finally_frames.push(FinallyFrame {
        completion: Some(AbruptCompletion::Return(LabeledReturn {
            value: Value::str("owned finalizer return"),
            label: Label::Public,
        })),
    });
    let pushed_frame = CallFrame {
        return_ip: 909,
        return_reg: 0,
        register_base: 8,
        register_width: core.config.max_registers as usize,
        function_index: Some(7),
        this_value: Value::str("receiver"),
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
        saved_pending_exception: Some(Value::str("outer error")),
        saved_pending_exception_label: Label::Public,
        saved_pending_return: None,
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
        .expect("seed rollback call-frame state should fit memory budget");

    core.rollback_call_setup();

    assert!(core.call_stack.is_empty());
    assert!(core.suspended_abrupt_completions.is_empty());
    assert!(core.finally_frames.is_empty());
    assert_eq!(core.pending_exception, Some(Value::str("outer error")));
    let restored_payload = core
        .scope_chain
        .frames
        .last()
        .and_then(|frame| frame.get("payload"))
        .map(|binding| {
            binding
                .value()
                .expect("restored binding should be readable")
        });
    assert_eq!(restored_payload, Some(Value::str("caller payload")));
    assert_eq!(
        core.recompute_estimated_memory_bytes(),
        core.estimated_memory_bytes,
        "rollback deltas must match full recompute"
    );
}

#[test]
fn callable_creation_destination_failures_roll_back_publication() {
    let instructions = [
        Ir3Instruction::CreateClosure {
            dst: 1,
            function_index: 0,
            capture_count: 1,
        },
        Ir3Instruction::CreateGenerator {
            dst: 1,
            function_index: 0,
            capture_count: 1,
        },
        Ir3Instruction::CreateAsyncFunction {
            dst: 1,
            function_index: 0,
            capture_count: 1,
        },
        Ir3Instruction::CreateAsyncGenerator {
            dst: 1,
            function_index: 0,
            capture_count: 1,
        },
    ];

    for instruction in instructions {
        let mut config = test_quickjs_config();
        config.max_registers = 1;
        let mut core = InterpreterCore::new(config, "callable-publication-rollback");
        let module = test_module(vec![instruction, Ir3Instruction::Halt]);
        core.prepare_execution(&module)
            .expect("module setup should succeed");
        core.active_generated_function_artifact = Some(GeneratedFunctionArtifactHandle {
            owner_program_id: ContentHash::compute(b"callable-rollback-owner"),
            artifact_id: ContentHash::compute(b"callable-rollback-artifact"),
        });
        core.pending_captures.push(7);
        core.sync_estimated_memory_bytes()
            .expect("pending capture should fit memory budget");

        let err = core.run_loop(&module).unwrap_err();
        assert!(matches!(
            err,
            InterpreterError::RegisterOutOfBounds {
                register: 1,
                max: 1
            }
        ));
        assert!(core.closures.is_empty());
        assert!(core.closure_module_origins.is_empty());
        assert!(
            core.closure_generated_function_artifacts.is_empty(),
            "failed callable publication must roll back generated-artifact provenance"
        );
        assert_eq!(core.pending_captures, vec![7]);
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }
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
fn retained_module_program_bytes_counts_exact_string_pool_backing_bd_vltnh() {
    let empty = test_module(Vec::new());
    let mut exact = test_module(Vec::new());
    exact.constant_pool = vec![JsString::from_code_units(&[0xD800])];

    let empty_bytes = InterpreterCore::retained_module_program_bytes(&empty, "test");
    let exact_bytes = InterpreterCore::retained_module_program_bytes(&exact, "test");
    let expected_delta = (std::mem::size_of::<JsString>() as u64).saturating_add(
        InterpreterCore::estimate_js_string_bytes(&exact.constant_pool[0]),
    );

    assert_eq!(exact_bytes.saturating_sub(empty_bytes), expected_delta);
}

#[test]
fn retained_module_function_sources_charge_whole_shared_backing() {
    let source: Arc<str> = Arc::from(format!(
        "{}function first() {{}} function second() {{}}",
        " ".repeat(4096)
    ));
    let mut module = test_module(Vec::new());
    let base_bytes = InterpreterCore::retained_module_program_bytes(&module, "test");
    for (index, name) in [(0, "first"), (1, "second")] {
        let start = source.find(&format!("function {name}")).unwrap();
        let end = source[start..].find('}').unwrap() + start + 1;
        module.function_sources.insert(
            index,
            crate::ast::FunctionSourceText::new(Arc::clone(&source), start, end).unwrap(),
        );
    }
    let entry_bytes = MEMORY_ESTIMATE_MAP_ENTRY_BYTES
        + std::mem::size_of::<(u32, crate::ast::FunctionSourceText)>() as u64;
    let backing_bytes = (std::mem::size_of::<[usize; 2]>() + source.len()) as u64;
    assert_eq!(
        InterpreterCore::retained_module_program_bytes(&module, "test") - base_bytes,
        2 * entry_bytes + backing_bytes,
        "two short ranges retain the full whitespace prefix once"
    );
}

#[test]
fn retained_module_function_sources_bound_mixed_owner_accounting_without_allocation() {
    let owners: Vec<Arc<str>> = (0..9).map(|_| Arc::from("function same() {}")).collect();
    assert!(!Arc::ptr_eq(&owners[0], &owners[1]));
    let mut module = test_module(Vec::new());
    for repeat in 0..2 {
        for (index, owner) in owners[..8].iter().enumerate() {
            module.function_sources.insert(
                u32::try_from(repeat * 8 + index).unwrap(),
                crate::ast::FunctionSourceText::new(Arc::clone(owner), 0, owner.len()).unwrap(),
            );
        }
    }
    let entry_bytes = MEMORY_ESTIMATE_MAP_ENTRY_BYTES
        + std::mem::size_of::<(u32, crate::ast::FunctionSourceText)>() as u64;
    let backing_bytes = (std::mem::size_of::<[usize; 2]>() + owners[0].len()) as u64;
    assert_eq!(
        InterpreterCore::retained_module_function_source_bytes(&module),
        16 * entry_bytes + 8 * backing_bytes,
        "equal text from distinct allocations must not be merged"
    );
    for index in [16, 17] {
        module.function_sources.insert(
            index,
            crate::ast::FunctionSourceText::new(Arc::clone(&owners[8]), 0, owners[8].len())
                .unwrap(),
        );
    }
    let bytes = InterpreterCore::retained_module_function_source_bytes(&module);
    assert_eq!(bytes, 18 * entry_bytes + 10 * backing_bytes);
    assert!(
        bytes >= 18 * entry_bytes + 9 * backing_bytes,
        "unremembered duplicate owners may overcharge, never provide free storage"
    );
}

#[test]
fn retained_module_function_source_budget_refusal_is_atomic_and_retryable() {
    let mut module = test_module(vec![Ir3Instruction::Return { value: 0 }]);
    let source: Arc<str> = Arc::from(format!("{}function f() {{}}", " ".repeat(4096)));
    module.function_table.push(Ir3FunctionDesc {
        entry: 0,
        arity: 0,
        frame_size: 1,
        name: Some("f".to_string()),
        is_generator: false,
        rest_param_index: None,
    });
    let specifier = "imported-source-budget.mjs";
    let base_bytes = InterpreterCore::retained_module_program_bytes(&module, specifier);
    module.function_sources.insert(
        0,
        crate::ast::FunctionSourceText::new(Arc::clone(&source), 4096, source.len()).unwrap(),
    );
    let source_bytes = MEMORY_ESTIMATE_MAP_ENTRY_BYTES
        + std::mem::size_of::<(u32, crate::ast::FunctionSourceText)>() as u64
        + (std::mem::size_of::<[usize; 2]>() + source.len()) as u64;
    let retained_bytes = base_bytes + source_bytes;
    let mut core = InterpreterCore::new(test_quickjs_config(), "source-budget");
    core.ensure_module_record(&module, specifier).unwrap();
    assert!(
        core.module_state.modules[specifier]
            .compiled_module
            .is_none()
    );
    let baseline = core.estimated_memory_bytes();
    let heap_before = core.heap_size();
    let events_before = core.events.len();
    assert_eq!(baseline, core.recompute_estimated_memory_bytes());
    core.config.max_total_memory_bytes = baseline + retained_bytes - 1;
    assert!(matches!(
        core.retain_module_program(specifier, &module),
        Err(InterpreterError::MemoryBudgetExceeded { .. })
    ));
    assert!(
        core.module_state.modules[specifier]
            .compiled_module
            .is_none()
    );
    assert_eq!(core.module_state.retained_program_bytes, 0);
    assert_eq!(core.heap_size(), heap_before);
    assert_eq!(core.events.len(), events_before);
    assert_eq!(core.estimated_memory_bytes(), baseline);
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );

    core.config.max_total_memory_bytes = baseline + retained_bytes;
    core.retain_module_program(specifier, &module).unwrap();
    assert!(
        core.module_state.modules[specifier]
            .compiled_module
            .is_some()
    );
    assert_eq!(core.module_state.retained_program_bytes, retained_bytes);
    assert_eq!(core.estimated_memory_bytes(), baseline + retained_bytes);
    core.retain_module_program(specifier, &module).unwrap();
    assert_eq!(core.module_state.retained_program_bytes, retained_bytes);
    assert_eq!(core.estimated_memory_bytes(), baseline + retained_bytes);
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn declare_binding_unknown_kind_fails_closed() {
    let module = test_module_with_pool(
        vec![
            Ir3Instruction::DeclareBinding {
                name_pool_index: 0,
                kind: 99,
            },
            Ir3Instruction::Halt,
        ],
        vec!["future_binding".to_string()],
    );
    let mut core = InterpreterCore::new(test_quickjs_config(), "binding-kind");
    let err = core.execute(&module).unwrap_err();
    assert!(matches!(
        err,
        InterpreterError::TypeError { expected, got }
            if expected == "binding kind 0..=5" && got == "kind 99"
    ));
}

#[test]
fn load_name_distinguishes_typeof_style_missing_from_reference_error() {
    let allow_missing = test_module_with_pool(
        vec![
            Ir3Instruction::LoadName {
                dst: 0,
                name_pool_index: 0,
                allow_missing: true,
            },
            Ir3Instruction::Halt,
        ],
        vec!["bd_0k19b_missing".to_string()],
    );
    assert_eq!(
        quickjs_execute(&allow_missing)
            .expect("allow-missing name load")
            .value,
        Value::Undefined
    );

    let required = test_module_with_pool(
        vec![
            Ir3Instruction::LoadName {
                dst: 0,
                name_pool_index: 0,
                allow_missing: false,
            },
            Ir3Instruction::Halt,
        ],
        vec!["bd_0k19b_missing".to_string()],
    );
    assert!(matches!(
        quickjs_execute(&required),
        Err(InterpreterError::UndefinedBinding { name })
            if name == "bd_0k19b_missing"
    ));
    assert_eq!(
        InterpreterCore::js_catchable_error_name(&InterpreterError::UndefinedBinding {
            name: "bd_0k19b_missing".to_string(),
        }),
        Some("ReferenceError")
    );
}

/// bd-9vouw.487: LoadName of a name the scope chain resolves carries the
/// label the cell holds (as LoadScoped of the same cell does); it used to
/// write the value under the destination register's previous label.
#[test]
fn load_name_of_a_scope_cell_carries_the_cell_label() {
    let module = test_module_with_pool(
        vec![
            Ir3Instruction::DeclareBinding {
                name_pool_index: 0,
                kind: BindingKind::Var as u8,
            },
            Ir3Instruction::StoreScoped {
                src: 0,
                name_pool_index: 0,
            },
            Ir3Instruction::LoadName {
                dst: 1,
                name_pool_index: 0,
                allow_missing: false,
            },
            Ir3Instruction::LoadScoped {
                dst: 2,
                name_pool_index: 0,
            },
            Ir3Instruction::Halt,
        ],
        vec!["bd_9vouw_487_cell".to_string()],
    );
    let mut core = quickjs_test_core();
    core.mutate_registers(|registers| registers[0] = Value::Int(42));
    core.set_register_label(0, Label::Secret)
        .expect("source label should be settable");
    // Both destinations start strictly below Secret: a read that keeps
    // the destination's label leaves them Public.
    core.set_register_label(1, Label::Public)
        .expect("LoadName destination label should be settable");
    core.set_register_label(2, Label::Public)
        .expect("LoadScoped destination label should be settable");
    core.execute(&module).expect("scope cell round trip");

    assert_eq!(core.read_reg(1).expect("LoadName value"), Value::Int(42));
    assert_eq!(
        core.get_register_label(1).expect("LoadName label"),
        &Label::Secret,
        "LoadName carries the cell's label"
    );
    assert_eq!(
        core.get_register_label(2).expect("LoadScoped label"),
        &Label::Secret,
        "LoadScoped of the same cell (the reference behaviour)"
    );
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn global_name_getters_preserve_runtime_result_labels() {
    // Keep the descriptor, receiver and closure Public. Only the value
    // returned by the getter is Secret, through a captured runtime cell.
    // Source-level taint inference cannot mask a missing LoadName join.
    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::DeclareBinding {
                name_pool_index: 0,
                kind: BindingKind::Var as u8,
            },
            Ir3Instruction::CreateClosure {
                dst: 2,
                function_index: 0,
                capture_count: 0,
            },
            Ir3Instruction::StoreScoped {
                src: 0,
                name_pool_index: 0,
            },
            Ir3Instruction::LoadName {
                dst: 3,
                name_pool_index: 1,
                allow_missing: false,
            },
            Ir3Instruction::LoadStr {
                dst: 4,
                pool_index: 2,
            },
            Ir3Instruction::DefineAccessor {
                obj: 3,
                key: 4,
                func: 2,
                kind: AccessorKind::Get,
            },
            Ir3Instruction::LoadInt { dst: 5, value: 7 },
            Ir3Instruction::PutName {
                src: 5,
                name_pool_index: 3,
                strict: false,
            },
            Ir3Instruction::LoadName {
                dst: 6,
                name_pool_index: 2,
                allow_missing: false,
            },
            Ir3Instruction::LoadName {
                dst: 7,
                name_pool_index: 3,
                allow_missing: false,
            },
            Ir3Instruction::LoadName {
                dst: 8,
                name_pool_index: 4,
                allow_missing: true,
            },
            Ir3Instruction::Halt,
            Ir3Instruction::LoadScoped {
                dst: 0,
                name_pool_index: 0,
            },
            Ir3Instruction::Return { value: 0 },
        ],
        vec![
            "global_getter_secret_cell".to_string(),
            "globalThis".to_string(),
            "global_getter_classified_value".to_string(),
            "global_getter_public_value".to_string(),
            "global_getter_missing_value".to_string(),
        ],
    );
    module.function_table.push(Ir3FunctionDesc {
        entry: 12,
        arity: 0,
        frame_size: 1,
        name: Some("classified_global_getter".to_string()),
        is_generator: false,
        rest_param_index: None,
    });
    let mut core = quickjs_test_core();
    core.mutate_registers(|registers| registers[0] = Value::Int(42));
    core.set_register_label(0, Label::Secret)
        .expect("seed classified runtime cell");
    core.execute(&module).expect("read global accessor");

    assert_eq!(core.get_register_label(2).unwrap(), &Label::Public);
    assert_eq!(core.get_register_label(3).unwrap(), &Label::Public);
    let Value::Object(global) = core.read_reg(3).unwrap() else {
        panic!("globalThis must be an object");
    };
    assert_eq!(
        core.runtime_property_label(
            global,
            &RuntimePropertyKey::from("global_getter_classified_value"),
        ),
        Label::Public,
        "the accessor descriptor itself carries no classified label"
    );
    assert_eq!(core.read_reg(6).unwrap(), Value::Int(42));
    assert_eq!(
        core.get_register_label(6).unwrap(),
        &Label::Secret,
        "LoadName must retain the getter's returned runtime label"
    );
    assert_eq!(core.read_reg(7).unwrap(), Value::Int(7));
    assert_eq!(core.get_register_label(7).unwrap(), &Label::Public);
    assert_eq!(core.read_reg(8).unwrap(), Value::Undefined);
    assert_eq!(core.get_register_label(8).unwrap(), &Label::Public);
    assert!(core.pending_hostcall_result_label.is_none());
    assert!(core.active_inline_callback_context_label.is_none());
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn put_name_strict_missing_throws_and_sloppy_missing_creates_global() {
    let strict = test_module_with_pool(
        vec![
            Ir3Instruction::LoadInt { dst: 0, value: 7 },
            Ir3Instruction::PutName {
                src: 0,
                name_pool_index: 0,
                strict: true,
            },
            Ir3Instruction::Halt,
        ],
        vec!["bd_0k19b_strict_missing".to_string()],
    );
    assert!(matches!(
        quickjs_execute(&strict),
        Err(InterpreterError::UndefinedBinding { name })
            if name == "bd_0k19b_strict_missing"
    ));

    let sloppy = test_module_with_pool(
        vec![
            Ir3Instruction::LoadInt { dst: 0, value: 7 },
            Ir3Instruction::PutName {
                src: 0,
                name_pool_index: 0,
                strict: false,
            },
            Ir3Instruction::LoadName {
                dst: 0,
                name_pool_index: 0,
                allow_missing: false,
            },
            Ir3Instruction::Halt,
        ],
        vec!["bd_0k19b_sloppy_global".to_string()],
    );
    let mut core = InterpreterCore::new(test_quickjs_config(), "bd-0k19b-sloppy-global");
    let result = core.execute(&sloppy).expect("sloppy PutName execution");
    assert_eq!(result.value, Value::Int(7));
    // A sloppy global is a property of the realm's global object.
    assert!(
        !core
            .realm_dynamic_globals
            .contains_key("bd_0k19b_sloppy_global")
    );
    assert_eq!(
        core.global_object_data_property("bd_0k19b_sloppy_global"),
        Some(Value::Int(7))
    );
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn writable_builtin_realm_seeding_is_idempotent_bd_1piai() {
    let mut core = InterpreterCore::new(test_quickjs_config(), "bd-1piai-realm-seeding");
    core.inject_runtime_globals()
        .expect("initial runtime-global injection");
    assert_eq!(core.realm_dynamic_globals.len(), 3);
    for name in ["Date", "Math", "Promise"] {
        assert!(
            core.realm_dynamic_globals.contains_key(name),
            "missing {name}"
        );
    }

    let original_globals = ["Date", "Math", "Promise"].map(|name| {
        (
            name,
            core.load_runtime_name(name, false)
                .expect("seeded realm global"),
        )
    });
    core.inject_runtime_globals()
        .expect("idempotent runtime-global injection");
    for (name, expected) in &original_globals {
        assert_eq!(
            core.load_runtime_name(name, false)
                .expect("preserved realm global"),
            expected.clone(),
            "repeated injection must preserve {name} identity"
        );
    }

    core.put_runtime_name("Date", Value::Int(1), true)
        .expect("strict Date replacement");
    core.put_runtime_name("Math", Value::Int(2), true)
        .expect("strict Math replacement");
    core.put_runtime_name("Promise", Value::Int(3), true)
        .expect("strict Promise replacement");
    core.inject_runtime_globals()
        .expect("repeated runtime-global injection");

    for (name, expected) in [("Date", 1), ("Math", 2), ("Promise", 3)] {
        assert_eq!(
            core.load_runtime_name(name, false)
                .expect("materialized realm global"),
            Value::Int(expected),
            "repeated preparation must not replace {name}"
        );
    }
    assert_eq!(core.realm_dynamic_globals.len(), 3);
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn bd_en0uq_inject_runtime_globals_is_failure_atomic_under_memory_refusal() {
    // A clean injection under an unbounded budget establishes the target
    // heap growth, memory total, and realm identities.
    let mut success = InterpreterCore::new(test_quickjs_config(), "bd-en0uq-success");
    let entry_heap = success.heap_size();
    let entry_mem = success.estimated_memory_bytes();
    success.config.max_total_memory_bytes = u64::MAX;
    success
        .inject_runtime_globals()
        .expect("injection fits under an unbounded budget");
    let success_heap = success.heap_size();
    let success_total = success.estimated_memory_bytes();
    assert!(success_heap > entry_heap, "injection must allocate globals");
    assert_eq!(
        success.estimated_memory_bytes(),
        success.recompute_estimated_memory_bytes(),
        "a clean injection must leave consistent accounting"
    );
    let realm_identity = |core: &mut InterpreterCore| {
        ["Promise", "Math", "Date"].map(|name| {
            core.load_runtime_name(name, false)
                .expect("seeded realm global")
        })
    };
    let seeded = realm_identity(&mut success);

    // Repeated successful preparation preserves the realm ObjectId/callable
    // backing identity (guarded seeds) and never duplicates a seed.
    success
        .inject_runtime_globals()
        .expect("repeated successful injection");
    assert_eq!(
        realm_identity(&mut success),
        seeded,
        "realm identity churned"
    );
    assert_eq!(success.realm_dynamic_globals.len(), 3);

    // Force a refusal at graduated budgets between the pre-injection
    // estimate and the successful total. Every budget below the total must
    // refuse, and each refusal must be atomic: no heap object, realm
    // binding, or accounting drift survives, and the estimate stays
    // consistent with a full recompute. A retry at full budget then
    // succeeds with no duplicated allocations.
    let step = ((success_total - entry_mem) / 12).max(1);
    let mut budget = entry_mem;
    let mut refusals = 0u32;
    while budget < success_total {
        let mut core = InterpreterCore::new(test_quickjs_config(), "bd-en0uq-refuse");
        let core_entry_heap = core.heap_size();
        let core_entry_mem = core.estimated_memory_bytes();
        core.config.max_total_memory_bytes = budget;
        let outcome = core.inject_runtime_globals();
        if outcome.is_ok() {
            // The exact success threshold can land on a step boundary; a
            // successful injection there is not a failure to exercise.
            budget = budget.saturating_add(step);
            continue;
        }
        refusals += 1;
        assert!(
            matches!(outcome, Err(InterpreterError::MemoryBudgetExceeded { .. })),
            "budget {budget} must refuse for memory, got {outcome:?}"
        );
        assert_eq!(
            core.heap_size(),
            core_entry_heap,
            "heap drift after atomic refusal at budget {budget}"
        );
        assert!(
            core.realm_dynamic_globals.is_empty(),
            "realm-global drift after atomic refusal at budget {budget}"
        );
        assert_eq!(
            core.estimated_memory_bytes(),
            core_entry_mem,
            "estimate drift after atomic refusal at budget {budget}"
        );
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes(),
            "estimate inconsistent after atomic refusal at budget {budget}"
        );

        core.config.max_total_memory_bytes = u64::MAX;
        core.inject_runtime_globals()
            .expect("retry after an atomic refusal must succeed");
        assert_eq!(
            core.heap_size(),
            success_heap,
            "retry must not leak duplicate allocations at budget {budget}"
        );
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes(),
            "retry accounting must be consistent at budget {budget}"
        );
        assert_eq!(core.realm_dynamic_globals.len(), 3);
        budget = budget.saturating_add(step);
    }
    assert!(
        refusals > 0,
        "the budget sweep must have exercised at least one atomic refusal"
    );
}

#[test]
fn date_backing_object_is_visible_to_callback_property_helpers_bd_1piai() {
    let mut core = InterpreterCore::new(test_quickjs_config(), "bd-1piai-date-properties");
    core.inject_runtime_globals()
        .expect("runtime-global injection");
    let date = core
        .load_runtime_name("Date", false)
        .expect("Date realm global");

    let original = core
        .simple_callback_get_property(None, date.clone(), &Value::str("now"))
        .expect("read Date.now through callback helper");
    assert!(matches!(
        original,
        Value::BuiltinFunction(BuiltinFunction {
            kind: BuiltinFunctionKind::DateNow,
            ..
        })
    ));

    // The reducer mini-lane no longer writes properties (bd-9vouw.175);
    // a write lands on Date's backing object as SetProperty's does.
    let Value::BuiltinFunction(date_builtin) = &date else {
        panic!("Date is a builtin function");
    };
    let backing = InterpreterCore::builtin_function_property_object(date_builtin)
        .expect("Date has a backing object");
    core.set_object_runtime_property(
        backing,
        RuntimePropertyKey::String(JsString::from("now")),
        Value::Int(17),
    )
    .expect("write Date.now to its backing object");
    assert_eq!(
        core.simple_callback_get_property(None, date, &Value::str("now"))
            .expect("read replaced Date.now through callback helper"),
        Value::Int(17)
    );
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn put_name_status_freezes_pre_rhs_unresolvable_state() {
    let module = test_module_with_pool(
        vec![
            Ir3Instruction::ResolveNameStatus {
                dst: 3,
                name_pool_index: 0,
            },
            Ir3Instruction::LoadInt { dst: 0, value: 2 },
            Ir3Instruction::LoadInt { dst: 1, value: 1 },
            Ir3Instruction::PutName {
                src: 1,
                name_pool_index: 0,
                strict: false,
            },
            Ir3Instruction::PutNameWithStatus {
                src: 0,
                status: 3,
                name_pool_index: 0,
                strict: true,
            },
            Ir3Instruction::Halt,
        ],
        vec!["bd_0k19b_frozen_missing".to_string()],
    );
    let mut core = InterpreterCore::new(test_quickjs_config(), "bd-0k19b-frozen-missing");
    assert!(matches!(
        core.execute(&module),
        Err(InterpreterError::UndefinedBinding { name })
            if name == "bd_0k19b_frozen_missing"
    ));
    assert_eq!(
        core.global_object_data_property("bd_0k19b_frozen_missing"),
        Some(Value::Int(1)),
        "RHS-created realm global survives the strict PutValue error"
    );
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn put_name_status_preserves_exact_scoped_binding_across_shadowing() {
    let mut core = InterpreterCore::new(test_quickjs_config(), "bd-0k19b-exact-scope");
    let outer = ScopeBinding::with_state(BindingKind::Var, Value::Int(1), true);
    core.scope_chain.frames[0].insert_binding("bd_0k19b_exact_scope".to_string(), outer.clone());
    core.sync_estimated_memory_bytes()
        .expect("seed outer binding accounting");

    let reference_token = core
        .capture_runtime_name_reference("bd_0k19b_exact_scope")
        .expect("capture exact outer binding");
    core.scope_chain
        .push(core.config.max_scope_depth)
        .expect("push shadowing scope");
    let inner = ScopeBinding::with_state(BindingKind::Param, Value::Int(99), true);
    core.scope_chain
        .current_mut()
        .expect("shadowing scope")
        .insert_binding("bd_0k19b_exact_scope".to_string(), inner.clone());
    core.sync_estimated_memory_bytes()
        .expect("seed shadowing binding accounting");

    core.put_runtime_name_with_status("bd_0k19b_exact_scope", Value::Int(2), true, reference_token)
        .expect("write captured outer binding");

    assert_eq!(outer.value().expect("outer value"), Value::Int(2));
    assert_eq!(inner.value().expect("inner value"), Value::Int(99));
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn sloppy_put_name_inside_closure_survives_scope_restore() {
    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::CreateClosure {
                dst: 1,
                function_index: 0,
                capture_count: 0,
            },
            Ir3Instruction::Call {
                callee: 1,
                args: RegRange {
                    start: 10,
                    count: 0,
                },
                dst: 2,
            },
            Ir3Instruction::LoadName {
                dst: 0,
                name_pool_index: 0,
                allow_missing: false,
            },
            Ir3Instruction::Halt,
            Ir3Instruction::LoadInt { dst: 0, value: 9 },
            Ir3Instruction::PutName {
                src: 0,
                name_pool_index: 0,
                strict: false,
            },
            Ir3Instruction::Return { value: 0 },
        ],
        vec!["bd_0k19b_closure_global".to_string()],
    );
    module.function_table.push(Ir3FunctionDesc {
        entry: 4,
        arity: 0,
        frame_size: 2,
        name: Some("create_sloppy_global".to_string()),
        is_generator: false,
        rest_param_index: None,
    });

    assert_eq!(
        quickjs_execute(&module)
            .expect("closure-created sloppy global")
            .value,
        Value::Int(9)
    );
}

#[test]
fn put_name_preserves_existing_binding_tdz_and_const_rules() {
    let mut core = InterpreterCore::new(test_quickjs_config(), "bd-0k19b-existing-names");
    let global = core
        .scope_chain
        .frames
        .first_mut()
        .expect("global scope frame");
    global.insert_binding(
        "mutable".to_string(),
        ScopeBinding::with_state(BindingKind::Var, Value::Int(1), true),
    );
    global.insert_binding(
        "constant".to_string(),
        ScopeBinding::with_state(BindingKind::Const, Value::Int(2), true),
    );
    global.insert_binding(
        "uninitialized".to_string(),
        ScopeBinding::new(BindingKind::Let),
    );
    core.sync_estimated_memory_bytes()
        .expect("seed existing binding accounting");

    core.put_runtime_name("mutable", Value::Int(3), true)
        .expect("strict put to an existing mutable binding");
    assert_eq!(
        core.resolve_runtime_name_binding("mutable")
            .expect("mutable binding")
            .value()
            .expect("mutable binding value"),
        Value::Int(3)
    );
    assert!(matches!(
        core.put_runtime_name("constant", Value::Int(4), false),
        Err(InterpreterError::ConstAssignment { name }) if name == "constant"
    ));
    assert!(matches!(
        core.put_runtime_name("uninitialized", Value::Int(5), false),
        Err(InterpreterError::UninitializedBinding { name }) if name == "uninitialized"
    ));
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn sloppy_put_name_memory_refusal_rolls_back_global_binding() {
    let mut core = InterpreterCore::new(test_quickjs_config(), "bd-0k19b-global-rollback");
    let baseline = core.estimated_memory_bytes();
    core.config.max_total_memory_bytes = baseline;

    let error = core
        .put_runtime_name("bd_0k19b_refused_global", Value::Int(1), false)
        .expect_err("new global binding must exceed a zero-headroom budget");
    assert!(matches!(
        error,
        InterpreterError::MemoryBudgetExceeded { .. }
    ));
    assert!(
        !core
            .realm_dynamic_globals
            .contains_key("bd_0k19b_refused_global")
    );
    assert_eq!(core.estimated_memory_bytes(), baseline);
    assert_eq!(baseline, core.recompute_estimated_memory_bytes());
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
fn module_snapshot_charge_stays_stable_when_shared_binding_payload_changes() {
    let mut core = quickjs_test_core();
    core.scope_chain
        .current_mut()
        .unwrap()
        .declare("payload".to_string(), BindingKind::Let);
    let binding = core
        .scope_chain
        .resolve("payload")
        .map(|(_, binding)| binding.clone())
        .expect("payload binding");
    binding
        .set_state(Value::str("short"), true)
        .expect("seed binding state");
    let saved_scope = core.scope_chain.snapshot();
    let pushed_frame = CallFrame {
        return_ip: 1,
        return_reg: 0,
        register_base: 0,
        register_width: core.config.max_registers as usize,
        function_index: None,
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
        saved_pending_return: None,
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
        .expect("seed shared binding fixture");

    let snapshot = core
        .snapshot_module_execution()
        .expect("module snapshot should fit");
    let fixed_snapshot_charge = snapshot.accounted_bytes;
    assert_eq!(
        fixed_snapshot_charge,
        core.module_execution_snapshot_memory_bytes()
    );

    let previous_scope_bytes = core.scope_chain_memory_bytes();
    let previous_closure_bytes = core.closures_memory_bytes();
    let previous_call_stack_bytes = core.call_stack_memory_bytes();
    binding
        .set_state(
            Value::str("expanded shared binding payload".repeat(64)),
            true,
        )
        .expect("grow shared binding state");
    core.apply_scope_closure_call_stack_memory_delta(
        previous_scope_bytes,
        previous_closure_bytes,
        previous_call_stack_bytes,
    )
    .expect("shared binding growth should fit");

    assert_eq!(snapshot.accounted_bytes, fixed_snapshot_charge);
    assert_eq!(
        core.module_execution_snapshot_memory_bytes(),
        fixed_snapshot_charge,
        "snapshot structure charge must exclude mutable shared-cell payloads"
    );
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
    core.discard_module_execution_snapshot(snapshot);
    assert_eq!(core.module_snapshot_in_flight_bytes, 0);
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn scope_chain_snapshot_respects_memory_budget() {
    let mut config = InterpreterConfig::quickjs_defaults();
    config.max_scope_depth = 4;
    let mut core = InterpreterCore::new(config, "scope-snapshot-budget");
    core.scope_chain
        .push(core.config.max_scope_depth)
        .expect("operation should succeed for valid inputs");
    core.scope_chain.current_mut().unwrap().insert_binding(
        "payload".to_string(),
        ScopeBinding::with_state(BindingKind::Var, Value::str("x".repeat(128)), true),
    );
    core.sync_estimated_memory_bytes()
        .expect("operation should succeed for valid inputs");
    let snapshot_bytes = InterpreterCore::estimate_scope_chain_bytes(&core.scope_chain.frames);
    core.config.max_total_memory_bytes = core
        .estimated_memory_bytes()
        .saturating_add(snapshot_bytes)
        .saturating_sub(1);
    let err = core.snapshot_scope_chain().unwrap_err();
    assert!(matches!(err, InterpreterError::MemoryBudgetExceeded { .. }));
}

#[test]
fn per_iteration_binding_clone_detaches_identity_and_preserves_state() {
    let original = ScopeBinding::with_labeled_state(
        BindingKind::Let,
        Value::str("iteration payload"),
        Label::Secret,
        true,
    );
    let detached = original.detached_clone().expect("detached clone");

    assert_eq!(detached.kind, BindingKind::Let);
    assert_eq!(detached.snapshot_state(), original.snapshot_state());
    assert_eq!(detached.label().unwrap(), Label::Secret);
    assert!(!Rc::ptr_eq(&original.state, &detached.state));

    detached
        .set_state(Value::str("next iteration"), true)
        .expect("mutate detached cell");
    assert_eq!(original.value().unwrap(), Value::str("iteration payload"));
    assert_eq!(detached.value().unwrap(), Value::str("next iteration"));
    assert_eq!(original.label().unwrap(), Label::Secret);
    assert_eq!(detached.label().unwrap(), Label::Secret);
}

#[test]
fn per_iteration_cells_preserve_exact_ifc_labels_through_nested_closures_bd_mpm0l() {
    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::DeclareBinding {
                name_pool_index: 0,
                kind: BindingKind::Let as u8,
            },
            Ir3Instruction::InitBinding {
                name_pool_index: 0,
                src: 0,
            },
            Ir3Instruction::CreateClosure {
                dst: 10,
                function_index: 0,
                capture_count: 0,
            },
            Ir3Instruction::CreatePerIterationBinding {
                name_pool_index: 0,
                kind: BindingKind::Let as u8,
                preserve_state: true,
            },
            Ir3Instruction::LoadScoped {
                dst: 1,
                name_pool_index: 0,
            },
            Ir3Instruction::StoreScoped {
                src: 2,
                name_pool_index: 0,
            },
            Ir3Instruction::CreateClosure {
                dst: 11,
                function_index: 0,
                capture_count: 0,
            },
            Ir3Instruction::CreatePerIterationBinding {
                name_pool_index: 0,
                kind: BindingKind::Let as u8,
                preserve_state: true,
            },
            Ir3Instruction::StoreScoped {
                src: 3,
                name_pool_index: 0,
            },
            Ir3Instruction::CreateClosure {
                dst: 12,
                function_index: 0,
                capture_count: 0,
            },
            Ir3Instruction::LoadScoped {
                dst: 4,
                name_pool_index: 0,
            },
            Ir3Instruction::Call {
                callee: 10,
                args: RegRange {
                    start: 30,
                    count: 0,
                },
                dst: 20,
            },
            Ir3Instruction::Call {
                callee: 11,
                args: RegRange {
                    start: 30,
                    count: 0,
                },
                dst: 21,
            },
            Ir3Instruction::Call {
                callee: 12,
                args: RegRange {
                    start: 30,
                    count: 0,
                },
                dst: 22,
            },
            Ir3Instruction::Halt,
            Ir3Instruction::CreateClosure {
                dst: 0,
                function_index: 1,
                capture_count: 0,
            },
            Ir3Instruction::Return { value: 0 },
            Ir3Instruction::LoadScoped {
                dst: 0,
                name_pool_index: 0,
            },
            Ir3Instruction::Return { value: 0 },
        ],
        vec!["iteration".to_string()],
    );
    module.function_table.extend([
        Ir3FunctionDesc {
            entry: 15,
            arity: 0,
            frame_size: 2,
            name: Some("capture_nested".to_string()),
            is_generator: false,
            rest_param_index: None,
        },
        Ir3FunctionDesc {
            entry: 17,
            arity: 0,
            frame_size: 2,
            name: Some("read_iteration".to_string()),
            is_generator: false,
            rest_param_index: None,
        },
    ]);

    let mut core = quickjs_test_core();
    core.write_reg_with_label(0, Value::str("iteration-0"), Label::Secret)
        .expect("seed the first iteration with a Secret label");
    core.write_reg_with_label(2, Value::str("iteration-1"), Label::Public)
        .expect("seed the second iteration with a Public label");
    core.write_reg_with_label(3, Value::str("iteration-2"), Label::Confidential)
        .expect("seed the third iteration with a Confidential label");

    assert_eq!(
        core.run_loop(&module),
        Err(InterpreterError::Halted),
        "the per-iteration nested-closure program must reach its explicit Halt"
    );

    assert_eq!(
        core.get_register_label(1).expect("preserved first label"),
        &Label::Secret,
        "the first detached iteration cell must copy the prior cell label"
    );
    assert_eq!(
        core.get_register_label(4).expect("final live label"),
        &Label::Confidential,
        "LoadScoped must restore the exact current cell label"
    );

    let binding_from = |closure: &ClosureValue| {
        closure
            .captured_env
            .iter()
            .rev()
            .find_map(|frame| frame.bindings.get("iteration"))
            .cloned()
            .expect("closure must capture the iteration binding")
    };
    let outer: Vec<ScopeBinding> = (0..3).map(|id| binding_from(&core.closures[id])).collect();
    let nested_ids: Vec<usize> = [20_u32, 21, 22]
        .into_iter()
        .map(
            |reg| match core.read_reg(reg).expect("nested closure result") {
                Value::Closure(id) => id as usize,
                other => panic!("expected nested closure, got {other:?}"),
            },
        )
        .collect();
    let nested: Vec<ScopeBinding> = nested_ids
        .iter()
        .map(|&id| binding_from(&core.closures[id]))
        .collect();

    for (index, (outer_binding, nested_binding)) in outer.iter().zip(nested.iter()).enumerate() {
        assert!(
            Rc::ptr_eq(&outer_binding.state, &nested_binding.state),
            "nested closure {index} must retain its outer closure's exact cell"
        );
    }
    assert!(!Rc::ptr_eq(&outer[0].state, &outer[1].state));
    assert!(!Rc::ptr_eq(&outer[1].state, &outer[2].state));
    assert_eq!(outer[0].value().unwrap(), Value::str("iteration-0"));
    assert_eq!(outer[0].label().unwrap(), Label::Secret);
    assert_eq!(outer[1].value().unwrap(), Value::str("iteration-1"));
    assert_eq!(outer[1].label().unwrap(), Label::Public);
    assert_eq!(outer[2].value().unwrap(), Value::str("iteration-2"));
    assert_eq!(outer[2].label().unwrap(), Label::Confidential);
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes(),
        "lexical-cell labels must participate in exact memory accounting"
    );
}

#[test]
fn iterator_head_cell_resets_stale_label_before_exact_initialization_bd_mpm0l() {
    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::DeclareBinding {
                name_pool_index: 0,
                kind: BindingKind::Let as u8,
            },
            Ir3Instruction::InitBinding {
                name_pool_index: 0,
                src: 0,
            },
            Ir3Instruction::CreateClosure {
                dst: 10,
                function_index: 0,
                capture_count: 0,
            },
            Ir3Instruction::CreatePerIterationBinding {
                name_pool_index: 0,
                kind: BindingKind::Let as u8,
                preserve_state: false,
            },
            Ir3Instruction::LoadScoped {
                dst: 2,
                name_pool_index: 0,
            },
            Ir3Instruction::InitBinding {
                name_pool_index: 0,
                src: 1,
            },
            Ir3Instruction::CreateClosure {
                dst: 11,
                function_index: 0,
                capture_count: 0,
            },
            Ir3Instruction::Halt,
        ],
        vec!["iterator_head".to_string()],
    );
    module.function_table.push(Ir3FunctionDesc {
        entry: 7,
        arity: 0,
        frame_size: 1,
        name: Some("capture_iterator_head".to_string()),
        is_generator: false,
        rest_param_index: None,
    });

    let mut core = quickjs_test_core();
    core.write_reg_with_label(0, Value::str("stale"), Label::Secret)
        .expect("seed the previous iteration");
    core.write_reg_with_label(1, Value::str("fresh"), Label::Confidential)
        .expect("seed the iterator-head value");

    assert!(matches!(
        core.run_loop(&module),
        Err(InterpreterError::UninitializedBinding { name }) if name == "iterator_head"
    ));
    assert_eq!(core.ip, 4, "the TDZ load itself must remain unconsumed");
    let previous = core.closures[0]
        .captured_env
        .iter()
        .rev()
        .find_map(|frame| frame.bindings.get("iterator_head"))
        .cloned()
        .expect("previous iteration closure binding");
    let fresh = core
        .scope_chain
        .resolve("iterator_head")
        .map(|(_, binding)| binding.clone())
        .expect("fresh iterator-head binding");
    assert!(!Rc::ptr_eq(&previous.state, &fresh.state));
    assert_eq!(previous.label().unwrap(), Label::Secret);
    let fresh_before_init = fresh.snapshot_state().expect("fresh cell state");
    assert_eq!(fresh_before_init.value, Value::Undefined);
    assert_eq!(fresh_before_init.label, Label::Public);
    assert!(!fresh_before_init.initialized);

    core.ip = 5;
    assert_eq!(
        core.run_loop(&module),
        Err(InterpreterError::Halted),
        "exact iterator-head initialization must resume through the explicit Halt"
    );
    let captured_fresh = core.closures[1]
        .captured_env
        .iter()
        .rev()
        .find_map(|frame| frame.bindings.get("iterator_head"))
        .cloned()
        .expect("initialized iterator-head closure binding");
    assert!(Rc::ptr_eq(&fresh.state, &captured_fresh.state));
    assert_eq!(captured_fresh.value().unwrap(), Value::str("fresh"));
    assert_eq!(captured_fresh.label().unwrap(), Label::Confidential);
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes(),
        "TDZ refusal and resumed initialization must preserve accounting"
    );
}

#[test]
fn scoped_binding_accounts_custom_ifc_label_payload_bd_mpm0l() {
    let initialize = test_module_with_pool(
        vec![
            Ir3Instruction::DeclareBinding {
                name_pool_index: 0,
                kind: BindingKind::Let as u8,
            },
            Ir3Instruction::InitBinding {
                name_pool_index: 0,
                src: 0,
            },
            Ir3Instruction::Halt,
        ],
        vec!["custom_labeled".to_string()],
    );
    let update = test_module_with_pool(
        vec![
            Ir3Instruction::StoreScoped {
                src: 1,
                name_pool_index: 0,
            },
            Ir3Instruction::Halt,
        ],
        vec!["custom_labeled".to_string()],
    );
    let custom = Label::Custom {
        name: "tenant-secret-compartment".repeat(8),
        level: Label::Secret.level(),
    };
    let mut core = quickjs_test_core();
    core.write_reg_with_label(0, Value::Int(7), Label::Public)
        .expect("seed public binding value");
    assert_eq!(
        core.run_loop(&initialize),
        Err(InterpreterError::Halted),
        "public lexical initialization must reach its explicit Halt"
    );
    let scope_before = core.scope_chain_memory_bytes();
    core.write_reg_with_label(1, Value::Int(7), custom.clone())
        .expect("seed custom-labeled replacement");
    core.ip = 0;
    assert_eq!(
        core.run_loop(&update),
        Err(InterpreterError::Halted),
        "custom-labeled lexical store must reach its explicit Halt"
    );
    let scope_after = core.scope_chain_memory_bytes();

    assert_eq!(
        scope_after.saturating_sub(scope_before),
        InterpreterCore::estimate_label_bytes(&custom),
        "only the dynamic Custom-label payload should grow for the same value"
    );
    let binding = core
        .scope_chain
        .resolve("custom_labeled")
        .map(|(_, binding)| binding)
        .expect("custom-labeled binding");
    assert_eq!(binding.label().unwrap(), custom);
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn temporary_scope_clone_budget_counts_existing_snapshot() {
    let config = InterpreterConfig::quickjs_defaults();
    let mut core = InterpreterCore::new(config, "temporary-scope-clone-budget");
    core.scope_chain.current_mut().unwrap().insert_binding(
        "payload".to_string(),
        ScopeBinding::with_state(BindingKind::Var, Value::str("x".repeat(128)), true),
    );
    core.sync_estimated_memory_bytes()
        .expect("operation should succeed for valid inputs");

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
fn generator_start_budget_failure_preserves_suspended_start_phase() {
    let payload = "x".repeat(128);
    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 1,
            },
            Ir3Instruction::DeclareBinding {
                name_pool_index: 0,
                kind: 0,
            },
            Ir3Instruction::StoreScoped {
                src: 0,
                name_pool_index: 0,
            },
            Ir3Instruction::CreateGenerator {
                dst: 1,
                function_index: 0,
                capture_count: 0,
            },
            Ir3Instruction::Call {
                dst: 0,
                callee: 1,
                args: RegRange {
                    start: 10,
                    count: 0,
                },
            },
            Ir3Instruction::Halt,
            Ir3Instruction::LoadScoped {
                dst: 0,
                name_pool_index: 0,
            },
            Ir3Instruction::Yield {
                value: 0,
                delegate: false,
                resume_dst: 1,
            },
            Ir3Instruction::Return { value: 0 },
        ],
        vec!["payload".to_string(), payload.clone()],
    );
    module.function_table.push(Ir3FunctionDesc {
        entry: 6,
        arity: 0,
        frame_size: 4,
        name: Some("capturing_generator".to_string()),
        is_generator: true,
        rest_param_index: None,
    });

    let mut core = InterpreterCore::new(test_quickjs_config(), "generator");
    let result = core
        .execute(&module)
        .expect("operation should succeed for valid inputs");
    assert_eq!(result.value, Value::Generator(0));

    let clone_bytes = InterpreterCore::estimate_scope_chain_bytes(&core.closures[0].captured_env);
    core.scope_chain.frames = vec![ScopeFrame::new()];
    core.sync_estimated_memory_bytes()
        .expect("operation should succeed for valid inputs");
    let baseline_memory = core.estimated_memory_bytes();
    core.config.max_total_memory_bytes = baseline_memory
        .saturating_add(clone_bytes)
        .saturating_sub(1);

    let err = core
        .generator_next(&module, 0, Value::Undefined, Label::Public)
        .unwrap_err();
    assert!(matches!(err, InterpreterError::MemoryBudgetExceeded { .. }));
    assert_eq!(core.generators[0].phase, GeneratorPhase::SuspendedStart);
    assert_eq!(core.estimated_memory_bytes(), baseline_memory);

    core.config.max_total_memory_bytes = u64::MAX;
    let (yielded, _) = core
        .generator_next(&module, 0, Value::Undefined, Label::Public)
        .expect("operation should succeed for valid inputs");
    assert_eq!(core.generators[0].phase, GeneratorPhase::SuspendedYield);

    let Value::Object(result_id) = yielded else {
        panic!("expected generator.next() to return a result object");
    };
    let result_object = &core.heap[result_id.0 as usize];
    assert_eq!(
        result_object.properties.get("done"),
        Some(&Value::Bool(false))
    );
    assert_eq!(
        result_object.properties.get("value"),
        Some(&Value::str(payload))
    );
}

#[test]
fn generator_next_updates_memory_incrementally() {
    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::Yield {
                value: 0,
                delegate: false,
                resume_dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 1,
            },
            Ir3Instruction::Return { value: 0 },
        ],
        vec!["yield-payload".to_string(), "return-payload".to_string()],
    );
    module.function_table.push(Ir3FunctionDesc {
        entry: 0,
        arity: 0,
        frame_size: 4,
        name: Some("memory_delta_generator".to_string()),
        is_generator: true,
        rest_param_index: None,
    });

    let mut core = InterpreterCore::new(test_quickjs_config(), "generator-memory-delta");
    core.generators.push(GeneratorObject {
        owner_module: Arc::new(module.clone()),
        invocation: Some(GeneratorInvocation {
            function_index: 0,
            closure_index: None,
            arguments: Vec::new(),
            argument_labels: Vec::new(),
            this_value: Value::Undefined,
            this_label: Label::Public,
            inline_context_label: None,
            module_specifier: None,
            generated_function_artifact: None,
        }),
        execution: None,
        resume_dst: None,
        phase: GeneratorPhase::SuspendedStart,
        prototype: None,
    });
    core.sync_estimated_memory_bytes()
        .expect("seed generator object should fit memory budget");

    let (first, _) = core
        .generator_next(&module, 0, Value::Undefined, Label::Public)
        .expect("initial generator resume should yield");
    assert_eq!(core.generators[0].phase, GeneratorPhase::SuspendedYield);
    assert_eq!(
        core.recompute_estimated_memory_bytes(),
        core.estimated_memory_bytes,
        "yield suspension deltas must match full recompute"
    );
    let Value::Object(first_result_id) = first else {
        panic!("expected first generator.next() to return a result object");
    };
    let first_result = &core.heap[first_result_id.0 as usize];
    assert_eq!(
        first_result.properties.get("value"),
        Some(&Value::str("yield-payload"))
    );
    assert_eq!(
        first_result.properties.get("done"),
        Some(&Value::Bool(false))
    );

    let (second, _) = core
        .generator_next(&module, 0, Value::Undefined, Label::Public)
        .expect("second generator resume should complete");
    assert_eq!(core.generators[0].phase, GeneratorPhase::Completed);
    assert_eq!(
        core.recompute_estimated_memory_bytes(),
        core.estimated_memory_bytes,
        "completion deltas must match full recompute"
    );
    let Value::Object(second_result_id) = second else {
        panic!("expected second generator.next() to return a result object");
    };
    let second_result = &core.heap[second_result_id.0 as usize];
    assert_eq!(
        second_result.properties.get("value"),
        Some(&Value::str("return-payload"))
    );
    assert_eq!(
        second_result.properties.get("done"),
        Some(&Value::Bool(true))
    );
}

#[test]
fn generator_invocation_argument_label_survives_first_yield_bd_ur3tk_5() {
    // The generator object resumes through its `next` method.
    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::Call {
                callee: 0,
                args: RegRange { start: 1, count: 1 },
                dst: 2,
            },
            Ir3Instruction::LoadStr {
                dst: 6,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 2,
                key: 6,
                dst: 7,
            },
            Ir3Instruction::CallMethod {
                receiver: 2,
                callee: 7,
                args: RegRange { start: 8, count: 0 },
                dst: 3,
            },
            Ir3Instruction::LoadStr {
                dst: 4,
                pool_index: 0,
            },
            Ir3Instruction::GetProperty {
                obj: 3,
                key: 4,
                dst: 5,
            },
            Ir3Instruction::Return { value: 5 },
            Ir3Instruction::Yield {
                value: 0,
                delegate: false,
                resume_dst: 1,
            },
            Ir3Instruction::Return { value: 0 },
        ],
        vec!["value".to_string(), "next".to_string()],
    );
    module.function_table.push(Ir3FunctionDesc {
        entry: 7,
        arity: 1,
        frame_size: 2,
        name: Some("labeled_generator".to_string()),
        is_generator: true,
        rest_param_index: None,
    });

    let mut core =
        InterpreterCore::new(test_quickjs_config(), "generator-invocation-label-snapshot");
    core.closures.push(ClosureValue {
        function_index: 0,
        captured_env: Vec::new(),
    });
    core.write_reg(0, Value::GeneratorFunction(0))
        .expect("generator function register");
    core.write_reg_with_label(1, Value::str("secret-argument"), Label::Secret)
        .expect("secret generator argument");

    assert_eq!(
        core.run_loop(&module)
            .expect("generator invocation and first next should execute"),
        Value::str("secret-argument")
    );
    assert_eq!(
        core.get_register_label(5)
            .expect("yielded property result label"),
        &Label::Secret
    );
    assert_eq!(core.generators[0].phase, GeneratorPhase::SuspendedYield);
}

#[test]
fn generator_rest_values_and_labels_survive_first_yield_bd_ur3tk_5() {
    let mut module = test_module(vec![
        Ir3Instruction::Yield {
            value: 1,
            delegate: false,
            resume_dst: 2,
        },
        Ir3Instruction::Return { value: 2 },
    ]);
    module.function_table.push(Ir3FunctionDesc {
        entry: 0,
        arity: 2,
        frame_size: 3,
        name: Some("rest_snapshot".to_string()),
        is_generator: true,
        rest_param_index: Some(1),
    });
    let mut core = InterpreterCore::new(test_quickjs_config(), "generator-rest-label-snapshot");
    for (arguments, argument_labels) in [
        (vec![Value::Int(10)], vec![Label::Public]),
        (
            vec![Value::Int(10), Value::Int(20), Value::Int(22)],
            vec![Label::Public, Label::Secret, Label::Confidential],
        ),
    ] {
        core.generators.push(GeneratorObject {
            owner_module: Arc::new(module.clone()),
            invocation: Some(GeneratorInvocation {
                function_index: 0,
                closure_index: None,
                arguments,
                argument_labels,
                this_value: Value::Undefined,
                this_label: Label::Public,
                inline_context_label: None,
                module_specifier: None,
                generated_function_artifact: None,
            }),
            execution: None,
            resume_dst: None,
            phase: GeneratorPhase::SuspendedStart,
            prototype: None,
        });
    }

    let (empty_yield, empty_label) = core
        .generator_next(&module, 0, Value::Undefined, Label::Public)
        .expect("empty rest tail should yield");
    assert_eq!(empty_label, Label::Public);
    let Value::Object(empty_result_id) = empty_yield else {
        panic!("generator.next() should return a result object");
    };
    let Some(Value::Object(empty_rest_id)) = core.heap[empty_result_id.0 as usize]
        .properties
        .get("value")
        .cloned()
    else {
        panic!("yielded value should be the materialized empty rest Array");
    };
    assert_eq!(
        core.heap[empty_rest_id.0 as usize].properties.get("length"),
        Some(&Value::Int(0))
    );

    let (fixed_yield, fixed_label) = core
        .generator_next(&module, 1, Value::Undefined, Label::Public)
        .expect("fixed and trailing arguments should yield their rest Array");
    assert_eq!(
        fixed_label,
        Label::Secret.join(&Label::Confidential),
        "the rest Array must carry the join of every retained tail label"
    );
    let Value::Object(fixed_result_id) = fixed_yield else {
        panic!("generator.next() should return a result object");
    };
    let Some(Value::Object(fixed_rest_id)) = core.heap[fixed_result_id.0 as usize]
        .properties
        .get("value")
        .cloned()
    else {
        panic!("yielded value should be the materialized fixed rest Array");
    };
    let fixed_rest = &core.heap[fixed_rest_id.0 as usize];
    assert_eq!(fixed_rest.properties.get("0"), Some(&Value::Int(20)));
    assert_eq!(fixed_rest.properties.get("1"), Some(&Value::Int(22)));
    assert_eq!(fixed_rest.properties.get("length"), Some(&Value::Int(2)));

    let (_, return_label) = core
        .generator_next(&module, 1, Value::Int(42), Label::Internal)
        .expect("resume input should reach the retained rest generator frame");
    assert_eq!(return_label, Label::Internal);
}

#[test]
fn generator_resume_labels_and_instances_are_isolated_bd_ur3tk_5() {
    let mut module = test_module(vec![
        Ir3Instruction::Yield {
            value: 0,
            delegate: false,
            resume_dst: 1,
        },
        Ir3Instruction::Return { value: 1 },
    ]);
    module.function_table.push(Ir3FunctionDesc {
        entry: 0,
        arity: 1,
        frame_size: 2,
        name: Some("isolated_labels".to_string()),
        is_generator: true,
        rest_param_index: None,
    });
    let mut core =
        InterpreterCore::new(test_quickjs_config(), "generator-instance-label-isolation");
    for (value, label) in [
        (Value::Int(11), Label::Secret),
        (Value::Int(22), Label::Internal),
    ] {
        core.generators.push(GeneratorObject {
            owner_module: Arc::new(module.clone()),
            invocation: Some(GeneratorInvocation {
                function_index: 0,
                closure_index: None,
                arguments: vec![value],
                argument_labels: vec![label],
                this_value: Value::Undefined,
                this_label: Label::Public,
                inline_context_label: None,
                module_specifier: None,
                generated_function_artifact: None,
            }),
            execution: None,
            resume_dst: None,
            phase: GeneratorPhase::SuspendedStart,
            prototype: None,
        });
    }
    core.sync_estimated_memory_bytes()
        .expect("seed generator objects should fit memory budget");

    let (_, first_label) = core
        .generator_next(&module, 0, Value::Undefined, Label::Public)
        .expect("first generator should yield");
    let (_, second_label) = core
        .generator_next(&module, 1, Value::Undefined, Label::Public)
        .expect("second generator should yield independently");
    assert_eq!(first_label, Label::Secret);
    assert_eq!(second_label, Label::Internal);

    let (_, return_label) = core
        .generator_next(&module, 0, Value::Int(33), Label::Confidential)
        .expect("resume value should become the first generator's return value");
    assert_eq!(return_label, Label::Confidential);
    assert_eq!(
        core.generators[1]
            .execution
            .as_ref()
            .expect("second generator should remain suspended")
            .register_labels[0],
        Label::Internal
    );
}

#[test]
fn generator_rejects_mismatched_value_and_label_snapshot_bd_ur3tk_5() {
    let mut module = test_module(vec![
        Ir3Instruction::Yield {
            value: 0,
            delegate: false,
            resume_dst: 1,
        },
        Ir3Instruction::Return { value: 1 },
    ]);
    module.function_table.push(Ir3FunctionDesc {
        entry: 0,
        arity: 1,
        frame_size: 2,
        name: Some("mismatched_label_snapshot".to_string()),
        is_generator: true,
        rest_param_index: None,
    });
    let mut core = InterpreterCore::new(test_quickjs_config(), "generator-label-snapshot-mismatch");
    core.generators.push(GeneratorObject {
        owner_module: Arc::new(module.clone()),
        invocation: Some(GeneratorInvocation {
            function_index: 0,
            closure_index: None,
            arguments: vec![Value::Int(7)],
            argument_labels: vec![Label::Secret],
            this_value: Value::Undefined,
            this_label: Label::Public,
            inline_context_label: None,
            module_specifier: None,
            generated_function_artifact: None,
        }),
        execution: None,
        resume_dst: None,
        phase: GeneratorPhase::SuspendedStart,
        prototype: None,
    });
    core.sync_estimated_memory_bytes()
        .expect("seed generator object should fit memory budget");

    core.generator_next(&module, 0, Value::Undefined, Label::Public)
        .expect("first resume should create a suspended activation");
    core.generators[0]
        .execution
        .as_mut()
        .expect("generator should be suspended after yield")
        .register_labels
        .pop();

    let error = core
        .generator_next(&module, 0, Value::Int(9), Label::Confidential)
        .expect_err("a mismatched label file must fail closed");
    assert!(matches!(
        error,
        InterpreterError::InternalError { details }
            if details.contains("value/label snapshot mismatch")
    ));
    assert_eq!(core.generators[0].phase, GeneratorPhase::SuspendedYield);
    assert!(
        core.generators[0].execution.is_some(),
        "the corrupt snapshot must remain quarantined instead of becoming active"
    );
    assert_eq!(core.generators[0].resume_dst, Some(1));
}

#[test]
fn generator_return_completion_survives_finally_yield_bd_ur3tk_5() {
    let mut module = test_module(vec![
        Ir3Instruction::BeginTry {
            catch_target: 2,
            finally_target: Some(2),
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
    module.function_table.push(Ir3FunctionDesc {
        entry: 0,
        arity: 1,
        frame_size: 2,
        name: Some("finally_snapshot".to_string()),
        is_generator: true,
        rest_param_index: None,
    });
    let mut core = InterpreterCore::new(test_quickjs_config(), "generator-finally-label-snapshot");
    core.generators.push(GeneratorObject {
        owner_module: Arc::new(module.clone()),
        invocation: Some(GeneratorInvocation {
            function_index: 0,
            closure_index: None,
            arguments: vec![Value::Int(7)],
            argument_labels: vec![Label::Secret],
            this_value: Value::Undefined,
            this_label: Label::Public,
            inline_context_label: None,
            module_specifier: None,
            generated_function_artifact: None,
        }),
        execution: None,
        resume_dst: None,
        phase: GeneratorPhase::SuspendedStart,
        prototype: None,
    });
    core.sync_estimated_memory_bytes()
        .expect("seed generator object should fit memory budget");

    let (_, yield_label) = core
        .generator_next(&module, 0, Value::Undefined, Label::Public)
        .expect("finally should yield before completing the pending return");
    assert_eq!(yield_label, Label::Secret);
    let suspended = core.generators[0]
        .execution
        .as_ref()
        .expect("yield should preserve the generator activation");
    assert!(matches!(
        suspended.finally_frames.last(),
        Some(FinallyFrame {
            completion: Some(AbruptCompletion::Return(LabeledReturn {
                value: Value::Int(7),
                label: Label::Secret,
            })),
        })
    ));

    let (_, return_label) = core
        .generator_next(&module, 0, Value::Undefined, Label::Public)
        .expect("resuming after yield should complete the original return");
    assert_eq!(return_label, Label::Secret);
    assert_eq!(core.generators[0].phase, GeneratorPhase::Completed);
}

#[test]
fn inline_wrappers_restore_memory_incrementally() {
    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::Return { value: 0 },
            Ir3Instruction::LoadThis { dst: 0 },
            Ir3Instruction::Return { value: 0 },
        ],
        vec!["method-result".to_string()],
    );
    module.function_table.extend([
        Ir3FunctionDesc {
            entry: 0,
            arity: 0,
            frame_size: 2,
            name: Some("inline_method_target".to_string()),
            is_generator: false,
            rest_param_index: None,
        },
        Ir3FunctionDesc {
            entry: 2,
            arity: 0,
            frame_size: 2,
            name: Some("inline_construct_target".to_string()),
            is_generator: false,
            rest_param_index: None,
        },
    ]);

    let mut core = InterpreterCore::new(test_quickjs_config(), "inline-wrapper-memory");
    core.sync_estimated_memory_bytes()
        .expect("empty interpreter state should fit memory budget");

    let method_result = core
        .invoke_inline_method_call(
            Some(&module),
            Value::Function(0),
            Value::Undefined,
            Vec::new(),
        )
        .expect("inline method wrapper should execute");
    assert_eq!(method_result, Value::str("method-result"));
    assert_eq!(
        core.recompute_estimated_memory_bytes(),
        core.estimated_memory_bytes,
        "method wrapper restore delta must match full recompute"
    );

    let construct_result = core
        .invoke_inline_construct(Some(&module), Value::Function(1), Vec::new())
        .expect("inline construct wrapper should execute");
    let Value::Object(constructed_id) = construct_result else {
        panic!("inline construct wrapper should return constructed object");
    };
    assert_eq!(
        core.heap[constructed_id.0 as usize].constructor_function,
        Some(1)
    );
    assert_eq!(
        core.recompute_estimated_memory_bytes(),
        core.estimated_memory_bytes,
        "construct wrapper restore delta must match full recompute"
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

    let result = quickjs_execute(&module).expect("operation should succeed for valid inputs");
    assert_eq!(result.value, Value::Int(2));
}

#[test]
fn scope_chain_snapshot_produces_correct_frame_count() {
    let config = InterpreterConfig::quickjs_defaults();
    let mut core = InterpreterCore::new(config, "snapshot-frame-count");

    // Push 4 additional frames (starting with 1 global = 5 total)
    for _ in 0..4 {
        core.scope_chain
            .push(core.config.max_scope_depth)
            .expect("operation should succeed for valid inputs");
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
            core.scope_chain
                .push(core.config.max_scope_depth)
                .expect("operation should succeed for valid inputs");
        }
        let binding_name = format!("var{}", i);
        let binding_value = format!("value{}", i);
        core.scope_chain.current_mut().unwrap().insert_binding(
            binding_name.clone(),
            ScopeBinding::with_state(BindingKind::Var, Value::str(binding_value.clone()), true),
        );
    }

    assert_eq!(core.scope_chain.depth(), 10);

    // Create a closure by capturing the scope chain
    let captured_env = core
        .snapshot_scope_chain()
        .expect("operation should succeed for valid inputs");
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
    let result = quickjs_execute(&m).expect("operation should succeed for valid inputs");
    assert_eq!(result.value, Value::Bool(false));
}

#[test]
fn v8_lane_execute_produces_result() {
    let m = test_module(vec![
        Ir3Instruction::LoadInt { dst: 0, value: 99 },
        Ir3Instruction::Halt,
    ]);
    let result = v8_execute(&m).expect("operation should succeed for valid inputs");
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
        InterpreterError::UndefinedBinding {
            name: "missing".to_string(),
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
        let json = serde_json::to_string(v).expect("serialize derived Serialize");
        let back: InterpreterError =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(*v, back);
    }
}

// -- Mixed Int/Float arithmetic tests --

#[test]
fn eval_add_int_float_promotion() {
    // Int + Float should promote to Float
    let mut core = quickjs_test_core();
    core.mutate_registers(|r| {
        r.resize(4, Value::Undefined);
    });
    core.set_reg(0, Value::Int(1));
    core.set_reg(1, Value::Float(Float64::new(0.5)));
    let result = core
        .eval_add(None, 0, 1)
        .expect("operation should succeed for valid inputs");
    assert_eq!(result, Value::Float(Float64::new(1.5)));
}

#[test]
fn eval_add_float_int_promotion() {
    // Float + Int should promote to Float
    let mut core = quickjs_test_core();
    core.mutate_registers(|r| {
        r.resize(4, Value::Undefined);
    });
    core.set_reg(0, Value::Float(Float64::new(2.5)));
    core.set_reg(1, Value::Int(3));
    let result = core
        .eval_add(None, 0, 1)
        .expect("operation should succeed for valid inputs");
    assert_eq!(result, Value::Float(Float64::new(5.5)));
}

#[test]
fn eval_div_int_int_exact() {
    // 6 / 3 = 2 (exact integer result)
    let mut core = quickjs_test_core();
    core.mutate_registers(|r| {
        r.resize(4, Value::Undefined);
    });
    core.set_reg(0, Value::Int(6));
    core.set_reg(1, Value::Int(3));
    let result = core
        .eval_div(0, 1)
        .expect("operation should succeed for valid inputs");
    assert_eq!(result, Value::Int(2));
}

#[test]
fn eval_div_int_int_fractional() {
    // 7 / 3 = 2.333... (fractional result)
    let mut core = quickjs_test_core();
    core.mutate_registers(|r| {
        r.resize(4, Value::Undefined);
    });
    core.mutate_registers(|r| {
        r[0] = Value::Int(7);
    });
    core.set_reg(1, Value::Int(3));
    let result = core
        .eval_div(0, 1)
        .expect("operation should succeed for valid inputs");
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
    core.mutate_registers(|r| {
        r.resize(4, Value::Undefined);
    });
    core.set_reg(0, Value::Int(1));
    core.set_reg(1, Value::Int(0));
    let result = core
        .eval_div(0, 1)
        .expect("operation should succeed for valid inputs");
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
    core.mutate_registers(|r| {
        r.resize(4, Value::Undefined);
    });
    core.set_reg(0, Value::Int(0));
    core.set_reg(1, Value::Int(0));
    let result = core
        .eval_div(0, 1)
        .expect("operation should succeed for valid inputs");
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
    core.mutate_registers(|r| {
        r.resize(4, Value::Undefined);
    });
    core.set_reg(0, Value::Float(Float64::new(f64::NAN)));
    core.set_reg(1, Value::Int(1));
    let result = core
        .eval_add(None, 0, 1)
        .expect("operation should succeed for valid inputs");
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
    core.mutate_registers(|r| {
        r.resize(4, Value::Undefined);
    });
    core.set_reg(0, Value::Float(Float64::new(f64::INFINITY)));
    core.set_reg(1, Value::Int(0));
    let result = core
        .eval_arith(0, 1, "mul")
        .expect("operation should succeed for valid inputs");
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
    core.mutate_registers(|r| {
        r.resize(4, Value::Undefined);
    });
    core.set_reg(0, Value::Float(Float64::new(5.5)));
    core.set_reg(1, Value::Float(Float64::new(2.0)));
    let result = core
        .eval_mod(0, 1)
        .expect("operation should succeed for valid inputs");
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
    core.mutate_registers(|r| {
        r.resize(4, Value::Undefined);
    });
    core.set_reg(0, Value::Float(Float64::new(1.5)));
    let result = core
        .eval_unary_neg(0)
        .expect("operation should succeed for valid inputs");
    assert_eq!(result, Value::Float(Float64::new(-1.5)));
}

#[test]
fn eval_ieee754_classic() {
    // 0.1 + 0.2 = 0.30000000000000004 (classic IEEE 754 test)
    let mut core = quickjs_test_core();
    core.mutate_registers(|r| {
        r.resize(4, Value::Undefined);
    });
    core.set_reg(0, Value::Float(Float64::new(0.1)));
    core.set_reg(1, Value::Float(Float64::new(0.2)));
    let result = core
        .eval_add(None, 0, 1)
        .expect("operation should succeed for valid inputs");
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
    core.mutate_registers(|r| {
        r.resize(4, Value::Undefined);
    });
    core.set_reg(0, Value::Float(Float64::new(1.0)));
    core.set_reg(1, Value::Float(Float64::new(-0.0)));
    let result = core
        .eval_div(0, 1)
        .expect("operation should succeed for valid inputs");
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
    core.mutate_registers(|r| {
        r.resize(4, Value::Undefined);
    });
    core.set_reg(0, Value::Float(Float64::new(-1.0)));
    core.set_reg(1, Value::Int(0));
    let result = core
        .eval_div(0, 1)
        .expect("operation should succeed for valid inputs");
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
    // Executing even a bare `Halt` runs runtime-global injection during
    // `prepare_execution`, which allocates heap objects and therefore also
    // requires HeapAllocate. VmDispatch is still checked first, so the
    // denial sub-case below remains a faithful VmDispatch-only assertion.
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

// -- ES2015 Class Semantics Tests (bd-6a61n.1.3) --

#[test]
fn class_declaration_creates_constructor() {
    let mut config = InterpreterConfig::quickjs_defaults();
    config
        .granted_capabilities
        .insert(RuntimeCapability::VmDispatch);
    config
        .granted_capabilities
        .insert(RuntimeCapability::HeapAllocate);
    let mut core = InterpreterCore::new(config, "class-constructor-test");

    // Test basic constructor functionality
    // Create a constructor function and test instantiation.
    // The constructor is loaded as Value::Function(0). The current IR has no
    // instruction that materializes a bare function value into a register,
    // so it is seeded directly (faithfully reproducing the legacy
    // `LoadConstant { value: Value::Function(0) }`). The constructor body is
    // inlined into the module's flat instruction stream at `entry`.
    let module = test_module_with_functions(
        vec![
            // Create instance with no arguments
            Ir3Instruction::Construct {
                callee: 0,
                args: RegRange { start: 1, count: 0 },
                dst: 1,
            },
            // Store result for verification
            Ir3Instruction::Halt,
            // Constructor body (entry = 2): returns undefined (object created
            // implicitly).
            Ir3Instruction::LoadUndefined { dst: 0 },
            Ir3Instruction::Return { value: 0 },
        ],
        vec![crate::ir_contract::Ir3FunctionDesc {
            entry: 2,
            arity: 0,
            frame_size: 8,
            name: Some("TestClass".to_string()),
            is_generator: false,
            rest_param_index: None,
        }],
    );
    core.set_reg(0, Value::Function(0));
    let result = core.execute(&module);
    assert!(result.is_ok());

    // Verify that Construct created an object instance
    let constructed_value = core.read_reg(1).unwrap();
    match constructed_value {
        Value::Object(obj_id) => {
            // Verify object has correct constructor property
            let obj = &core.heap[obj_id.0 as usize];
            assert_eq!(obj.constructor_function, Some(0));
        }
        _ => panic!(
            "Construct should create an object, got {:?}",
            constructed_value
        ),
    }
}

#[test]
fn class_method_on_prototype() {
    let mut config = InterpreterConfig::quickjs_defaults();
    config
        .granted_capabilities
        .insert(RuntimeCapability::VmDispatch);
    config
        .granted_capabilities
        .insert(RuntimeCapability::HeapAllocate);
    let mut core = InterpreterCore::new(config, "class-method-test");

    // Test that class methods are accessible on instances through prototype
    // chain. Constructor (Value::Function(0)) and method (Value::Function(1))
    // are seeded directly into registers — the current IR has no instruction
    // that materializes a bare function value, and the method assertion
    // requires the exact `Value::Function(1)` (a CreateClosure would yield a
    // `Value::Closure`). String-keyed property access now takes a register
    // key, so keys are materialized via LoadStr from the constant pool.
    // Function bodies are inlined into the flat instruction stream.
    let module = {
        let mut m = test_module_with_functions(
            vec![
                // r6 = "prototype", r7 = "testMethod" property-key scratch
                Ir3Instruction::LoadStr {
                    dst: 6,
                    pool_index: 0,
                },
                Ir3Instruction::LoadStr {
                    dst: 7,
                    pool_index: 1,
                },
                // Create instance (Value::Function(0) seeded in r0)
                Ir3Instruction::Construct {
                    callee: 0,
                    args: RegRange { start: 8, count: 0 },
                    dst: 1, // Instance in r1
                },
                // Get constructor's prototype and set method on it
                Ir3Instruction::GetProperty {
                    obj: 0,
                    key: 6,
                    dst: 3,
                },
                Ir3Instruction::SetProperty {
                    obj: 3,
                    key: 7,
                    val: 2,
                },
                // Call method on instance - should find it via prototype chain
                Ir3Instruction::GetProperty {
                    obj: 1,
                    key: 7,
                    dst: 4,
                },
                // Verify method is found
                Ir3Instruction::Halt,
                // Constructor body (entry = 7)
                Ir3Instruction::LoadUndefined { dst: 0 },
                Ir3Instruction::Return { value: 0 },
                // Method body (entry = 9): returns "method called"
                Ir3Instruction::LoadStr {
                    dst: 0,
                    pool_index: 2,
                },
                Ir3Instruction::Return { value: 0 },
            ],
            vec![
                // Constructor function
                crate::ir_contract::Ir3FunctionDesc {
                    entry: 7,
                    arity: 0,
                    frame_size: 8,
                    name: Some("TestClass".to_string()),
                    is_generator: false,
                    rest_param_index: None,
                },
                // Method function
                crate::ir_contract::Ir3FunctionDesc {
                    entry: 9,
                    arity: 0,
                    frame_size: 8,
                    name: Some("testMethod".to_string()),
                    is_generator: false,
                    rest_param_index: None,
                },
            ],
        );
        m.constant_pool = vec![
            "prototype".into(),
            "testMethod".into(),
            "method called".into(),
        ];
        m
    };
    core.set_reg(0, Value::Function(0));
    core.set_reg(2, Value::Function(1));
    let result = core.execute(&module);
    assert!(result.is_ok());

    // Verify the method is accessible on the instance
    let method_value = core.read_reg(4).unwrap();
    match method_value {
        Value::Function(1) => {
            // Method correctly retrieved from prototype
        }
        _ => panic!(
            "Method should be accessible via prototype chain, got {:?}",
            method_value
        ),
    }
}

#[test]
fn class_extends_sets_prototype_chain() {
    let mut config = InterpreterConfig::quickjs_defaults();
    config
        .granted_capabilities
        .insert(RuntimeCapability::VmDispatch);
    config
        .granted_capabilities
        .insert(RuntimeCapability::HeapAllocate);
    let mut core = InterpreterCore::new(config, "class-extends-test");

    // Test that class extends properly sets up prototype chain.
    // Parent (Value::Function(0)) and child (Value::Function(1)) constructors
    // are seeded directly; function bodies are inlined into the flat
    // instruction stream at their `entry` offsets. String-keyed property
    // access takes a register key, so keys are materialized via LoadStr.
    let module = {
        let mut m = test_module_with_functions(
            vec![
                // r6 = "prototype", r7 = "__proto__" property-key scratch
                Ir3Instruction::LoadStr {
                    dst: 6,
                    pool_index: 0,
                },
                Ir3Instruction::LoadStr {
                    dst: 7,
                    pool_index: 1,
                },
                // Get Parent.prototype
                Ir3Instruction::GetProperty {
                    obj: 0,
                    key: 6,
                    dst: 2, // Parent prototype
                },
                // Get Child.prototype
                Ir3Instruction::GetProperty {
                    obj: 1,
                    key: 6,
                    dst: 3, // Child prototype
                },
                // Set Child.prototype.__proto__ = Parent.prototype
                Ir3Instruction::SetProperty {
                    obj: 3,
                    key: 7,
                    val: 2,
                },
                // Create child instance (Value::Function(1) seeded in r1)
                Ir3Instruction::Construct {
                    callee: 1,
                    args: RegRange { start: 8, count: 0 },
                    dst: 4, // Child instance
                },
                // Verify inheritance by checking prototype chain
                Ir3Instruction::GetProperty {
                    obj: 4,
                    key: 7,
                    dst: 5, // Should be Child.prototype
                },
                Ir3Instruction::Halt,
                // Parent constructor body (entry = 8)
                Ir3Instruction::LoadUndefined { dst: 0 },
                Ir3Instruction::Return { value: 0 },
                // Child constructor body (entry = 10)
                Ir3Instruction::LoadUndefined { dst: 0 },
                Ir3Instruction::Return { value: 0 },
            ],
            vec![
                // Parent constructor
                crate::ir_contract::Ir3FunctionDesc {
                    entry: 8,
                    arity: 0,
                    frame_size: 8,
                    name: Some("ParentClass".to_string()),
                    is_generator: false,
                    rest_param_index: None,
                },
                // Child constructor
                crate::ir_contract::Ir3FunctionDesc {
                    entry: 10,
                    arity: 0,
                    frame_size: 8,
                    name: Some("ChildClass".to_string()),
                    is_generator: false,
                    rest_param_index: None,
                },
            ],
        );
        m.constant_pool = vec!["prototype".into(), "__proto__".into()];
        m
    };
    core.set_reg(0, Value::Function(0));
    core.set_reg(1, Value::Function(1));
    let result = core.execute(&module);
    assert!(result.is_ok());

    // Verify prototype chain is correctly established
    let child_instance = core.read_reg(4).unwrap();
    let child_proto = core.read_reg(5).unwrap();
    match (child_instance, child_proto) {
        (Value::Object(instance_id), Value::Object(_proto_id)) => {
            let instance = &core.heap[instance_id.0 as usize];
            assert_eq!(instance.constructor_function, Some(1)); // Child constructor
            // The prototype chain should be set up correctly
        }
        _ => panic!("Inheritance setup should create proper prototype chain"),
    }
}

// -----------------------------------------------------------------------
// Timer substrate tests
// -----------------------------------------------------------------------

/// bd-suwvw: setTimeout/setInterval return an object handle (like
/// Node/bun's Timeout); resolve the deterministic timer id from its
/// `__timerId` property.
fn timer_handle_id(core: &InterpreterCore, handle: &Value) -> u32 {
    let Value::Object(object_id) = handle else {
        panic!("timer builtins should return an object handle, got {handle:?}");
    };
    match core
        .heap
        .get(object_id.0 as usize)
        .and_then(|object| object.properties.get("__timerId"))
    {
        Some(Value::Int(id)) => *id as u32,
        other => panic!("timer handle should carry __timerId, got {other:?}"),
    }
}

#[test]
fn set_timeout_deterministic_regression() {
    // Regression test: Verify setTimeout uses deterministic timer IDs instead of wall-clock time
    // This test ensures the fix for bd-1orko where SystemTime::now() was replaced with next_timer_id

    let mut config = InterpreterConfig::quickjs_defaults();
    config
        .granted_capabilities
        .insert(RuntimeCapability::VmDispatch);
    config
        .granted_capabilities
        .insert(RuntimeCapability::HeapAllocate);
    config.granted_capabilities.insert(RuntimeCapability::Timer);

    // Create two identical interpreter instances with same initial state
    let mut core1 = InterpreterCore::new(config.clone(), "deterministic-timer-test-1");
    let mut core2 = InterpreterCore::new(config, "deterministic-timer-test-2");

    let function_id_1 = core1.allocate_function(
        "callback1",
        vec![],
        vec![Ir3Instruction::Halt],
        0,
        std::collections::BTreeMap::new(),
    );
    let function_id_2 = core2.allocate_function(
        "callback2",
        vec![],
        vec![Ir3Instruction::Halt],
        0,
        std::collections::BTreeMap::new(),
    );

    let callback1 = Value::Function(function_id_1);
    let callback2 = Value::Function(function_id_2);

    // Execute setTimeout on both cores - should get identical timer IDs
    // because they use deterministic next_timer_id, not wall-clock time
    let timer_id_1 = core1
        .execute_builtin_call(
            "builtin:SetTimeout",
            vec![Value::Undefined, callback1, Value::Int(1000)],
        )
        .expect("setTimeout should succeed on core1");

    let timer_id_2 = core2
        .execute_builtin_call(
            "builtin:SetTimeout",
            vec![Value::Undefined, callback2, Value::Int(1000)],
        )
        .expect("setTimeout should succeed on core2");

    // Timer IDs should be identical because they're deterministic, not wall-clock based
    let id1 = timer_handle_id(&core1, &timer_id_1);
    let id2 = timer_handle_id(&core2, &timer_id_2);
    assert_eq!(
        id1, id2,
        "Timer IDs should be identical across identical interpreter instances (deterministic)"
    );

    // Verify both interpreters have the timer in their active_timers state
    assert_eq!(core1.active_timers.len(), 1);
    assert_eq!(core2.active_timers.len(), 1);

    assert!(core1.active_timers.contains_key(&id1));
    assert!(core2.active_timers.contains_key(&id2));
}

#[test]
fn set_timeout_returns_deterministic_id() {
    // Regression test: setTimeout returns deterministic, monotonic timer IDs
    let mut config = InterpreterConfig::quickjs_defaults();
    config
        .granted_capabilities
        .insert(RuntimeCapability::VmDispatch);
    config
        .granted_capabilities
        .insert(RuntimeCapability::HeapAllocate);
    config.granted_capabilities.insert(RuntimeCapability::Timer);

    let mut core = InterpreterCore::new(config, "setTimeout-deterministic-test");

    // Create a simple callback function
    let function_id = core.allocate_function(
        "test_callback",
        vec![],
        vec![Ir3Instruction::Halt],
        0,
        std::collections::BTreeMap::new(),
    );
    let callback_val = Value::Function(function_id);

    // Test multiple setTimeout calls return sequential IDs
    let timer_id_1 = core
        .execute_builtin_call(
            "builtin:SetTimeout",
            vec![Value::Undefined, callback_val.clone(), Value::Int(1000)],
        )
        .expect("setTimeout should succeed");

    let timer_id_2 = core
        .execute_builtin_call(
            "builtin:SetTimeout",
            vec![Value::Undefined, callback_val.clone(), Value::Int(2000)],
        )
        .expect("setTimeout should succeed");

    // Verify timer IDs are deterministic and sequential
    let id1 = timer_handle_id(&core, &timer_id_1);
    let id2 = timer_handle_id(&core, &timer_id_2);
    assert_eq!(id2, id1 + 1, "Timer IDs should be sequential");

    // Verify timers are stored in active_timers
    assert_eq!(core.active_timers.len(), 2, "Both timers should be active");
    assert!(core.active_timers.contains_key(&id1));
    assert!(core.active_timers.contains_key(&id2));
}

#[test]
fn cancellation_before_timer_turn_revokes_delivery_permanently() {
    let token = CancellationToken::new();
    let mut config = InterpreterConfig::quickjs_defaults();
    config.granted_capabilities = BTreeSet::from([
        RuntimeCapability::VmDispatch,
        RuntimeCapability::HeapAllocate,
        RuntimeCapability::Timer,
    ]);
    config.cancellation_token = Some(token.clone());
    let mut core = InterpreterCore::new(config, "timer-cancellation-before-turn");
    let callback = core.allocate_function(
        "must_not_run",
        vec![],
        vec![Ir3Instruction::Halt],
        0,
        BTreeMap::new(),
    );
    core.execute_builtin_call(
        "builtin:SetTimeout",
        vec![Value::Undefined, Value::Function(callback), Value::Int(1)],
    )
    .expect("timer schedules before cancellation");
    assert_eq!(core.active_timers.len(), 1);
    assert_eq!(core.pending_timer_tasks.len(), 1);
    let callback_completion_count = core
        .witness_events
        .iter()
        .filter(|event| event.kind == WitnessEventKind::ExecutionCompleted)
        .count();
    let callback_witness_before = core.timer_callback_witness;

    token.cancel();
    assert_eq!(
        core.run_event_loop_until_idle_with_module(None),
        Err(InterpreterError::Cancelled)
    );
    assert!(core.active_timers.is_empty());
    assert!(core.pending_timer_tasks.is_empty());
    assert!(!core.event_loop.has_pending_work());
    assert_eq!(core.timer_callback_witness, callback_witness_before);
    assert_eq!(
        core.witness_events
            .iter()
            .filter(|event| event.kind == WitnessEventKind::ExecutionCompleted)
            .count(),
        callback_completion_count,
        "cancellation must prevent the timer callback completion witness"
    );

    token.reset();
    core.run_event_loop_until_idle_with_module(None)
        .expect("revoked timer cannot reappear after token reset");
    assert_eq!(core.timer_callback_witness, callback_witness_before);
    assert_eq!(
        core.witness_events
            .iter()
            .filter(|event| event.kind == WitnessEventKind::ExecutionCompleted)
            .count(),
        callback_completion_count,
        "resetting the token must not resurrect the revoked timer callback"
    );
}

#[test]
fn clear_timeout_cancels_deterministic() {
    // Regression test: clearTimeout properly cancels timers from active_timers
    let mut config = InterpreterConfig::quickjs_defaults();
    config
        .granted_capabilities
        .insert(RuntimeCapability::VmDispatch);
    config
        .granted_capabilities
        .insert(RuntimeCapability::HeapAllocate);
    config.granted_capabilities.insert(RuntimeCapability::Timer);

    let mut core = InterpreterCore::new(config, "clearTimeout-test");

    // Create a callback function
    let function_id = core.allocate_function(
        "test_callback",
        vec![],
        vec![Ir3Instruction::Halt],
        0,
        std::collections::BTreeMap::new(),
    );
    let callback_val = Value::Function(function_id);

    // Schedule multiple timers
    let timer_id_1 = core
        .execute_builtin_call(
            "builtin:SetTimeout",
            vec![Value::Undefined, callback_val.clone(), Value::Int(1000)],
        )
        .expect("setTimeout should succeed");

    let timer_id_2 = core
        .execute_builtin_call(
            "builtin:SetTimeout",
            vec![Value::Undefined, callback_val.clone(), Value::Int(2000)],
        )
        .expect("setTimeout should succeed");

    // Verify both timers are active
    assert_eq!(core.active_timers.len(), 2, "Both timers should be active");

    // Clear the first timer
    let clear_result = core
        .execute_builtin_call(
            "builtin:ClearTimeout",
            vec![Value::Undefined, timer_id_1.clone()],
        )
        .expect("clearTimeout should succeed");

    assert_eq!(
        clear_result,
        Value::Undefined,
        "clearTimeout returns undefined"
    );

    // Verify first timer was removed but second remains
    assert_eq!(
        core.active_timers.len(),
        1,
        "Only one timer should remain active"
    );
    assert!(
        !core
            .active_timers
            .contains_key(&timer_handle_id(&core, &timer_id_1))
    );
    assert!(
        core.active_timers
            .contains_key(&timer_handle_id(&core, &timer_id_2))
    );

    // Clear the second timer
    let clear_result_2 = core
        .execute_builtin_call(
            "builtin:ClearTimeout",
            vec![Value::Undefined, timer_id_2.clone()],
        )
        .expect("clearTimeout should succeed");

    assert_eq!(
        clear_result_2,
        Value::Undefined,
        "clearTimeout returns undefined"
    );

    // Verify all timers are cleared
    assert_eq!(
        core.active_timers.len(),
        0,
        "No timers should remain active"
    );

    // Test clearing non-existent timer (should be safe)
    let clear_invalid = core
        .execute_builtin_call(
            "builtin:ClearTimeout",
            vec![Value::Undefined, Value::Int(99999)],
        )
        .expect("clearTimeout with invalid ID should succeed");

    assert_eq!(
        clear_invalid,
        Value::Undefined,
        "clearing invalid timer returns undefined"
    );
}

#[test]
fn set_interval_builtin_registers_repeating_timer() {
    let mut config = InterpreterConfig::quickjs_defaults();
    config
        .granted_capabilities
        .insert(RuntimeCapability::VmDispatch);
    config
        .granted_capabilities
        .insert(RuntimeCapability::HeapAllocate);
    config.granted_capabilities.insert(RuntimeCapability::Timer);

    let mut core = InterpreterCore::new(config, "interval-repeats-test");

    // Create a callback function
    let function_id = core.allocate_function(
        "interval_callback",
        vec![],
        vec![], // No body needed for this test
        0,
        std::collections::BTreeMap::new(),
    );
    let callback_val = Value::Function(function_id);

    let timer_id_val = core
        .execute_builtin_call(
            "builtin:SetInterval",
            vec![Value::Undefined, callback_val, Value::Int(1000)],
        )
        .expect("setInterval should succeed");

    let timer_id = timer_handle_id(&core, &timer_id_val);

    let timer = core
        .active_timers
        .get(&timer_id)
        .expect("interval timer should exist");
    assert!(timer.repeating, "setInterval timer should be repeating");
    assert_eq!(timer.delay_ms, 1000, "Timer should have correct interval");
}

#[test]
fn clear_interval_builtin_removes_repeating_timer() {
    let mut config = InterpreterConfig::quickjs_defaults();
    config
        .granted_capabilities
        .insert(RuntimeCapability::VmDispatch);
    config
        .granted_capabilities
        .insert(RuntimeCapability::HeapAllocate);
    config.granted_capabilities.insert(RuntimeCapability::Timer);

    let mut core = InterpreterCore::new(config, "clearInterval-test");

    let function_id = core.allocate_function(
        "interval_callback",
        vec![],
        vec![Ir3Instruction::Halt],
        0,
        std::collections::BTreeMap::new(),
    );
    let callback_val = Value::Function(function_id);

    let timer_id = core
        .execute_builtin_call(
            "builtin:SetInterval",
            vec![Value::Undefined, callback_val, Value::Int(250)],
        )
        .expect("setInterval should succeed");

    assert_eq!(core.active_timers.len(), 1);

    let clear_result = core
        .execute_builtin_call(
            "builtin:ClearInterval",
            vec![Value::Undefined, timer_id.clone()],
        )
        .expect("clearInterval should succeed");

    assert_eq!(
        clear_result,
        Value::Undefined,
        "clearInterval returns undefined"
    );
    assert!(
        core.active_timers.is_empty(),
        "clearInterval should remove active interval"
    );

    let clear_invalid = core
        .execute_builtin_call(
            "builtin:ClearInterval",
            vec![Value::Undefined, Value::Int(99999)],
        )
        .expect("clearInterval with invalid ID should succeed");

    assert_eq!(
        clear_invalid,
        Value::Undefined,
        "clearing invalid interval returns undefined"
    );
}

// NOTE: prior `fn timer_ordering()` and `fn microtask_before_timer()`
// placeholder stubs (bd-5116c) were moved to the standalone
// `event_loop_timer_microtask_tests` module above, which compiles under
// plain `#[cfg(test)]` instead of this feature-gated (and currently
// broken — bd-2j7uk) `tests` module. The real tests now actually run.

#[test]
fn nested_set_timeout() {
    // Test that setTimeout inside timer callback works (nested timer scheduling)
    let mut config = InterpreterConfig::quickjs_defaults();
    config
        .granted_capabilities
        .insert(RuntimeCapability::VmDispatch);
    config
        .granted_capabilities
        .insert(RuntimeCapability::HeapAllocate);
    config.granted_capabilities.insert(RuntimeCapability::Timer);

    let mut core = InterpreterCore::new(config, "nested-timeout-test");

    // Create callback functions
    let function_id_1 = core.allocate_function(
        "outer_callback",
        vec![],
        vec![], // No body needed for this test
        0,
        std::collections::BTreeMap::new(),
    );
    let callback_val_1 = Value::Function(function_id_1);

    // Schedule first timer
    let timer_id_1 = core
        .execute_builtin_call(
            "builtin:SetTimeout",
            vec![Value::Undefined, callback_val_1, Value::Int(100)],
        )
        .expect("setTimeout should succeed");

    // Verify timer was created
    let _ = timer_handle_id(&core, &timer_id_1);
    assert_eq!(core.active_timers.len(), 1, "One timer should be active");

    // Run the event loop - this should execute the outer timer
    core.run_event_loop_until_idle();

    // The timer execution framework is now in place
    // In a full implementation, the nested timer would be scheduled during callback execution
    // For now, we verify that the event loop infrastructure works
}

#[test]
fn zero_delay_timeout() {
    // Test that setTimeout(cb, 0) fires after current macrotask + microtasks
    let mut config = InterpreterConfig::quickjs_defaults();
    config
        .granted_capabilities
        .insert(RuntimeCapability::VmDispatch);
    config
        .granted_capabilities
        .insert(RuntimeCapability::HeapAllocate);
    config.granted_capabilities.insert(RuntimeCapability::Timer);

    let mut core = InterpreterCore::new(config, "zero-delay-timeout-test");

    // Create a simple callback function that sets a variable
    let function_id = core.allocate_function(
        "timer_callback",
        vec![],
        vec![], // No body needed for this test
        0,
        std::collections::BTreeMap::new(),
    );
    let callback_val = Value::Function(function_id);

    // Call setTimeout with 0 delay
    let timer_id = core
        .execute_builtin_call(
            "builtin:SetTimeout",
            vec![Value::Undefined, callback_val, Value::Int(0)],
        )
        .expect("setTimeout should succeed");

    // Verify timer was created
    let id = timer_handle_id(&core, &timer_id);
    assert!(core.active_timers.contains_key(&id));

    // Run the event loop to execute the timer
    core.run_event_loop_until_idle();

    // The timer should have been executed
    // Note: In this simplified test, we just verify the event loop ran without errors
    // A more comprehensive test would verify the actual callback execution
}

// RC-4.3 Containment Action Enforcement Tests
mod containment_tests {
    use super::*;

    pub(super) fn test_interpreter() -> InterpreterCore {
        InterpreterCore::new(test_quickjs_config(), "test-containment")
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
            .expect("operation should succeed for valid inputs");

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
        // The decision-receipt timestamp is the interpreter's DETERMINISTIC
        // instruction counter (bd-jn3uv.1), not wall-clock, so a receipt minted
        // against a pristine interpreter (instruction 0) would legitimately carry
        // timestamp 0. Advance the counter to model a containment action taken
        // mid-execution — the realistic point at which receipts are emitted — so
        // the `timestamp > 0` field check holds. `ip` is left at 0, keeping the
        // `instruction_pointer == 0` assertion below intact.
        interpreter.instructions_executed = 1;
        interpreter
            .handle_containment_action(HookAction::Terminate("test".to_string()))
            .ok();

        let receipts = interpreter.decision_receipts().receipts();
        assert_eq!(receipts.len(), 1);

        let receipt = &receipts[0];
        assert_eq!(receipt.extension_id, "extension:current");
        assert_eq!(receipt.operation_type, "terminate");
        assert_eq!(receipt.risk_score, 900_000);
        assert!(receipt.action_taken.contains("terminate"));
        assert!(receipt.timestamp > 0);
        assert_eq!(receipt.instruction_pointer, 0);
        assert!(!receipt.register_state_hash.is_empty());
        assert!(!receipt.signature.is_empty());
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
    fn receipt_signature_uses_hmac_sha256() {
        let key = [0x11; 32];
        let log = EvidenceLog::with_key(key);
        let receipt = DecisionReceipt {
            extension_id: "extension:golden".to_string(),
            operation_type: "sandbox".to_string(),
            risk_score: 125_000,
            action_taken: "sandbox".to_string(),
            timestamp: 42,
            instruction_pointer: 7,
            register_state_hash: "reghash-test".to_string(),
            previous_receipt_hash: Some("prev-sig".to_string()),
            signature: String::new(),
        };

        let signature = log.sign_receipt(&receipt);
        let mut expected_mac = <Hmac<Sha256> as Mac>::new_from_slice(&key)
            .expect("operation should succeed for valid inputs");
        // bd-gn3mt: receipt_signing_message now returns Vec<u8> directly.
        expected_mac.update(&log.receipt_signing_message(&receipt));
        let expected = format!(
            "hmac-sha256-{}",
            hex::encode(expected_mac.finalize().into_bytes())
        );

        assert_eq!(signature, expected);
        assert_eq!(signature.len(), "hmac-sha256-".len() + 64);
    }

    #[test]
    fn chain_verification_rejects_payload_tampering() {
        let mut log = EvidenceLog::with_key([0x22; 32]);
        log.add_receipt(
            "extension:current".to_string(),
            "sandbox".to_string(),
            125_000,
            "sandbox".to_string(),
            0,
            &[Value::Int(1)],
            42, // deterministic timestamp (bd-jn3uv.1)
        );

        assert!(log.verify_chain());

        log.receipts[0].action_taken = "allow".to_string();

        assert!(!log.verify_chain());
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

        let json_export = interpreter
            .export_decision_receipts()
            .expect("operation should succeed for valid inputs");
        let parsed: serde_json::Value =
            serde_json::from_str(&json_export).expect("deserialize known-valid JSON");

        assert_eq!(parsed["evidence_type"], "guardplane_decision_chain");
        assert_eq!(parsed["receipt_count"], 1);
        assert_eq!(parsed["chain_verified"], true);
        assert!(parsed["receipts"].is_array());
        assert!(
            parsed["exported_at"]
                .as_u64()
                .expect("operation should succeed for valid inputs")
                > 0
        );
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

    #[test]
    fn async_function_call_returns_promise() {
        let mut core = test_interpreter();

        // Create a simple async function object in the store
        let async_func_id = core.async_functions.len() as u32;
        core.async_functions.push(AsyncFunctionObject {
            owner_module: Arc::new(test_module(vec![])),
            isolated_execution: None,
            function_index: 0, // dummy function index
            closure_index: None,
            saved_ip: 0,
            saved_registers: Vec::new(),
            saved_register_labels: Vec::new(),
            saved_register_base: 0,
            phase: AsyncFunctionPhase::SuspendedStart,
            result_promise: 0, // will be set when called
        });

        // Test that calling an async function returns a promise
        let async_func_value = Value::AsyncFunction(async_func_id);

        // For now, we can't fully test this without a complete module
        // but we can verify the Value::AsyncFunction variant exists
        match async_func_value {
            Value::AsyncFunction(id) => assert_eq!(id, async_func_id),
            _ => panic!("Expected AsyncFunction value"),
        }
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
                "boom".to_string()
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
    fn await_resolved_promise_returns_value() {
        let mut core = test_interpreter();

        // Create a pre-resolved promise
        let handle = core.promise_store.create();
        let js_val = crate::object_model::JsValue::Int(42);
        let label = crate::ifc_artifacts::Label::Public;
        core.promise_store
            .fulfill(handle, js_val, label, &mut core.event_loop.microtasks)
            .expect("operation should succeed for valid inputs");

        // Store the promise in a register
        core.mutate_registers(|r| {
            r.resize(10, Value::Undefined);
        });
        core.set_reg(0, Value::Promise(handle.0));

        // Test that we can read the promise value
        let promise_val = core
            .read_reg(0)
            .expect("operation should succeed for valid inputs");
        match promise_val {
            Value::Promise(h) => {
                assert_eq!(h, handle.0);

                // Verify the promise is resolved
                let record = core
                    .promise_store
                    .get(handle)
                    .expect("operation should succeed for valid inputs");
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
    // `3.14` below is an intentional decimal test value, not an approximation of PI (bd-n0sap).
    #[allow(clippy::approx_constant)]
    fn value_to_js_value_conversion() {
        // Test that the production value_to_js_value conversion works correctly
        // This exercises the actual conversion helper used by the promise subsystem

        let test_cases = vec![
            (Value::Undefined, crate::object_model::JsValue::Undefined),
            (Value::Null, crate::object_model::JsValue::Null),
            (Value::Bool(true), crate::object_model::JsValue::Bool(true)),
            (
                Value::Bool(false),
                crate::object_model::JsValue::Bool(false),
            ),
            (Value::Int(42), crate::object_model::JsValue::Int(42)),
            (Value::Int(-123), crate::object_model::JsValue::Int(-123)),
            (
                Value::str("hello"),
                crate::object_model::JsValue::Str("hello".to_string()),
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

        for (input, expected) in test_cases {
            let result = InterpreterCore::value_to_js_value(&input);
            assert_eq!(result, expected, "Conversion failed for {:?}", input);
        }

        // Test Float conversion (special case due to bit representation)
        let float_val = Value::Float(Float64::new(3.14));
        let float_result = InterpreterCore::value_to_js_value(&float_val);
        if let crate::object_model::JsValue::Float(bits) = float_result {
            assert_eq!(f64::from_bits(bits), 3.14, "Float conversion incorrect");
        } else {
            panic!("Expected Float JsValue");
        }

        // Test fallback case (complex types fall back to string conversion)
        let promise_val = Value::Promise(7);
        let promise_result = InterpreterCore::value_to_js_value(&promise_val);
        assert!(
            matches!(promise_result, crate::object_model::JsValue::Str(_)),
            "Complex types should fall back to string conversion"
        );
    }

    #[test]
    fn async_generator_creation() {
        let mut core = test_interpreter();
        let module = test_module_with_functions(
            vec![
                Ir3Instruction::Call {
                    callee: 0,
                    args: RegRange { start: 8, count: 0 },
                    dst: 5,
                },
                Ir3Instruction::Halt,
                Ir3Instruction::Halt,
            ],
            vec![Ir3FunctionDesc {
                entry: 2,
                arity: 0,
                frame_size: 0,
                name: Some("test_async_gen".to_string()),
                is_generator: false,
                rest_param_index: None,
            }],
        );

        core.closures.push(ClosureValue {
            function_index: 0,
            captured_env: Vec::new(),
        });
        core.mutate_registers(|r| {
            r.resize(10, Value::Undefined);
        });
        core.set_reg(0, Value::AsyncGeneratorFunction(0));

        core.execute(&module)
            .expect("async generator creation should succeed");

        assert_eq!(core.async_generators.len(), 1);
        let created_gen = &core.async_generators[0];
        let invocation = core.generators[created_gen.generator_id as usize]
            .invocation
            .as_ref()
            .unwrap();
        assert_eq!(invocation.function_index, 0);
        assert_eq!(invocation.closure_index, Some(0));
        assert!(matches!(
            created_gen.phase,
            AsyncGeneratorPhase::SuspendedStart
        ));

        if let Value::AsyncGeneratorObject(gen_id) = core.registers[5] {
            assert_eq!(gen_id, 0);
        } else {
            panic!("Expected AsyncGeneratorObject in result register");
        }
    }

    #[test]
    fn async_generator_function_call_creates_object() {
        let mut core = test_interpreter();

        let module = test_module_with_functions(
            vec![
                Ir3Instruction::Call {
                    callee: 0,
                    args: RegRange { start: 3, count: 1 },
                    dst: 5,
                },
                Ir3Instruction::Call {
                    callee: 7,
                    args: RegRange {
                        start: 10,
                        count: 2,
                    },
                    dst: 9,
                },
                Ir3Instruction::Halt,
                Ir3Instruction::Halt,
            ],
            vec![
                Ir3FunctionDesc {
                    entry: 3,
                    arity: 1,
                    frame_size: 1,
                    name: Some("async_gen_1".to_string()),
                    is_generator: false,
                    rest_param_index: None,
                },
                Ir3FunctionDesc {
                    entry: 3,
                    arity: 2,
                    frame_size: 2,
                    name: Some("async_gen_2".to_string()),
                    is_generator: false,
                    rest_param_index: None,
                },
            ],
        );

        core.closures.push(ClosureValue {
            function_index: 0,
            captured_env: Vec::new(),
        });
        core.closures.push(ClosureValue {
            function_index: 1,
            captured_env: Vec::new(),
        });

        core.mutate_registers(|r| {
            r.resize(15, Value::Undefined);
        });

        // First call: create async generator from function 0
        core.set_reg(0, Value::AsyncGeneratorFunction(0));
        core.set_reg(3, Value::str("arg1")); // argument

        // Second call: create async generator from function 1
        core.set_reg(7, Value::AsyncGeneratorFunction(1));
        core.set_reg(10, Value::str("arg1")); // argument 1
        core.set_reg(11, Value::Int(42)); // argument 2

        core.execute(&module)
            .expect("async generator calls should succeed");

        // Verify both async generators were created correctly
        assert_eq!(core.async_generators.len(), 2);

        // First async generator
        let gen1 = &core.async_generators[0];
        let invocation = core.generators[gen1.generator_id as usize]
            .invocation
            .as_ref()
            .unwrap();
        assert_eq!(invocation.function_index, 0);
        assert_eq!(invocation.closure_index, Some(0));
        assert!(matches!(gen1.phase, AsyncGeneratorPhase::SuspendedStart));

        // Second async generator
        let gen2 = &core.async_generators[1];
        let invocation = core.generators[gen2.generator_id as usize]
            .invocation
            .as_ref()
            .unwrap();
        assert_eq!(invocation.function_index, 1);
        assert_eq!(invocation.closure_index, Some(1));
        assert!(matches!(gen2.phase, AsyncGeneratorPhase::SuspendedStart));

        // Verify result registers contain correct AsyncGeneratorObject values
        if let Value::AsyncGeneratorObject(id1) = core.registers[5] {
            assert_eq!(id1, 0);
        } else {
            panic!("Expected first AsyncGeneratorObject");
        }

        if let Value::AsyncGeneratorObject(id2) = core.registers[9] {
            assert_eq!(id2, 1);
        } else {
            panic!("Expected second AsyncGeneratorObject");
        }
    }

    #[test]
    fn async_generator_next_returns_promise() {
        let mut core = test_interpreter();
        let backing = core
            .push_generator_object(GeneratorObject {
                owner_module: Arc::new(test_module(vec![])),
                invocation: None,
                execution: None,
                resume_dst: None,
                phase: GeneratorPhase::Completed,
                prototype: None,
            })
            .unwrap();
        let async_gen_id = core
            .push_async_generator_object(AsyncGeneratorObject {
                awaited_kind: async_generator::AwaitKind::Body,
                delegation: None,
                generator_id: backing,
                requests: VecDeque::new(),
                awaited: None,
                phase: AsyncGeneratorPhase::Completed,
            })
            .unwrap();

        let result = core
            .enqueue_async_generator_request(
                &test_module(vec![]),
                async_gen_id,
                GeneratorResumeKind::Next,
                Value::Undefined,
                Label::Public,
            )
            .expect("operation should succeed for valid inputs");

        match result {
            Value::Promise(_) => {}
            _ => panic!("Expected Promise value, got {:?}", result),
        }
    }

    #[test]
    fn async_generator_next_executes_suspended_body() {
        let mut core = test_interpreter();
        let module = test_module_with_functions(
            vec![
                Ir3Instruction::LoadInt { dst: 0, value: 41 },
                Ir3Instruction::Yield {
                    value: 0,
                    delegate: false,
                    resume_dst: 1,
                },
                Ir3Instruction::LoadInt { dst: 0, value: 42 },
                Ir3Instruction::Return { value: 0 },
            ],
            vec![Ir3FunctionDesc {
                entry: 0,
                arity: 0,
                frame_size: 2,
                name: Some("async-generator-body".into()),
                is_generator: true,
                rest_param_index: None,
            }],
        );
        let id = core
            .create_async_generator(
                Arc::new(module.clone()),
                GeneratorInvocation {
                    function_index: 0,
                    closure_index: None,
                    arguments: Vec::new(),
                    argument_labels: Vec::new(),
                    this_value: Value::Undefined,
                    this_label: Label::Public,
                    inline_context_label: None,
                    module_specifier: None,
                    generated_function_artifact: None,
                },
                None,
            )
            .unwrap();
        for (expected, done) in [(41, false), (42, true)] {
            let Value::Promise(promise) = core
                .enqueue_async_generator_request(
                    &module,
                    id,
                    GeneratorResumeKind::Next,
                    Value::Undefined,
                    Label::Public,
                )
                .unwrap()
            else {
                panic!("next must return a Promise");
            };
            core.drain_microtasks(Some(&module)).unwrap();
            let crate::promise_model::PromiseState::Fulfilled(
                crate::object_model::JsValue::Object(object),
            ) = core
                .promise_store
                .get(crate::promise_model::PromiseHandle(promise))
                .unwrap()
                .state
            else {
                panic!("next must fulfill with an iterator result");
            };
            assert_eq!(
                core.heap[object.0 as usize].properties.get("value"),
                Some(&Value::Int(expected))
            );
            assert_eq!(
                core.heap[object.0 as usize].properties.get("done"),
                Some(&Value::Bool(done))
            );
        }
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

    /// Regression test for bd-3ovua: String casing builtins should route through
    /// RequireObjectCoercible and stay stable across all mapped builtin IDs.
    #[test]
    fn string_case_conversion_id_dispatch_matrix() {
        let mut interpreter = test_interpreter();

        let lowercase_builtin_ids = [34u32, 293, 330, 386];
        let uppercase_builtin_ids = [35u32, 297, 331, 387];
        let all_builtin_ids = lowercase_builtin_ids
            .iter()
            .chain(uppercase_builtin_ids.iter());

        let invalid_values = vec![Value::Null, Value::Undefined];
        for invalid in invalid_values {
            for &builtin_id in lowercase_builtin_ids.iter().chain(&uppercase_builtin_ids) {
                interpreter.set_reg(0, invalid.clone());
                let result =
                    interpreter.call_builtin_by_id(builtin_id, RegRange { start: 0, count: 1 });
                assert!(
                    matches!(
                        result,
                        Err(InterpreterError::TypeError { expected, got })
                            if expected == "object-coercible String.prototype receiver" &&
                                ((got == "null" && invalid == Value::Null) ||
                                (got == "undefined" && invalid == Value::Undefined))
                    ),
                    "string case builtin {} should reject {:?}",
                    builtin_id,
                    invalid
                );
            }
        }

        let test_cases = vec![
            Value::Function(100),
            Value::Promise(200),
            Value::AsyncGeneratorObject(300),
            Value::BuiltinFunction(BuiltinFunction::require("array-from-test")),
            Value::Object(ObjectId(400)),
            Value::Iterator(500),
            Value::Bool(false),
            Value::Int(-42),
            Value::str("ßa"),
            Value::Closure(600),
        ];

        for input in test_cases {
            // These fixtures are non-nullish: their primitive spelling is
            // the casing expectation for every dispatched builtin ID.
            let expected = InterpreterCore::value_to_primitive_string(&input);

            for &builtin_id in all_builtin_ids.clone() {
                interpreter.set_reg(0, input.clone());
                let result = interpreter
                    .call_builtin_by_id(builtin_id, RegRange { start: 0, count: 1 })
                    .expect("string casing builtin should execute");
                let expected_result = if lowercase_builtin_ids.contains(&builtin_id) {
                    Value::str(expected.to_lowercase())
                } else {
                    Value::str(expected.to_uppercase())
                };
                assert_eq!(
                    result, expected_result,
                    "string casing builtin {} conversion mismatch for {:?}",
                    builtin_id, input
                );
            }
        }
    }

    #[test]
    fn string_case_conversion_preserves_exact_units_across_builtin_ids() {
        let input =
            JsString::from_code_units(&[0xd800, 0x00df, 0xdc00, 0x0130, 0xd801, 0xdc28, 0xd800]);
        let lower = JsString::from_code_units(&[
            0xd800, 0x00df, 0xdc00, 0x0069, 0x0307, 0xd801, 0xdc28, 0xd800,
        ]);
        let upper = JsString::from_code_units(&[
            0xd800, 0x0053, 0x0053, 0xdc00, 0x0130, 0xd801, 0xdc00, 0xd800,
        ]);
        let mut interpreter = test_interpreter();
        for (builtin_ids, expected) in [
            ([34_u32, 293, 330, 386], lower),
            ([35_u32, 297, 331, 387], upper),
        ] {
            for builtin_id in builtin_ids {
                interpreter.set_reg(0, Value::Str(input.clone()));
                let actual = interpreter
                    .call_builtin_by_id(builtin_id, RegRange { start: 0, count: 1 })
                    .expect("exact string casing should execute");
                assert_eq!(
                    actual,
                    Value::Str(expected.clone()),
                    "string casing builtin {builtin_id}"
                );
            }
        }
    }

    /// Keep helper-level RequireObjectCoercible behavior explicit and deterministic.
    #[test]
    fn string_case_conversion_require_object_coercible() {
        let null_result = InterpreterCore::require_object_coercible_to_js_string(&Value::Null);
        assert!(matches!(
            null_result,
            Err(InterpreterError::TypeError { expected, got })
                if expected == "object-coercible String.prototype receiver" && got == "null"
        ));

        let undefined_result =
            InterpreterCore::require_object_coercible_to_js_string(&Value::Undefined);
        assert!(matches!(
            undefined_result,
            Err(InterpreterError::TypeError { expected, got })
                if expected == "object-coercible String.prototype receiver" && got == "undefined"
        ));

        for valid in [
            Value::str("hello"),
            Value::Int(42),
            Value::Bool(true),
            Value::Function(1),
            Value::Promise(2),
            Value::AsyncGeneratorObject(3),
            Value::BuiltinFunction(BuiltinFunction::require("math-abs-test")),
            Value::Closure(4),
            Value::Iterator(5),
            Value::Object(ObjectId(6)),
        ] {
            assert!(InterpreterCore::require_object_coercible_to_js_string(&valid).is_ok());
        }
    }

    /// Regression test for ArrayPrototypeSort value preservation across builtin IDs.
    ///
    /// The issue was that builtin ID 385 implementation was converting all array elements
    /// to strings during sorting and then writing back string values instead of preserving
    /// the original Value types. This caused type corruption where numeric/boolean/object
    /// elements became strings after sorting.
    ///
    /// All three ArrayPrototypeSort builtin IDs (28, 248, 385) should preserve original
    /// element values while only using string representation for comparison during sorting.
    #[test]
    // `3.14` below is an intentional decimal test value, not an approximation of PI (bd-n0sap).
    #[allow(clippy::approx_constant)]
    fn array_prototype_sort_preserves_element_values_across_builtin_ids() {
        let mut interpreter = test_interpreter();

        // Create test array with mixed types that should be preserved after sorting
        let array_id = ObjectId(100);
        let test_elements = vec![
            (0, Value::Int(42)),               // Should remain Int(42), not Str("42")
            (1, Value::Bool(true)),            // Should remain Bool(true), not Str("true")
            (2, Value::Float(3.14.into())),    // Should remain Float, not Str("3.14")
            (3, Value::str("apple")),          // Should remain Str
            (4, Value::Object(ObjectId(200))), // Should remain Object, not Str("[object Object]")
        ];

        // Add object to heap
        interpreter.set_heap_object_at(
            array_id.0 as usize,
            HeapObject {
                properties: test_elements
                    .iter()
                    .map(|(i, val)| (i.to_string(), val.clone()))
                    .chain(std::iter::once(("length".to_string(), Value::Int(5))))
                    .collect(),
                prototype: None,
                ..Default::default()
            },
        );

        // Add nested object for testing object preservation
        interpreter.set_heap_object_at(
            200,
            HeapObject {
                properties: OrderedStringMap::new(),
                prototype: None,
                ..Default::default()
            },
        );

        // Test all three ArrayPrototypeSort builtin IDs
        let builtin_ids = [28, 248, 385];

        for builtin_id in builtin_ids {
            // Reset array to original state
            let heap_index = array_id.0 as usize;
            interpreter.mutate_heap(|heap| {
                if let Some(obj) = heap.get_mut(heap_index) {
                    obj.properties.clear();
                    for (i, val) in &test_elements {
                        obj.properties.insert(i.to_string(), val.clone());
                    }
                    obj.properties.insert("length".to_string(), Value::Int(5));
                }
            });

            // Invoke ArrayPrototypeSort via builtin dispatcher. The array
            // receiver is passed as the first argument register.
            interpreter.set_reg(0, Value::Object(array_id));
            let result =
                interpreter.call_builtin_by_id(builtin_id, RegRange { start: 0, count: 1 });

            assert!(
                result.is_ok(),
                "Builtin ID {} should complete successfully",
                builtin_id
            );

            // Verify all element types are preserved after sorting
            if let Some(sorted_obj) = interpreter.heap.get(array_id.0 as usize) {
                for i in 0..5 {
                    let element = sorted_obj
                        .properties
                        .get(&i.to_string())
                        .unwrap_or_else(|| {
                            panic!("Builtin ID {} should preserve element {}", builtin_id, i)
                        });

                    // Verify types are preserved, not converted to strings
                    match element {
                        Value::Int(_) => {}    // Good - preserved as Int
                        Value::Bool(_) => {}   // Good - preserved as Bool
                        Value::Float(_) => {}  // Good - preserved as Float
                        Value::Str(_) => {}    // Good - was already Str
                        Value::Object(_) => {} // Good - preserved as Object
                        Value::Undefined => {} // Acceptable for missing elements
                        other => panic!(
                            "Builtin ID {} corrupted element {} type: expected original type, got {:?}",
                            builtin_id, i, other
                        ),
                    }
                }
            }

            // Test specific preservation cases that were failing before the fix
            if let Some(sorted_obj) = interpreter.heap.get(array_id.0 as usize) {
                // Find where Int(42) ended up after sorting (should be lexicographically sorted by string rep)
                let mut found_int = false;
                for i in 0..5 {
                    if let Some(Value::Int(42)) = sorted_obj.properties.get(&i.to_string()) {
                        found_int = true;
                        break;
                    }
                }
                assert!(
                    found_int,
                    "Builtin ID {} should preserve Int(42) as Int type",
                    builtin_id
                );

                // Find where Bool(true) ended up
                let mut found_bool = false;
                for i in 0..5 {
                    if let Some(Value::Bool(true)) = sorted_obj.properties.get(&i.to_string()) {
                        found_bool = true;
                        break;
                    }
                }
                assert!(
                    found_bool,
                    "Builtin ID {} should preserve Bool(true) as Bool type",
                    builtin_id
                );

                // Find where Object ended up
                let mut found_object = false;
                for i in 0..5 {
                    if let Some(Value::Object(ObjectId(200))) =
                        sorted_obj.properties.get(&i.to_string())
                    {
                        found_object = true;
                        break;
                    }
                }
                assert!(
                    found_object,
                    "Builtin ID {} should preserve Object as Object type",
                    builtin_id
                );
            }
        }

        // Verify sorting order is correct (by string representation, but preserving types)
        // Expected order: "3.14", "42", "[object Object]", "apple", "true"
        if let Some(final_obj) = interpreter.heap.get(array_id.0 as usize) {
            let elem_0 = final_obj
                .properties
                .get("0")
                .expect("operation should succeed for valid inputs");
            let elem_1 = final_obj
                .properties
                .get("1")
                .expect("operation should succeed for valid inputs");
            let elem_4 = final_obj
                .properties
                .get("4")
                .expect("operation should succeed for valid inputs");

            // First element should be 3.14 (string "3.14" comes first lexicographically)
            assert!(
                matches!(elem_0, Value::Float(_)),
                "First element should be Float(3.14), got {:?}",
                elem_0
            );

            // Second element should be 42 (string "42" comes second)
            assert!(
                matches!(elem_1, Value::Int(42)),
                "Second element should be Int(42), got {:?}",
                elem_1
            );

            // Last element should be true (string "true" comes last)
            assert!(
                matches!(elem_4, Value::Bool(true)),
                "Last element should be Bool(true), got {:?}",
                elem_4
            );
        }
    }

    /// Regression test for batch-37 Math/RegExp builtin dispatch deduplication.
    ///
    /// The issue was duplicate match arms for MathSin, MathCos, MathTan, and
    /// RegExpPrototypeTest in the builtin dispatcher. Because both arms matched
    /// the same names, only the first arm was reachable and newer builtin IDs
    /// were effectively dead-code mapping entries.
    ///
    /// All first/duplicate ID pairs should execute the same canonical
    /// implementation and produce identical results.
    #[test]
    fn math_regexp_builtin_dispatch_deduplication_regression() {
        let mut interpreter = test_interpreter();

        // Recreate RegExp object with the `__type` marker + source property
        // the canonical impl requires: `regexp_source_flags_from_object`
        // ignores any object whose `__type` is not "RegExp" and makes
        // `.test()` return false, so the receiver must carry that tag.
        let regexp_obj_id = interpreter
            .alloc_object_with_prototype(None)
            .expect("operation should succeed for valid inputs");
        interpreter
            .set_object_brand(regexp_obj_id, "RegExp")
            .expect("operation should succeed for valid inputs");
        interpreter
            .set_regexp_source_and_flags(regexp_obj_id, "foo".to_string(), "")
            .expect("operation should succeed for valid inputs");

        let math_id_groups = [
            ([59u32, 244u32, 369u32], "builtin:MathSin"),
            ([60u32, 245u32, 370u32], "builtin:MathCos"),
            ([63u32, 247u32, 371u32], "builtin:MathTan"),
        ];
        let math_inputs = [
            Value::Int(1),
            Value::Float(Float64::new(1.0)),
            Value::Bool(true),
        ];

        for (ids, builtin_name) in math_id_groups {
            for input in &math_inputs {
                interpreter.set_reg(0, input.clone());

                let first_result = interpreter
                    .call_builtin_by_id(ids[0], RegRange { start: 0, count: 1 })
                    .expect("first mapping should execute");
                for builtin_id in ids {
                    assert_eq!(
                        interpreter.map_function_index_to_builtin_capability(builtin_id),
                        Some(builtin_name.to_string()),
                        "Builtin ID {} should map to {}",
                        builtin_id,
                        builtin_name
                    );
                    interpreter.set_reg(0, input.clone());
                    let result = interpreter
                        .call_builtin_by_id(builtin_id, RegRange { start: 0, count: 1 })
                        .expect("trig mapping should execute");
                    assert_eq!(
                        first_result, result,
                        "Builtin ID {} should execute same {} result",
                        builtin_id, builtin_name
                    );
                }
            }
        }

        let regexp_ids = [268u32, 372u32];
        let first_result = {
            interpreter.mutate_registers(|r| {
                r[0] = Value::Object(regexp_obj_id);
                r[1] = Value::str("a quick food");
            });
            interpreter
                .call_builtin_by_id(regexp_ids[0], RegRange { start: 0, count: 2 })
                .expect("first RegExp mapping should execute")
        };

        assert_eq!(first_result, Value::Bool(true));
        for builtin_id in regexp_ids {
            assert_eq!(
                interpreter.map_function_index_to_builtin_capability(builtin_id),
                Some("builtin:RegExpPrototypeTest".to_string()),
                "Builtin ID {} should map to RegExpPrototypeTest",
                builtin_id
            );
            interpreter.mutate_registers(|r| {
                r[0] = Value::Object(regexp_obj_id);
                r[1] = Value::str("a quick food");
            });
            let result = interpreter
                .call_builtin_by_id(builtin_id, RegRange { start: 0, count: 2 })
                .expect("RegExp mapping should execute");
            assert_eq!(first_result, result);
        }
    }

    /// Regression test for ArrayPrototypeSort builtin dispatch deduplication.
    ///
    /// The issue was that three separate match arms for "builtin:ArrayPrototypeSort"
    /// existed in the builtin dispatcher (at different line numbers), all matching
    /// the same string. Due to match ordering, only the first arm could execute,
    /// making builtin IDs 248 and 385 unreachable dead code despite being mapped
    /// in map_function_index_to_builtin_capability().
    ///
    /// After consolidation, all three builtin IDs (28, 248, 385) should route through
    /// the same shared implementation and work correctly with mixed Value types.
    #[test]
    fn array_prototype_sort_builtin_dispatch_deduplication_regression() {
        let mut interpreter = test_interpreter();

        // Create test array with mixed types including holes
        let array_id = ObjectId(100);
        let test_elements = vec![
            (0, Value::Int(3)),        // "3"
            (1, Value::str("banana")), // "banana"
            (2, Value::Bool(false)),   // "false"
            // index 3 is a hole (should become Undefined)
            (4, Value::Float(1.5.into())),     // "1.5"
            (5, Value::Object(ObjectId(200))), // "[object Object]"
        ];

        // Add objects to heap
        interpreter.set_heap_object_at(
            array_id.0 as usize,
            HeapObject {
                properties: test_elements
                    .iter()
                    .map(|(i, val)| (i.to_string(), val.clone()))
                    .chain(std::iter::once(("length".to_string(), Value::Int(6))))
                    .collect(),
                prototype: None,
                ..Default::default()
            },
        );

        interpreter.set_heap_object_at(
            200,
            HeapObject {
                properties: OrderedStringMap::new(),
                prototype: None,
                ..Default::default()
            },
        );

        // Test all three builtin IDs that should map to the same consolidated implementation
        let builtin_ids = [28u32, 248u32, 385u32];

        for builtin_id in builtin_ids {
            // Reset array to original state
            let heap_index = array_id.0 as usize;
            interpreter.mutate_heap(|heap| {
                if let Some(obj) = heap.get_mut(heap_index) {
                    obj.properties.clear();
                    for (i, val) in &test_elements {
                        obj.properties.insert(i.to_string(), val.clone());
                    }
                    obj.properties.insert("length".to_string(), Value::Int(6));
                }
            });

            // Invoke ArrayPrototypeSort via the specific builtin ID
            // This tests that the mapping works and reaches the consolidated implementation
            let builtin_name = interpreter.map_function_index_to_builtin_capability(builtin_id);
            assert_eq!(
                builtin_name,
                Some("builtin:ArrayPrototypeSort".to_string()),
                "Builtin ID {} should map to ArrayPrototypeSort",
                builtin_id
            );

            // Simulate builtin call through dispatcher. The array receiver
            // is passed as the first argument register.
            interpreter.set_reg(0, Value::Object(array_id));
            let result = interpreter.call_builtin(
                "builtin:ArrayPrototypeSort",
                RegRange { start: 0, count: 1 },
            );
            assert!(
                result.is_ok(),
                "Builtin ID {} should execute successfully",
                builtin_id
            );

            // Verify the array was sorted correctly
            if let Some(sorted_obj) = interpreter.heap.get(array_id.0 as usize) {
                // Expected lexicographic order: "1.5", "3", "[object Object]", "banana", "false", "undefined"
                let elem_0 = sorted_obj
                    .properties
                    .get("0")
                    .expect("operation should succeed for valid inputs");
                let elem_1 = sorted_obj
                    .properties
                    .get("1")
                    .expect("operation should succeed for valid inputs");
                let elem_2 = sorted_obj
                    .properties
                    .get("2")
                    .expect("operation should succeed for valid inputs");
                let elem_3 = sorted_obj
                    .properties
                    .get("3")
                    .expect("operation should succeed for valid inputs");
                let elem_4 = sorted_obj
                    .properties
                    .get("4")
                    .expect("operation should succeed for valid inputs");
                let elem_5 = sorted_obj
                    .properties
                    .get("5")
                    .expect("operation should succeed for valid inputs");

                // Verify elements are in correct sorted order and types preserved
                assert!(
                    matches!(elem_0, Value::Float(_)),
                    "ID {}: elem[0] should be Float(1.5), got {:?}",
                    builtin_id,
                    elem_0
                );
                assert!(
                    matches!(elem_1, Value::Int(3)),
                    "ID {}: elem[1] should be Int(3), got {:?}",
                    builtin_id,
                    elem_1
                );
                assert!(
                    matches!(elem_2, Value::Object(_)),
                    "ID {}: elem[2] should be Object, got {:?}",
                    builtin_id,
                    elem_2
                );
                assert!(
                    matches!(elem_3, Value::Str(s) if s.as_ref() == "banana"),
                    "ID {}: elem[3] should be Str(banana), got {:?}",
                    builtin_id,
                    elem_3
                );
                assert!(
                    matches!(elem_4, Value::Bool(false)),
                    "ID {}: elem[4] should be Bool(false), got {:?}",
                    builtin_id,
                    elem_4
                );
                assert!(
                    matches!(elem_5, Value::Undefined),
                    "ID {}: elem[5] should be Undefined (from hole), got {:?}",
                    builtin_id,
                    elem_5
                );
            }
        }
    }
}

// Regression tests for bd-19wq2: Array.prototype.concat array spreading
#[test]
fn array_concat_spreads_arrays() {
    let mut core = InterpreterCore::new(test_quickjs_config(), "test-trace");

    // Create first array [1]
    let arr1_id = core
        .alloc_object_with_prototype(None)
        .expect("operation should succeed for valid inputs");
    core.set_object_property(arr1_id, "0".to_string(), Value::Int(1))
        .expect("operation should succeed for valid inputs");
    core.set_object_property(arr1_id, "length".to_string(), Value::Int(1))
        .expect("operation should succeed for valid inputs");

    // Create second array [2]
    let arr2_id = core
        .alloc_object_with_prototype(None)
        .expect("operation should succeed for valid inputs");
    core.set_object_property(arr2_id, "0".to_string(), Value::Int(2))
        .expect("operation should succeed for valid inputs");
    core.set_object_property(arr2_id, "length".to_string(), Value::Int(1))
        .expect("operation should succeed for valid inputs");

    // Set up registers for concat call: this=arr1, args=[arr2]
    core.set_reg(0, Value::Object(arr1_id));
    core.set_reg(1, Value::Object(arr2_id));

    let _result = core
        .execute(&test_module(vec![
            Ir3Instruction::HostCall {
                capability: CapabilityTag("builtin:ArrayPrototypeConcat".to_string()),
                args: RegRange { start: 0, count: 2 },
                dst: 10,
            },
            Ir3Instruction::Halt,
        ]))
        .expect("operation should succeed for valid inputs");

    // Result should be an array with elements [1, 2], not [1, [2]]
    if let Value::Object(result_id) = core.registers[10] {
        let result_obj = &core.heap[result_id.0 as usize];

        // Check length is 2
        assert_eq!(result_obj.properties.get("length"), Some(&Value::Int(2)));

        // Check elements are 1 and 2 (not a nested array)
        assert_eq!(result_obj.properties.get("0"), Some(&Value::Int(1)));
        assert_eq!(result_obj.properties.get("1"), Some(&Value::Int(2)));
    } else {
        panic!("Array concat should return an object");
    }
}

#[test]
fn array_concat_non_array_as_single_element() {
    let mut core = InterpreterCore::new(test_quickjs_config(), "test-trace");

    // Create array [1]
    let arr_id = core
        .alloc_object_with_prototype(None)
        .expect("operation should succeed for valid inputs");
    core.set_object_property(arr_id, "0".to_string(), Value::Int(1))
        .expect("operation should succeed for valid inputs");
    core.set_object_property(arr_id, "length".to_string(), Value::Int(1))
        .expect("operation should succeed for valid inputs");

    // Set up registers for concat call: this=arr, args=["str"]
    core.set_reg(0, Value::Object(arr_id));
    core.set_reg(1, Value::str("str"));

    let _result = core
        .execute(&test_module(vec![
            Ir3Instruction::HostCall {
                capability: CapabilityTag("builtin:ArrayPrototypeConcat".to_string()),
                args: RegRange { start: 0, count: 2 },
                dst: 10,
            },
            Ir3Instruction::Halt,
        ]))
        .expect("operation should succeed for valid inputs");

    // Result should be [1, "str"]
    if let Value::Object(result_id) = core.registers[10] {
        let result_obj = &core.heap[result_id.0 as usize];

        // Check length is 2
        assert_eq!(result_obj.properties.get("length"), Some(&Value::Int(2)));

        // Check elements
        assert_eq!(result_obj.properties.get("0"), Some(&Value::Int(1)));
        assert_eq!(result_obj.properties.get("1"), Some(&Value::str("str")));
    } else {
        panic!("Array concat should return an object");
    }
}

#[test]
fn array_concat_multiple_arrays() {
    let mut core = InterpreterCore::new(test_quickjs_config(), "test-trace");

    // Create array [1]
    let arr1_id = core
        .alloc_object_with_prototype(None)
        .expect("operation should succeed for valid inputs");
    core.set_object_property(arr1_id, "0".to_string(), Value::Int(1))
        .expect("operation should succeed for valid inputs");
    core.set_object_property(arr1_id, "length".to_string(), Value::Int(1))
        .expect("operation should succeed for valid inputs");

    // Create array [2, 3]
    let arr2_id = core
        .alloc_object_with_prototype(None)
        .expect("operation should succeed for valid inputs");
    core.set_object_property(arr2_id, "0".to_string(), Value::Int(2))
        .expect("operation should succeed for valid inputs");
    core.set_object_property(arr2_id, "1".to_string(), Value::Int(3))
        .expect("operation should succeed for valid inputs");
    core.set_object_property(arr2_id, "length".to_string(), Value::Int(2))
        .expect("operation should succeed for valid inputs");

    // Create array [4]
    let arr3_id = core
        .alloc_object_with_prototype(None)
        .expect("operation should succeed for valid inputs");
    core.set_object_property(arr3_id, "0".to_string(), Value::Int(4))
        .expect("operation should succeed for valid inputs");
    core.set_object_property(arr3_id, "length".to_string(), Value::Int(1))
        .expect("operation should succeed for valid inputs");

    // Set up registers for concat call: this=arr1, args=[arr2, arr3]
    core.set_reg(0, Value::Object(arr1_id));
    core.set_reg(1, Value::Object(arr2_id));
    core.set_reg(2, Value::Object(arr3_id));

    let _result = core
        .execute(&test_module(vec![
            Ir3Instruction::HostCall {
                capability: CapabilityTag("builtin:ArrayPrototypeConcat".to_string()),
                args: RegRange { start: 0, count: 3 },
                dst: 10,
            },
            Ir3Instruction::Halt,
        ]))
        .expect("operation should succeed for valid inputs");

    // Result should be [1, 2, 3, 4]
    if let Value::Object(result_id) = core.registers[10] {
        let result_obj = &core.heap[result_id.0 as usize];

        // Check length is 4
        assert_eq!(result_obj.properties.get("length"), Some(&Value::Int(4)));

        // Check all elements
        assert_eq!(result_obj.properties.get("0"), Some(&Value::Int(1)));
        assert_eq!(result_obj.properties.get("1"), Some(&Value::Int(2)));
        assert_eq!(result_obj.properties.get("2"), Some(&Value::Int(3)));
        assert_eq!(result_obj.properties.get("3"), Some(&Value::Int(4)));
    } else {
        panic!("Array concat should return an object");
    }
}

// Regression tests for bd-11a8p: Global builtin argument indexing
#[test]
fn global_builtin_isnan_correct_argument() {
    let mut core = InterpreterCore::new(test_quickjs_config(), "test-trace");

    // Test IsNaN with number argument
    core.set_reg(0, Value::Float(Float64::new(f64::NAN)));

    let _result = core
        .execute(&test_module(vec![
            Ir3Instruction::HostCall {
                capability: CapabilityTag("builtin:isNaN".to_string()),
                args: RegRange { start: 0, count: 1 },
                dst: 10,
            },
            Ir3Instruction::Halt,
        ]))
        .expect("operation should succeed for valid inputs");

    // Should correctly read register 0 and return true for NaN
    assert_eq!(core.registers[10], Value::Bool(true));

    // Test with non-NaN value. Use a fresh core: the seed-tracked
    // re-execution model restores the initial register seed on a second
    // execute(), so a new core is needed to exercise a different input.
    let mut core = InterpreterCore::new(test_quickjs_config(), "test-trace");
    core.set_reg(0, Value::Int(42));

    let _result = core
        .execute(&test_module(vec![
            Ir3Instruction::HostCall {
                capability: CapabilityTag("builtin:isNaN".to_string()),
                args: RegRange { start: 0, count: 1 },
                dst: 10,
            },
            Ir3Instruction::Halt,
        ]))
        .expect("operation should succeed for valid inputs");

    // Should return false for non-NaN
    assert_eq!(core.registers[10], Value::Bool(false));
}

#[test]
fn global_builtin_isfinite_correct_argument() {
    let mut core = InterpreterCore::new(test_quickjs_config(), "test-trace");

    // Test IsFinite with finite number
    core.set_reg(0, Value::Int(42));

    let _result = core
        .execute(&test_module(vec![
            Ir3Instruction::HostCall {
                capability: CapabilityTag("builtin:isFinite".to_string()),
                args: RegRange { start: 0, count: 1 },
                dst: 10,
            },
            Ir3Instruction::Halt,
        ]))
        .expect("operation should succeed for valid inputs");

    // Should correctly read register 0 and return true for finite number
    assert_eq!(core.registers[10], Value::Bool(true));

    // Test with infinity. Use a fresh core: the seed-tracked re-execution
    // model restores the initial register seed on a second execute().
    let mut core = InterpreterCore::new(test_quickjs_config(), "test-trace");
    core.set_reg(0, Value::Float(Float64::new(f64::INFINITY)));

    let _result = core
        .execute(&test_module(vec![
            Ir3Instruction::HostCall {
                capability: CapabilityTag("builtin:isFinite".to_string()),
                args: RegRange { start: 0, count: 1 },
                dst: 10,
            },
            Ir3Instruction::Halt,
        ]))
        .expect("operation should succeed for valid inputs");

    // Should return false for infinity
    assert_eq!(core.registers[10], Value::Bool(false));
}

#[test]
fn global_builtin_parseint_correct_arguments() {
    let mut core = InterpreterCore::new(test_quickjs_config(), "test-trace");

    // Test ParseInt with string argument (single argument)
    core.set_reg(0, Value::str("123"));

    let _result = core
        .execute(&test_module(vec![
            Ir3Instruction::HostCall {
                capability: CapabilityTag("builtin:parseInt".to_string()),
                args: RegRange { start: 0, count: 1 },
                dst: 10,
            },
            Ir3Instruction::Halt,
        ]))
        .expect("operation should succeed for valid inputs");

    // parseInt returns an integer Value in this engine (an integral Number is
    // canonicalized to Int), consistent with the engine's other parseInt tests
    // (e.g. parseint_nan_radix_* expect Value::Int). The legacy "should return
    // a float" expectation was stale (bd-n0sap).
    assert_eq!(core.registers[10], Value::Int(123));

    // Test ParseInt with radix argument. Use a fresh core: the seed-tracked
    // re-execution model restores the initial register seed on a second
    // execute() (bd-n0sap).
    let mut core = InterpreterCore::new(test_quickjs_config(), "test-trace");
    core.set_reg(0, Value::str("101"));
    core.set_reg(1, Value::Int(2)); // binary radix

    let _result = core
        .execute(&test_module(vec![
            Ir3Instruction::HostCall {
                capability: CapabilityTag("builtin:parseInt".to_string()),
                args: RegRange { start: 0, count: 2 },
                dst: 10,
            },
            Ir3Instruction::Halt,
        ]))
        .expect("operation should succeed for valid inputs");

    // parseInt("101", 2) === 5, returned as an Int (see above) (bd-n0sap).
    assert_eq!(core.registers[10], Value::Int(5));
}

#[test]
// parseFloat("3.14") yields 3.14, the parsed value — not an approximation of PI (bd-n0sap).
#[allow(clippy::approx_constant)]
fn global_builtin_parsefloat_correct_argument() {
    let mut core = InterpreterCore::new(test_quickjs_config(), "test-trace");

    // Test ParseFloat with string argument
    core.set_reg(0, Value::str("3.14"));

    let _result = core
        .execute(&test_module(vec![
            Ir3Instruction::HostCall {
                capability: CapabilityTag("builtin:ParseFloat".to_string()),
                args: RegRange { start: 0, count: 1 },
                dst: 10,
            },
            Ir3Instruction::Halt,
        ]))
        .expect("operation should succeed for valid inputs");

    // Should correctly parse "3.14" as 3.14
    if let Value::Float(f) = core.registers[10] {
        assert!((f.inner() - 3.14).abs() < f64::EPSILON);
    } else {
        panic!("ParseFloat should return a float");
    }

    // Test with integer. Use a fresh core: the seed-tracked re-execution
    // model restores the initial register seed on a second execute().
    let mut core = InterpreterCore::new(test_quickjs_config(), "test-trace");
    core.set_reg(0, Value::Int(42));

    let _result = core
        .execute(&test_module(vec![
            Ir3Instruction::HostCall {
                capability: CapabilityTag("builtin:ParseFloat".to_string()),
                args: RegRange { start: 0, count: 1 },
                dst: 10,
            },
            Ir3Instruction::Halt,
        ]))
        .expect("operation should succeed for valid inputs");

    // Should return the integer as-is
    assert_eq!(core.registers[10], Value::Int(42));
}

// Regression tests for bd-2gbeb: Deterministic Date.now timing
#[test]
fn date_now_deterministic_across_runs() {
    let deterministic_epoch_ms = 1_767_225_600_000.0; // 2026-01-01T00:00:00Z

    // Run Date.now multiple times - should always return same value
    for _ in 0..5 {
        let mut core = InterpreterCore::new(test_quickjs_config(), "test-trace");

        let _result = core
            .execute(&test_module(vec![
                Ir3Instruction::HostCall {
                    capability: CapabilityTag("builtin:DateNow".to_string()),
                    args: RegRange { start: 0, count: 0 },
                    dst: 10,
                },
                Ir3Instruction::Halt,
            ]))
            .expect("operation should succeed for valid inputs");

        // Should always return the fixed deterministic epoch
        if let Value::Float(f) = core.registers[10] {
            assert_eq!(f.inner(), deterministic_epoch_ms);
        } else {
            panic!("Date.now should return a float");
        }
    }
}

#[test]
fn date_constructor_deterministic_across_runs() {
    let deterministic_epoch_ms = 1_767_225_600_000.0; // 2026-01-01T00:00:00Z

    // Run Date constructor multiple times - should always create same timestamp
    for _ in 0..5 {
        let mut core = InterpreterCore::new(test_quickjs_config(), "test-trace");

        let _result = core
            .execute(&test_module(vec![
                Ir3Instruction::HostCall {
                    capability: CapabilityTag("builtin:Date".to_string()),
                    args: RegRange { start: 0, count: 0 },
                    dst: 10,
                },
                Ir3Instruction::Halt,
            ]))
            .expect("operation should succeed for valid inputs");

        // Should create Date object with deterministic timestamp
        if let Value::Object(date_id) = core.registers[10] {
            let date_obj = &core.heap[date_id.0 as usize];
            assert_eq!(date_obj.date_time(), Some(deterministic_epoch_ms));
            assert!(!date_obj.properties.contains_key("__timestamp"));
        } else {
            panic!("Date constructor should return an object");
        }
    }
}

#[test]
fn date_private_value_round_trips_separately_from_guest_properties() {
    let mut core = InterpreterCore::new(test_quickjs_config(), "test-trace");
    let date = core.alloc_object_with_prototype(None).expect("date object");
    core.set_object_brand(date, "Date").expect("Date brand");
    core.set_object_property(date, "__timestamp".to_string(), Value::str("guest"))
        .expect("ordinary guest property");
    for time in [0.0, -123.0, 8.64e15, f64::NAN] {
        core.set_date_value(date, time).expect("private date value");
        let object = &core.heap[date.0 as usize];
        let wire = serde_json::to_value(object).expect("serialize heap object");
        assert_eq!(wire["date_value"].as_u64(), Some(time.to_bits()));
        let restored: HeapObject = serde_json::from_value(wire).expect("restore heap object");
        assert_eq!(restored, *object);
        assert_eq!(restored.date_time().unwrap().to_bits(), time.to_bits());
        assert_eq!(
            restored.properties.get("__timestamp"),
            Some(&Value::str("guest"))
        );
    }
}

#[test]
fn date_private_value_budget_admission_is_atomic_and_matches_heap_accounting() {
    let mut core = InterpreterCore::new(test_quickjs_config(), "test-trace");
    let date = core.alloc_object_with_prototype(None).expect("date object");
    core.set_object_brand(date, "Date").expect("Date brand");
    let before_bytes = core.estimated_memory_bytes;
    let before_seed_bytes =
        InterpreterCore::estimate_execution_seed_heap_object_bytes(&core.heap[date.0 as usize]);
    let before_epoch = core.seed_epoch;
    let value_bytes = std::mem::size_of::<Float64>() as u64;
    core.config.max_total_memory_bytes = before_bytes + value_bytes - 1;
    assert!(matches!(
        core.set_date_value(date, 7.0),
        Err(InterpreterError::MemoryBudgetExceeded { .. })
    ));
    assert_eq!(core.heap[date.0 as usize].date_time(), None);
    assert_eq!(core.estimated_memory_bytes, before_bytes);
    assert_eq!(core.seed_epoch, before_epoch);

    core.config.max_total_memory_bytes = before_bytes + value_bytes;
    core.set_date_value(date, 7.0)
        .expect("exact-budget slot allocation");
    assert_eq!(core.estimated_memory_bytes, before_bytes + value_bytes);
    assert_eq!(
        core.estimated_memory_bytes,
        core.recompute_estimated_memory_bytes()
    );
    assert_eq!(
        InterpreterCore::estimate_execution_seed_heap_object_bytes(&core.heap[date.0 as usize]),
        before_seed_bytes + value_bytes,
    );
    // Replacing the Number reuses its slot, even at the exact limit.
    core.set_date_value(date, f64::NAN)
        .expect("in-place date mutation");
    assert!(core.heap[date.0 as usize].date_time().unwrap().is_nan());
    assert_eq!(core.estimated_memory_bytes, before_bytes + value_bytes);
    assert_eq!(
        core.estimated_memory_bytes,
        core.recompute_estimated_memory_bytes()
    );
}

fn date_value_provenance_fixture(
    config: InterpreterConfig,
) -> (InterpreterCore, ObjectId, ObjectId) {
    let mut core = InterpreterCore::new(config, "date-value-provenance");
    let prototype = core.ensure_builtin_prototype("Date").unwrap();
    let date = core.alloc_object_with_prototype(Some(prototype)).unwrap();
    core.set_object_brand(date, "Date").unwrap();
    core.set_date_value(date, 0.0).unwrap();
    let public = core.alloc_object_with_prototype(Some(prototype)).unwrap();
    core.set_object_brand(public, "Date").unwrap();
    core.set_date_value(public, 7.0).unwrap();
    (core, date, public)
}

#[test]
fn date_value_provenance_survives_aliases_and_indirect_invocation() {
    for config in [test_quickjs_config(), test_v8_config()] {
        for setter_route in 0..4 {
            for getter_route in 0..4 {
                let (mut core, date, public) = date_value_provenance_fixture(config.clone());
                let arguments = core.alloc_array_from_values(&[Value::Int(1234)]).unwrap();
                core.set_own_runtime_property_label(
                    arguments,
                    &RuntimePropertyKey::from("0"),
                    &Label::Secret,
                )
                .unwrap();
                let empty = core.alloc_array_from_values(&[]).unwrap();
                let setter = Value::BuiltinFunction(
                    InterpreterCore::collection_prototype_method("Date", "setTime").unwrap(),
                );
                let getter = Value::BuiltinFunction(BuiltinFunction::date_get_time());
                core.mutate_registers(|registers| {
                    registers[0] = Value::Object(date);
                    registers[1] = Value::Object(date);
                    registers[2] = setter.clone();
                    registers[3] = getter.clone();
                    registers[4] = Value::BuiltinFunction(BuiltinFunction::new_kind(
                        BuiltinFunctionKind::FunctionPrototypeCall,
                    ));
                    registers[5] = Value::BuiltinFunction(BuiltinFunction::new_kind(
                        BuiltinFunctionKind::FunctionPrototypeApply,
                    ));
                    registers[7] = Value::Int(1234);
                    registers[12] = Value::Object(public);
                    registers[20] = setter;
                    registers[21] = Value::Object(date);
                    registers[22] = if setter_route < 2 {
                        Value::Int(1234)
                    } else {
                        Value::Object(arguments)
                    };
                    registers[29] = getter;
                    registers[30] = Value::Object(date);
                    registers[31] = Value::Object(empty);
                });
                core.set_register_label(7, Label::Secret).unwrap();
                if setter_route < 2 {
                    core.set_register_label(22, Label::Secret).unwrap();
                }
                let setter_call = match setter_route {
                    0 => Ir3Instruction::CallMethod {
                        receiver: 0,
                        callee: 2,
                        args: RegRange { start: 7, count: 1 },
                        dst: 10,
                    },
                    1 | 2 => Ir3Instruction::CallMethod {
                        receiver: 2,
                        callee: if setter_route == 1 { 4 } else { 5 },
                        args: RegRange {
                            start: 21,
                            count: 2,
                        },
                        dst: 10,
                    },
                    _ => Ir3Instruction::HostCall {
                        capability: CapabilityTag("builtin:ReflectApply".to_string()),
                        args: RegRange {
                            start: 20,
                            count: 3,
                        },
                        dst: 10,
                    },
                };
                let getter_call = match getter_route {
                    0 => Ir3Instruction::CallMethod {
                        receiver: 1,
                        callee: 3,
                        args: RegRange { start: 0, count: 0 },
                        dst: 11,
                    },
                    1 | 2 => Ir3Instruction::CallMethod {
                        receiver: 3,
                        callee: if getter_route == 1 { 4 } else { 5 },
                        args: RegRange {
                            start: 30,
                            count: if getter_route == 1 { 1 } else { 2 },
                        },
                        dst: 11,
                    },
                    _ => Ir3Instruction::HostCall {
                        capability: CapabilityTag("builtin:ReflectApply".to_string()),
                        args: RegRange {
                            start: 29,
                            count: 3,
                        },
                        dst: 11,
                    },
                };
                let module = test_module(vec![
                    setter_call,
                    getter_call,
                    Ir3Instruction::CallMethod {
                        receiver: 12,
                        callee: 3,
                        args: RegRange { start: 0, count: 0 },
                        dst: 13,
                    },
                    Ir3Instruction::Halt,
                ]);
                core.execute(&module).unwrap();
                assert_eq!(core.get_register_label(1).unwrap(), &Label::Public);
                assert_eq!(
                    core.read_reg(11).unwrap(),
                    Value::Float(Float64::new(1234.0))
                );
                assert_eq!(
                    core.get_register_label(11).unwrap(),
                    &Label::Secret,
                    "setter route {setter_route}, getter route {getter_route}"
                );
                assert_eq!(core.object_mutation_labels.get(&date), Some(&Label::Secret));
                assert_eq!(core.read_reg(13).unwrap(), Value::Float(Float64::new(7.0)));
                assert_eq!(core.get_register_label(13).unwrap(), &Label::Public);
                assert!(core.pending_hostcall_result_label.is_none());
                assert!(core.active_inline_callback_context_label.is_none());
                assert_eq!(
                    core.estimated_memory_bytes(),
                    core.recompute_estimated_memory_bytes()
                );
            }
        }
    }
}

#[test]
fn date_value_provenance_retains_coercion_callback_results() {
    let (mut core, date, public) = date_value_provenance_fixture(test_quickjs_config());
    let argument = core.alloc_object_with_prototype(None).unwrap();
    let public_argument = core.alloc_object_with_prototype(None).unwrap();
    core.mutate_registers(|registers| {
        registers[0] = Value::Object(date);
        registers[2] = Value::BuiltinFunction(
            InterpreterCore::collection_prototype_method("Date", "setUTCFullYear").unwrap(),
        );
        registers[3] = Value::BuiltinFunction(BuiltinFunction::date_get_time());
        registers[4] = Value::Int(2001);
        registers[8] = Value::Object(public);
        registers[10] = Value::Object(argument);
        registers[11] = Value::Object(public_argument);
    });
    core.set_register_label(4, Label::Secret).unwrap();
    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::DeclareBinding {
                name_pool_index: 0,
                kind: BindingKind::Var as u8,
            },
            Ir3Instruction::CreateClosure {
                dst: 6,
                function_index: 0,
                capture_count: 0,
            },
            Ir3Instruction::StoreScoped {
                src: 4,
                name_pool_index: 0,
            },
            Ir3Instruction::LoadStr {
                dst: 7,
                pool_index: 1,
            },
            Ir3Instruction::DefineMethod {
                obj: 10,
                key: 7,
                func: 6,
            },
            Ir3Instruction::CreateClosure {
                dst: 9,
                function_index: 1,
                capture_count: 0,
            },
            Ir3Instruction::DefineMethod {
                obj: 11,
                key: 7,
                func: 9,
            },
            Ir3Instruction::CallMethod {
                receiver: 0,
                callee: 2,
                args: RegRange {
                    start: 10,
                    count: 2,
                },
                dst: 12,
            },
            Ir3Instruction::CallMethod {
                receiver: 0,
                callee: 3,
                args: RegRange { start: 0, count: 0 },
                dst: 13,
            },
            Ir3Instruction::CallMethod {
                receiver: 8,
                callee: 3,
                args: RegRange { start: 0, count: 0 },
                dst: 14,
            },
            Ir3Instruction::Halt,
            Ir3Instruction::LoadScoped {
                dst: 0,
                name_pool_index: 0,
            },
            Ir3Instruction::Return { value: 0 },
            Ir3Instruction::LoadInt { dst: 0, value: 0 },
            Ir3Instruction::Return { value: 0 },
        ],
        vec![
            "classified_date_component".to_string(),
            "valueOf".to_string(),
        ],
    );
    module.function_table.push(Ir3FunctionDesc {
        entry: 11,
        arity: 0,
        frame_size: 1,
        name: Some("date_component".to_string()),
        is_generator: false,
        rest_param_index: None,
    });
    module.function_table.push(Ir3FunctionDesc {
        entry: 13,
        arity: 0,
        frame_size: 1,
        name: Some("public_month".to_string()),
        is_generator: false,
        rest_param_index: None,
    });
    core.execute(&module).unwrap();
    assert_eq!(core.get_register_label(0).unwrap(), &Label::Public);
    assert_eq!(core.get_register_label(10).unwrap(), &Label::Public);
    assert_eq!(core.get_register_label(11).unwrap(), &Label::Public);
    assert_eq!(core.get_register_label(6).unwrap(), &Label::Public);
    assert_eq!(
        core.read_reg(13).unwrap(),
        Value::Float(Float64::new(978_307_200_000.0))
    );
    assert_eq!(core.get_register_label(13).unwrap(), &Label::Secret);
    assert_eq!(core.get_register_label(14).unwrap(), &Label::Public);
    assert!(core.pending_hostcall_result_label.is_none());
    assert!(core.active_inline_callback_context_label.is_none());
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn date_value_provenance_survives_conversion_formatting_and_copying() {
    for config in [test_quickjs_config(), test_v8_config()] {
        let (mut core, date, public) = date_value_provenance_fixture(config);
        let date_array = core
            .alloc_array_from_values(&[Value::Object(date)])
            .unwrap();
        let number_array = core
            .alloc_array_from_values(&[Value::Int(1), Value::Int(2)])
            .unwrap();
        let empty_module = test_module(Vec::new());
        let Value::Object(formatter) = core
            .construct_intl_service(
                &empty_module,
                "DateTimeFormat",
                RegRange { start: 0, count: 0 },
            )
            .unwrap()
        else {
            panic!("Intl constructor must return an object");
        };
        let format = core.prototype_chain_get(formatter, "format").unwrap();
        core.mutate_registers(|registers| {
            registers[0] = Value::Object(date);
            registers[1] = Value::Object(date);
            for (register, method) in [
                (2, "setTime"),
                (5, "valueOf"),
                (6, "toISOString"),
                (9, "toJSON"),
                (11, "toLocaleString"),
            ] {
                registers[register] = Value::BuiltinFunction(
                    InterpreterCore::collection_prototype_method("Date", method).unwrap(),
                );
            }
            registers[3] = Value::BuiltinFunction(BuiltinFunction::date_get_time());
            registers[4] = Value::Int(1234);
            registers[7] = Value::Int(0);
            registers[8] = Value::str("");
            registers[10] = format;
            registers[14] = Value::Object(public);
            registers[16] = Value::Object(date_array);
            registers[17] =
                Value::BuiltinFunction(BuiltinFunction::new_kind(BuiltinFunctionKind::ArrayJoin));
            registers[18] = Value::Object(number_array);
        });
        core.set_register_label(4, Label::Secret).unwrap();
        let module = test_module(vec![
            Ir3Instruction::CallMethod {
                receiver: 0,
                callee: 2,
                args: RegRange { start: 4, count: 1 },
                dst: 15,
            },
            Ir3Instruction::UnaryPlus { dst: 20, src: 1 },
            Ir3Instruction::Sub {
                dst: 21,
                lhs: 1,
                rhs: 7,
            },
            Ir3Instruction::Add {
                dst: 22,
                lhs: 1,
                rhs: 8,
            },
            Ir3Instruction::CallMethod {
                receiver: 1,
                callee: 5,
                args: RegRange { start: 0, count: 0 },
                dst: 23,
            },
            Ir3Instruction::CallMethod {
                receiver: 1,
                callee: 6,
                args: RegRange { start: 0, count: 0 },
                dst: 24,
            },
            Ir3Instruction::CallMethod {
                receiver: 1,
                callee: 9,
                args: RegRange { start: 0, count: 0 },
                dst: 25,
            },
            Ir3Instruction::CallMethod {
                receiver: 1,
                callee: 11,
                args: RegRange { start: 0, count: 0 },
                dst: 26,
            },
            Ir3Instruction::Call {
                callee: 10,
                args: RegRange { start: 1, count: 1 },
                dst: 27,
            },
            Ir3Instruction::HostCall {
                capability: CapabilityTag("builtin:Date".to_string()),
                args: RegRange { start: 1, count: 1 },
                dst: 28,
            },
            Ir3Instruction::HostCall {
                capability: CapabilityTag("builtin:StructuredClone".to_string()),
                args: RegRange { start: 1, count: 1 },
                dst: 29,
            },
            Ir3Instruction::HostCall {
                capability: CapabilityTag("builtin:DatePrototypeGetTime".to_string()),
                args: RegRange { start: 1, count: 1 },
                dst: 30,
            },
            Ir3Instruction::HostCall {
                capability: CapabilityTag("builtin:DatePrototypeToString".to_string()),
                args: RegRange { start: 1, count: 1 },
                dst: 31,
            },
            Ir3Instruction::CallMethod {
                receiver: 16,
                callee: 17,
                args: RegRange { start: 0, count: 0 },
                dst: 33,
            },
            Ir3Instruction::CallMethod {
                receiver: 18,
                callee: 17,
                args: RegRange { start: 1, count: 1 },
                dst: 34,
            },
            Ir3Instruction::CallMethod {
                receiver: 14,
                callee: 3,
                args: RegRange { start: 0, count: 0 },
                dst: 32,
            },
            Ir3Instruction::Halt,
        ]);
        core.execute(&module).unwrap();
        for register in (20..=31).chain([33, 34]) {
            assert_eq!(
                core.get_register_label(register).unwrap(),
                &Label::Secret,
                "Date conversion/copy result r{register} must retain the time's provenance"
            );
        }
        assert_eq!(core.get_register_label(1).unwrap(), &Label::Public);
        assert_eq!(core.get_register_label(32).unwrap(), &Label::Public);
        for register in [20, 21, 23, 30] {
            assert_eq!(
                InterpreterCore::coerce_to_float(&core.read_reg(register).unwrap()),
                Some(1234.0)
            );
        }
        for register in [24, 25] {
            assert_eq!(
                core.read_reg(register).unwrap(),
                Value::str("1970-01-01T00:00:01.234Z")
            );
        }
        for register in [28, 29] {
            let Value::Object(copy) = core.read_reg(register).unwrap() else {
                panic!("Date copy must be an object");
            };
            assert_ne!(copy, date);
            assert_eq!(core.object_mutation_labels.get(&copy), Some(&Label::Secret));
            // An isolated invocation supplies an unlabelled receiver value,
            // independently of the classified copy-result register.
            let (value, label) = core
                .invoke_inline_method_call_with_argument_label(
                    Some(&module),
                    Value::BuiltinFunction(BuiltinFunction::date_get_time()),
                    Value::Object(copy),
                    Vec::new(),
                    None,
                )
                .unwrap();
            assert_eq!(value, Value::Float(Float64::new(1234.0)));
            assert_eq!(label, Label::Secret);
        }
        assert!(core.pending_hostcall_result_label.is_none());
        assert!(core.active_inline_callback_context_label.is_none());
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }
}

#[test]
fn date_value_provenance_labels_invalid_time_errors() {
    let (mut core, date, _) = date_value_provenance_fixture(test_quickjs_config());
    core.mutate_registers(|registers| {
        registers[0] = Value::Object(date);
        registers[1] = Value::Float(Float64::new(f64::NAN));
        registers[2] = Value::BuiltinFunction(
            InterpreterCore::collection_prototype_method("Date", "setTime").unwrap(),
        );
        registers[3] = Value::BuiltinFunction(
            InterpreterCore::collection_prototype_method("Date", "toISOString").unwrap(),
        );
    });
    core.set_register_label(1, Label::Secret).unwrap();
    let module = test_module(vec![
        Ir3Instruction::CallMethod {
            receiver: 0,
            callee: 2,
            args: RegRange { start: 1, count: 1 },
            dst: 4,
        },
        Ir3Instruction::BeginTry {
            catch_target: 4,
            finally_target: None,
        },
        Ir3Instruction::CallMethod {
            receiver: 0,
            callee: 3,
            args: RegRange { start: 0, count: 0 },
            dst: 5,
        },
        Ir3Instruction::Halt,
        Ir3Instruction::EnterCatch { dst: 6 },
        Ir3Instruction::Halt,
    ]);
    core.execute(&module).unwrap();
    assert!(matches!(core.read_reg(6).unwrap(), Value::Object(_)));
    assert_eq!(core.get_register_label(6).unwrap(), &Label::Secret);
    assert!(core.active_inline_callback_context_label.is_none());
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn date_value_provenance_is_admitted_before_setter_publication() {
    let (mut core, date, _) = date_value_provenance_fixture(test_quickjs_config());
    core.mutate_registers(|registers| {
        registers[0] = Value::Object(date);
        registers[1] = Value::Int(1234);
    });
    core.set_register_label(1, Label::Secret).unwrap();
    let baseline = core.estimated_memory_bytes();
    let label_bytes = InterpreterCore::estimate_object_mutation_label_entry_bytes(&Label::Secret);
    let setter = InterpreterCore::collection_prototype_method("Date", "setTime").unwrap();
    let module = test_module(Vec::new());
    core.config.max_total_memory_bytes = baseline + label_bytes - 1;
    assert!(matches!(
        core.dispatch_builtin_function(
            &module,
            &setter,
            RegRange { start: 1, count: 1 },
            Some(Value::Object(date)),
            Some(0),
        ),
        Err(InterpreterError::MemoryBudgetExceeded { .. })
    ));
    assert_eq!(core.heap[date.0 as usize].date_time(), Some(0.0));
    assert!(!core.object_mutation_labels.contains_key(&date));
    assert!(core.pending_hostcall_result_label.is_none());
    assert!(core.active_inline_callback_context_label.is_none());
    assert_eq!(core.estimated_memory_bytes(), baseline);

    core.config.max_total_memory_bytes = baseline + label_bytes;
    core.dispatch_builtin_function(
        &module,
        &setter,
        RegRange { start: 1, count: 1 },
        Some(Value::Object(date)),
        Some(0),
    )
    .expect("exact-budget Date provenance admission");
    assert_eq!(core.heap[date.0 as usize].date_time(), Some(1234.0));
    assert_eq!(core.object_mutation_labels.get(&date), Some(&Label::Secret));
    assert_eq!(core.estimated_memory_bytes(), baseline + label_bytes);
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn date_prototype_gettime_stable_values() {
    let deterministic_epoch_ms = 1_767_225_600_000.0; // 2026-01-01T00:00:00Z

    let mut core = InterpreterCore::new(test_quickjs_config(), "test-trace");

    // Create Date object via direct builtin dispatch so the allocated Date
    // stays live on this core's heap (no seed-tracked re-execution reset).
    let date = core
        .dispatch_builtin_hostcall("builtin:Date", RegRange { start: 0, count: 0 }, None)
        .expect("operation should succeed for valid inputs");

    // Multiple calls to getTime() should return same value
    for _ in 0..3 {
        // Set up this=date object for getTime call.
        core.set_reg(0, date.clone());

        let result = core
            .dispatch_builtin_hostcall(
                "builtin:DatePrototypeGetTime",
                RegRange { start: 0, count: 1 },
                None,
            )
            .expect("operation should succeed for valid inputs");

        // Should return the same deterministic timestamp
        if let Value::Float(f) = result {
            assert_eq!(f.inner(), deterministic_epoch_ms);
        } else {
            panic!("Date.prototype.getTime should return a float");
        }
    }
}

// Regression tests for bd-7f1a4: Console builtin deduplication and info capture
#[test]
fn console_info_capture_output() {
    let mut core = InterpreterCore::new(test_quickjs_config(), "test-trace");

    // Set up arguments for console.info
    core.set_reg(0, Value::str("Info message"));
    core.set_reg(1, Value::Int(42));

    let result = core
        .execute(&test_module(vec![
            Ir3Instruction::HostCall {
                capability: CapabilityTag("builtin:ConsoleInfo".to_string()),
                args: RegRange { start: 0, count: 2 },
                dst: 10,
            },
            Ir3Instruction::Halt,
        ]))
        .expect("operation should succeed for valid inputs");

    // Should capture console.info output (execute() moves the captured
    // console output into the returned ExecutionResult).
    assert_eq!(result.console_output.len(), 1);
    let console_entry = &result.console_output[0];
    assert_eq!(console_entry.level, ConsoleLevel::Info);
    assert_eq!(console_entry.message, "Info message 42");
    assert_eq!(console_entry.instruction_index, 1);
}

#[test]
fn console_info_hostcall_dispatch() {
    let mut core = quickjs_test_core();

    core.set_reg(0, Value::str("Info hostcall"));
    core.dispatch_console_hostcall("console:info", RegRange { start: 0, count: 1 }, None)
        .expect("operation should succeed for valid inputs");

    assert_eq!(core.console_output.len(), 1);
    let console_entry = &core.console_output[0];
    assert_eq!(console_entry.level, ConsoleLevel::Info);
    assert_eq!(console_entry.message, "Info hostcall");
}

#[test]
fn console_builtin_ids_100_102_captured() {
    // Test that the original builtin IDs 100-102 properly capture output
    let mut core = InterpreterCore::new(test_quickjs_config(), "test-trace");

    core.set_reg(0, Value::str("Log test"));

    let result = core
        .execute(&test_module(vec![
            Ir3Instruction::HostCall {
                capability: CapabilityTag("builtin:ConsoleLog".to_string()),
                args: RegRange { start: 0, count: 1 },
                dst: 10,
            },
            Ir3Instruction::Halt,
        ]))
        .expect("operation should succeed for valid inputs");

    // Should capture output with Log level
    assert_eq!(result.console_output.len(), 1);
    assert_eq!(result.console_output[0].level, ConsoleLevel::Log);
    assert_eq!(result.console_output[0].message, "Log test");

    // Fresh core per level: execute() restores the initial register seed on
    // a second call, so each capture uses its own interpreter.
    let mut core = InterpreterCore::new(test_quickjs_config(), "test-trace");
    core.set_reg(0, Value::str("Error test"));

    let result = core
        .execute(&test_module(vec![
            Ir3Instruction::HostCall {
                capability: CapabilityTag("builtin:ConsoleError".to_string()),
                args: RegRange { start: 0, count: 1 },
                dst: 10,
            },
            Ir3Instruction::Halt,
        ]))
        .expect("operation should succeed for valid inputs");

    // Should capture output with Error level
    assert_eq!(result.console_output.len(), 1);
    assert_eq!(result.console_output[0].level, ConsoleLevel::Error);
    assert_eq!(result.console_output[0].message, "Error test");

    let mut core = InterpreterCore::new(test_quickjs_config(), "test-trace");
    core.set_reg(0, Value::str("Warn test"));

    let result = core
        .execute(&test_module(vec![
            Ir3Instruction::HostCall {
                capability: CapabilityTag("builtin:ConsoleWarn".to_string()),
                args: RegRange { start: 0, count: 1 },
                dst: 10,
            },
            Ir3Instruction::Halt,
        ]))
        .expect("operation should succeed for valid inputs");

    // Should capture output with Warn level
    assert_eq!(result.console_output.len(), 1);
    assert_eq!(result.console_output[0].level, ConsoleLevel::Warn);
    assert_eq!(result.console_output[0].message, "Warn test");
}

#[test]
fn console_output_deterministic_metadata() {
    let mut core = InterpreterCore::new(test_quickjs_config(), "test-trace");

    // Test that console output includes proper metadata
    core.set_reg(0, Value::str("Test"));
    core.set_reg(1, Value::Int(123));

    let result = core
        .execute(&test_module(vec![
            Ir3Instruction::HostCall {
                capability: CapabilityTag("builtin:ConsoleInfo".to_string()),
                args: RegRange { start: 0, count: 2 },
                dst: 10,
            },
            Ir3Instruction::Halt,
        ]))
        .expect("operation should succeed for valid inputs");

    assert_eq!(result.console_output.len(), 1);
    let entry = &result.console_output[0];

    // Check all metadata fields are populated
    assert_eq!(entry.level, ConsoleLevel::Info);
    assert_eq!(entry.message, "Test 123");
    assert!(entry.instruction_index > 0, "Should have instruction index");
}

#[test]
fn string_prototype_replace_object_coercion() {
    // Test that objects are properly coerced to "[object Object]"
    let mut core = InterpreterCore::new(test_quickjs_config(), "test");
    let obj_id = core
        .alloc_object_with_prototype(None)
        .expect("operation should succeed for valid inputs");
    core.set_register(0, Value::Object(obj_id))
        .expect("operation should succeed for valid inputs");
    core.set_register(1, Value::str("object"))
        .expect("operation should succeed for valid inputs");
    core.set_register(2, Value::str("replacement"))
        .expect("operation should succeed for valid inputs");

    core.execute_module(&test_module(vec![
        Ir3Instruction::HostCall {
            capability: CapabilityTag("builtin:StringPrototypeReplace".to_string()),
            args: RegRange { start: 0, count: 3 },
            dst: 3,
        },
        Ir3Instruction::Halt,
    ]))
    .expect("operation should succeed for valid inputs");

    let result = core
        .read_register(3)
        .expect("operation should succeed for valid inputs");
    assert_eq!(result, Value::str("[replacement Object]"));
}

#[test]
fn string_prototype_replace_no_search_arg() {
    // Test that no search argument returns original string
    let mut core = InterpreterCore::new(test_quickjs_config(), "test");
    core.set_register(0, Value::str("hello world"))
        .expect("operation should succeed for valid inputs");

    core.execute_module(&test_module(vec![
        Ir3Instruction::HostCall {
            capability: CapabilityTag("builtin:StringPrototypeReplace".to_string()),
            args: RegRange { start: 0, count: 1 },
            dst: 1,
        },
        Ir3Instruction::Halt,
    ]))
    .expect("operation should succeed for valid inputs");

    let result = core
        .read_register(1)
        .expect("operation should succeed for valid inputs");
    assert_eq!(result, Value::str("hello world"));
}

#[test]
fn string_prototype_replace_iterator_coercion() {
    // Test that other value types are coerced to "[object Object]" by default
    let mut core = InterpreterCore::new(test_quickjs_config(), "test");

    // Using Value::Iterator as an example of non-primitive type
    core.set_register(0, Value::Iterator(0))
        .expect("operation should succeed for valid inputs");
    core.set_register(1, Value::str("object"))
        .expect("operation should succeed for valid inputs");
    core.set_register(2, Value::str("replaced"))
        .expect("operation should succeed for valid inputs");

    core.execute_module(&test_module(vec![
        Ir3Instruction::HostCall {
            capability: CapabilityTag("builtin:StringPrototypeReplace".to_string()),
            args: RegRange { start: 0, count: 3 },
            dst: 3,
        },
        Ir3Instruction::Halt,
    ]))
    .expect("operation should succeed for valid inputs");

    let result = core
        .read_register(3)
        .expect("operation should succeed for valid inputs");
    assert_eq!(result, Value::str("[replaced Object]"));
}

#[test]
fn string_prototype_replace_builtin_function_coercion() {
    // Test that builtin functions are coerced to "[object Object]"
    let mut core = InterpreterCore::new(test_quickjs_config(), "test");
    let builtin_fn = BuiltinFunction::new_kind(BuiltinFunctionKind::FunctionConstructor);
    core.set_register(0, Value::BuiltinFunction(builtin_fn))
        .expect("operation should succeed for valid inputs");
    core.set_register(1, Value::str("object"))
        .expect("operation should succeed for valid inputs");
    core.set_register(2, Value::str("function"))
        .expect("operation should succeed for valid inputs");

    core.execute_module(&test_module(vec![
        Ir3Instruction::HostCall {
            capability: CapabilityTag("builtin:StringPrototypeReplace".to_string()),
            args: RegRange { start: 0, count: 3 },
            dst: 3,
        },
        Ir3Instruction::Halt,
    ]))
    .expect("operation should succeed for valid inputs");

    let result = core
        .read_register(3)
        .expect("operation should succeed for valid inputs");
    assert_eq!(result, Value::str("[function Object]"));
}

// Regression tests for bd-1b3v6: parseFloat exponent and Infinity semantics
#[test]
fn parse_float_scientific_notation() {
    let mut core = InterpreterCore::new(test_quickjs_config(), "test-trace");

    // Test parseFloat("1e3") should return 1000
    core.set_reg(0, Value::str("1e3"));

    let _result = core
        .execute(&test_module(vec![
            Ir3Instruction::HostCall {
                capability: CapabilityTag("builtin:ParseFloat".to_string()),
                args: RegRange { start: 0, count: 1 },
                dst: 10,
            },
            Ir3Instruction::Halt,
        ]))
        .expect("operation should succeed for valid inputs");

    // Should parse "1e3" as 1000
    assert_eq!(core.registers[10], Value::Int(1000));

    // Test parseFloat("2.5e2") should return 250. Fresh core: the
    // seed-tracked re-execution restores the initial register seed on a
    // second execute(), so a new core is required per input.
    let mut core = InterpreterCore::new(test_quickjs_config(), "test-trace");
    core.set_reg(0, Value::str("2.5e2"));

    let _result = core
        .execute(&test_module(vec![
            Ir3Instruction::HostCall {
                capability: CapabilityTag("builtin:ParseFloat".to_string()),
                args: RegRange { start: 0, count: 1 },
                dst: 10,
            },
            Ir3Instruction::Halt,
        ]))
        .expect("operation should succeed for valid inputs");

    // parseFloat("2.5e2") === 250, returned as Int: this engine canonicalizes
    // an integral parseFloat result to Int (the same test asserts Int(1000)
    // for "1e3" above; non-integral results like "3.14" stay Float). The
    // legacy "Expected Float" expectation was stale (bd-n0sap).
    assert_eq!(core.registers[10], Value::Int(250));
}

#[test]
fn parse_float_negative_exponent() {
    let mut core = InterpreterCore::new(test_quickjs_config(), "test-trace");

    // Test parseFloat("1e-3") should return 0.001
    core.set_reg(0, Value::str("1e-3"));

    let _result = core
        .execute(&test_module(vec![
            Ir3Instruction::HostCall {
                capability: CapabilityTag("builtin:ParseFloat".to_string()),
                args: RegRange { start: 0, count: 1 },
                dst: 10,
            },
            Ir3Instruction::Halt,
        ]))
        .expect("operation should succeed for valid inputs");

    // Should parse "1e-3" as 0.001
    if let Value::Float(f) = core.registers[10] {
        assert!((f.inner() - 0.001).abs() < f64::EPSILON);
    } else {
        panic!("Expected Float for 1e-3");
    }

    // Test parseFloat("5E+2") should return 500. Fresh core: see above.
    let mut core = InterpreterCore::new(test_quickjs_config(), "test-trace");
    core.set_reg(0, Value::str("5E+2"));

    let _result = core
        .execute(&test_module(vec![
            Ir3Instruction::HostCall {
                capability: CapabilityTag("builtin:ParseFloat".to_string()),
                args: RegRange { start: 0, count: 1 },
                dst: 10,
            },
            Ir3Instruction::Halt,
        ]))
        .expect("operation should succeed for valid inputs");

    // Should parse "5E+2" as 500
    assert_eq!(core.registers[10], Value::Int(500));
}

#[test]
fn parse_float_infinity_literals() {
    let mut core = InterpreterCore::new(test_quickjs_config(), "test-trace");

    // Test parseFloat("Infinity")
    core.set_reg(0, Value::str("Infinity"));

    let _result = core
        .execute(&test_module(vec![
            Ir3Instruction::HostCall {
                capability: CapabilityTag("builtin:ParseFloat".to_string()),
                args: RegRange { start: 0, count: 1 },
                dst: 10,
            },
            Ir3Instruction::Halt,
        ]))
        .expect("operation should succeed for valid inputs");

    // Should return positive infinity
    if let Value::Float(f) = core.registers[10] {
        assert!(f.inner().is_infinite() && f.inner().is_sign_positive());
    } else {
        panic!("Expected Float for Infinity");
    }

    // Test parseFloat("-Infinity"). Fresh core: see above.
    let mut core = InterpreterCore::new(test_quickjs_config(), "test-trace");
    core.set_reg(0, Value::str("-Infinity"));

    let _result = core
        .execute(&test_module(vec![
            Ir3Instruction::HostCall {
                capability: CapabilityTag("builtin:ParseFloat".to_string()),
                args: RegRange { start: 0, count: 1 },
                dst: 10,
            },
            Ir3Instruction::Halt,
        ]))
        .expect("operation should succeed for valid inputs");

    // Should return negative infinity
    if let Value::Float(f) = core.registers[10] {
        assert!(f.inner().is_infinite() && f.inner().is_sign_negative());
    } else {
        panic!("Expected Float for -Infinity");
    }

    // Test parseFloat("+Infinity"). Fresh core: see above.
    let mut core = InterpreterCore::new(test_quickjs_config(), "test-trace");
    core.set_reg(0, Value::str("+Infinity"));

    let _result = core
        .execute(&test_module(vec![
            Ir3Instruction::HostCall {
                capability: CapabilityTag("builtin:ParseFloat".to_string()),
                args: RegRange { start: 0, count: 1 },
                dst: 10,
            },
            Ir3Instruction::Halt,
        ]))
        .expect("operation should succeed for valid inputs");

    // Should return positive infinity
    if let Value::Float(f) = core.registers[10] {
        assert!(f.inner().is_infinite() && f.inner().is_sign_positive());
    } else {
        panic!("Expected Float for +Infinity");
    }
}

#[test]
fn parse_float_invalid_exponent_fallback() {
    let mut core = InterpreterCore::new(test_quickjs_config(), "test-trace");

    // Test parseFloat("1e") - incomplete exponent should parse as 1
    core.set_reg(0, Value::str("1e"));

    let _result = core
        .execute(&test_module(vec![
            Ir3Instruction::HostCall {
                capability: CapabilityTag("builtin:ParseFloat".to_string()),
                args: RegRange { start: 0, count: 1 },
                dst: 10,
            },
            Ir3Instruction::Halt,
        ]))
        .expect("operation should succeed for valid inputs");

    // The incomplete exponent is not part of the longest decimal prefix.
    assert_eq!(core.registers[10], Value::Int(1));

    // Test parseFloat("123abc") should stop at 'a' and return 123. Fresh core.
    let mut core = InterpreterCore::new(test_quickjs_config(), "test-trace");
    core.set_reg(0, Value::str("123abc"));

    let _result = core
        .execute(&test_module(vec![
            Ir3Instruction::HostCall {
                capability: CapabilityTag("builtin:ParseFloat".to_string()),
                args: RegRange { start: 0, count: 1 },
                dst: 10,
            },
            Ir3Instruction::Halt,
        ]))
        .expect("operation should succeed for valid inputs");

    // Should stop at first invalid character and return 123
    assert_eq!(core.registers[10], Value::Int(123));
}

#[test]
fn parse_float_builtin_dispatch_deduplication_regression() {
    let mut core = InterpreterCore::new(test_quickjs_config(), "test-trace");

    let float_builtin_ids = [83u32, 232u32, 378u32];
    let inputs = [
        Value::str("1e3"),
        Value::str("Infinityxyz"),
        Value::str(" 2.5e2 "),
        Value::Int(7),
        Value::Float(Float64::new(3.5)),
    ];

    for input in inputs {
        core.set_reg(0, input);
        let first_cap = core
            .map_function_index_to_builtin_capability(float_builtin_ids[0])
            .expect("first parseFloat builtin id should be mapped");
        let first = core
            .dispatch_builtin_hostcall(&first_cap, RegRange { start: 0, count: 1 }, None)
            .expect("first parseFloat builtin id should execute");

        for builtin_id in &float_builtin_ids[1..] {
            let cap = core
                .map_function_index_to_builtin_capability(*builtin_id)
                .expect("all parseFloat builtin ids should be mapped");
            let next = core
                .dispatch_builtin_hostcall(&cap, RegRange { start: 0, count: 1 }, None)
                .expect("all parseFloat builtin ids should execute");
            assert_eq!(
                first, next,
                "Builtin IDs {{83, 232, 378}} should be deduplicated"
            );
        }
    }

    assert_eq!(
        core.map_function_index_to_builtin_capability(83),
        Some("builtin:parseFloat".to_string())
    );
    assert_eq!(
        core.map_function_index_to_builtin_capability(232),
        Some("builtin:NumberParseFloat".to_string())
    );
    assert_eq!(
        core.map_function_index_to_builtin_capability(378),
        Some("builtin:ParseFloat".to_string())
    );
}

#[test]
fn batch_29_number_and_char_at_builtin_ids_use_canonical_dispatch() {
    let mut core = InterpreterCore::new(test_quickjs_config(), "test-trace");

    let number_is_nan_ids = [90u32, 239u32, 337u32];
    let nan_cases = [
        (Value::Float(Float64::new(f64::NAN)), true),
        (Value::str("NaN"), false),
        (Value::Undefined, false),
    ];
    for builtin_id in number_is_nan_ids {
        assert_eq!(
            core.builtin_name_from_id(builtin_id),
            Some("builtin:NumberIsNaN".to_string())
        );

        for (value, expected) in &nan_cases {
            core.set_reg(4, value.clone());
            let result = core
                .call_builtin_by_id(builtin_id, RegRange { start: 4, count: 1 })
                .expect("Number.isNaN alias should execute");
            assert_eq!(
                result,
                Value::Bool(*expected),
                "Number.isNaN id {builtin_id} should share canonical strict semantics"
            );
        }
    }

    let number_is_finite_ids = [91u32, 338u32];
    let finite_cases = [
        (Value::Int(7), true),
        (Value::Float(Float64::new(f64::INFINITY)), false),
        (Value::str("7"), false),
    ];
    for builtin_id in number_is_finite_ids {
        assert_eq!(
            core.builtin_name_from_id(builtin_id),
            Some("builtin:NumberIsFinite".to_string())
        );

        for (value, expected) in &finite_cases {
            core.set_reg(4, value.clone());
            let result = core
                .call_builtin_by_id(builtin_id, RegRange { start: 4, count: 1 })
                .expect("Number.isFinite alias should execute");
            assert_eq!(
                result,
                Value::Bool(*expected),
                "Number.isFinite id {builtin_id} should share canonical strict semantics"
            );
        }
    }

    for builtin_id in [30u32, 339u32] {
        assert_eq!(
            core.builtin_name_from_id(builtin_id),
            Some("builtin:StringPrototypeCharAt".to_string())
        );

        core.set_reg(4, Value::str("hello"));
        core.set_reg(5, Value::Int(1));
        let explicit_index = core
            .call_builtin_by_id(builtin_id, RegRange { start: 4, count: 2 })
            .expect("String.prototype.charAt alias should execute");
        assert_eq!(explicit_index, Value::str("e"));

        core.set_reg(4, Value::Int(42));
        let default_index = core
            .call_builtin_by_id(builtin_id, RegRange { start: 4, count: 1 })
            .expect("String.prototype.charAt alias should execute");
        assert_eq!(default_index, Value::str("4"));
    }
}

#[test]
fn math_random_deterministic_replay() {
    // Regression test: same execution state should produce same random sequence
    // This ensures DefaultHasher replacement with SHA-256 maintains determinism
    let mut core1 = InterpreterCore::new(test_quickjs_config(), "test");
    let mut core2 = InterpreterCore::new(test_quickjs_config(), "test");

    // Set both cores to identical state
    core1.instructions_executed = 42;
    core1.ip = 10;
    core2.instructions_executed = 42;
    core2.ip = 10;

    // Call Math.random on both cores
    let result1 = core1
        .math_random_impl()
        .expect("operation should succeed for valid inputs");
    let result2 = core2
        .math_random_impl()
        .expect("operation should succeed for valid inputs");

    // Should produce identical results (deterministic)
    assert_eq!(
        result1, result2,
        "Math.random should be deterministic with same execution state"
    );

    // Verify it's actually a valid random number in [0, 1)
    if let Value::Float(f) = result1 {
        let val = f.inner();
        assert!(val >= 0.0, "Math.random should be >= 0.0, got {}", val);
        assert!(val < 1.0, "Math.random should be < 1.0, got {}", val);
    } else {
        panic!("Math.random should return a Float, got {:?}", result1);
    }
}

#[test]
fn math_random_different_states_produce_different_values() {
    // Test that different execution states produce different random values
    let mut core1 = InterpreterCore::new(test_quickjs_config(), "test");
    let mut core2 = InterpreterCore::new(test_quickjs_config(), "test");

    // Set cores to different states
    core1.instructions_executed = 10;
    core2.instructions_executed = 20;

    let result1 = core1
        .math_random_impl()
        .expect("operation should succeed for valid inputs");
    let result2 = core2
        .math_random_impl()
        .expect("operation should succeed for valid inputs");

    // Should produce different results
    assert_ne!(
        result1, result2,
        "Different execution states should produce different random values"
    );
}

#[test]
fn string_prototype_char_code_at_basic() {
    // Test basic charCodeAt functionality with ASCII characters
    let mut core = InterpreterCore::new(test_quickjs_config(), "test");
    // SAFETY: Register 0 is valid in a fresh interpreter and owns the test string.
    core.set_register(0, Value::str("Hello"))
        .expect("operation should succeed for valid inputs");
    // SAFETY: Register 1 is valid in a fresh interpreter and the index is immediate.
    core.set_register(1, Value::Int(0))
        .expect("operation should succeed for valid inputs"); // index 0

    // SAFETY: The inline module uses initialized registers and a registered builtin id.
    core.execute_module(&test_module(vec![
        Ir3Instruction::HostCall {
            capability: CapabilityTag("builtin:StringPrototypeCharCodeAt".to_string()),
            args: RegRange { start: 0, count: 2 },
            dst: 2,
        },
        Ir3Instruction::Halt,
    ]))
    .expect("operation should succeed for valid inputs");

    // "Hello"[0] = 'H' = 72
    // SAFETY: StringPrototypeCharCodeAt writes destination register 2 before halt.
    let result = core
        .read_register(2)
        .expect("operation should succeed for valid inputs");
    assert_eq!(result, Value::Int(72), "charCodeAt('H') should be 72");
}

#[test]
fn string_indexed_properties_follow_exact_utf16_code_units_bd_opsnv() {
    let text = JsString::from("A😀B");
    assert_eq!(
        InterpreterCore::string_property_value(&text, "length"),
        Value::Int(4)
    );
    assert_eq!(
        InterpreterCore::string_property_value(&text, "0"),
        Value::str("A")
    );
    assert_eq!(
        InterpreterCore::string_property_value(&text, "1"),
        Value::Str(JsString::from_code_units(&[0xD83D]))
    );
    assert_eq!(
        InterpreterCore::string_property_value(&text, "2"),
        Value::Str(JsString::from_code_units(&[0xDE00]))
    );
    assert_eq!(
        InterpreterCore::string_property_value(&text, "3"),
        Value::str("B")
    );
    assert_eq!(
        InterpreterCore::string_property_value(&text, "4"),
        Value::Undefined
    );
    assert_eq!(
        InterpreterCore::string_property_value(&text, "01"),
        Value::Undefined,
        "a non-canonical numeric property key is not a string index"
    );

    let lone_surrogate = JsString::from_code_units(&[0xD800]);
    assert_eq!(
        InterpreterCore::string_property_value(&lone_surrogate, "0"),
        Value::Str(lone_surrogate),
        "indexed access must preserve an exact lone surrogate"
    );
}

#[test]
fn string_prototype_char_code_at_utf16_surrogate_pairs() {
    // Test charCodeAt with UTF-16 surrogate pairs (characters outside BMP).
    // charCodeAt indexes UTF-16 code units over the UTF-8 storage
    // (string_prototype_char_code_at_value uses encode_utf16), so both
    // surrogate halves of U+1F600 (😀 = 0xD83D 0xDE00) are observable.
    // A fresh core per index: seed-tracked re-execution restores prior
    // register state when the same core re-runs (bd-n0sap port note).
    for (index, expected, label) in [
        (0, 0xD83D, "First UTF-16 code unit should be high surrogate"),
        (1, 0xDE00, "Second UTF-16 code unit should be low surrogate"),
    ] {
        let mut core = InterpreterCore::new(test_quickjs_config(), "test");
        // SAFETY: Register 0 is valid in a fresh interpreter and owns the test string.
        core.set_register(0, Value::str("😀"))
            .expect("operation should succeed for valid inputs");
        // SAFETY: Register 1 is valid in a fresh interpreter and the index is immediate.
        core.set_register(1, Value::Int(index))
            .expect("operation should succeed for valid inputs");
        // SAFETY: The inline module uses initialized registers and a registered builtin id.
        core.execute_module(&test_module(vec![
            Ir3Instruction::HostCall {
                capability: CapabilityTag("builtin:StringPrototypeCharCodeAt".to_string()),
                args: RegRange { start: 0, count: 2 },
                dst: 2,
            },
            Ir3Instruction::Halt,
        ]))
        .expect("operation should succeed for valid inputs");

        // SAFETY: StringPrototypeCharCodeAt writes destination register 2 before halt.
        let result = core
            .read_register(2)
            .expect("operation should succeed for valid inputs");
        assert_eq!(result, Value::Int(expected), "{label}");
    }
}

#[test]
fn string_prototype_char_code_at_out_of_bounds() {
    // Test charCodeAt with out-of-bounds index returns NaN
    let mut core = InterpreterCore::new(test_quickjs_config(), "test");
    // SAFETY: Register 0 is valid in a fresh interpreter and owns the test string.
    core.set_register(0, Value::str("Hi"))
        .expect("operation should succeed for valid inputs");
    // SAFETY: Register 1 is valid in a fresh interpreter and the out-of-bounds index is intentional.
    core.set_register(1, Value::Int(5))
        .expect("operation should succeed for valid inputs"); // index 5 (out of bounds)

    // SAFETY: The inline module uses initialized registers and a registered builtin id.
    core.execute_module(&test_module(vec![
        Ir3Instruction::HostCall {
            capability: CapabilityTag("builtin:StringPrototypeCharCodeAt".to_string()),
            args: RegRange { start: 0, count: 2 },
            dst: 2,
        },
        Ir3Instruction::Halt,
    ]))
    .expect("operation should succeed for valid inputs");

    // SAFETY: StringPrototypeCharCodeAt writes destination register 2 before halt.
    let result = core
        .read_register(2)
        .expect("operation should succeed for valid inputs");
    if let Value::Float(f) = result {
        assert!(
            f.inner().is_nan(),
            "Out-of-bounds charCodeAt should return NaN"
        );
    } else {
        panic!("Expected Float NaN, got {:?}", result);
    }
}

#[test]
fn string_prototype_char_code_at_negative_index() {
    // Test charCodeAt with negative index (should treat as 0)
    let mut core = InterpreterCore::new(test_quickjs_config(), "test");
    core.set_register(0, Value::str("Test"))
        .expect("operation should succeed for valid inputs");
    core.set_register(1, Value::Int(-1))
        .expect("operation should succeed for valid inputs"); // negative index

    core.execute_module(&test_module(vec![
        Ir3Instruction::HostCall {
            capability: CapabilityTag("builtin:StringPrototypeCharCodeAt".to_string()),
            args: RegRange { start: 0, count: 2 },
            dst: 2,
        },
        Ir3Instruction::Halt,
    ]))
    .expect("operation should succeed for valid inputs");

    // Should return first character 'T' = 84
    let result = core
        .read_register(2)
        .expect("operation should succeed for valid inputs");
    // "Test".charCodeAt(-1) === NaN per ES: an out-of-range index yields NaN,
    // not a clamp to 0. The legacy assertion expected 84 ('T') (bd-n0sap).
    let Value::Float(f) = result else {
        panic!("charCodeAt(-1) should be a NaN float, got {result:?}");
    };
    assert!(f.inner().is_nan(), "charCodeAt(-1) is NaN per ES");
}

#[test]
fn string_prototype_char_code_at_no_index() {
    // Test charCodeAt with no index argument (should default to 0)
    let mut core = InterpreterCore::new(test_quickjs_config(), "test");
    core.set_register(0, Value::str("ABC"))
        .expect("operation should succeed for valid inputs");

    core.execute_module(&test_module(vec![
        Ir3Instruction::HostCall {
            capability: CapabilityTag("builtin:StringPrototypeCharCodeAt".to_string()),
            args: RegRange { start: 0, count: 1 }, // no index argument
            dst: 1,
        },
        Ir3Instruction::Halt,
    ]))
    .expect("operation should succeed for valid inputs");

    // Should return first character 'A' = 65
    let result = core
        .read_register(1)
        .expect("operation should succeed for valid inputs");
    assert_eq!(result, Value::Int(65), "No index should default to 0");
}

#[test]
fn string_prototype_char_code_at_type_coercion() {
    // Test charCodeAt with non-string values (should coerce to string)
    let mut core = InterpreterCore::new(test_quickjs_config(), "test");
    // SAFETY: Register 0 is a valid test register and Value::Int needs no heap allocation.
    core.set_register(0, Value::Int(123))
        .expect("operation should succeed for valid inputs"); // should become "123"
    // SAFETY: Register 1 is a valid test register and the index value is immediate.
    core.set_register(1, Value::Int(1))
        .expect("operation should succeed for valid inputs"); // index 1

    // SAFETY: The inline module only calls a registered builtin with initialized registers.
    core.execute_module(&test_module(vec![
        Ir3Instruction::HostCall {
            capability: CapabilityTag("builtin:StringPrototypeCharCodeAt".to_string()),
            args: RegRange { start: 0, count: 2 },
            dst: 2,
        },
        Ir3Instruction::Halt,
    ]))
    .expect("operation should succeed for valid inputs");

    // "123"[1] = '2' = 50
    // SAFETY: The builtin writes destination register 2 before the halt instruction.
    let result = core
        .read_register(2)
        .expect("operation should succeed for valid inputs");
    assert_eq!(
        result,
        Value::Int(50),
        "charCodeAt on number should coerce to string"
    );
}

#[test]
fn string_prototype_char_at_basic() {
    // Test basic charAt functionality with ASCII characters
    let mut core = InterpreterCore::new(test_quickjs_config(), "test");
    // SAFETY: Register 0 is valid in a fresh interpreter and owns the test string.
    core.set_register(0, Value::str("Hello"))
        .expect("operation should succeed for valid inputs");
    // SAFETY: Register 1 is valid in a fresh interpreter and the index is immediate.
    core.set_register(1, Value::Int(1))
        .expect("operation should succeed for valid inputs"); // index 1

    // SAFETY: The inline module uses initialized registers and a registered builtin id.
    core.execute_module(&test_module(vec![
        Ir3Instruction::HostCall {
            capability: CapabilityTag("builtin:StringPrototypeCharAt".to_string()),
            args: RegRange { start: 0, count: 2 },
            dst: 2,
        },
        Ir3Instruction::Halt,
    ]))
    .expect("operation should succeed for valid inputs");

    // "Hello"[1] = 'e'
    // SAFETY: StringPrototypeCharAt writes destination register 2 before halt.
    let result = core
        .read_register(2)
        .expect("operation should succeed for valid inputs");
    assert_eq!(result, Value::str("e"), "charAt(1) should return 'e'");
}

#[test]
fn string_prototype_char_at_utf16_surrogate_pairs() {
    // Test charAt with UTF-16 surrogate pairs (characters outside BMP).
    // Un-ignored by bd-neika: `JsString` carries exact code units, so
    // charAt on a surrogate half returns a real lone-surrogate string
    // (its `encode_utf16` yields the surrogate; its UTF-8 projection is
    // the 3-byte U+FFFD).
    // A fresh core per index: seed-tracked re-execution restores prior
    // register state when the same core re-runs (bd-n0sap port note).
    for (index, expected, label) in [
        (0, 0xD83D, "First character should be high surrogate"),
        (1, 0xDE00, "Second character should be low surrogate"),
    ] {
        let mut core = InterpreterCore::new(test_quickjs_config(), "test");
        // U+1F600 (😀) is encoded as surrogate pair: 0xD83D 0xDE00
        core.set_register(0, Value::str("😀"))
            .expect("operation should succeed for valid inputs");
        core.set_register(1, Value::Int(index))
            .expect("operation should succeed for valid inputs");
        core.execute_module(&test_module(vec![
            Ir3Instruction::HostCall {
                capability: CapabilityTag("builtin:StringPrototypeCharAt".to_string()),
                args: RegRange { start: 0, count: 2 },
                dst: 2,
            },
            Ir3Instruction::Halt,
        ]))
        .expect("operation should succeed for valid inputs");

        let result = core
            .read_register(2)
            .expect("operation should succeed for valid inputs");
        if let Value::Str(s) = result {
            // A lone surrogate is one UTF-16 code unit (3 bytes in UTF-8
            // under a WTF-8-style encoding).
            assert_eq!(s.len(), 3, "surrogate half should be 3 bytes");
            let utf16_units: Vec<u16> = s.encode_utf16().collect();
            assert_eq!(utf16_units[0], expected, "{label}");
            assert!(
                !s.is_well_formed(),
                "a surrogate half must be a real lone-surrogate value, \
                     not the U+FFFD projection"
            );
        } else {
            panic!("Expected Str, got {result:?}");
        }
    }
}

#[test]
fn string_char_at_surrogate_halves_heal_on_concatenation() {
    // bd-neika AC: "😀".charAt(0) + "😀".charAt(1) === "😀". The two
    // lone-surrogate halves must survive charAt and re-heal into the
    // supplementary code point through the `+` concatenation path.
    let mut core = InterpreterCore::new(test_quickjs_config(), "test");
    core.set_register(0, Value::str("😀"))
        .expect("operation should succeed for valid inputs");
    core.set_register(1, Value::Int(0))
        .expect("operation should succeed for valid inputs");
    core.set_register(2, Value::str("😀"))
        .expect("operation should succeed for valid inputs");
    core.set_register(3, Value::Int(1))
        .expect("operation should succeed for valid inputs");
    core.execute_module(&test_module(vec![
        Ir3Instruction::HostCall {
            capability: CapabilityTag("builtin:StringPrototypeCharAt".to_string()),
            args: RegRange { start: 0, count: 2 },
            dst: 4,
        },
        Ir3Instruction::HostCall {
            capability: CapabilityTag("builtin:StringPrototypeCharAt".to_string()),
            args: RegRange { start: 2, count: 2 },
            dst: 5,
        },
        Ir3Instruction::Add {
            dst: 6,
            lhs: 4,
            rhs: 5,
        },
        Ir3Instruction::Halt,
    ]))
    .expect("operation should succeed for valid inputs");

    let healed = core
        .read_register(6)
        .expect("operation should succeed for valid inputs");
    assert_eq!(
        healed,
        Value::str("😀"),
        "charAt(0) + charAt(1) must heal back to the original string"
    );
    if let Value::Str(s) = healed {
        assert!(s.is_well_formed(), "healed pair must be well-formed");
        assert_eq!(s.code_units_vec(), vec![0xD83D, 0xDE00]);
    }
}

#[test]
fn string_from_char_code_lone_surrogate_and_pair_healing() {
    // bd-neika AC: String.fromCharCode(0xD83D) is a real lone-surrogate
    // string (previously NUL); fromCharCode(0xD83D, 0xDE00) heals into
    // U+1F600 exactly as concatenation would.
    let mut core = InterpreterCore::new(test_quickjs_config(), "test");
    core.set_register(0, Value::Int(0xD83D))
        .expect("operation should succeed for valid inputs");
    core.execute_module(&test_module(vec![
        Ir3Instruction::HostCall {
            capability: CapabilityTag("builtin:StringFromCharCode".to_string()),
            args: RegRange { start: 0, count: 1 },
            dst: 1,
        },
        Ir3Instruction::Halt,
    ]))
    .expect("operation should succeed for valid inputs");
    let lone = core
        .read_register(1)
        .expect("operation should succeed for valid inputs");
    if let Value::Str(s) = &lone {
        assert!(!s.is_well_formed(), "0xD83D must stay a lone surrogate");
        assert_eq!(s.code_units_vec(), vec![0xD83D]);
        assert_eq!(s.as_utf8_projection(), "\u{FFFD}");
    } else {
        panic!("Expected Str, got {lone:?}");
    }

    let mut core = InterpreterCore::new(test_quickjs_config(), "test");
    core.set_register(0, Value::Int(0xD83D))
        .expect("operation should succeed for valid inputs");
    core.set_register(1, Value::Int(0xDE00))
        .expect("operation should succeed for valid inputs");
    core.execute_module(&test_module(vec![
        Ir3Instruction::HostCall {
            capability: CapabilityTag("builtin:StringFromCharCode".to_string()),
            args: RegRange { start: 0, count: 2 },
            dst: 2,
        },
        Ir3Instruction::Halt,
    ]))
    .expect("operation should succeed for valid inputs");
    let healed = core
        .read_register(2)
        .expect("operation should succeed for valid inputs");
    assert_eq!(healed, Value::str("😀"), "surrogate pair must heal");
}

#[test]
fn string_from_code_point_accepts_surrogate_code_points() {
    // ES 21.1.2.2: surrogate code points are valid fromCodePoint
    // arguments and yield lone-surrogate code units (bd-neika replaced
    // the earlier non-spec RangeError).
    let mut core = InterpreterCore::new(test_quickjs_config(), "test");
    core.set_register(0, Value::Int(0xD800))
        .expect("operation should succeed for valid inputs");
    core.execute_module(&test_module(vec![
        Ir3Instruction::HostCall {
            capability: CapabilityTag("builtin:StringFromCodePoint".to_string()),
            args: RegRange { start: 0, count: 1 },
            dst: 1,
        },
        Ir3Instruction::Halt,
    ]))
    .expect("operation should succeed for valid inputs");
    let result = core
        .read_register(1)
        .expect("operation should succeed for valid inputs");
    if let Value::Str(s) = &result {
        assert_eq!(s.code_units_vec(), vec![0xD800]);
        assert!(!s.is_well_formed());
    } else {
        panic!("Expected Str, got {result:?}");
    }
}

#[test]
fn json_parse_rolls_back_late_invalid_allocations() {
    let mut core = InterpreterCore::new(test_quickjs_config(), "test");
    for name in ["Object", "Array", "SyntaxError"] {
        core.ensure_builtin_prototype(name).unwrap();
    }
    core.seed_register(0, Value::str(r#"{"a":[1,2]} trailing"#))
        .expect("invalid JSON input should fit register zero");
    let heap_before = core.heap_size();

    let error = core
        .dispatch_builtin_hostcall_inner("builtin:JsonParse", RegRange { start: 0, count: 1 }, None)
        .expect_err("invalid JSON must throw SyntaxError");

    assert!(matches!(error, InterpreterError::UncaughtException { .. }));
    // Only the error object survives, not the partially parsed object/array.
    assert_eq!(core.heap_size(), heap_before + 1);
    assert_eq!(
        core.chain_data_property(ObjectId(heap_before as u32), "name"),
        Some(&Value::str("SyntaxError"))
    );
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn json_parse_preserves_raw_lone_surrogate_units() {
    let mut core = InterpreterCore::new(test_quickjs_config(), "test");
    for expected in [vec![0xD800], vec![0xDC00], vec![0xD83D, 0xDE00]] {
        let mut json = vec![0x22];
        json.extend_from_slice(&expected);
        json.push(0x22);
        core.set_register(0, Value::Str(JsString::from_code_units(&json)))
            .expect("raw UTF-16 JSON input should fit register zero");

        let result = core
            .dispatch_builtin_hostcall("builtin:JsonParse", RegRange { start: 0, count: 1 }, None)
            .expect("raw UTF-16 JSON string should parse");

        let Value::Str(parsed) = result else {
            panic!("JSON.parse should return the parsed string");
        };
        assert_eq!(parsed.code_units_vec(), expected);
    }

    let mut nested = "{\"value\":\"".encode_utf16().collect::<Vec<_>>();
    nested.push(0xD800);
    nested.extend("\"}".encode_utf16());
    core.set_register(0, Value::Str(JsString::from_code_units(&nested)))
        .expect("nested raw UTF-16 JSON input should fit register zero");
    let nested_result = core
        .dispatch_builtin_hostcall("builtin:JsonParse", RegRange { start: 0, count: 1 }, None)
        .expect("nested raw UTF-16 JSON string should parse");
    let Value::Object(nested_id) = nested_result else {
        panic!("JSON.parse should allocate the nested object");
    };
    let Some(Value::Str(nested_value)) = core.heap[nested_id.0 as usize].properties.get("value")
    else {
        panic!("nested JSON string should be stored as a data property");
    };
    assert_eq!(nested_value.code_units_vec(), vec![0xD800]);

    core.set_register(
        0,
        Value::Str(JsString::from_code_units(&[0x22, 0x1F, 0x22])),
    )
    .expect("raw control-unit JSON input should fit register zero");
    assert!(matches!(
        core.dispatch_builtin_hostcall("builtin:JsonParse", RegRange { start: 0, count: 1 }, None,),
        Err(InterpreterError::UncaughtException { .. })
    ));
}

#[test]
fn json_parse_lone_surrogate_escape_and_stringify_round_trip() {
    // bd-neika AC: JSON round-trip of lone surrogates. The JSON text
    // "\uD800" (a lone-surrogate escape, valid JSON per ES 24.5.1)
    // parses to a lone-surrogate string value, and JSON.stringify emits
    // it back as a \uXXXX escape so parse(stringify(v)) == v.
    let json_text = "\"\\uD800\"";
    let mut core = InterpreterCore::new(test_quickjs_config(), "test");
    core.set_register(0, Value::str(json_text))
        .expect("operation should succeed for valid inputs");
    core.execute_module(&test_module(vec![
        Ir3Instruction::HostCall {
            capability: CapabilityTag("builtin:JsonParse".to_string()),
            args: RegRange { start: 0, count: 1 },
            dst: 1,
        },
        Ir3Instruction::HostCall {
            capability: CapabilityTag("builtin:JsonStringify".to_string()),
            args: RegRange { start: 1, count: 1 },
            dst: 2,
        },
        Ir3Instruction::HostCall {
            capability: CapabilityTag("builtin:JsonParse".to_string()),
            args: RegRange { start: 2, count: 1 },
            dst: 3,
        },
        Ir3Instruction::Halt,
    ]))
    .expect("operation should succeed for valid inputs");

    let parsed = core
        .read_register(1)
        .expect("operation should succeed for valid inputs");
    if let Value::Str(s) = &parsed {
        assert_eq!(s.code_units_vec(), vec![0xD800]);
        assert!(
            !s.is_well_formed(),
            "parsed value must be a real lone surrogate"
        );
    } else {
        panic!("Expected Str from JSON.parse, got {parsed:?}");
    }

    let stringified = core
        .read_register(2)
        .expect("operation should succeed for valid inputs");
    if let Value::Str(s) = &stringified {
        assert_eq!(
            s.as_str(),
            Some("\"\\ud800\""),
            "stringify must escape the lone surrogate (lowercase hex per UnicodeEscape)"
        );
    } else {
        panic!("Expected Str from JSON.stringify, got {stringified:?}");
    }

    let round_tripped = core
        .read_register(3)
        .expect("operation should succeed for valid inputs");
    assert_eq!(
        round_tripped, parsed,
        "JSON.parse(JSON.stringify(v)) must round-trip the lone surrogate exactly"
    );
}

#[test]
fn json_parse_combines_paired_surrogate_escapes() {
    // "😀" in JSON text is the standard escape spelling of
    // U+1F600; the parser must combine the pair (previously the whole
    // parse returned undefined because each escape was converted to
    // char independently).
    let mut core = InterpreterCore::new(test_quickjs_config(), "test");
    core.set_register(0, Value::str("\"\\uD83D\\uDE00\""))
        .expect("operation should succeed for valid inputs");
    core.execute_module(&test_module(vec![
        Ir3Instruction::HostCall {
            capability: CapabilityTag("builtin:JsonParse".to_string()),
            args: RegRange { start: 0, count: 1 },
            dst: 1,
        },
        Ir3Instruction::Halt,
    ]))
    .expect("operation should succeed for valid inputs");
    let parsed = core
        .read_register(1)
        .expect("operation should succeed for valid inputs");
    assert_eq!(parsed, Value::str("😀"));
}

#[test]
fn string_prototype_char_at_out_of_bounds() {
    // Test charAt with out-of-bounds index returns empty string
    let mut core = InterpreterCore::new(test_quickjs_config(), "test");
    // SAFETY: test setup writes to valid registers in a fresh interpreter.
    core.set_register(0, Value::str("Hi"))
        .expect("operation should succeed for valid inputs");
    // SAFETY: test setup writes to valid registers in a fresh interpreter.
    core.set_register(1, Value::Int(5))
        .expect("operation should succeed for valid inputs"); // index 5 (out of bounds)

    // SAFETY: the test module is well-formed and should execute successfully.
    core.execute_module(&test_module(vec![
        Ir3Instruction::HostCall {
            capability: CapabilityTag("builtin:StringPrototypeCharAt".to_string()),
            args: RegRange { start: 0, count: 2 },
            dst: 2,
        },
        Ir3Instruction::Halt,
    ]))
    .expect("operation should succeed for valid inputs");

    // SAFETY: the executed module writes its result to register 2.
    let result = core
        .read_register(2)
        .expect("operation should succeed for valid inputs");
    assert_eq!(
        result,
        Value::str(""),
        "Out-of-bounds charAt should return empty string"
    );
}

#[test]
fn string_prototype_char_at_negative_index() {
    // Test charAt with negative index (should treat as 0)
    let mut core = InterpreterCore::new(test_quickjs_config(), "test");
    // SAFETY: test setup writes to valid registers in a fresh interpreter.
    core.set_register(0, Value::str("Test"))
        .expect("operation should succeed for valid inputs");
    // SAFETY: test setup writes to valid registers in a fresh interpreter.
    core.set_register(1, Value::Int(-1))
        .expect("operation should succeed for valid inputs"); // negative index

    // SAFETY: the test module is well-formed and should execute successfully.
    core.execute_module(&test_module(vec![
        Ir3Instruction::HostCall {
            capability: CapabilityTag("builtin:StringPrototypeCharAt".to_string()),
            args: RegRange { start: 0, count: 2 },
            dst: 2,
        },
        Ir3Instruction::Halt,
    ]))
    .expect("operation should succeed for valid inputs");

    // Should return first character 'T'
    // SAFETY: the executed module writes its result to register 2.
    let result = core
        .read_register(2)
        .expect("operation should succeed for valid inputs");
    // "Test".charAt(-1) === "" per ES: an out-of-range index (including a
    // negative one) yields the empty string; charAt does NOT clamp to 0.
    // The legacy comment/expectation was non-conformant (bd-n0sap).
    assert_eq!(
        result,
        Value::str(""),
        "charAt(-1) is the empty string per ES"
    );
}

#[test]
fn string_prototype_char_at_no_index() {
    // Test charAt with no index argument (should default to 0)
    let mut core = InterpreterCore::new(test_quickjs_config(), "test");
    // SAFETY: test setup writes to a valid register in a fresh interpreter.
    core.set_register(0, Value::str("ABC"))
        .expect("operation should succeed for valid inputs");

    // SAFETY: the test module is well-formed and should execute successfully.
    core.execute_module(&test_module(vec![
        Ir3Instruction::HostCall {
            capability: CapabilityTag("builtin:StringPrototypeCharAt".to_string()),
            args: RegRange { start: 0, count: 1 }, // no index argument
            dst: 1,
        },
        Ir3Instruction::Halt,
    ]))
    .expect("operation should succeed for valid inputs");

    // Should return first character 'A'
    // SAFETY: the executed module writes its result to register 1.
    let result = core
        .read_register(1)
        .expect("operation should succeed for valid inputs");
    assert_eq!(result, Value::str("A"), "No index should default to 0");
}

#[test]
fn string_prototype_char_at_type_coercion() {
    // Test charAt with non-string values (should coerce to string)
    let mut core = InterpreterCore::new(test_quickjs_config(), "test");
    core.set_register(0, Value::Int(456))
        .expect("operation should succeed for valid inputs"); // should become "456"
    core.set_register(1, Value::Int(2))
        .expect("operation should succeed for valid inputs"); // index 2

    core.execute_module(&test_module(vec![
        Ir3Instruction::HostCall {
            capability: CapabilityTag("builtin:StringPrototypeCharAt".to_string()),
            args: RegRange { start: 0, count: 2 },
            dst: 2,
        },
        Ir3Instruction::Halt,
    ]))
    .expect("operation should succeed for valid inputs");

    // "456"[2] = '6'
    let result = core
        .read_register(2)
        .expect("operation should succeed for valid inputs");
    assert_eq!(
        result,
        Value::str("6"),
        "charAt on number should coerce to string"
    );
}

#[test]
fn bitwise_to_int32_wraps_floats_past_2_pow_31() {
    // Rust's `f64 as i32` saturates; JS `ToInt32` wraps modulo 2^32. A
    // float operand whose magnitude exceeds 2^31 must wrap, not collapse
    // to i32::MAX.
    let mut core = InterpreterCore::new(test_quickjs_config(), "test");

    // (3000000000.5) | 0 == -1294967296 (was 2147483647 when saturating).
    core.set_register(0, Value::Float(Float64::new(3_000_000_000.5)))
        .expect("set reg 0");
    core.set_register(1, Value::Int(0)).expect("set reg 1");
    assert_eq!(
        core.eval_bitwise(0, 1, "|").expect("bitwise or"),
        Value::Int(-1_294_967_296)
    );

    // (5000000000.7) >> 0 == 705032704.
    core.set_register(0, Value::Float(Float64::new(5_000_000_000.7)))
        .expect("set reg 0");
    core.set_register(1, Value::Int(0)).expect("set reg 1");
    assert_eq!(
        core.eval_bitwise(0, 1, ">>").expect("shift right"),
        Value::Int(705_032_704)
    );

    // ~(3000000000.5) == 1294967295 (was -2147483648 when saturating).
    core.set_register(0, Value::Float(Float64::new(3_000_000_000.5)))
        .expect("set reg 0");
    assert_eq!(
        core.eval_bit_not(0).expect("bit not"),
        Value::Int(1_294_967_295)
    );

    // In-range floats are unaffected: (5.9 | 0) == 5.
    core.set_register(0, Value::Float(Float64::new(5.9)))
        .expect("set reg 0");
    core.set_register(1, Value::Int(0)).expect("set reg 1");
    assert_eq!(
        core.eval_bitwise(0, 1, "|").expect("bitwise or"),
        Value::Int(5)
    );
}

#[test]
fn math_round_just_below_half_rounds_to_zero() {
    // `floor(x + 0.5)` returns 1 for 0.49999999999999994 because the sum
    // rounds up to exactly 1.0; the correct Math.round is 0.
    let mut core = InterpreterCore::new(test_quickjs_config(), "test");
    core.set_register(0, Value::Float(Float64::new(0.499_999_999_999_999_94)))
        .expect("set reg 0");
    core.execute_module(&test_module(vec![
        Ir3Instruction::HostCall {
            capability: CapabilityTag("builtin:MathRound".to_string()),
            args: RegRange { start: 0, count: 1 },
            dst: 1,
        },
        Ir3Instruction::Halt,
    ]))
    .expect("execute module");
    let result = core.read_register(1).expect("read result");
    match result {
        Value::Int(0) => {}
        Value::Float(f) => assert_eq!(f.inner(), 0.0, "should be 0, got {result:?}"),
        _ => panic!("Math.round(0.49999999999999994) should be 0, got {result:?}"),
    }
}

#[test]
fn math_round_negative_half_semantics() {
    // Test JavaScript Math.round negative half semantics
    // JavaScript uses floor(x + 0.5), not Rust's round away from zero
    let mut core = InterpreterCore::new(test_quickjs_config(), "test");

    // Test -0.5 → -0 (not -1)
    core.set_register(0, Value::Float(Float64::new(-0.5)))
        .expect("operation should succeed for valid inputs");
    core.execute_module(&test_module(vec![
        Ir3Instruction::HostCall {
            capability: CapabilityTag("builtin:MathRound".to_string()),
            args: RegRange { start: 0, count: 1 },
            dst: 1,
        },
        Ir3Instruction::Halt,
    ]))
    .expect("operation should succeed for valid inputs");

    let result = core
        .read_register(1)
        .expect("operation should succeed for valid inputs");
    match result {
        Value::Float(f) => {
            let val = f.inner();
            assert!(
                val == -0.0 || val == 0.0,
                "Math.round(-0.5) should be -0, got {}",
                val
            );
        }
        Value::Int(0) => {} // Also acceptable
        _ => panic!("Math.round(-0.5) should be -0, got {:?}", result),
    }

    // Test -1.5 → -1 (not -2) (fresh core: execute() restores the initial seed).
    let mut core = InterpreterCore::new(test_quickjs_config(), "test");
    core.set_register(0, Value::Float(Float64::new(-1.5)))
        .expect("operation should succeed for valid inputs");
    core.execute_module(&test_module(vec![
        Ir3Instruction::HostCall {
            capability: CapabilityTag("builtin:MathRound".to_string()),
            args: RegRange { start: 0, count: 1 },
            dst: 1,
        },
        Ir3Instruction::Halt,
    ]))
    .expect("operation should succeed for valid inputs");

    let result = core
        .read_register(1)
        .expect("operation should succeed for valid inputs");
    assert_eq!(
        result,
        Value::Int(-1),
        "Math.round(-1.5) should be -1, got {:?}",
        result
    );
}

#[test]
fn math_round_edge_cases() {
    let mut core = InterpreterCore::new(test_quickjs_config(), "test");

    // Test -0.1 → -0
    core.set_register(0, Value::Float(Float64::new(-0.1)))
        .expect("operation should succeed for valid inputs");
    core.execute_module(&test_module(vec![
        Ir3Instruction::HostCall {
            capability: CapabilityTag("builtin:MathRound".to_string()),
            args: RegRange { start: 0, count: 1 },
            dst: 1,
        },
        Ir3Instruction::Halt,
    ]))
    .expect("operation should succeed for valid inputs");

    let result = core
        .read_register(1)
        .expect("operation should succeed for valid inputs");
    match result {
        Value::Float(f) => {
            let val = f.inner();
            assert!(
                val == -0.0 || val == 0.0,
                "Math.round(-0.1) should be -0, got {}",
                val
            );
        }
        Value::Int(0) => {} // Also acceptable
        _ => panic!("Math.round(-0.1) should be -0, got {:?}", result),
    }

    // Test +0.5 → 1 (fresh core: execute() restores the initial seed).
    let mut core = InterpreterCore::new(test_quickjs_config(), "test");
    core.set_register(0, Value::Float(Float64::new(0.5)))
        .expect("operation should succeed for valid inputs");
    core.execute_module(&test_module(vec![
        Ir3Instruction::HostCall {
            capability: CapabilityTag("builtin:MathRound".to_string()),
            args: RegRange { start: 0, count: 1 },
            dst: 1,
        },
        Ir3Instruction::Halt,
    ]))
    .expect("operation should succeed for valid inputs");

    let result = core
        .read_register(1)
        .expect("operation should succeed for valid inputs");
    assert_eq!(
        result,
        Value::Int(1),
        "Math.round(0.5) should be 1, got {:?}",
        result
    );

    // Test NaN → NaN (fresh core).
    let mut core = InterpreterCore::new(test_quickjs_config(), "test");
    core.set_register(0, Value::Float(Float64::new(f64::NAN)))
        .expect("operation should succeed for valid inputs");
    core.execute_module(&test_module(vec![
        Ir3Instruction::HostCall {
            capability: CapabilityTag("builtin:MathRound".to_string()),
            args: RegRange { start: 0, count: 1 },
            dst: 1,
        },
        Ir3Instruction::Halt,
    ]))
    .expect("operation should succeed for valid inputs");

    let result = core
        .read_register(1)
        .expect("operation should succeed for valid inputs");
    match result {
        Value::Float(f) => assert!(f.inner().is_nan(), "Math.round(NaN) should be NaN"),
        _ => panic!("Math.round(NaN) should be NaN, got {:?}", result),
    }

    // Test +Infinity → +Infinity
    let mut core = InterpreterCore::new(test_quickjs_config(), "test");
    core.set_register(0, Value::Float(Float64::new(f64::INFINITY)))
        .expect("operation should succeed for valid inputs");
    core.execute_module(&test_module(vec![
        Ir3Instruction::HostCall {
            capability: CapabilityTag("builtin:MathRound".to_string()),
            args: RegRange { start: 0, count: 1 },
            dst: 1,
        },
        Ir3Instruction::Halt,
    ]))
    .expect("operation should succeed for valid inputs");

    let result = core
        .read_register(1)
        .expect("operation should succeed for valid inputs");
    match result {
        Value::Float(f) => assert_eq!(
            f.inner(),
            f64::INFINITY,
            "Math.round(+Infinity) should be +Infinity"
        ),
        _ => panic!(
            "Math.round(+Infinity) should be +Infinity, got {:?}",
            result
        ),
    }

    // Test -Infinity → -Infinity. Use a fresh core: reusing the +Infinity
    // core would let the seed-tracked re-execution restore reg0 to the prior
    // (+Infinity) seed and clobber this input before Math.round reads it.
    let mut core = InterpreterCore::new(test_quickjs_config(), "test");
    core.set_register(0, Value::Float(Float64::new(f64::NEG_INFINITY)))
        .expect("operation should succeed for valid inputs");
    core.execute_module(&test_module(vec![
        Ir3Instruction::HostCall {
            capability: CapabilityTag("builtin:MathRound".to_string()),
            args: RegRange { start: 0, count: 1 },
            dst: 1,
        },
        Ir3Instruction::Halt,
    ]))
    .expect("operation should succeed for valid inputs");

    let result = core
        .read_register(1)
        .expect("operation should succeed for valid inputs");
    match result {
        Value::Float(f) => assert_eq!(
            f.inner(),
            f64::NEG_INFINITY,
            "Math.round(-Infinity) should be -Infinity"
        ),
        _ => panic!(
            "Math.round(-Infinity) should be -Infinity, got {:?}",
            result
        ),
    }
}

#[test]
fn console_builtin_id_deduplication_audit_fix() {
    // Regression test for bd-7f1a4: Verify duplicate console builtin IDs are removed
    // and only correct mappings remain after audit fix

    let core = InterpreterCore::new(test_quickjs_config(), "test-trace");

    // Verify correct console builtin IDs (100-102) are mapped
    assert_eq!(
        core.map_function_index_to_builtin_capability(100),
        Some("builtin:ConsoleLog".to_string()),
        "ID 100 should map to ConsoleLog"
    );
    assert_eq!(
        core.map_function_index_to_builtin_capability(101),
        Some("builtin:ConsoleError".to_string()),
        "ID 101 should map to ConsoleError"
    );
    assert_eq!(
        core.map_function_index_to_builtin_capability(102),
        Some("builtin:ConsoleWarn".to_string()),
        "ID 102 should map to ConsoleWarn"
    );

    // Verify ConsoleInfo (ID 384) is mapped
    assert_eq!(
        core.map_function_index_to_builtin_capability(384),
        Some("builtin:ConsoleInfo".to_string()),
        "ID 384 should map to ConsoleInfo"
    );

    // Verify duplicate IDs (381-383) are NOT mapped after audit fix
    assert_eq!(
        core.map_function_index_to_builtin_capability(381),
        None,
        "ID 381 should NOT be mapped (duplicate ConsoleLog removed)"
    );
    assert_eq!(
        core.map_function_index_to_builtin_capability(382),
        None,
        "ID 382 should NOT be mapped (duplicate ConsoleError removed)"
    );
    assert_eq!(
        core.map_function_index_to_builtin_capability(383),
        None,
        "ID 383 should NOT be mapped (duplicate ConsoleWarn removed)"
    );
}

#[test]
fn console_builtin_captured_output_all_levels() {
    // Comprehensive test that all console levels capture output correctly
    // with proper level/message/instruction metadata as required by audit

    let mut core = InterpreterCore::new(test_quickjs_config(), "test-trace");

    // Test ConsoleLog (ID 100)
    core.set_reg(0, Value::str("Log message"));
    let result = core
        .execute(&test_module(vec![
            Ir3Instruction::HostCall {
                capability: CapabilityTag("builtin:ConsoleLog".to_string()),
                args: RegRange { start: 0, count: 1 },
                dst: 10,
            },
            Ir3Instruction::Halt,
        ]))
        .expect("operation should succeed for valid inputs");

    assert_eq!(result.console_output.len(), 1);
    assert_eq!(result.console_output[0].level, ConsoleLevel::Log);
    assert_eq!(result.console_output[0].message, "Log message");
    assert_eq!(result.console_output[0].instruction_index, 1);

    // Test ConsoleError (ID 101)
    // Fresh core per level (execute() restores the initial register seed).
    let mut core = InterpreterCore::new(test_quickjs_config(), "test-trace");
    core.set_reg(0, Value::str("Error message"));
    // SAFETY: the console-error regression module is well-formed and should execute.
    let result = core
        .execute(&test_module(vec![
            Ir3Instruction::HostCall {
                capability: CapabilityTag("builtin:ConsoleError".to_string()),
                args: RegRange { start: 0, count: 1 },
                dst: 10,
            },
            Ir3Instruction::Halt,
        ]))
        .expect("operation should succeed for valid inputs");

    assert_eq!(result.console_output.len(), 1);
    assert_eq!(result.console_output[0].level, ConsoleLevel::Error);
    assert_eq!(result.console_output[0].message, "Error message");

    // Test ConsoleWarn (ID 102)
    let mut core = InterpreterCore::new(test_quickjs_config(), "test-trace");
    core.set_reg(0, Value::str("Warn message"));
    // SAFETY: the console-warn regression module is well-formed and should execute.
    let result = core
        .execute(&test_module(vec![
            Ir3Instruction::HostCall {
                capability: CapabilityTag("builtin:ConsoleWarn".to_string()),
                args: RegRange { start: 0, count: 1 },
                dst: 10,
            },
            Ir3Instruction::Halt,
        ]))
        .expect("operation should succeed for valid inputs");

    assert_eq!(result.console_output.len(), 1);
    assert_eq!(result.console_output[0].level, ConsoleLevel::Warn);
    assert_eq!(result.console_output[0].message, "Warn message");

    // Test ConsoleInfo (ID 384) - the critical one from audit
    let mut core = InterpreterCore::new(test_quickjs_config(), "test-trace");
    core.set_reg(0, Value::str("Info message"));
    // SAFETY: the console-info regression module is well-formed and should execute.
    let result = core
        .execute(&test_module(vec![
            Ir3Instruction::HostCall {
                capability: CapabilityTag("builtin:ConsoleInfo".to_string()),
                args: RegRange { start: 0, count: 1 },
                dst: 10,
            },
            Ir3Instruction::Halt,
        ]))
        .expect("operation should succeed for valid inputs");

    assert_eq!(result.console_output.len(), 1);
    assert_eq!(result.console_output[0].level, ConsoleLevel::Info);
    assert_eq!(result.console_output[0].message, "Info message");

    // Verify ConsoleInfo no longer silently drops output as mentioned in audit
    assert!(
        !result.console_output[0].message.is_empty(),
        "ConsoleInfo should capture output, not silently drop it"
    );
}

#[test]
fn console_output_zero_limit_drops_every_level_without_panicking() {
    let mut config = test_quickjs_config();
    config.max_console_entries = 0;
    let mut core = InterpreterCore::new(config, "test-trace");

    for builtin_id in [100, 101, 102, 384] {
        core.mutate_registers(|r| {
            r[0] = Value::str(format!("message-{builtin_id}"));
        });
        let builtin = core
            .map_function_index_to_builtin_capability(builtin_id)
            .expect("console builtin id should be mapped");
        let result = core
            .dispatch_builtin_hostcall(&builtin, RegRange { start: 0, count: 1 }, None)
            .expect("console builtin should return normally with zero output cap");

        assert_eq!(result, Value::Undefined);
        assert!(
            core.console_output.is_empty(),
            "console builtin id {builtin_id} must not retain output at zero cap"
        );
    }

    for cap in [
        "console:log",
        "console:error",
        "console:warn",
        "console:info",
    ] {
        core.set_reg(0, Value::str(cap));
        let result = core
            .dispatch_console_hostcall(cap, RegRange { start: 0, count: 1 }, None)
            .expect("console hostcall should return normally with zero output cap");

        assert_eq!(result, Value::Undefined);
        assert!(
            core.console_output.is_empty(),
            "console hostcall {cap} must not retain output at zero cap"
        );
    }
}

#[test]
fn string_prototype_split_builtin_id_deduplication_audit_fix() {
    // Regression test for bd-5wpm4 StringPrototypeSplit deduplication audit
    // Verifies that ID 36 is the primary mapping, and ID 356 was correctly removed
    let interpreter = InterpreterCore::new(test_quickjs_config(), "test");

    // Verify ID 36 maps to StringPrototypeSplit
    assert_eq!(
        interpreter.builtin_name_from_id(36),
        Some("builtin:StringPrototypeSplit".to_string())
    );

    // Verify ID 356 no longer maps to StringPrototypeSplit (duplicate removed)
    assert_ne!(
        interpreter.builtin_name_from_id(356),
        Some("builtin:StringPrototypeSplit".to_string())
    );

    // Verify ID 357 still works (ArrayPrototypeMap should be unaffected)
    assert_eq!(
        interpreter.builtin_name_from_id(357),
        Some("builtin:ArrayPrototypeMap".to_string())
    );
}

#[test]
fn string_prototype_split_execution_works() {
    // Verify StringPrototypeSplit builtin is functional after deduplication
    let mut core = InterpreterCore::new(test_quickjs_config(), "test");

    // Test string split functionality
    core.set_reg(0, Value::str("hello,world,test"));
    core.set_reg(1, Value::str(","));

    let result = core.execute(&test_module(vec![
        Ir3Instruction::HostCall {
            capability: CapabilityTag("builtin:StringPrototypeSplit".to_string()),
            args: RegRange { start: 0, count: 2 },
            dst: 10,
        },
        Ir3Instruction::Halt,
    ]));

    // Verify the call succeeded (should not panic or error)
    assert!(
        result.is_ok(),
        "StringPrototypeSplit builtin should work after deduplication"
    );
}

#[test]
fn batch_27_deduplication_regression_test() {
    // Regression test for bd-3n6hg batch-27 Array.reverse and Object.toString deduplication
    // Verifies that duplicate dispatch arms were removed and only first occurrences remain
    let interpreter = InterpreterCore::new(test_quickjs_config(), "test");

    // Test ArrayPrototypeReverse builtin IDs still work
    assert_eq!(
        interpreter.builtin_name_from_id(21),
        Some("builtin:ArrayPrototypeReverse".to_string())
    );
    assert_eq!(
        interpreter.builtin_name_from_id(243),
        Some("builtin:ArrayPrototypeReverse".to_string())
    );
    assert_eq!(
        interpreter.builtin_name_from_id(329),
        Some("builtin:ArrayPrototypeReverse".to_string())
    );

    // Test ObjectPrototypeToString builtin IDs still work
    assert_eq!(
        interpreter.builtin_name_from_id(264),
        Some("builtin:ObjectPrototypeToString".to_string())
    );
    assert_eq!(
        interpreter.builtin_name_from_id(332),
        Some("builtin:ObjectPrototypeToString".to_string())
    );
}

#[test]
fn array_reverse_functionality_after_dedup() {
    // Verify ArrayPrototypeReverse functionality preserved after removing duplicates
    let mut core = InterpreterCore::new(test_quickjs_config(), "test");

    // Create an array object with elements
    let array_id = ObjectId(10);
    core.set_heap_object_at(
        array_id.0 as usize,
        Object {
            properties: OrderedStringMap::from(BTreeMap::from([
                ("length".to_string(), Value::Int(3)),
                ("0".to_string(), Value::str("first")),
                ("1".to_string(), Value::str("second")),
                ("2".to_string(), Value::str("third")),
            ])),
            ..Default::default()
        },
    );
    core.set_reg(0, Value::Object(array_id));

    let result = core.execute(&test_module(vec![
        Ir3Instruction::HostCall {
            capability: CapabilityTag("builtin:ArrayPrototypeReverse".to_string()),
            args: RegRange { start: 0, count: 1 },
            dst: 10,
        },
        Ir3Instruction::Halt,
    ]));

    // Verify the call succeeded
    assert!(
        result.is_ok(),
        "ArrayPrototypeReverse should work after deduplication"
    );

    // Verify the array was modified (elements should be reversed)
    let obj = core
        .heap
        .get(array_id.0 as usize)
        .expect("operation should succeed for valid inputs");
    if let Some(Value::Str(first)) = obj.properties.get("0") {
        assert_eq!(
            first.as_ref(),
            "third",
            "Array should be reversed after calling reverse()"
        );
    }
}

#[test]
fn object_tostring_functionality_after_dedup() {
    // Verify ObjectPrototypeToString functionality preserved after removing duplicates
    let mut core = InterpreterCore::new(test_quickjs_config(), "test");

    // Dispatch the builtin directly rather than via `execute()`: the tested
    // receivers include heap objects allocated on this core, and the
    // seed-tracked `execute()` would restore the initial register/heap seed
    // between repeated calls. `dispatch_builtin_hostcall` reads the receiver
    // from r0 and returns the tag string without touching the seed.
    let run_to_string = |core: &mut InterpreterCore, value: Value, expected: &str| {
        core.set_reg(0, value);
        let result = core
            .dispatch_builtin_hostcall(
                "builtin:ObjectPrototypeToString",
                RegRange { start: 0, count: 1 },
                None,
            )
            .expect("ObjectPrototypeToString should run successfully");
        assert_eq!(result, Value::str(expected));
    };

    run_to_string(&mut core, Value::Undefined, "[object Undefined]");
    run_to_string(&mut core, Value::Null, "[object Null]");
    run_to_string(&mut core, Value::Bool(false), "[object Boolean]");
    run_to_string(&mut core, Value::Int(7), "[object Number]");
    run_to_string(
        &mut core,
        Value::Float(Float64::new(1.5)),
        "[object Number]",
    );
    run_to_string(&mut core, Value::str("test"), "[object String]");

    // Array-like object with length property should not be treated as an array.
    let object_id = core
        .alloc_object_with_prototype(None)
        .expect("operation should succeed for valid inputs");
    core.set_object_property(object_id, "length".to_string(), Value::Int(1))
        .expect("operation should succeed for valid inputs");
    core.set_object_property(object_id, "0".to_string(), Value::Int(99))
        .expect("operation should succeed for valid inputs");
    run_to_string(&mut core, Value::Object(object_id), "[object Object]");

    // Arrays should still return the array tag.
    let array_id = core
        .alloc_array_from_values(&[Value::str("x")])
        .expect("operation should succeed for valid inputs");
    run_to_string(&mut core, Value::Object(array_id), "[object Array]");

    // Runtime callable and object-like tags.
    run_to_string(&mut core, Value::Function(1), "[object Function]");
    run_to_string(&mut core, Value::Closure(2), "[object Function]");
    run_to_string(
        &mut core,
        Value::BuiltinFunction(BuiltinFunction::require("console")),
        "[object Function]",
    );
    // An iterator's @@toStringTag is %ArrayIteratorPrototype%'s.
    run_to_string(&mut core, Value::Iterator(3), "[object Array Iterator]");
    run_to_string(
        &mut core,
        Value::GeneratorFunction(4),
        "[object GeneratorFunction]",
    );
    run_to_string(&mut core, Value::Generator(5), "[object Generator]");
    run_to_string(&mut core, Value::AsyncFunction(6), "[object AsyncFunction]");
    run_to_string(
        &mut core,
        Value::AsyncFunctionObject(7),
        "[object AsyncFunction]",
    );
    run_to_string(
        &mut core,
        Value::AsyncGeneratorFunction(8),
        "[object AsyncGeneratorFunction]",
    );
    run_to_string(
        &mut core,
        Value::AsyncGeneratorObject(9),
        "[object AsyncGenerator]",
    );
    run_to_string(&mut core, Value::Promise(10), "[object Promise]");
}

#[test]
fn array_constructors_preserve_array_object_tag_metadata() {
    let mut core = InterpreterCore::new(test_quickjs_config(), "test");

    let object_tag = |core: &mut InterpreterCore, value: Value| {
        core.set_reg(12, value);
        core.dispatch_builtin_hostcall(
            "builtin:ObjectPrototypeToString",
            RegRange {
                start: 12,
                count: 1,
            },
            None,
        )
        .expect("ObjectPrototypeToString should run successfully")
    };

    core.set_reg(0, Value::Int(1));
    core.set_reg(1, Value::Int(2));
    let array_of = core
        .dispatch_builtin_hostcall("builtin:ArrayOf", RegRange { start: 0, count: 2 }, None)
        .expect("Array.of should produce a value");
    assert_eq!(
        object_tag(&mut core, array_of),
        Value::str("[object Array]")
    );

    let array_like_id = core
        .alloc_object_with_prototype(None)
        .expect("array-like source should allocate");
    core.set_object_property(array_like_id, "0".to_string(), Value::str("x"))
        .expect("array-like source should accept index 0");
    core.set_object_property(array_like_id, "length".to_string(), Value::Int(1))
        .expect("array-like source should accept length");
    core.set_reg(0, Value::Object(array_like_id));
    let array_from = core
        .dispatch_builtin_hostcall("builtin:ArrayFrom", RegRange { start: 0, count: 1 }, None)
        .expect("Array.from should produce a value");
    assert_eq!(
        object_tag(&mut core, array_from),
        Value::str("[object Array]")
    );

    // ES2024 Array.fromAsync returns a promise of the array (here rejected:
    // `undefined` has no iterator and is not array-like); the old stub
    // returned the array itself (bd-9vouw.172).
    let array_from_async = core
        .dispatch_builtin_hostcall(
            "builtin:ArrayFromAsync",
            RegRange { start: 0, count: 0 },
            None,
        )
        .expect("Array.fromAsync should produce a value");
    assert_eq!(
        object_tag(&mut core, array_from_async),
        Value::str("[object Promise]")
    );
}

#[test]
fn array_producing_builtins_preserve_array_object_tag_metadata() {
    let mut core = quickjs_test_core();

    fn object_tag(core: &mut InterpreterCore, value: Value) -> Value {
        core.set_reg(12, value);
        core.dispatch_builtin_hostcall(
            "builtin:ObjectPrototypeToString",
            RegRange {
                start: 12,
                count: 1,
            },
            None,
        )
        .expect("ObjectPrototypeToString should run successfully")
    }

    fn assert_array_tag(core: &mut InterpreterCore, value: Value) {
        assert_eq!(object_tag(core, value), Value::str("[object Array]"));
    }

    let source_array = core
        .alloc_array_from_values(&[Value::Int(1), Value::Int(2), Value::Int(3)])
        .expect("source array should allocate");
    core.set_reg(0, Value::Object(source_array));
    core.set_reg(1, Value::Int(1));
    core.set_reg(2, Value::Int(3));
    let slice_result = core
        .dispatch_builtin_hostcall(
            "builtin:ArrayPrototypeSlice",
            RegRange { start: 0, count: 3 },
            None,
        )
        .expect("Array.prototype.slice should return a value");
    assert_array_tag(&mut core, slice_result);

    let object_id = core
        .alloc_object_with_prototype(None)
        .expect("source object should allocate");
    core.set_object_property(object_id, "a".to_string(), Value::Int(10))
        .expect("source object should accept property a");
    core.set_object_property(object_id, "b".to_string(), Value::Int(20))
        .expect("source object should accept property b");
    core.set_reg(0, Value::Object(object_id));

    let keys_result = core
        .dispatch_builtin_hostcall("builtin:ObjectKeys", RegRange { start: 0, count: 1 }, None)
        .expect("Object.keys should return a value");
    assert_array_tag(&mut core, keys_result);

    core.set_reg(0, Value::Object(object_id));
    let values_result = core
        .dispatch_builtin_hostcall(
            "builtin:ObjectValues",
            RegRange { start: 0, count: 1 },
            None,
        )
        .expect("Object.values should return a value");
    assert_array_tag(&mut core, values_result);

    core.set_reg(0, Value::Object(object_id));
    let entries_result = core
        .dispatch_builtin_hostcall(
            "builtin:ObjectEntries",
            RegRange { start: 0, count: 1 },
            None,
        )
        .expect("Object.entries should return a value");
    assert_array_tag(&mut core, entries_result.clone());

    let Value::Object(entries_id) = entries_result else {
        panic!("Object.entries should return an object value");
    };
    let first_entry = core.heap[entries_id.0 as usize]
        .properties
        .get("0")
        .cloned()
        .expect("Object.entries should produce a first entry");
    assert_array_tag(&mut core, first_entry);
}

#[test]
fn baseline_data_property_consumers_use_es_own_key_order() {
    let mut core = quickjs_test_core();
    let object_id = core
        .alloc_object_with_prototype(None)
        .expect("source object should allocate");
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
            .expect("data property should be accepted");
    }
    core.set_object_property(object_id, "b".to_string(), Value::Int(8))
        .expect("updating a property should retain its position");
    assert!(
        core.remove_object_property(object_id, "b")
            .expect("property removal should succeed")
    );
    core.set_object_property(object_id, "b".to_string(), Value::Int(8))
        .expect("re-adding a property should append it");

    let expected_keys = vec![
        "0".to_string(),
        "2".to_string(),
        "10".to_string(),
        "4294967294".to_string(),
        "01".to_string(),
        "4294967295".to_string(),
        "a".to_string(),
        "b".to_string(),
    ];
    assert_eq!(
        core.ordinary_own_property_key_values(object_id).unwrap(),
        expected_keys
            .iter()
            .map(|key| Value::str(key.as_str()))
            .collect::<Vec<_>>()
    );

    core.set_reg(0, Value::Object(object_id));
    let keys = core
        .dispatch_builtin_hostcall("builtin:ObjectKeys", RegRange { start: 0, count: 1 }, None)
        .expect("Object.keys should succeed");
    let Value::Object(keys_id) = keys else {
        panic!("Object.keys should return an array");
    };
    assert_eq!(
        core.read_array_like_values(keys_id),
        expected_keys
            .iter()
            .map(|key| Value::str(key.as_str()))
            .collect::<Vec<_>>()
    );

    core.set_reg(0, Value::Object(object_id));
    let values = core
        .dispatch_builtin_hostcall(
            "builtin:ObjectValues",
            RegRange { start: 0, count: 1 },
            None,
        )
        .expect("Object.values should succeed");
    let Value::Object(values_id) = values else {
        panic!("Object.values should return an array");
    };
    assert_eq!(
        core.read_array_like_values(values_id),
        vec![
            Value::Int(6),
            Value::Int(3),
            Value::Int(2),
            Value::Int(9),
            Value::Int(4),
            Value::Int(5),
            Value::Int(7),
            Value::Int(8),
        ]
    );

    core.set_reg(0, Value::Object(object_id));
    let entries = core
        .dispatch_builtin_hostcall(
            "builtin:ObjectEntries",
            RegRange { start: 0, count: 1 },
            None,
        )
        .expect("Object.entries should succeed");
    let Value::Object(entries_id) = entries else {
        panic!("Object.entries should return an array");
    };
    let entry_keys = core
        .read_array_like_values(entries_id)
        .into_iter()
        .map(|entry| {
            let Value::Object(entry_id) = entry else {
                panic!("Object.entries member should be a pair array");
            };
            core.read_array_like_values(entry_id)
                .into_iter()
                .next()
                .expect("entry pair should contain a key")
        })
        .collect::<Vec<_>>();
    assert_eq!(
        entry_keys,
        expected_keys
            .iter()
            .map(|key| Value::str(key.as_str()))
            .collect::<Vec<_>>()
    );

    core.set_reg(0, Value::Object(object_id));
    let reflected = core
        .dispatch_builtin_hostcall(
            "builtin:ReflectOwnKeys",
            RegRange { start: 0, count: 1 },
            None,
        )
        .expect("Reflect.ownKeys should succeed");
    let Value::Object(reflected_id) = reflected else {
        panic!("Reflect.ownKeys should return an array");
    };
    assert_eq!(
        core.read_array_like_values(reflected_id),
        expected_keys
            .iter()
            .map(|key| Value::str(key.as_str()))
            .collect::<Vec<_>>()
    );

    let assigned_id = core
        .alloc_object_with_prototype(None)
        .expect("Object.assign target should allocate");
    core.set_reg(0, Value::Object(assigned_id));
    core.set_reg(1, Value::Object(object_id));
    assert_eq!(
        core.dispatch_builtin_hostcall(
            "builtin:ObjectAssign",
            RegRange { start: 0, count: 2 },
            None,
        )
        .expect("Object.assign should succeed"),
        Value::Object(assigned_id)
    );
    assert_eq!(
        core.heap[assigned_id.0 as usize]
            .properties
            .keys()
            .cloned()
            .collect::<Vec<_>>(),
        expected_keys
    );

    assert_eq!(
        core.collect_for_in_keys(None, object_id).unwrap(),
        expected_keys
            .iter()
            .map(|key| JsString::from(key.as_str()))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        core.qs_stringify_object(object_id, "&", "=").unwrap(),
        "0=6&2=3&10=2&4294967294=9&01=4&4294967295=5&a=7&b=8"
    );
    assert_eq!(
        core.json_stringify_value(None, &Value::Object(object_id), &mut Vec::new())
            .unwrap(),
        Some(
            r#"{"0":6,"2":3,"10":2,"4294967294":9,"01":4,"4294967295":5,"a":7,"b":8}"#.to_string()
        )
    );
}

#[test]
fn exact_string_key_consumers_preserve_identity_bd_b12xs_6() {
    let mut core = quickjs_test_core();
    let object = core
        .alloc_object_with_prototype(None)
        .expect("exact-key source should allocate");
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
        .expect("exact property should fit");
    }

    assert_eq!(
        core.collect_for_in_keys(None, object).unwrap(),
        expected_keys
    );
    assert_eq!(
        core.ordinary_own_property_key_values(object).unwrap(),
        expected_keys
            .iter()
            .cloned()
            .map(Value::Str)
            .collect::<Vec<_>>()
    );

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
        .init_for_in_iterator(None, Value::Object(iteration_object))
        .unwrap();
    assert_eq!(
        core.advance_for_in_iterator(iterator.clone()).unwrap(),
        Some(Value::Str(d800.clone()))
    );
    assert!(core.iteration_traces.last().is_some_and(|trace| {
        trace.events.iter().any(|event| {
            matches!(
                &event.operation,
                IterationOperation::IteratorNext { result }
                    if result.value == IteratorValue::String("~pk~x:D800".to_string())
            )
        })
    }));
    core.set_reg(20, Value::Object(iteration_object));
    core.set_reg(21, Value::Str(d801.clone()));
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

    core.set_reg(0, Value::Object(object));
    for builtin in [
        "builtin:ObjectKeys",
        "builtin:ObjectGetOwnPropertyNames",
        "builtin:ReflectOwnKeys",
    ] {
        let keys = core
            .dispatch_builtin_hostcall(builtin, RegRange { start: 0, count: 1 }, None)
            .expect("exact key reflection should succeed");
        let Value::Object(keys) = keys else {
            panic!("{builtin} must return an array");
        };
        assert_eq!(
            core.read_array_like_values(keys),
            expected_keys
                .iter()
                .cloned()
                .map(Value::Str)
                .collect::<Vec<_>>()
        );
    }

    let handler = core.alloc_object_with_prototype(None).unwrap();
    core.set_reg(0, Value::Object(object));
    core.set_reg(1, Value::Object(handler));
    let proxy = core
        .dispatch_builtin_hostcall("builtin:Proxy", RegRange { start: 0, count: 2 }, None)
        .unwrap();
    let Value::Object(proxy) = proxy else {
        panic!("Proxy constructor must return an object");
    };
    core.set_reg(0, Value::Object(proxy));
    core.set_reg(1, Value::Str(d800.clone()));
    assert_eq!(
            core.dispatch_builtin_hostcall(
                "builtin:ReflectGet",
                RegRange { start: 0, count: 2 },
                None,
            )
            .unwrap(),
            Value::Int(8)
        );
    let proxy_keys = core
        .dispatch_builtin_hostcall(
            "builtin:ReflectOwnKeys",
            RegRange { start: 0, count: 1 },
            None,
        )
        .unwrap();
    let Value::Object(proxy_keys) = proxy_keys else {
        panic!("Proxy ordinary ownKeys fallback must return an array");
    };
    assert_eq!(
        core.read_array_like_values(proxy_keys),
        expected_keys
            .iter()
            .cloned()
            .map(Value::Str)
            .collect::<Vec<_>>()
    );

    core.set_reg(0, Value::Object(object));
    let values = core
        .dispatch_builtin_hostcall(
            "builtin:ObjectValues",
            RegRange { start: 0, count: 1 },
            None,
        )
        .expect("Object.values should preserve exact-key values");
    let Value::Object(values) = values else {
        panic!("Object.values must return an array");
    };
    assert_eq!(
        core.read_array_like_values(values),
        vec![Value::Int(8), Value::Int(9), Value::Int(10)]
    );

    let entries = core
        .dispatch_builtin_hostcall(
            "builtin:ObjectEntries",
            RegRange { start: 0, count: 1 },
            None,
        )
        .expect("Object.entries should preserve exact keys");
    let Value::Object(entries) = entries else {
        panic!("Object.entries must return an array");
    };
    let entries = core
        .read_array_like_values(entries)
        .into_iter()
        .map(|entry| {
            let Value::Object(entry) = entry else {
                panic!("Object.entries member must be a pair array");
            };
            core.read_array_like_values(entry)
        })
        .collect::<Vec<_>>();
    assert_eq!(
        entries,
        vec![
            vec![Value::Str(d800.clone()), Value::Int(8)],
            vec![Value::Str(d801.clone()), Value::Int(9)],
            vec![Value::Str(replacement.clone()), Value::Int(10)],
        ]
    );

    core.set_reg(0, Value::Object(object));
    core.set_reg(1, Value::Str(d800.clone()));
    assert_eq!(
            core.dispatch_builtin_hostcall(
                "builtin:ReflectGet",
                RegRange { start: 0, count: 2 },
                None,
            )
            .unwrap(),
            Value::Int(8)
        );
    assert_eq!(
            core.dispatch_builtin_hostcall(
                "builtin:ReflectHas",
                RegRange { start: 0, count: 2 },
                None,
            )
            .unwrap(),
            Value::Bool(true)
        );
    assert_eq!(
        core.dispatch_builtin_hostcall(
            "builtin:ObjectHasOwnProperty",
            RegRange { start: 0, count: 2 },
            None,
        )
        .unwrap(),
        Value::Bool(true)
    );

    core.set_reg(1, Value::Str(d801.clone()));
    core.set_reg(2, Value::Int(19));
    assert_eq!(
            core.dispatch_builtin_hostcall(
                "builtin:ReflectSet",
                RegRange { start: 0, count: 3 },
                None,
            )
            .unwrap(),
            Value::Bool(true)
        );
    assert_eq!(
        core.heap[object.0 as usize].properties.get_exact(&d801),
        Some(&Value::Int(19))
    );
    assert_eq!(
        core.dispatch_builtin_hostcall(
            "builtin:ReflectDeleteProperty",
            RegRange { start: 0, count: 2 },
            None,
        )
        .unwrap(),
        Value::Bool(true)
    );
    core.set_object_runtime_property(
        object,
        RuntimePropertyKey::String(d801.clone()),
        Value::Int(9),
    )
    .unwrap();
    let expected_after_delete = vec![d800.clone(), replacement.clone(), d801.clone()];

    let assigned = core.alloc_object_with_prototype(None).unwrap();
    core.set_reg(0, Value::Object(assigned));
    core.set_reg(1, Value::Object(object));
    assert_eq!(
        core.dispatch_builtin_hostcall(
            "builtin:ObjectAssign",
            RegRange { start: 0, count: 2 },
            None,
        )
        .unwrap(),
        Value::Object(assigned)
    );
    assert_eq!(
        core.heap[assigned.0 as usize].properties.exact_keys(),
        expected_after_delete
    );

    let spread_target = core.alloc_object_with_prototype(None).unwrap();
    core.set_reg(5, Value::Object(spread_target));
    core.set_reg(6, Value::Object(object));
    core.ip = 0;
    assert_eq!(
        core.run_loop(&test_module(vec![
            Ir3Instruction::SpreadIntoObject {
                target: 5,
                source: 6,
            },
            Ir3Instruction::Return { value: 5 },
        ]))
        .unwrap(),
        Value::Object(spread_target)
    );
    assert_eq!(
        core.heap[spread_target.0 as usize].properties.exact_keys(),
        expected_after_delete
    );

    let entry_pairs = [
        (d800.clone(), Value::Int(28)),
        (d801.clone(), Value::Int(29)),
        (replacement.clone(), Value::Int(30)),
    ]
    .into_iter()
    .map(|(key, value)| {
        core.alloc_array_from_values(&[Value::Str(key), value])
            .unwrap()
    })
    .map(Value::Object)
    .collect::<Vec<_>>();
    let entry_source = core.alloc_array_from_values(&entry_pairs).unwrap();
    core.set_reg(0, Value::Object(entry_source));
    let from_entries = core
        .dispatch_builtin_hostcall(
            "builtin:ObjectFromEntries",
            RegRange { start: 0, count: 1 },
            None,
        )
        .unwrap();
    let Value::Object(from_entries) = from_entries else {
        panic!("Object.fromEntries must return an object");
    };
    assert_eq!(
        core.heap[from_entries.0 as usize].properties.exact_keys(),
        expected_keys
    );

    let descriptor = core
        .alloc_object_with_properties(&[("value", Value::Int(88))])
        .unwrap();
    let defined = core.alloc_object_with_prototype(None).unwrap();
    core.set_reg(0, Value::Object(defined));
    core.set_reg(1, Value::Str(d800.clone()));
    core.set_reg(2, Value::Object(descriptor));
    core.dispatch_builtin_hostcall(
        "builtin:ObjectDefineProperty",
        RegRange { start: 0, count: 3 },
        None,
    )
    .unwrap();
    assert_eq!(
        core.heap[defined.0 as usize].properties.get_exact(&d800),
        Some(&Value::Int(88))
    );
    let descriptor = core
        .dispatch_builtin_hostcall(
            "builtin:ObjectGetOwnPropertyDescriptor",
            RegRange { start: 0, count: 2 },
            None,
        )
        .unwrap();
    let Value::Object(descriptor) = descriptor else {
        panic!("exact descriptor lookup must return an object");
    };
    assert_eq!(
        core.heap[descriptor.0 as usize].properties.get("value"),
        Some(&Value::Int(88))
    );

    let inherited = core
        .alloc_object_with_prototype(Some(defined))
        .expect("descriptor child should allocate");
    core.set_reg(0, Value::Object(inherited));
    core.set_reg(1, Value::Str(d800.clone()));
    let descriptor = core
        .dispatch_builtin_hostcall(
            "builtin:ObjectGetPropertyDescriptor",
            RegRange { start: 0, count: 2 },
            None,
        )
        .unwrap();
    let Value::Object(descriptor) = descriptor else {
        panic!("exact inherited descriptor lookup must return an object");
    };
    assert_eq!(
        core.heap[descriptor.0 as usize].properties.get("value"),
        Some(&Value::Int(88))
    );

    core.set_reg(0, Value::Object(object));
    assert_eq!(
        core.dispatch_builtin_hostcall(
            "builtin:JsonStringify",
            RegRange { start: 0, count: 1 },
            None,
        )
        .unwrap(),
        Value::str(r#"{"\ud800":8,"�":10,"\ud801":9}"#)
    );
    assert!(matches!(
        core.qs_stringify_object(object, "&", "="),
        Err(InterpreterError::UncaughtException { .. })
    ));
    assert_eq!(
        core.heap
            .iter()
            .rev()
            .find_map(|object| object.properties.get("code")),
        Some(&Value::str("ERR_INVALID_URI"))
    );
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
            import_meta_object: None,
            exports: BTreeMap::new(),
            star_exports: BTreeMap::new(),
            flow_label_ceiling: None,
            resolved_source_hash: None,
            import_bindings: BTreeMap::new(),
            star_reexporters: BTreeSet::new(),
            cjs_module_object: Some(module_object),
            compiled_module: None,
            evaluation_promise: None,
            async_execution: None,
        },
    );
    core.current_module_specifier = Some(specifier.clone());
    core.finalize_cjs_exports(
        None,
        &CjsModuleContext {
            module_object,
            exports_object,
            module_specifier: specifier.clone(),
        },
    )
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

#[test]
fn intrinsic_combinators_keep_native_element_jobs_bd_9vouw_295() {
    for promise_inputs in [false, true] {
        let mut core = quickjs_test_core();
        core.inject_runtime_globals().unwrap();
        for prototype in ["Array", ARRAY_ITERATOR_PROTOTYPE, "Promise"] {
            core.ensure_builtin_prototype(prototype).unwrap();
        }
        let constructor = core.promise_intrinsic_constructor().unwrap();
        let module = test_module(vec![Ir3Instruction::Halt]);
        let mut values = Vec::new();
        for index in 0..128 {
            values.push(if promise_inputs {
                let promise = core
                    .create_fulfilled_promise(
                        crate::object_model::JsValue::Int(index),
                        Label::Public,
                    )
                    .unwrap();
                Value::Promise(promise.0)
            } else {
                Value::Int(index)
            });
        }
        let input = core.alloc_array_from_values(&values).unwrap();
        core.write_reg(0, Value::Object(input)).unwrap();
        let before = core.promise_store.len();
        let result = core
            .promise_combinator_call(
                &module,
                PromiseCombinatorKind::All,
                "promise:all",
                "all",
                RegRange { start: 0, count: 1 },
                Some(&constructor),
            )
            .unwrap();
        let Value::Promise(result) = result else {
            panic!("Promise.all result")
        };
        assert_eq!(
            core.promise_store.len(),
            before + 1,
            "intrinsic elements need no artificial promises or guest capabilities"
        );
        assert_eq!(core.promise_combinators.len(), 1);
        assert_eq!(core.event_loop.microtasks.pending_count(), 128);
        assert!(matches!(
            core.promise_store
                .get(crate::promise_model::PromiseHandle(result))
                .unwrap()
                .state,
            crate::promise_model::PromiseState::Pending
        ));
        core.drain_microtasks(None).unwrap();
        assert!(core.promise_combinators.is_empty());
        assert!(
            core.promise_store
                .get(crate::promise_model::PromiseHandle(result))
                .unwrap()
                .state
                .is_fulfilled()
        );
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }
}

#[test]
fn native_combinator_budget_failure_closes_labeled_dependents_bd_9vouw_295() {
    let mut core = quickjs_test_core();
    let first = core.create_promise().unwrap();
    let second = core.create_promise().unwrap();
    let result = core
        .dispatch_promise_combinator_inputs(
            PromiseCombinatorKind::All,
            vec![
                Value::Promise(first.0),
                Value::Promise(second.0),
                Value::Promise(second.0),
            ],
            Label::Internal,
        )
        .unwrap();
    let Value::Promise(result) = result else {
        panic!("aggregate promise")
    };
    let result = crate::promise_model::PromiseHandle(result);
    let secret = Label::Custom {
        name: "combinator-secret".repeat(64),
        level: 7,
    };
    core.fulfill_promise(first, crate::object_model::JsValue::Int(1), secret.clone())
        .unwrap();
    core.drain_microtasks(None).unwrap();
    assert_eq!(core.promise_store.get(result).unwrap().label, secret);
    assert_eq!(
        core.promise_store.get(result).unwrap().state,
        crate::promise_model::PromiseState::Pending
    );
    let descendant = core
        .register_promise_then(result, None, None, Label::Public)
        .unwrap();
    core.fulfill_promise(
        second,
        crate::object_model::JsValue::Str("large-element".repeat(128)),
        Label::Public,
    )
    .unwrap();
    assert_eq!(core.event_loop.microtasks.pending_count(), 2);
    let ceiling = core.sync_estimated_memory_bytes().unwrap();
    core.config.max_total_memory_bytes = ceiling;
    let heap_slots = core.heap.len();
    assert!(matches!(
        core.drain_microtasks(None),
        Err(InterpreterError::MemoryBudgetExceeded { .. })
    ));
    for promise in [result, descendant] {
        let record = core.promise_store.get(promise).unwrap();
        assert_eq!(
            record.state,
            crate::promise_model::PromiseState::Rejected(crate::object_model::JsValue::Undefined)
        );
        assert_eq!(record.label.level(), 7);
        assert!(!record.label.can_flow_to(&Label::Public));
        assert!(record.reactions.is_empty());
    }
    assert_eq!(
        core.heap.len(),
        heap_slots,
        "tracker admission failed before result allocation"
    );
    assert!(core.promise_combinators.is_empty());
    assert!(core.promise_combinator_watchers.is_empty());
    assert_eq!(core.promise_in_flight_task_bytes, 0);
    assert!(core.estimated_memory_bytes() <= ceiling);
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
    core.drain_microtasks(None)
        .expect("remaining native jobs for a closed aggregate are inert");
    assert!(core.promise_combinators.is_empty());
    assert!(core.event_loop.microtasks.is_empty());
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn native_combinator_terminal_payload_copy_requires_scratch_bd_9vouw_295() {
    let mut core = quickjs_test_core();
    let result = core.create_promise().unwrap();
    let text = "terminal-payload".repeat(1024);
    let text_len = text.len();
    let payload_bytes = InterpreterCore::estimate_string_bytes(&text);
    let combinator = core
        .register_combinator(PromiseCombinatorState::All(
            crate::promise_model::PromiseAllTracker {
                result_promise: result,
                values: BTreeMap::from([(0, crate::object_model::JsValue::Str(text))]),
                total: 1,
                resolved_count: 1,
                settled: true,
            },
        ))
        .unwrap();
    let before = core.sync_estimated_memory_bytes().unwrap();
    let heap_slots = core.heap.len();
    // The empty destination fits, but copying the first retained string
    // and its bounded key misses admission by exactly one byte. The
    // tracker must survive unchanged and no result property may appear.
    let required = before
        + MEMORY_ESTIMATE_HEAP_OBJECT_BASE_BYTES
        + payload_bytes
        + MEMORY_ESTIMATE_STRING_BASE_BYTES
        + 6;
    core.config.max_total_memory_bytes = required - 1;
    let error = core.build_native_combinator_result(combinator).unwrap_err();
    assert!(
        matches!(error, InterpreterError::MemoryBudgetExceeded { requested_bytes, .. }
            if requested_bytes == required)
    );
    assert_eq!(core.heap.len(), heap_slots + 1);
    assert!(core.heap[heap_slots].properties.is_empty());
    assert!(matches!(core.native_combinator_element(combinator, 0),
            Some((crate::object_model::JsValue::Str(text), None)) if text.len() == text_len));
    assert_eq!(core.promise_in_flight_task_bytes, 0);
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn builtin_promise_all_uses_real_aggregate_tracking() {
    let mut core = quickjs_test_core();
    let label = crate::ifc_artifacts::Label::Public;

    let first = core.create_promise().unwrap();
    let second = core.create_promise().unwrap();
    let input = core
        .alloc_array_from_values(&[Value::Promise(first.0), Value::Promise(second.0)])
        .expect("promise input array should allocate");
    core.set_reg(0, Value::Object(input));

    let result = core
        .dispatch_builtin_hostcall("builtin:PromiseAll", RegRange { start: 0, count: 1 }, None)
        .expect("Promise.all should dispatch through the builtin surface");
    let Value::Promise(aggregate_id) = result else {
        panic!("Promise.all should return a runtime promise handle, got {result:?}");
    };
    let aggregate = crate::promise_model::PromiseHandle(aggregate_id);

    let pending = core
        .promise_store
        .get(aggregate)
        .expect("aggregate promise should exist");
    assert!(
        matches!(pending.state, crate::promise_model::PromiseState::Pending),
        "aggregate should stay pending until all inputs settle"
    );

    core.fulfill_promise(first, crate::object_model::JsValue::Int(7), Label::Secret)
        .expect("first input promise should fulfill");
    core.drain_microtasks(None)
        .expect("first native element job");
    let after_first = core
        .promise_store
        .get(aggregate)
        .expect("aggregate promise should still exist");
    assert!(
        matches!(
            after_first.state,
            crate::promise_model::PromiseState::Pending
        ),
        "aggregate should remain pending after only one fulfillment"
    );

    core.fulfill_promise(second, crate::object_model::JsValue::Int(11), label)
        .expect("second input promise should fulfill");
    assert!(
        matches!(
            core.promise_store.get(aggregate).unwrap().state,
            crate::promise_model::PromiseState::Pending
        ),
        "the final input settlement queues its element job before the aggregate settles"
    );
    core.drain_microtasks(None)
        .expect("final native element job");
    let resolved = core
        .promise_store
        .get(aggregate)
        .expect("aggregate promise should resolve after all inputs fulfill");
    assert_eq!(
        resolved.label,
        Label::Secret,
        "the first input's label survives a later public input"
    );
    let crate::promise_model::PromiseState::Fulfilled(crate::object_model::JsValue::Object(
        values_handle,
    )) = &resolved.state
    else {
        panic!(
            "aggregate should fulfill with an array value, got {:?}",
            resolved.state
        );
    };

    let values = &core.heap[values_handle.0 as usize];
    assert!(
        values.is_array,
        "Promise.all should resolve to an array object"
    );
    assert_eq!(values.properties.get("0"), Some(&Value::Int(7)));
    assert_eq!(values.properties.get("1"), Some(&Value::Int(11)));
    assert_eq!(values.properties.get("length"), Some(&Value::Int(2)));
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn batch_28_deduplication_regression_test() {
    // Regression test for bd-vu73s batch-28 trim, integer, endsWith deduplication
    // Verifies that duplicate dispatch arms were removed and only first occurrences remain
    let interpreter = InterpreterCore::new(test_quickjs_config(), "test");

    // Test StringPrototypeTrim builtin ID still works
    assert_eq!(
        interpreter.builtin_name_from_id(37), // From original mapping
        Some("builtin:StringPrototypeTrim".to_string())
    );
    assert_eq!(
        interpreter.builtin_name_from_id(333), // From batch-28 mapping
        Some("builtin:StringPrototypeTrim".to_string())
    );

    // Test NumberIsInteger builtin IDs still work
    assert_eq!(
        interpreter.builtin_name_from_id(231), // From batch-28 mapping
        Some("builtin:NumberIsInteger".to_string())
    );
    assert_eq!(
        interpreter.builtin_name_from_id(335), // From batch-28 mapping
        Some("builtin:NumberIsInteger".to_string())
    );

    // Test StringPrototypeEndsWith builtin IDs still work
    assert_eq!(
        interpreter.builtin_name_from_id(40), // From original mapping
        Some("builtin:StringPrototypeEndsWith".to_string())
    );
    assert_eq!(
        interpreter.builtin_name_from_id(230), // From batch-28 mapping
        Some("builtin:StringPrototypeEndsWith".to_string())
    );
    assert_eq!(
        interpreter.builtin_name_from_id(336), // From batch-28 mapping
        Some("builtin:StringPrototypeEndsWith".to_string())
    );
}

#[test]
fn batch_28_functionality_preserved() {
    // Verify that all batch-28 deduplicated functions still work correctly
    let mut core = InterpreterCore::new(test_quickjs_config(), "test");

    // Test StringPrototypeTrim functionality
    core.set_reg(0, Value::str("  hello world  "));
    let trim_result = core.execute(&test_module(vec![
        Ir3Instruction::HostCall {
            capability: CapabilityTag("builtin:StringPrototypeTrim".to_string()),
            args: RegRange { start: 0, count: 1 },
            dst: 10,
        },
        Ir3Instruction::Halt,
    ]));
    assert!(
        trim_result.is_ok(),
        "StringPrototypeTrim should work after deduplication"
    );

    // Test NumberIsInteger functionality
    core.set_reg(0, Value::Int(42));
    let integer_result = core.execute(&test_module(vec![
        Ir3Instruction::HostCall {
            capability: CapabilityTag("builtin:NumberIsInteger".to_string()),
            args: RegRange { start: 0, count: 1 },
            dst: 10,
        },
        Ir3Instruction::Halt,
    ]));
    assert!(
        integer_result.is_ok(),
        "NumberIsInteger should work after deduplication"
    );

    // Test StringPrototypeEndsWith functionality
    core.set_reg(0, Value::str("hello world"));
    core.set_reg(1, Value::str("world"));
    let endswith_result = core.execute(&test_module(vec![
        Ir3Instruction::HostCall {
            capability: CapabilityTag("builtin:StringPrototypeEndsWith".to_string()),
            args: RegRange { start: 0, count: 2 },
            dst: 10,
        },
        Ir3Instruction::Halt,
    ]));
    assert!(
        endswith_result.is_ok(),
        "StringPrototypeEndsWith should work after deduplication"
    );
}

#[test]
fn string_prototype_pad_start_deduplication_regression() {
    let mut interpreter = InterpreterCore::new(test_quickjs_config(), "test-trace");

    for builtin_id in [43_u32, 226_u32] {
        interpreter.set_reg(0, Value::str("7"));
        interpreter.set_reg(1, Value::Int(3));
        interpreter.set_reg(2, Value::str("0"));

        assert_eq!(
            interpreter.builtin_name_from_id(builtin_id),
            Some("builtin:StringPrototypePadStart".to_string())
        );
        let result = interpreter
            .call_builtin_by_id(builtin_id, RegRange { start: 0, count: 3 })
            .expect("StringPrototypePadStart ID should execute");
        assert_eq!(result, Value::str("007"));
    }
}

#[test]
fn string_prototype_pad_end_deduplication_regression() {
    let mut interpreter = InterpreterCore::new(test_quickjs_config(), "test-trace");

    for builtin_id in [44_u32, 227_u32] {
        interpreter.set_reg(0, Value::str("7"));
        interpreter.set_reg(1, Value::Int(3));
        interpreter.set_reg(2, Value::str("0"));

        assert_eq!(
            interpreter.builtin_name_from_id(builtin_id),
            Some("builtin:StringPrototypePadEnd".to_string())
        );
        let result = interpreter
            .call_builtin_by_id(builtin_id, RegRange { start: 0, count: 3 })
            .expect("StringPrototypePadEnd ID should execute");
        assert_eq!(result, Value::str("700"));
    }
}

#[test]
fn string_prototype_starts_with_deduplication_regression() {
    let mut interpreter = InterpreterCore::new(test_quickjs_config(), "test-trace");

    for builtin_id in [39_u32, 229_u32] {
        interpreter.set_reg(0, Value::str("alpha"));
        interpreter.set_reg(1, Value::str("ph"));
        interpreter.set_reg(2, Value::Int(2));

        assert_eq!(
            interpreter.builtin_name_from_id(builtin_id),
            Some("builtin:StringPrototypeStartsWith".to_string())
        );
        let result = interpreter
            .call_builtin_by_id(builtin_id, RegRange { start: 0, count: 3 })
            .expect("StringPrototypeStartsWith ID should execute");
        assert_eq!(result, Value::Bool(true));
    }
}

#[test]
fn string_prototype_ends_with_deduplication_regression() {
    let mut interpreter = InterpreterCore::new(test_quickjs_config(), "test-trace");

    for builtin_id in [40_u32, 230_u32, 336_u32] {
        interpreter.set_reg(0, Value::str("frankenengine"));
        interpreter.set_reg(1, Value::str("engine"));
        interpreter.set_reg(2, Value::Int(13));

        assert_eq!(
            interpreter.builtin_name_from_id(builtin_id),
            Some("builtin:StringPrototypeEndsWith".to_string())
        );
        let result = interpreter
            .call_builtin_by_id(builtin_id, RegRange { start: 0, count: 3 })
            .expect("StringPrototypeEndsWith ID should execute");
        assert_eq!(result, Value::Bool(true));
    }
}

#[test]
fn string_prototype_ends_with_utf16_regression() {
    let mut interpreter = InterpreterCore::new(test_quickjs_config(), "test-trace");

    let cases: [(&str, &str, Option<i64>, bool); 6] = [
        ("😀", "", Some(1), true),
        ("😀", "", Some(2), true),
        ("😀", "", Some(0), true),
        ("A😀B", "B", Some(10), true),
        ("A😀B", "😀", Some(3), true),
        ("A😀B", "engine", None, false),
    ];

    for builtin_id in [40_u32, 230_u32, 336_u32] {
        assert_eq!(
            interpreter.builtin_name_from_id(builtin_id),
            Some("builtin:StringPrototypeEndsWith".to_string())
        );

        for (this_str, search_str, length, expected) in cases {
            interpreter.set_reg(0, Value::str(this_str));
            interpreter.set_reg(1, Value::str(search_str));

            let args = if let Some(length) = length {
                interpreter.set_reg(2, Value::Int(length));
                RegRange { start: 0, count: 3 }
            } else {
                RegRange { start: 0, count: 2 }
            };

            let result = interpreter
                .call_builtin_by_id(builtin_id, args)
                .expect("StringPrototypeEndsWith ID should execute");
            assert_eq!(result, Value::Bool(expected));
        }
    }
}

#[test]
fn string_prototype_ends_with_split_pair_boundary_is_lossless() {
    // bd-rdnhc: an end position inside a surrogate pair is a legal
    // code-unit offset (previously failed closed with a TypeError).
    // "A😀B" is [0x41, 0xD83D, 0xDE00, 0x42]; the prefix of length 2 is
    // [0x41, 0xD83D], which does not end with the full pair but does end
    // with the lone high surrogate.
    let mut interpreter = InterpreterCore::new(test_quickjs_config(), "test-trace");

    for builtin_id in [40_u32, 230_u32, 336_u32] {
        interpreter.set_reg(0, Value::str("A😀B"));
        interpreter.set_reg(1, Value::str("😀"));
        interpreter.set_reg(2, Value::Int(2));

        let result = interpreter
            .call_builtin_by_id(builtin_id, RegRange { start: 0, count: 3 })
            .expect("split-pair end position is a legal code-unit offset");
        assert_eq!(result, Value::Bool(false));

        interpreter.set_reg(1, Value::Str(JsString::from_code_units(&[0xD83D])));
        let result = interpreter
            .call_builtin_by_id(builtin_id, RegRange { start: 0, count: 3 })
            .expect("split-pair end position is a legal code-unit offset");
        assert_eq!(
            result,
            Value::Bool(true),
            "prefix of length 2 ends with the lone high surrogate"
        );
    }
}

#[test]
fn string_prototype_repeat_deduplication_regression() {
    let mut interpreter = InterpreterCore::new(test_quickjs_config(), "test-trace");

    for builtin_id in [42_u32, 233_u32] {
        interpreter.set_reg(0, Value::str("ha"));
        interpreter.set_reg(1, Value::Int(3));

        assert_eq!(
            interpreter.builtin_name_from_id(builtin_id),
            Some("builtin:StringPrototypeRepeat".to_string())
        );
        let result = interpreter
            .call_builtin_by_id(builtin_id, RegRange { start: 0, count: 2 })
            .expect("StringPrototypeRepeat ID should execute");
        assert_eq!(result, Value::str("hahaha"));
    }
}

#[test]
fn string_prototype_includes_deduplication_regression() {
    let mut interpreter = InterpreterCore::new(test_quickjs_config(), "test-trace");

    for builtin_id in [38_u32, 238_u32] {
        interpreter.set_reg(0, Value::str("frankenengine"));
        interpreter.set_reg(1, Value::str("engine"));
        interpreter.set_reg(2, Value::Int(4));

        assert_eq!(
            interpreter.builtin_name_from_id(builtin_id),
            Some("builtin:StringPrototypeIncludes".to_string())
        );
        let result = interpreter
            .call_builtin_by_id(builtin_id, RegRange { start: 0, count: 3 })
            .expect("StringPrototypeIncludes ID should execute");
        assert_eq!(result, Value::Bool(true));
    }
}

#[test]
fn string_prototype_trim_start_deduplication_regression() {
    let mut interpreter = InterpreterCore::new(test_quickjs_config(), "test-trace");

    for builtin_id in [223_u32, 301_u32] {
        interpreter.set_reg(0, Value::str("  frankenengine  "));

        assert_eq!(
            interpreter.builtin_name_from_id(builtin_id),
            Some("builtin:StringPrototypeTrimStart".to_string())
        );
        let result = interpreter
            .call_builtin_by_id(builtin_id, RegRange { start: 0, count: 1 })
            .expect("StringPrototypeTrimStart ID should execute");
        assert_eq!(result, Value::str("frankenengine  "));
    }
}

#[test]
fn object_define_property_deduplication_regression() {
    let mut interpreter = InterpreterCore::new(test_quickjs_config(), "test-trace");

    for builtin_id in [7_u32, 280_u32] {
        let object_id = interpreter
            .alloc_object_with_prototype(None)
            .expect("test object allocation should succeed");
        let descriptor_id = interpreter
            .alloc_object_with_prototype(None)
            .expect("test descriptor allocation should succeed");
        interpreter
            .set_object_property(descriptor_id, "value".to_string(), Value::Int(42))
            .expect("test descriptor value write should succeed");

        interpreter.set_reg(0, Value::Object(object_id));
        interpreter.set_reg(1, Value::str("answer"));
        interpreter.set_reg(2, Value::Object(descriptor_id));

        assert_eq!(
            interpreter.builtin_name_from_id(builtin_id),
            Some("builtin:ObjectDefineProperty".to_string())
        );
        let result = interpreter
            .call_builtin_by_id(builtin_id, RegRange { start: 0, count: 3 })
            .expect("ObjectDefineProperty ID should execute");
        assert_eq!(result, Value::Object(object_id));

        let object = interpreter
            .heap
            .get(object_id.0 as usize)
            .expect("defined test object should remain allocated");
        assert_eq!(object.properties.get("answer"), Some(&Value::Int(42)));
    }
}

#[test]
fn array_prototype_fill_deduplication_regression() {
    let mut interpreter = InterpreterCore::new(test_quickjs_config(), "test-trace");

    for builtin_id in [209_u32, 251_u32] {
        let array_id = interpreter
            .alloc_object_with_prototype(None)
            .expect("test array allocation should succeed");
        interpreter
            .set_object_property(array_id, "length".to_string(), Value::Int(3))
            .expect("test array length write should succeed");
        interpreter
            .set_object_property(array_id, "0".to_string(), Value::str("a"))
            .expect("test array element write should succeed");
        interpreter
            .set_object_property(array_id, "1".to_string(), Value::str("b"))
            .expect("test array element write should succeed");
        interpreter
            .set_object_property(array_id, "2".to_string(), Value::str("c"))
            .expect("test array element write should succeed");
        interpreter.set_reg(0, Value::Object(array_id));
        interpreter.set_reg(1, Value::str("x"));
        interpreter.set_reg(2, Value::Int(1));
        interpreter.set_reg(3, Value::Int(3));

        assert_eq!(
            interpreter.builtin_name_from_id(builtin_id),
            Some("builtin:ArrayPrototypeFill".to_string())
        );
        let result = interpreter
            .call_builtin_by_id(builtin_id, RegRange { start: 0, count: 4 })
            .expect("ArrayPrototypeFill ID should execute");
        assert_eq!(result, Value::Object(array_id));

        let array = interpreter
            .heap
            .get(array_id.0 as usize)
            .expect("filled test array should remain allocated");
        assert_eq!(array.properties.get("0"), Some(&Value::str("a")));
        assert_eq!(array.properties.get("1"), Some(&Value::str("x")));
        assert_eq!(array.properties.get("2"), Some(&Value::str("x")));
    }
}

// -- bd-31ijt: incremental memory accounting on write_reg ---------------

#[test]
fn write_reg_string_value_updates_running_total_incrementally() {
    // Exercise the bd-31ijt fast path: a single write_reg with a sized
    // value must move estimated_memory_bytes by exactly the delta
    // between the previous slot's bytes and the new slot's bytes — no
    // full recompute, no drift relative to the source-of-truth.
    let mut interp = InterpreterCore::new(test_quickjs_config(), "test-trace");
    let seed_bytes = interp.estimated_memory_bytes;
    assert_eq!(interp.recompute_estimated_memory_bytes(), seed_bytes);

    let payload = "hello-world".to_string();
    let payload_bytes = InterpreterCore::estimate_value_bytes(&Value::str(payload.clone()));
    assert!(payload_bytes > 0, "string value must contribute bytes");

    interp.write_reg(0, Value::str(payload)).expect("write_reg");
    assert_eq!(interp.estimated_memory_bytes, seed_bytes + payload_bytes);
    // Source-of-truth recompute must agree — no drift introduced by
    // the incremental update.
    assert_eq!(
        interp.recompute_estimated_memory_bytes(),
        interp.estimated_memory_bytes
    );
}

#[test]
fn write_reg_replacing_string_with_undefined_subtracts_bytes() {
    let mut interp = InterpreterCore::new(test_quickjs_config(), "test-trace");
    let payload = Value::str("x".repeat(64));
    let seed_bytes = interp.estimated_memory_bytes;
    let initial_bytes = InterpreterCore::estimate_value_bytes(&payload);
    interp.write_reg(0, payload).expect("write_reg string");
    assert_eq!(interp.estimated_memory_bytes, seed_bytes + initial_bytes);

    interp
        .write_reg(0, Value::Undefined)
        .expect("write_reg undefined");
    assert_eq!(interp.estimated_memory_bytes, seed_bytes);
    assert_eq!(
        interp.recompute_estimated_memory_bytes(),
        interp.estimated_memory_bytes,
        "incremental subtract must match full recompute"
    );
}

#[test]
fn write_reg_rejects_value_that_pushes_total_over_budget() {
    // Tight memory budget: a single write of a large string should
    // exceed it. The fast path must still return MemoryBudgetExceeded
    // and must NOT install the rejected value (state unchanged).
    let mut config = test_quickjs_config();
    config.max_total_memory_bytes = 64;
    let mut interp = InterpreterCore::new(config, "test-trace");
    let seed_bytes = interp.estimated_memory_bytes;

    let huge = Value::str("x".repeat(1024));
    let result = interp.write_reg(0, huge);
    assert!(
        matches!(result, Err(InterpreterError::MemoryBudgetExceeded { .. })),
        "expected MemoryBudgetExceeded, got {result:?}"
    );
    assert_eq!(
        interp.read_reg(0).expect("read undefined"),
        Value::Undefined,
        "rejected write must not mutate the register"
    );
    assert_eq!(
        interp.estimated_memory_bytes, seed_bytes,
        "rejected write must not move the running total"
    );
}

#[test]
fn write_reg_burst_does_not_drift_against_full_recompute() {
    // Hot loop: many register writes with mixed value sizes. After the
    // burst, the incrementally-maintained `estimated_memory_bytes` must
    // exactly equal a fresh full recompute. Catches any sign error or
    // missed-delta bug in the bd-31ijt fast path.
    let mut interp = InterpreterCore::new(test_quickjs_config(), "test-trace");
    for i in 0..256u32 {
        let value = if i.is_multiple_of(3) {
            Value::str(format!("payload-{i}-{}", "x".repeat((i % 32) as usize)))
        } else if i.is_multiple_of(2) {
            Value::Int(i as i64)
        } else {
            Value::Undefined
        };
        interp
            .write_reg(i % 8, value)
            .expect("burst write must stay within budget");
    }
    assert_eq!(
        interp.recompute_estimated_memory_bytes(),
        interp.estimated_memory_bytes,
        "burst writes must not introduce drift"
    );
}
