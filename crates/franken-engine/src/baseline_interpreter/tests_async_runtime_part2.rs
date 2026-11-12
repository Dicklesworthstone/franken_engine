#[allow(unused_imports)]
use super::*;
#[allow(unused_imports)]
use crate::baseline_interpreter::*;
#[allow(unused_imports)]
use crate::ir_contract::{
    CapabilityTag, Ir3FunctionDesc, IrHeader, IrLevel, IrSchemaVersion, RegRange,
};
#[allow(unused_imports)]
use frankenengine_extension_host::host_io::{HostIoError, HostIoOutcome, HostIoRequest};

#[test]
fn isolated_result_label_clone_has_an_exact_transient_ceiling_bd_8hv4e() {
    let mut core = test_interpreter();
    let label = Label::Custom {
        name: "isolated-result-register-label".repeat(12),
        level: 19,
    };
    core.write_reg_with_label(0, Value::Int(7), label.clone())
        .expect("isolated result register");
    core.sync_estimated_memory_bytes()
        .expect("initial isolated-result accounting");
    let before = core.estimated_memory_bytes();
    let temporary_bytes = InterpreterCore::estimate_label_bytes(&label);

    core.config.max_total_memory_bytes = before.saturating_add(temporary_bytes - 1);
    assert!(matches!(
        core.clone_register_label_with_temporary_budget(0),
        Err(InterpreterError::MemoryBudgetExceeded { .. })
    ));
    assert_eq!(core.estimated_memory_bytes(), before);
    assert_eq!(core.get_register_label(0).expect("r0 label"), &label);

    core.config.max_total_memory_bytes = before.saturating_add(temporary_bytes);
    assert_eq!(
        core.clone_register_label_with_temporary_budget(0)
            .expect("exact isolated-result clone ceiling"),
        label
    );
    assert_eq!(core.estimated_memory_bytes(), before);
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );

    let module = test_module_with_functions(
        vec![Ir3Instruction::Return { value: 0 }],
        vec![Ir3FunctionDesc {
            entry: 0,
            arity: 1,
            frame_size: 2,
            name: Some("isolated_result_identity".to_string()),
            is_generator: false,
            rest_param_index: None,
        }],
    );
    let argument_label = Label::Custom {
        name: "isolated-wrapper-result-context".repeat(24),
        level: 31,
    };
    let caller_label = Label::Custom {
        name: "caller-snapshot-label".repeat(4),
        level: 5,
    };
    let caller_value = Value::str("caller-snapshot-value");
    let (baseline, baseline_register_bytes) = {
        let mut core = test_interpreter();
        core.write_reg_with_label(7, caller_value.clone(), caller_label.clone())
            .expect("caller snapshot register");
        let total = core
            .sync_estimated_memory_bytes()
            .expect("caller snapshot accounting");
        (
            total,
            core.registers_memory_bytes()
                .saturating_add(core.register_labels_memory_bytes()),
        )
    };
    let attempt = |budget: u64| {
        let mut core = test_interpreter();
        core.write_reg_with_label(7, caller_value.clone(), caller_label.clone())
            .expect("caller snapshot register");
        assert_eq!(
            core.sync_estimated_memory_bytes()
                .expect("caller snapshot accounting"),
            baseline
        );
        core.config.max_total_memory_bytes = budget;
        let result = core.invoke_inline_method_call_with_argument_label(
            Some(&module),
            Value::Function(0),
            Value::Undefined,
            vec![Value::Int(29)],
            Some(argument_label.clone()),
        );
        (core, result)
    };

    let mut distance = 1u64;
    let mut upper = loop {
        let budget = baseline.saturating_add(distance);
        if attempt(budget).1.is_ok() {
            break budget;
        }
        distance = distance
            .checked_mul(2)
            .expect("isolated wrapper ceiling search remains bounded");
        assert!(
            distance <= (1 << 32),
            "isolated wrapper ceiling is implausible"
        );
    };
    let mut lower = baseline;
    while lower < upper {
        let midpoint = lower + (upper - lower) / 2;
        if attempt(midpoint).1.is_ok() {
            upper = midpoint;
        } else {
            lower = midpoint + 1;
        }
    }
    let exact_ceiling = lower;
    let (refused_core, refusal) = attempt(exact_ceiling - 1);
    assert!(matches!(
        refusal,
        Err(InterpreterError::MemoryBudgetExceeded {
            requested_bytes,
            max_bytes,
            ..
        }) if requested_bytes == exact_ceiling && max_bytes == exact_ceiling - 1
    ));
    assert_eq!(
        refused_core.read_reg(7).expect("restored caller value"),
        caller_value
    );
    assert_eq!(
        refused_core
            .get_register_label(7)
            .expect("restored caller label"),
        &caller_label
    );
    assert_eq!(refused_core.active_inline_callback_context_label, None);
    assert_eq!(refused_core.ip, 0);
    assert_eq!(refused_core.estimated_memory_bytes(), baseline);
    assert_eq!(
        refused_core.estimated_memory_bytes(),
        refused_core.recompute_estimated_memory_bytes()
    );

    let (exact_core, exact_result) = attempt(exact_ceiling);
    assert_eq!(
        exact_result.expect("exact isolated-wrapper result ceiling"),
        (Value::Int(29), argument_label.clone())
    );
    assert_eq!(
        exact_core.read_reg(7).expect("restored caller value"),
        caller_value
    );
    assert_eq!(
        exact_core
            .get_register_label(7)
            .expect("restored caller label"),
        &caller_label
    );
    assert_eq!(exact_core.active_inline_callback_context_label, None);
    // A same-module callback runs as a nested call on the live register
    // stack (65ccf179a), not in a snapshot the wrapper restores. Like
    // every ordinary call, it leaves its dead frames' registers in place
    // until a later frame at that depth clears them. Every other
    // component is exactly back at the baseline; the only residual is
    // the register file's contents.
    let register_bytes = |core: &InterpreterCore| {
        core.registers_memory_bytes()
            .saturating_add(core.register_labels_memory_bytes())
    };
    assert_eq!(
        exact_core
            .estimated_memory_bytes()
            .saturating_sub(register_bytes(&exact_core)),
        baseline.saturating_sub(baseline_register_bytes)
    );
    assert_eq!(
        exact_core.estimated_memory_bytes(),
        exact_core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn writable_discarded_and_terminal_label_peaks_are_exact_bd_8hv4e() {
    let module = test_module_with_functions(Vec::new(), Vec::new());
    let mut write_core = test_interpreter();
    let Value::Object(writable) = write_core
        .construct_stream_writable(RegRange { start: 0, count: 0 })
        .expect("non-dominant-label Writable")
    else {
        panic!("Writable constructor must return an object");
    };
    let dominant = Label::Custom {
        name: "z".to_string(),
        level: 23,
    };
    let discarded = Label::Custom {
        name: "lower-but-longer-incoming-label".repeat(2),
        level: 22,
    };
    {
        let state = write_core
            .writable_streams
            .get_mut(&writable)
            .expect("live non-dominant-label Writable");
        state.object_mode = true;
        state.cork_depth = 1;
        state.lifecycle_label = dominant.clone();
    }
    write_core
        .write_reg_with_label(0, Value::Int(31), discarded.clone())
        .expect("lower labeled chunk");
    write_core
        .sync_estimated_memory_bytes()
        .expect("initial non-dominant write accounting");
    let record = WritableWriteRecord {
        value: Value::Int(31),
        label: dominant.clone(),
        units: 1,
        callback: None,
        status: WritableWriteStatus::Pending,
        completion_failed: false,
    };
    let write_delta = InterpreterCore::estimate_writable_write_record_bytes(&record);
    let discarded_temporary = InterpreterCore::estimate_label_bytes(&discarded);
    assert!(
        write_delta > discarded_temporary,
        "the final write-record charge must be the controlling ceiling"
    );
    let before_write = write_core.estimated_memory_bytes();
    let before_state = format!("{:?}", write_core.writable_streams[&writable]);
    write_core.config.max_total_memory_bytes = before_write.saturating_add(write_delta - 1);
    assert!(matches!(
        write_core.writable_write(
            &module,
            Value::Object(writable),
            RegRange { start: 0, count: 1 },
        ),
        Err(InterpreterError::MemoryBudgetExceeded { .. })
    ));
    assert_eq!(
        format!("{:?}", write_core.writable_streams[&writable]),
        before_state
    );
    assert_eq!(write_core.estimated_memory_bytes(), before_write);

    write_core.config.max_total_memory_bytes = before_write.saturating_add(write_delta);
    assert_eq!(
        write_core
            .writable_write(
                &module,
                Value::Object(writable),
                RegRange { start: 0, count: 1 },
            )
            .expect("exact non-dominant write ceiling"),
        Value::Bool(true)
    );
    assert_eq!(
        write_core.writable_streams[&writable].lifecycle_label,
        dominant
    );
    assert_eq!(write_core.writable_streams[&writable].writes.len(), 1);
    assert_eq!(
        write_core.estimated_memory_bytes(),
        write_core.recompute_estimated_memory_bytes()
    );

    let mut end_core = test_interpreter();
    let Value::Object(end_writable) = end_core
        .construct_stream_writable(RegRange { start: 0, count: 0 })
        .expect("terminal backing-label Writable")
    else {
        panic!("Writable constructor must return an object");
    };
    let old_terminal_label = Label::Custom {
        name: "lower-terminal-label".repeat(6),
        level: 28,
    };
    {
        let state = end_core
            .writable_streams
            .get_mut(&end_writable)
            .expect("live Writable before terminalization");
        state.end_requested = true;
        state.finished = true;
        state.lifecycle_label = old_terminal_label.clone();
    }
    end_core
        .sync_estimated_memory_bytes()
        .expect("pre-terminal lower lifecycle accounting");
    end_core
        .terminalize_writable_state_storage(end_writable)
        .expect("terminal backing-label tombstone");
    let chunk = end_core
        .alloc_zeroed_buffer(4, 0)
        .expect("Buffer-like terminal chunk");
    let backing_label = Label::Custom {
        name: "dominant-backing-label".repeat(12),
        level: 29,
    };
    end_core
        .join_binary_storage_label(chunk, &backing_label)
        .expect("binary label join fits test budget");
    let callback_value =
        Value::BuiltinFunction(BuiltinFunction::new_kind(BuiltinFunctionKind::ArrayIsArray));
    let callback_label = Label::Custom {
        name: "callback-label".repeat(8),
        level: 27,
    };
    end_core
        .write_reg(0, Value::Object(chunk))
        .expect("terminal object chunk");
    end_core
        .write_reg_with_label(1, callback_value.clone(), callback_label.clone())
        .expect("terminal callback label");
    end_core
        .sync_estimated_memory_bytes()
        .expect("terminal backing+callback accounting");
    let callback_record = WritableCallbackRecord {
        value: callback_value,
        label: callback_label.clone(),
        module_specifier: end_core.current_module_specifier.clone(),
    };
    let callback_charge = MEMORY_ESTIMATE_WRITABLE_END_CALLBACK_BYTES.saturating_add(
        InterpreterCore::estimate_writable_callback_bytes(&callback_record),
    );
    let retained_delta = InterpreterCore::estimate_label_bytes(&backing_label)
        .saturating_sub(InterpreterCore::estimate_label_bytes(&old_terminal_label))
        .saturating_add(callback_charge);
    let temporary_peak = InterpreterCore::estimate_label_bytes(&backing_label)
        .saturating_add(InterpreterCore::estimate_label_bytes(&callback_label));
    let required = retained_delta.max(temporary_peak);
    let before_end = end_core.estimated_memory_bytes();
    let before_terminal = end_core.writable_terminal_states[&end_writable].clone();
    end_core.config.max_total_memory_bytes = before_end.saturating_add(required - 1);
    assert!(matches!(
        end_core.writable_end(
            &module,
            Value::Object(end_writable),
            RegRange { start: 0, count: 2 },
        ),
        Err(InterpreterError::MemoryBudgetExceeded { .. })
    ));
    assert_eq!(
        end_core.writable_terminal_states[&end_writable],
        before_terminal
    );
    assert_eq!(end_core.estimated_memory_bytes(), before_end);

    end_core.config.max_total_memory_bytes = before_end.saturating_add(required);
    assert_eq!(
        end_core
            .writable_end(
                &module,
                Value::Object(end_writable),
                RegRange { start: 0, count: 2 },
            )
            .expect("exact terminal backing+callback ceiling"),
        Value::Object(end_writable)
    );
    let terminal = &end_core.writable_terminal_states[&end_writable];
    assert_eq!(terminal.lifecycle_label, backing_label);
    assert_eq!(terminal.callbacks.len(), 1);
    assert_eq!(
        end_core.estimated_memory_bytes(),
        end_core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn writable_write_and_end_custom_labels_are_exact_and_atomic_bd_8hv4e() {
    let module = test_module_with_functions(Vec::new(), Vec::new());
    let mut core = test_interpreter();
    let Value::Object(writable) = core
        .construct_stream_writable(RegRange { start: 0, count: 0 })
        .expect("strict-label Writable")
    else {
        panic!("Writable constructor must return an object");
    };
    let label = Label::Custom {
        name: "writable-register-label".repeat(10),
        level: 9,
    };
    let chunk = Value::Int(17);
    core.writable_streams
        .get_mut(&writable)
        .expect("live Writable")
        .object_mode = true;
    core.writable_streams
        .get_mut(&writable)
        .expect("live Writable")
        .cork_depth = 1;
    core.write_reg_with_label(0, chunk.clone(), label.clone())
        .expect("labeled chunk register");
    let record = WritableWriteRecord {
        value: chunk,
        label: label.clone(),
        units: 1,
        callback: None,
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
    let write_delta = next_state_bytes.saturating_sub(previous_state_bytes);
    let before_write = core.estimated_memory_bytes();
    let before_write_state = format!("{:?}", core.writable_streams[&writable]);

    core.config.max_total_memory_bytes = before_write.saturating_add(write_delta - 1);
    assert!(matches!(
        core.writable_write(
            &module,
            Value::Object(writable),
            RegRange { start: 0, count: 1 },
        ),
        Err(InterpreterError::MemoryBudgetExceeded { .. })
    ));
    assert_eq!(
        format!("{:?}", core.writable_streams[&writable]),
        before_write_state
    );
    assert_eq!(core.estimated_memory_bytes(), before_write);

    core.config.max_total_memory_bytes = before_write.saturating_add(write_delta);
    assert_eq!(
        core.writable_write(
            &module,
            Value::Object(writable),
            RegRange { start: 0, count: 1 },
        )
        .expect("exact labeled write transaction"),
        Value::Bool(true)
    );
    assert_eq!(core.writable_streams[&writable].writes.len(), 1);
    assert_eq!(core.writable_streams[&writable].lifecycle_label, label);
    assert_eq!(core.estimated_memory_bytes(), before_write + write_delta);
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );

    let mut end_core = test_interpreter();
    let Value::Object(end_writable) = end_core
        .construct_stream_writable(RegRange { start: 0, count: 0 })
        .expect("context-label Writable")
    else {
        panic!("Writable constructor must return an object");
    };
    let context = Label::Custom {
        name: "same-level-z-end-context".repeat(10),
        level: 9,
    };
    end_core.active_inline_callback_context_label = Some(context.clone());
    end_core
        .sync_estimated_memory_bytes()
        .expect("end context accounting");
    let before_end = end_core.estimated_memory_bytes();
    let end_delta = InterpreterCore::estimate_label_bytes(&context);
    end_core.config.max_total_memory_bytes = before_end.saturating_add(end_delta - 1);
    assert!(matches!(
        end_core.writable_end(
            &module,
            Value::Object(end_writable),
            RegRange { start: 0, count: 0 },
        ),
        Err(InterpreterError::MemoryBudgetExceeded { .. })
    ));
    assert!(!end_core.writable_streams[&end_writable].end_requested);
    assert_eq!(end_core.estimated_memory_bytes(), before_end);

    end_core.config.max_total_memory_bytes = before_end.saturating_add(end_delta);
    assert_eq!(
        end_core
            .writable_end(
                &module,
                Value::Object(end_writable),
                RegRange { start: 0, count: 0 },
            )
            .expect("exact zero-argument end context"),
        Value::Object(end_writable)
    );
    assert_eq!(end_core.stream_state_label(end_writable), context);
    assert_eq!(
        end_core.estimated_memory_bytes(),
        end_core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn repeated_writable_end_callback_has_exact_node_charge_and_atomic_refusal_bd_fw7zd_1() {
    let module = test_module_with_functions(Vec::new(), Vec::new());
    let mut core = test_interpreter();
    let Value::Object(writable) = core
        .construct_stream_writable(RegRange { start: 0, count: 0 })
        .expect("generic Writable")
    else {
        panic!("Writable constructor must return an object");
    };
    let callback =
        Value::BuiltinFunction(BuiltinFunction::new_kind(BuiltinFunctionKind::ArrayIsArray));
    let repeated_callback_bytes = MEMORY_ESTIMATE_WRITABLE_END_CALLBACK_BYTES
        .saturating_add(InterpreterCore::estimate_writable_value_bytes(&callback));
    core.write_reg(0, callback.clone())
        .expect("first callback register");
    core.writable_end(
        &module,
        Value::Object(writable),
        RegRange { start: 0, count: 1 },
    )
    .expect("first end callback");
    assert_eq!(core.writable_streams[&writable].end_callbacks.len(), 1);

    core.write_reg(1, callback.clone())
        .expect("second callback register");
    let before_second = core.estimated_memory_bytes();
    core.config.max_total_memory_bytes = before_second.saturating_add(repeated_callback_bytes);
    core.writable_end(
        &module,
        Value::Object(writable),
        RegRange { start: 1, count: 1 },
    )
    .expect("one exact charged node must fit at its ceiling");
    assert_eq!(core.writable_streams[&writable].end_callbacks.len(), 2);
    assert_eq!(
        core.estimated_memory_bytes(),
        before_second + repeated_callback_bytes
    );
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );

    core.config.max_total_memory_bytes = u64::MAX;
    core.drain_runtime_checkpoint(Some(&module))
        .expect("repeated terminal callback lifecycle");
    assert!(!core.writable_streams.contains_key(&writable));
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );

    let mut refusal_core = test_interpreter();
    let Value::Object(refusal_writable) = refusal_core
        .construct_stream_writable(RegRange { start: 0, count: 0 })
        .expect("refusal Writable")
    else {
        panic!("Writable constructor must return an object");
    };
    refusal_core
        .write_reg(0, callback.clone())
        .expect("refusal first callback register");
    refusal_core
        .writable_end(
            &module,
            Value::Object(refusal_writable),
            RegRange { start: 0, count: 1 },
        )
        .expect("refusal first end callback");
    let refusal_state = format!("{:?}", refusal_core.writable_streams[&refusal_writable]);
    refusal_core
        .write_reg(1, callback)
        .expect("refusal second callback register");
    let refusal_bytes = refusal_core.estimated_memory_bytes();
    refusal_core.config.max_total_memory_bytes = refusal_bytes
        .saturating_add(repeated_callback_bytes)
        .saturating_sub(1);
    assert!(matches!(
        refusal_core.writable_end(
            &module,
            Value::Object(refusal_writable),
            RegRange { start: 1, count: 1 },
        ),
        Err(InterpreterError::MemoryBudgetExceeded { .. })
    ));
    assert_eq!(
        format!("{:?}", refusal_core.writable_streams[&refusal_writable]),
        refusal_state
    );
    assert_eq!(refusal_core.estimated_memory_bytes(), refusal_bytes);
    assert_eq!(
        refusal_core.estimated_memory_bytes(),
        refusal_core.recompute_estimated_memory_bytes()
    );

    // Raising the ceiling by exactly one deterministic node plus its
    // retained callback owner turns the same append into a success; there
    // is no hidden replacement peak.
    refusal_core.config.max_total_memory_bytes =
        refusal_bytes.saturating_add(repeated_callback_bytes);
    refusal_core
        .writable_end(
            &module,
            Value::Object(refusal_writable),
            RegRange { start: 1, count: 1 },
        )
        .expect("exact node charge must be sufficient");
    assert_eq!(
        refusal_core.writable_streams[&refusal_writable]
            .end_callbacks
            .len(),
        2
    );
    assert_eq!(
        refusal_core.estimated_memory_bytes(),
        refusal_bytes + repeated_callback_bytes
    );
    assert_eq!(
        refusal_core.estimated_memory_bytes(),
        refusal_core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn writable_terminal_tombstone_is_accounted_atomic_and_reset_safe_bd_fw7zd_2() {
    assert!(
        usize::try_from(MEMORY_ESTIMATE_WRITABLE_BASE_BYTES)
            .expect("live Writable base charge fits usize")
            >= std::mem::size_of::<WritableState>()
                .saturating_add(MEMORY_ESTIMATE_WRITABLE_MAP_ENTRY_MARGIN_BYTES),
        "the fixed live charge covers inline state and map-entry margin before dynamic payloads"
    );
    assert!(
        usize::try_from(MEMORY_ESTIMATE_WRITABLE_TERMINAL_BASE_BYTES)
            .expect("terminal Writable base charge fits usize")
            >= std::mem::size_of::<WritableTerminalState>()
                .saturating_add(MEMORY_ESTIMATE_WRITABLE_MAP_ENTRY_MARGIN_BYTES),
        "the fixed terminal charge covers retained inline state and map-entry margin before dynamic payloads"
    );
    assert!(
        usize::try_from(MEMORY_ESTIMATE_WRITABLE_END_CALLBACK_BYTES)
            .expect("terminal callback node charge fits usize")
            >= std::mem::size_of::<WritableTerminalCallbackRecord>()
                .saturating_add(2 * std::mem::size_of::<usize>()),
        "the terminal callback charge covers the record and linked-list pointers"
    );
    let module = test_module_with_functions(Vec::new(), Vec::new());
    let mut core = test_interpreter();
    let seed = core
        .capture_execution_seed()
        .expect("test execution-seed capture must fit");
    let Value::Object(writable) = core
        .construct_stream_writable(RegRange { start: 0, count: 0 })
        .expect("generic Writable")
    else {
        panic!("Writable constructor must return an object");
    };
    let terminal_label = Label::Custom {
        name: "terminal-secret".to_string(),
        level: 4,
    };
    {
        let state = core
            .writable_streams
            .get_mut(&writable)
            .expect("live Writable before terminalization");
        state.end_requested = true;
        state.finished = true;
        state.final_status = WritableFinalStatus::Done;
        state.prefinish_emitted = true;
        state.tick_phase = WritableTickPhase::Release;
        state.lifecycle_label = terminal_label.clone();
    }
    core.sync_estimated_memory_bytes()
        .expect("custom terminal label accounting");
    let before_terminalization = core.estimated_memory_bytes();
    let live_bytes =
        InterpreterCore::estimate_writable_state_bytes(&core.writable_streams[&writable]);

    core.terminalize_writable_state_storage(writable)
        .expect("normal live-to-terminal conversion");
    assert!(!core.writable_streams.contains_key(&writable));
    let tombstone = core
        .writable_terminal_states
        .get(&writable)
        .expect("accounted terminal tombstone");
    let tombstone_bytes = InterpreterCore::estimate_writable_terminal_state_bytes(tombstone);
    assert_eq!(
        core.estimated_memory_bytes(),
        before_terminalization - live_bytes + tombstone_bytes
    );
    assert_eq!(
        core.writable_state_view_value(writable, "writableFinished"),
        Some(Value::Bool(true))
    );
    assert_eq!(
        core.writable_state_view_value(writable, "destroyed"),
        Some(Value::Bool(true))
    );
    assert_eq!(core.stream_state_label(writable), terminal_label);
    assert_eq!(
        core.writable_receiver_id(Value::Object(writable)),
        Ok(writable),
        "terminal branding must not depend on a forgeable heap tag"
    );
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );

    core.remove_object_property(writable, "closed")
        .expect("delete forgeable closed mirror");
    let inherited = core
        .alloc_object_with_prototype(Some(writable))
        .expect("object inheriting a terminal Writable");
    assert_eq!(
        core.prototype_chain_get(inherited, "closed")
            .expect("inherited authoritative state read"),
        Value::Bool(true)
    );
    assert_eq!(core.stream_state_label(inherited), terminal_label);
    let proxy_handler = core
        .alloc_object_with_prototype(None)
        .expect("transparent Proxy handler");
    let transparent_proxy = core
        .create_proxy_object(writable, proxy_handler)
        .expect("transparent Proxy over terminal Writable");
    assert_eq!(
        core.stream_state_label(transparent_proxy),
        terminal_label,
        "Proxy target edges retain terminal lifecycle provenance"
    );
    core.write_reg(0, Value::Object(inherited))
        .expect("Reflect.has receiver");
    core.write_reg(1, Value::str("closed"))
        .expect("Reflect.has key");
    core.pending_hostcall_result_label = None;
    assert_eq!(
        core.dispatch_builtin_hostcall(
            "builtin:ReflectHas",
            RegRange { start: 0, count: 2 },
            Some(&module),
        )
        .expect("Reflect.has on terminal Writable"),
        Value::Bool(true)
    );
    assert_eq!(
        core.pending_hostcall_result_label,
        Some(terminal_label.clone()),
        "reflective state observations retain the terminal lifecycle label"
    );

    let callback = WritableCallbackRecord {
        value: Value::BuiltinFunction(BuiltinFunction::new_kind(BuiltinFunctionKind::ArrayIsArray)),
        label: Label::Secret,
        module_specifier: None,
    };
    let callback_charge = MEMORY_ESTIMATE_WRITABLE_END_CALLBACK_BYTES
        .saturating_add(InterpreterCore::estimate_writable_callback_bytes(&callback));
    let before_append = core.estimated_memory_bytes();
    let before_state = core.writable_terminal_states[&writable].clone();
    let before_sequence = core.next_writable_tick_sequence;
    core.config.max_total_memory_bytes = before_append
        .saturating_add(callback_charge)
        .saturating_sub(1);
    assert!(matches!(
        core.append_writable_terminal_callback(
            writable,
            callback.clone(),
            WritableTerminalCallbackError::EndAfterFinish,
            Label::Secret,
        ),
        Err(InterpreterError::MemoryBudgetExceeded { .. })
    ));
    assert_eq!(core.writable_terminal_states[&writable], before_state);
    assert_eq!(core.estimated_memory_bytes(), before_append);
    assert_eq!(core.next_writable_tick_sequence, before_sequence);
    assert_eq!(core.pending_writable_terminal_ticks, 0);

    core.config.max_total_memory_bytes = before_append.saturating_add(callback_charge);
    core.append_writable_terminal_callback(
        writable,
        callback,
        WritableTerminalCallbackError::EndAfterFinish,
        Label::Secret,
    )
    .expect("exact callback charge must fit");
    assert_eq!(
        core.estimated_memory_bytes(),
        before_append + callback_charge
    );
    assert_eq!(core.pending_writable_terminal_ticks, 1);
    assert!(
        core.writable_terminal_states[&writable]
            .tick_sequence
            .is_some()
    );
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );

    core.config.max_total_memory_bytes = u64::MAX;
    core.drain_runtime_checkpoint(Some(&module))
        .expect("post-close callback checkpoint");
    assert!(
        core.writable_terminal_states[&writable]
            .callbacks
            .is_empty()
    );
    assert_eq!(core.pending_writable_terminal_ticks, 0);
    assert_eq!(core.estimated_memory_bytes(), before_append);

    core.reset_execution_state_from_seed(&seed)
        .expect("seed reset clears terminal Writable state");
    assert!(!core.writable_terminal_states.contains_key(&writable));
    assert_eq!(core.pending_writable_terminal_ticks, 0);
    let replacement = core
        .alloc_object_with_prototype(None)
        .expect("ordinary replacement object after reset");
    assert_eq!(replacement, writable, "reset must permit ObjectId reuse");
    assert!(matches!(
        core.writable_receiver_id(Value::Object(replacement)),
        Err(InterpreterError::TypeError { .. })
    ));
    assert_eq!(core.stream_state_label(replacement), Label::Public);

    core.reset_execution_state_from_seed(&seed)
        .expect("second seed reset before branded ObjectId reuse");
    let Value::Object(reused_writable) = core
        .construct_stream_writable(RegRange { start: 0, count: 0 })
        .expect("Writable after terminal ObjectId reset")
    else {
        panic!("Writable constructor must return an object");
    };
    assert_eq!(reused_writable, writable);
    assert!(core.writable_streams.contains_key(&reused_writable));
    assert!(!core.writable_terminal_states.contains_key(&reused_writable));
    assert_eq!(core.stream_state_label(reused_writable), Label::Public);
    assert_eq!(core.pending_writable_terminal_ticks, 0);
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn writable_write_and_final_errors_progress_at_exact_memory_ceiling_bd_fw7zd() {
    let module = test_module_with_functions(Vec::new(), Vec::new());

    let mut write_core = test_interpreter();
    let Value::Object(write_stream) = write_core
        .construct_stream_writable(RegRange { start: 0, count: 0 })
        .expect("write-error Writable")
    else {
        panic!("Writable constructor must return an object");
    };
    write_core
        .insert_event_listener(
            write_stream,
            "error",
            EventListenerRecord {
                listener: Value::BuiltinFunction(BuiltinFunction::new_kind(
                    BuiltinFunctionKind::ArrayIsArray,
                )),
                once: false,
            },
            false,
        )
        .expect("handled write error listener");
    write_core
        .writable_enqueue(write_stream, Value::str("x"), Label::Public, None)
        .expect("write-error record");
    {
        let state = write_core
            .writable_streams
            .get_mut(&write_stream)
            .expect("write-error state");
        state.writes[0].status = WritableWriteStatus::Active(21);
        state.end_requested = true;
        state.final_status = WritableFinalStatus::Done;
    }
    let write_error = Value::str("ceiling-write-error");
    write_core
        .write_reg(0, write_error.clone())
        .expect("write error argument");
    let retained_write_error_bytes = InterpreterCore::estimate_writable_value_bytes(&write_error)
        .saturating_add(InterpreterCore::estimate_label_bytes(
            write_core.get_register_label(0).expect("write error label"),
        ));
    write_core.config.max_total_memory_bytes = write_core
        .estimated_memory_bytes()
        .saturating_add(retained_write_error_bytes);
    let write_completion = BuiltinFunction::writable_completion(
        BuiltinFunctionKind::StreamWritableWriteDone,
        write_stream,
        21,
    );
    write_core
        .writable_write_done(&module, &write_completion, RegRange { start: 0, count: 1 })
        .expect("write callback(error) must progress at the exact ceiling");
    assert_eq!(
        write_core.writable_streams[&write_stream].writes[0].status,
        WritableWriteStatus::Completed
    );
    assert!(write_core.writable_streams[&write_stream].writes[0].completion_failed);
    assert_eq!(
        write_core
            .read_reg(0)
            .expect("retained write error argument"),
        write_error
    );
    write_core.config.max_total_memory_bytes = u64::MAX;
    write_core
        .drain_runtime_checkpoint(Some(&module))
        .expect("handled write error lifecycle");
    assert!(!write_core.writable_streams.contains_key(&write_stream));

    let mut final_core = test_interpreter();
    let Value::Object(final_stream) = final_core
        .construct_stream_writable(RegRange { start: 0, count: 0 })
        .expect("final-error Writable")
    else {
        panic!("Writable constructor must return an object");
    };
    final_core
        .insert_event_listener(
            final_stream,
            "error",
            EventListenerRecord {
                listener: Value::BuiltinFunction(BuiltinFunction::new_kind(
                    BuiltinFunctionKind::ArrayIsArray,
                )),
                once: false,
            },
            false,
        )
        .expect("handled final error listener");
    {
        let state = final_core
            .writable_streams
            .get_mut(&final_stream)
            .expect("final-error state");
        state.end_requested = true;
        state.final_status = WritableFinalStatus::Active(22);
    }
    let final_error = Value::str("ceiling-final-error");
    final_core
        .write_reg(0, final_error.clone())
        .expect("final error argument");
    let retained_final_error_bytes = InterpreterCore::estimate_writable_value_bytes(&final_error)
        .saturating_add(InterpreterCore::estimate_label_bytes(
            final_core.get_register_label(0).expect("final error label"),
        ));
    final_core.config.max_total_memory_bytes = final_core
        .estimated_memory_bytes()
        .saturating_add(retained_final_error_bytes);
    let final_completion = BuiltinFunction::writable_completion(
        BuiltinFunctionKind::StreamWritableFinalDone,
        final_stream,
        22,
    );
    final_core
        .writable_final_done(&module, &final_completion, RegRange { start: 0, count: 1 })
        .expect("final callback(error) must progress at the exact ceiling");
    assert_eq!(
        final_core.writable_streams[&final_stream].final_status,
        WritableFinalStatus::Done
    );
    assert_eq!(
        final_core
            .read_reg(0)
            .expect("retained final error argument"),
        final_error
    );
    final_core.config.max_total_memory_bytes = u64::MAX;
    final_core
        .drain_runtime_checkpoint(Some(&module))
        .expect("handled final error lifecycle");
    assert!(!final_core.writable_streams.contains_key(&final_stream));

    let mut refusal_core = test_interpreter();
    let Value::Object(refusal_stream) = refusal_core
        .construct_stream_writable(RegRange { start: 0, count: 0 })
        .expect("refusal Writable")
    else {
        panic!("Writable constructor must return an object");
    };
    refusal_core
        .writable_enqueue(refusal_stream, Value::str("x"), Label::Public, None)
        .expect("refusal record");
    refusal_core
        .writable_streams
        .get_mut(&refusal_stream)
        .expect("refusal state")
        .writes[0]
        .status = WritableWriteStatus::Active(23);
    refusal_core
        .write_reg(0, Value::Int(1))
        .expect("zero-byte error value");
    let refusal_label = Label::Custom {
        name: "ceiling-label".repeat(32),
        level: 3,
    };
    refusal_core
        .set_register_label(0, refusal_label.clone())
        .expect("large error label");
    refusal_core.config.max_total_memory_bytes = refusal_core.estimated_memory_bytes();
    let refusal_completion = BuiltinFunction::writable_completion(
        BuiltinFunctionKind::StreamWritableWriteDone,
        refusal_stream,
        23,
    );
    let refusal_bytes = refusal_core.estimated_memory_bytes();
    let requested_bytes = match refusal_core.writable_write_done(
        &module,
        &refusal_completion,
        RegRange { start: 0, count: 1 },
    ) {
        Err(InterpreterError::MemoryBudgetExceeded {
            requested_bytes, ..
        }) => requested_bytes,
        other => panic!("expected atomic completion refusal, got {other:?}"),
    };
    assert_eq!(
        refusal_core.writable_streams[&refusal_stream].writes[0].status,
        WritableWriteStatus::Active(23)
    );
    assert!(!refusal_core.writable_streams[&refusal_stream].writes[0].completion_failed);
    assert_eq!(
        refusal_core.read_reg(0).expect("refused error argument"),
        Value::Int(1)
    );
    assert_eq!(
        refusal_core.writable_streams[&refusal_stream].lifecycle_label,
        Label::Public
    );
    assert_eq!(refusal_core.estimated_memory_bytes(), refusal_bytes);

    refusal_core.config.max_total_memory_bytes = requested_bytes;
    refusal_core
        .writable_write_done(
            &module,
            &refusal_completion,
            RegRange { start: 0, count: 1 },
        )
        .expect("the exact retained completion charge must succeed");
    assert_eq!(
        refusal_core.writable_streams[&refusal_stream].writes[0].status,
        WritableWriteStatus::Completed
    );
    assert!(refusal_core.writable_streams[&refusal_stream].writes[0].completion_failed);
    assert_eq!(
        refusal_core.read_reg(0).expect("retained error argument"),
        Value::Int(1)
    );
    assert_eq!(
        refusal_core
            .get_register_label(0)
            .expect("retained error argument label"),
        &refusal_label
    );

    let mut final_refusal_core = test_interpreter();
    let Value::Object(final_refusal_stream) = final_refusal_core
        .construct_stream_writable(RegRange { start: 0, count: 0 })
        .expect("final refusal Writable")
    else {
        panic!("Writable constructor must return an object");
    };
    {
        let state = final_refusal_core
            .writable_streams
            .get_mut(&final_refusal_stream)
            .expect("final refusal state");
        state.end_requested = true;
        state.final_status = WritableFinalStatus::Active(24);
    }
    final_refusal_core
        .write_reg(0, Value::Int(2))
        .expect("zero-byte final error value");
    let final_refusal_label = Label::Custom {
        name: "final-ceiling-label".repeat(32),
        level: 4,
    };
    final_refusal_core
        .set_register_label(0, final_refusal_label.clone())
        .expect("large final error label");
    final_refusal_core.config.max_total_memory_bytes = final_refusal_core.estimated_memory_bytes();
    let final_refusal_bytes = final_refusal_core.estimated_memory_bytes();
    let final_refusal_completion = BuiltinFunction::writable_completion(
        BuiltinFunctionKind::StreamWritableFinalDone,
        final_refusal_stream,
        24,
    );
    let final_requested_bytes = match final_refusal_core.writable_final_done(
        &module,
        &final_refusal_completion,
        RegRange { start: 0, count: 1 },
    ) {
        Err(InterpreterError::MemoryBudgetExceeded {
            requested_bytes, ..
        }) => requested_bytes,
        other => panic!("expected atomic final refusal, got {other:?}"),
    };
    assert_eq!(
        final_refusal_core.writable_streams[&final_refusal_stream].final_status,
        WritableFinalStatus::Active(24)
    );
    assert_eq!(
        final_refusal_core
            .read_reg(0)
            .expect("refused final error argument"),
        Value::Int(2)
    );
    assert_eq!(
        final_refusal_core.writable_streams[&final_refusal_stream].lifecycle_label,
        Label::Public
    );
    assert_eq!(
        final_refusal_core.estimated_memory_bytes(),
        final_refusal_bytes
    );

    final_refusal_core.config.max_total_memory_bytes = final_requested_bytes;
    final_refusal_core
        .writable_final_done(
            &module,
            &final_refusal_completion,
            RegRange { start: 0, count: 1 },
        )
        .expect("the exact retained final charge must succeed");
    assert_eq!(
        final_refusal_core.writable_streams[&final_refusal_stream].final_status,
        WritableFinalStatus::Done
    );
    assert_eq!(
        final_refusal_core
            .read_reg(0)
            .expect("retained final error argument"),
        Value::Int(2)
    );
    assert_eq!(
        final_refusal_core
            .get_register_label(0)
            .expect("retained final error argument label"),
        &final_refusal_label
    );

    let mut overflow_core = test_interpreter();
    let Value::Object(overflow_stream) = overflow_core
        .construct_stream_writable(RegRange { start: 0, count: 0 })
        .expect("sequence-overflow Writable")
    else {
        panic!("Writable constructor must return an object");
    };
    overflow_core
        .writable_enqueue(overflow_stream, Value::str("x"), Label::Public, None)
        .expect("sequence-overflow write");
    overflow_core
        .writable_streams
        .get_mut(&overflow_stream)
        .expect("sequence-overflow state")
        .writes[0]
        .status = WritableWriteStatus::Active(25);
    overflow_core
        .write_reg(0, Value::Int(3))
        .expect("sequence-overflow error");
    overflow_core
        .set_register_label(0, Label::Secret)
        .expect("sequence-overflow error label");
    overflow_core.next_writable_tick_sequence = u64::MAX;
    let overflow_state = format!("{:?}", overflow_core.writable_streams[&overflow_stream]);
    let overflow_bytes = overflow_core.estimated_memory_bytes();
    let overflow_completion = BuiltinFunction::writable_completion(
        BuiltinFunctionKind::StreamWritableWriteDone,
        overflow_stream,
        25,
    );
    assert!(matches!(
        overflow_core.writable_write_done(
            &module,
            &overflow_completion,
            RegRange { start: 0, count: 1 },
        ),
        Err(InterpreterError::InternalError { details })
            if details == "Writable tick sequence space exhausted"
    ));
    assert_eq!(
        format!("{:?}", overflow_core.writable_streams[&overflow_stream]),
        overflow_state
    );
    assert_eq!(
        overflow_core
            .read_reg(0)
            .expect("unconsumed overflow error"),
        Value::Int(3)
    );
    assert_eq!(overflow_core.get_register_label(0), Ok(&Label::Secret));
    assert_eq!(overflow_core.estimated_memory_bytes(), overflow_bytes);

    let mut record_overflow_core = test_interpreter();
    let Value::Object(record_overflow_stream) = record_overflow_core
        .construct_stream_writable(RegRange { start: 0, count: 0 })
        .expect("record-overflow Writable")
    else {
        panic!("Writable constructor must return an object");
    };
    record_overflow_core.next_writable_tick_sequence = u64::MAX;
    let record_overflow_state = format!(
        "{:?}",
        record_overflow_core.writable_streams[&record_overflow_stream]
    );
    let record_overflow_bytes = record_overflow_core.estimated_memory_bytes();
    assert!(matches!(
        record_overflow_core.record_writable_terminal_error(
            record_overflow_stream,
            Value::BigInt(Arc::from("7".repeat(256))),
            Label::Custom {
                name: "record-overflow-label".repeat(16),
                level: 4,
            },
            WritableErrorOrigin::Final,
            false,
        ),
        Err(InterpreterError::InternalError { details })
            if details == "Writable tick sequence space exhausted"
    ));
    assert_eq!(
        format!(
            "{:?}",
            record_overflow_core.writable_streams[&record_overflow_stream]
        ),
        record_overflow_state
    );
    assert_eq!(
        record_overflow_core.estimated_memory_bytes(),
        record_overflow_bytes
    );

    let pending_digits = "8".repeat(256);
    let pending_label_name = "pending-overflow-label".repeat(16);
    record_overflow_core
        .replace_pending_abrupt_slots(
            Some((
                Value::BigInt(Arc::from(pending_digits.clone())),
                Label::Custom {
                    name: pending_label_name.clone(),
                    level: 5,
                },
            )),
            None,
        )
        .expect("accounted pending overflow exception");
    let pending_overflow_bytes = record_overflow_core.estimated_memory_bytes();
    let (pending_error, pending_label, consumes_pending_exception) = record_overflow_core
        .writable_invocation_error_value(
            &InterpreterError::UncaughtException {
                value: "pending-overflow".to_string(),
            },
            Label::Public,
        );
    assert!(consumes_pending_exception);
    assert_eq!(record_overflow_core.pending_exception, None);
    assert_eq!(record_overflow_core.pending_exception_label, Label::Public);
    assert!(matches!(
        record_overflow_core.record_writable_terminal_error(
            record_overflow_stream,
            pending_error,
            pending_label,
            WritableErrorOrigin::Final,
            consumes_pending_exception,
        ),
        Err(InterpreterError::InternalError { details })
            if details == "Writable tick sequence space exhausted"
    ));
    assert_eq!(
        record_overflow_core.pending_exception,
        Some(Value::BigInt(Arc::from(pending_digits)))
    );
    assert_eq!(
        record_overflow_core.pending_exception_label,
        Label::Custom {
            name: pending_label_name,
            level: 5,
        }
    );
    assert_eq!(
        format!(
            "{:?}",
            record_overflow_core.writable_streams[&record_overflow_stream]
        ),
        record_overflow_state
    );
    assert_eq!(
        record_overflow_core.estimated_memory_bytes(),
        pending_overflow_bytes
    );

    for (name, core) in [
        ("write", &write_core),
        ("final", &final_core),
        ("refusal", &refusal_core),
        ("final-refusal", &final_refusal_core),
        ("overflow", &overflow_core),
        ("record-overflow", &record_overflow_core),
    ] {
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes(),
            "{name}: live={} terminal={} in_flight={} listeners={}",
            core.writable_streams_memory_bytes(),
            core.writable_terminal_states_memory_bytes(),
            core.writable_in_flight_callback_bytes,
            core.event_listeners_memory_bytes(),
        );
    }
}

#[test]
fn writable_guest_failures_leave_the_next_phase_scheduled_bd_fw7zd() {
    let module = test_module_with_functions(Vec::new(), Vec::new());
    let throwing_listener = || EventListenerRecord {
        listener: Value::BuiltinFunction(BuiltinFunction::new_kind(
            BuiltinFunctionKind::StreamReadablePause,
        )),
        once: false,
    };

    let mut callback_core = test_interpreter();
    let Value::Object(callback_writable) = callback_core
        .construct_stream_writable(RegRange { start: 0, count: 0 })
        .expect("callback Writable")
    else {
        panic!("Writable constructor must return an object");
    };
    callback_core
        .writable_enqueue(
            callback_writable,
            Value::str("x"),
            Label::Public,
            Some(WritableCallbackRecord {
                value: throwing_listener().listener,
                label: Label::Public,
                module_specifier: None,
            }),
        )
        .expect("callback write enqueue");
    {
        let state = callback_core
            .writable_streams
            .get_mut(&callback_writable)
            .expect("callback state");
        state.writes[0].status = WritableWriteStatus::Completed;
        state.buffered_length = 0;
        state.end_requested = true;
        state.final_status = WritableFinalStatus::Done;
        state.tick_sequence = None;
    }
    assert!(matches!(
        callback_core.drive_writable_tick(callback_writable, Some(&module)),
        Err(InterpreterError::TypeError { .. })
    ));
    assert!(
        callback_core.writable_streams[&callback_writable]
            .tick_sequence
            .is_some()
    );
    callback_core
        .drain_runtime_checkpoint(Some(&module))
        .expect("throwing write callback must not strand finish/close");
    assert!(
        !callback_core
            .writable_streams
            .contains_key(&callback_writable)
    );

    let mut prefinish_core = test_interpreter();
    let Value::Object(prefinish_writable) = prefinish_core
        .construct_stream_writable(RegRange { start: 0, count: 0 })
        .expect("prefinish Writable")
    else {
        panic!("Writable constructor must return an object");
    };
    prefinish_core
        .insert_event_listener(prefinish_writable, "prefinish", throwing_listener(), false)
        .expect("prefinish listener");
    {
        let state = prefinish_core
            .writable_streams
            .get_mut(&prefinish_writable)
            .expect("prefinish state");
        state.end_requested = true;
        state.final_status = WritableFinalStatus::Done;
    }
    assert!(matches!(
        prefinish_core.emit_writable_prefinish(prefinish_writable, &module),
        Err(InterpreterError::TypeError { .. })
    ));
    let state = &prefinish_core.writable_streams[&prefinish_writable];
    assert!(state.prefinish_emitted);
    assert!(state.tick_sequence.is_some());
    prefinish_core
        .drain_runtime_checkpoint(Some(&module))
        .expect("throwing prefinish listener must not strand finish/close");
    assert!(
        !prefinish_core
            .writable_streams
            .contains_key(&prefinish_writable)
    );

    let mut finish_core = test_interpreter();
    let Value::Object(finish_writable) = finish_core
        .construct_stream_writable(RegRange { start: 0, count: 0 })
        .expect("finish Writable")
    else {
        panic!("Writable constructor must return an object");
    };
    finish_core
        .insert_event_listener(finish_writable, "finish", throwing_listener(), false)
        .expect("finish listener");
    {
        let state = finish_core
            .writable_streams
            .get_mut(&finish_writable)
            .expect("finish state");
        state.end_requested = true;
        state.final_status = WritableFinalStatus::Done;
        state.tick_phase = WritableTickPhase::Finish;
    }
    assert!(matches!(
        finish_core.drive_writable_tick(finish_writable, Some(&module)),
        Err(InterpreterError::TypeError { .. })
    ));
    let state = &finish_core.writable_streams[&finish_writable];
    assert_eq!(state.tick_phase, WritableTickPhase::Close);
    assert!(state.tick_sequence.is_some());
    finish_core
        .drain_runtime_checkpoint(Some(&module))
        .expect("throwing finish listener must not strand close");
    assert!(!finish_core.writable_streams.contains_key(&finish_writable));

    for core in [&callback_core, &prefinish_core, &finish_core] {
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }
}

#[test]
fn native_writable_terminal_callback_stops_its_batch_bd_9vouw_7() {
    let module = test_module_with_functions(Vec::new(), Vec::new());
    for console_allowed in [false, true] {
        let mut core = test_interpreter();
        if console_allowed {
            core.config
                .granted_capabilities
                .insert(RuntimeCapability::Console);
        }
        let Value::Object(writable) = core
            .construct_stream_writable(RegRange { start: 0, count: 0 })
            .expect("native Writable")
        else {
            panic!("Writable constructor must return an object");
        };
        {
            let state = core
                .writable_streams
                .get_mut(&writable)
                .expect("native state");
            state.end_requested = true;
            state.final_status = WritableFinalStatus::Done;
            state.tick_phase = WritableTickPhase::Callbacks;
            for _ in 0..2 {
                state.end_callbacks.push_back(WritableEndCallbackRecord {
                    callback: WritableCallbackRecord {
                        value: Value::BuiltinFunction(BuiltinFunction::new_kind(
                            BuiltinFunctionKind::ConsoleLog,
                        )),
                        label: Label::Public,
                        module_specifier: None,
                    },
                    registered_after_end: false,
                });
            }
        }
        core.sync_estimated_memory_bytes()
            .expect("account callback batch");
        core.schedule_writable_tick(writable)
            .expect("schedule callback batch");
        let prior_decisions = core.hostcall_decisions.len();
        let outcome = core.drain_runtime_checkpoint(Some(&module));
        if console_allowed {
            outcome.expect("allowed native callbacks drain normally");
            assert_eq!(core.hostcall_decisions.len(), prior_decisions + 2);
            assert!(!core.writable_streams.contains_key(&writable));
        } else {
            assert!(matches!(
                outcome,
                Err(InterpreterError::CapabilityDenied { capability, .. })
                    if capability == "console:log"
            ));
            assert_eq!(core.hostcall_decisions.len(), prior_decisions + 1);
            assert_eq!(core.writable_streams[&writable].end_callbacks.len(), 1);
            assert_eq!(
                core.writable_streams[&writable].tick_phase,
                WritableTickPhase::Finish
            );
        }
        assert_eq!(core.writable_in_flight_callback_bytes, 0);
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }
}

#[test]
fn native_writable_final_does_not_convert_terminal_denial_to_stream_error_bd_9vouw_7() {
    let module = test_module_with_functions(Vec::new(), Vec::new());
    for console_allowed in [false, true] {
        let mut core = test_interpreter();
        if console_allowed {
            core.config
                .granted_capabilities
                .insert(RuntimeCapability::Console);
        }
        let Value::Object(writable) = core
            .construct_stream_writable(RegRange { start: 0, count: 0 })
            .expect("native Writable")
        else {
            panic!("Writable constructor must return an object");
        };
        {
            let state = core
                .writable_streams
                .get_mut(&writable)
                .expect("native state");
            state.end_requested = true;
            state.final_callback = Some(Value::BuiltinFunction(BuiltinFunction::new_kind(
                BuiltinFunctionKind::ConsoleLog,
            )));
        }
        core.sync_estimated_memory_bytes()
            .expect("account final callback");
        let prior_decisions = core.hostcall_decisions.len();
        let outcome = core.drive_writable(writable, &module);
        if console_allowed {
            outcome.expect("allowed final callback runs");
        } else {
            assert!(matches!(
                outcome,
                Err(InterpreterError::CapabilityDenied { capability, .. })
                    if capability == "console:log"
            ));
        }
        assert_eq!(core.hostcall_decisions.len(), prior_decisions + 1);
        assert!(core.writable_streams[&writable].terminal_error.is_none());
        assert!(
            core.writable_streams[&writable]
                .terminal_error_origin
                .is_none()
        );
        assert_eq!(core.writable_in_flight_callback_bytes, 0);
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }
}

#[test]
fn throwing_terminal_callback_does_not_mask_stream_error_lifecycle_bd_fw7zd_1() {
    let module = test_module_with_functions(Vec::new(), Vec::new());
    let mut core = test_interpreter();
    let Value::Object(writable) = core
        .construct_stream_writable(RegRange { start: 0, count: 0 })
        .expect("terminal-error Writable")
    else {
        panic!("Writable constructor must return an object");
    };
    core.insert_event_listener(
        writable,
        "error",
        EventListenerRecord {
            listener: Value::BuiltinFunction(BuiltinFunction::new_kind(
                BuiltinFunctionKind::ArrayIsArray,
            )),
            once: false,
        },
        false,
    )
    .expect("handled stream error listener");
    {
        let state = core
            .writable_streams
            .get_mut(&writable)
            .expect("live terminal-error Writable");
        state.end_requested = true;
        state.final_status = WritableFinalStatus::Done;
        state.terminal_error = Some((Value::str("write failed"), Label::Secret));
        state.terminal_error_origin = Some(WritableErrorOrigin::Write);
        state.end_callbacks.push_back(WritableEndCallbackRecord {
            callback: WritableCallbackRecord {
                value: Value::BuiltinFunction(BuiltinFunction::new_kind(
                    BuiltinFunctionKind::ArrayIsArray,
                )),
                label: Label::Secret,
                module_specifier: None,
            },
            registered_after_end: false,
        });
        state.end_callbacks.push_back(WritableEndCallbackRecord {
            callback: WritableCallbackRecord {
                value: Value::BuiltinFunction(BuiltinFunction::new_kind(
                    BuiltinFunctionKind::StreamReadablePause,
                )),
                label: Label::Secret,
                module_specifier: None,
            },
            registered_after_end: false,
        });
    }
    core.sync_estimated_memory_bytes()
        .expect("terminal-error state accounting");
    core.schedule_writable_tick(writable)
        .expect("terminal-error callback tick");

    assert!(matches!(
        core.drain_runtime_checkpoint(Some(&module)),
        Err(InterpreterError::TypeError { .. })
    ));
    assert!(
        !core.writable_streams.contains_key(&writable),
        "a callback failure must remain reportable without masking handled error/close/release"
    );
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn writable_error_drains_every_queued_callback_before_terminal_cleanup_bd_fw7zd() {
    let module = test_module_with_functions(Vec::new(), Vec::new());
    let mut core = test_interpreter();
    let Value::Object(writable) = core
        .construct_stream_writable(RegRange { start: 0, count: 0 })
        .expect("generic Writable")
    else {
        panic!("Writable constructor must return an object");
    };
    let callback = || WritableCallbackRecord {
        value: Value::BuiltinFunction(BuiltinFunction::new_kind(BuiltinFunctionKind::ArrayIsArray)),
        label: Label::Secret,
        module_specifier: None,
    };
    for chunk in ["first", "second", "third"] {
        core.writable_enqueue(writable, Value::str(chunk), Label::Secret, Some(callback()))
            .expect("queued write");
    }
    let state = core
        .writable_streams
        .get_mut(&writable)
        .expect("live Writable state");
    state.writes[0].status = WritableWriteStatus::Completed;
    state.writes[1].status = WritableWriteStatus::Active(9);
    state.writes[2].status = WritableWriteStatus::Pending;
    state.buffered_length = state.writes[1].units + state.writes[2].units;
    state.end_requested = true;
    state.final_status = WritableFinalStatus::Done;
    state.end_callbacks.push_back(WritableEndCallbackRecord {
        callback: callback(),
        registered_after_end: false,
    });
    core.sync_estimated_memory_bytes()
        .expect("account arranged write queue");
    core.write_reg(10, Value::Object(writable))
        .expect("events.once receiver");
    core.write_reg(11, Value::str("never"))
        .expect("events.once event name");
    let Value::Promise(error_promise_id) = core
        .register_event_promise_once(RegRange {
            start: 10,
            count: 2,
        })
        .expect("unsettled Writable waiter")
    else {
        panic!("events.once must return a Promise");
    };

    core.write_reg(0, Value::str("write failed"))
        .expect("completion error register");
    core.set_register_label(0, Label::Secret)
        .expect("completion error label");
    let completion = BuiltinFunction::writable_completion(
        BuiltinFunctionKind::StreamWritableWriteDone,
        writable,
        9,
    );
    core.writable_write_done(&module, &completion, RegRange { start: 0, count: 1 })
        .expect("write failure must enter terminal drainage");

    let state = &core.writable_streams[&writable];
    assert!(
        state
            .writes
            .iter()
            .all(|record| record.status == WritableWriteStatus::Completed)
    );
    assert_eq!(state.buffered_length, 0);
    assert!(!state.writes[0].completion_failed);
    assert!(state.writes[1].completion_failed);
    assert!(state.writes[2].completion_failed);
    assert!(state.terminal_error.is_some());

    core.drain_runtime_checkpoint(Some(&module))
        .expect("events.once error link must handle and reject on terminal error");
    let error_promise = core
        .promise_store
        .get(crate::promise_model::PromiseHandle(error_promise_id))
        .expect("terminal error Promise");
    assert!(matches!(
        &error_promise.state,
        crate::promise_model::PromiseState::Rejected(
            crate::object_model::JsValue::Str(reason)
        ) if reason == "write failed"
    ));
    assert_eq!(error_promise.label, Label::Secret);
    assert!(
        !core.writable_streams.contains_key(&writable),
        "handled error must remain observable without stranding close/release"
    );
    assert!(
        !core.event_promise_waiters.contains_key(&writable),
        "terminal release must not leave a waiter keyed by a reusable ObjectId"
    );
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn writable_write_and_final_failures_preserve_node_phase_order_bd_fw7zd() {
    let write_module = writable_order_module(&["a", "b", "end", "error", "close"]);
    let mut write_core = test_interpreter();
    let write_log = install_writable_order_log(&mut write_core);
    let Value::Object(write_stream) = write_core
        .construct_stream_writable(RegRange { start: 0, count: 0 })
        .expect("write-failure Writable")
    else {
        panic!("Writable constructor must return an object");
    };
    for (chunk, function_index) in [("a", 0), ("b", 1)] {
        write_core
            .writable_enqueue(
                write_stream,
                Value::str(chunk),
                Label::Public,
                Some(WritableCallbackRecord {
                    value: Value::Function(function_index),
                    label: Label::Public,
                    module_specifier: None,
                }),
            )
            .expect("write-failure queue");
    }
    let state = write_core
        .writable_streams
        .get_mut(&write_stream)
        .expect("write-failure state");
    state.writes[0].status = WritableWriteStatus::Completed;
    state.writes[1].status = WritableWriteStatus::Active(11);
    state.buffered_length = state.writes[1].units;
    state.end_requested = true;
    state.final_status = WritableFinalStatus::Done;
    state.end_callbacks.push_back(WritableEndCallbackRecord {
        callback: WritableCallbackRecord {
            value: Value::Function(2),
            label: Label::Public,
            module_specifier: None,
        },
        registered_after_end: false,
    });
    write_core
        .sync_estimated_memory_bytes()
        .expect("write-failure state accounting");
    write_core
        .insert_event_listener(
            write_stream,
            "error",
            EventListenerRecord {
                listener: Value::Function(3),
                once: false,
            },
            false,
        )
        .expect("write error listener");
    write_core
        .insert_event_listener(
            write_stream,
            "close",
            EventListenerRecord {
                listener: Value::Function(4),
                once: false,
            },
            false,
        )
        .expect("write close listener");
    write_core
        .write_reg(0, Value::str("b"))
        .expect("write failure value");
    let write_completion = BuiltinFunction::writable_completion(
        BuiltinFunctionKind::StreamWritableWriteDone,
        write_stream,
        11,
    );
    write_core
        .writable_write_done(
            &write_module,
            &write_completion,
            RegRange { start: 0, count: 1 },
        )
        .expect("write failure completion");
    assert_eq!(
        write_core.writable_streams[&write_stream].terminal_error_origin,
        Some(WritableErrorOrigin::Write)
    );
    write_core
        .drain_runtime_checkpoint(Some(&write_module))
        .expect("handled write failure checkpoint");
    assert_eq!(
        writable_order_entries(&write_core, write_log),
        ["a", "b", "end", "error", "close"]
    );

    let final_module = writable_order_module(&["wcb", "error", "close", "endcb"]);
    let mut final_core = test_interpreter();
    let final_log = install_writable_order_log(&mut final_core);
    let Value::Object(final_stream) = final_core
        .construct_stream_writable(RegRange { start: 0, count: 0 })
        .expect("final-failure Writable")
    else {
        panic!("Writable constructor must return an object");
    };
    final_core
        .writable_enqueue(
            final_stream,
            Value::str("done"),
            Label::Public,
            Some(WritableCallbackRecord {
                value: Value::Function(0),
                label: Label::Public,
                module_specifier: None,
            }),
        )
        .expect("final-failure write");
    let state = final_core
        .writable_streams
        .get_mut(&final_stream)
        .expect("final-failure state");
    state.writes[0].status = WritableWriteStatus::Completed;
    state.buffered_length = 0;
    state.end_requested = true;
    state.final_status = WritableFinalStatus::Active(12);
    state.end_callbacks.push_back(WritableEndCallbackRecord {
        callback: WritableCallbackRecord {
            value: Value::Function(3),
            label: Label::Public,
            module_specifier: None,
        },
        registered_after_end: false,
    });
    final_core
        .sync_estimated_memory_bytes()
        .expect("final-failure state accounting");
    for (event, function_index) in [("error", 1), ("close", 2)] {
        final_core
            .insert_event_listener(
                final_stream,
                event,
                EventListenerRecord {
                    listener: Value::Function(function_index),
                    once: false,
                },
                false,
            )
            .expect("final-failure listener");
    }
    final_core
        .write_reg(0, Value::str("f"))
        .expect("final failure value");
    let final_completion = BuiltinFunction::writable_completion(
        BuiltinFunctionKind::StreamWritableFinalDone,
        final_stream,
        12,
    );
    final_core
        .writable_final_done(
            &final_module,
            &final_completion,
            RegRange { start: 0, count: 1 },
        )
        .expect("final failure completion");
    assert_eq!(
        final_core.writable_streams[&final_stream].terminal_error_origin,
        Some(WritableErrorOrigin::Final)
    );
    final_core
        .drain_runtime_checkpoint(Some(&final_module))
        .expect("handled final failure checkpoint");
    assert_eq!(
        writable_order_entries(&final_core, final_log),
        ["wcb", "error", "close", "endcb"]
    );

    for core in [&write_core, &final_core] {
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }
}

#[test]
fn writable_ticks_follow_monotonic_schedule_order_not_object_ids_bd_fw7zd() {
    let mut core = test_interpreter();
    let Value::Object(lower_id) = core
        .construct_stream_writable(RegRange { start: 0, count: 0 })
        .expect("first Writable")
    else {
        panic!("Writable constructor must return an object");
    };
    let Value::Object(higher_id) = core
        .construct_stream_writable(RegRange { start: 0, count: 0 })
        .expect("second Writable")
    else {
        panic!("Writable constructor must return an object");
    };
    assert!(lower_id < higher_id);

    core.schedule_writable_tick(higher_id)
        .expect("schedule higher ObjectId first");
    core.schedule_writable_tick(lower_id)
        .expect("schedule lower ObjectId second");
    assert!(
        core.writable_streams[&higher_id].tick_sequence
            < core.writable_streams[&lower_id].tick_sequence
    );
    assert_eq!(
        core.next_scheduled_writable_tick()
            .expect("charged Writable tick selection"),
        Some(higher_id)
    );
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes(),
        "fixed-size tick sequence metadata must not create an unaccounted queue"
    );
}

#[test]
fn writable_checkpoint_yields_between_stream_units_in_bun_order_bd_fw7zd() {
    let module = writable_order_module(&[
        "b:writecb",
        "a:writecb",
        "b:endcb1",
        "b:endcb2",
        "b:finish",
        "a:endcb1",
        "a:endcb2",
        "a:finish",
        "b:close",
        "a:close",
    ]);
    let mut core = test_interpreter();
    let log = install_writable_order_log(&mut core);
    let Value::Object(a) = core
        .construct_stream_writable(RegRange { start: 0, count: 0 })
        .expect("Writable A")
    else {
        panic!("Writable constructor must return an object");
    };
    let Value::Object(b) = core
        .construct_stream_writable(RegRange { start: 0, count: 0 })
        .expect("Writable B")
    else {
        panic!("Writable constructor must return an object");
    };

    for (stream, write_fn, end_fns, finish_fn, close_fn) in
        [(b, 0, [2, 3], 4, 8), (a, 1, [5, 6], 7, 9)]
    {
        core.writable_enqueue(
            stream,
            Value::str("x"),
            Label::Public,
            Some(WritableCallbackRecord {
                value: Value::Function(write_fn),
                label: Label::Public,
                module_specifier: None,
            }),
        )
        .expect("completed write record");
        let state = core
            .writable_streams
            .get_mut(&stream)
            .expect("live Writable");
        state.writes[0].status = WritableWriteStatus::Completed;
        state.buffered_length = 0;
        state.end_requested = true;
        state.final_status = WritableFinalStatus::Done;
        for end_fn in end_fns {
            state.end_callbacks.push_back(WritableEndCallbackRecord {
                callback: WritableCallbackRecord {
                    value: Value::Function(end_fn),
                    label: Label::Public,
                    module_specifier: None,
                },
                registered_after_end: false,
            });
        }
        core.sync_estimated_memory_bytes()
            .expect("terminal state accounting");
        for (event, function_index) in [("finish", finish_fn), ("close", close_fn)] {
            core.insert_event_listener(
                stream,
                event,
                EventListenerRecord {
                    listener: Value::Function(function_index),
                    once: false,
                },
                false,
            )
            .expect("lifecycle listener");
        }
    }

    core.schedule_writable_tick(b).expect("schedule B first");
    core.schedule_writable_tick(a).expect("schedule A second");
    core.drain_runtime_checkpoint(Some(&module))
        .expect("two-stream checkpoint");
    assert_eq!(
        writable_order_entries(&core, log),
        [
            "b:writecb",
            "a:writecb",
            "b:endcb1",
            "b:endcb2",
            "b:finish",
            "a:endcb1",
            "a:endcb2",
            "a:finish",
            "b:close",
            "a:close",
        ]
    );
    assert!(!core.writable_streams.contains_key(&a));
    assert!(!core.writable_streams.contains_key(&b));
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn writable_write_error_batches_do_not_interleave_between_streams_bd_fw7zd_1() {
    let module = writable_order_module(&[
        "b:endcb1", "b:endcb2", "a:endcb1", "a:endcb2", "b:error", "a:error", "b:close", "a:close",
    ]);
    let mut core = test_interpreter();
    let log = install_writable_order_log(&mut core);
    let Value::Object(a) = core
        .construct_stream_writable(RegRange { start: 0, count: 0 })
        .expect("Writable A")
    else {
        panic!("Writable constructor must return an object");
    };
    let Value::Object(b) = core
        .construct_stream_writable(RegRange { start: 0, count: 0 })
        .expect("Writable B")
    else {
        panic!("Writable constructor must return an object");
    };

    for (stream, end_fns, error_fn, close_fn, error_message) in
        [(b, [0, 1], 4, 6, "b-write"), (a, [2, 3], 5, 7, "a-write")]
    {
        let state = core
            .writable_streams
            .get_mut(&stream)
            .expect("live Writable");
        state.end_requested = true;
        state.final_status = WritableFinalStatus::Done;
        state.terminal_error = Some((Value::str(error_message), Label::Public));
        state.terminal_error_origin = Some(WritableErrorOrigin::Write);
        for end_fn in end_fns {
            state.end_callbacks.push_back(WritableEndCallbackRecord {
                callback: WritableCallbackRecord {
                    value: Value::Function(end_fn),
                    label: Label::Public,
                    module_specifier: None,
                },
                registered_after_end: false,
            });
        }
        for (event, function_index) in [("error", error_fn), ("close", close_fn)] {
            core.insert_event_listener(
                stream,
                event,
                EventListenerRecord {
                    listener: Value::Function(function_index),
                    once: false,
                },
                false,
            )
            .expect("lifecycle listener");
        }
    }
    core.sync_estimated_memory_bytes()
        .expect("arranged error-batch accounting");
    core.schedule_writable_tick(b).expect("schedule B first");
    core.schedule_writable_tick(a).expect("schedule A second");
    core.drain_runtime_checkpoint(Some(&module))
        .expect("two-stream write-error checkpoint");
    assert_eq!(
        writable_order_entries(&core, log),
        [
            "b:endcb1", "b:endcb2", "a:endcb1", "a:endcb2", "b:error", "a:error", "b:close",
            "a:close",
        ]
    );
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn writable_nested_cork_flushes_fifo_with_exact_ifc_state_bd_fw7zd() {
    let module = test_module_with_functions(
        vec![
            Ir3Instruction::LoadUndefined { dst: 0 },
            Ir3Instruction::Return { value: 0 },
        ],
        vec![Ir3FunctionDesc {
            entry: 0,
            arity: 3,
            frame_size: 4,
            name: Some("pending_write".to_string()),
            is_generator: false,
            rest_param_index: None,
        }],
    );
    let mut core = test_interpreter();
    let options = core
        .alloc_object_with_properties(&[("write", Value::Function(0))])
        .expect("Writable write options");
    core.write_reg(0, Value::Object(options))
        .expect("Writable options register");
    let Value::Object(writable) = core
        .construct_stream_writable(RegRange { start: 0, count: 1 })
        .expect("Writable with pending write callback")
    else {
        panic!("Writable constructor must return an object");
    };

    core.active_inline_callback_context_label = Some(Label::Secret);
    core.writable_cork(Value::Object(writable), RegRange { start: 1, count: 0 })
        .expect("first cork");
    core.writable_cork(Value::Object(writable), RegRange { start: 1, count: 0 })
        .expect("nested cork");
    core.active_inline_callback_context_label = None;
    core.writable_enqueue(writable, Value::str("a"), Label::Public, None)
        .expect("first queued write");
    core.writable_enqueue(writable, Value::str("bb"), Label::Public, None)
        .expect("second queued write");
    core.drive_writable(writable, &module)
        .expect("cork suppresses direct drive");
    let state = &core.writable_streams[&writable];
    assert_eq!(state.cork_depth, 2);
    assert_eq!(state.lifecycle_label, Label::Secret);
    assert_eq!(state.buffered_length, 3);
    assert!(
        state
            .writes
            .iter()
            .all(|record| record.status == WritableWriteStatus::Pending)
    );

    core.writable_uncork(
        &module,
        Value::Object(writable),
        RegRange { start: 1, count: 0 },
    )
    .expect("first uncork retains nesting");
    assert_eq!(core.writable_streams[&writable].cork_depth, 1);
    assert!(
        core.writable_streams[&writable]
            .writes
            .iter()
            .all(|record| record.status == WritableWriteStatus::Pending)
    );

    core.writable_uncork(
        &module,
        Value::Object(writable),
        RegRange { start: 1, count: 0 },
    )
    .expect("zero-depth uncork starts FIFO drive");
    let first_token = match core.writable_streams[&writable].writes[0].status {
        WritableWriteStatus::Active(token) => token,
        ref status => panic!("first FIFO write must be active, got {status:?}"),
    };
    assert_eq!(
        core.writable_streams[&writable].writes[1].status,
        WritableWriteStatus::Pending
    );
    let first_completion = BuiltinFunction::writable_completion(
        BuiltinFunctionKind::StreamWritableWriteDone,
        writable,
        first_token,
    );
    core.writable_write_done(&module, &first_completion, RegRange { start: 1, count: 0 })
        .expect("complete first FIFO write");
    let second_token = match core.writable_streams[&writable].writes[1].status {
        WritableWriteStatus::Active(token) => token,
        ref status => panic!("second FIFO write must follow first, got {status:?}"),
    };
    assert_eq!(core.writable_streams[&writable].buffered_length, 2);
    let second_completion = BuiltinFunction::writable_completion(
        BuiltinFunctionKind::StreamWritableWriteDone,
        writable,
        second_token,
    );
    core.writable_write_done(&module, &second_completion, RegRange { start: 1, count: 0 })
        .expect("complete second FIFO write");
    assert_eq!(core.writable_streams[&writable].buffered_length, 0);
    assert_eq!(
        core.heap[writable.0 as usize]
            .properties
            .get("writableCorked"),
        Some(&Value::Int(0))
    );
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn writable_end_implicitly_uncorks_every_nested_level_bd_fw7zd() {
    let module = test_module_with_functions(
        vec![
            Ir3Instruction::LoadUndefined { dst: 0 },
            Ir3Instruction::Return { value: 0 },
        ],
        vec![Ir3FunctionDesc {
            entry: 0,
            arity: 3,
            frame_size: 4,
            name: Some("pending_write".to_string()),
            is_generator: false,
            rest_param_index: None,
        }],
    );
    let mut core = test_interpreter();
    let options = core
        .alloc_object_with_properties(&[("write", Value::Function(0))])
        .expect("Writable write options");
    core.write_reg(0, Value::Object(options))
        .expect("Writable options register");
    let Value::Object(writable) = core
        .construct_stream_writable(RegRange { start: 0, count: 1 })
        .expect("Writable with pending write callback")
    else {
        panic!("Writable constructor must return an object");
    };

    core.writable_cork(Value::Object(writable), RegRange { start: 2, count: 0 })
        .expect("first cork");
    core.writable_cork(Value::Object(writable), RegRange { start: 2, count: 0 })
        .expect("nested cork");
    core.writable_enqueue(writable, Value::str("queued"), Label::Public, None)
        .expect("queued write");
    core.write_reg(1, Value::str("tail"))
        .expect("terminal chunk register");
    core.writable_end(
        &module,
        Value::Object(writable),
        RegRange { start: 1, count: 1 },
    )
    .expect("end implicitly uncorks and starts FIFO delivery");

    let state = &core.writable_streams[&writable];
    assert_eq!(state.cork_depth, 0);
    assert!(state.end_requested);
    assert_eq!(state.writes.len(), 2);
    assert!(matches!(
        state.writes[0].status,
        WritableWriteStatus::Active(_)
    ));
    assert_eq!(state.writes[1].status, WritableWriteStatus::Pending);
    assert_eq!(
        core.heap[writable.0 as usize]
            .properties
            .get("writableCorked"),
        Some(&Value::Int(0))
    );
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn writable_destroy_is_deferred_idempotent_ifc_exact_and_ceiling_safe_bd_fw7zd() {
    let module = test_module_with_functions(Vec::new(), Vec::new());
    let consume_scheduled_tick = |core: &mut InterpreterCore, object_id: ObjectId| {
        assert!(
            core.writable_streams
                .get_mut(&object_id)
                .expect("scheduled live Writable")
                .tick_sequence
                .take()
                .is_some(),
            "direct tick driving must consume the scheduler-owned sequence"
        );
    };
    let mut core = test_interpreter();
    let Value::Object(writable) = core
        .construct_stream_writable(RegRange { start: 0, count: 0 })
        .expect("generic Writable")
    else {
        panic!("Writable constructor must return an object");
    };
    core.writable_enqueue(
        writable,
        Value::str("queued"),
        Label::Confidential,
        Some(WritableCallbackRecord {
            value: Value::Function(0),
            label: Label::Confidential,
            module_specifier: None,
        }),
    )
    .expect("queued write with callback");
    core.write_reg(1, Value::str("classified destroy"))
        .expect("destroy error register");
    core.set_register_label(1, Label::Secret)
        .expect("destroy error label");
    core.insert_event_listener(
        writable,
        "error",
        EventListenerRecord {
            listener: Value::BuiltinFunction(BuiltinFunction::new_kind(
                BuiltinFunctionKind::ArrayIsArray,
            )),
            once: false,
        },
        false,
    )
    .expect("handled destroy error listener");
    assert_eq!(
        core.writable_destroy(Value::Object(writable), RegRange { start: 1, count: 1 },)
            .expect("destroy(error)"),
        Value::Object(writable)
    );
    let destroyed = &core.writable_streams[&writable];
    assert!(destroyed.destroy_requested);
    assert!(destroyed.writes.is_empty());
    assert_eq!(destroyed.buffered_length, 0);
    assert_eq!(destroyed.cork_depth, 0);
    assert!(destroyed.write_callback.is_none());
    assert!(destroyed.final_callback.is_none());
    assert!(destroyed.end_callbacks.is_empty());
    assert_eq!(destroyed.lifecycle_label, Label::Secret);
    assert_eq!(
        destroyed.terminal_error,
        Some((Value::str("classified destroy"), Label::Secret))
    );
    assert_eq!(
        destroyed.terminal_error_origin,
        Some(WritableErrorOrigin::Destroy)
    );
    assert_eq!(destroyed.tick_phase, WritableTickPhase::Error);
    assert_eq!(
        core.heap[writable.0 as usize].properties.get("destroyed"),
        Some(&Value::Bool(true))
    );
    assert_eq!(
        core.heap[writable.0 as usize].properties.get("closed"),
        Some(&Value::Bool(true)),
        "Bun exposes the closed mirror synchronously while deferring the close event"
    );
    assert_eq!(
        core.heap[writable.0 as usize]
            .properties
            .get("writableFinished"),
        Some(&Value::Bool(false))
    );
    assert_eq!(
        core.heap[writable.0 as usize]
            .properties
            .get("writableLength"),
        Some(&Value::Int(6)),
        "Bun retains queued length synchronously until close"
    );
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );

    core.write_reg(1, Value::str("ignored second error"))
        .expect("second destroy error register");
    core.writable_destroy(Value::Object(writable), RegRange { start: 1, count: 1 })
        .expect("duplicate destroy is idempotent");
    assert_eq!(
        core.writable_streams[&writable].terminal_error,
        Some((Value::str("classified destroy"), Label::Secret))
    );
    consume_scheduled_tick(&mut core, writable);
    core.drive_writable_tick(writable, Some(&module))
        .expect("handled destroy error emission");
    assert!(core.writable_streams[&writable].terminal_error_emitted);
    assert_eq!(
        core.writable_streams[&writable].tick_phase,
        WritableTickPhase::Close
    );
    consume_scheduled_tick(&mut core, writable);
    core.drive_writable_tick(writable, Some(&module))
        .expect("deferred close");
    assert_eq!(
        core.heap[writable.0 as usize].properties.get("closed"),
        Some(&Value::Bool(true))
    );
    assert_eq!(
        core.heap[writable.0 as usize]
            .properties
            .get("writableFinished"),
        Some(&Value::Bool(false)),
        "destroy must not fabricate finish"
    );
    assert_eq!(
        core.heap[writable.0 as usize]
            .properties
            .get("writableLength"),
        Some(&Value::Int(0)),
        "queued chunks are discarded at close"
    );
    consume_scheduled_tick(&mut core, writable);
    core.drive_writable_tick(writable, Some(&module))
        .expect("deferred release");
    assert!(!core.writable_streams.contains_key(&writable));
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );

    let mut ceiling_core = test_interpreter();
    let Value::Object(ceiling_writable) = ceiling_core
        .construct_stream_writable(RegRange { start: 0, count: 0 })
        .expect("memory-ceiling Writable")
    else {
        panic!("Writable constructor must return an object");
    };
    ceiling_core
        .writable_enqueue(
            ceiling_writable,
            Value::str("full queue"),
            Label::Public,
            Some(WritableCallbackRecord {
                value: Value::Function(0),
                label: Label::Public,
                module_specifier: None,
            }),
        )
        .expect("ceiling queue");
    let ceiling_state = ceiling_core
        .writable_streams
        .get_mut(&ceiling_writable)
        .expect("ceiling Writable state");
    ceiling_state.writes[0].status = WritableWriteStatus::Completed;
    ceiling_state.buffered_length = 0;
    ceiling_state.end_requested = true;
    ceiling_state.final_status = WritableFinalStatus::Done;
    ceiling_state
        .end_callbacks
        .push_back(WritableEndCallbackRecord {
            callback: WritableCallbackRecord {
                value: Value::BuiltinFunction(BuiltinFunction::new_kind(
                    BuiltinFunctionKind::ArrayIsArray,
                )),
                label: Label::Secret,
                module_specifier: Some(module.header.source_label.clone()),
            },
            registered_after_end: false,
        });
    ceiling_core
        .sync_estimated_memory_bytes()
        .expect("ceiling terminal FIFO accounting");
    ceiling_core.config.max_total_memory_bytes = ceiling_core.estimated_memory_bytes();
    ceiling_core
        .writable_destroy(
            Value::Object(ceiling_writable),
            RegRange { start: 0, count: 0 },
        )
        .expect("destroy teardown must not clone the queue at the exact ceiling");
    assert!(
        ceiling_core.writable_streams[&ceiling_writable]
            .writes
            .is_empty()
    );
    assert_eq!(
        ceiling_core.estimated_memory_bytes(),
        ceiling_core.recompute_estimated_memory_bytes()
    );
    ceiling_core.config.max_total_memory_bytes = u64::MAX;
    consume_scheduled_tick(&mut ceiling_core, ceiling_writable);
    ceiling_core
        .drive_writable_tick(ceiling_writable, Some(&module))
        .expect("ceiling terminal callback");
    consume_scheduled_tick(&mut ceiling_core, ceiling_writable);
    ceiling_core
        .drive_writable_tick(ceiling_writable, Some(&module))
        .expect("ceiling error-to-close transition");
    consume_scheduled_tick(&mut ceiling_core, ceiling_writable);
    ceiling_core
        .drive_writable_tick(ceiling_writable, Some(&module))
        .expect("ceiling close");
    consume_scheduled_tick(&mut ceiling_core, ceiling_writable);
    ceiling_core
        .drive_writable_tick(ceiling_writable, Some(&module))
        .expect("ceiling release");
    assert!(
        !ceiling_core
            .writable_streams
            .contains_key(&ceiling_writable)
    );
    assert_eq!(
        ceiling_core.estimated_memory_bytes(),
        ceiling_core.recompute_estimated_memory_bytes()
    );

    let mut transfer_core = test_interpreter();
    let Value::Object(transfer_writable) = transfer_core
        .construct_stream_writable(RegRange { start: 0, count: 0 })
        .expect("error-transfer Writable")
    else {
        panic!("Writable constructor must return an object");
    };
    transfer_core
        .insert_event_listener(
            transfer_writable,
            "error",
            EventListenerRecord {
                listener: Value::BuiltinFunction(BuiltinFunction::new_kind(
                    BuiltinFunctionKind::ArrayIsArray,
                )),
                once: false,
            },
            false,
        )
        .expect("handled transfer error listener");
    transfer_core
        .write_reg(0, Value::str("owned error"))
        .expect("owned error register");
    let retained_destroy_error_bytes = InterpreterCore::estimate_writable_value_bytes(
        &transfer_core
            .read_reg(0)
            .expect("retained destroy error value"),
    )
    .saturating_add(InterpreterCore::estimate_label_bytes(
        transfer_core
            .get_register_label(0)
            .expect("retained destroy error label"),
    ));
    transfer_core.config.max_total_memory_bytes = transfer_core
        .estimated_memory_bytes()
        .saturating_add(retained_destroy_error_bytes);
    transfer_core
        .writable_destroy(
            Value::Object(transfer_writable),
            RegRange { start: 0, count: 1 },
        )
        .expect("destroy must retain its error clone at the exact ceiling");
    assert_eq!(
        transfer_core
            .read_reg(0)
            .expect("destroy argument remains guest-visible"),
        Value::str("owned error")
    );
    assert_eq!(
        transfer_core.estimated_memory_bytes(),
        transfer_core.recompute_estimated_memory_bytes()
    );
    transfer_core.config.max_total_memory_bytes = u64::MAX;
    transfer_core
        .drain_runtime_checkpoint(Some(&module))
        .expect("handled error, close, and release");
    assert!(
        !transfer_core
            .writable_streams
            .contains_key(&transfer_writable)
    );
    assert_eq!(
        transfer_core.estimated_memory_bytes(),
        transfer_core.recompute_estimated_memory_bytes()
    );

    let mut refusal_core = test_interpreter();
    let Value::Object(refusal_writable) = refusal_core
        .construct_stream_writable(RegRange { start: 0, count: 0 })
        .expect("label-refusal Writable")
    else {
        panic!("Writable constructor must return an object");
    };
    refusal_core
        .write_reg(0, Value::Int(17))
        .expect("zero-byte destroy error");
    refusal_core
        .set_register_label(
            0,
            Label::Custom {
                name: "destroy-ceiling-label".repeat(32),
                level: 3,
            },
        )
        .expect("large destroy label");
    refusal_core.config.max_total_memory_bytes = refusal_core.estimated_memory_bytes();
    let before_refusal = format!("{:?}", refusal_core.writable_streams[&refusal_writable]);
    assert!(matches!(
        refusal_core.writable_destroy(
            Value::Object(refusal_writable),
            RegRange { start: 0, count: 1 },
        ),
        Err(InterpreterError::MemoryBudgetExceeded { .. })
    ));
    assert_eq!(
        format!("{:?}", refusal_core.writable_streams[&refusal_writable]),
        before_refusal,
        "destroy refusal must leave authoritative state unchanged"
    );
    assert_eq!(
        refusal_core
            .read_reg(0)
            .expect("refused argument remains live"),
        Value::Int(17)
    );
    assert_eq!(
        refusal_core.estimated_memory_bytes(),
        refusal_core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn unhandled_writable_destroy_error_does_not_schedule_close_bd_fw7zd() {
    let module = test_module_with_functions(Vec::new(), Vec::new());
    let mut core = test_interpreter();
    let Value::Object(writable) = core
        .construct_stream_writable(RegRange { start: 0, count: 0 })
        .expect("generic Writable")
    else {
        panic!("Writable constructor must return an object");
    };
    core.write_reg(0, Value::str("unhandled destroy"))
        .expect("destroy error register");
    core.writable_destroy(Value::Object(writable), RegRange { start: 0, count: 1 })
        .expect("destroy(error)");

    assert!(matches!(
        core.drain_runtime_checkpoint(Some(&module)),
        Err(InterpreterError::UncaughtException { .. })
    ));
    let state = &core.writable_streams[&writable];
    assert_eq!(state.tick_phase, WritableTickPhase::Close);
    assert!(state.tick_sequence.is_none());
    assert_eq!(
        core.heap[writable.0 as usize].properties.get("closed"),
        Some(&Value::Bool(true)),
        "the synchronous mirror remains true even though close delivery is aborted"
    );
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn secret_uncork_controls_deferred_write_callback_label_bd_fw7zd() {
    let module = test_module_with_functions(
        vec![
            Ir3Instruction::LoadInt { dst: 0, value: 41 },
            Ir3Instruction::Throw { value: 0 },
        ],
        vec![Ir3FunctionDesc {
            entry: 0,
            arity: 0,
            frame_size: 2,
            name: Some("uncork_controlled_callback".to_string()),
            is_generator: false,
            rest_param_index: None,
        }],
    );
    let mut core = test_interpreter();
    let Value::Object(writable) = core
        .construct_stream_writable(RegRange { start: 0, count: 0 })
        .expect("generic Writable")
    else {
        panic!("Writable constructor must return an object");
    };
    core.writable_enqueue(
        writable,
        Value::str("public"),
        Label::Public,
        Some(WritableCallbackRecord {
            value: Value::Function(0),
            label: Label::Public,
            module_specifier: None,
        }),
    )
    .expect("Public queued record");
    {
        let state = core
            .writable_streams
            .get_mut(&writable)
            .expect("live Writable");
        state.writes[0].status = WritableWriteStatus::Completed;
        state.buffered_length = 0;
    }
    core.writable_cork(Value::Object(writable), RegRange { start: 1, count: 0 })
        .expect("Public cork");
    core.active_inline_callback_context_label = Some(Label::Secret);
    core.writable_uncork(
        &module,
        Value::Object(writable),
        RegRange { start: 1, count: 0 },
    )
    .expect("Secret-controlled uncork");
    core.active_inline_callback_context_label = None;
    core.schedule_writable_tick(writable)
        .expect("deferred callback tick");

    assert!(matches!(
        core.drain_runtime_checkpoint(Some(&module)),
        Err(InterpreterError::UncaughtException { .. })
    ));
    assert_eq!(core.pending_exception, Some(Value::Int(41)));
    assert_eq!(core.pending_exception_label, Label::Secret);
}

#[test]
fn writable_write_dispatch_rejoins_live_aliased_binary_label_bd_bjwzv() {
    let module = test_module_with_functions(
        vec![
            Ir3Instruction::LoadInt { dst: 0, value: 97 },
            Ir3Instruction::Throw { value: 0 },
        ],
        vec![Ir3FunctionDesc {
            entry: 0,
            arity: 3,
            frame_size: 4,
            name: Some("aliased_buffer_write".to_string()),
            is_generator: false,
            rest_param_index: None,
        }],
    );
    let mut core = test_interpreter();
    let options = core
        .alloc_object_with_properties(&[("write", Value::Function(0))])
        .expect("Writable write options");
    core.write_reg(0, Value::Object(options))
        .expect("Writable options register");
    let Value::Object(writable) = core
        .construct_stream_writable(RegRange { start: 0, count: 1 })
        .expect("Writable with throwing write callback")
    else {
        panic!("Writable constructor must return an object");
    };
    core.writable_cork(Value::Object(writable), RegRange { start: 3, count: 0 })
        .expect("cork before enqueue");

    let chunk = core
        .alloc_buffer_from_bytes(b"public-at-enqueue")
        .expect("queued Buffer");
    let backing = core
        .array_buffer_id_for_object(chunk)
        .expect("Buffer backing");
    let alias = core
        .alloc_buffer_view_object(backing, 0, b"public-at-enqueue".len())
        .expect("shared Buffer alias");
    core.write_reg_with_label(1, Value::Object(chunk), Label::Public)
        .expect("public Buffer argument");
    core.writable_write(
        &module,
        Value::Object(writable),
        RegRange { start: 1, count: 1 },
    )
    .expect("corked write enqueue");
    assert_eq!(
        core.writable_streams[&writable].writes[0].label,
        Label::Public,
        "enqueue must capture the then-current backing label"
    );
    assert_eq!(
        core.writable_streams[&writable].writes[0].status,
        WritableWriteStatus::Pending
    );

    core.join_binary_storage_label(alias, &Label::Secret)
        .expect("Secret alias mutation");
    assert!(matches!(
        core.writable_uncork(
            &module,
            Value::Object(writable),
            RegRange { start: 3, count: 0 },
        ),
        Err(InterpreterError::UncaughtException { .. })
    ));
    assert_eq!(core.pending_exception, Some(Value::Int(97)));
    assert_eq!(
        core.pending_exception_label,
        Label::Secret,
        "_write dispatch must resolve the shared backing label again"
    );
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn writable_completion_errors_preserve_arguments_and_rejoin_binary_labels_bd_bjwzv() {
    let module = test_module_with_functions(
        vec![
            Ir3Instruction::CallMethod {
                receiver: 0,
                callee: 1,
                args: RegRange { start: 2, count: 1 },
                dst: 3,
            },
            Ir3Instruction::Halt,
            Ir3Instruction::LoadInt { dst: 0, value: 313 },
            Ir3Instruction::Throw { value: 0 },
        ],
        vec![Ir3FunctionDesc {
            entry: 2,
            arity: 1,
            frame_size: 2,
            name: Some("deferred_writable_error_listener".to_string()),
            is_generator: false,
            rest_param_index: None,
        }],
    );
    let consume_scheduled_tick = |core: &mut InterpreterCore, object_id: ObjectId| {
        assert!(
            core.writable_streams
                .get_mut(&object_id)
                .expect("scheduled live Writable")
                .tick_sequence
                .take()
                .is_some(),
            "direct tick driving must consume the scheduler-owned sequence"
        );
    };

    let mut core = test_interpreter();
    let Value::Object(writable) = core
        .construct_stream_writable(RegRange { start: 4, count: 0 })
        .expect("write-error Writable")
    else {
        panic!("Writable constructor must return an object");
    };
    core.writable_enqueue(writable, Value::str("x"), Label::Public, None)
        .expect("active write record");
    {
        let state = core
            .writable_streams
            .get_mut(&writable)
            .expect("write-error state");
        state.writes[0].status = WritableWriteStatus::Active(31);
        state.end_requested = true;
        state.final_status = WritableFinalStatus::Done;
    }
    let error = core
        .alloc_buffer_from_bytes(b"binary-error")
        .expect("Buffer completion error");
    let backing = core
        .array_buffer_id_for_object(error)
        .expect("Buffer error backing");
    let alias = core
        .alloc_buffer_view_object(backing, 0, b"binary-error".len())
        .expect("Buffer error alias");
    core.join_binary_storage_label(alias, &Label::Secret)
        .expect("Secret completion backing");
    core.write_reg(0, Value::Undefined)
        .expect("public CallMethod receiver");
    core.write_reg(
        1,
        Value::BuiltinFunction(BuiltinFunction::writable_completion(
            BuiltinFunctionKind::StreamWritableWriteDone,
            writable,
            31,
        )),
    )
    .expect("write completion callee");
    core.write_reg_with_label(2, Value::Object(error), Label::Confidential)
        .expect("guest-visible completion argument");
    core.write_reg(3, Value::Int(-1))
        .expect("completion destination sentinel");

    assert_eq!(core.run_loop(&module), Err(InterpreterError::Halted));
    assert_eq!(
        core.read_reg(2).expect("preserved completion argument"),
        Value::Object(error)
    );
    assert_eq!(
        core.get_register_label(2)
            .expect("preserved completion argument label"),
        &Label::Confidential
    );
    assert_eq!(
        core.get_register_label(3)
            .expect("post-CallMethod destination label"),
        &Label::Confidential,
        "the normal post-call argument-label join must still observe r2"
    );
    assert_eq!(
        core.writable_streams[&writable].terminal_error,
        Some((Value::Object(error), Label::Secret))
    );
    assert_eq!(
        core.writable_streams[&writable].lifecycle_label,
        Label::Secret
    );

    core.join_binary_storage_label(alias, &Label::TopSecret)
        .expect("post-record TopSecret alias mutation");
    core.insert_event_listener(
        writable,
        "error",
        EventListenerRecord {
            listener: Value::Function(0),
            once: false,
        },
        false,
    )
    .expect("throwing error listener");
    consume_scheduled_tick(&mut core, writable);
    core.drive_writable_tick(writable, Some(&module))
        .expect("remove completed callback-free write");
    consume_scheduled_tick(&mut core, writable);
    assert!(matches!(
        core.drive_writable_tick(writable, Some(&module)),
        Err(InterpreterError::UncaughtException { .. })
    ));
    assert_eq!(core.pending_exception, Some(Value::Int(313)));
    assert_eq!(
        core.pending_exception_label,
        Label::TopSecret,
        "error emission must resolve the backing label after record creation"
    );
    assert_eq!(
        core.writable_streams[&writable].lifecycle_label,
        Label::TopSecret
    );
    assert_eq!(
        core.writable_streams[&writable]
            .terminal_error
            .as_ref()
            .map(|(_, label)| label),
        Some(&Label::TopSecret)
    );
    assert!(
        core.writable_streams[&writable].tick_sequence.is_some(),
        "a registered error listener that throws must leave close reserved"
    );
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );

    let mut final_core = test_interpreter();
    let Value::Object(final_writable) = final_core
        .construct_stream_writable(RegRange { start: 4, count: 0 })
        .expect("final-error Writable")
    else {
        panic!("Writable constructor must return an object");
    };
    final_core
        .writable_streams
        .get_mut(&final_writable)
        .expect("final-error state")
        .final_status = WritableFinalStatus::Active(32);
    let final_error = final_core
        .alloc_buffer_from_bytes(b"final-binary-error")
        .expect("final Buffer error");
    final_core
        .join_binary_storage_label(final_error, &Label::Secret)
        .expect("Secret final backing");
    final_core
        .write_reg_with_label(0, Value::Object(final_error), Label::Public)
        .expect("final completion argument");
    let final_completion = BuiltinFunction::writable_completion(
        BuiltinFunctionKind::StreamWritableFinalDone,
        final_writable,
        32,
    );
    final_core
        .writable_final_done(&module, &final_completion, RegRange { start: 0, count: 1 })
        .expect("final completion with binary error");
    assert_eq!(
        final_core
            .read_reg(0)
            .expect("preserved final completion argument"),
        Value::Object(final_error)
    );
    assert_eq!(
        final_core
            .get_register_label(0)
            .expect("preserved final argument label"),
        &Label::Public
    );
    assert_eq!(
        final_core.writable_streams[&final_writable].terminal_error,
        Some((Value::Object(final_error), Label::Secret))
    );
    assert_eq!(
        final_core.writable_streams[&final_writable].lifecycle_label,
        Label::Secret
    );
    assert_eq!(
        final_core.estimated_memory_bytes(),
        final_core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn zero_argument_writable_callbacks_inherit_lifecycle_ifc_context_bd_fw7zd() {
    let module = test_module_with_functions(
        vec![
            Ir3Instruction::LoadInt { dst: 0, value: 7 },
            Ir3Instruction::Throw { value: 0 },
        ],
        vec![Ir3FunctionDesc {
            entry: 0,
            arity: 0,
            frame_size: 2,
            name: Some("zero_arg_writable_callback".to_string()),
            is_generator: false,
            rest_param_index: None,
        }],
    );
    let mut core = test_interpreter();
    let Value::Object(writable) = core
        .construct_stream_writable(RegRange { start: 0, count: 0 })
        .expect("generic Writable")
    else {
        panic!("Writable constructor must return an object");
    };
    core.writable_enqueue(
        writable,
        Value::str("classified"),
        Label::Secret,
        Some(WritableCallbackRecord {
            value: Value::Function(0),
            label: Label::Secret,
            module_specifier: None,
        }),
    )
    .expect("Secret Writable record");
    {
        let state = core
            .writable_streams
            .get_mut(&writable)
            .expect("live Writable");
        state.writes[0].status = WritableWriteStatus::Completed;
        state.buffered_length = 0;
        state.end_requested = true;
        state.final_status = WritableFinalStatus::Done;
    }
    core.schedule_writable_tick(writable)
        .expect("Writable callback tick");
    assert!(matches!(
        core.drive_writable_tick(writable, Some(&module)),
        Err(InterpreterError::UncaughtException { .. })
    ));
    assert_eq!(core.pending_exception, Some(Value::Int(7)));
    assert_eq!(
        core.pending_exception_label,
        Label::Secret,
        "a real zero-argument callback write must retain its lifecycle label through throw capture"
    );
    core.drain_runtime_checkpoint(Some(&module))
        .expect("throwing callback must not strand finish/close");
    assert!(!core.writable_streams.contains_key(&writable));
}

#[test]
fn writable_terminal_callback_fifo_retains_ifc_and_owner_module_bd_fw7zd_1() {
    let throwing_module = test_module_with_functions(
        vec![
            Ir3Instruction::LoadInt { dst: 0, value: 71 },
            Ir3Instruction::Throw { value: 0 },
        ],
        vec![Ir3FunctionDesc {
            entry: 0,
            arity: 0,
            frame_size: 2,
            name: Some("terminal_callback".to_string()),
            is_generator: false,
            rest_param_index: None,
        }],
    );
    let mut ifc_core = test_interpreter();
    let Value::Object(ifc_writable) = ifc_core
        .construct_stream_writable(RegRange { start: 0, count: 0 })
        .expect("IFC Writable")
    else {
        panic!("Writable constructor must return an object");
    };
    {
        let state = ifc_core
            .writable_streams
            .get_mut(&ifc_writable)
            .expect("live IFC Writable");
        state.end_requested = true;
        state.final_status = WritableFinalStatus::Done;
        state.lifecycle_label = Label::Confidential;
        state.end_callbacks.push_back(WritableEndCallbackRecord {
            callback: WritableCallbackRecord {
                value: Value::Function(0),
                label: Label::Secret,
                module_specifier: Some(throwing_module.header.source_label.clone()),
            },
            registered_after_end: false,
        });
    }
    ifc_core
        .sync_estimated_memory_bytes()
        .expect("arranged terminal callback accounting");
    ifc_core
        .schedule_writable_tick(ifc_writable)
        .expect("terminal callback tick");
    assert!(matches!(
        ifc_core.drive_writable_tick(ifc_writable, Some(&throwing_module)),
        Err(InterpreterError::UncaughtException { .. })
    ));
    assert_eq!(ifc_core.pending_exception, Some(Value::Int(71)));
    assert_eq!(
        ifc_core.pending_exception_label,
        Label::Secret,
        "registration and lifecycle provenance must reach a throwing terminal callback"
    );
    assert!(
        ifc_core.writable_streams[&ifc_writable]
            .end_callbacks
            .is_empty()
    );
    ifc_core
        .drain_runtime_checkpoint(Some(&throwing_module))
        .expect("throwing terminal callback must not strand finish/close");
    assert!(!ifc_core.writable_streams.contains_key(&ifc_writable));

    let mut owner = writable_order_module(&["owner"]);
    owner.header.source_label = "terminal-owner.mjs".to_string();
    let mut caller = writable_order_module(&["caller"]);
    caller.header.source_label = "terminal-caller.mjs".to_string();
    let mut owner_core = test_interpreter();
    let log = install_writable_order_log(&mut owner_core);
    owner_core
        .ensure_module_record(&owner, "terminal-owner.mjs")
        .expect("terminal callback owner program should be retained");
    let Value::Object(owner_writable) = owner_core
        .construct_stream_writable(RegRange { start: 0, count: 0 })
        .expect("owner Writable")
    else {
        panic!("Writable constructor must return an object");
    };
    owner_core.current_module_specifier = Some("terminal-owner.mjs".to_string());
    owner_core
        .write_reg(0, Value::Function(0))
        .expect("owner callback register");
    owner_core
        .writable_end(
            &owner,
            Value::Object(owner_writable),
            RegRange { start: 0, count: 1 },
        )
        .expect("register owner callback through the public end path");
    assert_eq!(
        owner_core.writable_streams[&owner_writable]
            .end_callbacks
            .front()
            .expect("registered owner callback")
            .callback
            .module_specifier
            .as_deref(),
        Some("terminal-owner.mjs"),
        "the API registration path must retain the active raw-function module"
    );
    owner_core.current_module_specifier = Some("terminal-caller.mjs".to_string());
    owner_core
        .drain_runtime_checkpoint(Some(&caller))
        .expect("imported terminal callback checkpoint");
    assert_eq!(writable_order_entries(&owner_core, log), ["owner"]);
    assert!(
        !owner_core.writable_streams.contains_key(&owner_writable),
        "owner callback must execute once and release terminal state"
    );

    for core in [&ifc_core, &owner_core] {
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }
}

#[test]
fn nested_zero_argument_callback_inherits_outer_ifc_context_bd_fw7zd() {
    let module = test_module_with_functions(
        vec![
            Ir3Instruction::LoadInt { dst: 0, value: 13 },
            Ir3Instruction::Throw { value: 0 },
        ],
        vec![Ir3FunctionDesc {
            entry: 0,
            arity: 0,
            frame_size: 2,
            name: Some("nested_zero_arg_callback".to_string()),
            is_generator: false,
            rest_param_index: None,
        }],
    );
    let mut core = test_interpreter();
    core.active_inline_callback_context_label = Some(Label::Secret);
    assert!(matches!(
        core.invoke_inline_method_call_with_argument_label(
            Some(&module),
            Value::Function(0),
            Value::Undefined,
            Vec::new(),
            None,
        ),
        Err(InterpreterError::UncaughtException { .. })
    ));
    assert_eq!(core.pending_exception, Some(Value::Int(13)));
    assert_eq!(core.pending_exception_label, Label::Secret);
    assert_eq!(
        core.active_inline_callback_context_label,
        Some(Label::Secret),
        "the nested wrapper restore must preserve its outer callback context"
    );
}

#[test]
fn synchronous_final_throw_is_fail_fast_before_close_bd_fw7zd() {
    let module = test_module_with_functions(Vec::new(), Vec::new());
    let mut core = test_interpreter();
    let options = core
        .alloc_object_with_properties(&[(
            "final",
            Value::BuiltinFunction(BuiltinFunction::new_kind(
                BuiltinFunctionKind::StreamReadablePause,
            )),
        )])
        .expect("Writable final options");
    core.write_reg(0, Value::Object(options))
        .expect("Writable options register");
    let Value::Object(writable) = core
        .construct_stream_writable(RegRange { start: 0, count: 1 })
        .expect("Writable with throwing final")
    else {
        panic!("Writable constructor must return an object");
    };

    core.writable_end(
        &module,
        Value::Object(writable),
        RegRange { start: 1, count: 0 },
    )
    .expect("synchronous final throw must become terminal stream state");
    let state = &core.writable_streams[&writable];
    assert_eq!(state.final_status, WritableFinalStatus::Done);
    assert!(state.terminal_error.is_some());
    assert!(state.tick_sequence.is_some());

    assert!(matches!(
        core.drain_runtime_checkpoint(Some(&module)),
        Err(InterpreterError::UncaughtException { .. })
    ));
    let state = &core.writable_streams[&writable];
    assert_eq!(state.tick_phase, WritableTickPhase::Close);
    assert!(state.tick_sequence.is_none());
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes(),
        "terminal final failure must remain accounted while the process aborts"
    );
}

#[test]
fn writable_missing_write_refusal_preserves_pending_transaction_bd_2q8dg() {
    let module = test_module_with_functions(Vec::new(), Vec::new());
    let mut core = test_interpreter();
    let Value::Object(writable) = core
        .construct_stream_writable(RegRange { start: 0, count: 0 })
        .expect("generic Writable")
    else {
        panic!("Writable constructor must return an object");
    };
    let label = Label::Custom {
        name: "missing-write-refusal".repeat(8),
        level: 23,
    };
    core.write_reg_with_label(1, Value::str("pending"), label.clone())
        .expect("labeled write chunk");
    let token_before = core.next_writable_completion_token;

    assert!(matches!(
        core.writable_write(
            &module,
            Value::Object(writable),
            RegRange { start: 1, count: 1 },
        ),
        Err(InterpreterError::TypeError { expected, got })
            if expected == "Writable with a callable write implementation"
                && got == "missing write option"
    ));
    let memory_after_enqueue = core.estimated_memory_bytes();
    let state_after_enqueue = format!("{:?}", core.writable_streams[&writable]);
    let state = &core.writable_streams[&writable];
    assert_eq!(state.writes.len(), 1);
    assert_eq!(state.writes[0].status, WritableWriteStatus::Pending);
    assert_eq!(state.writes[0].label, label);
    assert_eq!(state.lifecycle_label, label);
    assert_eq!(state.buffered_length, "pending".len());
    assert!(!state.inside_write_invocation);
    assert_eq!(core.next_writable_completion_token, token_before);

    assert!(matches!(
        core.drive_writable(writable, &module),
        Err(InterpreterError::TypeError { expected, got })
            if expected == "Writable with a callable write implementation"
                && got == "missing write option"
    ));
    assert_eq!(
        format!("{:?}", core.writable_streams[&writable]),
        state_after_enqueue,
        "repeated startup refusal must not mutate the queued transaction"
    );
    assert_eq!(core.next_writable_completion_token, token_before);
    assert_eq!(core.estimated_memory_bytes(), memory_after_enqueue);
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn writable_public_write_startup_has_exact_atomic_ceiling_bd_2q8dg() {
    let module = test_module_with_functions(
        vec![
            Ir3Instruction::LoadUndefined { dst: 0 },
            Ir3Instruction::Return { value: 0 },
        ],
        vec![Ir3FunctionDesc {
            entry: 0,
            arity: 3,
            frame_size: 4,
            name: Some("pending_write".to_string()),
            is_generator: false,
            rest_param_index: None,
        }],
    );
    let label = Label::Custom {
        name: "write-startup-ceiling".repeat(12),
        level: 29,
    };
    let attempt = |budget: u64| {
        let mut core = test_interpreter();
        let options = core
            .alloc_object_with_properties(&[("write", Value::Function(0))])
            .expect("Writable write options");
        core.write_reg(0, Value::Object(options))
            .expect("Writable options register");
        let Value::Object(writable) = core
            .construct_stream_writable(RegRange { start: 0, count: 1 })
            .expect("Writable with pending write")
        else {
            panic!("Writable constructor must return an object");
        };
        core.write_reg_with_label(1, Value::str("startup-chunk"), label.clone())
            .expect("labeled startup chunk");
        let baseline = core
            .sync_estimated_memory_bytes()
            .expect("startup refusal baseline");
        let token_before = core.next_writable_completion_token;
        core.config.max_total_memory_bytes = budget;
        let result = core.writable_write(
            &module,
            Value::Object(writable),
            RegRange { start: 1, count: 1 },
        );
        (core, writable, baseline, token_before, result)
    };

    let unbounded = attempt(u64::MAX);
    assert_eq!(unbounded.4, Ok(Value::Bool(true)));
    assert!(matches!(
        unbounded.0.writable_streams[&unbounded.1].writes[0].status,
        WritableWriteStatus::Active(_)
    ));
    let baseline = unbounded.2;
    let callback_started = |core: &InterpreterCore, writable: ObjectId| {
        core.writable_streams.get(&writable).is_some_and(|state| {
            state
                .writes
                .front()
                .is_some_and(|record| matches!(record.status, WritableWriteStatus::Active(_)))
        })
    };
    let mut distance = 1u64;
    let mut upper = loop {
        let budget = baseline.saturating_add(distance);
        let candidate = attempt(budget);
        if callback_started(&candidate.0, candidate.1) {
            break budget;
        }
        distance = distance
            .checked_mul(2)
            .expect("Writable startup ceiling search remains bounded");
        assert!(
            distance <= (1 << 32),
            "Writable startup ceiling is implausible"
        );
    };
    let mut lower = baseline;
    while lower < upper {
        let midpoint = lower + (upper - lower) / 2;
        let candidate = attempt(midpoint);
        if callback_started(&candidate.0, candidate.1) {
            upper = midpoint;
        } else {
            lower = midpoint + 1;
        }
    }
    let exact_ceiling = lower;

    let (mut refused_core, writable, _, token_before, refusal) = attempt(exact_ceiling - 1);
    assert!(matches!(
        refusal,
        Err(InterpreterError::MemoryBudgetExceeded {
            requested_bytes,
            max_bytes,
            ..
        }) if requested_bytes == exact_ceiling && max_bytes == exact_ceiling - 1
    ));
    let state = &refused_core.writable_streams[&writable];
    assert_eq!(state.writes.len(), 1);
    assert_eq!(state.writes[0].status, WritableWriteStatus::Pending);
    assert_eq!(state.writes[0].label, label);
    assert_eq!(state.lifecycle_label, label);
    assert_eq!(state.buffered_length, "startup-chunk".len());
    assert!(!state.inside_write_invocation);
    assert_eq!(refused_core.next_writable_completion_token, token_before);
    assert_eq!(
        refused_core.estimated_memory_bytes(),
        refused_core.recompute_estimated_memory_bytes()
    );

    refused_core.config.max_total_memory_bytes = u64::MAX;
    refused_core
        .drive_writable(writable, &module)
        .expect("Pending write must retry after the startup ceiling is raised");
    let token = match refused_core.writable_streams[&writable].writes[0].status {
        WritableWriteStatus::Active(token) => token,
        ref status => panic!("retried write must be Active, got {status:?}"),
    };
    assert_eq!(token, token_before);
    assert_eq!(refused_core.next_writable_completion_token, token + 1);
    let completion = BuiltinFunction::writable_completion(
        BuiltinFunctionKind::StreamWritableWriteDone,
        writable,
        token,
    );
    refused_core
        .writable_write_done(&module, &completion, RegRange { start: 0, count: 0 })
        .expect("retried write completion");
    refused_core
        .drain_runtime_checkpoint(Some(&module))
        .expect("completed retried write drain");
    let state = &refused_core.writable_streams[&writable];
    assert!(state.writes.is_empty());
    assert_eq!(state.buffered_length, 0);
    assert_eq!(state.lifecycle_label, label);
    assert_eq!(
        refused_core.estimated_memory_bytes(),
        refused_core.recompute_estimated_memory_bytes()
    );

    let (exact_core, exact_writable, _, exact_token, _) = attempt(exact_ceiling);
    let entered_token = match exact_core.writable_streams[&exact_writable].writes[0].status {
        WritableWriteStatus::Active(token) => token,
        ref status => panic!("exact startup ceiling must enter guest, got {status:?}"),
    };
    assert_eq!(entered_token, exact_token);
    assert_eq!(exact_core.next_writable_completion_token, exact_token + 1);
    assert!(exact_core.inline_callback_start_probes.is_empty());
    assert_eq!(
        exact_core.estimated_memory_bytes(),
        exact_core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn writable_in_flight_callbacks_have_exact_reentrant_ceilings_bd_66awx() {
    #[derive(Clone, Copy)]
    enum CallbackSurface {
        Write,
        EndError,
        Terminal,
    }

    let mut instructions = Vec::new();
    for register in 0..8 {
        instructions.push(Ir3Instruction::NewObject { dst: register });
    }
    instructions.push(Ir3Instruction::Return { value: 7 });
    let mut module = test_module_with_functions(
        instructions,
        vec![Ir3FunctionDesc {
            entry: 0,
            arity: 1,
            frame_size: 10,
            name: Some("reentrant_writable_allocation".to_string()),
            is_generator: false,
            rest_param_index: None,
        }],
    );
    module.header.source_label = "writable-callback-owner/".repeat(24);
    let callback_label = Label::Custom {
        name: "writable-callback-label".repeat(24),
        level: 31,
    };
    let lifecycle_label = Label::Custom {
        name: "writable-lifecycle-label".repeat(20),
        level: 29,
    };
    let error_label = Label::Custom {
        name: "writable-error-label".repeat(22),
        level: 33,
    };

    let attempt = |surface: CallbackSurface, budget: u64| {
        let mut core = test_interpreter();
        let Value::Object(writable) = core
            .construct_stream_writable(RegRange { start: 0, count: 0 })
            .expect("reentrant-ceiling Writable")
        else {
            panic!("Writable constructor must return an object");
        };
        let callback = WritableCallbackRecord {
            value: Value::Function(0),
            label: callback_label.clone(),
            module_specifier: Some(module.header.source_label.clone()),
        };
        match surface {
            CallbackSurface::Write => {
                core.writable_streams
                    .get_mut(&writable)
                    .expect("live object-mode write callback state")
                    .object_mode = true;
                core.writable_enqueue(
                    writable,
                    Value::BigInt(Arc::from("9".repeat(2048))),
                    lifecycle_label.clone(),
                    Some(callback),
                )
                .expect("completed write callback record");
                let state = core
                    .writable_streams
                    .get_mut(&writable)
                    .expect("live write callback state");
                state.writes[0].status = WritableWriteStatus::Completed;
                state.buffered_length = 0;
            }
            CallbackSurface::EndError => {
                let state = core
                    .writable_streams
                    .get_mut(&writable)
                    .expect("live end callback state");
                state.lifecycle_label = lifecycle_label.clone();
                state.end_callbacks.push_back(WritableEndCallbackRecord {
                    callback,
                    registered_after_end: false,
                });
                state.end_callback_batch_remaining = 1;
                state.end_requested = true;
                state.final_status = WritableFinalStatus::Done;
                state.terminal_error = Some((
                    Value::BigInt(Arc::from("7".repeat(3072))),
                    error_label.clone(),
                ));
                state.terminal_error_origin = Some(WritableErrorOrigin::Write);
                state.tick_phase = WritableTickPhase::Error;
            }
            CallbackSurface::Terminal => {
                {
                    let state = core
                        .writable_streams
                        .get_mut(&writable)
                        .expect("live terminal callback state");
                    state.lifecycle_label = lifecycle_label.clone();
                    state.end_requested = true;
                    state.finished = true;
                    state.final_status = WritableFinalStatus::Done;
                    state.prefinish_emitted = true;
                    state.tick_phase = WritableTickPhase::Release;
                }
                core.sync_estimated_memory_bytes()
                    .expect("pre-terminal callback accounting");
                core.terminalize_writable_state_storage(writable)
                    .expect("terminal callback tombstone");
                core.append_writable_terminal_callback(
                    writable,
                    callback,
                    WritableTerminalCallbackError::EndAfterFinish,
                    lifecycle_label.clone(),
                )
                .expect("terminal callback record");
            }
        }
        let baseline = core
            .sync_estimated_memory_bytes()
            .expect("reentrant callback baseline");
        let heap_before = core.heap.len();
        core.config.max_total_memory_bytes = budget;
        let result = match surface {
            CallbackSurface::Terminal => core.drive_writable_terminal_tick(writable, Some(&module)),
            CallbackSurface::Write | CallbackSurface::EndError => {
                core.drive_writable_tick(writable, Some(&module))
            }
        };
        assert_eq!(core.writable_in_flight_callback_bytes, 0);
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
        (core, result, baseline, heap_before)
    };

    for surface in [
        CallbackSurface::Write,
        CallbackSurface::EndError,
        CallbackSurface::Terminal,
    ] {
        let (_, unbounded, baseline, _) = attempt(surface, u64::MAX);
        assert!(unbounded.is_ok());
        let mut distance = 1u64;
        let mut upper = loop {
            let budget = baseline.saturating_add(distance);
            if attempt(surface, budget).1.is_ok() {
                break budget;
            }
            distance = distance
                .checked_mul(2)
                .expect("Writable callback ceiling search remains bounded");
            assert!(
                distance <= (1 << 32),
                "Writable callback ceiling is implausible"
            );
        };
        let mut lower = baseline;
        while lower < upper {
            let midpoint = lower + (upper - lower) / 2;
            if attempt(surface, midpoint).1.is_ok() {
                upper = midpoint;
            } else {
                lower = midpoint + 1;
            }
        }
        let exact_ceiling = lower;
        assert!(exact_ceiling > baseline);

        let (refused_core, refusal, _, refused_heap_before) = attempt(surface, exact_ceiling - 1);
        assert!(matches!(
            refusal,
            Err(InterpreterError::MemoryBudgetExceeded {
                max_bytes,
                ..
            }) if max_bytes == exact_ceiling - 1
        ));
        assert!(refused_core.heap.len() >= refused_heap_before);

        let (exact_core, exact, _, exact_heap_before) = attempt(surface, exact_ceiling);
        exact.expect("exact Writable callback ceiling");
        assert_eq!(
            exact_core.heap.len(),
            exact_heap_before + 8,
            "the guest callback must complete every re-entrant allocation at its exact ceiling"
        );
    }
}

#[test]
fn writable_thrown_payload_stays_charged_across_later_callback_bd_66awx() {
    let thrown_digits = "8".repeat(4096);
    let mut instructions = vec![
        Ir3Instruction::LoadBigInt {
            dst: 0,
            value: thrown_digits.clone(),
        },
        Ir3Instruction::Throw { value: 0 },
    ];
    for register in 0..8 {
        instructions.push(Ir3Instruction::NewObject { dst: register });
    }
    instructions.push(Ir3Instruction::Return { value: 7 });
    let module = test_module_with_functions(
        instructions,
        vec![
            Ir3FunctionDesc {
                entry: 0,
                arity: 0,
                frame_size: 2,
                name: Some("throw_large_writable_error".to_string()),
                is_generator: false,
                rest_param_index: None,
            },
            Ir3FunctionDesc {
                entry: 2,
                arity: 0,
                frame_size: 10,
                name: Some("allocate_after_writable_error".to_string()),
                is_generator: false,
                rest_param_index: None,
            },
        ],
    );
    let lifecycle_label = Label::Custom {
        name: "writable-error-batch-snapshot".repeat(24),
        level: 37,
    };

    let attempt = |budget: u64| {
        let mut core = test_interpreter();
        let Value::Object(writable) = core
            .construct_stream_writable(RegRange { start: 0, count: 0 })
            .expect("error-batch Writable")
        else {
            panic!("Writable constructor must return an object");
        };
        let state = core
            .writable_streams
            .get_mut(&writable)
            .expect("live error-batch Writable");
        state.lifecycle_label = lifecycle_label.clone();
        for function in 0..2 {
            state.end_callbacks.push_back(WritableEndCallbackRecord {
                callback: WritableCallbackRecord {
                    value: Value::Function(function),
                    label: lifecycle_label.clone(),
                    module_specifier: Some(module.header.source_label.clone()),
                },
                registered_after_end: false,
            });
        }
        state.end_callback_batch_remaining = 2;
        state.end_requested = true;
        state.final_status = WritableFinalStatus::Done;
        state.tick_phase = WritableTickPhase::Finish;
        let baseline = core
            .sync_estimated_memory_bytes()
            .expect("error-batch callback baseline");
        let heap_before = core.heap.len();
        core.config.max_total_memory_bytes = budget;
        let result = core.drive_writable_tick(writable, Some(&module));
        assert_eq!(core.writable_in_flight_callback_bytes, 0);
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
        (core, result, baseline, heap_before)
    };

    let (unbounded_core, unbounded_result, baseline, heap_before) = attempt(u64::MAX);
    assert!(matches!(
        unbounded_result,
        Err(InterpreterError::UncaughtException { .. })
    ));
    assert_eq!(unbounded_core.heap.len(), heap_before + 8);
    assert_eq!(
        unbounded_core.pending_exception,
        Some(Value::BigInt(Arc::from(thrown_digits.clone())))
    );

    let completed = |budget| {
        let (core, result, _, heap_before) = attempt(budget);
        core.heap.len() == heap_before + 8
            && matches!(result, Err(InterpreterError::UncaughtException { .. }))
    };
    let mut distance = 1u64;
    let mut upper = loop {
        let budget = baseline.saturating_add(distance);
        if completed(budget) {
            break budget;
        }
        distance = distance
            .checked_mul(2)
            .expect("Writable thrown-payload ceiling search remains bounded");
        assert!(distance <= (1 << 32));
    };
    let mut lower = baseline;
    while lower < upper {
        let midpoint = lower + (upper - lower) / 2;
        if completed(midpoint) {
            upper = midpoint;
        } else {
            lower = midpoint + 1;
        }
    }
    let exact_ceiling = lower;
    assert!(exact_ceiling > baseline);
    assert!(!completed(exact_ceiling - 1));
    assert!(completed(exact_ceiling));
}

#[test]
fn writable_throw_charge_refusal_clears_unowned_payload_bd_66awx() {
    let thrown_digits = "6".repeat(8192);
    let module = test_module_with_functions(
        vec![
            Ir3Instruction::NewObject { dst: 1 },
            Ir3Instruction::Throw { value: 0 },
        ],
        vec![Ir3FunctionDesc {
            entry: 0,
            arity: 1,
            frame_size: 2,
            name: Some("throw_over_writable_retention_budget".to_string()),
            is_generator: false,
            rest_param_index: None,
        }],
    );

    let attempt = |budget: u64| {
        let mut core = test_interpreter();
        let Value::Object(writable) = core
            .construct_stream_writable(RegRange { start: 0, count: 0 })
            .expect("throw-refusal Writable")
        else {
            panic!("Writable constructor must return an object");
        };
        let error_label = Label::Custom {
            name: "throw-retention-refusal-label".repeat(16),
            level: 41,
        };
        let state = core
            .writable_streams
            .get_mut(&writable)
            .expect("live throw-refusal Writable");
        state.lifecycle_label = error_label.clone();
        state.end_callbacks.push_back(WritableEndCallbackRecord {
            callback: WritableCallbackRecord {
                value: Value::Function(0),
                label: error_label.clone(),
                module_specifier: Some(module.header.source_label.clone()),
            },
            registered_after_end: false,
        });
        state.end_callback_batch_remaining = 1;
        state.end_requested = true;
        state.final_status = WritableFinalStatus::Done;
        state.terminal_error = Some((Value::BigInt(Arc::from(thrown_digits.clone())), error_label));
        state.terminal_error_origin = Some(WritableErrorOrigin::Write);
        state.tick_phase = WritableTickPhase::Error;
        let baseline = core
            .sync_estimated_memory_bytes()
            .expect("throw-refusal baseline");
        let heap_before = core.heap.len();
        core.config.max_total_memory_bytes = budget;
        let result = core.drive_writable_tick(writable, Some(&module));
        assert_eq!(core.writable_in_flight_callback_bytes, 0);
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
        (core, result, baseline, heap_before)
    };

    let (_, _, baseline, _) = attempt(u64::MAX);
    let entered_guest = |budget| {
        let (core, _, _, heap_before) = attempt(budget);
        core.heap.len() == heap_before + 1
    };
    let mut distance = 1u64;
    let mut upper = loop {
        let budget = baseline.saturating_add(distance);
        if entered_guest(budget) {
            break budget;
        }
        distance = distance
            .checked_mul(2)
            .expect("Writable throw-refusal ceiling search remains bounded");
        assert!(distance <= (1 << 32));
    };
    let mut lower = baseline;
    while lower < upper {
        let midpoint = lower + (upper - lower) / 2;
        if entered_guest(midpoint) {
            upper = midpoint;
        } else {
            lower = midpoint + 1;
        }
    }
    let (core, result, _, heap_before) = attempt(lower);
    assert_eq!(core.heap.len(), heap_before + 1);
    assert!(matches!(
        result,
        Err(InterpreterError::MemoryBudgetExceeded { .. })
    ));
    assert_eq!(core.pending_exception, None);
    assert_eq!(core.pending_exception_label, Label::Public);
}

#[test]
fn synchronous_write_throw_propagates_without_fabricating_completion_bd_fw7zd() {
    let module = test_module_with_functions(
        vec![
            Ir3Instruction::LoadInt { dst: 0, value: 31 },
            Ir3Instruction::Throw { value: 0 },
        ],
        vec![Ir3FunctionDesc {
            entry: 0,
            arity: 3,
            frame_size: 4,
            name: Some("throwing_write".to_string()),
            is_generator: false,
            rest_param_index: None,
        }],
    );
    let mut core = test_interpreter();
    let options = core
        .alloc_object_with_properties(&[("write", Value::Function(0))])
        .expect("Writable write options");
    core.write_reg(0, Value::Object(options))
        .expect("Writable options register");
    let Value::Object(writable) = core
        .construct_stream_writable(RegRange { start: 0, count: 1 })
        .expect("Writable with throwing write")
    else {
        panic!("Writable constructor must return an object");
    };
    core.write_reg(1, Value::str("x")).expect("write chunk");
    assert!(matches!(
        core.writable_write(
            &module,
            Value::Object(writable),
            RegRange { start: 1, count: 1 },
        ),
        Err(InterpreterError::UncaughtException { .. })
    ));
    let state = &core.writable_streams[&writable];
    let token = match state.writes[0].status {
        WritableWriteStatus::Active(token) => token,
        ref status => panic!("entered throwing write must stay Active, got {status:?}"),
    };
    assert_eq!(state.buffered_length, 1);
    assert!(state.terminal_error.is_none());
    assert!(!state.inside_write_invocation);
    assert!(state.tick_sequence.is_none());
    assert_eq!(core.pending_exception, Some(Value::Int(31)));
    let instructions_after_throw = core.instructions_executed;
    core.drive_writable(writable, &module)
        .expect("an entered throwing write must not be retried");
    assert_eq!(
        core.writable_streams[&writable].writes[0].status,
        WritableWriteStatus::Active(token)
    );
    assert_eq!(core.instructions_executed, instructions_after_throw);
    assert!(core.inline_callback_start_probes.is_empty());
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn empty_writable_end_progresses_at_memory_ceiling_bd_fw7zd() {
    let module = test_module_with_functions(Vec::new(), Vec::new());
    let mut core = test_interpreter();
    let Value::Object(writable) = core
        .construct_stream_writable(RegRange { start: 0, count: 0 })
        .expect("generic Writable")
    else {
        panic!("Writable constructor must return an object");
    };
    core.config.max_total_memory_bytes = core.estimated_memory_bytes();
    core.writable_end(
        &module,
        Value::Object(writable),
        RegRange { start: 0, count: 0 },
    )
    .expect("empty end must not require a temporary full-state clone");
    core.drain_runtime_checkpoint(Some(&module))
        .expect("empty Writable lifecycle checkpoint");
    assert!(!core.writable_streams.contains_key(&writable));
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn seed_reset_clears_writable_state_listeners_and_waiters_bd_fw7zd() {
    let mut core = test_interpreter();
    let Value::Object(writable) = core
        .construct_stream_writable(RegRange { start: 0, count: 0 })
        .expect("generic Writable")
    else {
        panic!("Writable constructor must return an object");
    };
    core.insert_event_listener(
        writable,
        "finish",
        EventListenerRecord {
            listener: Value::BuiltinFunction(BuiltinFunction::new_kind(
                BuiltinFunctionKind::ArrayIsArray,
            )),
            once: false,
        },
        false,
    )
    .expect("Writable listener");
    core.write_reg(0, Value::Object(writable))
        .expect("events.once receiver");
    core.write_reg(1, Value::str("finish"))
        .expect("events.once name");
    // Keep the heap/register seed byte-identical so this test isolates the
    // execution-local side-table release performed by the reset boundary.
    let seed = core
        .capture_execution_seed()
        .expect("test execution-seed capture must fit");
    core.register_event_promise_once(RegRange { start: 0, count: 2 })
        .expect("events.once waiter");
    core.writable_streams
        .get_mut(&writable)
        .expect("live Writable before reset")
        .end_callbacks
        .push_back(WritableEndCallbackRecord {
            callback: WritableCallbackRecord {
                value: Value::BuiltinFunction(BuiltinFunction::new_kind(
                    BuiltinFunctionKind::ArrayIsArray,
                )),
                label: Label::Secret,
                module_specifier: Some("reset-owner.mjs".to_string()),
            },
            registered_after_end: false,
        });
    core.sync_estimated_memory_bytes()
        .expect("populated terminal FIFO accounting");
    assert!(core.event_listeners.contains_key(&writable));
    assert!(core.event_promise_waiters.contains_key(&writable));
    assert_eq!(core.writable_streams[&writable].end_callbacks.len(), 1);

    core.reset_execution_state_from_seed(&seed)
        .expect("seed reset");
    assert!(!core.writable_streams.contains_key(&writable));
    assert!(!core.event_listeners.contains_key(&writable));
    assert!(!core.event_promise_waiters.contains_key(&writable));
    assert!(matches!(
        core.writable_receiver_id(Value::Object(writable)),
        Err(InterpreterError::TypeError { .. })
    ));
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn passthrough_constructor_is_aggregate_and_seed_reset_clears_both_halves_bd_fw7zd() {
    let mut accepted = test_interpreter();
    let accepted_base = accepted.estimated_memory_bytes();
    let accepted_heap_len = accepted.heap.len();
    let Value::Object(passthrough) = accepted
        .construct_stream_passthrough(RegRange { start: 0, count: 0 })
        .expect("aggregate PassThrough constructor")
    else {
        panic!("PassThrough constructor must return an object");
    };
    assert!(accepted.readable_from_streams.contains_key(&passthrough));
    assert!(accepted.writable_streams.contains_key(&passthrough));
    assert_eq!(
        accepted.estimated_memory_bytes(),
        accepted.recompute_estimated_memory_bytes()
    );
    let aggregate_delta = accepted
        .estimated_memory_bytes()
        .saturating_sub(accepted_base);

    let mut refused = test_interpreter();
    let refused_base = refused.estimated_memory_bytes();
    let refused_heap_len = refused.heap.len();
    assert_eq!(refused_base, accepted_base);
    refused.config.max_total_memory_bytes = refused_base
        .saturating_add(aggregate_delta)
        .saturating_sub(1);
    assert!(matches!(
        refused.construct_stream_passthrough(RegRange { start: 0, count: 0 }),
        Err(InterpreterError::MemoryBudgetExceeded { .. })
    ));
    assert_eq!(refused.heap.len(), refused_heap_len);
    assert!(refused.readable_from_streams.is_empty());
    assert!(refused.writable_streams.is_empty());
    assert_eq!(refused.estimated_memory_bytes(), refused_base);
    assert_eq!(
        refused.estimated_memory_bytes(),
        refused.recompute_estimated_memory_bytes()
    );

    let mut reset = test_interpreter();
    let seed = reset
        .capture_execution_seed()
        .expect("test execution-seed capture must fit");
    let Value::Object(reused) = reset
        .construct_stream_passthrough(RegRange { start: 0, count: 0 })
        .expect("PassThrough before reset")
    else {
        panic!("PassThrough constructor must return an object");
    };
    reset
        .readable_from_streams
        .get_mut(&reused)
        .expect("PassThrough readable state before reset")
        .nonflowing_read_consumed = true;
    reset
        .schedule_readable_from_pump(reused)
        .expect("pending PassThrough readable pump");
    reset
        .insert_event_listener(
            reused,
            "data",
            EventListenerRecord {
                listener: Value::BuiltinFunction(BuiltinFunction::new_kind(
                    BuiltinFunctionKind::ArrayIsArray,
                )),
                once: false,
            },
            false,
        )
        .expect("PassThrough listener before reset");
    assert!(!reset.pending_readable_from_pumps.is_empty());

    reset
        .reset_execution_state_from_seed(&seed)
        .expect("PassThrough seed reset");
    assert_eq!(reset.heap.len(), accepted_heap_len);
    assert!(!reset.readable_from_streams.contains_key(&reused));
    assert!(!reset.writable_streams.contains_key(&reused));
    assert!(reset.pending_readable_from_pumps.is_empty());
    assert!(!reset.event_listeners.contains_key(&reused));
    assert_eq!(
        reset.estimated_memory_bytes(),
        reset.recompute_estimated_memory_bytes()
    );
}

#[test]
fn passthrough_internal_write_failure_terminalizes_both_halves_bd_fw7zd() {
    let mut core = test_interpreter();
    let Value::Object(passthrough) = core
        .construct_stream_passthrough(RegRange { start: 0, count: 0 })
        .expect("PassThrough")
    else {
        panic!("PassThrough constructor must return an object");
    };
    core.writable_enqueue(passthrough, Value::str("pending"), Label::Public, None)
        .expect("pending PassThrough write");
    let token = core
        .allocate_writable_completion_token()
        .expect("completion token");
    let state = core
        .writable_streams
        .get_mut(&passthrough)
        .expect("writable half");
    state.writes[0].status = WritableWriteStatus::Active(token);
    state.inside_write_invocation = true;

    core.record_dual_stream_failure(
        passthrough,
        Value::str("forwarding failed"),
        Label::Secret,
        WritableErrorOrigin::Write,
        false,
    )
    .expect("aggregate PassThrough failure");

    let readable = &core.readable_from_streams[&passthrough];
    assert!(readable.destroy_requested);
    assert_eq!(readable.phase, ReadableFromPumpPhase::DestroyError);
    assert_eq!(readable.lifecycle_label, Label::Secret);
    let writable = &core.writable_streams[&passthrough];
    assert!(writable.destroy_requested);
    assert!(writable.terminal_error_emitted);
    assert_eq!(writable.buffered_length, 0);
    assert!(writable.writes.iter().all(|record| {
        record.status == WritableWriteStatus::Completed && record.completion_failed
    }));
    assert!(!core.pending_readable_from_pumps.is_empty());
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn passthrough_flowing_final_reserves_its_deferred_tick_bd_fw7zd() {
    let module = test_module_with_functions(Vec::new(), Vec::new());
    let mut core = test_interpreter();
    let Value::Object(passthrough) = core
        .construct_stream_passthrough(RegRange { start: 0, count: 0 })
        .expect("PassThrough")
    else {
        panic!("PassThrough constructor must return an object");
    };
    let Value::Object(other) = core
        .construct_stream_writable(RegRange { start: 0, count: 0 })
        .expect("other Writable")
    else {
        panic!("Writable constructor must return an object");
    };
    let token = core
        .allocate_writable_completion_token()
        .expect("final completion token");
    core.writable_streams
        .get_mut(&passthrough)
        .expect("PassThrough Writable half")
        .final_status = WritableFinalStatus::Active(token);
    let readable = core
        .readable_from_streams
        .get_mut(&passthrough)
        .expect("PassThrough Readable half");
    readable.flowing = true;
    readable.paused = false;
    let completion = BuiltinFunction::writable_completion(
        BuiltinFunctionKind::StreamWritableFinalDone,
        passthrough,
        token,
    );
    core.write_reg(0, Value::BuiltinFunction(completion))
        .expect("final completion register");
    core.next_writable_tick_sequence = u64::MAX - 1;

    core.stream_passthrough_final(
        &module,
        Value::Object(passthrough),
        RegRange { start: 0, count: 1 },
    )
    .expect("flowing PassThrough final");
    let state = &core.writable_streams[&passthrough];
    assert_eq!(state.final_status, WritableFinalStatus::Active(token));
    assert_eq!(state.deferred_final_tick_sequence, Some(u64::MAX - 1));
    assert_eq!(state.tick_sequence, None);
    assert_eq!(core.next_writable_tick_sequence, u64::MAX);
    assert!(matches!(
        core.schedule_writable_tick(other),
        Err(InterpreterError::InternalError { .. })
    ));

    core.complete_deferred_dual_stream_final(passthrough, &module)
        .expect("reserved final tick remains usable after global exhaustion");
    let state = &core.writable_streams[&passthrough];
    assert_eq!(state.final_status, WritableFinalStatus::Done);
    assert_eq!(state.deferred_final_tick_sequence, None);
    assert_eq!(state.tick_sequence, Some(u64::MAX - 1));
    assert_eq!(core.next_writable_tick_sequence, u64::MAX);
}

#[test]
fn passthrough_pull_drain_is_engine_owned_and_defers_final_bd_fw7zd_11() {
    let module = test_module_with_functions(Vec::new(), Vec::new());
    let mut core = test_interpreter();
    let Value::Object(passthrough) = core
        .construct_stream_passthrough(RegRange { start: 0, count: 0 })
        .expect("PassThrough")
    else {
        panic!("PassThrough constructor must return an object");
    };
    core.readable_enqueue_value(passthrough, Value::str("x"), Label::Secret)
        .expect("secret readable chunk");
    core.active_readable_listener_target = Some(passthrough);
    let consumed = core
        .readable_read(Value::Object(passthrough), RegRange { start: 0, count: 0 })
        .expect("non-flowing read");
    core.active_readable_listener_target = None;
    assert!(matches!(consumed, Value::Object(_)));
    let readable = &core.readable_from_streams[&passthrough];
    assert!(readable.nonflowing_read_consumed);
    assert!(readable.buffer.is_empty());
    assert_eq!(readable.lifecycle_label, Label::Secret);

    // A forgeable mirror cannot erase the engine-owned pull evidence.
    core.set_object_property(
        passthrough,
        "readableFlowing".to_string(),
        Value::Bool(true),
    )
    .expect("tamper readableFlowing mirror");
    let token = core
        .allocate_writable_completion_token()
        .expect("final completion token");
    core.writable_streams
        .get_mut(&passthrough)
        .expect("PassThrough writable state")
        .final_status = WritableFinalStatus::Active(token);
    let completion = BuiltinFunction::writable_completion(
        BuiltinFunctionKind::StreamWritableFinalDone,
        passthrough,
        token,
    );
    core.write_reg(0, Value::BuiltinFunction(completion))
        .expect("final completion register");
    core.stream_passthrough_final(
        &module,
        Value::Object(passthrough),
        RegRange { start: 0, count: 1 },
    )
    .expect("pull-drained final");

    let writable = &core.writable_streams[&passthrough];
    assert_eq!(writable.final_status, WritableFinalStatus::Active(token));
    assert!(writable.deferred_final_tick_sequence.is_some());
    assert_eq!(
        core.readable_from_streams[&passthrough].phase,
        ReadableFromPumpPhase::Data
    );
    assert!(core.readable_from_streams[&passthrough].eof_readable_pending);
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn passthrough_prefinish_push_error_consumes_reserved_final_tick_bd_fw7zd_11() {
    let module = test_module_with_functions(Vec::new(), Vec::new());
    let mut core = test_interpreter();
    let Value::Object(passthrough) = core
        .construct_stream_passthrough(RegRange { start: 0, count: 0 })
        .expect("PassThrough")
    else {
        panic!("PassThrough constructor must return an object");
    };
    let token = core
        .allocate_writable_completion_token()
        .expect("final completion token");
    let writable = core
        .writable_streams
        .get_mut(&passthrough)
        .expect("PassThrough writable state");
    writable.end_requested = true;
    writable.final_status = WritableFinalStatus::Active(token);
    let readable = core
        .readable_from_streams
        .get_mut(&passthrough)
        .expect("PassThrough readable state");
    readable.flowing = true;
    readable.paused = false;
    let completion = BuiltinFunction::writable_completion(
        BuiltinFunctionKind::StreamWritableFinalDone,
        passthrough,
        token,
    );
    core.write_reg(0, Value::BuiltinFunction(completion))
        .expect("final completion register");
    core.next_writable_tick_sequence = 41;
    core.stream_passthrough_final(
        &module,
        Value::Object(passthrough),
        RegRange { start: 0, count: 1 },
    )
    .expect("flowing final");
    assert_eq!(
        core.writable_streams[&passthrough].deferred_final_tick_sequence,
        Some(41)
    );

    core.write_reg_with_label(1, Value::str("extra"), Label::Secret)
        .expect("secret rejected push");
    assert_eq!(
        core.readable_push(Value::Object(passthrough), RegRange { start: 1, count: 1 },)
            .expect("push after committed EOF"),
        Value::Bool(false)
    );

    let writable = &core.writable_streams[&passthrough];
    assert_eq!(writable.final_status, WritableFinalStatus::Done);
    assert_eq!(writable.deferred_final_tick_sequence, None);
    assert_eq!(writable.tick_sequence, Some(41));
    assert_eq!(
        writable.terminal_error_origin,
        Some(WritableErrorOrigin::Final)
    );
    assert_eq!(writable.lifecycle_label, Label::Secret);
    let (Value::Object(error_id), error_label) = writable
        .terminal_error
        .as_ref()
        .expect("retained push-after-EOF error")
    else {
        panic!("push-after-EOF error must be an Error object");
    };
    assert_eq!(error_label, &Label::Secret);
    assert_eq!(
        core.heap[error_id.0 as usize].properties.get("code"),
        Some(&Value::str("ERR_STREAM_PUSH_AFTER_EOF"))
    );
    let readable = &core.readable_from_streams[&passthrough];
    assert_eq!(readable.phase, ReadableFromPumpPhase::DestroyError);
    assert_eq!(readable.lifecycle_label, Label::Secret);
    assert_eq!(core.next_writable_tick_sequence, 42);
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn passthrough_prefinish_write_then_pause_consumes_reserved_final_tick_bd_fw7zd_11() {
    let module = writable_order_module(&["error", "close", "finish"]);
    let mut core = test_interpreter();
    let log = install_writable_order_log(&mut core);
    let Value::Object(passthrough) = core
        .construct_stream_passthrough(RegRange { start: 0, count: 0 })
        .expect("PassThrough")
    else {
        panic!("PassThrough constructor must return an object");
    };
    for (event, function_index) in [("error", 0), ("close", 1), ("finish", 2)] {
        core.insert_event_listener(
            passthrough,
            event,
            EventListenerRecord {
                listener: Value::Function(function_index),
                once: false,
            },
            false,
        )
        .expect("observe deferred PassThrough lifecycle");
    }
    let token = core
        .allocate_writable_completion_token()
        .expect("final completion token");
    let writable = core
        .writable_streams
        .get_mut(&passthrough)
        .expect("PassThrough writable state");
    writable.end_requested = true;
    writable.final_status = WritableFinalStatus::Active(token);
    let readable = core
        .readable_from_streams
        .get_mut(&passthrough)
        .expect("PassThrough readable state");
    readable.flowing = true;
    readable.paused = false;
    let completion = BuiltinFunction::writable_completion(
        BuiltinFunctionKind::StreamWritableFinalDone,
        passthrough,
        token,
    );
    core.write_reg(0, Value::BuiltinFunction(completion))
        .expect("final completion register");
    core.next_writable_tick_sequence = 91;
    core.stream_passthrough_final(
        &module,
        Value::Object(passthrough),
        RegRange { start: 0, count: 1 },
    )
    .expect("flowing final");
    assert_eq!(
        core.writable_streams[&passthrough].deferred_final_tick_sequence,
        Some(91)
    );

    core.write_reg_with_label(1, Value::str("extra"), Label::Secret)
        .expect("secret rejected write");
    assert_eq!(
        core.writable_write(
            &module,
            Value::Object(passthrough),
            RegRange { start: 1, count: 1 },
        )
        .expect("write after committed end"),
        Value::Bool(false)
    );
    core.readable_pause(Value::Object(passthrough))
        .expect("prefinish pause after rejected write");

    let writable = &core.writable_streams[&passthrough];
    assert_eq!(writable.final_status, WritableFinalStatus::Done);
    assert_eq!(writable.deferred_final_tick_sequence, None);
    assert_eq!(writable.tick_sequence, Some(91));
    // The reserved turn first drains callbacks; it publishes the error
    // only at a checkpoint. Recording the terminal failure is synchronous.
    assert_eq!(writable.tick_phase, WritableTickPhase::Callbacks);
    // A dual stream reserves delivery for the readable half and marks
    // the writable half to suppress a duplicate shared-emitter event.
    // The empty log below proves this ownership marker is not delivery.
    assert!(writable.terminal_error_emitted);
    assert!(writable_order_entries(&core, log).is_empty());
    assert_eq!(
        writable.terminal_error_origin,
        Some(WritableErrorOrigin::Write)
    );
    assert_eq!(writable.lifecycle_label, Label::Secret);
    let (Value::Object(error_id), error_label) = writable
        .terminal_error
        .as_ref()
        .expect("retained write-after-end error")
    else {
        panic!("write-after-end error must be an Error object");
    };
    assert_eq!(error_label, &Label::Secret);
    assert_eq!(
        core.heap[error_id.0 as usize].properties.get("code"),
        Some(&Value::str("ERR_STREAM_WRITE_AFTER_END"))
    );
    let readable = &core.readable_from_streams[&passthrough];
    assert_eq!(readable.phase, ReadableFromPumpPhase::DestroyError);
    assert!(readable.paused);
    assert!(!readable.flowing);
    assert_eq!(readable.lifecycle_label, Label::Secret);
    assert_eq!(
        core.fs_object_property(&Value::Object(passthrough), "readableFlowing"),
        Some(Value::Bool(false))
    );
    assert_eq!(core.next_writable_tick_sequence, 92);
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );

    core.run_event_loop_until_idle_with_module(Some(&module))
        .expect("deliver the reserved error and deferred close");
    assert_eq!(writable_order_entries(&core, log), ["error", "close"]);
    assert_eq!(core.object_mutation_labels.get(&log), Some(&Label::Secret));
    assert!(!core.writable_streams.contains_key(&passthrough));
    assert!(!core.readable_from_streams.contains_key(&passthrough));
    assert_eq!(
        core.fs_object_property(&Value::Object(passthrough), "writableFinished"),
        Some(Value::Bool(false)),
        "a failed final must not publish a successful finish"
    );
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn passthrough_throwing_eof_readable_consumes_reserved_final_tick_bd_fw7zd_11() {
    let module = test_module_with_functions(
        vec![Ir3Instruction::Throw { value: 0 }],
        vec![Ir3FunctionDesc {
            entry: 0,
            arity: 0,
            frame_size: 1,
            name: Some("throw_from_eof_readable".to_string()),
            is_generator: false,
            rest_param_index: None,
        }],
    );
    let mut core = test_interpreter();
    let Value::Object(passthrough) = core
        .construct_stream_passthrough(RegRange { start: 0, count: 0 })
        .expect("PassThrough")
    else {
        panic!("PassThrough constructor must return an object");
    };
    core.readable_enqueue_value(passthrough, Value::str("unread"), Label::Secret)
        .expect("unread PassThrough chunk");
    core.insert_event_listener(
        passthrough,
        "readable",
        EventListenerRecord {
            listener: Value::Function(0),
            once: false,
        },
        false,
    )
    .expect("throwing readable listener");
    let token = core
        .allocate_writable_completion_token()
        .expect("final completion token");
    let writable = core
        .writable_streams
        .get_mut(&passthrough)
        .expect("PassThrough writable state");
    writable.end_requested = true;
    writable.final_status = WritableFinalStatus::Active(token);
    writable.deferred_final_tick_sequence = Some(u64::MAX - 1);
    writable.lifecycle_label = Label::Secret;
    core.next_writable_tick_sequence = u64::MAX;
    let readable = core
        .readable_from_streams
        .get_mut(&passthrough)
        .expect("PassThrough readable state");
    readable.flowing = false;
    readable.paused = true;
    readable.eof_requested = true;
    readable.data_readable_pending = false;
    readable.eof_readable_pending = true;

    let error = core
        .run_event_loop_until_idle_with_module(Some(&module))
        .expect_err("throwing EOF-readable listener must escape");
    assert_eq!(
        error,
        InterpreterError::UncaughtException {
            value: "undefined".to_string()
        }
    );
    assert!(!core.readable_from_streams.contains_key(&passthrough));
    assert!(!core.writable_streams.contains_key(&passthrough));
    let writable = &core.writable_terminal_states[&passthrough];
    assert!(writable.end_requested);
    assert_eq!(writable.tick_sequence, None);
    assert_eq!(writable.lifecycle_label, Label::Secret);
    assert_eq!(core.next_writable_tick_sequence, u64::MAX);
    assert!(core.pending_readable_from_pumps.is_empty());
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn passthrough_throwing_initial_readable_terminalizes_pre_final_lane_bd_fw7zd_11() {
    let module = test_module_with_functions(
        vec![Ir3Instruction::Throw { value: 0 }],
        vec![Ir3FunctionDesc {
            entry: 0,
            arity: 0,
            frame_size: 1,
            name: Some("throw_from_initial_readable".to_string()),
            is_generator: false,
            rest_param_index: None,
        }],
    );
    let mut core = test_interpreter();
    let Value::Object(passthrough) = core
        .construct_stream_passthrough(RegRange { start: 0, count: 0 })
        .expect("PassThrough")
    else {
        panic!("PassThrough constructor must return an object");
    };
    core.readable_enqueue_value(passthrough, Value::str("unread"), Label::Secret)
        .expect("initial unread PassThrough chunk");
    core.insert_event_listener(
        passthrough,
        "readable",
        EventListenerRecord {
            listener: Value::Function(0),
            once: false,
        },
        false,
    )
    .expect("throwing readable listener");
    let writable = core
        .writable_streams
        .get_mut(&passthrough)
        .expect("PassThrough writable state");
    writable.end_requested = true;
    writable.lifecycle_label = Label::Secret;
    core.next_writable_tick_sequence = u64::MAX - 1;
    let readable = core
        .readable_from_streams
        .get_mut(&passthrough)
        .expect("PassThrough readable state");
    readable.flowing = false;
    readable.paused = true;
    assert!(readable.data_readable_pending);
    core.drive_writable(passthrough, &module)
        .expect("pre-final pull lane waits for its readable notification");
    assert_eq!(core.writable_streams[&passthrough].tick_sequence, None);
    assert_eq!(core.next_writable_tick_sequence, u64::MAX - 1);
    core.drain_runtime_checkpoint(Some(&module))
        .expect("top-level checkpoint before the readable turn");
    assert_eq!(core.writable_streams[&passthrough].tick_sequence, None);
    assert_eq!(core.next_writable_tick_sequence, u64::MAX - 1);

    let error = core
        .run_event_loop_until_idle_with_module(Some(&module))
        .expect_err("throwing initial readable listener must escape");
    assert_eq!(
        error,
        InterpreterError::UncaughtException {
            value: "undefined".to_string()
        }
    );
    assert!(!core.readable_from_streams.contains_key(&passthrough));
    assert!(!core.writable_streams.contains_key(&passthrough));
    let writable = &core.writable_terminal_states[&passthrough];
    assert!(writable.end_requested);
    assert_eq!(writable.tick_sequence, None);
    assert_eq!(writable.lifecycle_label, Label::Secret);
    assert_eq!(core.next_writable_tick_sequence, u64::MAX - 1);
    assert!(core.pending_readable_from_pumps.is_empty());
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn passthrough_end_destroy_preserves_reserved_finish_lane_bd_fw7zd_11() {
    for (error, expected_phase) in [
        (None, ReadableFromPumpPhase::Close),
        (
            Some(Value::str("boom")),
            ReadableFromPumpPhase::DestroyError,
        ),
    ] {
        let mut core = test_interpreter();
        let Value::Object(passthrough) = core
            .construct_stream_passthrough(RegRange { start: 0, count: 0 })
            .expect("PassThrough")
        else {
            panic!("PassThrough constructor must return an object");
        };
        let token = core
            .allocate_writable_completion_token()
            .expect("final completion token");
        let writable = core
            .writable_streams
            .get_mut(&passthrough)
            .expect("PassThrough writable state");
        writable.final_status = WritableFinalStatus::Active(token);
        writable.deferred_final_tick_sequence = Some(73);
        core.next_writable_tick_sequence = 74;
        core.readable_from_streams
            .get_mut(&passthrough)
            .expect("PassThrough readable state")
            .phase = ReadableFromPumpPhase::Close;

        let args = if let Some(error) = error {
            core.write_reg_with_label(0, error, Label::Secret)
                .expect("destroy error register");
            RegRange { start: 0, count: 1 }
        } else {
            RegRange { start: 0, count: 0 }
        };
        core.stream_passthrough_destroy(Value::Object(passthrough), args)
            .expect("destroy from end listener");

        let writable = &core.writable_streams[&passthrough];
        assert_eq!(writable.final_status, WritableFinalStatus::Done);
        assert_eq!(writable.deferred_final_tick_sequence, None);
        assert_eq!(writable.tick_sequence, Some(73));
        assert_eq!(writable.tick_phase, WritableTickPhase::Finish);
        assert!(writable.finished);
        assert_eq!(
            core.fs_object_property(&Value::Object(passthrough), "writableFinished"),
            Some(Value::Bool(false))
        );
        let readable = &core.readable_from_streams[&passthrough];
        assert!(readable.destroy_requested);
        assert_eq!(readable.phase, expected_phase);
        if expected_phase == ReadableFromPumpPhase::DestroyError {
            assert_eq!(writable.lifecycle_label, Label::Secret);
            assert_eq!(readable.lifecycle_label, Label::Secret);
        }
        assert_eq!(core.next_writable_tick_sequence, 74);
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }
}

#[test]
fn writable_completion_tokens_fail_closed_before_wraparound_bd_fw7zd() {
    let module = test_module_with_functions(Vec::new(), Vec::new());
    let mut core = test_interpreter();
    let Value::Object(writable) = core
        .construct_stream_writable(RegRange { start: 0, count: 0 })
        .expect("generic Writable")
    else {
        panic!("Writable constructor must return an object");
    };
    core.writable_streams
        .get_mut(&writable)
        .expect("live Writable")
        .write_callback = Some(Value::BuiltinFunction(BuiltinFunction::new_kind(
        BuiltinFunctionKind::ArrayIsArray,
    )));
    core.writable_enqueue(writable, Value::str("x"), Label::Public, None)
        .expect("pending write");
    core.next_writable_completion_token = u32::MAX;
    assert!(matches!(
        core.drive_writable(writable, &module),
        Err(InterpreterError::InternalError { .. })
    ));
    assert_eq!(
        core.writable_streams[&writable].writes[0].status,
        WritableWriteStatus::Pending
    );
}

#[test]
fn writable_public_token_exhaustion_refuses_before_state_mutation_bd_o2xvz() {
    let module = test_module_with_functions(
        vec![
            Ir3Instruction::LoadUndefined { dst: 0 },
            Ir3Instruction::Return { value: 0 },
        ],
        vec![Ir3FunctionDesc {
            entry: 0,
            arity: 3,
            frame_size: 4,
            name: Some("pending_write".to_string()),
            is_generator: false,
            rest_param_index: None,
        }],
    );
    let mut write_core = test_interpreter();
    let write_options = write_core
        .alloc_object_with_properties(&[("write", Value::Function(0))])
        .expect("Writable write options");
    write_core
        .write_reg(0, Value::Object(write_options))
        .expect("Writable options register");
    let Value::Object(write_stream) = write_core
        .construct_stream_writable(RegRange { start: 0, count: 1 })
        .expect("Writable with write implementation")
    else {
        panic!("Writable constructor must return an object");
    };
    write_core
        .write_reg_with_label(1, Value::str("refused"), Label::Secret)
        .expect("write chunk");
    write_core.next_writable_completion_token = u32::MAX;
    let write_state_before = format!("{:?}", write_core.writable_streams[&write_stream]);
    let write_mirror_before =
        write_core.fs_object_property(&Value::Object(write_stream), "writableLength");
    let write_bytes_before = write_core.estimated_memory_bytes();

    assert!(matches!(
        write_core.writable_write(
            &module,
            Value::Object(write_stream),
            RegRange { start: 1, count: 1 },
        ),
        Err(InterpreterError::InternalError { details })
            if details == "Writable completion token space exhausted"
    ));
    assert_eq!(
        format!("{:?}", write_core.writable_streams[&write_stream]),
        write_state_before
    );
    assert_eq!(
        write_core.fs_object_property(&Value::Object(write_stream), "writableLength"),
        write_mirror_before
    );
    assert_eq!(write_core.next_writable_completion_token, u32::MAX);
    assert_eq!(write_core.estimated_memory_bytes(), write_bytes_before);
    assert_eq!(
        write_core.estimated_memory_bytes(),
        write_core.recompute_estimated_memory_bytes()
    );

    write_core
        .writable_streams
        .get_mut(&write_stream)
        .expect("live Writable after token refusal")
        .end_requested = true;
    let ended_state_before = format!("{:?}", write_core.writable_streams[&write_stream]);
    assert!(matches!(
        write_core.writable_write(
            &module,
            Value::Object(write_stream),
            RegRange { start: 1, count: 1 },
        ),
        Err(InterpreterError::TypeError { got, .. }) if got == "write after end"
    ));
    assert_eq!(
        format!("{:?}", write_core.writable_streams[&write_stream]),
        ended_state_before,
        "semantic write-after-end refusal must precede token preflight"
    );
    assert_eq!(write_core.next_writable_completion_token, u32::MAX);
    assert_eq!(
        write_core.estimated_memory_bytes(),
        write_core.recompute_estimated_memory_bytes()
    );

    let mut end_core = test_interpreter();
    let final_options = end_core
        .alloc_object_with_properties(&[("final", Value::Function(0))])
        .expect("Writable final options");
    end_core
        .write_reg(0, Value::Object(final_options))
        .expect("Writable options register");
    let Value::Object(end_stream) = end_core
        .construct_stream_writable(RegRange { start: 0, count: 1 })
        .expect("Writable with final implementation")
    else {
        panic!("Writable constructor must return an object");
    };
    end_core.next_writable_completion_token = u32::MAX;
    let end_state_before = format!("{:?}", end_core.writable_streams[&end_stream]);
    let end_heap_before = serde_json::to_string(&end_core.heap[end_stream.0 as usize])
        .expect("serialize Writable mirrors");
    let end_bytes_before = end_core.estimated_memory_bytes();

    assert!(matches!(
        end_core.writable_end(
            &module,
            Value::Object(end_stream),
            RegRange { start: 1, count: 0 },
        ),
        Err(InterpreterError::InternalError { details })
            if details == "Writable completion token space exhausted"
    ));
    assert_eq!(
        format!("{:?}", end_core.writable_streams[&end_stream]),
        end_state_before
    );
    assert_eq!(
        serde_json::to_string(&end_core.heap[end_stream.0 as usize])
            .expect("serialize refused Writable mirrors"),
        end_heap_before
    );
    assert_eq!(end_core.next_writable_completion_token, u32::MAX);
    assert_eq!(end_core.estimated_memory_bytes(), end_bytes_before);
    assert_eq!(
        end_core.estimated_memory_bytes(),
        end_core.recompute_estimated_memory_bytes()
    );

    // Pending callbacks reserve the remaining nonce capacity even while a
    // cork prevents immediate activation. A second stream must not
    // overbook the same final token and become permanently stranded.
    let mut reservation_core = test_interpreter();
    let reservation_options = reservation_core
        .alloc_object_with_properties(&[("write", Value::Function(0))])
        .expect("reservation Writable options");
    reservation_core
        .write_reg(0, Value::Object(reservation_options))
        .expect("reservation options register");
    let Value::Object(first_stream) = reservation_core
        .construct_stream_writable(RegRange { start: 0, count: 1 })
        .expect("first reservation Writable")
    else {
        panic!("Writable constructor must return an object");
    };
    let Value::Object(second_stream) = reservation_core
        .construct_stream_writable(RegRange { start: 0, count: 1 })
        .expect("second reservation Writable")
    else {
        panic!("Writable constructor must return an object");
    };
    for stream in [first_stream, second_stream] {
        reservation_core
            .writable_cork(Value::Object(stream), RegRange { start: 0, count: 0 })
            .expect("cork reservation Writable");
    }
    reservation_core.next_writable_completion_token = u32::MAX - 1;
    reservation_core
        .write_reg(1, Value::str("reserved"))
        .expect("first reserved chunk");
    reservation_core
        .writable_write(
            &module,
            Value::Object(first_stream),
            RegRange { start: 1, count: 1 },
        )
        .expect("first corked write reserves the final token");
    reservation_core
        .write_reg(1, Value::str("refused"))
        .expect("second refused chunk");
    let second_state_before = format!("{:?}", reservation_core.writable_streams[&second_stream]);
    let reservation_bytes_before = reservation_core.estimated_memory_bytes();

    assert!(matches!(
        reservation_core.writable_write(
            &module,
            Value::Object(second_stream),
            RegRange { start: 1, count: 1 },
        ),
        Err(InterpreterError::InternalError { details })
            if details == "Writable completion token space exhausted"
    ));
    assert_eq!(
        format!("{:?}", reservation_core.writable_streams[&second_stream]),
        second_state_before
    );
    assert_eq!(
        reservation_core.next_writable_completion_token,
        u32::MAX - 1
    );
    assert_eq!(
        reservation_core.estimated_memory_bytes(),
        reservation_bytes_before
    );

    reservation_core
        .writable_uncork(
            &module,
            Value::Object(first_stream),
            RegRange { start: 0, count: 0 },
        )
        .expect("activate the reserved write");
    assert_eq!(reservation_core.next_writable_completion_token, u32::MAX);
    assert!(matches!(
        reservation_core.writable_streams[&first_stream]
            .writes
            .front()
            .map(|record| record.status),
        Some(WritableWriteStatus::Active(token)) if token == u32::MAX - 1
    ));
    assert_eq!(
        reservation_core.estimated_memory_bytes(),
        reservation_core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn writable_live_tick_exhaustion_preserves_completed_fifo_bd_o2xvz() {
    let module = test_module_with_functions(
        vec![
            Ir3Instruction::LoadUndefined { dst: 0 },
            Ir3Instruction::Return { value: 0 },
        ],
        vec![Ir3FunctionDesc {
            entry: 0,
            arity: 1,
            frame_size: 2,
            name: Some("write_done".to_string()),
            is_generator: false,
            rest_param_index: None,
        }],
    );
    let callback = |label| WritableCallbackRecord {
        value: Value::Function(0),
        label,
        module_specifier: None,
    };
    let mut core = test_interpreter();
    let Value::Object(writable) = core
        .construct_stream_writable(RegRange { start: 0, count: 0 })
        .expect("Writable")
    else {
        panic!("Writable constructor must return an object");
    };
    core.writable_enqueue(
        writable,
        Value::str("first"),
        Label::Public,
        Some(callback(Label::Public)),
    )
    .expect("first completed write");
    core.writable_enqueue(
        writable,
        Value::str("second"),
        Label::Secret,
        Some(callback(Label::Secret)),
    )
    .expect("second completed write");
    {
        let state = core
            .writable_streams
            .get_mut(&writable)
            .expect("Writable state");
        for record in &mut state.writes {
            record.status = WritableWriteStatus::Completed;
        }
        state.buffered_length = 0;
        state.tick_sequence = None;
    }
    core.next_writable_tick_sequence = u64::MAX;
    let state_before = format!("{:?}", core.writable_streams[&writable]);
    let bytes_before = core.estimated_memory_bytes();

    assert!(matches!(
        core.drive_writable_tick(writable, Some(&module)),
        Err(InterpreterError::InternalError { details })
            if details == "Writable tick sequence space exhausted"
    ));
    assert_eq!(
        format!("{:?}", core.writable_streams[&writable]),
        state_before
    );
    assert_eq!(core.next_writable_tick_sequence, u64::MAX);
    assert_eq!(core.estimated_memory_bytes(), bytes_before);
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );

    core.next_writable_tick_sequence = 17;
    core.drive_writable_tick(writable, Some(&module))
        .expect("retry first completed callback");
    let state = &core.writable_streams[&writable];
    assert_eq!(state.writes.len(), 1);
    assert_eq!(
        state.writes.front().map(|record| &record.value),
        Some(&Value::str("second"))
    );
    assert_eq!(state.tick_sequence, Some(17));
    assert_eq!(core.next_writable_tick_sequence, 18);
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn writable_terminal_tick_exhaustion_preserves_callback_fifo_bd_o2xvz() {
    let module = test_module_with_functions(
        vec![
            Ir3Instruction::LoadUndefined { dst: 0 },
            Ir3Instruction::Return { value: 0 },
        ],
        vec![Ir3FunctionDesc {
            entry: 0,
            arity: 1,
            frame_size: 2,
            name: Some("terminal_callback".to_string()),
            is_generator: false,
            rest_param_index: None,
        }],
    );
    let callback = WritableCallbackRecord {
        value: Value::Function(0),
        label: Label::Public,
        module_specifier: None,
    };
    let mut core = test_interpreter();
    let Value::Object(writable) = core
        .construct_stream_writable(RegRange { start: 0, count: 0 })
        .expect("Writable")
    else {
        panic!("Writable constructor must return an object");
    };
    core.terminalize_writable_state_storage(writable)
        .expect("Writable tombstone");
    core.append_writable_terminal_callback(
        writable,
        callback.clone(),
        WritableTerminalCallbackError::EndAfterFinish,
        Label::Public,
    )
    .expect("first terminal callback");
    core.append_writable_terminal_callback(
        writable,
        callback,
        WritableTerminalCallbackError::WriteAfterFinish,
        Label::Public,
    )
    .expect("second terminal callback");
    core.writable_terminal_states
        .get_mut(&writable)
        .expect("terminal state")
        .tick_sequence = None;
    core.pending_writable_terminal_ticks = 0;
    core.next_writable_tick_sequence = u64::MAX;
    let state_before = format!("{:?}", core.writable_terminal_states[&writable]);
    let bytes_before = core.estimated_memory_bytes();

    assert!(matches!(
        core.drive_writable_terminal_tick(writable, Some(&module)),
        Err(InterpreterError::InternalError { details })
            if details == "Writable tick sequence space exhausted"
    ));
    assert_eq!(
        format!("{:?}", core.writable_terminal_states[&writable]),
        state_before
    );
    assert_eq!(core.pending_writable_terminal_ticks, 0);
    assert_eq!(core.next_writable_tick_sequence, u64::MAX);
    assert_eq!(core.estimated_memory_bytes(), bytes_before);
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );

    core.next_writable_tick_sequence = 23;
    core.drive_writable_terminal_tick(writable, Some(&module))
        .expect("retry first terminal callback");
    let state = &core.writable_terminal_states[&writable];
    assert_eq!(state.callbacks.len(), 1);
    assert_eq!(
        state.callbacks.front().map(|record| record.error),
        Some(WritableTerminalCallbackError::WriteAfterFinish)
    );
    assert_eq!(state.tick_sequence, Some(23));
    assert_eq!(core.pending_writable_terminal_ticks, 1);
    assert_eq!(core.next_writable_tick_sequence, 24);
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn writable_finish_tick_exhaustion_preserves_end_callback_fifo_bd_o2xvz() {
    let module = test_module_with_functions(Vec::new(), Vec::new());
    let mut core = test_interpreter();
    let Value::Object(writable) = core
        .construct_stream_writable(RegRange { start: 0, count: 0 })
        .expect("Writable")
    else {
        panic!("Writable constructor must return an object");
    };
    {
        let state = core
            .writable_streams
            .get_mut(&writable)
            .expect("Writable finish state");
        state.end_callbacks.push_back(WritableEndCallbackRecord {
            callback: WritableCallbackRecord {
                value: Value::BuiltinFunction(BuiltinFunction::new_kind(
                    BuiltinFunctionKind::ArrayIsArray,
                )),
                label: Label::Public,
                module_specifier: None,
            },
            registered_after_end: false,
        });
        state.end_callback_batch_remaining = 1;
        state.end_requested = true;
        state.final_status = WritableFinalStatus::Done;
        state.tick_phase = WritableTickPhase::Finish;
        state.tick_sequence = None;
    }
    core.sync_estimated_memory_bytes()
        .expect("accounted finish callback state");
    core.next_writable_tick_sequence = u64::MAX;
    let state_before = format!("{:?}", core.writable_streams[&writable]);
    let bytes_before = core.estimated_memory_bytes();

    assert!(matches!(
        core.drive_writable_tick(writable, Some(&module)),
        Err(InterpreterError::InternalError { details })
            if details == "Writable tick sequence space exhausted"
    ));
    assert_eq!(
        format!("{:?}", core.writable_streams[&writable]),
        state_before
    );
    assert_eq!(core.next_writable_tick_sequence, u64::MAX);
    assert_eq!(core.estimated_memory_bytes(), bytes_before);
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );

    core.next_writable_tick_sequence = 19;
    core.drive_writable_tick(writable, Some(&module))
        .expect("retry finish callback batch");
    let state = &core.writable_streams[&writable];
    assert!(state.end_callbacks.is_empty());
    assert_eq!(state.end_callback_batch_remaining, 0);
    assert_eq!(state.tick_phase, WritableTickPhase::Close);
    assert_eq!(state.tick_sequence, Some(19));
    assert_eq!(core.next_writable_tick_sequence, 20);
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn writable_prefinish_tick_exhaustion_remains_retryable_bd_o2xvz() {
    let module = test_module_with_functions(Vec::new(), Vec::new());
    let mut core = test_interpreter();
    let Value::Object(writable) = core
        .construct_stream_writable(RegRange { start: 0, count: 0 })
        .expect("Writable")
    else {
        panic!("Writable constructor must return an object");
    };
    {
        let state = core
            .writable_streams
            .get_mut(&writable)
            .expect("Writable state");
        state.end_requested = true;
        state.final_status = WritableFinalStatus::Done;
    }
    core.next_writable_tick_sequence = u64::MAX;
    let state_before = format!("{:?}", core.writable_streams[&writable]);
    let bytes_before = core.estimated_memory_bytes();

    assert!(matches!(
        core.emit_writable_prefinish(writable, &module),
        Err(InterpreterError::InternalError { details })
            if details == "Writable tick sequence space exhausted"
    ));
    assert_eq!(
        format!("{:?}", core.writable_streams[&writable]),
        state_before
    );
    assert_eq!(core.estimated_memory_bytes(), bytes_before);

    core.next_writable_tick_sequence = 31;
    core.emit_writable_prefinish(writable, &module)
        .expect("retry prefinish after sequence capacity returns");
    let state = &core.writable_streams[&writable];
    assert!(state.prefinish_emitted);
    assert_eq!(state.tick_sequence, Some(31));
    assert_eq!(core.next_writable_tick_sequence, 32);
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn writable_completion_nonce_survives_seed_reset_and_object_id_reuse_bd_fw7zd() {
    let module = test_module_with_functions(Vec::new(), Vec::new());
    let mut core = test_interpreter();
    let seed = core
        .capture_execution_seed()
        .expect("test execution-seed capture must fit");

    let Value::Object(old_stream) = core
        .construct_stream_writable(RegRange { start: 0, count: 0 })
        .expect("old Writable")
    else {
        panic!("Writable constructor must return an object");
    };
    core.writable_enqueue(old_stream, Value::str("old"), Label::Public, None)
        .expect("old write");
    let old_token = core
        .allocate_writable_completion_token()
        .expect("old completion token");
    core.writable_streams
        .get_mut(&old_stream)
        .expect("old state")
        .writes[0]
        .status = WritableWriteStatus::Active(old_token);
    let stale_completion = BuiltinFunction::writable_completion(
        BuiltinFunctionKind::StreamWritableWriteDone,
        old_stream,
        old_token,
    );

    core.reset_execution_state_from_seed(&seed)
        .expect("execution reset");

    let Value::Object(new_stream) = core
        .construct_stream_writable(RegRange { start: 0, count: 0 })
        .expect("new Writable")
    else {
        panic!("Writable constructor must return an object");
    };
    assert_eq!(
        new_stream, old_stream,
        "heap ObjectId must be reused by the probe"
    );
    core.writable_enqueue(new_stream, Value::str("new"), Label::Public, None)
        .expect("new write");
    let new_token = core
        .allocate_writable_completion_token()
        .expect("new completion token");
    assert_ne!(new_token, old_token);
    core.writable_streams
        .get_mut(&new_stream)
        .expect("new state")
        .writes[0]
        .status = WritableWriteStatus::Active(new_token);

    core.writable_write_done(&module, &stale_completion, RegRange { start: 0, count: 0 })
        .expect("stale completion must be an authenticated no-op");
    assert_eq!(
        core.writable_streams[&new_stream].writes[0].status,
        WritableWriteStatus::Active(new_token)
    );
    assert_eq!(core.next_writable_completion_token, new_token + 1);
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn writable_scheduler_scans_are_instruction_budgeted_bd_fw7zd() {
    let mut core = test_interpreter();
    let mut streams = Vec::new();
    for _ in 0..8 {
        let Value::Object(stream) = core
            .construct_stream_writable(RegRange { start: 0, count: 0 })
            .expect("budgeted Writable")
        else {
            panic!("Writable constructor must return an object");
        };
        core.schedule_writable_tick(stream)
            .expect("schedule budgeted Writable");
        streams.push(stream);
    }
    core.instructions_executed = 0;
    core.config.instruction_budget = 7;
    assert!(matches!(
        core.next_scheduled_writable_tick(),
        Err(InterpreterError::BudgetExhausted {
            executed: 0,
            budget: 7
        })
    ));
    assert!(
        streams
            .iter()
            .all(|stream| core.writable_streams[stream].tick_sequence.is_some())
    );
    assert_eq!(core.instructions_executed, 0);
}

#[test]
fn string_to_string_builtin_rejects_non_string_receiver_bd_fw7zd() {
    let module = test_module_with_functions(Vec::new(), Vec::new());
    let mut core = test_interpreter();
    let builtin = BuiltinFunction::new_kind(BuiltinFunctionKind::StringToString);
    assert_eq!(
        core.dispatch_builtin_function(
            &module,
            &builtin,
            RegRange { start: 0, count: 0 },
            Some(Value::str("text")),
            None,
        )
        .expect("string receiver"),
        Value::str("text")
    );
    assert!(matches!(
        core.dispatch_builtin_function(
            &module,
            &builtin,
            RegRange { start: 0, count: 0 },
            Some(Value::Int(123)),
            None,
        ),
        Err(InterpreterError::TypeError { .. })
    ));
}

#[test]
fn readable_enqueue_peak_is_exact_atomic_and_ifc_preserving_bd_71jw4() {
    let fixture = || {
        let mut core = test_interpreter();
        let Value::Object(readable) = core
            .construct_stream_readable(RegRange { start: 0, count: 0 })
            .expect("generic Readable")
        else {
            panic!("Readable constructor must return an object");
        };
        core.write_reg_with_label(0, Value::str("classified"), Label::Secret)
            .expect("secret enqueue register");
        (core, readable)
    };
    let operation = |core: &mut InterpreterCore, readable| {
        core.readable_push(Value::Object(readable), RegRange { start: 0, count: 1 })
    };
    let exact_ceiling = calibrate_readable_memory_ceiling(fixture, operation);

    let (mut refused, readable) = fixture();
    let before_state = refused.readable_from_streams[&readable].clone();
    let before_heap_len = refused.heap.len();
    let before_memory = refused.estimated_memory_bytes();
    let before_promise_runtime = refused.promise_runtime_memory_bytes();
    refused.config.max_total_memory_bytes = exact_ceiling - 1;
    assert!(matches!(
        operation(&mut refused, readable),
        Err(InterpreterError::MemoryBudgetExceeded {
            requested_bytes,
            max_bytes,
            ..
        }) if requested_bytes == exact_ceiling && max_bytes == exact_ceiling - 1
    ));
    assert_eq!(refused.readable_from_streams[&readable], before_state);
    assert_eq!(refused.heap.len(), before_heap_len);
    assert!(refused.pending_readable_from_pumps.is_empty());
    assert!(refused.readable_pump_reservations.is_empty());
    assert_eq!(
        refused.promise_runtime_memory_bytes(),
        before_promise_runtime
    );
    assert_eq!(refused.estimated_memory_bytes(), before_memory);
    assert_eq!(
        refused.estimated_memory_bytes(),
        refused.recompute_estimated_memory_bytes()
    );

    let (mut exact, readable) = fixture();
    exact.config.max_total_memory_bytes = exact_ceiling;
    assert_eq!(
        operation(&mut exact, readable).expect("exact enqueue peak"),
        Value::Bool(true)
    );
    let state = &exact.readable_from_streams[&readable];
    assert_eq!(state.buffered_length, "classified".len());
    assert_eq!(state.lifecycle_label, Label::Secret);
    assert_eq!(
        state.buffer.front().map(|chunk| &chunk.label),
        Some(&Label::Secret)
    );
    assert_eq!(
        state.buffer.front().map(|chunk| &chunk.value),
        Some(&Value::str("classified"))
    );
    assert_eq!(exact.pending_readable_from_pumps.len(), 1);
    assert!(exact.readable_pump_reservations.is_empty());
    assert!(exact.estimated_memory_bytes() <= exact_ceiling);
    assert_eq!(
        exact.estimated_memory_bytes(),
        exact.recompute_estimated_memory_bytes()
    );
}

#[test]
fn readable_raw_read_coalescing_peak_is_exact_atomic_and_labeled_bd_71jw4() {
    let fixture = || {
        let mut core = test_interpreter();
        let Value::Object(readable) = core
            .construct_stream_readable(RegRange { start: 0, count: 0 })
            .expect("generic Readable")
        else {
            panic!("Readable constructor must return an object");
        };
        for (register, value, label) in [(0, "ab", Label::Public), (1, "cd", Label::Secret)] {
            core.write_reg_with_label(register, Value::str(value), label)
                .expect("coalescing input register");
            core.readable_push(
                Value::Object(readable),
                RegRange {
                    start: register,
                    count: 1,
                },
            )
            .expect("queue coalescing input");
        }
        core.write_reg(2, Value::Int(3))
            .expect("read size register");
        (core, readable)
    };
    let operation = |core: &mut InterpreterCore, readable| {
        core.readable_read(Value::Object(readable), RegRange { start: 2, count: 1 })
    };
    let exact_ceiling = calibrate_readable_memory_ceiling(fixture, operation);

    let (mut refused, readable) = fixture();
    let before_state = refused.readable_from_streams[&readable].clone();
    let before_heap_len = refused.heap.len();
    let before_memory = refused.estimated_memory_bytes();
    let before_promise_runtime = refused.promise_runtime_memory_bytes();
    let before_pumps = refused.pending_readable_from_pumps.clone();
    refused.config.max_total_memory_bytes = exact_ceiling - 1;
    assert!(matches!(
        operation(&mut refused, readable),
        Err(InterpreterError::MemoryBudgetExceeded {
            requested_bytes,
            max_bytes,
            ..
        }) if requested_bytes == exact_ceiling && max_bytes == exact_ceiling - 1
    ));
    assert_eq!(refused.readable_from_streams[&readable], before_state);
    assert_eq!(refused.heap.len(), before_heap_len);
    assert_eq!(refused.pending_readable_from_pumps, before_pumps);
    assert!(refused.readable_pump_reservations.is_empty());
    assert_eq!(
        refused.promise_runtime_memory_bytes(),
        before_promise_runtime
    );
    assert_eq!(refused.estimated_memory_bytes(), before_memory);
    assert_eq!(
        refused.estimated_memory_bytes(),
        refused.recompute_estimated_memory_bytes()
    );

    let (mut exact, readable) = fixture();
    exact.config.max_total_memory_bytes = exact_ceiling;
    let Value::Object(result) = operation(&mut exact, readable).expect("exact raw read peak")
    else {
        panic!("raw read must return a Buffer");
    };
    let result_view = exact
        .buffer_like_view(&Value::Object(result))
        .expect("coalesced result Buffer");
    assert_eq!(exact.typed_array_view_bytes(&result_view).unwrap(), b"abc");
    let state = &exact.readable_from_streams[&readable];
    assert_eq!(state.buffered_length, 1);
    assert_eq!(state.lifecycle_label, Label::Secret);
    assert_eq!(
        state.buffer.front().map(|chunk| &chunk.label),
        Some(&Label::Secret)
    );
    let remainder = state
        .buffer
        .front()
        .expect("one-byte remainder")
        .value
        .clone();
    let remainder_view = exact
        .buffer_like_view(&remainder)
        .expect("remainder Buffer");
    assert_eq!(exact.typed_array_view_bytes(&remainder_view).unwrap(), b"d");
    assert!(exact.estimated_memory_bytes() <= exact_ceiling);
    assert_eq!(
        exact.estimated_memory_bytes(),
        exact.recompute_estimated_memory_bytes()
    );
}

#[test]
fn readable_custom_read_pump_peak_is_exact_atomic_and_labeled_bd_71jw4() {
    let mut module = test_module_with_functions(
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
            Ir3Instruction::LoadStr {
                dst: 3,
                pool_index: 1,
            },
            Ir3Instruction::CallMethod {
                receiver: 0,
                callee: 2,
                args: RegRange { start: 3, count: 1 },
                dst: 4,
            },
            Ir3Instruction::LoadUndefined { dst: 5 },
            Ir3Instruction::Return { value: 5 },
        ],
        vec![Ir3FunctionDesc {
            entry: 0,
            arity: 1,
            frame_size: 6,
            name: Some("custom_read_push".to_string()),
            is_generator: false,
            rest_param_index: None,
        }],
    );
    module.constant_pool = vec!["push".into(), "x".into()];
    let fixture = || {
        let mut core = test_interpreter();
        let options = core
            .alloc_object_with_properties(&[("read", Value::Function(0))])
            .expect("custom read options");
        core.write_reg_with_label(0, Value::Object(options), Label::Secret)
            .expect("secret custom read options register");
        let Value::Object(readable) = core
            .construct_stream_readable(RegRange { start: 0, count: 1 })
            .expect("custom Readable")
        else {
            panic!("Readable constructor must return an object");
        };
        (core, readable)
    };
    let operation = |core: &mut InterpreterCore, readable| {
        core.drive_readable_from_pump(readable, Some(&module))
    };
    let exact_ceiling = calibrate_readable_memory_ceiling(fixture, operation);

    let (mut refused, readable) = fixture();
    let before_state = refused.readable_from_streams[&readable].clone();
    let before_heap_len = refused.heap.len();
    let before_memory = refused.estimated_memory_bytes();
    let before_promise_runtime = refused.promise_runtime_memory_bytes();
    refused.config.max_total_memory_bytes = exact_ceiling - 1;
    assert!(matches!(
        operation(&mut refused, readable),
        Err(InterpreterError::MemoryBudgetExceeded {
            requested_bytes,
            max_bytes,
            ..
        }) if requested_bytes == exact_ceiling && max_bytes == exact_ceiling - 1
    ));
    assert_eq!(refused.readable_from_streams[&readable], before_state);
    assert_eq!(refused.heap.len(), before_heap_len);
    assert!(refused.pending_readable_from_pumps.is_empty());
    assert!(refused.readable_pump_reservations.is_empty());
    assert_eq!(
        refused.promise_runtime_memory_bytes(),
        before_promise_runtime
    );
    assert_eq!(refused.estimated_memory_bytes(), before_memory);
    assert_eq!(
        refused.estimated_memory_bytes(),
        refused.recompute_estimated_memory_bytes()
    );

    let (mut exact, readable) = fixture();
    exact.config.max_total_memory_bytes = exact_ceiling;
    operation(&mut exact, readable).expect("exact custom read pump peak");
    let state = &exact.readable_from_streams[&readable];
    assert!(!state.read_callback_active);
    assert_eq!(state.buffered_length, 1);
    assert_eq!(state.lifecycle_label, Label::Secret);
    assert_eq!(
        state.buffer.front().map(|chunk| &chunk.label),
        Some(&Label::Secret)
    );
    assert_eq!(
        state.buffer.front().map(|chunk| &chunk.value),
        Some(&Value::str("x"))
    );
    assert_eq!(exact.pending_readable_from_pumps.len(), 1);
    assert!(exact.readable_pump_reservations.is_empty());
    assert!(exact.estimated_memory_bytes() <= exact_ceiling);
    assert_eq!(
        exact.estimated_memory_bytes(),
        exact.recompute_estimated_memory_bytes()
    );
}

#[test]
fn readable_set_encoding_peak_is_exact_atomic_and_labeled_bd_71jw4() {
    let fixture = || {
        let mut core = test_interpreter();
        let Value::Object(readable) = core
            .construct_stream_readable(RegRange { start: 0, count: 0 })
            .expect("generic Readable")
        else {
            panic!("Readable constructor must return an object");
        };
        for (register, bytes) in [(1, &[0xe2, 0x82][..]), (2, &[0xac, b'!'][..])] {
            let buffer = core
                .alloc_buffer_from_bytes(bytes)
                .expect("UTF-8 input Buffer");
            core.write_reg_with_label(register, Value::Object(buffer), Label::Secret)
                .expect("secret Buffer register");
            core.readable_push(
                Value::Object(readable),
                RegRange {
                    start: register,
                    count: 1,
                },
            )
            .expect("queue encoded input");
        }
        core.write_reg_with_label(0, Value::str("utf8"), Label::Secret)
            .expect("secret encoding register");
        (core, readable)
    };
    let operation = |core: &mut InterpreterCore, readable| {
        core.readable_set_encoding(Value::Object(readable), RegRange { start: 0, count: 1 })
    };
    let exact_ceiling = calibrate_readable_memory_ceiling(fixture, operation);

    let (mut refused, readable) = fixture();
    let before_state = refused.readable_from_streams[&readable].clone();
    let before_heap_len = refused.heap.len();
    let before_memory = refused.estimated_memory_bytes();
    let before_promise_runtime = refused.promise_runtime_memory_bytes();
    let before_pumps = refused.pending_readable_from_pumps.clone();
    refused.config.max_total_memory_bytes = exact_ceiling - 1;
    assert!(matches!(
        operation(&mut refused, readable),
        Err(InterpreterError::MemoryBudgetExceeded {
            requested_bytes,
            max_bytes,
            ..
        }) if requested_bytes == exact_ceiling && max_bytes == exact_ceiling - 1
    ));
    assert_eq!(refused.readable_from_streams[&readable], before_state);
    assert_eq!(refused.heap.len(), before_heap_len);
    assert_eq!(refused.pending_readable_from_pumps, before_pumps);
    assert!(refused.readable_pump_reservations.is_empty());
    assert_eq!(
        refused.promise_runtime_memory_bytes(),
        before_promise_runtime
    );
    assert_eq!(refused.estimated_memory_bytes(), before_memory);
    assert_eq!(
        refused.estimated_memory_bytes(),
        refused.recompute_estimated_memory_bytes()
    );

    let (mut exact, readable) = fixture();
    exact.config.max_total_memory_bytes = exact_ceiling;
    assert_eq!(
        operation(&mut exact, readable).expect("exact setEncoding peak"),
        Value::Object(readable)
    );
    let state = &exact.readable_from_streams[&readable];
    assert!(state.decode_utf8);
    assert!(state.utf8_pending.is_empty());
    assert_eq!(state.buffered_length, 2);
    assert_eq!(state.lifecycle_label, Label::Secret);
    assert_eq!(state.buffer.len(), 1);
    assert_eq!(
        state.buffer.front().map(|chunk| &chunk.label),
        Some(&Label::Secret)
    );
    assert_eq!(
        state.buffer.front().map(|chunk| &chunk.value),
        Some(&Value::str("€!"))
    );
    assert!(exact.estimated_memory_bytes() <= exact_ceiling);
    assert_eq!(
        exact.estimated_memory_bytes(),
        exact.recompute_estimated_memory_bytes()
    );
}

#[test]
fn readable_pause_resume_and_push_null_are_synchronous_bd_fw7zd() {
    let module = test_module_with_functions(Vec::new(), Vec::new());
    let mut core = test_interpreter();
    let Value::Object(readable) = core
        .construct_stream_readable(RegRange { start: 0, count: 0 })
        .expect("generic Readable")
    else {
        panic!("Readable constructor must return an object");
    };
    assert_eq!(
        core.readable_is_paused(Value::Object(readable))
            .expect("initial isPaused"),
        Value::Bool(false)
    );
    assert_eq!(
        core.readable_pause(Value::Object(readable)).expect("pause"),
        Value::Object(readable)
    );
    assert_eq!(
        core.readable_is_paused(Value::Object(readable))
            .expect("paused isPaused"),
        Value::Bool(true)
    );
    assert_eq!(
        core.readable_resume(Value::Object(readable))
            .expect("resume"),
        Value::Object(readable)
    );
    assert_eq!(
        core.readable_is_paused(Value::Object(readable))
            .expect("resumed isPaused"),
        Value::Bool(false)
    );
    core.write_reg(0, Value::Null).expect("push null register");
    core.set_register_label(0, Label::Secret)
        .expect("push null label");
    assert_eq!(
        core.readable_push(Value::Object(readable), RegRange { start: 0, count: 1 })
            .expect("push null"),
        Value::Bool(false)
    );
    assert_eq!(
        core.heap[readable.0 as usize]
            .properties
            .get("readableEnded"),
        Some(&Value::Bool(false)),
        "EOF request must not forge synchronous readableEnded"
    );
    assert_eq!(
        core.readable_from_streams
            .get(&readable)
            .expect("live generic state")
            .lifecycle_label,
        Label::Secret,
        "EOF trigger taint must join terminal lifecycle emissions"
    );
    core.drive_readable_from_pump(readable, Some(&module))
        .expect("end phase");
    assert_eq!(
        core.heap[readable.0 as usize]
            .properties
            .get("readableEnded"),
        Some(&Value::Bool(true))
    );
    core.drive_readable_from_pump(readable, Some(&module))
        .expect("close phase");
    assert!(!core.readable_from_streams.contains_key(&readable));
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn readable_custom_queue_coalesces_bytes_and_ignores_forged_hwm_bd_fw7zd() {
    let mut core = test_interpreter();
    let Value::Object(readable) = core
        .construct_stream_readable(RegRange { start: 0, count: 0 })
        .expect("generic Readable")
    else {
        panic!("Readable constructor must return an object");
    };
    core.set_object_property(readable, "readableHighWaterMark".to_string(), Value::Int(0))
        .expect("forge public HWM mirror");

    for (index, value) in ["r1", "r2"].into_iter().enumerate() {
        core.write_reg(0, Value::str(value)).expect("push register");
        core.set_register_label(
            0,
            if index == 0 {
                Label::Public
            } else {
                Label::Secret
            },
        )
        .expect("push label");
        assert_eq!(
            core.readable_push(Value::Object(readable), RegRange { start: 0, count: 1 })
                .expect("push byte chunk"),
            Value::Bool(true),
            "backpressure must use the internal HWM, not the guest mirror"
        );
    }
    assert_eq!(
        core.readable_from_streams
            .get(&readable)
            .expect("live custom state")
            .lifecycle_label,
        Label::Secret
    );
    let Value::Object(buffer) = core
        .readable_read(Value::Object(readable), RegRange { start: 0, count: 0 })
        .expect("coalesced read")
    else {
        panic!("byte-mode read must return a Buffer");
    };
    assert!(core.is_buffer_object(buffer));
    let view = core
        .buffer_like_view(&Value::Object(buffer))
        .expect("Buffer view");
    assert_eq!(core.typed_array_view_bytes(&view).unwrap(), b"r1r2");
    assert_eq!(
        core.readable_from_streams
            .get(&readable)
            .expect("live custom state")
            .buffered_length,
        0
    );
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );

    let mut identity_core = test_interpreter();
    let Value::Object(identity_readable) = identity_core
        .construct_stream_readable(RegRange { start: 0, count: 0 })
        .expect("identity Readable")
    else {
        panic!("Readable constructor must return an object");
    };
    let original = identity_core
        .alloc_buffer_from_bytes(b"same")
        .expect("original Buffer");
    identity_core
        .write_reg(0, Value::Object(original))
        .expect("Buffer register");
    identity_core
        .readable_push(
            Value::Object(identity_readable),
            RegRange { start: 0, count: 1 },
        )
        .expect("push Buffer");
    assert_eq!(
        identity_core
            .readable_read(
                Value::Object(identity_readable),
                RegRange { start: 0, count: 0 },
            )
            .expect("identity-preserving read"),
        Value::Object(original)
    );
}

#[test]
fn readable_set_encoding_retains_split_utf8_and_labels_bd_fw7zd() {
    let mut core = test_interpreter();
    let Value::Object(readable) = core
        .construct_stream_readable(RegRange { start: 0, count: 0 })
        .expect("generic Readable")
    else {
        panic!("Readable constructor must return an object");
    };
    for bytes in [&[0xe2, 0x82][..], &[0xac][..]] {
        let buffer = core.alloc_buffer_from_bytes(bytes).expect("input Buffer");
        core.write_reg(1, Value::Object(buffer))
            .expect("Buffer push register");
        core.set_register_label(1, Label::Secret)
            .expect("Buffer push label");
        core.readable_push(Value::Object(readable), RegRange { start: 1, count: 1 })
            .expect("push encoded bytes");
    }
    core.write_reg(0, Value::str("utf-8"))
        .expect("encoding register");
    core.set_register_label(0, Label::Secret)
        .expect("encoding label");
    assert_eq!(
        core.readable_set_encoding(Value::Object(readable), RegRange { start: 0, count: 1 })
            .expect("setEncoding"),
        Value::Object(readable)
    );
    assert_eq!(
        core.readable_from_streams
            .get(&readable)
            .expect("converted queue")
            .buffered_length,
        1,
        "decoded readableLength counts JavaScript UTF-16 code units"
    );
    assert_eq!(
        core.readable_read(Value::Object(readable), RegRange { start: 0, count: 0 })
            .expect("decoded read"),
        Value::str("€")
    );
    let state = core
        .readable_from_streams
        .get(&readable)
        .expect("live encoded state");
    assert!(state.utf8_pending.is_empty());
    assert_eq!(state.lifecycle_label, Label::Secret);
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );

    let mut invalid_core = test_interpreter();
    let Value::Object(invalid_readable) = invalid_core
        .construct_stream_readable(RegRange { start: 0, count: 0 })
        .expect("invalid-prefix Readable")
    else {
        panic!("Readable constructor must return an object");
    };
    invalid_core
        .write_reg(0, Value::str("utf8"))
        .expect("encoding register");
    invalid_core
        .readable_set_encoding(
            Value::Object(invalid_readable),
            RegRange { start: 0, count: 1 },
        )
        .expect("setEncoding");
    for (bytes, expected) in [(&[0xff, 0xe2][..], "�"), (&[0x82, 0xac][..], "€")] {
        let buffer = invalid_core
            .alloc_buffer_from_bytes(bytes)
            .expect("input Buffer");
        invalid_core
            .write_reg(1, Value::Object(buffer))
            .expect("push register");
        invalid_core
            .readable_push(
                Value::Object(invalid_readable),
                RegRange { start: 1, count: 1 },
            )
            .expect("push incremental bytes");
        assert_eq!(
            invalid_core
                .readable_read(
                    Value::Object(invalid_readable),
                    RegRange { start: 0, count: 0 },
                )
                .expect("incremental decoded read"),
            Value::str(expected)
        );
    }
}

#[test]
fn readable_read_result_inherits_engine_owned_chunk_label_bd_fw7zd() {
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
            Ir3Instruction::CallMethod {
                receiver: 0,
                callee: 2,
                args: RegRange { start: 4, count: 0 },
                dst: 3,
            },
            Ir3Instruction::Halt,
        ],
        Vec::new(),
    );
    module.constant_pool.push("read".into());

    let mut core = test_interpreter();
    let Value::Object(readable) = core
        .construct_stream_readable(RegRange { start: 0, count: 0 })
        .expect("generic Readable")
    else {
        panic!("Readable constructor must return an object");
    };
    core.write_reg(4, Value::str("classified"))
        .expect("push register");
    core.set_register_label(4, Label::Secret)
        .expect("secret push label");
    core.readable_push(Value::Object(readable), RegRange { start: 4, count: 1 })
        .expect("push secret chunk");
    core.write_reg(0, Value::Object(readable))
        .expect("public receiver register");
    core.set_register_label(0, Label::Public)
        .expect("public receiver label");
    assert!(matches!(
        core.run_loop(&module),
        Ok(_) | Err(InterpreterError::Halted)
    ));

    assert!(matches!(core.read_reg(3), Ok(Value::Object(_))));
    assert_eq!(
        core.get_register_label(3).expect("read result label"),
        &Label::Secret,
        "engine-owned queue provenance must taint direct read() results"
    );
}

#[test]
fn readable_sized_read_and_unshift_preserve_exact_units_and_memory_bd_fw7zd() {
    let mut core = test_interpreter();
    let Value::Object(readable) = core
        .construct_stream_readable(RegRange { start: 0, count: 0 })
        .expect("custom Readable")
    else {
        panic!("Readable constructor must return an object");
    };
    core.write_reg(0, Value::str("utf8"))
        .expect("encoding register");
    core.readable_set_encoding(Value::Object(readable), RegRange { start: 0, count: 1 })
        .expect("setEncoding");

    let original = JsString::from_code_units(&[0xd83d, 0xde00, 0x00e9, 0x0061]);
    core.write_reg(1, Value::Str(original))
        .expect("push register");
    core.readable_push(Value::Object(readable), RegRange { start: 1, count: 1 })
        .expect("push exact string");
    core.write_reg(1, Value::Null).expect("EOF register");
    core.readable_push(Value::Object(readable), RegRange { start: 1, count: 1 })
        .expect("request EOF");

    core.write_reg(2, Value::Int(1)).expect("size register");
    let Value::Str(first) = core
        .readable_read(Value::Object(readable), RegRange { start: 2, count: 1 })
        .expect("read one UTF-16 unit")
    else {
        panic!("decoded read must return a string");
    };
    assert_eq!(first.code_units_vec(), vec![0xd83d]);
    assert_eq!(
        core.readable_from_streams
            .get(&readable)
            .expect("live Readable")
            .buffered_length,
        3
    );

    core.write_reg(3, Value::Str(first))
        .expect("unshift register");
    core.set_register_label(3, Label::Secret)
        .expect("secret unshift label");
    assert_eq!(
        core.readable_unshift(Value::Object(readable), RegRange { start: 3, count: 1 })
            .expect("unshift exact prefix"),
        Value::Bool(false),
        "unshift after push(null) restores data but reports the EOF request"
    );
    let Value::Str(restored) = core
        .readable_read(Value::Object(readable), RegRange { start: 2, count: 0 })
        .expect("read restored prefix")
    else {
        panic!("decoded read must return a string");
    };
    assert_eq!(
        restored.code_units_vec(),
        vec![0xd83d, 0xde00, 0x00e9, 0x0061]
    );
    assert_eq!(
        core.readable_from_streams
            .get(&readable)
            .expect("live Readable")
            .lifecycle_label,
        Label::Secret
    );
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn readable_sized_raw_read_retains_buffer_remainder_bd_fw7zd() {
    let mut core = test_interpreter();
    for (raw, expected) in [
        ("1e2", Some(1)),
        ("2tail", Some(2)),
        ("0x10", Some(0)),
        ("nonnumeric", None),
    ] {
        core.write_reg(7, Value::str(raw)).expect("string size");
        assert_eq!(
            core.readable_requested_size(RegRange { start: 7, count: 1 })
                .expect("coerce stream size"),
            expected,
            "leading decimal size coercion for {raw:?}"
        );
    }
    let Value::Object(readable) = core
        .construct_stream_readable(RegRange { start: 0, count: 0 })
        .expect("custom Readable")
    else {
        panic!("Readable constructor must return an object");
    };
    core.write_reg(0, Value::str("abcd"))
        .expect("push register");
    core.readable_push(Value::Object(readable), RegRange { start: 0, count: 1 })
        .expect("push bytes");
    core.write_reg(1, Value::Int(2)).expect("size register");
    let Value::Object(first) = core
        .readable_read(Value::Object(readable), RegRange { start: 1, count: 1 })
        .expect("read byte prefix")
    else {
        panic!("byte-mode read must return a Buffer");
    };
    let first_view = core
        .buffer_like_view(&Value::Object(first))
        .expect("first Buffer view");
    assert_eq!(core.typed_array_view_bytes(&first_view).unwrap(), b"ab");
    let Value::Object(second) = core
        .readable_read(Value::Object(readable), RegRange { start: 0, count: 0 })
        .expect("read retained suffix")
    else {
        panic!("byte-mode read must return a Buffer");
    };
    let second_view = core
        .buffer_like_view(&Value::Object(second))
        .expect("second Buffer view");
    assert_eq!(core.typed_array_view_bytes(&second_view).unwrap(), b"cd");
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn readable_decoded_read_refusal_is_state_atomic_bd_fw7zd() {
    let mut core = test_interpreter();
    let Value::Object(readable) = core
        .construct_stream_readable(RegRange { start: 0, count: 0 })
        .expect("custom Readable")
    else {
        panic!("Readable constructor must return an object");
    };
    core.write_reg(0, Value::str("utf8"))
        .expect("encoding register");
    core.readable_set_encoding(Value::Object(readable), RegRange { start: 0, count: 1 })
        .expect("setEncoding");
    core.write_reg(1, Value::str("abcdef"))
        .expect("push register");
    core.readable_push(Value::Object(readable), RegRange { start: 1, count: 1 })
        .expect("push decoded data");
    core.write_reg(2, Value::Int(2)).expect("size register");

    let before_state = core
        .readable_from_streams
        .get(&readable)
        .expect("live Readable")
        .clone();
    let before_heap_len = core.heap.len();
    let before_memory = core.estimated_memory_bytes();
    let state_clone_bytes = InterpreterCore::estimate_readable_from_state_bytes(&before_state);
    core.config.max_total_memory_bytes = before_memory.saturating_add(state_clone_bytes);
    assert!(matches!(
        core.readable_read(Value::Object(readable), RegRange { start: 2, count: 1 }),
        Err(InterpreterError::MemoryBudgetExceeded { .. })
    ));
    assert_eq!(core.readable_from_streams[&readable], before_state);
    assert_eq!(core.heap.len(), before_heap_len);
    assert_eq!(core.estimated_memory_bytes(), before_memory);
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn readable_unshift_byte_mode_noop_chunks_match_node_bd_fw7zd() {
    let mut core = test_interpreter();
    let Value::Object(readable) = core
        .construct_stream_readable(RegRange { start: 0, count: 0 })
        .expect("custom Readable")
    else {
        panic!("Readable constructor must return an object");
    };
    for (value, expected) in [
        (Value::Null, Value::Bool(false)),
        (Value::Undefined, Value::Bool(true)),
        (Value::str(""), Value::Bool(true)),
    ] {
        core.write_reg(0, value).expect("unshift register");
        assert_eq!(
            core.readable_unshift(Value::Object(readable), RegRange { start: 0, count: 1 })
                .expect("no-op unshift"),
            expected
        );
        assert!(core.readable_from_streams[&readable].buffer.is_empty());
    }
    core.readable_request_eof(readable, Label::Public)
        .expect("request EOF");
    core.write_reg(0, Value::str(""))
        .expect("empty post-EOF chunk");
    assert_eq!(
        core.readable_unshift(Value::Object(readable), RegRange { start: 0, count: 1 })
            .expect("post-EOF no-op unshift"),
        Value::Bool(false)
    );
    assert!(core.readable_from_streams[&readable].buffer.is_empty());
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn readable_to_array_settles_only_after_close_with_source_label_bd_fw7zd() {
    let module = test_module_with_functions(Vec::new(), Vec::new());
    let mut core = test_interpreter();
    let source = core
        .alloc_array_from_values(&[Value::str("left"), Value::str("right")])
        .expect("source array");
    core.write_reg(0, Value::Object(source))
        .expect("source register");
    core.set_register_label(0, Label::Secret)
        .expect("source label");
    let Value::Object(readable) = core
        .construct_readable_from(RegRange { start: 0, count: 1 })
        .expect("finite Readable")
    else {
        panic!("Readable.from must return an object");
    };
    assert!(
        core.readable_pull_source_chunk(readable)
            .expect("prefetch first source chunk")
    );
    assert_eq!(
        core.readable_from_streams
            .get(&readable)
            .expect("prefetched state")
            .buffer
            .len(),
        1
    );
    let Value::Promise(promise_id) = core
        .readable_to_array(Value::Object(readable))
        .expect("toArray")
    else {
        panic!("toArray must return a Promise");
    };
    let promise = crate::promise_model::PromiseHandle(promise_id);
    assert!(matches!(
        core.promise_store.get(promise).map(|record| &record.state),
        Ok(crate::promise_model::PromiseState::Pending)
    ));
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );

    core.drive_readable_from_pump(readable, Some(&module))
        .expect("end phase");
    assert!(matches!(
        core.promise_store.get(promise).map(|record| &record.state),
        Ok(crate::promise_model::PromiseState::Pending)
    ));
    assert_eq!(
        core.heap[readable.0 as usize]
            .properties
            .get("readableEnded"),
        Some(&Value::Bool(true))
    );

    core.drive_readable_from_pump(readable, Some(&module))
        .expect("close phase");
    let record = core.promise_store.get(promise).expect("settled Promise");
    let crate::promise_model::PromiseState::Fulfilled(crate::object_model::JsValue::Object(result)) =
        &record.state
    else {
        panic!("toArray Promise must fulfill with an array object");
    };
    assert_eq!(record.label, Label::Secret);
    assert_eq!(
        core.read_array_like_values(ObjectId(result.0)),
        vec![Value::str("left"), Value::str("right")]
    );
    assert!(!core.readable_from_streams.contains_key(&readable));
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn readable_from_carries_stored_element_label_into_lifecycle_bd_ojvo1() {
    let module = test_module_with_functions(Vec::new(), Vec::new());
    let mut core = test_interpreter();
    let source = core
        .alloc_array_from_values(&[Value::str("classified")])
        .expect("source array");
    core.set_own_runtime_property_label(
        source,
        &RuntimePropertyKey::String(JsString::from("0")),
        &Label::Secret,
    )
    .expect("element label should fit");
    core.write_reg_with_label(0, Value::Object(source), Label::Public)
        .expect("Public source register");
    let Value::Object(readable) = core
        .construct_readable_from(RegRange { start: 0, count: 1 })
        .expect("finite Readable")
    else {
        panic!("Readable.from must return an object");
    };

    assert!(core.readable_pull_source_chunk(readable).unwrap());
    let state = &core.readable_from_streams[&readable];
    assert_eq!(state.lifecycle_label, Label::Secret);
    assert_eq!(state.buffer.front().unwrap().label, Label::Secret);

    let Value::Promise(promise_id) = core
        .readable_to_array(Value::Object(readable))
        .expect("toArray")
    else {
        panic!("toArray must return a Promise");
    };
    core.drive_readable_from_pump(readable, Some(&module))
        .expect("end phase");
    core.drive_readable_from_pump(readable, Some(&module))
        .expect("close phase");
    let record = core
        .promise_store
        .get(crate::promise_model::PromiseHandle(promise_id))
        .expect("settled Promise");
    assert_eq!(record.label, Label::Secret);
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn readable_prefetched_to_array_peak_is_exact_atomic_and_labeled_bd_71jw4() {
    let fixture = || {
        let mut core = test_interpreter();
        let source = core
            .alloc_array_from_values(&[
                Value::str("left"),
                Value::str("middle"),
                Value::str("right"),
            ])
            .expect("toArray source");
        core.write_reg_with_label(0, Value::Object(source), Label::Secret)
            .expect("secret source register");
        let Value::Object(readable) = core
            .construct_readable_from(RegRange { start: 0, count: 1 })
            .expect("finite Readable")
        else {
            panic!("Readable.from must return an object");
        };
        assert!(
            core.readable_pull_source_chunk(readable)
                .expect("prefetch first source value")
        );
        assert_eq!(core.readable_from_streams[&readable].buffer.len(), 1);
        (core, readable)
    };
    let operation =
        |core: &mut InterpreterCore, readable| core.readable_to_array(Value::Object(readable));
    let exact_ceiling = calibrate_readable_memory_ceiling(fixture, operation);

    let (mut refused, readable) = fixture();
    let before_state = refused.readable_from_streams[&readable].clone();
    let before_heap_len = refused.heap.len();
    let before_remembered_set = refused.gc_remembered_set.clone();
    let before_memory = refused.estimated_memory_bytes();
    let before_promise_runtime = refused.promise_runtime_memory_bytes();
    let before_promise_count = refused.promise_store.len();
    let before_promise_witness = refused.promise_store.witness_log().to_vec();
    let before_pumps = refused.pending_readable_from_pumps.clone();
    refused.config.max_total_memory_bytes = exact_ceiling - 1;
    assert!(matches!(
        operation(&mut refused, readable),
        Err(InterpreterError::MemoryBudgetExceeded {
            requested_bytes,
            max_bytes,
            ..
        }) if requested_bytes == exact_ceiling && max_bytes == exact_ceiling - 1
    ));
    assert_eq!(refused.readable_from_streams[&readable], before_state);
    assert_eq!(refused.heap.len(), before_heap_len);
    assert_eq!(refused.gc_remembered_set, before_remembered_set);
    assert_eq!(refused.promise_store.len(), before_promise_count);
    assert_eq!(refused.promise_store.witness_log(), before_promise_witness);
    assert_eq!(refused.pending_readable_from_pumps, before_pumps);
    assert!(refused.readable_pump_reservations.is_empty());
    assert_eq!(
        refused.promise_runtime_memory_bytes(),
        before_promise_runtime
    );
    assert_eq!(refused.estimated_memory_bytes(), before_memory);
    assert_eq!(
        refused.estimated_memory_bytes(),
        refused.recompute_estimated_memory_bytes()
    );

    let (mut exact, readable) = fixture();
    exact.config.max_total_memory_bytes = exact_ceiling;
    let Value::Promise(promise_id) =
        operation(&mut exact, readable).expect("exact prefetched toArray peak")
    else {
        panic!("toArray must return a Promise");
    };
    let promise = crate::promise_model::PromiseHandle(promise_id);
    assert!(matches!(
        exact.promise_store.get(promise).map(|record| &record.state),
        Ok(crate::promise_model::PromiseState::Pending)
    ));
    let state = &exact.readable_from_streams[&readable];
    assert_eq!(state.phase, ReadableFromPumpPhase::End);
    assert_eq!(state.next_index, 3);
    assert!(state.buffer.is_empty());
    assert_eq!(state.buffered_length, 0);
    assert_eq!(state.lifecycle_label, Label::Secret);
    let waiter = state.to_array_waiter.as_ref().expect("toArray waiter");
    assert_eq!(waiter.promise, promise);
    assert_eq!(waiter.label, Label::Secret);
    let result = waiter.result;
    assert_eq!(
        exact.read_array_like_values(result),
        vec![
            Value::str("left"),
            Value::str("middle"),
            Value::str("right")
        ]
    );
    assert_eq!(exact.pending_readable_from_pumps.len(), 1);
    assert!(exact.readable_pump_reservations.is_empty());
    assert!(exact.estimated_memory_bytes() <= exact_ceiling);
    assert_eq!(
        exact.estimated_memory_bytes(),
        exact.recompute_estimated_memory_bytes()
    );
}

#[test]
fn readable_to_array_terminal_settlement_is_transactional_bd_33wvn() {
    let module = test_module_with_functions(
        vec![Ir3Instruction::Throw { value: 0 }],
        vec![Ir3FunctionDesc {
            entry: 0,
            arity: 0,
            frame_size: 1,
            name: Some("unexpected_second_close".to_string()),
            is_generator: false,
            rest_param_index: None,
        }],
    );

    for destroy_requested in [false, true] {
        let fixture = || {
            let mut core = test_interpreter();
            let source = core
                .alloc_array_from_values(&[Value::str("terminal item")])
                .expect("toArray source");
            core.write_reg(0, Value::Object(source))
                .expect("source register");
            let Value::Object(readable) = core
                .construct_readable_from(RegRange { start: 0, count: 1 })
                .expect("finite Readable")
            else {
                panic!("Readable.from must return an object");
            };
            let Value::Promise(promise_id) = core
                .readable_to_array(Value::Object(readable))
                .expect("toArray Promise")
            else {
                panic!("toArray must return a Promise");
            };
            let promise = crate::promise_model::PromiseHandle(promise_id);

            if destroy_requested {
                core.readable_destroy(Value::Object(readable), RegRange { start: 0, count: 0 })
                    .expect("destroy pending toArray");
            } else {
                core.drive_readable_from_pump(readable, Some(&module))
                    .expect("advance toArray through end");
            }

            assert_eq!(
                core.readable_from_streams
                    .get(&readable)
                    .expect("terminal Readable state")
                    .phase,
                ReadableFromPumpPhase::Close
            );
            assert_eq!(core.pending_readable_from_pumps.len(), 1);
            assert_eq!(
                core.estimated_memory_bytes(),
                core.recompute_estimated_memory_bytes()
            );
            (core, readable, promise)
        };

        let drive_scheduled_close = |core: &mut InterpreterCore| {
            let previous_promise_bytes = core.promise_runtime_memory_bytes();
            let macrotask = core
                .event_loop
                .turn()
                .macrotask
                .expect("scheduled close pump");
            let transferred_bytes = core.begin_promise_task_transfer(previous_promise_bytes);
            let result = core.execute_macrotask_callback(&macrotask, Some(&module));
            core.finish_promise_task_transfer(transferred_bytes);
            result
        };

        let assert_settled =
            |core: &InterpreterCore, promise: crate::promise_model::PromiseHandle| {
                let state = &core
                    .promise_store
                    .get(promise)
                    .expect("toArray Promise record")
                    .state;
                if destroy_requested {
                    assert!(matches!(
                        state,
                        crate::promise_model::PromiseState::Rejected(
                            crate::object_model::JsValue::Str(reason)
                        ) if reason == "Premature close"
                    ));
                } else {
                    assert!(matches!(
                        state,
                        crate::promise_model::PromiseState::Fulfilled(
                            crate::object_model::JsValue::Object(_)
                        )
                    ));
                }
            };

        let (mut ceiling_probe, probe_readable, probe_promise) = fixture();
        ceiling_probe.config.max_total_memory_bytes = 0;
        let exact_terminal_bytes = match drive_scheduled_close(&mut ceiling_probe) {
            Err(InterpreterError::MemoryBudgetExceeded {
                requested_bytes,
                max_bytes: 0,
                ..
            }) => requested_bytes,
            other => panic!("settlement ceiling probe returned {other:?}"),
        };
        assert!(exact_terminal_bytes > 0);
        assert!(matches!(
            ceiling_probe
                .promise_store
                .get(probe_promise)
                .expect("ceiling-probe Promise survives")
                .state,
            crate::promise_model::PromiseState::Pending
        ));
        assert_eq!(
            ceiling_probe
                .readable_from_streams
                .get(&probe_readable)
                .expect("ceiling probe retains terminal owner")
                .phase,
            ReadableFromPumpPhase::SettleToArray
        );
        assert!(ceiling_probe.pending_readable_from_pumps.is_empty());
        assert!(ceiling_probe.readable_pump_reservations.is_empty());
        assert_eq!(
            ceiling_probe.estimated_memory_bytes(),
            ceiling_probe.recompute_estimated_memory_bytes()
        );

        let (mut refused, refused_readable, refused_promise) = fixture();
        refused.config.max_total_memory_bytes = exact_terminal_bytes.saturating_sub(1);
        match drive_scheduled_close(&mut refused) {
            Err(InterpreterError::MemoryBudgetExceeded {
                requested_bytes,
                max_bytes,
                ..
            }) => {
                assert_eq!(requested_bytes, exact_terminal_bytes);
                assert_eq!(max_bytes, exact_terminal_bytes - 1);
            }
            other => panic!("one-byte-short settlement returned {other:?}"),
        }
        assert!(matches!(
            refused
                .promise_store
                .get(refused_promise)
                .expect("refused toArray Promise survives")
                .state,
            crate::promise_model::PromiseState::Pending
        ));
        let retained = refused
            .readable_from_streams
            .get(&refused_readable)
            .expect("refused settlement retains terminal ownership");
        assert_eq!(retained.phase, ReadableFromPumpPhase::SettleToArray);
        assert!(retained.to_array_waiter.is_some());
        assert!(refused.pending_readable_from_pumps.is_empty());
        assert!(refused.readable_pump_reservations.is_empty());
        assert!(
            refused
                .readable_receiver_id(Value::Object(refused_readable))
                .is_err()
        );
        assert!(!refused.readable_activation_applies(refused_readable, "data"));
        assert_eq!(
            refused.estimated_memory_bytes(),
            refused.recompute_estimated_memory_bytes()
        );

        refused.config.max_total_memory_bytes = DEFAULT_QUICKJS_MAX_TOTAL_MEMORY_BYTES;
        refused
            .insert_event_listener(
                refused_readable,
                "close",
                EventListenerRecord {
                    listener: Value::Function(0),
                    once: false,
                },
                false,
            )
            .expect("post-close listener registration");
        refused
            .drive_readable_from_pump(refused_readable, Some(&module))
            .expect("retry only terminal settlement");
        assert_settled(&refused, refused_promise);
        assert!(
            !refused
                .readable_from_streams
                .contains_key(&refused_readable)
        );
        assert!(refused.pending_readable_from_pumps.is_empty());
        assert!(refused.readable_pump_reservations.is_empty());
        assert_eq!(
            refused
                .event_listeners
                .get(&refused_readable)
                .and_then(|events| events.get(&RuntimePropertyKey::from("close")))
                .map(Vec::len),
            Some(1),
            "settlement retry must not emit or clear close again"
        );
        refused.clear_event_listeners(refused_readable, None);
        assert_eq!(
            refused.estimated_memory_bytes(),
            refused.recompute_estimated_memory_bytes()
        );

        let (mut exact, exact_readable, exact_promise) = fixture();
        exact.config.max_total_memory_bytes = exact_terminal_bytes;
        drive_scheduled_close(&mut exact).expect("terminal settlement at the exact ceiling");
        assert_settled(&exact, exact_promise);
        assert!(!exact.readable_from_streams.contains_key(&exact_readable));
        assert!(exact.pending_readable_from_pumps.is_empty());
        assert!(exact.readable_pump_reservations.is_empty());
        assert!(exact.estimated_memory_bytes() <= exact_terminal_bytes);
        assert_eq!(
            exact.estimated_memory_bytes(),
            exact.recompute_estimated_memory_bytes()
        );
    }
}

#[test]
fn readable_state_guards_reentrancy_brand_and_sparse_to_array_bd_fw7zd() {
    let mut core = test_interpreter();
    let Value::Object(readable) = core
        .construct_stream_readable(RegRange { start: 0, count: 0 })
        .expect("generic Readable")
    else {
        panic!("Readable constructor must return an object");
    };
    core.readable_pause(Value::Object(readable)).expect("pause");
    core.set_object_property(readable, "readableFlowing".to_string(), Value::Bool(true))
        .expect("forge public mirror");
    assert_eq!(
        core.readable_is_paused(Value::Object(readable))
            .expect("internal isPaused"),
        Value::Bool(true),
        "guest writes must not forge the internal paused slot"
    );

    let forged = core
        .alloc_object_with_properties(&[("__type", Value::str("Readable"))])
        .expect("forged object");
    assert!(matches!(
        core.readable_pause(Value::Object(forged)),
        Err(InterpreterError::TypeError { .. })
    ));

    core.write_reg(0, Value::Null).expect("EOF register");
    core.readable_from_streams
        .get_mut(&readable)
        .expect("live generic state")
        .phase = ReadableFromPumpPhase::Close;
    core.readable_push(Value::Object(readable), RegRange { start: 0, count: 1 })
        .expect("reentrant push(null) is an idempotent false");
    assert_eq!(
        core.readable_from_streams
            .get(&readable)
            .expect("live generic state")
            .phase,
        ReadableFromPumpPhase::Close,
        "push(null) must not rewind Close to End"
    );

    let mut atomic_core = test_interpreter();
    let Value::Object(atomic_readable) = atomic_core
        .construct_stream_readable(RegRange { start: 0, count: 0 })
        .expect("atomicity Readable")
    else {
        panic!("Readable constructor must return an object");
    };
    let state = atomic_core
        .readable_from_streams
        .get_mut(&atomic_readable)
        .expect("live atomicity state");
    state.flowing = true;
    state.buffer.push_back(ReadableBufferedChunk {
        value: Value::Int(7),
        label: Label::Secret,
        units: 1,
    });
    state.buffered_length = 1;
    let before = state.clone();
    assert!(matches!(
        atomic_core.drive_readable_from_pump(
            atomic_readable,
            Some(&test_module_with_functions(Vec::new(), Vec::new())),
        ),
        Err(InterpreterError::TypeError { .. })
    ));
    assert_eq!(
        atomic_core
            .readable_from_streams
            .get(&atomic_readable)
            .expect("failed emission retains live queue"),
        &before,
        "fallible byte materialization must not advance engine-owned stream state"
    );

    let mut sparse_core = test_interpreter();
    let source = sparse_core
        .alloc_array_from_values(&[])
        .expect("sparse source");
    sparse_core
        .set_object_property(
            source,
            "length".to_string(),
            Value::Int(i64::from(u32::MAX)),
        )
        .expect("huge sparse length");
    sparse_core
        .write_reg(0, Value::Object(source))
        .expect("sparse source register");
    let Value::Object(sparse_readable) = sparse_core
        .construct_readable_from(RegRange { start: 0, count: 1 })
        .expect("sparse finite Readable")
    else {
        panic!("Readable.from must return an object");
    };
    let heap_len = sparse_core.heap.len();
    assert!(matches!(
        sparse_core.readable_to_array(Value::Object(sparse_readable)),
        Err(InterpreterError::MemoryBudgetExceeded { .. })
    ));
    assert_eq!(sparse_core.heap.len(), heap_len);
    let state = sparse_core
        .readable_from_streams
        .get(&sparse_readable)
        .expect("failed toArray must retain source state");
    assert_eq!(state.phase, ReadableFromPumpPhase::Data);
    assert!(state.to_array_waiter.is_none());
    assert_eq!(
        sparse_core.estimated_memory_bytes(),
        sparse_core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn readable_destroy_is_synchronous_idempotent_and_memory_exact_bd_fw7zd() {
    let module = test_module_with_functions(Vec::new(), Vec::new());
    let mut core = test_interpreter();
    let Value::Object(readable) = core
        .construct_stream_readable(RegRange { start: 0, count: 0 })
        .expect("generic Readable")
    else {
        panic!("Readable constructor must return an object");
    };
    core.write_reg(0, Value::str("queued"))
        .expect("queued chunk register");
    core.readable_push(Value::Object(readable), RegRange { start: 0, count: 1 })
        .expect("queue byte chunk");
    assert_eq!(
        core.heap[readable.0 as usize]
            .properties
            .get("readableLength"),
        Some(&Value::Int(6))
    );

    core.write_reg(1, Value::str("classified failure"))
        .expect("destroy error register");
    core.set_register_label(1, Label::Secret)
        .expect("destroy error label");
    assert_eq!(
        core.readable_destroy(Value::Object(readable), RegRange { start: 1, count: 1 },)
            .expect("destroy(error)"),
        Value::Object(readable)
    );
    let destroyed = core
        .readable_from_streams
        .get(&readable)
        .expect("destroy waits for deferred error/close");
    assert_eq!(destroyed.phase, ReadableFromPumpPhase::DestroyError);
    assert!(destroyed.destroy_requested);
    assert!(destroyed.buffer.is_empty());
    assert_eq!(destroyed.lifecycle_label, Label::Secret);
    assert_eq!(
        destroyed.destroy_error,
        Some(Value::str("classified failure"))
    );
    assert_eq!(
        core.heap[readable.0 as usize]
            .properties
            .get("readableLength"),
        Some(&Value::Int(6)),
        "destroy releases the internal queue without rewriting Bun's retained diagnostic"
    );
    for (key, expected) in [
        ("destroyed", Value::Bool(true)),
        ("closed", Value::Bool(true)),
        ("readable", Value::Bool(false)),
        ("readableEnded", Value::Bool(false)),
    ] {
        assert_eq!(
            core.heap[readable.0 as usize].properties.get(key),
            Some(&expected),
            "synchronous destroy mirror {key}"
        );
    }
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );

    core.write_reg(1, Value::str("ignored second error"))
        .expect("second destroy register");
    core.readable_destroy(Value::Object(readable), RegRange { start: 1, count: 1 })
        .expect("duplicate destroy is idempotent");
    assert_eq!(
        core.readable_from_streams
            .get(&readable)
            .expect("still waiting")
            .destroy_error,
        Some(Value::str("classified failure"))
    );

    assert!(matches!(
        core.drive_readable_from_pump(readable, Some(&module)),
        Err(InterpreterError::UncaughtException { .. })
    ));
    assert_eq!(
        core.readable_from_streams
            .get(&readable)
            .expect("close remains scheduled after unhandled error")
            .phase,
        ReadableFromPumpPhase::Close
    );
    core.drive_readable_from_pump(readable, Some(&module))
        .expect("close still releases state after error");
    assert!(!core.readable_from_streams.contains_key(&readable));

    let mut ceiling_core = test_interpreter();
    let Value::Object(ceiling_readable) = ceiling_core
        .construct_stream_readable(RegRange { start: 0, count: 0 })
        .expect("memory-ceiling Readable")
    else {
        panic!("Readable constructor must return an object");
    };
    ceiling_core
        .write_reg(0, Value::str("full queue"))
        .expect("ceiling chunk register");
    ceiling_core
        .readable_push(
            Value::Object(ceiling_readable),
            RegRange { start: 0, count: 1 },
        )
        .expect("ceiling chunk push");
    ceiling_core.config.max_total_memory_bytes = ceiling_core.estimated_memory_bytes();
    ceiling_core
        .readable_destroy(
            Value::Object(ceiling_readable),
            RegRange { start: 0, count: 0 },
        )
        .expect("teardown must not clone a full queue at the memory ceiling");
    assert!(
        ceiling_core
            .readable_from_streams
            .get(&ceiling_readable)
            .expect("close is deferred")
            .buffer
            .is_empty()
    );
    assert_eq!(
        ceiling_core.estimated_memory_bytes(),
        ceiling_core.recompute_estimated_memory_bytes()
    );
    ceiling_core
        .run_event_loop_until_idle_with_module(Some(&module))
        .expect("ceiling readable event loop");
    assert!(
        !ceiling_core
            .readable_from_streams
            .contains_key(&ceiling_readable)
    );
    assert!(ceiling_core.pending_readable_from_pumps.is_empty());
    assert_eq!(
        ceiling_core.estimated_memory_bytes(),
        ceiling_core.recompute_estimated_memory_bytes()
    );

    let mut array_core = test_interpreter();
    let source = array_core
        .alloc_array_from_values(&[Value::str("partial")])
        .expect("toArray source");
    array_core
        .write_reg(0, Value::Object(source))
        .expect("source register");
    let Value::Object(array_readable) = array_core
        .construct_readable_from(RegRange { start: 0, count: 1 })
        .expect("finite Readable")
    else {
        panic!("Readable.from must return an object");
    };
    let Value::Promise(promise_id) = array_core
        .readable_to_array(Value::Object(array_readable))
        .expect("pending toArray")
    else {
        panic!("toArray must return a Promise");
    };
    array_core
        .write_reg(1, Value::str("abort"))
        .expect("destroy reason register");
    array_core
        .readable_destroy(
            Value::Object(array_readable),
            RegRange { start: 1, count: 1 },
        )
        .expect("destroy pending toArray");
    assert!(matches!(
        array_core.drive_readable_from_pump(array_readable, Some(&module)),
        Err(InterpreterError::UncaughtException { .. })
    ));
    array_core
        .drive_readable_from_pump(array_readable, Some(&module))
        .expect("destroyed toArray close");
    assert!(matches!(
        &array_core
            .promise_store
            .get(crate::promise_model::PromiseHandle(promise_id))
            .expect("settled toArray Promise")
            .state,
        crate::promise_model::PromiseState::Rejected(crate::object_model::JsValue::Str(
            reason
        )) if reason == "abort"
    ));
}

#[test]
fn readable_terminal_provenance_survives_close_destroy_and_repeated_reads_bd_k2ig3() {
    let lifecycle_module = test_module_with_functions(Vec::new(), Vec::new());
    let property_module = test_module_with_functions(
        vec![
            Ir3Instruction::GetProperty {
                obj: 0,
                key: 1,
                dst: 4,
            },
            Ir3Instruction::GetProperty {
                obj: 0,
                key: 2,
                dst: 5,
            },
            Ir3Instruction::GetProperty {
                obj: 0,
                key: 3,
                dst: 6,
            },
            Ir3Instruction::GetProperty {
                obj: 0,
                key: 1,
                dst: 7,
            },
            Ir3Instruction::GetProperty {
                obj: 0,
                key: 2,
                dst: 8,
            },
            Ir3Instruction::GetProperty {
                obj: 0,
                key: 3,
                dst: 9,
            },
            Ir3Instruction::Halt,
        ],
        Vec::new(),
    );
    let assert_repeated_terminal_reads =
        |core: &mut InterpreterCore, readable: ObjectId, expected_label: &Label| {
            // Forge every ordinary terminal mirror back to Public-looking
            // values. The read values remain compatibility data, but their
            // provenance must come from the engine-owned tombstone.
            for key in ["closed", "destroyed", "readableEnded"] {
                core.set_object_property(readable, key.to_string(), Value::Bool(false))
                    .expect("forge ordinary terminal mirror");
            }
            core.write_reg_with_label(0, Value::Object(readable), Label::Public)
                .expect("terminal Readable receiver");
            for (register, key) in [(1, "closed"), (2, "destroyed"), (3, "readableEnded")] {
                core.write_reg_with_label(register, Value::str(key), Label::Public)
                    .expect("terminal property key");
            }
            for register in 4..=9 {
                core.write_reg_with_label(register, Value::Undefined, Label::Public)
                    .expect("Public property destination");
            }
            core.ip = 0;
            assert_eq!(
                core.run_loop(&property_module),
                Err(InterpreterError::Halted)
            );
            for register in 4..=9 {
                assert_eq!(
                    core.read_reg(register).expect("terminal property value"),
                    Value::Bool(false),
                    "the test must actually observe the guest-forged mirror"
                );
                assert_eq!(
                    core.get_register_label(register)
                        .expect("terminal property label"),
                    expected_label,
                    "every repeated terminal observation retains lifecycle provenance"
                );
            }
            assert_eq!(core.stream_state_label(readable), expected_label.clone());
            assert_eq!(
                core.estimated_memory_bytes(),
                core.recompute_estimated_memory_bytes()
            );
        };

    let mut close_core = test_interpreter();
    let reset_seed = close_core
        .capture_execution_seed()
        .expect("test execution-seed capture must fit");
    let options = close_core
        .alloc_object_with_properties(&[("highWaterMark", Value::Int(4))])
        .expect("configured Readable options");
    let config_label = Label::Custom {
        name: "terminal-readable-config".to_string(),
        level: 4,
    };
    close_core
        .write_reg_with_label(0, Value::Object(options), config_label.clone())
        .expect("classified Readable options");
    let Value::Object(closed_readable) = close_core
        .construct_stream_readable(RegRange { start: 0, count: 1 })
        .expect("configured Readable")
    else {
        panic!("Readable constructor must return an object");
    };
    close_core
        .readable_request_eof(closed_readable, Label::Public)
        .expect("request configured Readable EOF");
    close_core
        .run_event_loop_until_idle_with_module(Some(&lifecycle_module))
        .expect("configured Readable close");
    assert!(
        !close_core
            .readable_from_streams
            .contains_key(&closed_readable)
    );
    assert_eq!(
        close_core.readable_terminal_states[&closed_readable].lifecycle_label,
        config_label
    );
    assert_repeated_terminal_reads(&mut close_core, closed_readable, &config_label);

    close_core
        .reset_execution_state_from_seed(&reset_seed)
        .expect("reset terminal Readable state");
    assert!(close_core.readable_terminal_states.is_empty());
    assert_eq!(
        close_core.stream_state_label(closed_readable),
        Label::Public,
        "a reset heap identity cannot inherit terminal provenance"
    );
    assert_eq!(
        close_core.estimated_memory_bytes(),
        close_core.recompute_estimated_memory_bytes()
    );

    let mut error_core = test_interpreter();
    let Value::Object(destroyed_readable) = error_core
        .construct_stream_readable(RegRange { start: 0, count: 0 })
        .expect("destroyed Readable")
    else {
        panic!("Readable constructor must return an object");
    };
    error_core
        .write_reg_with_label(1, Value::str("classified failure"), Label::Secret)
        .expect("classified destroy error");
    error_core
        .readable_destroy(
            Value::Object(destroyed_readable),
            RegRange { start: 1, count: 1 },
        )
        .expect("destroy(error)");
    assert!(matches!(
        error_core.drive_readable_from_pump(destroyed_readable, Some(&lifecycle_module)),
        Err(InterpreterError::UncaughtException { .. })
    ));
    error_core
        .drive_readable_from_pump(destroyed_readable, Some(&lifecycle_module))
        .expect("close after unhandled destroy error");
    error_core
        .run_event_loop_until_idle_with_module(Some(&lifecycle_module))
        .expect("drain stale scheduled Readable pump");
    assert!(
        !error_core
            .readable_from_streams
            .contains_key(&destroyed_readable)
    );
    assert_eq!(
        error_core.readable_terminal_states[&destroyed_readable].lifecycle_label,
        Label::Secret
    );
    assert_repeated_terminal_reads(&mut error_core, destroyed_readable, &Label::Secret);
}

#[test]
fn readable_from_data_end_and_close_promises_retain_source_label_bd_fw7zd() {
    let module = test_module_with_functions(Vec::new(), Vec::new());
    let mut core = test_interpreter();
    let source = core
        .alloc_array_from_values(&[Value::str("classified")])
        .expect("single-chunk source array");
    core.mutate_registers(|registers| registers[0] = Value::Object(source));
    core.set_register_label(0, Label::Secret)
        .expect("source label");
    let Value::Object(readable_id) = core
        .construct_readable_from(RegRange { start: 0, count: 1 })
        .expect("construct finite readable")
    else {
        panic!("Readable.from must return an object");
    };

    let mut promises = Vec::new();
    for event in ["data", "end", "close"] {
        core.write_reg(1, Value::Object(readable_id))
            .expect("emitter registration value");
        core.write_reg(2, Value::str(event))
            .expect("event registration value");
        core.set_register_label(1, Label::Public)
            .expect("emitter registration label");
        core.set_register_label(2, Label::Public)
            .expect("event registration label");
        let Value::Promise(promise) = core
            .register_event_promise_once(RegRange { start: 1, count: 2 })
            .expect("register static events.once waiter")
        else {
            panic!("events.once must return a Promise");
        };
        promises.push(promise);
    }

    core.run_event_loop_until_idle_with_module(Some(&module))
        .expect("readable lifecycle event loop");

    for promise in promises {
        let record = core
            .promise_store
            .get(crate::promise_model::PromiseHandle(promise))
            .expect("settled lifecycle promise");
        assert!(matches!(
            &record.state,
            crate::promise_model::PromiseState::Fulfilled(_)
        ));
        assert_eq!(record.label, Label::Secret);
    }
    assert!(core.readable_from_streams.is_empty());
    assert!(core.pending_readable_from_pumps.is_empty());
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn static_events_once_publishes_removable_once_wrappers_bd_asw4m_4() {
    let module = test_module_with_functions(Vec::new(), Vec::new());
    let mut core = test_interpreter();
    let emitter = core
        .alloc_branded_object("EventEmitter", &[])
        .expect("emitter object");

    // events.once(emitter, "ready")
    core.write_reg(1, Value::Object(emitter))
        .expect("emitter registration value");
    core.write_reg(2, Value::str("ready"))
        .expect("event registration value");
    core.set_register_label(1, Label::Public)
        .expect("emitter registration label");
    core.set_register_label(2, Label::Public)
        .expect("event registration label");
    let Value::Promise(promise) = core
        .register_event_promise_once(RegRange { start: 1, count: 2 })
        .expect("register static events.once waiter")
    else {
        panic!("events.once must return a Promise");
    };

    // Both the requested event and the implicit `error` link now surface one
    // callable once wrapper through rawListeners (bd-asw4m.4), and both share
    // the same static waiter id so either settlement removes the pair.
    let mut waiter_ids = Vec::new();
    for event in ["ready", "error"] {
        let records = core.event_listener_records_for(emitter, event);
        assert_eq!(
            records.len(),
            1,
            "static events.once must expose one wrapper on `{event}`"
        );
        assert!(records[0].once, "the static-once wrapper is one-shot");
        let property_object =
            InterpreterCore::event_once_wrapper_property_object(&records[0].listener)
                .expect("static-once listener is a once wrapper");
        let waiter = core
            .event_once_wrappers
            .get(&property_object)
            .and_then(|state| state.static_once_waiter)
            .expect("static-once wrapper carries its waiter id");
        waiter_ids.push(waiter);
    }
    assert_eq!(
        waiter_ids[0], waiter_ids[1],
        "the requested-event and error wrappers belong to one registration"
    );
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes(),
        "publishing static-once wrappers keeps the memory estimate exact"
    );

    // Emitting the event settles the Promise through the waiter table and
    // strips BOTH wrappers without invoking them (no duplicated settlement).
    core.emit_event_listener_records(
        &module,
        emitter,
        "ready",
        vec![Value::str("go")],
        Label::Public,
    )
    .expect("emit ready");
    assert!(
        core.event_listener_records_for(emitter, "ready").is_empty(),
        "settling removes the requested-event wrapper"
    );
    assert!(
        core.event_listener_records_for(emitter, "error").is_empty(),
        "settling one link removes the sibling error wrapper"
    );
    let record = core
        .promise_store
        .get(crate::promise_model::PromiseHandle(promise))
        .expect("settled events.once promise");
    assert!(
        matches!(
            &record.state,
            crate::promise_model::PromiseState::Fulfilled(_)
        ),
        "the requested event fulfils the events.once promise"
    );
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes(),
        "settling static-once wrappers keeps the memory estimate exact"
    );
}

#[test]
fn remove_all_listeners_emits_meta_and_stays_atomic_bd_asw4m_6() {
    // function_table[0] throws when invoked (a throwing guest
    // `removeListener` handler); function_table[1] returns normally.
    let module = test_module_with_functions(
        vec![
            Ir3Instruction::Throw { value: 0 },
            Ir3Instruction::Return { value: 0 },
        ],
        vec![
            Ir3FunctionDesc {
                entry: 0,
                arity: 2,
                frame_size: 2,
                name: Some("throwing_remove_listener".to_string()),
                is_generator: false,
                rest_param_index: None,
            },
            Ir3FunctionDesc {
                entry: 1,
                arity: 2,
                frame_size: 2,
                name: Some("returning_remove_listener".to_string()),
                is_generator: false,
                rest_param_index: None,
            },
        ],
    );
    let remove_all = BuiltinFunction::new_kind(BuiltinFunctionKind::EmitterRemoveAllListeners);
    // Register through the canonical EmitterOn dispatch so listener memory is
    // accounted exactly as production does.
    let register = |core: &mut InterpreterCore, emitter: ObjectId, event: &str, listener: Value| {
        core.mutate_registers(|registers| {
            if registers.len() < 2 {
                registers.resize(2, Value::Undefined);
            }
            registers[0] = Value::str(event);
            registers[1] = listener;
        });
        core.dispatch_builtin_function(
            &module,
            &BuiltinFunction::new_kind(BuiltinFunctionKind::EmitterOn),
            RegRange { start: 0, count: 2 },
            Some(Value::Object(emitter)),
            None,
        )
        .expect("register listener via EmitterOn");
    };
    let remove_all_for = |core: &mut InterpreterCore, emitter: ObjectId| {
        core.mutate_registers(|registers| {
            if registers.is_empty() {
                registers.resize(1, Value::Undefined);
            }
            registers[0] = Value::str("ready");
        });
        core.dispatch_builtin_function(
            &module,
            &remove_all,
            RegRange { start: 0, count: 1 },
            Some(Value::Object(emitter)),
            None,
        )
    };

    // Fast path: with no `removeListener` handler registered, Node clears
    // silently and emits no meta-events.
    let mut fast = test_interpreter();
    let fast_emitter = fast
        .alloc_branded_object("EventEmitter", &[])
        .expect("emitter object");
    register(&mut fast, fast_emitter, "ready", Value::Closure(1));
    register(&mut fast, fast_emitter, "ready", Value::Closure(2));
    remove_all_for(&mut fast, fast_emitter).expect("fast-path removeAllListeners");
    assert!(
        fast.event_listener_records_for(fast_emitter, "ready")
            .is_empty(),
        "the silent fast path still removes the listeners"
    );

    // Slow path, full completion: a non-throwing `removeListener` handler is
    // invoked once per removed listener; every `ready` listener is removed,
    // the handler stays, and accounting is exact after settlement.
    let mut done = test_interpreter();
    let done_emitter = done
        .alloc_branded_object("EventEmitter", &[])
        .expect("emitter object");
    register(
        &mut done,
        done_emitter,
        "removeListener",
        Value::Function(1),
    );
    register(&mut done, done_emitter, "ready", Value::Closure(1));
    register(&mut done, done_emitter, "ready", Value::Closure(2));
    // Gap-invariance: removeAllListeners must release exactly the memory it
    // charged, so the estimate/recompute delta is unchanged across the call
    // (robust to any fixed test-setup accounting baseline).
    let gap_before =
        done.recompute_estimated_memory_bytes() as i128 - done.estimated_memory_bytes() as i128;
    remove_all_for(&mut done, done_emitter).expect("slow-path removeAllListeners completes");
    let gap_after =
        done.recompute_estimated_memory_bytes() as i128 - done.estimated_memory_bytes() as i128;
    assert_eq!(
        gap_before, gap_after,
        "a fully-completing removeAllListeners releases exactly the charged listener memory"
    );
    assert!(
        done.event_listener_records_for(done_emitter, "ready")
            .is_empty(),
        "every requested-event listener is removed"
    );
    assert!(
        !done
            .event_listener_records_for(done_emitter, "removeListener")
            .is_empty(),
        "an event-specific removeAllListeners leaves the removeListener handler in place"
    );

    // Slow path, throwing handler: proves the meta-events fire in LIFO order
    // and that a throw leaves consistent state — exactly the most-recent
    // listener is removed before the handler aborts.
    let mut slow = test_interpreter();
    let slow_emitter = slow
        .alloc_branded_object("EventEmitter", &[])
        .expect("emitter object");
    register(
        &mut slow,
        slow_emitter,
        "removeListener",
        Value::Function(0),
    );
    register(&mut slow, slow_emitter, "ready", Value::Closure(1));
    register(&mut slow, slow_emitter, "ready", Value::Closure(2));
    let result = remove_all_for(&mut slow, slow_emitter);
    assert!(
        result.is_err(),
        "a throwing removeListener handler propagates out of removeAllListeners"
    );
    let remaining = slow.event_listener_records_for(slow_emitter, "ready");
    assert_eq!(
        remaining.len(),
        1,
        "only the LIFO-first removal completed before the meta handler threw"
    );
    assert_eq!(
        remaining[0].listener,
        Value::Closure(1),
        "the most-recently registered listener is removed first"
    );
}

#[test]
fn readable_from_throwing_data_or_end_listener_still_closes_bd_fw7zd() {
    let module = test_module_with_functions(
        vec![Ir3Instruction::Throw { value: 0 }],
        vec![Ir3FunctionDesc {
            entry: 0,
            arity: 1,
            frame_size: 1,
            name: Some("throw_from_stream_listener".to_string()),
            is_generator: false,
            rest_param_index: None,
        }],
    );

    for event in ["data", "end"] {
        let mut core = test_interpreter();
        let source = core
            .alloc_array_from_values(&[Value::str("chunk")])
            .expect("single-chunk source array");
        core.mutate_registers(|registers| registers[0] = Value::Object(source));
        let Value::Object(readable_id) = core
            .construct_readable_from(RegRange { start: 0, count: 1 })
            .expect("construct finite readable")
        else {
            panic!("Readable.from must return an object");
        };
        core.insert_event_listener(
            readable_id,
            event,
            EventListenerRecord {
                listener: Value::Function(0),
                once: false,
            },
            false,
        )
        .expect("throwing listener registration");
        core.activate_readable_from_data_flow(readable_id, "data")
            .expect("flow activation");

        let error = core
            .run_event_loop_until_idle_with_module(Some(&module))
            .expect_err("throwing readable listener must escape the event loop");
        assert_eq!(
            error,
            InterpreterError::UncaughtException {
                value: if event == "data" {
                    "chunk".to_string()
                } else {
                    "undefined".to_string()
                }
            },
            "cleanup must not swallow the original {event} listener exception"
        );

        assert!(
            !core.readable_from_streams.contains_key(&readable_id),
            "throwing {event} listener must not retain stream state"
        );
        assert!(core.pending_readable_from_pumps.is_empty());
        assert!(!core.event_loop.has_pending_work());
        assert!(!core.event_listeners.contains_key(&readable_id));
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }
}

/// bd-2dmnn: listener records live outside the JS heap but still consume
/// the same total-memory budget. Failed registrations must leave both the
/// side table and incremental accumulator unchanged, while removals release
/// the full conservative charge.
#[test]
fn event_emitter_listener_side_table_is_memory_accounted_bd_2dmnn() {
    let mut core = test_interpreter();
    let target_id = ObjectId(999);
    let event = "tick";
    let record = EventListenerRecord {
        listener: Value::Closure(7),
        once: false,
    };
    let baseline_bytes = core.estimated_memory_bytes();
    let record_bytes = InterpreterCore::estimate_event_listener_record_bytes(
        &RuntimePropertyKey::from(event),
        &record,
    );

    assert_eq!(baseline_bytes, core.recompute_estimated_memory_bytes());
    core.config.max_total_memory_bytes = baseline_bytes
        .saturating_add(record_bytes)
        .saturating_sub(1);
    let error = core
        .insert_event_listener(target_id, event, record.clone(), false)
        .expect_err("listener registration above the memory budget must fail");
    assert!(matches!(
        error,
        InterpreterError::MemoryBudgetExceeded { .. }
    ));
    assert!(!core.event_listeners.contains_key(&target_id));
    assert_eq!(core.estimated_memory_bytes(), baseline_bytes);

    core.config.max_total_memory_bytes = u64::MAX;
    core.insert_event_listener(target_id, event, record.clone(), false)
        .expect("listener registration within the memory budget");
    assert_eq!(
        core.estimated_memory_bytes(),
        baseline_bytes.saturating_add(record_bytes)
    );
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );

    assert_eq!(
        core.remove_event_listener(target_id, event, &record.listener),
        Some(record)
    );
    assert_eq!(core.estimated_memory_bytes(), baseline_bytes);
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn exact_event_keys_are_collision_free_and_memory_atomic_bd_9vouw_307() {
    let mut core = test_interpreter();
    let target = core
        .alloc_branded_object("EventEmitter", &[])
        .expect("event target");
    let symbol = core
        .allocate_private_symbol(Some(JsString::from("event")))
        .expect("event symbol");
    let symbol_key = RuntimePropertyKey::Symbol(symbol);
    let keys = [
        RuntimePropertyKey::from(symbol_key.diagnostic().as_str()),
        symbol_key,
        RuntimePropertyKey::String(JsString::from_code_units(&[0xD800])),
        RuntimePropertyKey::String(JsString::from_code_units(&[0xD801])),
        RuntimePropertyKey::from("\u{FFFD}"),
    ];
    let record = EventListenerRecord {
        listener: Value::BuiltinFunction(BuiltinFunction::new_kind(
            BuiltinFunctionKind::ArrayIsArray,
        )),
        once: false,
    };
    let baseline_bytes = core.estimated_memory_bytes();

    for (index, key) in keys.iter().enumerate() {
        let before = core.estimated_memory_bytes();
        let record_bytes = InterpreterCore::estimate_event_listener_record_bytes(key, &record);
        core.config.max_total_memory_bytes = before + record_bytes - 1;
        assert!(matches!(
            core.insert_event_listener(target, key, record.clone(), false),
            Err(InterpreterError::MemoryBudgetExceeded { .. })
        ));
        assert!(core.event_listener_records_for(target, key).is_empty());
        assert_eq!(core.estimated_memory_bytes(), before);
        assert_eq!(before, core.recompute_estimated_memory_bytes());

        core.config.max_total_memory_bytes = before + record_bytes;
        core.insert_event_listener(target, key, record.clone(), false)
            .expect("exact event registration budget");
        assert_eq!(core.event_listeners[&target].len(), index + 1);
        assert_eq!(core.estimated_memory_bytes(), before + record_bytes);
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }

    for (index, key) in keys.iter().enumerate() {
        assert_eq!(
            core.remove_event_listener(target, key, &record.listener),
            Some(record.clone())
        );
        assert!(core.event_listener_records_for(target, key).is_empty());
        for remaining in &keys[index + 1..] {
            assert_eq!(core.event_listener_records_for(target, remaining).len(), 1);
        }
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }
    assert!(!core.event_listeners.contains_key(&target));
    assert_eq!(core.estimated_memory_bytes(), baseline_bytes);
}

#[test]
fn symbol_event_waiters_preserve_labels_and_release_links_bd_9vouw_307() {
    let module = test_module_with_functions(Vec::new(), Vec::new());
    for reject in [false, true] {
        let mut core = test_interpreter();
        let target = core
            .alloc_branded_object("EventEmitter", &[])
            .expect("event target");
        let symbol = core
            .allocate_private_symbol(Some(JsString::from("error")))
            .expect("event symbol");
        let event = RuntimePropertyKey::Symbol(symbol);
        let registration_label = Label::Custom {
            name: "symbol-event-registration".to_string(),
            level: 4,
        };
        core.write_reg_with_label(0, Value::Object(target), Label::Public)
            .expect("event target register");
        core.write_reg_with_label(1, event.value(), registration_label.clone())
            .expect("classified symbol event register");
        let Value::Promise(promise) = core
            .register_event_promise_once(RegRange { start: 0, count: 2 })
            .expect("symbol events.once registration")
        else {
            panic!("events.once returns a promise");
        };
        assert_eq!(core.event_listener_records_for(target, &event).len(), 1);
        assert_eq!(core.event_listener_records_for(target, "error").len(), 1);
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );

        let emitted = if reject {
            RuntimePropertyKey::from("error")
        } else {
            event.clone()
        };
        core.emit_event_listener_records(
            &module,
            target,
            &emitted,
            vec![Value::str("payload")],
            Label::Secret,
        )
        .expect("settle symbol waiter");
        let settled = core
            .promise_store
            .get(crate::promise_model::PromiseHandle(promise))
            .expect("settled event promise");
        assert_eq!(settled.label, registration_label.join(&Label::Secret));
        if reject {
            assert!(matches!(
                &settled.state,
                crate::promise_model::PromiseState::Rejected(
                    crate::object_model::JsValue::Str(value)
                ) if value == "payload"
            ));
        } else {
            assert!(matches!(
                &settled.state,
                crate::promise_model::PromiseState::Fulfilled(
                    crate::object_model::JsValue::Object(_)
                )
            ));
        }
        assert!(!core.event_listeners.contains_key(&target));
        assert!(!core.event_promise_waiters.contains_key(&target));
        assert!(core.event_once_wrappers.values().all(|state| state.fired));
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }
}

#[test]
fn event_once_wrapper_allocation_is_atomic_accounted_and_seed_safe_bd_asw4m_2() {
    let mut core = test_interpreter();
    let target = core
        .alloc_branded_object("EventEmitter", &[])
        .expect("emitter target before seed capture");
    let seed = core
        .capture_execution_seed()
        .expect("test execution-seed capture must fit");
    core.materialize_pending_lazy_seeds_with_current_state();
    assert!(!seed.is_lazy());
    let baseline_heap_len = core.heap.len();
    let baseline_bytes = core.estimated_memory_bytes();
    let original_listener =
        Value::BuiltinFunction(BuiltinFunction::new_kind(BuiltinFunctionKind::ArrayIsArray));
    let projected_state = EventOnceWrapperState {
        target,
        event: RuntimePropertyKey::from("tick"),
        original_listener: original_listener.clone(),
        fired: false,
        static_once_waiter: None,
    };
    let state_bytes = InterpreterCore::estimate_event_once_wrapper_state_bytes(&projected_state);
    let mut projected_object = HeapObject::new();
    projected_object
        .properties
        .insert("listener".to_string(), original_listener.clone());
    let object_bytes = InterpreterCore::estimate_heap_object_bytes(&projected_object);
    let exact_bytes = baseline_bytes
        .saturating_add(state_bytes)
        .saturating_add(object_bytes);

    core.config.max_total_memory_bytes = exact_bytes.saturating_sub(1);
    let error = core
        .create_event_once_wrapper(target, "tick", original_listener.clone(), None)
        .expect_err("one-byte-short wrapper allocation must fail atomically");
    assert!(matches!(
        error,
        InterpreterError::MemoryBudgetExceeded { .. }
    ));
    assert_eq!(core.heap.len(), baseline_heap_len);
    assert!(core.event_once_wrappers.is_empty());
    assert_eq!(core.estimated_memory_bytes(), baseline_bytes);
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );

    core.config.max_total_memory_bytes = exact_bytes;
    let (wrapper, property_object, previous_heap_len) = core
        .create_event_once_wrapper(target, "tick", original_listener.clone(), None)
        .expect("exact wrapper allocation ceiling must succeed");
    assert_eq!(previous_heap_len, baseline_heap_len);
    assert_eq!(
        InterpreterCore::event_once_wrapper_property_object(&wrapper),
        Some(property_object)
    );
    assert_eq!(
        core.heap[property_object.0 as usize]
            .properties
            .get("listener"),
        Some(&original_listener)
    );
    assert_eq!(
        core.event_once_wrappers.get(&property_object),
        Some(&projected_state)
    );
    assert_eq!(core.estimated_memory_bytes(), exact_bytes);
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );

    core.config.max_total_memory_bytes = u64::MAX;
    core.insert_event_listener(
        target,
        "tick",
        EventListenerRecord {
            listener: wrapper,
            once: true,
        },
        false,
    )
    .expect("plain EventEmitter wrapper registration before reset");
    assert!(core.event_listeners.contains_key(&target));
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
    core.reset_execution_state_from_seed(&seed)
        .expect("seed reset clears once-wrapper side state");
    assert!(core.event_once_wrappers.is_empty());
    assert!(core.event_listeners.is_empty());
    assert_eq!(core.heap.len(), baseline_heap_len);
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
    let replacement = core
        .alloc_object_with_prototype(None)
        .expect("ordinary object after once-wrapper seed reset");
    assert_eq!(
        replacement, property_object,
        "cleared wrapper state must not brand a reused ObjectId"
    );
    assert!(
        !core.event_once_wrappers.contains_key(&replacement),
        "the reused ObjectId has no stale once-wrapper state"
    );
}

#[test]
fn deferred_http_event_preserves_once_wrapper_until_delivery_bd_asw4m_2() {
    let module = test_module_with_functions(Vec::new(), Vec::new());
    let mut core = test_interpreter();
    let source = core
        .alloc_branded_object("EventEmitter", &[])
        .expect("source emitter");
    let delivery_target = core
        .alloc_branded_object("ClientRequest", &[])
        .expect("deferred delivery emitter");
    let original =
        Value::BuiltinFunction(BuiltinFunction::new_kind(BuiltinFunctionKind::ArrayIsArray));
    let (wrapper, property_object, _) = core
        .create_event_once_wrapper(source, "source", original, None)
        .expect("stable once wrapper");
    core.insert_event_listener(
        source,
        "source",
        EventListenerRecord {
            listener: wrapper.clone(),
            once: true,
        },
        false,
    )
    .expect("source once registration");
    core.insert_event_listener(
        delivery_target,
        "response",
        EventListenerRecord {
            listener: wrapper.clone(),
            once: false,
        },
        false,
    )
    .expect("cross-registered raw wrapper");

    core.schedule_io_callback_with_label(0, Vec::new(), Label::Public)
        .expect("finish callback turn");
    let finish_sequence = *core
        .pending_io_callbacks
        .keys()
        .next()
        .expect("finish callback registration");
    let delivery_sequence = core
        .schedule_http_task(PendingHttpTask::EmitLegacyEvent {
            target: delivery_target,
            event: "response".to_string(),
            arguments: vec![Value::Undefined],
            leading_callback: None,
            label: Label::Public,
        })
        .expect("logical response event turn");
    assert!(
        finish_sequence < delivery_sequence,
        "the finish callback is queued before response-event delivery"
    );
    assert!(
        core.event_listeners
            .get(&source)
            .and_then(|events| events.get(&RuntimePropertyKey::from("source")))
            .is_some_and(|records| records.len() == 1),
        "scheduling must not consume the source once registration"
    );
    assert_eq!(
        core.event_once_wrappers
            .get(&property_object)
            .map(|state| state.fired),
        Some(false)
    );

    let task = core
        .pending_http_tasks
        .remove(&delivery_sequence)
        .expect("queued logical response event");
    core.execute_pending_http_task(task, Some(&module))
        .expect("response-event delivery");

    assert_eq!(
        core.event_once_wrappers
            .get(&property_object)
            .map(|state| state.fired),
        Some(true),
        "the wrapper fires only on the deferred event turn"
    );
    assert!(
        core.event_listeners
            .get(&source)
            .and_then(|events| events.get(&RuntimePropertyKey::from("source")))
            .is_none(),
        "direct wrapper invocation consumes its captured source registration"
    );
    assert!(
        core.event_listeners
            .get(&delivery_target)
            .and_then(|events| events.get(&RuntimePropertyKey::from("response")))
            .is_some_and(|records| {
                records.len() == 1
                    && InterpreterCore::strict_eq_values(&records[0].listener, &wrapper)
                    && !records[0].once
            }),
        "cross-registration remains on the delivery emitter after its wrapper fires"
    );
}

#[test]
fn event_snapshot_ignores_listener_mutations_after_emit_start_bd_asw4m_2() {
    let module = test_module_with_functions(Vec::new(), Vec::new());
    let mut core = test_interpreter();
    let target = core
        .alloc_branded_object("ClientRequest", &[])
        .expect("response emitter");
    let original =
        Value::BuiltinFunction(BuiltinFunction::new_kind(BuiltinFunctionKind::ArrayIsArray));
    let (keep, keep_state, _) = core
        .create_event_once_wrapper(target, "response", original.clone(), None)
        .expect("pre-existing response wrapper");
    core.insert_event_listener(
        target,
        "response",
        EventListenerRecord {
            listener: keep.clone(),
            once: true,
        },
        false,
    )
    .expect("pre-existing response listener");
    let snapshot = core.event_listener_records_for(target, "response");

    core.remove_event_listener(target, "response", &keep)
        .expect("leading callback removes pre-existing listener");
    let (late, late_state, _) = core
        .create_event_once_wrapper(target, "response", original, None)
        .expect("late response wrapper");
    core.insert_event_listener(
        target,
        "response",
        EventListenerRecord {
            listener: late.clone(),
            once: true,
        },
        false,
    )
    .expect("listener added during leading callback");

    core.emit_event_listener_snapshot(
        &module,
        target,
        "response",
        vec![Value::Undefined],
        Label::Public,
        snapshot,
    )
    .expect("dispatch pre-callback listener snapshot");

    assert_eq!(
        core.event_once_wrappers
            .get(&keep_state)
            .map(|state| state.fired),
        Some(true),
        "removing a snapshotted listener does not suppress the current emit"
    );
    assert_eq!(
        core.event_once_wrappers
            .get(&late_state)
            .map(|state| state.fired),
        Some(false),
        "a listener added after the snapshot waits for the next emit"
    );
    assert!(
        core.event_listeners
            .get(&target)
            .and_then(|events| events.get(&RuntimePropertyKey::from("response")))
            .is_some_and(|records| {
                records.len() == 1 && InterpreterCore::strict_eq_values(&records[0].listener, &late)
            })
    );
}

/// bd-3894s slice (2d): scheduling the readable-stream `'data'` phase drives a
/// `'data'` turn that then schedules the `'end'` turn; after `'end'` the object's
/// listener table is released. Exercised on the module-less event-loop path (the
/// listener closures are not invoked there — that is proven by the node mock-free
/// e2e); this asserts the data→end chaining and the cleanup are mechanism-correct.
#[test]
fn stream_emission_side_table_charge_is_atomic_exact_and_scales_bd_rgx1b() {
    let mut core = test_interpreter();
    let first = core
        .alloc_object_with_properties(&[("body", Value::str("first"))])
        .expect("first response object");
    let second = core
        .alloc_object_with_properties(&[("body", Value::str("second"))])
        .expect("second response object");
    let baseline_bytes = core.estimated_memory_bytes();
    let baseline_event_loop_bytes = core.event_loop.estimated_memory_bytes();
    let registration_bytes = core
        .event_loop
        .projected_io_completion_memory_bytes(&Label::Public)
        .saturating_sub(baseline_event_loop_bytes);
    let retained_bytes = registration_bytes.saturating_add(MEMORY_ESTIMATE_MAP_ENTRY_BYTES);

    core.config.max_total_memory_bytes = baseline_bytes
        .saturating_add(retained_bytes)
        .saturating_sub(1);
    assert!(matches!(
        core.schedule_stream_emission(first, StreamEventPhase::Data, Label::Public),
        Err(InterpreterError::MemoryBudgetExceeded { .. })
    ));
    assert!(core.pending_stream_emissions.is_empty());
    assert_eq!(
        core.event_loop.estimated_memory_bytes(),
        baseline_event_loop_bytes
    );
    assert_eq!(core.estimated_memory_bytes(), baseline_bytes);

    core.config.max_total_memory_bytes =
        baseline_bytes.saturating_add(retained_bytes.saturating_mul(2));
    core.schedule_stream_emission(first, StreamEventPhase::Data, Label::Public)
        .expect("first exact stream emission charge");
    core.schedule_stream_emission(second, StreamEventPhase::Data, Label::Public)
        .expect("second exact stream emission charge");
    let registrations: Vec<u64> = core.pending_stream_emissions.keys().copied().collect();
    assert_eq!(registrations.len(), 2);
    assert_eq!(
        core.pending_stream_emissions_memory_bytes(),
        MEMORY_ESTIMATE_MAP_ENTRY_BYTES.saturating_mul(2)
    );
    assert_eq!(
        core.event_loop.estimated_memory_bytes(),
        baseline_event_loop_bytes.saturating_add(registration_bytes.saturating_mul(2))
    );
    assert_eq!(
        core.estimated_memory_bytes(),
        baseline_bytes.saturating_add(retained_bytes.saturating_mul(2))
    );
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );

    core.clear_http_execution_state();
    assert!(core.pending_stream_emissions.is_empty());
    for registration in registrations {
        assert!(core.event_loop.cancel_registration(registration).is_none());
    }
    assert_eq!(
        core.event_loop.estimated_memory_bytes(),
        baseline_event_loop_bytes
    );
    assert_eq!(core.estimated_memory_bytes(), baseline_bytes);
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn stream_emission_seed_reset_cancels_stale_object_id_task_bd_rgx1b() {
    let mut core = test_interpreter();
    let seed = core
        .capture_execution_seed()
        .expect("test execution-seed capture must fit");
    let stale_target = core
        .alloc_object_with_properties(&[("body", Value::str("stale"))])
        .expect("stale response object");
    core.insert_event_listener(
        stale_target,
        "end",
        EventListenerRecord {
            listener: Value::BuiltinFunction(BuiltinFunction::new_kind(
                BuiltinFunctionKind::ArrayIsArray,
            )),
            once: false,
        },
        false,
    )
    .expect("stale response listener");
    core.schedule_stream_emission(stale_target, StreamEventPhase::Data, Label::Public)
        .expect("stale response emission");
    let registration = *core
        .pending_stream_emissions
        .keys()
        .next()
        .expect("stale response registration");

    core.reset_execution_state_from_seed(&seed)
        .expect("seed reset cancels stale stream emission");
    assert!(core.pending_stream_emissions.is_empty());
    assert!(core.event_loop.cancel_registration(registration).is_none());
    assert!(!core.event_listeners.contains_key(&stale_target));
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );

    let reused = core
        .alloc_object_with_properties(&[("body", Value::str("replacement"))])
        .expect("replacement response object");
    assert_eq!(reused, stale_target, "seed reset must reuse the ObjectId");
    core.insert_event_listener(
        reused,
        "end",
        EventListenerRecord {
            listener: Value::BuiltinFunction(BuiltinFunction::new_kind(
                BuiltinFunctionKind::ArrayIsArray,
            )),
            once: false,
        },
        false,
    )
    .expect("replacement response listener");

    core.run_event_loop_until_idle();

    assert_eq!(core.event_listener_records_for(reused, "end").len(), 1);
    assert!(core.pending_stream_emissions.is_empty());
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn stream_emission_drives_data_then_end_and_clears_listeners_bd_3894s() {
    let mut core = test_interpreter();
    let obj_id = core.mutate_heap(|h| {
        let id = ObjectId(h.len() as u32);
        let mut obj = HeapObject::new();
        obj.brand = Some(Box::new(JsString::from("IncomingMessage")));
        obj.properties
            .insert("body".to_string(), Value::str("chunk-bytes"));
        h.push(obj);
        id
    });
    core.register_event_listener(obj_id, "data", 11);
    core.register_event_listener(obj_id, "data", 12);
    core.register_event_listener(obj_id, "end", 13);

    core.schedule_stream_emission(obj_id, StreamEventPhase::Data, Label::Public)
        .expect("stream emission scheduling fits test budget");
    assert_eq!(
        core.pending_stream_emissions.len(),
        1,
        "the 'data' emission is scheduled as one IoCompletion macrotask"
    );

    core.run_event_loop_until_idle();

    assert!(
        core.pending_stream_emissions.is_empty(),
        "both the 'data' and the chained 'end' emission drained"
    );
    assert!(
        !core.event_listeners.contains_key(&obj_id),
        "the 'end' phase released the object's listener table"
    );
}

/// bd-3894s slice (2d): a failed egress (here: no host-I/O provider, so the seam
/// yields `undefined`) fires the request's `req.on('error', …)` listeners with an
/// Error-shaped value carrying `code`, and fires no response/data/end. `.end()`
/// evaluates to `undefined`.
#[test]
fn client_request_on_error_fires_on_failed_egress_bd_3894s() {
    let mut core = test_interpreter();
    core.config
        .granted_capabilities
        .insert(RuntimeCapability::NetworkEgress);
    let module = test_module_with_functions(vec![], vec![]);

    // http.request('http://127.0.0.1:0/') — build the writable request (no egress).
    core.mutate_registers(|r| {
        if r.is_empty() {
            r.resize(1, Value::Undefined);
        }
        r[0] = Value::str("http://127.0.0.1:0/");
    });
    let req = core
        .dispatch_client_request_create(RegRange { start: 0, count: 1 })
        .expect("client request creation");
    let Value::Object(req_id) = req else {
        panic!("expected a ClientRequest object");
    };

    // req.on('error', closure#9)
    let on = BuiltinFunction::emitter_on();
    core.mutate_registers(|r| {
        if r.len() < 2 {
            r.resize(2, Value::Undefined);
        }
        r[0] = Value::str("error");
        r[1] = Value::Closure(9);
    });
    core.dispatch_builtin_function(
        &module,
        &on,
        RegRange { start: 0, count: 2 },
        Some(Value::Object(req_id)),
        None,
    )
    .expect("req.on('error')");

    // req.end() — no host-I/O provider is set, so the egress seam returns
    // undefined (the failed-egress path) and the 'error' event fires.
    let end = BuiltinFunction::client_request_end();
    let result = core
        .dispatch_builtin_function(
            &module,
            &end,
            RegRange { start: 0, count: 0 },
            Some(Value::Object(req_id)),
            None,
        )
        .expect("req.end with a failed egress");
    assert_eq!(
        result,
        Value::Undefined,
        "a failed egress evaluates .end() to undefined (no response is returned)"
    );

    assert_eq!(
        core.pending_http_tasks.len(),
        1,
        "the logical 'error' event is scheduled as a pending IoCompletion macrotask"
    );
    let task = core
        .pending_http_tasks
        .values()
        .next()
        .expect("a scheduled error event");
    let PendingHttpTask::EmitLegacyEvent {
        target,
        event,
        arguments: args,
        leading_callback,
        label,
    } = task
    else {
        panic!("expected a deferred error event, got {task:?}");
    };
    assert_eq!(*target, req_id);
    assert_eq!(event, "error");
    assert_eq!(*leading_callback, None);
    assert_eq!(label, &Label::Internal);
    assert_eq!(
        args.len(),
        1,
        "the 'error' listener receives a single Error arg"
    );
    let Value::Object(err_id) = &args[0] else {
        panic!("the error arg must be an Error object, got {:?}", args[0]);
    };
    let err = core.heap.get(err_id.0 as usize).expect("error object");
    assert_eq!(
        err.properties.get("code"),
        Some(&Value::str("ERR_NETWORK")),
        "the Error carries a code the listener can branch on"
    );
    assert!(
        core.pending_stream_emissions.is_empty(),
        "a failed egress drives no readable-stream 'data'/'end'"
    );
}

/// bd-3894s slice (2d): `http.request(url)` with a `req.on('response', …)`
/// listener (and no `http.request(url, opts, cb)` callback) delivers the parsed
/// response to the listener on the next event-loop turn and `.end()` evaluates to
/// `undefined`; the readable stream is scheduled to drive afterward.
#[test]
fn client_request_on_response_listener_receives_response_bd_3894s() {
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
        "frankenengine_interp_req_on_resp_{}",
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
    let module = test_module_with_functions(vec![], vec![]);

    // const req = http.request(url) — writable request, no callback, no egress.
    let url = format!("http://{addr}/");
    core.mutate_registers(|r| {
        if r.is_empty() {
            r.resize(1, Value::Undefined);
        }
        r[0] = Value::Str(JsString::from(url.as_str()));
    });
    let req = core
        .dispatch_client_request_create(RegRange { start: 0, count: 1 })
        .expect("client request creation");
    let Value::Object(req_id) = req else {
        panic!("expected a ClientRequest object");
    };

    // req.on('response', closure#5)
    let on = BuiltinFunction::emitter_on();
    core.mutate_registers(|r| {
        if r.len() < 2 {
            r.resize(2, Value::Undefined);
        }
        r[0] = Value::str("response");
        r[1] = Value::Closure(5);
    });
    core.dispatch_builtin_function(
        &module,
        &on,
        RegRange { start: 0, count: 2 },
        Some(Value::Object(req_id)),
        None,
    )
    .expect("req.on('response')");

    // req.end() — perform the deferred egress and schedule the 'response' delivery.
    let end = BuiltinFunction::client_request_end();
    let result = core
        .dispatch_builtin_function(
            &module,
            &end,
            RegRange { start: 0, count: 0 },
            Some(Value::Object(req_id)),
            None,
        )
        .expect("req.end");
    assert_eq!(
        result,
        Value::Undefined,
        "a req.on('response') consumer makes .end() async (returns undefined)"
    );

    // The 'response' listener was scheduled with the parsed response object.
    assert_eq!(
        core.pending_http_tasks.len(),
        1,
        "the logical 'response' event is scheduled as a pending IoCompletion macrotask"
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
    assert_eq!(*leading_callback, None);
    assert_eq!(label, &Label::Internal);
    let Value::Object(resp_id) = &args[0] else {
        panic!(
            "the listener arg must be the response object, got {:?}",
            args[0]
        );
    };
    let resp = core.heap.get(resp_id.0 as usize).expect("response object");
    assert_eq!(resp.properties.get("status"), Some(&Value::Int(200)));
    assert_eq!(resp.properties.get("body"), Some(&Value::str("ok")));
    // The readable stream is scheduled to drive 'data'/'end' after the delivery.
    assert_eq!(
        core.pending_stream_emissions.len(),
        1,
        "the IncomingMessage readable stream is scheduled to emit after delivery"
    );

    let _ = server.join().expect("server thread");
    let _ = std::fs::remove_dir_all(&root);
}

/// bd-3894s slice (4): `build_net_response_value` parses raw HTTP/1.1 response
/// bytes into the JS response object — status code, reason phrase, ok flag,
/// lower-cased headers, and the decoded body.
#[test]
fn build_net_response_value_parses_status_headers_body_bd_3894s() {
    let mut core = test_interpreter();
    let raw = b"HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nX-Trace: abc\r\n\r\nmissing";
    let Value::Object(id) = core
        .build_net_response_value(raw, "GET")
        .expect("parse response")
    else {
        panic!("expected a response object");
    };
    let response = core.heap.get(id.0 as usize).expect("response object");
    assert_eq!(response.properties.get("status"), Some(&Value::Int(404)));
    assert_eq!(
        response.properties.get("statusText"),
        Some(&Value::str("Not Found")),
        "a multi-word reason phrase is preserved intact"
    );
    assert_eq!(
        response.properties.get("ok"),
        Some(&Value::Bool(false)),
        "a 4xx status is not ok"
    );
    assert_eq!(
        response.properties.get("body"),
        Some(&Value::str("missing"))
    );
    let Some(Value::Object(headers_id)) = response.properties.get("headers") else {
        panic!("response carries a headers object");
    };
    let headers = core
        .heap
        .get(headers_id.0 as usize)
        .expect("headers object");
    assert_eq!(
        headers.properties.get("content-type"),
        Some(&Value::str("text/plain")),
        "header names are lower-cased"
    );
    assert_eq!(headers.properties.get("x-trace"), Some(&Value::str("abc")));
}

/// Empty or malformed recorded/provider outcomes must not fabricate a
/// response object. Failure leaves guest heap state unchanged.
#[test]
fn build_net_response_value_handles_empty_reply_bd_3894s() {
    let mut core = test_interpreter();
    let before = core.heap.len();
    assert_eq!(
        core.build_net_response_value(b"", "GET").unwrap(),
        Value::Undefined
    );
    assert_eq!(core.heap.len(), before);
}

#[test]
fn build_net_response_value_decodes_chunks_after_final_status() {
    let raw = b"HTTP/1.1 103 Early Hints\r\nX-Source: interim\r\n\r\nHTTP/1.1 201 Created\r\nTransfer-Encoding: chunked\r\nX-Source: final\r\n\r\n3\r\none\r\n3\r\ntwo\r\n0\r\nX-Source: trailer\r\n\r\n";
    let mut core = test_interpreter();
    let Value::Object(id) = core.build_net_response_value(raw, "GET").unwrap() else {
        panic!("complete chunked reply must produce a response");
    };
    let response = &core.heap[id.0 as usize];
    assert_eq!(response.properties.get("status"), Some(&Value::Int(201)));
    assert_eq!(response.properties.get("body"), Some(&Value::str("onetwo")));
    assert_eq!(response.properties.get("ok"), Some(&Value::Bool(true)));
    let Some(Value::Object(headers)) = response.properties.get("headers") else {
        panic!("response must contain headers");
    };
    assert_eq!(
        core.heap[headers.0 as usize].properties.get("x-source"),
        Some(&Value::str("final"))
    );
}

#[test]
fn build_net_response_value_decodes_split_utf8_only_after_dechunking() {
    let raw =
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\n\xc3\r\n1\r\n\xa9\r\n0\r\n\r\n";
    let mut core = test_interpreter();
    let Value::Object(id) = core.build_net_response_value(raw, "GET").unwrap() else {
        panic!("complete reply must produce a response");
    };
    assert_eq!(
        core.heap[id.0 as usize].properties.get("body"),
        Some(&Value::str("é"))
    );
}

#[test]
fn build_net_response_value_preserves_head_method_semantics() {
    let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 999999\r\n\r\n";
    let mut core = test_interpreter();
    let Value::Object(id) = core.build_net_response_value(raw, "HEAD").unwrap() else {
        panic!("HEAD reply must produce a bodyless response");
    };
    assert_eq!(
        core.heap[id.0 as usize].properties.get("body"),
        Some(&Value::str(""))
    );
    let before = core.heap.len();
    assert_eq!(
        core.build_net_response_value(raw, "GET").unwrap(),
        Value::Undefined
    );
    assert_eq!(core.heap.len(), before);
}

#[test]
fn build_net_response_value_rejects_malformed_recorded_outcomes_before_allocation() {
    let mut core = test_interpreter();
    for raw in [
        &b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nshort"[..],
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nbody\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\nextra",
    ] {
        let before = core.heap.len();
        assert_eq!(
            core.build_net_response_value(raw, "GET").unwrap(),
            Value::Undefined
        );
        assert_eq!(core.heap.len(), before);
    }
}

/// bd-rul7k: `decode_fs_read_result` honors the dependency-free single-arg
/// Node `BufferEncoding` values (string output, case-insensitive) and falls
/// back to a Buffer for the no-encoding and unknown-encoding paths. Direct
/// unit coverage of the encoding matrix (utf8/utf16le/latin1/ascii/hex).
#[test]
fn decode_fs_read_result_encoding_matrix_bd_rul7k() {
    let mut core = test_interpreter();
    let bytes = b"real effect bytes";

    // Recognized character encodings -> decoded JS strings.
    assert_eq!(
        core.decode_fs_read_result(bytes, Some("utf8")).unwrap(),
        Value::Str(JsString::from("real effect bytes"))
    );
    assert_eq!(
        core.decode_fs_read_result(bytes, Some("UTF-8")).unwrap(),
        Value::Str(JsString::from("real effect bytes")),
        "encoding match is case-insensitive"
    );
    assert_eq!(
        core.decode_fs_read_result(bytes, Some("latin1")).unwrap(),
        Value::Str(JsString::from("real effect bytes"))
    );
    assert_eq!(
        core.decode_fs_read_result(bytes, Some("ascii")).unwrap(),
        Value::Str(JsString::from("real effect bytes"))
    );
    assert_eq!(
        core.decode_fs_read_result(bytes, Some("hex")).unwrap(),
        Value::Str(JsString::from(hex::encode(bytes)))
    );

    // utf16le round-trips an even-length little-endian u16 byte stream.
    let utf16_bytes: Vec<u8> = "hi".encode_utf16().flat_map(u16::to_le_bytes).collect();
    assert_eq!(
        core.decode_fs_read_result(&utf16_bytes, Some("utf16le"))
            .unwrap(),
        Value::Str(JsString::from("hi"))
    );

    // base64/base64url ENCODE the raw bytes (like hex), not decode. The two
    // differ only in alphabet + padding: `base64` is standard-with-padding,
    // `base64url` is URL-safe-without-padding. Use bytes whose standard
    // base64 contains both a `+`/`/` glyph and trailing padding so the
    // alphabet and padding differences are actually exercised.
    let b64_bytes = [0xfbu8, 0xff, 0xbf]; // standard "+/+/"-class glyphs
    assert_eq!(
        core.decode_fs_read_result(&b64_bytes, Some("base64"))
            .unwrap(),
        Value::Str(JsString::from("+/+/")),
        "base64: standard alphabet with padding"
    );
    assert_eq!(
        core.decode_fs_read_result(&b64_bytes, Some("base64url"))
            .unwrap(),
        Value::Str(JsString::from("-_-_")),
        "base64url: URL-safe alphabet, no padding"
    );
    // A single byte forces padding under standard base64; base64url omits it.
    assert_eq!(
        core.decode_fs_read_result(b"f", Some("base64")).unwrap(),
        Value::Str(JsString::from("Zg==")),
        "base64 pads to a 4-char quantum"
    );
    assert_eq!(
        core.decode_fs_read_result(b"f", Some("BASE64URL")).unwrap(),
        Value::Str(JsString::from("Zg")),
        "base64url match is case-insensitive and unpadded"
    );

    // No encoding -> Buffer (Uint8Array-backed); unknown encoding also falls back.
    assert!(matches!(
        core.decode_fs_read_result(bytes, None).unwrap(),
        Value::Object(_)
    ));
    assert!(
        matches!(
            core.decode_fs_read_result(bytes, Some("totally-bogus"))
                .unwrap(),
            Value::Object(_)
        ),
        "unknown encoding falls back to Buffer"
    );
}

/// bd-fqlfw.3.5.5 (E3.T5d): an armed state capture at tick 0 observes
/// pre-set register values and labels at the first instruction boundary.
#[test]
fn state_capture_at_tick_zero_observes_registers_and_labels() {
    let mut module = test_module_with_functions(vec![Ir3Instruction::Halt], vec![]);
    module.header.source_label = "capture-t0".to_string();

    let mut core = test_interpreter();
    core.mutate_registers(|r| {
        r[0] = Value::Int(41);
    });
    core.set_register_label(0, crate::ifc_artifacts::Label::Secret)
        .expect("register label should be settable");
    core.arm_state_capture_at_tick(0);
    core.execute(&module)
        .expect("trivial module should execute");

    let captured = core
        .take_captured_state()
        .expect("tick-0 capture should land on the first boundary");
    assert_eq!(captured.tick, 0);
    let reg0 = captured
        .registers
        .iter()
        .find(|entry| entry.register == 0)
        .expect("register 0 should be captured (non-Undefined)");
    assert_eq!(reg0.value, Value::Int(41));
    assert_eq!(reg0.label, crate::ifc_artifacts::Label::Secret);
}

/// bd-fqlfw.3.5.5: a capture armed beyond the final nondeterminism tick
/// never fires; the caller fails closed on the missing observation.
#[test]
fn state_capture_beyond_final_tick_stays_uncaptured() {
    let module = test_module_with_functions(vec![Ir3Instruction::Halt], vec![]);
    let mut core = test_interpreter();
    core.arm_state_capture_at_tick(1_000_000);
    core.execute(&module)
        .expect("trivial module should execute");
    assert!(
        core.take_captured_state().is_none(),
        "capture beyond the trace range must stay uncaptured"
    );
}

/// bd-fqlfw.3.5.5: identical module + config + tick produce identical
/// observations across fresh cores (the debugger's determinism contract).
#[test]
fn state_capture_is_deterministic_across_fresh_cores() {
    let capture = || {
        let mut module = test_module_with_functions(
            vec![
                Ir3Instruction::LoadInt { dst: 1, value: 7 },
                Ir3Instruction::Halt,
            ],
            vec![],
        );
        module.header.source_label = "capture-det".to_string();
        let mut core = test_interpreter();
        core.mutate_registers(|r| {
            r[0] = Value::Int(3);
        });
        core.arm_state_capture_at_tick(0);
        core.execute(&module).expect("module should execute");
        core.take_captured_state()
            .expect("tick-0 capture should land")
    };
    assert_eq!(capture(), capture(), "captures must be byte-identical");
}

/// bd-fqlfw.3.5.5: heap-object labels in a capture are the join of the
/// labels of registers from which the object is transitively reachable;
/// unreferenced objects stay Public.
#[test]
fn state_capture_projects_register_labels_onto_reachable_heap() {
    let module = test_module_with_functions(vec![Ir3Instruction::Halt], vec![]);
    let mut core = test_interpreter();
    let secret_obj = core
        .alloc_object_with_properties(&[("data", Value::Int(9))])
        .expect("allocation should succeed");
    let public_obj = core
        .alloc_object_with_properties(&[("data", Value::Int(1))])
        .expect("allocation should succeed");
    core.mutate_registers(|r| {
        r[0] = Value::Object(secret_obj);
    });
    core.set_register_label(0, crate::ifc_artifacts::Label::Secret)
        .expect("register label should be settable");
    core.arm_state_capture_at_tick(0);
    core.execute(&module).expect("module should execute");

    let captured = core
        .take_captured_state()
        .expect("tick-0 capture should land");
    let find = |id: ObjectId| {
        captured
            .heap
            .iter()
            .find(|entry| entry.object_id == id)
            .expect("captured heap should include the object")
    };
    assert_eq!(
        find(secret_obj).label,
        crate::ifc_artifacts::Label::Secret,
        "object referenced from a Secret register must project Secret"
    );
    assert_eq!(
        find(public_obj).label,
        crate::ifc_artifacts::Label::Public,
        "object unreachable from any register stays Public"
    );
}

/// bd-0zybl: reading a property off a Secret-labeled object must taint the
/// destination register at least Secret. Before the fix, `GetProperty`
/// wrote only the value via `write_reg` and never touched the dst's label,
/// so a Secret object's field laundered to a stale `Public` dst — an IFC
/// confinement bypass (a subsequent egress hostcall would see Public and be
/// permitted). Sibling of bd-n2mjy (the HostCall-arg variant).
#[test]
fn get_property_joins_object_label_onto_dst() {
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

    let mut core = test_interpreter();
    let secret_obj = core
        .alloc_object_with_properties(&[("data", Value::Int(99))])
        .expect("test object allocation should succeed");
    core.mutate_registers(|r| {
        r[0] = Value::Object(secret_obj);
    });
    core.set_register_label(0, crate::ifc_artifacts::Label::Secret)
        .expect("object label should be settable");
    // Seed dst strictly below Secret to prove the read raises it. If the
    // join were a no-op the dst label would stay Public (the bd-0zybl bug).
    core.set_register_label(2, crate::ifc_artifacts::Label::Public)
        .expect("dst label should be settable");

    core.execute(&module)
        .expect("property read off a secret object should execute");

    assert_eq!(
        core.get_register_label(2)
            .expect("dst register label should exist"),
        &crate::ifc_artifacts::Label::Secret,
        "GetProperty dst must inherit (join) the source object's label"
    );
}

/// IFC: `new Builtin(secret)` must taint the constructed value at least
/// Secret. The `Construct` builtin arm wrote the result via `write_reg`
/// but — unlike the byte-identical `Call` builtin arm — never joined the
/// argument labels onto the dst, so a constructed value laundered Secret
/// args to a stale Public dst. Constructor sibling of bd-n2mjy / bd-ooaka.1.
#[test]
fn construct_builtin_joins_arg_label_onto_dst() {
    let module = test_module_with_functions(
        vec![
            Ir3Instruction::Construct {
                callee: 3,
                args: RegRange { start: 0, count: 1 },
                dst: 2,
            },
            Ir3Instruction::Halt,
        ],
        vec![],
    );

    let mut core = test_interpreter();
    core.mutate_registers(|r| {
        r[0] = Value::str("return 42;");
        // `Function` is the one first-class builtin with [[Construct]].
        // The result is a generated callable artifact, which lets this
        // test continue to exercise the constructible-builtin label join.
        r[3] = Value::BuiltinFunction(BuiltinFunction::function_constructor());
    });
    core.set_register_label(0, crate::ifc_artifacts::Label::Secret)
        .expect("arg label should be settable");
    // Seed dst strictly below Secret to prove the construct raises it.
    core.set_register_label(2, crate::ifc_artifacts::Label::Public)
        .expect("dst label should be settable");

    core.execute(&module)
        .expect("constructing a builtin should execute");

    assert_eq!(
        core.get_register_label(2)
            .expect("dst register label should exist"),
        &crate::ifc_artifacts::Label::Secret,
        "Construct-builtin dst must inherit (join) the args' labels"
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
            Ir3FunctionDesc {
                entry: 3,
                arity: 0,
                frame_size: 2,
                name: Some("Child".to_string()),
                is_generator: false,
                rest_param_index: None,
            },
            Ir3FunctionDesc {
                entry: 6,
                arity: 0,
                frame_size: 1,
                name: Some("Parent".to_string()),
                is_generator: false,
                rest_param_index: None,
            },
        ],
    );
    let mut core = test_interpreter();
    core.write_reg_with_label(0, Value::Function(0), Label::Public)
        .expect("child constructor should be writable");
    core.write_reg_with_label(1, Value::Function(1), Label::Secret)
        .expect("parent constructor should be writable");

    core.execute(&module)
        .expect("derived super construction should execute");

    assert!(matches!(core.read_reg(2), Ok(Value::Object(_))));
    assert_eq!(
        core.get_register_label(2).expect("derived result label"),
        &Label::Secret,
        "the private parent-constructor label must reach initialized derived this"
    );
}

#[test]
fn default_derived_builtin_chain_accumulates_parent_label_bd_ppfz7() {
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
        ],
        vec![
            Ir3FunctionDesc {
                entry: 4,
                arity: 0,
                frame_size: 1,
                name: Some("Leaf".to_string()),
                is_generator: false,
                rest_param_index: None,
            },
            Ir3FunctionDesc {
                entry: 6,
                arity: 0,
                frame_size: 1,
                name: Some("Middle".to_string()),
                is_generator: false,
                rest_param_index: None,
            },
        ],
    );
    let mut core = test_interpreter();
    core.write_reg_with_label(0, Value::Function(0), Label::Public)
        .expect("leaf constructor should be writable");
    core.write_reg_with_label(1, Value::Function(1), Label::Secret)
        .expect("intermediate constructor should be writable");
    core.write_reg_with_label(2, Value::str("Array"), Label::Public)
        .expect("builtin parent should be writable");

    core.execute(&module)
        .expect("default-derived builtin chain should execute");

    assert!(matches!(core.read_reg(3), Ok(Value::Object(_))));
    assert_eq!(
        core.get_register_label(3)
            .expect("default-derived result label"),
        &Label::Secret,
        "forwarding into a builtin must preserve intermediate constructor provenance"
    );
}

/// IFC: slicing a Secret array must taint the resulting array at least
/// Secret. The dedicated `ArraySlice` opcode built a fresh array from the
/// source's elements but never propagated the source label, so
/// `secretArr.slice(0)` laundered to a Public dst. `GetProperty` joins the
/// container label for exactly this reason; the slice is analogous.
#[test]
fn lazy_array_iterator_state_does_not_expand_sparse_length() {
    let mut core = test_interpreter();
    let array = core.alloc_array_from_values(&[]).expect("array");
    core.set_object_property(array, "length".to_string(), Value::Int(i64::from(u32::MAX)))
        .expect("sparse length");
    let objects = core.heap.len();
    let iterator = core
        .array_prototype_iterator_for_receiver(Value::Object(array), "keys")
        .expect("lazy keys");
    let Value::Iterator(handle) = iterator else {
        panic!("iterator handle")
    };
    let RuntimeIteratorState::ForOf(state) = core.iterator_state_mut(handle).expect("state") else {
        panic!("for-of state")
    };
    assert!(state.values.is_empty(), "no eager element snapshot");
    assert!(state.array.is_some());
    assert_eq!(core.heap.len(), objects);
    assert_eq!(
        core.advance_for_of_iterator(None, Value::Iterator(handle))
            .expect("first"),
        Some(Value::Int(0))
    );
    assert_eq!(
        core.advance_for_of_iterator(None, Value::Iterator(handle))
            .expect("second"),
        Some(Value::Int(1))
    );
    assert_eq!(core.heap.len(), objects);
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn lazy_array_entries_allocate_only_when_advanced() {
    let mut core = test_interpreter();
    let array = core
        .alloc_array_from_values(&[Value::Int(7)])
        .expect("array");
    let objects = core.heap.len();
    let iterator = core
        .array_prototype_iterator_for_receiver(Value::Object(array), "entries")
        .expect("entries");
    assert_eq!(
        core.heap.len(),
        objects,
        "creation does not allocate entry pairs"
    );
    let Some(Value::Object(pair)) = core.advance_for_of_iterator(None, iterator).expect("next")
    else {
        panic!("entry pair")
    };
    assert_eq!(core.heap.len(), objects + 1);
    assert_eq!(
        core.heap[pair.0 as usize].properties.get("0"),
        Some(&Value::Int(0))
    );
    assert_eq!(
        core.heap[pair.0 as usize].properties.get("1"),
        Some(&Value::Int(7))
    );
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn array_suffix_does_not_allocate_the_skipped_sparse_prefix() {
    let mut core = test_interpreter();
    let array = core.alloc_array_from_values(&[]).expect("array");
    let last = u32::MAX - 1;
    core.set_object_property(array, last.to_string(), Value::Int(42))
        .expect("last sparse element");
    core.set_object_property(array, "length".to_string(), Value::Int(i64::from(u32::MAX)))
        .expect("length");
    let Value::Object(result) = core
        .slice_array_suffix(None, Value::Object(array), Value::Int(i64::from(last)))
        .expect("one-element suffix")
    else {
        panic!("suffix array")
    };
    assert_eq!(
        core.heap[result.0 as usize].properties.get("length"),
        Some(&Value::Int(1))
    );
    assert_eq!(
        core.heap[result.0 as usize].properties.get("0"),
        Some(&Value::Int(42))
    );
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn array_suffix_internal_loop_obeys_instruction_budget() {
    let mut core = test_interpreter();
    let array = core.alloc_array_from_values(&[]).expect("array");
    core.set_object_property(array, "length".to_string(), Value::Int(1_000_000))
        .expect("sparse length");
    core.config.instruction_budget = 3;
    assert!(matches!(
        core.slice_array_suffix(None, Value::Object(array), Value::Int(0)),
        Err(InterpreterError::BudgetExhausted {
            executed: 3,
            budget: 3
        })
    ));
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn array_slice_propagates_source_array_label_onto_dst() {
    let module = test_module_with_functions(
        vec![
            Ir3Instruction::ArraySlice {
                array: 0,
                start: 1,
                dst: 2,
            },
            Ir3Instruction::Halt,
        ],
        vec![],
    );

    let mut core = test_interpreter();
    let arr = core
        .alloc_array_from_values(&[Value::Int(1), Value::Int(2), Value::Int(3)])
        .expect("test array allocation should succeed");
    core.mutate_registers(|r| {
        r[0] = Value::Object(arr);
        r[1] = Value::Int(0);
    });
    core.set_register_label(0, crate::ifc_artifacts::Label::Secret)
        .expect("array label should be settable");
    // Seed dst strictly below Secret to prove the slice raises it.
    core.set_register_label(2, crate::ifc_artifacts::Label::Public)
        .expect("dst label should be settable");

    core.execute(&module)
        .expect("slicing a secret array should execute");

    assert_eq!(
        core.get_register_label(2)
            .expect("dst register label should exist"),
        &crate::ifc_artifacts::Label::Secret,
        "ArraySlice dst must inherit (join) the source array's label"
    );
}

/// bd-0zybl: the label propagation is a JOIN, not a bare overwrite — a dst
/// already carrying higher taint than the object must not be lowered by a
/// property read (over-taint is safe; under-taint is the security bug).
#[test]
fn get_property_join_preserves_higher_prior_dst_label() {
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

    let mut core = test_interpreter();
    let public_obj = core
        .alloc_object_with_properties(&[("data", Value::Int(1))])
        .expect("test object allocation should succeed");
    core.mutate_registers(|r| {
        r[0] = Value::Object(public_obj);
    });
    core.set_register_label(0, crate::ifc_artifacts::Label::Public)
        .expect("object label should be settable");
    core.set_register_label(2, crate::ifc_artifacts::Label::Secret)
        .expect("dst label should be settable");

    core.execute(&module)
        .expect("property read off a public object should execute");

    assert_eq!(
        core.get_register_label(2)
            .expect("dst register label should exist"),
        &crate::ifc_artifacts::Label::Secret,
        "GetProperty join must not lower a dst that already holds higher taint"
    );
}

#[test]
fn materialized_constructor_reads_preserve_actual_prototype_labels() {
    for key in [
        RuntimePropertyKey::String(JsString::from("inherited")),
        RuntimePropertyKey::Symbol(WellKnownSymbol::ToStringTag.id()),
    ] {
        for (inherited_label, shadowed_label) in [
            (Label::Secret, Label::Public),
            (Label::Public, Label::Secret),
        ] {
            let module = test_module_with_functions(
                vec![
                    Ir3Instruction::GetProperty {
                        obj: 0,
                        key: 1,
                        dst: 2,
                    },
                    Ir3Instruction::Halt,
                ],
                vec![],
            );
            let mut core = test_interpreter();
            let constructor =
                Value::BuiltinFunction(BuiltinFunction::standard_constructor("Object"));
            core.ensure_function_own_property_object(&module, &constructor)
                .expect("constructor storage should allocate")
                .expect("standard constructor has property storage");
            let function_prototype = core
                .ensure_builtin_prototype("Function")
                .expect("Function.prototype should allocate");
            let object_prototype = core
                .ensure_builtin_prototype("Object")
                .expect("Object.prototype should allocate");
            core.set_object_runtime_property(object_prototype, key.clone(), Value::Int(7))
                .expect("shadowed property should be writable");
            core.set_own_runtime_property_label(object_prototype, &key, &shadowed_label)
                .expect("shadowed property label should be settable");
            core.set_object_runtime_property(function_prototype, key.clone(), Value::Int(41))
                .expect("inherited property should be writable");
            core.set_own_runtime_property_label(function_prototype, &key, &inherited_label)
                .expect("inherited property label should be settable");
            core.write_reg_with_label(0, constructor, Label::Public)
                .expect("constructor register should fit");
            core.write_reg_with_label(1, key.value(), Label::Public)
                .expect("key register should fit");
            core.write_reg_with_label(2, Value::Undefined, Label::Public)
                .expect("destination register should fit");

            core.execute(&module)
                .expect("inherited constructor property read should execute");

            assert_eq!(core.read_reg(2).unwrap(), Value::Int(41));
            assert_eq!(
                core.get_register_label(2).unwrap(),
                &inherited_label,
                "the resolved Function.prototype property supplies the label, including a Public shadow"
            );
        }
    }
}

#[test]
fn ordinary_own_property_fast_path_matches_forced_fallback_trace_and_ifc() {
    let run = |force_fallback: bool, with_prototype: bool| {
        let module = test_module_with_functions(
            vec![
                Ir3Instruction::GetProperty {
                    obj: 0,
                    key: 1,
                    dst: 2,
                },
                Ir3Instruction::Halt,
            ],
            vec![],
        );
        let mut core = test_interpreter();
        let object = core
            .alloc_object_with_properties(&[("data", Value::Int(41))])
            .expect("ordinary object should allocate");
        let empty_prototype = core
            .alloc_object_with_prototype(None)
            .expect("empty prototype should allocate");
        if with_prototype {
            let index = object.0 as usize;
            core.mutate_heap(|heap| {
                heap[index].prototype = Some(empty_prototype);
            });
        }
        FORCE_GENERIC_OWN_PROPERTY_READS.with(|force| force.set(force_fallback));
        core.set_own_property_label(object, "data", &Label::Secret)
            .expect("property label should be settable");
        core.mutate_registers(|registers| {
            registers[0] = Value::Object(object);
            registers[1] = Value::str("data");
            registers[2] = Value::Undefined;
        });
        core.set_register_label(0, Label::Public)
            .expect("object label should be settable");
        core.set_register_label(1, Label::Public)
            .expect("key label should be settable");
        core.set_register_label(2, Label::Confidential)
            .expect("destination label should be settable");

        assert_eq!(
            core.ordinary_own_property_read_fast_path_eligible(
                object,
                &RuntimePropertyKey::String(JsString::from("data")),
            ),
            !force_fallback,
            "the test switch forces the generic path; a prototype does not (bd-9vouw.504)"
        );
        let result = core
            .execute(&module)
            .expect("ordinary own-property read should execute");
        FORCE_GENERIC_OWN_PROPERTY_READS.with(|force| force.set(false));
        assert_eq!(
            core.nondeterminism_trace_ref(),
            &result.nondeterminism_trace,
            "public direct-core execution must retain the finalised trace after handoff"
        );

        (
            core.read_reg(2).expect("destination value should exist"),
            core.get_register_label(2)
                .expect("destination label should exist")
                .clone(),
            core.nondeterminism_trace_ref().clone(),
            core.instructions_executed,
        )
    };

    for with_prototype in [false, true] {
        let fast = run(false, with_prototype);
        let fallback = run(true, with_prototype);
        assert_eq!(fast.0, Value::Int(41));
        assert_eq!(fast.1, Label::Secret);
        assert_eq!(
            fast, fallback,
            "fast and generic paths must preserve the read outcome, IFC label, trace, and \
                 instruction count (prototype: {with_prototype})"
        );
    }
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

    let mut core = test_interpreter();
    let array = core
        .alloc_array_with_prototype(None)
        .expect("array should allocate");
    core.write_reg_with_label(0, Value::Object(array), Label::Public)
        .expect("array register should fit");
    core.write_reg_with_label(1, Value::str("classified"), Label::Secret)
        .expect("Secret element register should fit");

    core.execute(&module).expect("ArrayPush followed by read");

    assert_eq!(core.read_reg(3).unwrap(), Value::str("classified"));
    assert_eq!(core.get_register_label(3).unwrap(), &Label::Secret);
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn array_mapping_preserves_callback_element_and_aggregate_labels_bd_9vouw_110() {
    let module = test_module_with_functions(
        vec![Ir3Instruction::Halt, Ir3Instruction::Return { value: 0 }],
        vec![Ir3FunctionDesc {
            entry: 1,
            arity: 3,
            frame_size: 3,
            name: Some("identity".to_string()),
            is_generator: false,
            rest_param_index: None,
        }],
    );
    for kind in [
        BuiltinFunctionKind::ArrayMap,
        BuiltinFunctionKind::ArrayFlatMap,
    ] {
        for first_label in [Label::Public, Label::Secret] {
            let mut core = test_interpreter();
            let array = core
                .alloc_array_from_values(&[Value::str("first"), Value::str("last")])
                .expect("source array");
            core.set_own_property_label(array, "0", &first_label)
                .expect("source label");
            core.write_reg(0, Value::Function(0))
                .expect("callback register");
            let mapped = core
                .dispatch_builtin_function(
                    &module,
                    &BuiltinFunction::new_kind(kind),
                    RegRange { start: 0, count: 1 },
                    Some(Value::Object(array)),
                    None,
                )
                .expect("mapping should execute");
            let Value::Object(mapped) = mapped else {
                panic!("{kind:?} must return an array");
            };
            assert_eq!(
                core.heap[mapped.0 as usize].properties.get("0"),
                Some(&Value::str("first")),
                "{kind:?}"
            );
            assert_eq!(
                core.own_property_label(mapped, "0"),
                first_label,
                "{kind:?}: callback result label must survive storage"
            );
            let later_label = if kind == BuiltinFunctionKind::ArrayFlatMap {
                first_label.clone()
            } else {
                Label::Public
            };
            assert_eq!(
                core.own_property_label(mapped, "1"),
                later_label,
                "{kind:?}: flatMap positions retain earlier callback provenance"
            );
            assert_eq!(
                core.take_pending_hostcall_result_label()
                    .unwrap_or(Label::Public),
                first_label,
                "{kind:?}: the later Public callback must not erase earlier provenance"
            );
            assert_eq!(
                core.estimated_memory_bytes(),
                core.recompute_estimated_memory_bytes(),
                "{kind:?}: label storage must remain accounted"
            );
        }
    }
}

fn array_shape_species_module() -> Ir3Module {
    let mut module = test_module_with_functions(
        vec![
            Ir3Instruction::Halt,
            Ir3Instruction::Return { value: 0 },
            Ir3Instruction::LoadScoped {
                dst: 1,
                name_pool_index: 0,
            },
            Ir3Instruction::Return { value: 1 },
            Ir3Instruction::LoadBool {
                dst: 3,
                value: false,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec![
            Ir3FunctionDesc {
                entry: 1,
                arity: 3,
                frame_size: 3,
                name: Some("identity".to_string()),
                is_generator: false,
                rest_param_index: None,
            },
            Ir3FunctionDesc {
                entry: 2,
                arity: 1,
                frame_size: 2,
                name: Some("existing_species_result".to_string()),
                is_generator: false,
                rest_param_index: None,
            },
            Ir3FunctionDesc {
                entry: 4,
                arity: 3,
                frame_size: 4,
                name: Some("reject_element".to_string()),
                is_generator: false,
                rest_param_index: None,
            },
        ],
    );
    module.constant_pool.push("array_shape_result".into());
    module
}

fn install_array_shape_species(core: &mut InterpreterCore, source: ObjectId) -> ObjectId {
    let result = core.alloc_array_from_values(&[]).expect("species array");
    core.inject_runtime_global_binding("array_shape_result", Value::Object(result))
        .expect("Public species result binding");
    core.write_reg_with_label(8, Value::Object(result), Label::Public)
        .expect("pre-existing Public alias");
    let constructor = core
        .alloc_object_with_prototype(None)
        .expect("species constructor holder");
    core.set_object_runtime_property(
        constructor,
        RuntimePropertyKey::Symbol(WellKnownSymbol::Species.id()),
        Value::Function(1),
    )
    .expect("species constructor");
    core.set_object_property(
        source,
        "constructor".to_string(),
        Value::Object(constructor),
    )
    .expect("source constructor");
    result
}

fn assert_array_shape_alias_length(core: &mut InterpreterCore, length: i64, label: &Label) {
    // Read through the alias that predates the call after dropping its
    // aggregate completion label. Only the stored length provenance remains.
    core.clear_pending_hostcall_result_label();
    assert_eq!(core.get_register_label(8).unwrap(), &Label::Public);
    let mut module = test_module_with_functions(
        vec![
            Ir3Instruction::LoadStr {
                dst: 9,
                pool_index: 0,
            },
            Ir3Instruction::GetProperty {
                obj: 8,
                key: 9,
                dst: 10,
            },
            Ir3Instruction::Return { value: 10 },
        ],
        vec![],
    );
    module.constant_pool.push("length".into());
    core.ip = 0;
    let observed = core.run_loop_labeled(&module).expect("alias length read");
    assert_eq!(observed.value, Value::Int(length));
    assert_eq!(&observed.label, label);
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn filter_prefix_and_empty_length_survive_public_species_alias_bd_9vouw_110() {
    let module = array_shape_species_module();
    for first_label in [Label::Public, Label::Secret] {
        // Identity rejects the first element and keeps the later Public
        // one. The constant callback rejects everything, but its literal
        // return still inherits the first element's execution context.
        for callback in [0, 2] {
            let mut core = test_interpreter();
            let source = core
                .alloc_array_from_values(&[Value::Bool(false), Value::Bool(true)])
                .expect("source array");
            core.set_own_property_label(source, "0", &first_label)
                .expect("first source label");
            let result = install_array_shape_species(&mut core, source);
            core.write_reg_with_label(0, Value::Function(callback), Label::Public)
                .expect("callback register");
            let returned = core
                .dispatch_builtin_function(
                    &module,
                    &BuiltinFunction::new_kind(BuiltinFunctionKind::ArrayFilter),
                    RegRange { start: 0, count: 1 },
                    Some(Value::Object(source)),
                    None,
                )
                .expect("filter should execute");
            assert_eq!(returned, Value::Object(result));
            let (_, later_label) = core
                .invoke_labeled_array_callback(
                    Some(&module),
                    &Value::Function(callback),
                    Value::Undefined,
                    Value::Bool(true),
                    1,
                    source,
                )
                .expect("later callback is Public");
            assert_eq!(later_label, Label::Public);
            assert_eq!(
                core.take_pending_hostcall_result_label()
                    .unwrap_or(Label::Public),
                first_label
            );
            let length = if callback == 0 { 1 } else { 0 };
            if callback == 0 {
                assert_eq!(
                    core.heap[result.0 as usize].properties.get("0"),
                    Some(&Value::Bool(true))
                );
                assert_eq!(core.own_property_label(result, "0"), first_label);
            }
            assert_array_shape_alias_length(&mut core, length, &first_label);
        }
    }
}

#[test]
fn flat_map_empty_source_length_and_mutation_taint_later_species_positions_bd_9vouw_110() {
    let module = array_shape_species_module();
    for source_label in [Label::Public, Label::Secret] {
        for use_mutation_label in [false, true] {
            for append_public in [false, true] {
                let mut core = test_interpreter();
                let empty = core
                    .alloc_array_from_values(&[])
                    .expect("empty mapped array");
                if use_mutation_label {
                    core.join_object_mutation_label(empty, &source_label)
                        .expect("empty source mutation label");
                } else {
                    core.set_own_property_label(empty, "length", &source_label)
                        .expect("empty source length label");
                }
                let mut elements = vec![Value::Object(empty)];
                if append_public {
                    elements.push(Value::str("last"));
                }
                let source = core
                    .alloc_array_from_values(&elements)
                    .expect("source array");
                let result = install_array_shape_species(&mut core, source);
                core.write_reg_with_label(0, Value::Function(0), Label::Public)
                    .expect("callback register");
                let returned = core
                    .dispatch_builtin_function(
                        &module,
                        &BuiltinFunction::new_kind(BuiltinFunctionKind::ArrayFlatMap),
                        RegRange { start: 0, count: 1 },
                        Some(Value::Object(source)),
                        None,
                    )
                    .expect("flatMap should execute");
                assert_eq!(returned, Value::Object(result));
                assert_eq!(
                    core.take_pending_hostcall_result_label()
                        .unwrap_or(Label::Public),
                    source_label,
                    "empty source: mutation={use_mutation_label}, tail={append_public}"
                );
                if append_public {
                    assert_eq!(
                        core.heap[result.0 as usize].properties.get("0"),
                        Some(&Value::str("last"))
                    );
                    assert_eq!(core.own_property_label(result, "0"), source_label);
                }
                let length = i64::from(append_public);
                assert_array_shape_alias_length(&mut core, length, &source_label);
            }
        }
    }
}

#[test]
fn array_prefix_custom_label_is_preflighted_before_cloning_bd_9vouw_110() {
    let mut core = test_interpreter();
    let source = core.alloc_array_from_values(&[]).expect("source array");
    let result = core.alloc_array_from_values(&[]).expect("result array");
    let label = Label::Custom {
        name: "large-array-length-label".repeat(256),
        level: 6,
    };
    core.set_own_property_label(source, "length", &label)
        .expect("stored Custom length label");
    let inherited = core
        .alloc_object_with_prototype(Some(source))
        .expect("inherited length receiver");
    let shadow = core
        .alloc_object_with_prototype(Some(source))
        .expect("Public own length receiver");
    core.set_object_property(shadow, "length".to_string(), Value::Int(0))
        .expect("Public length shadow");
    let before = core.estimated_memory_bytes();
    let label_bytes = InterpreterCore::estimate_label_bytes(&label);

    core.config.max_total_memory_bytes = before + label_bytes - 1;
    for receiver in [source, inherited] {
        assert!(matches!(
            core.array_result_prefix_label(receiver, result, &Label::Public),
            Err(InterpreterError::MemoryBudgetExceeded { .. })
        ));
        assert_eq!(core.estimated_memory_bytes(), before);
        assert_eq!(core.own_property_label(result, "length"), Label::Public);
        assert!(core.pending_hostcall_result_label.is_none());
    }

    // A Public first owner ends the lookup without cloning the inherited
    // Custom name. Only the winning label's temporary bytes are required.
    core.config.max_total_memory_bytes = before;
    assert_eq!(
        core.array_result_prefix_label(shadow, result, &Label::Public)
            .expect("Public own length requires no Custom clone"),
        Label::Public
    );
    core.config.max_total_memory_bytes = before + label_bytes;
    assert_eq!(
        core.array_result_prefix_label(inherited, result, &Label::Public)
            .expect("the exact winning label budget should suffice"),
        label
    );
    assert_eq!(core.estimated_memory_bytes(), before);
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn flat_map_preserves_labels_stored_in_callback_returned_arrays_bd_9vouw_110() {
    let module = test_module_with_functions(
        vec![Ir3Instruction::Halt, Ir3Instruction::Return { value: 0 }],
        vec![Ir3FunctionDesc {
            entry: 1,
            arity: 3,
            frame_size: 3,
            name: Some("identity".to_string()),
            is_generator: false,
            rest_param_index: None,
        }],
    );
    let mut core = test_interpreter();
    let nested = core
        .alloc_array_from_values(&[Value::str("classified")])
        .expect("nested array");
    core.set_own_property_label(nested, "0", &Label::Secret)
        .expect("nested element label");
    let array = core
        .alloc_array_from_values(&[Value::Object(nested)])
        .expect("source array");
    core.write_reg(0, Value::Function(0))
        .expect("callback register");
    let result = core
        .dispatch_builtin_function(
            &module,
            &BuiltinFunction::new_kind(BuiltinFunctionKind::ArrayFlatMap),
            RegRange { start: 0, count: 1 },
            Some(Value::Object(array)),
            None,
        )
        .expect("flatMap should execute");
    let Value::Object(result) = result else {
        panic!("flatMap must return an array");
    };
    assert_eq!(
        core.heap[result.0 as usize].properties.get("0"),
        Some(&Value::str("classified"))
    );
    assert_eq!(core.own_property_label(result, "0"), Label::Secret);
    assert_eq!(
        core.take_pending_hostcall_result_label(),
        Some(Label::Secret)
    );
}

#[test]
fn labeled_array_result_write_restores_prior_label_on_refusal_bd_9vouw_110() {
    let mut core = test_interpreter();
    let array = core
        .alloc_array_from_values(&[Value::str("original")])
        .expect("result array");
    core.mutate_heap(|heap| heap[array.0 as usize].is_frozen = true);
    let before = core.estimated_memory_bytes();
    let error = core
        .create_labeled_data_property_or_throw(
            array,
            "0".to_string(),
            Value::str("classified"),
            &Label::Secret,
        )
        .expect_err("a frozen species result must reject the write");
    assert!(matches!(error, InterpreterError::TypeError { .. }));
    assert_eq!(
        core.heap[array.0 as usize].properties.get("0"),
        Some(&Value::str("original"))
    );
    assert_eq!(core.own_property_label(array, "0"), Label::Public);
    assert_eq!(core.estimated_memory_bytes(), before);
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn labeled_array_result_write_keeps_secret_labels_on_tight_frozen_refusal_bd_9vouw_110() {
    for tightly_budgeted in [true, false] {
        let mut core = test_interpreter();
        let array = core
            .alloc_array_from_values(&[Value::str("classified"), Value::str("other")])
            .expect("species result array");
        core.set_own_property_label(array, "0", &Label::Secret)
            .expect("first result label");
        core.set_own_property_label(array, "1", &Label::Secret)
            .expect("second result label");
        core.mutate_heap(|heap| heap[array.0 as usize].is_frozen = true);
        let before = core.estimated_memory_bytes();
        if tightly_budgeted {
            core.config.max_total_memory_bytes = before;
        }
        let error = core
            .create_labeled_data_property_or_throw(
                array,
                "0".to_string(),
                Value::str("public"),
                &Label::Public,
            )
            .expect_err("a frozen species result must reject replacement");
        if tightly_budgeted {
            assert!(matches!(
                error,
                InterpreterError::MemoryBudgetExceeded { .. }
            ));
        } else {
            assert!(matches!(error, InterpreterError::TypeError { .. }));
        }
        // Clearing the first label before a frozen write was refused
        // required cloning the remaining map to restore it. At this
        // ceiling that rollback itself failed and exposed the old value.
        assert_eq!(
            core.heap[array.0 as usize].properties.get("0"),
            Some(&Value::str("classified"))
        );
        assert_eq!(core.own_property_label(array, "0"), Label::Secret);
        assert_eq!(core.own_property_label(array, "1"), Label::Secret);
        assert_eq!(core.estimated_memory_bytes(), before);
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }
}

#[test]
fn labeled_array_result_write_releases_staged_labels_after_value_budget_refusal_bd_9vouw_110() {
    let mut core = test_interpreter();
    let array = core
        .alloc_array_from_values(&[Value::str("classified"), Value::str("other")])
        .expect("species result array");
    core.set_own_property_label(array, "0", &Label::Secret)
        .expect("first result label");
    core.set_own_property_label(array, "1", &Label::Secret)
        .expect("second result label");
    let before = core.estimated_memory_bytes();
    // The two small labels fit in this headroom, but the replacement
    // value does not. This reaches the value writer after label staging.
    core.config.max_total_memory_bytes = before.saturating_add(4096);
    let error = core
        .create_labeled_data_property_or_throw(
            array,
            "0".to_string(),
            Value::str("x".repeat(8192)),
            &Label::Public,
        )
        .expect_err("oversized replacement must be refused");
    assert!(matches!(
        error,
        InterpreterError::MemoryBudgetExceeded { .. }
    ));
    assert_eq!(
        core.heap[array.0 as usize].properties.get("0"),
        Some(&Value::str("classified"))
    );
    assert_eq!(core.own_property_label(array, "0"), Label::Secret);
    assert_eq!(core.own_property_label(array, "1"), Label::Secret);
    assert_eq!(core.estimated_memory_bytes(), before);
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );

    // A subsequent admitted replacement clears only its own old label
    // and releases the temporary map on the success path as well.
    core.create_labeled_data_property_or_throw(
        array,
        "0".to_string(),
        Value::str("public"),
        &Label::Public,
    )
    .expect("a small Public replacement should fit");
    assert_eq!(
        core.heap[array.0 as usize].properties.get("0"),
        Some(&Value::str("public"))
    );
    assert_eq!(core.own_property_label(array, "0"), Label::Public);
    assert_eq!(core.own_property_label(array, "1"), Label::Secret);
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

/// IFC: join, indexOf, includes and lastIndexOf read elements natively,
/// and the generic array-like path reads them through [[Get]]; the stored
/// element label (bd-ojvo1) joins their result label, so a Secret element
/// does not come back Public through an aggregate read (`[secret].join()`
/// was Public).
#[test]
fn array_aggregate_reads_join_stored_element_labels() {
    use crate::baseline_interpreter::tests_builtins_and_modules::active_builtin_regressions::call_builtin_for_test;

    let module = test_module_with_functions(
        vec![
            Ir3Instruction::ArrayPush {
                array: 0,
                element: 1,
            },
            Ir3Instruction::Halt,
        ],
        vec![],
    );
    let mut core = test_interpreter();
    let array = core
        .alloc_array_with_prototype(None)
        .expect("array should allocate");
    core.write_reg_with_label(0, Value::Object(array), Label::Public)
        .expect("array register should fit");
    core.write_reg_with_label(1, Value::str("classified"), Label::Secret)
        .expect("Secret element register should fit");
    core.execute(&module)
        .expect("ArrayPush of a Secret element");

    for (kind, args, expected) in [
        (
            BuiltinFunctionKind::ArrayJoin,
            vec![],
            Value::str("classified"),
        ),
        (
            BuiltinFunctionKind::ArrayIncludes,
            vec![Value::str("x")],
            Value::Bool(false),
        ),
        (
            BuiltinFunctionKind::ArrayIndexOf,
            vec![Value::str("classified")],
            Value::Int(0),
        ),
        (
            BuiltinFunctionKind::ArrayLastIndexOf,
            vec![Value::str("x")],
            Value::Int(-1),
        ),
    ] {
        core.clear_pending_hostcall_result_label();
        let result =
            call_builtin_for_test(&mut core, BuiltinFunction::new_kind(kind), array, &args)
                .expect("aggregate read should succeed");
        assert_eq!(result, expected, "{kind:?}");
        assert_eq!(
            core.take_pending_hostcall_result_label(),
            Some(Label::Secret),
            "{kind:?} must carry the Secret element's label"
        );
    }

    // The generic array-like path ([[Get]] through generic_get).
    let array_like = core
        .alloc_object_with_properties(&[("0", Value::str("classified")), ("length", Value::Int(1))])
        .expect("array-like should allocate");
    core.set_own_runtime_property_label(
        array_like,
        &RuntimePropertyKey::String(JsString::from("0")),
        &Label::Secret,
    )
    .expect("Secret element label should fit");
    core.clear_pending_hostcall_result_label();
    let joined = call_builtin_for_test(
        &mut core,
        BuiltinFunction::new_kind(BuiltinFunctionKind::ArrayJoin),
        array_like,
        &[],
    )
    .expect("generic join should succeed");
    assert_eq!(joined, Value::str("classified"));
    assert_eq!(
        core.take_pending_hostcall_result_label(),
        Some(Label::Secret)
    );
}

#[test]
fn array_aggregate_reads_follow_inherited_element_labels_and_own_shadowing() {
    use crate::baseline_interpreter::tests_builtins_and_modules::active_builtin_regressions::call_builtin_for_test;

    for native_array in [true, false] {
        for own_shadow in [false, true] {
            let mut core = test_interpreter();
            let prototype = core
                .alloc_object_with_properties(&[("0", Value::str("classified"))])
                .expect("prototype should allocate");
            core.set_own_property_label(prototype, "0", &Label::Secret)
                .expect("inherited element label should fit");
            let intermediate = core
                .alloc_object_with_prototype(Some(prototype))
                .expect("intermediate prototype should allocate");
            let receiver = if native_array {
                core.alloc_array_with_prototype(Some(intermediate))
            } else {
                core.alloc_object_with_prototype(Some(intermediate))
            }
            .expect("receiver should allocate");
            core.set_object_property(receiver, "length".to_string(), Value::Int(1))
                .expect("array-like length should fit");
            if own_shadow {
                core.set_object_property(receiver, "0".to_string(), Value::str("public"))
                    .expect("Public own element should fit");
            }

            let expected_label = if own_shadow {
                Label::Public
            } else {
                Label::Secret
            };
            let expected_index = if own_shadow { -1 } else { 0 };
            for (kind, args, expected) in [
                (
                    BuiltinFunctionKind::ArrayJoin,
                    vec![],
                    Value::str(if own_shadow { "public" } else { "classified" }),
                ),
                (
                    BuiltinFunctionKind::ArrayIncludes,
                    vec![Value::str("classified")],
                    Value::Bool(!own_shadow),
                ),
                (
                    BuiltinFunctionKind::ArrayIndexOf,
                    vec![Value::str("classified")],
                    Value::Int(expected_index),
                ),
                (
                    BuiltinFunctionKind::ArrayLastIndexOf,
                    vec![Value::str("classified")],
                    Value::Int(expected_index),
                ),
            ] {
                core.clear_pending_hostcall_result_label();
                let result = call_builtin_for_test(
                    &mut core,
                    BuiltinFunction::new_kind(kind),
                    receiver,
                    &args,
                )
                .expect("aggregate read should succeed");
                assert_eq!(
                    result, expected,
                    "{kind:?}, native_array={native_array}, own_shadow={own_shadow}"
                );
                assert_eq!(
                    core.take_pending_hostcall_result_label()
                        .unwrap_or(Label::Public),
                    expected_label,
                    "{kind:?} must use the label of the property that supplied its value; \
                         native_array={native_array}, own_shadow={own_shadow}"
                );
            }
            assert_eq!(
                core.estimated_memory_bytes(),
                core.recompute_estimated_memory_bytes()
            );
        }
    }
}

#[test]
fn property_label_delete_serde_and_budget_are_accounted_bd_ojvo1() {
    let mut core = test_interpreter();
    let object = core
        .alloc_object_with_properties(&[("data", Value::Int(7))])
        .expect("object should allocate");
    let key = RuntimePropertyKey::String(JsString::from("data"));
    let before_label = core.estimated_memory_bytes();
    core.set_own_runtime_property_label(object, &key, &Label::Secret)
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
    assert_eq!(decoded.property_labels.get("data"), Some(&Label::Secret));

    assert!(core.remove_object_property(object, "data").unwrap());
    assert_eq!(
        core.own_stored_runtime_property_label(object, &key),
        Label::Public
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
        core.set_own_runtime_property_label(object, &key, &Label::Secret),
        Err(InterpreterError::MemoryBudgetExceeded { .. })
    ));
    assert_eq!(
        serde_json::to_vec(&core.heap[object.0 as usize]).unwrap(),
        stable_heap
    );
    assert_eq!(core.estimated_memory_bytes(), stable_memory);
}

#[test]
fn inherited_string_and_symbol_labels_follow_the_value_owner_bd_ojvo1() {
    let mut core = test_interpreter();
    let prototype = core
        .alloc_object_with_properties(&[("inherited", Value::Int(1))])
        .expect("prototype should allocate");
    let child = core
        .alloc_object_with_prototype(Some(prototype))
        .expect("child should allocate");
    let string_key = RuntimePropertyKey::String(JsString::from("inherited"));
    core.set_own_runtime_property_label(prototype, &string_key, &Label::Secret)
        .expect("string label should fit");
    assert_eq!(core.own_property_label(child, "inherited"), Label::Secret);

    let symbol = core
        .allocate_private_symbol(Some(JsString::from("classified")))
        .expect("private Symbol should allocate");
    let symbol_key = RuntimePropertyKey::Symbol(symbol);
    core.set_object_runtime_property(prototype, symbol_key.clone(), Value::Int(2))
        .expect("Symbol property should fit");
    core.set_own_runtime_property_label(prototype, &symbol_key, &Label::Confidential)
        .expect("Symbol label should fit");
    assert_eq!(
        core.runtime_property_label(child, &symbol_key),
        Label::Confidential
    );
}

#[test]
fn ephemeral_trace_handoff_moves_the_finalised_trace_without_byte_drift() {
    let run = |trace_handoff, halt| {
        let mut instructions = vec![Ir3Instruction::GetProperty {
            obj: 0,
            key: 1,
            dst: 2,
        }];
        instructions.push(if halt {
            Ir3Instruction::Halt
        } else {
            Ir3Instruction::Return { value: 2 }
        });
        let module = test_module_with_functions(instructions, vec![]);
        let mut core = test_interpreter();
        let object = core
            .alloc_object_with_properties(&[("data", Value::Int(41))])
            .expect("ordinary object should allocate");
        core.mutate_registers(|registers| {
            registers[0] = Value::Object(object);
            registers[1] = Value::str("data");
            registers[2] = Value::Undefined;
        });

        let result = core
            .execute_with_trace_handoff(&module, None, trace_handoff)
            .expect("ordinary own-property read should execute");
        (result, core.nondeterminism_trace_ref().clone())
    };

    for (termination, halt) in [("return", false), ("halt", true)] {
        let (retained_result, retained_core_trace) = run(TraceHandoff::RetainInCore, halt);
        let (drained_result, drained_core_trace) = run(TraceHandoff::DrainEphemeralCore, halt);

        assert_eq!(
            retained_result.nondeterminism_trace, drained_result.nondeterminism_trace,
            "moving the ephemeral trace must preserve every replay-visible field for {termination}"
        );
        assert_eq!(
            serde_json::to_vec(&retained_result.nondeterminism_trace)
                .expect("retained trace should serialize"),
            serde_json::to_vec(&drained_result.nondeterminism_trace)
                .expect("drained trace should serialize"),
            "moving the ephemeral trace must preserve serialized replay bytes for {termination}"
        );
        assert_eq!(
            retained_core_trace, retained_result.nondeterminism_trace,
            "the public retention policy must leave the complete trace in the core for {termination}"
        );
        // bd-9vouw.18: a property read is folded into the deterministic
        // witness, so that is the replay content the handoff must move.
        assert!(
            drained_result
                .nondeterminism_trace
                .deterministic_witness
                .event_count
                > 0,
            "the property read must reach the moved trace's witness for {termination}"
        );
        drained_result
            .nondeterminism_trace
            .validate_for_replay()
            .expect("the moved trace must remain finalised and replay-valid");
        assert!(drained_core_trace.events.is_empty());
        assert_eq!(
            drained_core_trace.deterministic_witness,
            crate::deterministic_replay::DeterministicEventWitness::default(),
            "draining must leave a fresh witness in the core for {termination}"
        );
        assert!(!drained_core_trace.is_finalised());
        assert!(drained_core_trace.session_id.is_empty());
    }
}

/// bd-9vouw.504: `ScopeChain::binds` answers `resolve(name).is_some()`
/// for a name bound in the outermost, a middle or the innermost frame,
/// in two frames, or in none.
#[test]
fn scope_chain_binds_matches_resolve_bd_9vouw_504() {
    let mut chain = ScopeChain::new();
    for _ in 0..4 {
        chain.push(64).expect("scope depth should fit");
    }
    let declare = |chain: &mut ScopeChain, frame: usize, name: &str| {
        chain.frames[frame].declare(name.to_string(), BindingKind::Var);
    };
    declare(&mut chain, 1, "module");
    declare(&mut chain, 2, "middle");
    declare(&mut chain, 4, "inner");
    declare(&mut chain, 0, "twice");
    declare(&mut chain, 3, "twice");
    for name in ["module", "middle", "inner", "twice", "absent"] {
        assert_eq!(chain.binds(name), chain.resolve(name).is_some(), "{name}");
    }
    assert!(chain.binds("module"));
    assert!(!chain.binds("absent"));
}

/// bd-9vouw.504: `static_move` copies a value and label that own no
/// dynamic bytes into a destination holding none, label included and with
/// the memory estimate unchanged; anything else is left to the accounted
/// path, with every register untouched.
#[test]
fn static_move_copies_only_static_pairs_bd_9vouw_504() {
    let mut core = test_interpreter();
    core.mutate_registers(|registers| {
        registers[0] = Value::Int(5);
        registers[1] = Value::Undefined;
        registers[2] = Value::str("owned");
        registers[3] = Value::Int(1);
    });
    core.set_register_label(0, Label::Secret)
        .expect("source label should be settable");
    let bytes_before = core.estimated_memory_bytes;
    assert!(core.static_move(1, 0));
    assert_eq!(core.read_reg(1).unwrap(), Value::Int(5));
    assert_eq!(
        core.get_register_label(1).unwrap(),
        &Label::Secret,
        "the source label moves with the value"
    );
    assert_eq!(core.estimated_memory_bytes, bytes_before);

    // A string owns bytes as the source or as the replaced destination
    // value, and a Custom label owns its name.
    assert!(!core.static_move(3, 2));
    assert!(!core.static_move(2, 0));
    core.set_register_label(
        0,
        Label::Custom {
            name: "custom".to_string(),
            level: 2,
        },
    )
    .expect("custom label should be settable");
    assert!(!core.static_move(3, 0));
    assert_eq!(core.read_reg(3).unwrap(), Value::Int(1));
    assert_eq!(core.get_register_label(3).unwrap(), &Label::Public);
    assert_eq!(core.read_reg(2).unwrap(), Value::str("owned"));
    let max_registers = core.config.max_registers;
    assert!(!core.static_move(max_registers, 1));
    assert!(!core.static_move(1, max_registers));
}

/// bd-9vouw.504: `join_owned_label_with_temporary_budget` returns the
/// owned label for a Public operand without comparing, which is right
/// only while Public is the bottom of Label's order, Custom labels of
/// level 0 included.
#[test]
fn public_is_the_bottom_of_the_label_order_bd_9vouw_504() {
    let core = test_interpreter();
    for label in [
        Label::Public,
        Label::Internal,
        Label::Confidential,
        Label::Secret,
        Label::TopSecret,
        Label::Custom {
            name: String::new(),
            level: 0,
        },
        Label::Custom {
            name: "a".to_string(),
            level: 0,
        },
    ] {
        assert!(label >= Label::Public, "{label:?}");
        assert_eq!(
            core.join_owned_label_with_temporary_budget(label.clone(), &Label::Public)
                .unwrap(),
            label
        );
    }
}

/// bd-9vouw.490: the bitset remembered set answers as the BTreeSet it
/// replaces through a deterministic mix of inserts, removes, retains and
/// clears: the same insert/remove results, members, ascending order and
/// length, and set equality that ignores emptied words.
#[test]
fn remembered_set_matches_a_btree_set_bd_9vouw_490() {
    let mut bits = RememberedSet::default();
    let mut tree = BTreeSet::<ObjectId>::new();
    let mut state = 0x2545_f491_4f6c_dd1du64;
    for step in 0..4_000u32 {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let id = ObjectId((state % 700) as u32);
        match state % 11 {
            0..=5 => assert_eq!(bits.insert(id), tree.insert(id), "insert {id:?}"),
            6..=8 => assert_eq!(bits.remove(&id), tree.remove(&id), "remove {id:?}"),
            9 => {
                let cut = (state % 700) as u32;
                bits.retain(|object| object.0 < cut);
                tree.retain(|object| object.0 < cut);
            }
            _ if step % 500 == 0 => {
                bits.clear();
                tree.clear();
            }
            _ => {}
        }
        assert_eq!(bits.contains(&id), tree.contains(&id));
        assert_eq!(bits.len(), tree.len());
    }
    assert_eq!(
        bits.iter().collect::<Vec<_>>(),
        tree.iter().copied().collect::<Vec<_>>()
    );

    let mut emptied = bits.clone();
    let extra = ObjectId(10_000);
    emptied.insert(extra);
    assert_ne!(emptied, bits);
    emptied.remove(&extra);
    assert_eq!(
        emptied, bits,
        "an emptied trailing word does not change the set"
    );
}

/// bd-9vouw.504: setting a Public label on a property without a stored
/// label changes nothing (no entry, the same estimate); over a stored
/// label it removes the entry and gives back its bytes.
#[test]
fn public_label_on_an_unlabelled_property_changes_nothing_bd_9vouw_504() {
    let mut core = test_interpreter();
    let object = core
        .alloc_object_with_properties(&[("data", Value::Int(7)), ("other", Value::Int(8))])
        .expect("ordinary object should allocate");
    let data = RuntimePropertyKey::String(JsString::from("data"));
    let bytes_before = core.estimated_memory_bytes;
    core.set_own_runtime_property_label(object, &data, &Label::Public)
        .expect("a Public label should fit");
    assert_eq!(core.estimated_memory_bytes, bytes_before);
    assert_eq!(core.runtime_property_label(object, &data), Label::Public);

    core.set_own_runtime_property_label(object, &data, &Label::Secret)
        .expect("a Secret label should fit");
    assert_eq!(core.runtime_property_label(object, &data), Label::Secret);
    assert!(core.estimated_memory_bytes > bytes_before);
    core.set_own_runtime_property_label(object, &data, &Label::Public)
        .expect("a Public label should fit");
    assert_eq!(core.runtime_property_label(object, &data), Label::Public);
    assert_eq!(core.estimated_memory_bytes, bytes_before);
}

/// bd-9vouw.504: the mutation-label join labels an ordinary object, and
/// along a Proxy chain stops at the first repeat: two proxies targeting
/// each other, and one targeting itself.
#[test]
fn object_mutation_label_join_follows_proxy_chains_and_stops_on_cycles_bd_9vouw_504() {
    let mut core = test_interpreter();
    let plain = core
        .alloc_object_with_properties(&[])
        .expect("object should allocate");
    core.join_object_mutation_label(plain, &Label::Secret)
        .expect("join should fit");
    assert_eq!(
        core.object_mutation_labels.get(&plain),
        Some(&Label::Secret)
    );

    let first = core
        .alloc_object_with_properties(&[])
        .expect("object should allocate");
    let second = core
        .alloc_object_with_properties(&[])
        .expect("object should allocate");
    let lone = core
        .alloc_object_with_properties(&[])
        .expect("object should allocate");
    for (proxy, target) in [(first, second), (second, first), (lone, lone)] {
        core.set_object_brand(proxy, PROXY_TYPE_TAG)
            .expect("proxy marker should fit");
        core.set_object_property(proxy, PROXY_TARGET_SLOT.to_string(), Value::Object(target))
            .expect("proxy target slot should fit");
    }
    core.join_object_mutation_label(first, &Label::Confidential)
        .expect("a two-proxy cycle should end");
    assert_eq!(
        core.object_mutation_labels.get(&first),
        Some(&Label::Confidential)
    );
    assert_eq!(
        core.object_mutation_labels.get(&second),
        Some(&Label::Confidential)
    );
    core.join_object_mutation_label(lone, &Label::Internal)
        .expect("a self-targeting proxy should end");
    assert_eq!(
        core.object_mutation_labels.get(&lone),
        Some(&Label::Internal)
    );
}

#[test]
fn ordinary_own_property_fast_path_excludes_proto_proxy_and_missing_keys() {
    let mut core = test_interpreter();
    let object = core
        .alloc_object_with_properties(&[("data", Value::Int(7))])
        .expect("ordinary object should allocate");
    let data_key = RuntimePropertyKey::String(JsString::from("data"));
    assert!(core.ordinary_own_property_read_fast_path_eligible(object, &data_key));

    let exact_key = JsString::from_code_units(&[0xD800]);
    core.set_object_runtime_property(
        object,
        RuntimePropertyKey::String(exact_key.clone()),
        Value::Int(8),
    )
    .expect("exact string own property should fit");
    assert!(core.ordinary_own_property_read_fast_path_eligible(
        object,
        &RuntimePropertyKey::String(exact_key),
    ));

    let symbol = core
        .allocate_private_symbol(Some(JsString::from("fast-path-symbol")))
        .expect("symbol should allocate");
    core.set_object_runtime_property(object, RuntimePropertyKey::Symbol(symbol), Value::Int(9))
        .expect("symbol own property should fit");
    assert!(core.ordinary_own_property_read_fast_path_eligible(
        object,
        &RuntimePropertyKey::Symbol(symbol),
    ));

    core.set_object_property(
        object,
        "accessor".to_string(),
        Value::Accessor {
            get: None,
            set: None,
        },
    )
    .expect("accessor own property should fit");
    assert!(core.ordinary_own_property_read_fast_path_eligible(
        object,
        &RuntimePropertyKey::String(JsString::from("accessor")),
    ));

    let array = core
        .alloc_array_from_values(&[Value::Int(1)])
        .expect("dense array should allocate");
    assert!(core.ordinary_own_property_read_fast_path_eligible(
        array,
        &RuntimePropertyKey::String(JsString::from("0")),
    ));
    assert!(!core.ordinary_own_property_read_fast_path_eligible(
        object,
        &RuntimePropertyKey::String(JsString::from("missing")),
    ));
    assert!(!core.ordinary_own_property_read_fast_path_eligible(
        object,
        &RuntimePropertyKey::String(JsString::from("__proto__")),
    ));

    core.set_object_brand(object, PROXY_TYPE_TAG)
        .expect("proxy marker should fit");
    assert!(
        !core.ordinary_own_property_read_fast_path_eligible(object, &data_key),
        "even a malformed proxy-tagged object must fail closed to proxy validation"
    );

    core.mutate_registers(|registers| {
        registers[0] = Value::Object(object);
        registers[1] = Value::str("data");
        registers[2] = Value::Int(123);
    });
    core.set_register_label(2, Label::Secret)
        .expect("destination label should be settable");
    let trace_count_before = core.nondeterminism_event_count();
    let error = core
        .run_loop(&test_module_with_functions(
            vec![
                Ir3Instruction::GetProperty {
                    obj: 0,
                    key: 1,
                    dst: 2,
                },
                Ir3Instruction::Halt,
            ],
            vec![],
        ))
        .expect_err("malformed Proxy metadata must fail before the own property is read");
    assert!(matches!(
        error,
        InterpreterError::TypeError { expected, got }
            if expected == "well-formed Proxy target slot" && got == "missing"
    ));
    assert_eq!(core.read_reg(2).unwrap(), Value::Int(123));
    assert_eq!(core.get_register_label(2).unwrap(), &Label::Secret);
    assert_eq!(
        core.nondeterminism_event_count(),
        trace_count_before,
        "a malformed Proxy must not emit an ordinary property-found trace"
    );
}

/// bd-9vouw.505: inside a callback scope (an active inline callback
/// context), [[Get]] observes the owner's shape label and the property's
/// stored label into the context (da779790e). The own-property fast path
/// predates that and skipped it: reading a public key of an object whose
/// shape a Secret store labelled left the context Public. The fast read
/// now makes the same observation, so it matches the generic path (forced
/// by the test switch) in value, labels, context, instruction count and
/// trace, for an object with or without a prototype.
#[test]
fn own_property_read_in_a_callback_scope_observes_the_shape_label_bd_9vouw_505() {
    let module = test_module_with_functions(
        vec![
            Ir3Instruction::GetProperty {
                obj: 0,
                key: 1,
                dst: 2,
            },
            Ir3Instruction::Halt,
        ],
        vec![],
    );
    let run = |force_generic: bool, with_prototype: bool| {
        let mut core = test_interpreter();
        let object = core
            .alloc_object_with_properties(&[("data", Value::Int(7))])
            .expect("ordinary object should allocate");
        if with_prototype {
            let prototype = core
                .alloc_object_with_properties(&[])
                .expect("prototype should allocate");
            core.mutate_heap(|heap| heap[object.0 as usize].prototype = Some(prototype));
        }
        core.join_object_mutation_label(object, &Label::Secret)
            .expect("shape label should fit");
        core.mutate_registers(|registers| {
            registers[0] = Value::Object(object);
            registers[1] = Value::str("data");
        });
        core.active_inline_callback_context_label = Some(Label::Public);
        let data = RuntimePropertyKey::String(JsString::from("data"));
        assert!(
            core.ordinary_own_property_fast_read(object, &data)
                .is_some(),
            "the fast read serves the object in a callback scope"
        );
        FORCE_GENERIC_OWN_PROPERTY_READS.with(|force| force.set(force_generic));
        let halted = core.run_loop(&module);
        FORCE_GENERIC_OWN_PROPERTY_READS.with(|force| force.set(false));
        assert_eq!(halted, Err(InterpreterError::Halted));
        (
            core.read_reg(2).unwrap(),
            core.get_register_label(2).unwrap().clone(),
            core.active_inline_callback_context_label.clone(),
            core.instructions_executed,
            core.nondeterminism_trace_ref().clone(),
        )
    };
    for with_prototype in [false, true] {
        let fast = run(false, with_prototype);
        let generic = run(true, with_prototype);
        assert_eq!(fast.0, Value::Int(7));
        assert_eq!(
            fast.2,
            Some(Label::Secret),
            "the read observes the Secret shape label (prototype: {with_prototype})"
        );
        assert_eq!(
            fast, generic,
            "fast and generic reads in a callback scope (prototype: {with_prototype})"
        );
    }
}

/// bd-9vouw.504: a store the plain fast path takes ends exactly as the
/// generic [[Set]] (forced with the test switch): the same outcome,
/// receiver and prototype values and stored labels, mutation labels,
/// instructions charged, memory estimate, context and pending labels, and
/// witness. The stores it must leave to the generic path (inherited
/// read-only or accessor, labelled shape or inherited label, frozen,
/// non-extensible, array, `__proto__`) are refused and end the same too.
/// Each case runs through SetPropertySloppy and SetProperty, entered with
/// no context and with a Public one, and as a direct [[Set]] without a
/// context.
#[test]
fn plain_store_fast_path_matches_the_generic_set_bd_9vouw_504() {
    let cases = [
        ("new key", "fresh", true),
        ("own key", "own", true),
        ("new key on an instance", "fresh", true),
        ("inherited writable", "inherited", true),
        ("inherited read-only", "inherited", false),
        ("inherited accessor", "inherited", false),
        ("labelled shape", "fresh", false),
        ("inherited Secret label", "inherited", false),
        ("frozen", "own", false),
        ("non-extensible, new key", "fresh", false),
        ("non-extensible, inherited key", "inherited", false),
        ("array", "fresh", false),
        ("__proto__", "__proto__", false),
    ];
    let setup = |case: &str| {
        let mut core = test_interpreter();
        let (receiver, prototype) = if case == "array" {
            let array = core
                .alloc_array_from_values(&[Value::Int(1)])
                .expect("array should allocate");
            (array, None)
        } else {
            let receiver = core
                .alloc_object_with_properties(&[("own", Value::Int(1))])
                .expect("receiver should allocate");
            let prototype = core
                .alloc_object_with_properties(&[
                    ("other", Value::Int(2)),
                    ("inherited", Value::Int(3)),
                ])
                .expect("prototype should allocate");
            if case != "new key" && case != "own key" && case != "labelled shape" {
                core.mutate_heap(|heap| heap[receiver.0 as usize].prototype = Some(prototype));
            }
            (receiver, Some(prototype))
        };
        let inherited = RuntimePropertyKey::String(JsString::from("inherited"));
        match case {
            "inherited read-only" => core
                .set_own_property_attributes(
                    prototype.unwrap(),
                    &inherited,
                    PropertyAttributes {
                        writable: false,
                        enumerable: true,
                        configurable: true,
                    },
                )
                .expect("attributes should fit"),
            "inherited accessor" => core
                .set_object_property(
                    prototype.unwrap(),
                    "inherited".to_string(),
                    Value::Accessor {
                        get: None,
                        set: None,
                    },
                )
                .expect("accessor should fit"),
            "labelled shape" => core
                .join_object_mutation_label(receiver, &Label::Secret)
                .expect("shape label should fit"),
            "inherited Secret label" => core
                .set_own_property_label(prototype.unwrap(), "inherited", &Label::Secret)
                .expect("label should fit"),
            "frozen" => core.mutate_heap(|heap| heap[receiver.0 as usize].is_frozen = true),
            "non-extensible, new key" | "non-extensible, inherited key" => {
                core.mutate_heap(|heap| heap[receiver.0 as usize].is_non_extensible = true)
            }
            _ => {}
        }
        (core, receiver, prototype)
    };
    let snapshot = |core: &InterpreterCore,
                    receiver: ObjectId,
                    prototype: Option<ObjectId>,
                    key: &RuntimePropertyKey| {
        let read = |object: ObjectId| {
            core.heap
                .get(object.0 as usize)
                .and_then(|object| object.own_runtime_property_value(key))
        };
        format!(
            "{:?} {:?} {:?} {:?} {:?} {} {} {:?} {:?} {:?}",
            read(receiver),
            prototype.map(read),
            core.own_stored_runtime_property_label(receiver, key),
            prototype.map(|prototype| core.own_stored_runtime_property_label(prototype, key)),
            core.object_mutation_labels,
            core.instructions_executed,
            core.estimated_memory_bytes,
            core.active_inline_callback_context_label,
            core.pending_hostcall_result_label,
            core.nondeterminism_trace_ref().deterministic_witness,
        )
    };
    for (case, name, fast) in cases {
        let key = RuntimePropertyKey::String(JsString::from(name));
        for strict in [false, true] {
            for context in [None, Some(Label::Public)] {
                let module = test_module_with_functions(
                    vec![
                        if strict {
                            Ir3Instruction::SetProperty {
                                obj: 0,
                                key: 1,
                                val: 2,
                            }
                        } else {
                            Ir3Instruction::SetPropertySloppy {
                                obj: 0,
                                key: 1,
                                val: 2,
                            }
                        },
                        Ir3Instruction::Halt,
                    ],
                    vec![],
                );
                let run = |force_generic: bool| {
                    let (mut core, receiver, prototype) = setup(case);
                    core.mutate_registers(|registers| {
                        registers[0] = Value::Object(receiver);
                        registers[1] = Value::str(name);
                        registers[2] = Value::Int(9);
                    });
                    core.active_inline_callback_context_label = context.clone();
                    assert_eq!(
                        core.plain_store_observation_steps(receiver, &key).is_some(),
                        fast,
                        "{case}: fast path eligibility"
                    );
                    FORCE_GENERIC_STORES.with(|force| force.set(force_generic));
                    let outcome = core.run_loop(&module);
                    FORCE_GENERIC_STORES.with(|force| force.set(false));
                    format!("{outcome:?} {}", snapshot(&core, receiver, prototype, &key))
                };
                assert_eq!(
                    run(false),
                    run(true),
                    "{case}, strict {strict}, context {context:?}"
                );
            }
        }
        let direct = |force_generic: bool| {
            let (mut core, receiver, prototype) = setup(case);
            FORCE_GENERIC_STORES.with(|force| force.set(force_generic));
            let outcome = core.proxy_aware_set_runtime_property(
                None,
                receiver,
                &key,
                Value::Int(9),
                Value::Object(receiver),
                0,
            );
            FORCE_GENERIC_STORES.with(|force| force.set(false));
            format!("{outcome:?} {}", snapshot(&core, receiver, prototype, &key))
        };
        assert_eq!(direct(false), direct(true), "{case}, direct [[Set]]");
    }
}

/// bd-9vouw.504: the depth-0 observation of an own data property leaves
/// the context label, the charged instructions and the estimate exactly
/// as reflect_observe_selected_property does, with no shape label or a
/// Secret one, a Public or Confidential stored label, and a Public or
/// TopSecret starting context.
#[test]
fn own_data_property_observation_matches_the_selected_property_walk_bd_9vouw_504() {
    for shape in [None, Some(Label::Secret)] {
        for stored in [Label::Public, Label::Confidential] {
            for context in [Label::Public, Label::TopSecret] {
                let run = |depth_zero: bool| {
                    let mut core = test_interpreter();
                    let object = core
                        .alloc_object_with_properties(&[("data", Value::Int(7))])
                        .expect("object should allocate");
                    if let Some(shape) = &shape {
                        core.join_object_mutation_label(object, shape)
                            .expect("shape label should fit");
                    }
                    core.set_own_property_label(object, "data", &stored)
                        .expect("stored label should fit");
                    core.active_inline_callback_context_label = Some(context.clone());
                    let key = RuntimePropertyKey::String(JsString::from("data"));
                    let label = core.own_stored_runtime_property_label(object, &key);
                    if depth_zero {
                        core.reflect_observe_own_data_property(object, &label)
                            .expect("observation should fit");
                    } else {
                        core.reflect_observe_selected_property(object, &key)
                            .expect("observation should fit");
                    }
                    (
                        core.active_inline_callback_context_label.clone(),
                        core.instructions_executed,
                        core.estimated_memory_bytes,
                    )
                };
                assert_eq!(
                    run(true),
                    run(false),
                    "shape {shape:?}, stored {stored:?}, context {context:?}"
                );
            }
        }
    }
}

/// bd-9vouw.504: the fast own-property read returns a data property's
/// stored label (the label the [[Get]] owner join reads) from one lookup,
/// and no label for an accessor, whose getter runs before the join.
#[test]
fn ordinary_own_property_fast_read_carries_a_data_label_only_bd_9vouw_504() {
    let mut core = test_interpreter();
    let object = core
        .alloc_object_with_properties(&[("data", Value::Int(7))])
        .expect("ordinary object should allocate");
    core.set_own_property_label(object, "data", &Label::Secret)
        .expect("property label should be settable");
    let data_key = RuntimePropertyKey::String(JsString::from("data"));
    assert_eq!(
        core.ordinary_own_property_fast_read(object, &data_key),
        Some((Value::Int(7), Some(Label::Secret)))
    );
    assert_eq!(
        core.runtime_property_label(object, &data_key),
        Label::Secret
    );

    core.set_object_property(
        object,
        "accessor".to_string(),
        Value::Accessor {
            get: None,
            set: None,
        },
    )
    .expect("accessor own property should fit");
    assert!(matches!(
        core.ordinary_own_property_fast_read(
            object,
            &RuntimePropertyKey::String(JsString::from("accessor")),
        ),
        Some((Value::Accessor { .. }, None))
    ));
    assert_eq!(
        core.ordinary_own_property_fast_read(
            object,
            &RuntimePropertyKey::String(JsString::from("missing")),
        ),
        None
    );
    core.set_object_brand(object, PROXY_TYPE_TAG)
        .expect("proxy marker should fit");
    assert_eq!(
        core.ordinary_own_property_fast_read(object, &data_key),
        None,
        "a proxy-tagged object keeps the generic path"
    );
}

/// bd-9vouw.504: a small index's shared key is the decimal key the
/// formatted path builds; larger and negative integers keep that path.
#[test]
fn small_index_keys_are_the_decimal_keys_bd_9vouw_504() {
    let core = test_interpreter();
    for number in [0_i64, 7, 10, 1023] {
        let shared = small_index_key(number).expect("a small index has a shared key");
        assert_eq!(shared, JsString::from(number.to_string()));
        assert_eq!(small_index_key(number), Some(shared));
        assert_eq!(
            core.executable_property_key_from_value(&Value::Int(number)),
            RuntimePropertyKey::String(JsString::from(number.to_string()))
        );
    }
    for number in [-1_i64, 1024, i64::MAX] {
        assert_eq!(small_index_key(number), None);
        assert_eq!(
            core.executable_property_key_from_value(&Value::Int(number)),
            RuntimePropertyKey::String(JsString::from(number.to_string()))
        );
    }
}

/// bd-gqaa4/bd-0zybl: the conservative prior-dst join must not clone a
/// losing attacker-sized label while the already-owned result label is
/// live. The exact ceiling below admits the small dominant result label
/// but refuses the obsolete two-clone implementation.
#[test]
fn get_property_prior_dst_join_clones_only_the_dominant_label_bd_gqaa4() {
    let module = test_module_with_functions(
        vec![
            Ir3Instruction::GetProperty {
                obj: 0,
                key: 1,
                dst: 2,
            },
            Ir3Instruction::Halt,
        ],
        vec![],
    );
    let dominant_label = Label::Custom {
        name: "dominant".to_string(),
        level: 9,
    };
    let losing_large_label = Label::Custom {
        name: "losing-prior-dst-label".repeat(128),
        level: 8,
    };
    let mut core = test_interpreter();
    let object = core
        .alloc_object_with_properties(&[("data", Value::Int(1))])
        .expect("test object allocation should succeed");
    core.write_reg_with_label(0, Value::Object(object), dominant_label.clone())
        .expect("object register should be writable");
    core.write_reg_with_label(1, Value::str("data"), Label::Public)
        .expect("key register should be writable");
    core.write_reg_with_label(2, Value::Undefined, losing_large_label)
        .expect("dst register should be writable");
    let before = core
        .sync_estimated_memory_bytes()
        .expect("fixture accounting should synchronize");
    core.config.max_total_memory_bytes =
        before.saturating_add(InterpreterCore::estimate_label_bytes(&dominant_label));

    assert_eq!(
        core.run_loop(&module),
        Err(InterpreterError::Halted),
        "the one-clone dominant-label join should reach the fixture halt"
    );

    assert_eq!(
        core.get_register_label(2)
            .expect("dst register label should exist"),
        &dominant_label
    );
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes(),
        "temporary join storage must not escape into retained accounting"
    );
}

/// bd-ojvo1: a Secret value written to a Public object's own property must
/// read back as (at least) Secret. Before per-property labels, SetProperty
/// dropped the value's provenance and GetProperty recovered only the
/// object's (Public) label, laundering the Secret out through an aliased
/// container.
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

    let mut core = test_interpreter();
    let public_obj = core
        .alloc_object_with_properties(&[])
        .expect("test object allocation should succeed");
    core.mutate_registers(|r| {
        r[0] = Value::Object(public_obj);
        r[2] = Value::Int(42);
    });
    core.set_register_label(0, crate::ifc_artifacts::Label::Public)
        .expect("object label should be settable");
    core.set_register_label(2, crate::ifc_artifacts::Label::Secret)
        .expect("written value label should be settable");

    core.execute(&module)
        .expect("set then get off a public object should execute");

    assert_eq!(
        core.get_register_label(3)
            .expect("dst register label should exist"),
        &crate::ifc_artifacts::Label::Secret,
        "a Secret value written to a Public object property must read back Secret (bd-ojvo1)"
    );
}

#[test]
fn create_data_property_keeps_ifc_labels_and_rejection_accounting_bd_9vouw_280() {
    let module = test_module_with_functions(
        vec![
            Ir3Instruction::CreateDataProperty {
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
    for frozen in [false, true] {
        let mut core = test_interpreter();
        let object = core
            .alloc_object_with_properties(&[("data", Value::Int(1))])
            .expect("object allocation");
        if frozen {
            core.mutate_heap(|heap| heap[object.0 as usize].is_frozen = true);
        }
        core.write_reg_with_label(0, Value::Object(object), Label::Public)
            .expect("target register");
        core.write_reg_with_label(1, Value::str("data"), Label::Public)
            .expect("key register");
        core.write_reg_with_label(2, Value::Int(42), Label::Secret)
            .expect("value register");
        let result = core.execute(&module);
        if frozen {
            assert!(matches!(result, Err(InterpreterError::TypeError { .. })));
            assert_eq!(
                core.heap[object.0 as usize].properties.get("data"),
                Some(&Value::Int(1))
            );
            assert_eq!(core.own_property_label(object, "data"), Label::Public);
        } else {
            result.expect("own definition and read");
            assert_eq!(core.read_reg(3).unwrap(), Value::Int(42));
            assert_eq!(core.get_register_label(3).unwrap(), &Label::Secret);
            assert_eq!(core.own_property_label(object, "data"), Label::Secret);
        }
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }
}

#[test]
fn inherited_setter_receives_the_assigned_scalar_label_bd_9vouw_280() {
    let mut module = test_module_with_functions(
        vec![
            Ir3Instruction::SetPropertySloppy {
                obj: 0,
                key: 1,
                val: 2,
            },
            Ir3Instruction::Halt,
            Ir3Instruction::LoadThis { dst: 1 },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 0,
            },
            Ir3Instruction::CreateDataProperty {
                obj: 1,
                key: 2,
                val: 0,
            },
            Ir3Instruction::Return { value: 0 },
        ],
        vec![Ir3FunctionDesc {
            entry: 2,
            arity: 1,
            frame_size: 3,
            name: Some("capture_assigned_value".to_string()),
            is_generator: false,
            rest_param_index: None,
        }],
    );
    module.constant_pool.push("captured".into());
    let mut core = test_interpreter();
    let prototype = core
        .ensure_builtin_prototype("Object")
        .expect("Object prototype");
    core.set_object_runtime_property(
        prototype,
        RuntimePropertyKey::String("slot".into()),
        Value::Accessor {
            get: None,
            set: Some(Arc::new(Value::Function(0))),
        },
    )
    .expect("inherited setter");
    let object = core
        .alloc_object_with_properties(&[])
        .expect("ordinary object");
    core.write_reg_with_label(0, Value::Object(object), Label::Public)
        .unwrap();
    core.write_reg_with_label(1, Value::str("slot"), Label::Public)
        .unwrap();
    core.write_reg_with_label(2, Value::Int(42), Label::Secret)
        .unwrap();
    core.execute(&module).expect("inherited setter executes");
    assert_eq!(
        core.heap[object.0 as usize].properties.get("captured"),
        Some(&Value::Int(42))
    );
    assert_eq!(core.own_property_label(object, "captured"), Label::Secret);
    assert!(!core.heap[object.0 as usize].properties.contains_key("slot"));
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn inherited_setters_keep_backed_receiver_identity_and_labels_bd_9vouw_280() {
    for throws in [false, true] {
        let mut module = test_module_with_functions(
            vec![
                Ir3Instruction::SetPropertySloppy {
                    obj: 0,
                    key: 1,
                    val: 2,
                },
                Ir3Instruction::Halt,
                Ir3Instruction::LoadThis { dst: 1 },
                Ir3Instruction::LoadStr {
                    dst: 2,
                    pool_index: 0,
                },
                Ir3Instruction::SetPropertySloppy {
                    obj: 1,
                    key: 2,
                    val: 0,
                },
                Ir3Instruction::LoadStr {
                    dst: 2,
                    pool_index: 1,
                },
                Ir3Instruction::SetPropertySloppy {
                    obj: 1,
                    key: 2,
                    val: 1,
                },
                if throws {
                    Ir3Instruction::Throw { value: 0 }
                } else {
                    Ir3Instruction::Return { value: 0 }
                },
                Ir3Instruction::Return { value: 0 },
            ],
            vec![
                Ir3FunctionDesc {
                    entry: 2,
                    arity: 1,
                    frame_size: 3,
                    name: Some("capture_backed_receiver".to_string()),
                    is_generator: false,
                    rest_param_index: None,
                },
                Ir3FunctionDesc {
                    entry: 8,
                    arity: 0,
                    frame_size: 1,
                    name: Some("ordinary_receiver".to_string()),
                    is_generator: false,
                    rest_param_index: None,
                },
            ],
        );
        module.constant_pool = vec!["captured".into(), "seenThis".into()];
        for kind in 0..4 {
            let mut core = test_interpreter();
            let prototype = core
                .ensure_builtin_prototype("Object")
                .expect("Object prototype");
            let key = RuntimePropertyKey::String("slot".into());
            core.set_object_runtime_property(
                prototype,
                key.clone(),
                Value::Accessor {
                    get: None,
                    set: Some(Arc::new(Value::Function(0))),
                },
            )
            .expect("inherited setter");
            let receiver = match kind {
                0 => Value::BuiltinFunction(BuiltinFunction::new_kind(
                    BuiltinFunctionKind::ArrayIsArray,
                )),
                1 => Value::Function(1),
                2 => Value::Promise(core.create_promise().expect("promise receiver").0),
                _ => {
                    let emitter = core
                        .alloc_branded_object("EventEmitter", &[])
                        .expect("wrapper emitter");
                    core.create_event_once_wrapper(emitter, "tick", Value::Function(1), None)
                        .expect("callable once wrapper")
                        .0
                }
            };
            core.write_reg_with_label(0, receiver.clone(), Label::Public)
                .expect("original receiver register");
            core.write_reg_with_label(1, key.value(), Label::Public)
                .expect("key register");
            core.write_reg_with_label(2, Value::Int(42), Label::Secret)
                .expect("classified assigned value");
            let outcome = core.execute(&module);
            if throws {
                assert!(matches!(
                    outcome,
                    Err(InterpreterError::UncaughtException { .. })
                ));
                assert_eq!(core.pending_exception_label, Label::Secret);
            } else {
                outcome.expect("setter completed");
            }
            let backing = core
                .own_property_holder(Some(&module), &receiver, false)
                .expect("receiver lookup")
                .expect("receiver backing");
            assert_eq!(
                core.heap[backing.0 as usize].properties.get("seenThis"),
                Some(&receiver),
                "kind {kind}: setter must receive the original JavaScript identity"
            );
            assert_eq!(
                core.heap[backing.0 as usize].properties.get("captured"),
                Some(&Value::Int(42))
            );
            assert_eq!(core.own_property_label(backing, "captured"), Label::Secret);
            assert!(!core.heap[backing.0 as usize].contains_own_runtime_property(&key));
            assert_eq!(
                core.own_stored_runtime_property_label(backing, &key),
                Label::Public
            );
            assert_eq!(
                core.estimated_memory_bytes(),
                core.recompute_estimated_memory_bytes()
            );
        }
    }
}

/// A promise's own properties live on a backing object; a Secret value
/// stored there must read back Secret too (the read joins the backing
/// object's stored label, as bd-ojvo1 does for an object).
#[test]
fn promise_own_property_read_keeps_the_stored_label() {
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
    module.constant_pool.push("cancel".into());

    let mut core = test_interpreter();
    let promise = core
        .create_promise()
        .expect("test promise allocation should succeed");
    core.mutate_registers(|r| {
        r[0] = Value::Promise(promise.0);
        r[2] = Value::Int(42);
    });
    core.set_register_label(0, crate::ifc_artifacts::Label::Public)
        .expect("promise label should be settable");
    core.set_register_label(2, crate::ifc_artifacts::Label::Secret)
        .expect("written value label should be settable");

    core.execute(&module)
        .expect("set then get off a promise should execute");

    assert_eq!(core.read_reg(3).expect("dst register"), Value::Int(42));
    assert_eq!(
        core.get_register_label(3)
            .expect("dst register label should exist"),
        &crate::ifc_artifacts::Label::Secret,
        "a Secret value written to a promise's own property must read back Secret"
    );
}

/// for-of binds each element out of the iterable; the loop variable must
/// inherit the iterable's IFC label so `for (const x of secret) egress(x)`
/// cannot launder the taint. Sibling of the reduce/array-from callback-lane
/// fix (bd-ooaka.1) and the GetProperty join (bd-0zybl): before the fix
/// `ForOfInit`/`ForOfNext` wrote their dst via `write_reg` without touching
/// `register_labels`, so the element landed at the dst's stale prior label.
#[test]
fn for_of_propagates_iterable_label_to_loop_variable() {
    let module = test_module_with_functions(
        vec![
            Ir3Instruction::ForOfInit { src: 0, dst: 1 },
            Ir3Instruction::ForOfNext {
                iterator: 1,
                value_dst: 2,
                done_target: 3,
            },
            Ir3Instruction::Halt,
        ],
        vec![],
    );

    let mut core = test_interpreter();
    let secret_arr = core
        .alloc_array_from_values(&[Value::Int(7), Value::Int(8)])
        .expect("array allocation should succeed");
    core.mutate_registers(|r| {
        r[0] = Value::Object(secret_arr);
    });
    core.set_register_label(0, crate::ifc_artifacts::Label::Secret)
        .expect("iterable label should be settable");
    // Seed the loop-variable dst strictly below Secret to prove the bind
    // raises it; a no-op propagation would leave it Public.
    core.set_register_label(2, crate::ifc_artifacts::Label::Public)
        .expect("dst label should be settable");

    core.execute(&module)
        .expect("for-of over a secret array should execute");

    assert_eq!(
        core.get_register_label(2)
            .expect("loop-variable label should exist"),
        &crate::ifc_artifacts::Label::Secret,
        "for-of loop variable must inherit (join) the iterable's label"
    );
}

/// bd-9vouw.70: for-of over an array whose @@iterator is the intrinsic
/// `ArrayValues` gets the label the isolated call of that method returns,
/// for every combination of inherited callback context and lookup label
/// (including same-level Custom labels that differ only by name), and its
/// array-backed consumption record yields what stepping the iterator that
/// call returns yields.
#[test]
fn intrinsic_array_values_matches_the_isolated_call_bd_9vouw_70() {
    use crate::ifc_artifacts::Label;
    let module = test_module_with_functions(vec![Ir3Instruction::Halt], vec![]);
    let custom = |name: &str| Label::Custom {
        name: name.to_string(),
        level: 3,
    };
    let contexts = [
        None,
        Some(Label::Public),
        Some(Label::Secret),
        Some(custom("a")),
    ];
    let lookups = [
        None,
        Some(Label::Public),
        Some(Label::Internal),
        Some(Label::Secret),
        Some(custom("b")),
        Some(Label::TopSecret),
    ];
    let array_values =
        Value::BuiltinFunction(BuiltinFunction::new_kind(BuiltinFunctionKind::ArrayValues));
    for context in &contexts {
        for lookup in &lookups {
            let mut core = test_interpreter();
            let array = core
                .alloc_array_from_values(&[Value::Int(1), Value::Int(2), Value::Int(3)])
                .expect("array allocation");
            core.active_inline_callback_context_label = context.clone();
            core.sync_estimated_memory_bytes()
                .expect("callback-context accounting");
            let (isolated, isolated_label) = core
                .invoke_inline_method_call_with_argument_label(
                    Some(&module),
                    array_values.clone(),
                    Value::Object(array),
                    Vec::new(),
                    lookup.clone(),
                )
                .expect("isolated ArrayValues call");
            let direct_label = core.intrinsic_array_values_label(array, lookup.clone());
            assert_eq!(
                direct_label, isolated_label,
                "context {context:?}, lookup {lookup:?}"
            );
            let Value::Iterator(isolated) = isolated else {
                panic!("ArrayValues returns an iterator");
            };
            let mut sequences = Vec::new();
            for init in [
                RuntimeForOfInit::from_existing(isolated),
                RuntimeForOfInit::from_array(array),
            ] {
                let record = core
                    .init_iterator_from_state(Value::Object(array), init, IterationKind::ForOf)
                    .expect("consumption record");
                let mut values = Vec::new();
                while let Some(value) = core
                    .advance_for_of_iterator(Some(&module), record.clone())
                    .expect("step")
                {
                    values.push(value);
                }
                assert_eq!(
                    core.advance_for_of_iterator(Some(&module), record)
                        .expect("step after done"),
                    None
                );
                sequences.push(values);
            }
            assert_eq!(
                sequences[0],
                vec![Value::Int(1), Value::Int(2), Value::Int(3)]
            );
            assert_eq!(sequences[0], sequences[1]);
            assert_eq!(core.active_inline_callback_context_label, *context);
            assert_eq!(
                core.estimated_memory_bytes(),
                core.recompute_estimated_memory_bytes()
            );
        }
    }
}

/// bd-l0d6z: a thrown value's label must survive the throw->catch edge.
/// Before the fix `Throw` stored only the bare `Value` into
/// `pending_exception` and `EnterCatch` wrote it to the catch binding via
/// `write_reg` without touching `register_labels[dst]` — so
/// `try { throw secret } catch (e) { egress(e) }` laundered a Secret value
/// to the dst's stale prior label (typically Public). Fifth member of the
/// bd-n2mjy/bd-0zybl under-tainting family.
#[test]
fn throw_propagates_thrown_value_label_to_catch_binding() {
    let module = test_module_with_functions(
        vec![
            Ir3Instruction::BeginTry {
                catch_target: 2,
                finally_target: None,
            },
            Ir3Instruction::Throw { value: 0 },
            Ir3Instruction::EnterCatch { dst: 1 },
            Ir3Instruction::Halt,
        ],
        vec![],
    );

    let mut core = test_interpreter();
    core.mutate_registers(|r| {
        r[0] = Value::str("secret-token".to_string());
    });
    core.set_register_label(0, crate::ifc_artifacts::Label::Secret)
        .expect("thrown register label should be settable");
    // Seed the catch binding strictly below Secret to prove EnterCatch
    // re-establishes the thrown value's label (the bd-l0d6z bug left it
    // at this stale Public).
    core.set_register_label(1, crate::ifc_artifacts::Label::Public)
        .expect("catch binding label should be settable");

    core.execute(&module)
        .expect("throw inside try should reach the catch handler");

    assert_eq!(
        core.registers[1],
        Value::str("secret-token".to_string()),
        "catch binding must receive the thrown value"
    );
    assert_eq!(
        core.get_register_label(1)
            .expect("catch binding label should exist"),
        &crate::ifc_artifacts::Label::Secret,
        "catch binding must inherit the thrown value's label (bd-l0d6z)"
    );
}

/// bd-l0d6z: the catch-binding label is the THROWN value's label exactly —
/// a later, lower-labelled throw must not inherit an earlier exception's
/// higher label (no cross-contamination through the pending-exception
/// shadow), and a stale higher label on the binding register is
/// overwritten because the binding's new content is exactly the thrown
/// value (fresh provenance, mirroring the zero-arg HostCall reset).
#[test]
fn sequential_catches_use_each_thrown_values_own_label() {
    let module = test_module_with_functions(
        vec![
            Ir3Instruction::BeginTry {
                catch_target: 2,
                finally_target: None,
            },
            Ir3Instruction::Throw { value: 0 },
            Ir3Instruction::EnterCatch { dst: 1 },
            Ir3Instruction::BeginTry {
                catch_target: 5,
                finally_target: None,
            },
            Ir3Instruction::Throw { value: 2 },
            Ir3Instruction::EnterCatch { dst: 3 },
            Ir3Instruction::Halt,
        ],
        vec![],
    );

    let mut core = test_interpreter();
    core.mutate_registers(|r| {
        r[0] = Value::str("secret-token".to_string());
        r[2] = Value::Int(7);
    });
    core.set_register_label(0, crate::ifc_artifacts::Label::Secret)
        .expect("first thrown label should be settable");
    core.set_register_label(2, crate::ifc_artifacts::Label::Public)
        .expect("second thrown label should be settable");
    // Seed the second catch binding ABOVE the second thrown value's label
    // to prove EnterCatch overwrites with the thrown value's own label.
    core.set_register_label(3, crate::ifc_artifacts::Label::Confidential)
        .expect("second catch binding label should be settable");

    core.execute(&module)
        .expect("both throws should reach their catch handlers");

    assert_eq!(
        core.get_register_label(1)
            .expect("first catch binding label should exist"),
        &crate::ifc_artifacts::Label::Secret,
        "first catch binding carries the Secret thrown label"
    );
    assert_eq!(core.registers[3], Value::Int(7));
    assert_eq!(
        core.get_register_label(3)
            .expect("second catch binding label should exist"),
        &crate::ifc_artifacts::Label::Public,
        "second catch binding must carry the second thrown value's own \
             label, not the earlier Secret exception's"
    );
}

/// bd-ooaka.1: a receiver-aware builtin's result must inherit the
/// receiver's label. `arr.reduce(cb, 0)` on a Secret-labeled array runs
/// the callback mini-lane (which tracks no labels internally) and used to
/// write the result via `write_reg` with no label propagation — so a
/// Secret array laundered to a stale Public dst, the same family as
/// bd-0zybl/bd-n2mjy. The fix joins receiver + arg labels onto dst at
/// the CallMethod builtin dispatch (a sound upper bound for anything the
/// mini-lane computes, since the lane only sees values seeded from those
/// registers).
#[test]
fn builtin_method_result_inherits_receiver_label() {
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
            Ir3Instruction::CallMethod {
                receiver: 0,
                callee: 2,
                args: RegRange { start: 8, count: 2 },
                dst: 3,
            },
            Ir3Instruction::Halt,
            // Reducer callback body: (acc, cur) => acc + cur.
            Ir3Instruction::Add {
                dst: 4,
                lhs: 0,
                rhs: 1,
            },
            Ir3Instruction::Return { value: 4 },
        ],
        vec![Ir3FunctionDesc {
            entry: 4,
            arity: 4,
            frame_size: 5,
            name: Some("reducer".to_string()),
            is_generator: false,
            rest_param_index: None,
        }],
    );
    module.constant_pool.push("reduce".into());

    let mut core = test_interpreter();
    let array_id = core
        .alloc_array_from_values(&[Value::Int(1), Value::Int(2), Value::Int(3)])
        .expect("array allocation should succeed");
    core.mutate_registers(|r| {
        r[0] = Value::Object(array_id);
        r[8] = Value::Function(0);
        r[9] = Value::Int(0);
    });
    core.set_register_label(0, crate::ifc_artifacts::Label::Secret)
        .expect("receiver label should be settable");
    // Seed dst strictly below Secret to prove the dispatch raises it.
    core.set_register_label(3, crate::ifc_artifacts::Label::Public)
        .expect("dst label should be settable");

    core.execute(&module)
        .expect("reduce over a secret array should execute");

    assert_eq!(
        core.registers[3],
        Value::Int(6),
        "reduce must compute 1 + 2 + 3"
    );
    assert_eq!(
        core.get_register_label(3)
            .expect("dst register label should exist"),
        &crate::ifc_artifacts::Label::Secret,
        "builtin method result must inherit the receiver's label (bd-ooaka.1)"
    );
}

/// bd-8enww.4.8 (IFC soundness for the value-fidelity fix): the legacy
/// reduce mini-lane now preserves a callback's explicitly-thrown value —
/// which can be a real element of the receiver array. Because the mini-lane
/// tracks no per-register labels, the `CallMethod` throw-path join must raise
/// the caught binding to the receiver's label; otherwise a Secret array whose
/// reducer throws one of its elements would launder that element to a Public
/// catch binding. This is the throw-path sibling of
/// `builtin_method_result_inherits_receiver_label` (the success path).
#[test]
fn reducer_explicit_throw_over_secret_array_taints_catch_binding() {
    let mut module = test_module_with_functions(
        vec![
            // try { r3 = arr.reduce(reducer, 0) } catch (r1) { }
            Ir3Instruction::BeginTry {
                catch_target: 4,
                finally_target: None,
            },
            Ir3Instruction::LoadStr {
                dst: 1,
                pool_index: 0,
            },
            Ir3Instruction::GetProperty {
                obj: 0,
                key: 1,
                dst: 2,
            },
            Ir3Instruction::CallMethod {
                receiver: 0,
                callee: 2,
                args: RegRange { start: 8, count: 2 },
                dst: 3,
            },
            Ir3Instruction::EnterCatch { dst: 1 },
            Ir3Instruction::Halt,
            // Reducer callback body: throw the current element (local reg 1).
            Ir3Instruction::Throw { value: 1 },
        ],
        vec![Ir3FunctionDesc {
            entry: 6,
            arity: 4,
            frame_size: 5,
            name: Some("throwing_reducer".to_string()),
            is_generator: false,
            rest_param_index: None,
        }],
    );
    module.constant_pool.push("reduce".into());

    let mut core = test_interpreter();
    let array_id = core
        .alloc_array_from_values(&[Value::Int(1), Value::Int(2), Value::Int(3)])
        .expect("array allocation should succeed");
    core.mutate_registers(|r| {
        r[0] = Value::Object(array_id);
        r[8] = Value::Function(0);
        r[9] = Value::Int(0);
    });
    core.set_register_label(0, crate::ifc_artifacts::Label::Secret)
        .expect("receiver label should be settable");
    // Seed the catch binding strictly below Secret to prove the throw-path
    // join raises it (a no-op would leave it at this stale Public).
    core.set_register_label(1, crate::ifc_artifacts::Label::Public)
        .expect("catch binding label should be settable");

    core.execute(&module)
        .expect("a reducer that throws should be caught in-frame");

    // The reducer threw its current element (the first element, Int(1), with
    // accumulator seeded to 0); the catch binding holds it verbatim...
    assert_eq!(
        core.registers[1],
        Value::Int(1),
        "the catch binding must hold the reducer's thrown element verbatim"
    );
    // ...and carries at least the receiver's Secret label (no laundering).
    assert_eq!(
        core.get_register_label(1)
            .expect("catch binding label should exist"),
        &crate::ifc_artifacts::Label::Secret,
        "an explicit reducer throw over a Secret array must taint the catch binding"
    );
}

/// bd-8enww.4.10 (IFC soundness for the hostcall-path catchability fix): the
/// array-literal `[…].some(cb)` fast-path dispatches through the `HostCall`
/// IR3 instruction (`builtin:ArrayPrototypeSome`), not `CallMethod`. When the
/// predicate explicitly throws one of the receiver array's elements, the new
/// throw-path join at the `builtin:` hostcall arm must raise the caught
/// binding to the join of the arg-register labels (which include the receiver
/// array as arg 0); otherwise a Secret array whose predicate throws an element
/// would launder that element to a Public catch binding. Throw-path sibling of
/// the CallMethod-side `reducer_explicit_throw_over_secret_array_taints_catch_binding`.
#[test]
fn array_hostcall_explicit_throw_over_secret_array_taints_catch_binding() {
    let module = test_module_with_functions(
        vec![
            // try { r3 = some_hostcall(arr, predicate) } catch (r1) { }
            Ir3Instruction::BeginTry {
                catch_target: 3,
                finally_target: None,
            },
            Ir3Instruction::HostCall {
                capability: CapabilityTag("builtin:ArrayPrototypeSome".to_string()),
                args: RegRange { start: 8, count: 2 },
                dst: 3,
            },
            Ir3Instruction::Halt,
            Ir3Instruction::EnterCatch { dst: 1 },
            Ir3Instruction::Halt,
            // Predicate callback body: throw the current element (local reg 0).
            Ir3Instruction::Throw { value: 0 },
        ],
        vec![Ir3FunctionDesc {
            entry: 5,
            arity: 3,
            frame_size: 5,
            name: Some("throwing_predicate".to_string()),
            is_generator: false,
            rest_param_index: None,
        }],
    );

    let mut core = test_interpreter();
    core.config
        .granted_capabilities
        .insert(RuntimeCapability::Builtin);
    let array_id = core
        .alloc_array_from_values(&[Value::Int(1), Value::Int(2), Value::Int(3)])
        .expect("array allocation should succeed");
    core.mutate_registers(|r| {
        r[8] = Value::Object(array_id);
        r[9] = Value::Function(0);
    });
    core.set_register_label(8, crate::ifc_artifacts::Label::Secret)
        .expect("receiver (arg 0) label should be settable");
    // Seed the catch binding strictly below Secret to prove the throw-path
    // join raises it (a no-op would leave it at this stale Public).
    core.set_register_label(1, crate::ifc_artifacts::Label::Public)
        .expect("catch binding label should be settable");

    core.execute(&module)
        .expect("a predicate that throws should be caught in-frame");

    // The predicate threw its current element (the first, Int(1)); the catch
    // binding holds it verbatim...
    assert_eq!(
        core.registers[1],
        Value::Int(1),
        "the catch binding must hold the predicate's thrown element verbatim"
    );
    // ...and carries at least the receiver's Secret label (no laundering).
    assert_eq!(
        core.get_register_label(1)
            .expect("catch binding label should exist"),
        &crate::ifc_artifacts::Label::Secret,
        "an explicit predicate throw over a Secret array (hostcall path) must taint the catch binding"
    );
}

/// bd-ooaka.1: the join covers arg-derived taint too — a Public receiver
/// with a Secret arg (e.g. a Secret initial accumulator) must still
/// produce a Secret-labeled result.
#[test]
fn builtin_method_result_joins_arg_labels() {
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
            Ir3Instruction::CallMethod {
                receiver: 0,
                callee: 2,
                args: RegRange { start: 8, count: 2 },
                dst: 3,
            },
            Ir3Instruction::Halt,
            Ir3Instruction::Add {
                dst: 4,
                lhs: 0,
                rhs: 1,
            },
            Ir3Instruction::Return { value: 4 },
        ],
        vec![Ir3FunctionDesc {
            entry: 4,
            arity: 4,
            frame_size: 5,
            name: Some("reducer".to_string()),
            is_generator: false,
            rest_param_index: None,
        }],
    );
    module.constant_pool.push("reduce".into());

    let mut core = test_interpreter();
    let array_id = core
        .alloc_array_from_values(&[Value::Int(1), Value::Int(2)])
        .expect("array allocation should succeed");
    core.mutate_registers(|r| {
        r[0] = Value::Object(array_id);
        r[8] = Value::Function(0);
        r[9] = Value::Int(10);
    });
    // Public receiver, Secret initial accumulator (arg register 9).
    core.set_register_label(9, crate::ifc_artifacts::Label::Secret)
        .expect("arg label should be settable");

    core.execute(&module)
        .expect("reduce with secret initial value should execute");

    assert_eq!(core.registers[3], Value::Int(13));
    assert_eq!(
        core.get_register_label(3)
            .expect("dst register label should exist"),
        &crate::ifc_artifacts::Label::Secret,
        "builtin method result must join arg labels (bd-ooaka.1)"
    );
}

/// bd-0zybl family: a template literal's output is derived from every
/// part, so `` `${secret}` `` must carry the secret part's label. Before
/// the fix `TemplateLiteral` wrote the concatenated string via `write_reg`
/// and left the dst register's stale prior label in place — the same
/// under-tainting laundering hole as GetProperty/HostCall.
#[test]
fn template_literal_joins_part_labels_onto_dst() {
    let module = test_module_with_functions(
        vec![
            Ir3Instruction::TemplateLiteral {
                parts: RegRange { start: 0, count: 2 },
                dst: 2,
            },
            Ir3Instruction::Halt,
        ],
        vec![],
    );

    let mut core = test_interpreter();
    core.mutate_registers(|r| {
        r[0] = Value::str("prefix-".to_string());
        r[1] = Value::str("secret-suffix".to_string());
    });
    core.set_register_label(1, crate::ifc_artifacts::Label::Secret)
        .expect("part label should be settable");
    // Seed dst strictly below Secret to prove the join raises it.
    core.set_register_label(2, crate::ifc_artifacts::Label::Public)
        .expect("dst label should be settable");

    core.execute(&module)
        .expect("template literal should execute");

    assert_eq!(
        core.get_register_label(2)
            .expect("dst register label should exist"),
        &crate::ifc_artifacts::Label::Secret,
        "TemplateLiteral dst must inherit join(parts' labels)"
    );
}

/// ES2015 §22.1.3.3: `copyWithin` clamps non-negative `target`/`start` to
/// `len` (inclusive), not `len - 1`. Before the fix, `copyWithin(len, 0)`
/// overwrote the last element instead of being a no-op, and on an empty
/// array the `min(len - 1)` clamp produced index `-1`, inserting a bogus
/// `"-1"` property.
#[test]
fn copy_within_clamps_target_and_start_to_length() {
    let module = test_module_with_functions(
        vec![
            Ir3Instruction::HostCall {
                capability: CapabilityTag("builtin:ArrayPrototypeCopyWithin".to_string()),
                args: RegRange { start: 0, count: 3 },
                dst: 3,
            },
            Ir3Instruction::Halt,
        ],
        vec![],
    );

    let mut core = test_interpreter();
    core.config
        .granted_capabilities
        .insert(RuntimeCapability::Builtin);
    let arr = core
        .alloc_array_from_values(&[
            Value::Int(10),
            Value::Int(20),
            Value::Int(30),
            Value::Int(40),
            Value::Int(50),
        ])
        .expect("test array allocation should succeed");
    core.mutate_registers(|r| {
        r[0] = Value::Object(arr);
        r[1] = Value::Int(5); // target == length → must be a no-op
        r[2] = Value::Int(0); // start
    });

    core.execute(&module)
        .expect("copyWithin hostcall should execute");

    let last = core
        .heap
        .get(arr.0 as usize)
        .and_then(|obj| obj.properties.get("4"))
        .cloned();
    assert_eq!(
        last,
        Some(Value::Int(50)),
        "copyWithin(len, 0) must be a no-op, not overwrite the last element"
    );

    // Empty array: copyWithin(0, 0) must not synthesize a "-1" property.
    let empty = core
        .alloc_array_from_values(&[])
        .expect("empty array allocation should succeed");
    core.mutate_registers(|r| {
        r[0] = Value::Object(empty);
        r[1] = Value::Int(0);
        r[2] = Value::Int(0);
    });
    core.execute(&module)
        .expect("copyWithin on empty array should execute");
    let bogus = core
        .heap
        .get(empty.0 as usize)
        .and_then(|obj| obj.properties.get("-1"))
        .cloned();
    assert_eq!(
        bogus, None,
        "copyWithin on an empty array must not insert a \"-1\" property"
    );
}

/// The legacy `builtin:ArrayPrototypeSplice` capability-dispatch path
/// (reached when `splice` is invoked as a bare builtin function value,
/// `map_function_index_to_builtin_capability` → `dispatch_builtin_hostcall`)
/// rewrites the array densely but must also refresh the dense-length cache.
/// Before the fix it left `cached_dense_length` at the PRE-splice length, so
/// a subsequent `ArrayPush` (which trusts the cache as the next write index)
/// appended past the end. The modern receiver-aware `ArraySplice` already
/// refreshes the cache; this pins the legacy path to the same invariant.
#[test]
fn legacy_splice_dispatch_refreshes_dense_length_cache() {
    let mut core = test_interpreter();
    core.config
        .granted_capabilities
        .insert(RuntimeCapability::Builtin);
    let arr = core
        .alloc_array_from_values(&[
            Value::Int(1),
            Value::Int(2),
            Value::Int(3),
            Value::Int(4),
            Value::Int(5),
        ])
        .expect("array allocation should succeed");
    // Pre-condition: dense cache reflects the original length.
    assert_eq!(
        core.heap
            .get(arr.0 as usize)
            .and_then(|o| o.cached_dense_length),
        Some(5)
    );

    // splice(start=0, deleteCount=3) — this at args.start, start at +1,
    // deleteCount at +2.
    core.mutate_registers(|r| {
        r[0] = Value::Object(arr);
        r[1] = Value::Int(0);
        r[2] = Value::Int(3);
    });
    core.dispatch_builtin_hostcall(
        "builtin:ArrayPrototypeSplice",
        RegRange { start: 0, count: 3 },
        None,
    )
    .expect("legacy splice dispatch should succeed");

    let obj = core.heap.get(arr.0 as usize).expect("array still on heap");
    assert_eq!(
        obj.properties.get("length"),
        Some(&Value::Int(2)),
        "splice must shrink length to 2"
    );
    assert_eq!(
        obj.cached_dense_length,
        Some(2),
        "the dense-length cache must follow splice's new length, not stay stale at 5"
    );
}

#[test]
fn array_length_truncation_classification_skips_growth_scans() {
    let mut object = HeapObject {
        is_array: true,
        ..Default::default()
    };
    object.properties.insert("0".to_string(), Value::Int(10));
    object.properties.insert("1".to_string(), Value::Int(20));
    object.properties.insert("2".to_string(), Value::Int(30));
    object
        .properties
        .insert("named".to_string(), Value::Int(40));
    object
        .properties
        .insert(u32::MAX.to_string(), Value::Int(50));
    object
        .properties
        .insert("length".to_string(), Value::Int(3));
    object.cached_dense_length = Some(3);

    assert_eq!(
        InterpreterCore::array_length_truncation_keys(&object, 4),
        None,
        "known growth must not enumerate existing array properties"
    );
    assert_eq!(
        InterpreterCore::array_length_truncation_keys(&object, 3),
        Some(Vec::new()),
        "an unchanged low-level length must retain conservative enumeration"
    );
    assert_eq!(
        InterpreterCore::array_length_truncation_keys(&object, 1),
        Some(vec!["1".to_string(), "2".to_string()]),
        "shrink must retain the exact canonical index deletion set"
    );

    object
        .properties
        .insert("length".to_string(), Value::str("malformed"));
    assert_eq!(
        InterpreterCore::array_length_truncation_keys(&object, 1),
        Some(vec!["1".to_string(), "2".to_string()]),
        "malformed prior length must preserve conservative enumeration"
    );

    object
        .properties
        .insert("length".to_string(), Value::Int(3));
    object.properties.insert("5".to_string(), Value::Int(60));
    object.cached_dense_length = None;
    assert_eq!(
        InterpreterCore::array_length_truncation_keys(&object, 4),
        Some(vec!["5".to_string()]),
        "an untrusted sparse state must scan even when the visible length grows"
    );
}

#[test]
fn public_sparse_array_state_keeps_conservative_length_truncation() {
    let mut core = test_interpreter();
    let array = core
        .alloc_array_with_prototype(None)
        .expect("array allocation should succeed");
    core.set_object_property(array, "length".to_string(), Value::Int(3))
        .expect("initial length write should succeed");
    core.set_object_property(array, "5".to_string(), Value::Int(50))
        .expect("low-level sparse index write should succeed");
    assert_eq!(
        core.heap[array.0 as usize].cached_dense_length, None,
        "a low-level out-of-bounds index must invalidate dense-length trust"
    );

    core.set_object_property(array, "length".to_string(), Value::Int(4))
        .expect("length growth over an untrusted sparse state should succeed");
    let object = &core.heap[array.0 as usize];
    assert_eq!(object.properties.get("5"), None);
    assert_eq!(object.properties.get("length"), Some(&Value::Int(4)));
}

#[test]
fn public_boundary_index_keeps_conservative_equal_length_truncation() {
    let mut core = test_interpreter();
    let array = core
        .alloc_array_with_prototype(None)
        .expect("array allocation should succeed");
    core.set_object_property(array, "length".to_string(), Value::Int(3))
        .expect("initial length write should succeed");
    core.set_object_property(array, "3".to_string(), Value::Int(30))
        .expect("low-level boundary index write should succeed");
    assert_eq!(
        core.heap[array.0 as usize].cached_dense_length,
        Some(3),
        "the low-level boundary write demonstrates why equality cannot use the shortcut"
    );

    core.set_object_property(array, "length".to_string(), Value::Int(3))
        .expect("equal length write should succeed");
    let object = &core.heap[array.0 as usize];
    assert_eq!(object.properties.get("3"), None);
    assert_eq!(object.properties.get("length"), Some(&Value::Int(3)));
}

/// Index assignment at `arr.length` must grow the ES array length and the
/// dense-length cache so a following `ArrayPush` appends past the new
/// element instead of overwriting it. Before the fix `SetProperty` left
/// both stale, so `a[3] = 40; a.push(50)` lost the `40` (push wrote 50 at
/// the stale cache index 3) and reported length 4 — a sibling of the
/// splice dense-cache bug.
#[test]
fn array_index_append_then_push_keeps_both_elements() {
    let mut core = test_interpreter();
    let arr = core
        .alloc_array_from_values(&[Value::Int(10), Value::Int(20), Value::Int(30)])
        .expect("array allocation should succeed");
    core.mutate_registers(|r| {
        r[0] = Value::Object(arr);
        r[1] = Value::Int(3); // key index 3 (== length)
        r[2] = Value::Int(40); // value
        r[3] = Value::Int(50); // push value
    });
    let module = test_module_with_functions(
        vec![
            Ir3Instruction::SetProperty {
                obj: 0,
                key: 1,
                val: 2,
            },
            Ir3Instruction::ArrayPush {
                array: 0,
                element: 3,
            },
            Ir3Instruction::Halt,
        ],
        vec![],
    );
    core.execute(&module)
        .expect("index append + push should execute");
    let obj = core.heap.get(arr.0 as usize).expect("array on heap");
    assert_eq!(
        obj.properties.get("3"),
        Some(&Value::Int(40)),
        "a[3] must keep 40"
    );
    assert_eq!(
        obj.properties.get("4"),
        Some(&Value::Int(50)),
        "push must append 50 at index 4"
    );
    assert_eq!(
        obj.properties.get("length"),
        Some(&Value::Int(5)),
        "length must be 5 after one index append and one push"
    );
    assert_eq!(
        obj.cached_dense_length,
        Some(5),
        "dense cache must track the true length"
    );
}

/// Index assignment past the end makes the array sparse: `length` grows to
/// `index + 1` but the dense-length cache is invalidated so the
/// `ArrayPush` fast path falls back to a scan rather than trusting a stale
/// dense length.
#[test]
fn array_index_assignment_past_end_grows_length_and_invalidates_cache() {
    let mut core = test_interpreter();
    let arr = core
        .alloc_array_from_values(&[Value::Int(1), Value::Int(2)])
        .expect("array allocation should succeed");
    core.mutate_registers(|r| {
        r[0] = Value::Object(arr);
        r[1] = Value::Int(5); // gap: skips indices 2,3,4
        r[2] = Value::Int(99);
    });
    let module = test_module_with_functions(
        vec![
            Ir3Instruction::SetProperty {
                obj: 0,
                key: 1,
                val: 2,
            },
            Ir3Instruction::Halt,
        ],
        vec![],
    );
    core.execute(&module)
        .expect("sparse index set should execute");
    let obj = core.heap.get(arr.0 as usize).expect("array on heap");
    assert_eq!(
        obj.properties.get("length"),
        Some(&Value::Int(6)),
        "length must grow to index+1 even for a sparse gap"
    );
    assert_eq!(
        obj.cached_dense_length, None,
        "a sparse gap must invalidate the dense-length cache"
    );
}

/// In-bounds overwrite (`arr[i] = x` with `i < length`) changes neither the
/// length nor the dense-length cache.
#[test]
fn array_index_in_bounds_overwrite_leaves_length_and_cache() {
    let mut core = test_interpreter();
    let arr = core
        .alloc_array_from_values(&[Value::Int(1), Value::Int(2), Value::Int(3)])
        .expect("array allocation should succeed");
    core.mutate_registers(|r| {
        r[0] = Value::Object(arr);
        r[1] = Value::Int(1);
        r[2] = Value::Int(99);
    });
    let module = test_module_with_functions(
        vec![
            Ir3Instruction::SetProperty {
                obj: 0,
                key: 1,
                val: 2,
            },
            Ir3Instruction::Halt,
        ],
        vec![],
    );
    core.execute(&module).expect("overwrite should execute");
    let obj = core.heap.get(arr.0 as usize).expect("array on heap");
    assert_eq!(obj.properties.get("1"), Some(&Value::Int(99)));
    assert_eq!(
        obj.properties.get("length"),
        Some(&Value::Int(3)),
        "length unchanged"
    );
    assert_eq!(obj.cached_dense_length, Some(3), "dense cache unchanged");
}

#[test]
fn array_u32_max_property_does_not_extend_length_before_push() {
    let mut core = test_interpreter();
    let arr = core
        .alloc_array_from_values(&[])
        .expect("array allocation should succeed");
    core.mutate_registers(|r| {
        r[0] = Value::Object(arr);
        r[1] = Value::str("4294967295");
        r[2] = Value::Int(1);
        r[3] = Value::Int(2);
    });
    let module = test_module_with_functions(
        vec![
            Ir3Instruction::SetProperty {
                obj: 0,
                key: 1,
                val: 2,
            },
            Ir3Instruction::ArrayPush {
                array: 0,
                element: 3,
            },
            Ir3Instruction::Halt,
        ],
        vec![],
    );

    core.execute(&module)
        .expect("u32::MAX ordinary property + push should execute");

    let obj = core.heap.get(arr.0 as usize).expect("array on heap");
    assert_eq!(
        obj.properties.get("4294967295"),
        Some(&Value::Int(1)),
        "u32::MAX key must remain an ordinary property"
    );
    assert_eq!(
        obj.properties.get("0"),
        Some(&Value::Int(2)),
        "push must append at index 0, not after u32::MAX"
    );
    assert_eq!(
        obj.properties.get("length"),
        Some(&Value::Int(1)),
        "u32::MAX key must not extend array length"
    );
}

#[test]
fn promise_then_fulfillment_handler_transforms_value() {
    let module = test_module_with_functions(
        vec![
            Ir3Instruction::HostCall {
                capability: CapabilityTag("promise:resolve".to_string()),
                args: RegRange { start: 0, count: 1 },
                dst: 1,
            },
            Ir3Instruction::HostCall {
                capability: CapabilityTag("promise:then".to_string()),
                args: RegRange { start: 1, count: 2 },
                dst: 4,
            },
            Ir3Instruction::Halt,
            Ir3Instruction::LoadInt { dst: 1, value: 5 },
            Ir3Instruction::Add {
                dst: 0,
                lhs: 0,
                rhs: 1,
            },
            Ir3Instruction::Return { value: 0 },
        ],
        vec![Ir3FunctionDesc {
            entry: 3,
            arity: 1,
            frame_size: 2,
            name: Some("plus_five".to_string()),
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
        r[0] = Value::Int(7);
    });
    core.mutate_registers(|r| {
        r[2] = Value::Closure(0);
    });

    core.execute(&module)
        .expect("promise handler should execute during microtask drain");

    assert_eq!(
        promise_state_for_register(&core, 4),
        crate::promise_model::PromiseState::Fulfilled(crate::object_model::JsValue::Int(12))
    );
}

#[test]
fn promise_then_rejection_handler_recovers_value() {
    let mut module = test_module_with_functions(
        vec![
            Ir3Instruction::HostCall {
                capability: CapabilityTag("promise:reject".to_string()),
                args: RegRange { start: 0, count: 1 },
                dst: 1,
            },
            Ir3Instruction::HostCall {
                capability: CapabilityTag("promise:then".to_string()),
                args: RegRange { start: 1, count: 3 },
                dst: 4,
            },
            Ir3Instruction::Halt,
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::Return { value: 0 },
        ],
        vec![Ir3FunctionDesc {
            entry: 3,
            arity: 1,
            frame_size: 1,
            name: Some("recover".to_string()),
            is_generator: false,
            rest_param_index: None,
        }],
    );
    module.constant_pool.push("recovered".into());

    let mut core = test_interpreter();
    core.closures.push(ClosureValue {
        function_index: 0,
        captured_env: Vec::new(),
    });
    core.mutate_registers(|r| {
        r[0] = Value::str("bad");
        r[2] = Value::Undefined;
        r[3] = Value::Closure(0);
    });

    core.execute(&module)
        .expect("rejection handler should execute during microtask drain");

    assert_eq!(
        promise_state_for_register(&core, 4),
        crate::promise_model::PromiseState::Fulfilled(crate::object_model::JsValue::Str(
            "recovered".to_string()
        ))
    );
}

#[test]
fn promise_then_throwing_handler_rejects_result_promise() {
    let mut module = test_module_with_functions(
        vec![
            Ir3Instruction::HostCall {
                capability: CapabilityTag("promise:resolve".to_string()),
                args: RegRange { start: 0, count: 1 },
                dst: 1,
            },
            Ir3Instruction::HostCall {
                capability: CapabilityTag("promise:then".to_string()),
                args: RegRange { start: 1, count: 2 },
                dst: 4,
            },
            Ir3Instruction::Halt,
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::Throw { value: 0 },
        ],
        vec![Ir3FunctionDesc {
            entry: 3,
            arity: 1,
            frame_size: 1,
            name: Some("throws".to_string()),
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
        r[0] = Value::Int(7);
    });
    core.mutate_registers(|r| {
        r[2] = Value::Closure(0);
    });

    core.execute(&module)
        .expect("throwing promise handler should reject result promise");

    assert_eq!(
        promise_state_for_register(&core, 4),
        crate::promise_model::PromiseState::Rejected(crate::object_model::JsValue::Str(
            "boom".to_string()
        ))
    );
}

#[test]
fn promise_then_absent_handlers_preserve_identity_and_rejection() {
    let fulfilled_module = test_module_with_functions(
        vec![
            Ir3Instruction::HostCall {
                capability: CapabilityTag("promise:resolve".to_string()),
                args: RegRange { start: 0, count: 1 },
                dst: 1,
            },
            Ir3Instruction::HostCall {
                capability: CapabilityTag("promise:then".to_string()),
                args: RegRange { start: 1, count: 1 },
                dst: 4,
            },
            Ir3Instruction::Halt,
        ],
        Vec::new(),
    );
    let mut fulfilled_core = test_interpreter();
    fulfilled_core.mutate_registers(|r| {
        r[0] = Value::Int(7);
    });
    fulfilled_core
        .execute(&fulfilled_module)
        .expect("absent fulfill handler should apply identity");
    assert_eq!(
        promise_state_for_register(&fulfilled_core, 4),
        crate::promise_model::PromiseState::Fulfilled(crate::object_model::JsValue::Int(7))
    );

    let rejected_module = test_module_with_functions(
        vec![
            Ir3Instruction::HostCall {
                capability: CapabilityTag("promise:reject".to_string()),
                args: RegRange { start: 0, count: 1 },
                dst: 1,
            },
            Ir3Instruction::HostCall {
                capability: CapabilityTag("promise:then".to_string()),
                args: RegRange { start: 1, count: 1 },
                dst: 4,
            },
            Ir3Instruction::Halt,
        ],
        Vec::new(),
    );
    let mut rejected_core = test_interpreter();
    rejected_core.mutate_registers(|r| {
        r[0] = Value::str("bad");
    });
    rejected_core
        .execute(&rejected_module)
        .expect("absent rejection handler should propagate rejection");
    assert_eq!(
        promise_state_for_register(&rejected_core, 4),
        crate::promise_model::PromiseState::Rejected(crate::object_model::JsValue::Str(
            "bad".to_string()
        ))
    );
}

#[test]
fn zlib_buffer_and_dictionary_backing_labels_reach_output_bd_fdqd4() {
    let mut core = test_interpreter();
    let source = core
        .alloc_buffer_from_bytes(b"classified payload")
        .expect("source Buffer");
    core.join_binary_storage_label(source, &Label::Secret)
        .expect("classify source backing");
    core.write_reg(0, Value::Object(source))
        .expect("source register");

    let Value::Object(compressed) = core
        .dispatch_zlib_hostcall("builtin:ZlibGzipSync", RegRange { start: 0, count: 1 })
        .expect("classified gzip")
    else {
        panic!("gzip must return a Buffer");
    };
    assert_eq!(core.binary_storage_label(compressed), Label::Secret);
    assert_eq!(core.pending_hostcall_result_label, Some(Label::Secret));
    core.clear_pending_hostcall_result_label();

    let dictionary = core
        .alloc_buffer_from_bytes(b"classified dictionary")
        .expect("dictionary Buffer");
    core.join_binary_storage_label(dictionary, &Label::Secret)
        .expect("classify dictionary backing");
    let options = core
        .alloc_object_with_properties(&[("dictionary", Value::Object(dictionary))])
        .expect("zlib options");
    core.write_reg(0, Value::str("classified dictionary payload"))
        .expect("public source register");
    core.write_reg(1, Value::Object(options))
        .expect("options register");
    core.set_register_label(0, Label::Public)
        .expect("public source label");
    core.set_register_label(1, Label::Public)
        .expect("public options label");

    let Value::Object(compressed) = core
        .dispatch_zlib_hostcall("builtin:ZlibDeflateSync", RegRange { start: 0, count: 2 })
        .expect("dictionary deflate")
    else {
        panic!("deflate must return a Buffer");
    };
    assert_eq!(core.binary_storage_label(compressed), Label::Secret);
    assert_eq!(core.pending_hostcall_result_label, Some(Label::Secret));
}

#[test]
fn zlib_decompression_limit_refuses_without_heap_publication_bd_fdqd4() {
    let oversized = vec![b'x'; MAX_ARRAY_BUFFER_BYTE_LENGTH as usize + 1];
    let mut storage = vec![0u8; zlib_rs::compress_bound(oversized.len())];
    let compressed = {
        let (written, _) = zlib_rs::compress_slice(&mut storage, &oversized, Default::default());
        written.to_vec()
    };

    let mut core = test_interpreter();
    let input = core
        .alloc_buffer_from_bytes(&compressed)
        .expect("compressed bomb Buffer");
    core.write_reg(0, Value::Object(input))
        .expect("compressed input register");
    let heap_before = core.heap.len();
    let memory_before = core.estimated_memory_bytes();

    assert!(matches!(
        core.dispatch_zlib_hostcall("builtin:ZlibInflateSync", RegRange { start: 0, count: 1 },),
        Err(InterpreterError::RangeError { .. })
    ));
    assert_eq!(core.heap.len(), heap_before);
    assert_eq!(core.estimated_memory_bytes(), memory_before);
    assert!(core.pending_hostcall_result_label.is_none());
}

#[test]
fn zlib_codec_preflight_and_labeled_io_scheduling_are_atomic_bd_fdqd4() {
    let mut core = test_interpreter();
    core.write_reg(0, Value::str("small input"))
        .expect("input register");
    let baseline = core.sync_estimated_memory_bytes().expect("memory baseline");
    let heap_before = core.heap.len();
    core.config.max_total_memory_bytes = baseline
        .saturating_add(ZLIB_CODEC_WORKSPACE_BYTES)
        .saturating_add(MAX_ARRAY_BUFFER_BYTE_LENGTH.saturating_mul(2))
        .saturating_add(ZLIB_IO_CHUNK_BYTES as u64)
        .saturating_add(ZLIB_PUBLICATION_METADATA_BYTES)
        .saturating_sub(1);

    assert!(matches!(
        core.dispatch_zlib_hostcall("builtin:ZlibGzipSync", RegRange { start: 0, count: 1 },),
        Err(InterpreterError::MemoryBudgetExceeded { .. })
    ));
    assert_eq!(core.heap.len(), heap_before);
    assert_eq!(core.estimated_memory_bytes(), baseline);

    core.config.max_total_memory_bytes = DEFAULT_QUICKJS_MAX_TOTAL_MEMORY_BYTES;
    core.schedule_io_callback_with_label(77, vec![Value::Undefined], Label::Secret)
        .expect("labeled I/O callback");
    let turn = core.event_loop.turn();
    assert_eq!(
        turn.macrotask.expect("scheduled callback").label,
        Label::Secret
    );
}

#[test]
fn zlib_composite_clone_peak_and_codec_work_refuse_before_mutation_bd_fdqd4() {
    let mut core = test_interpreter();
    let input = core
        .alloc_buffer_from_bytes(&vec![b'a'; 64 * 1024])
        .expect("input Buffer");
    let dictionary = core
        .alloc_buffer_from_bytes(&vec![b'b'; 64 * 1024])
        .expect("dictionary Buffer");
    let options = core
        .alloc_object_with_properties(&[("dictionary", Value::Object(dictionary))])
        .expect("options");
    core.write_reg(0, Value::Object(input)).expect("input reg");
    core.write_reg(1, Value::Object(options))
        .expect("options reg");
    let baseline = core.sync_estimated_memory_bytes().expect("memory baseline");
    let heap_before = core.heap.len();
    let instructions_before = core.instructions_executed;

    // Each old sequential copy fit this allowance in isolation; their
    // combined clone+codec+publication peak does not.
    core.config.max_total_memory_bytes = baseline.saturating_add(128 * 1024);
    assert!(matches!(
        core.dispatch_zlib_hostcall("builtin:ZlibDeflateSync", RegRange { start: 0, count: 2 },),
        Err(InterpreterError::MemoryBudgetExceeded { .. })
    ));
    assert_eq!(core.heap.len(), heap_before);
    assert_eq!(core.estimated_memory_bytes(), baseline);
    assert_eq!(core.instructions_executed, instructions_before);

    core.config.max_total_memory_bytes = DEFAULT_QUICKJS_MAX_TOTAL_MEMORY_BYTES;
    let cost = InterpreterCore::zlib_work_cost(64 * 1024, 64 * 1024, true, 6);
    core.config.instruction_budget = instructions_before.saturating_add(cost).saturating_sub(1);
    assert!(matches!(
        core.dispatch_zlib_hostcall("builtin:ZlibDeflateSync", RegRange { start: 0, count: 2 },),
        Err(InterpreterError::BudgetExhausted { .. })
    ));
    assert_eq!(core.heap.len(), heap_before);
    assert_eq!(core.estimated_memory_bytes(), baseline);
    assert_eq!(core.instructions_executed, instructions_before);
}

#[test]
fn zlib_error_transactions_preserve_prototype_and_pending_state_bd_fdqd4() {
    let mut core = test_interpreter();
    let error_prototype = core
        .ensure_builtin_prototype("Error")
        .expect("Error prototype");
    let baseline = core.sync_estimated_memory_bytes().expect("memory baseline");
    let heap_before = core.heap.len();

    // Measure the exact retained error-object delta, then leave precisely
    // enough room for construction but not callback scheduling.
    core.construct_buffer_node_error(
        "Error",
        "Z_DATA_ERROR",
        "transactional zlib error".to_string(),
    )
    .expect("probe error");
    let error_delta = core.estimated_memory_bytes().saturating_sub(baseline);
    core.rollback_heap_to_len(heap_before);
    core.estimated_memory_bytes = baseline;
    core.config.max_total_memory_bytes = baseline.saturating_add(error_delta);

    assert!(matches!(
        core.schedule_zlib_data_error_callback(
            77,
            "Z_DATA_ERROR",
            "transactional zlib error".to_string(),
            Label::Public,
        ),
        Err(InterpreterError::MemoryBudgetExceeded { .. })
    ));
    assert_eq!(core.heap.len(), heap_before);
    assert_eq!(core.estimated_memory_bytes(), baseline);
    assert!(core.pending_io_callbacks.is_empty());
    assert!(!core.event_loop.has_pending_work());
    assert_eq!(core.builtin_prototypes.get("Error"), Some(&error_prototype));
    assert!((error_prototype.0 as usize) < core.heap.len());

    let custom_label = Label::Custom {
        name: "zlib-sync-error-label".repeat(64),
        level: 9,
    };
    core.config.max_total_memory_bytes = baseline;
    let sync_error = core.zlib_sync_data_error(
        "Z_DATA_ERROR",
        "sync label refusal".to_string(),
        &custom_label,
    );
    assert!(matches!(
        sync_error,
        InterpreterError::MemoryBudgetExceeded { .. }
    ));
    assert_eq!(core.heap.len(), heap_before);
    assert_eq!(core.estimated_memory_bytes(), baseline);
    assert!(core.pending_exception.is_none());
    assert_eq!(core.pending_exception_label, Label::Public);
    assert_eq!(core.builtin_prototypes.get("Error"), Some(&error_prototype));

    let mut callback_core = test_interpreter();
    callback_core
        .schedule_zlib_data_error_callback(
            91,
            "Z_DATA_ERROR",
            "one callback argument".to_string(),
            Label::Public,
        )
        .expect("schedule zlib error callback");
    let callback_args = callback_core
        .pending_io_callbacks
        .values()
        .next()
        .expect("pending zlib callback args");
    assert_eq!(callback_args.len(), 1);
}

#[test]
fn event_emitter_constructor_cluster_and_instances_share_canonical_prototype_bd_dspwz() {
    let mut core = test_interpreter();
    let first_constructor = core
        .dispatch_builtin_hostcall_inner(
            "builtin:EventEmitterConstructorRef",
            RegRange { start: 0, count: 0 },
            None,
        )
        .expect("first EventEmitter constructor reference");
    let second_constructor = core
        .dispatch_builtin_hostcall_inner(
            "builtin:EventEmitterConstructorRef",
            RegRange { start: 0, count: 0 },
            None,
        )
        .expect("second EventEmitter constructor reference");
    assert_eq!(first_constructor, second_constructor);
    assert!(matches!(
        &first_constructor,
        Value::BuiltinFunction(BuiltinFunction {
            kind: BuiltinFunctionKind::EventEmitterConstructor,
            ..
        })
    ));

    let Value::Object(emitter_id) = core
        .dispatch_builtin_hostcall_inner(
            "builtin:EventEmitter",
            RegRange { start: 0, count: 0 },
            None,
        )
        .expect("construct standalone EventEmitter")
    else {
        panic!("EventEmitter constructor must return an object");
    };
    let Value::Object(cluster_id) = core
        .construct_cluster_facade()
        .expect("construct cluster facade")
    else {
        panic!("cluster facade must be an object");
    };
    let prototype = core
        .builtin_prototypes
        .get("EventEmitter")
        .copied()
        .expect("canonical EventEmitter prototype");
    assert_eq!(core.heap[emitter_id.0 as usize].prototype, Some(prototype));
    assert_eq!(core.heap[cluster_id.0 as usize].prototype, Some(prototype));

    for tag in ["Cluster", "EventEmitter"] {
        let forged = core
            .alloc_object_with_properties(&[("__type", Value::str(tag))])
            .expect("allocate forged tag object");
        assert!(
            !core
                .prototype_chain_contains(forged, prototype)
                .expect("walk forged object prototype chain"),
            "a writable __type={tag:?} tag must not forge prototype identity"
        );
    }
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );

    core.write_reg_with_label(0, Value::Object(cluster_id), Label::Secret)
        .expect("secret cluster candidate");
    core.write_reg_with_label(1, first_constructor, Label::Public)
        .expect("public EventEmitter constructor");
    let execution = core
        .execute(&test_module_with_functions(
            vec![
                Ir3Instruction::InstanceOf {
                    dst: 2,
                    lhs: 0,
                    rhs: 1,
                },
                Ir3Instruction::Halt,
            ],
            Vec::new(),
        ))
        .expect("ordinary IR3 instanceof execution");
    assert_eq!(core.registers[2], Value::Bool(true));
    assert_eq!(
        core.get_register_label(2).expect("instanceof result label"),
        &Label::Secret,
        "ordinary InstanceOf must join candidate and constructor labels"
    );
    assert_eq!(
        execution.instructions_executed, 3,
        "InstanceOf, Halt, and the empty Writable checkpoint scan are charged"
    );
}

#[test]
fn zlib_brotli_round_trip_through_direct_hostcall_bd_zlib_residual() {
    let mut core = test_interpreter();
    core.write_reg(0, Value::str("brotli roundtrip content"))
        .expect("input register");

    let Value::Object(compressed) = core
        .dispatch_zlib_hostcall(
            "builtin:ZlibBrotliCompressSync",
            RegRange { start: 0, count: 1 },
        )
        .expect("brotli compress must succeed")
    else {
        panic!("brotli compress must return a Buffer");
    };
    core.write_reg(0, Value::Object(compressed))
        .expect("compressed register");

    let Value::Object(decompressed) = core
        .dispatch_zlib_hostcall(
            "builtin:ZlibBrotliDecompressSync",
            RegRange { start: 0, count: 1 },
        )
        .expect("brotli decompress must succeed")
    else {
        panic!("brotli decompress must return a Buffer");
    };
    let bytes = core
        .bytes_for_buffer_like(&Value::Object(decompressed))
        .expect("decompressed bytes");
    assert_eq!(bytes, b"brotli roundtrip content");
}

#[test]
fn zlib_brotli_params_option_selects_quality_bd_zlib_residual() {
    // Fixture 0016 shape: { params: { [zlib.constants.BROTLI_PARAM_QUALITY]: 5 } }
    // — the computed numeric constant (4) becomes the property name "4".
    let mut core = test_interpreter();
    let params = core
        .alloc_object_with_properties(&[("4", Value::Int(5))])
        .expect("params object");
    let options = core
        .alloc_object_with_properties(&[("params", Value::Object(params))])
        .expect("options object");
    core.write_reg(0, Value::str("brotli with quality option"))
        .expect("input register");
    core.write_reg(1, Value::Object(options))
        .expect("options register");

    let Value::Object(compressed) = core
        .dispatch_zlib_hostcall(
            "builtin:ZlibBrotliCompressSync",
            RegRange { start: 0, count: 2 },
        )
        .expect("quality-5 brotli compress must succeed")
    else {
        panic!("compress must return a Buffer");
    };
    core.write_reg(0, Value::Object(compressed))
        .expect("compressed register");

    let Value::Object(decompressed) = core
        .dispatch_zlib_hostcall(
            "builtin:ZlibBrotliDecompressSync",
            RegRange { start: 0, count: 1 },
        )
        .expect("decompress must succeed")
    else {
        panic!("decompress must return a Buffer");
    };
    let bytes = core
        .bytes_for_buffer_like(&Value::Object(decompressed))
        .expect("decompressed bytes");
    assert_eq!(bytes, b"brotli with quality option");
}

#[test]
fn zlib_brotli_invalid_input_throws_data_error_bd_zlib_residual() {
    // Fixture 0009 semantics: brotliDecompressSync on invalid brotli bytes
    // throws an Error rather than returning data or failing silently.
    let mut core = test_interpreter();
    let input = core
        .alloc_buffer_from_bytes(&[1, 2, 3, 4, 5])
        .expect("invalid payload Buffer");
    core.write_reg(0, Value::Object(input))
        .expect("input register");

    match core.dispatch_zlib_hostcall(
        "builtin:ZlibBrotliDecompressSync",
        RegRange { start: 0, count: 1 },
    ) {
        Err(InterpreterError::UncaughtException { value }) => {
            assert!(
                value.contains("Invalid Data"),
                "corrupt brotli input must raise the brotli data error, got {value:?}"
            );
        }
        other => panic!("corrupt brotli input must throw a guest Error, got {other:?}"),
    }
}

#[test]
fn zlib_brotli_quality_outside_range_rejected_bd_zlib_residual() {
    let mut core = test_interpreter();
    let params = core
        .alloc_object_with_properties(&[("4", Value::Int(12))])
        .expect("params object");
    let options = core
        .alloc_object_with_properties(&[("params", Value::Object(params))])
        .expect("options object");
    core.write_reg(0, Value::str("payload"))
        .expect("input register");
    core.write_reg(1, Value::Object(options))
        .expect("options register");

    assert!(matches!(
        core.dispatch_zlib_hostcall(
            "builtin:ZlibBrotliCompressSync",
            RegRange { start: 0, count: 2 },
        ),
        Err(InterpreterError::RangeError { .. })
    ));
}

#[test]
fn event_emitter_instance_allocation_is_atomic_under_final_byte_refusal_bd_dspwz() {
    let mut core = test_interpreter();
    let prototype = core
        .ensure_builtin_prototype("EventEmitter")
        .expect("materialize EventEmitter prototype before instance transaction");
    let baseline = core.sync_estimated_memory_bytes().expect("memory baseline");
    let heap_before = core.heap.len();
    core.dispatch_builtin_hostcall_inner(
        "builtin:EventEmitter",
        RegRange { start: 0, count: 0 },
        None,
    )
    .expect("probe EventEmitter allocation");
    let instance_delta = core.estimated_memory_bytes.saturating_sub(baseline);
    assert!(instance_delta > 0);
    core.rollback_heap_to_len(heap_before);
    core.estimated_memory_bytes = baseline;
    core.config.max_total_memory_bytes = baseline.saturating_add(instance_delta).saturating_sub(1);

    assert!(matches!(
        core.dispatch_builtin_hostcall_inner(
            "builtin:EventEmitter",
            RegRange { start: 0, count: 0 },
            None,
        ),
        Err(InterpreterError::MemoryBudgetExceeded { .. })
    ));
    assert_eq!(core.heap.len(), heap_before);
    assert_eq!(core.estimated_memory_bytes, baseline);
    assert_eq!(
        core.builtin_prototypes.get("EventEmitter"),
        Some(&prototype)
    );
}

#[test]
fn cluster_facade_allocation_is_atomic_under_final_byte_refusal_bd_9p2v3() {
    let mut core = test_interpreter();
    let event_emitter_prototype = core
        .ensure_builtin_prototype("EventEmitter")
        .expect("materialize EventEmitter prototype before facade transaction");
    let baseline = core.sync_estimated_memory_bytes().expect("memory baseline");
    let heap_before = core.heap.len();

    let Value::Object(probe_id) = core
        .construct_cluster_facade()
        .expect("probe cluster facade")
    else {
        panic!("cluster facade must be an object");
    };
    assert!(
        !core.heap[probe_id.0 as usize]
            .properties
            .contains_key("worker"),
        "primary facade must not forge an own worker key"
    );
    let facade_delta = core.estimated_memory_bytes.saturating_sub(baseline);
    assert!(facade_delta > 0);
    core.clear_cluster_execution_state();
    core.rollback_heap_to_len(heap_before);
    core.estimated_memory_bytes = baseline;
    core.config.max_total_memory_bytes = baseline.saturating_add(facade_delta).saturating_sub(1);

    assert!(matches!(
        core.construct_cluster_facade(),
        Err(InterpreterError::MemoryBudgetExceeded { .. })
    ));
    assert_eq!(core.heap.len(), heap_before);
    assert_eq!(core.estimated_memory_bytes, baseline);
    assert!(core.cluster_facades.is_empty());
    assert_eq!(
        core.builtin_prototypes.get("EventEmitter"),
        Some(&event_emitter_prototype),
        "facade rollback must retain only the valid pre-transaction prototype"
    );
}

#[test]
fn cluster_hostcalls_share_identity_and_seed_reset_clears_authenticated_state_bd_9p2v3() {
    let mut core = test_interpreter();
    let seed = core
        .capture_execution_seed()
        .expect("test execution-seed capture must fit");
    let first = core
        .dispatch_builtin_hostcall_inner(
            "builtin:ClusterFacade",
            RegRange { start: 0, count: 0 },
            None,
        )
        .expect("first cluster hostcall");
    let second = core
        .dispatch_builtin_hostcall_inner(
            "builtin:ClusterFacade",
            RegRange { start: 0, count: 0 },
            None,
        )
        .expect("second cluster hostcall");
    assert_eq!(first, second, "one execution owns one cluster facade");
    let Value::Object(first_id) = first else {
        panic!("cluster facade must be an object");
    };
    assert!(core.cluster_facades.contains_key(&first_id));
    core.cluster_facades
        .get_mut(&first_id)
        .expect("authenticated facade state")
        .lifecycle_label = Label::Secret;
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );

    core.reset_execution_state_from_seed(&seed)
        .expect("restore pre-cluster seed");
    assert!(core.cluster_facades.is_empty());
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );

    let Value::Object(reused_id) = core
        .dispatch_builtin_hostcall_inner(
            "builtin:ClusterFacade",
            RegRange { start: 0, count: 0 },
            None,
        )
        .expect("post-reset cluster hostcall")
    else {
        panic!("cluster facade must be an object");
    };
    assert_eq!(
        core.cluster_facades[&reused_id].lifecycle_label,
        Label::Public,
        "a reused heap id must never inherit prior execution provenance"
    );
}

#[test]
fn cluster_setup_precharges_work_and_never_publishes_partial_settings_bd_9p2v3() {
    let mut core = test_interpreter();
    let Value::Object(cluster_id) = core.construct_cluster_facade().expect("cluster facade") else {
        panic!("cluster facade must be an object");
    };
    let original_settings = match core.heap[cluster_id.0 as usize].properties.get("settings") {
        Some(Value::Object(settings_id)) => *settings_id,
        other => panic!("missing settings object: {other:?}"),
    };
    let args_array = core
        .alloc_array_from_values(&[Value::str("--one"), Value::str("--two")])
        .expect("args array");
    let options = core
        .alloc_object_with_properties(&[
            ("exec", Value::str("worker.js")),
            ("args", Value::Object(args_array)),
        ])
        .expect("setup options");
    core.write_reg(0, Value::Object(options))
        .expect("options register");
    let heap_before = core.heap.len();
    let memory_before = core.sync_estimated_memory_bytes().expect("memory baseline");
    let instructions_before = core.instructions_executed;

    core.config.instruction_budget = instructions_before.saturating_add(1);
    assert!(matches!(
        core.cluster_setup(
            Some(Value::Object(cluster_id)),
            Some(cluster_id.0),
            RegRange { start: 0, count: 1 },
        ),
        Err(InterpreterError::BudgetExhausted { .. })
    ));
    assert_eq!(core.heap.len(), heap_before);
    assert_eq!(core.estimated_memory_bytes, memory_before);
    assert_eq!(core.instructions_executed, instructions_before);
    assert_eq!(
        core.heap[cluster_id.0 as usize].properties.get("settings"),
        Some(&Value::Object(original_settings))
    );

    core.config.instruction_budget = u64::MAX;
    let options_bytes = InterpreterCore::estimate_heap_object_bytes(&core.heap[options.0 as usize]);
    let settings_bytes =
        InterpreterCore::estimate_heap_object_bytes(&core.heap[original_settings.0 as usize]);
    core.config.max_total_memory_bytes = memory_before
        .saturating_add(
            options_bytes
                .saturating_add(settings_bytes)
                .saturating_mul(2),
        )
        .saturating_sub(1);
    assert!(matches!(
        core.cluster_setup(
            Some(Value::Object(cluster_id)),
            Some(cluster_id.0),
            RegRange { start: 0, count: 1 },
        ),
        Err(InterpreterError::MemoryBudgetExceeded { .. })
    ));
    assert_eq!(core.heap.len(), heap_before);
    assert_eq!(core.estimated_memory_bytes, memory_before);
    assert_eq!(
        core.heap[cluster_id.0 as usize].properties.get("settings"),
        Some(&Value::Object(original_settings))
    );

    core.config.max_total_memory_bytes = DEFAULT_QUICKJS_MAX_TOTAL_MEMORY_BYTES;
    core.cluster_setup(
        Some(Value::Object(cluster_id)),
        Some(cluster_id.0),
        RegRange { start: 0, count: 1 },
    )
    .expect("successful setup merge");
    let replacement = match core.heap[cluster_id.0 as usize].properties.get("settings") {
        Some(Value::Object(settings_id)) => *settings_id,
        other => panic!("missing replacement settings: {other:?}"),
    };
    assert_ne!(replacement, original_settings);
    assert_eq!(
        core.heap[replacement.0 as usize].properties.get("exec"),
        Some(&Value::str("worker.js"))
    );
    assert_eq!(
        core.heap[replacement.0 as usize].properties.get("args"),
        Some(&Value::Object(args_array)),
        "setup merge must retain supplied array identity"
    );
    assert!(
        core.heap[original_settings.0 as usize]
            .properties
            .is_empty()
    );
}

#[test]
fn cluster_setup_charges_reserved_keys_before_traversal_bd_9p2v3() {
    let mut core = test_interpreter();
    let Value::Object(cluster_id) = core.construct_cluster_facade().expect("cluster facade") else {
        panic!("cluster facade must be an object");
    };
    let options = core
        .alloc_object_with_properties(&[
            ("__a", Value::Int(1)),
            ("__b", Value::Int(2)),
            ("__c", Value::Int(3)),
            ("__d", Value::Int(4)),
            ("__e", Value::Int(5)),
            ("__f", Value::Int(6)),
            ("__g", Value::Int(7)),
            ("__h", Value::Int(8)),
        ])
        .expect("reserved-key options");
    core.write_reg(0, Value::Object(options))
        .expect("options register");
    let heap_before = core.heap.len();
    let memory_before = core.estimated_memory_bytes();
    let instructions_before = core.instructions_executed;
    core.config.instruction_budget = instructions_before
        .saturating_add(CLUSTER_SETUP_FIXED_WORK as u64)
        .saturating_add(8)
        .saturating_sub(1);

    assert!(matches!(
        core.cluster_setup(
            Some(Value::Object(cluster_id)),
            Some(cluster_id.0),
            RegRange { start: 0, count: 1 },
        ),
        Err(InterpreterError::BudgetExhausted { .. })
    ));
    assert_eq!(core.instructions_executed, instructions_before);
    assert_eq!(core.heap.len(), heap_before);
    assert_eq!(core.estimated_memory_bytes(), memory_before);
}

#[test]
fn cluster_setup_lifecycle_taints_settings_nested_reads_and_methods_bd_9p2v3() {
    let mut core = test_interpreter();
    let Value::Object(cluster_id) = core.construct_cluster_facade().expect("cluster facade") else {
        panic!("cluster facade must be an object");
    };
    let options = core
        .alloc_object_with_properties(&[("exec", Value::str("classified-worker.js"))])
        .expect("setup options");
    core.write_reg(0, Value::Object(options))
        .expect("options register");
    core.set_register_label(0, Label::Secret)
        .expect("classified setup options");
    core.cluster_setup(
        Some(Value::Object(cluster_id)),
        Some(cluster_id.0),
        RegRange { start: 0, count: 1 },
    )
    .expect("classified setup");
    let settings_id = core.cluster_facades[&cluster_id].settings;
    assert_eq!(
        core.cluster_state_label_ref(cluster_id),
        Some(&Label::Secret)
    );
    assert_eq!(
        core.cluster_state_label_ref(settings_id),
        Some(&Label::Secret)
    );
    assert_eq!(
        core.dispatch_builtin_hostcall_inner(
            "builtin:ClusterFacade",
            RegRange { start: 0, count: 0 },
            None,
        ),
        Ok(Value::Object(cluster_id))
    );
    assert_eq!(core.pending_hostcall_result_label, Some(Label::Secret));
    core.clear_pending_hostcall_result_label();

    core.write_reg(1, Value::Object(cluster_id))
        .expect("cluster register");
    core.write_reg(2, Value::str("settings"))
        .expect("settings key");
    core.write_reg(3, Value::str("exec")).expect("exec key");
    core.write_reg(6, Value::str("emit")).expect("emit key");
    core.write_reg(8, Value::str("missing"))
        .expect("event name");
    let module = test_module_with_functions(
        vec![
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 4,
            },
            Ir3Instruction::GetProperty {
                obj: 4,
                key: 3,
                dst: 5,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 6,
                dst: 7,
            },
            Ir3Instruction::CallMethod {
                receiver: 1,
                callee: 7,
                args: RegRange { start: 8, count: 1 },
                dst: 9,
            },
            Ir3Instruction::Halt,
        ],
        vec![],
    );
    assert_eq!(core.run_loop(&module), Err(InterpreterError::Halted));
    assert_eq!(core.get_register_label(4), Ok(&Label::Secret));
    assert_eq!(core.get_register_label(5), Ok(&Label::Secret));
    assert_eq!(core.get_register_label(9), Ok(&Label::Secret));
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn cluster_disconnect_preserves_ifc_label_and_rolls_back_failed_schedule_bd_9p2v3() {
    let mut refused = test_interpreter();
    let Value::Object(refused_cluster) = refused
        .construct_cluster_facade()
        .expect("refused cluster facade")
    else {
        panic!("cluster facade must be an object");
    };
    refused
        .write_reg(0, Value::Closure(7))
        .expect("callback register");
    refused
        .set_register_label(0, Label::Secret)
        .expect("classified callback");
    let refused_baseline = refused
        .sync_estimated_memory_bytes()
        .expect("refused memory baseline");
    refused.config.max_total_memory_bytes = refused_baseline;
    let module = test_module_with_functions(vec![], vec![]);
    let disconnect = match refused.heap[refused_cluster.0 as usize]
        .properties
        .get("disconnect")
    {
        Some(Value::BuiltinFunction(disconnect)) => disconnect.clone(),
        other => panic!("missing bound disconnect builtin: {other:?}"),
    };
    assert!(matches!(
        refused.dispatch_builtin_function(
            &module,
            &disconnect,
            RegRange { start: 0, count: 1 },
            Some(Value::Object(refused_cluster)),
            None,
        ),
        Err(InterpreterError::MemoryBudgetExceeded { .. })
    ));
    assert!(refused.pending_io_callbacks.is_empty());
    assert!(!refused.event_loop.has_pending_work());
    assert_eq!(refused.estimated_memory_bytes, refused_baseline);

    let mut accepted = test_interpreter();
    let Value::Object(accepted_cluster) = accepted
        .construct_cluster_facade()
        .expect("accepted cluster facade")
    else {
        panic!("cluster facade must be an object");
    };
    accepted
        .write_reg(0, Value::Closure(9))
        .expect("callback register");
    accepted
        .set_register_label(0, Label::Secret)
        .expect("classified callback");
    let accepted_disconnect = match accepted.heap[accepted_cluster.0 as usize]
        .properties
        .get("disconnect")
    {
        Some(Value::BuiltinFunction(disconnect)) => disconnect.clone(),
        other => panic!("missing bound disconnect builtin: {other:?}"),
    };
    accepted
        .dispatch_builtin_function(
            &module,
            &accepted_disconnect,
            RegRange { start: 0, count: 1 },
            Some(Value::Object(accepted_cluster)),
            None,
        )
        .expect("disconnect schedule");
    let task = accepted
        .event_loop
        .turn()
        .macrotask
        .expect("disconnect callback task");
    assert_eq!(task.label, Label::Secret);
    assert_eq!(
        accepted.pending_io_callbacks.get(&task.registration_seq),
        Some(&Vec::new()),
        "disconnect callback receives zero arguments"
    );
}
