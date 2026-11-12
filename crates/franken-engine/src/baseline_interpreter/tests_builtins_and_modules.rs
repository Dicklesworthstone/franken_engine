#[allow(unused_imports)]
use super::*;

#[cfg(test)]
pub(in crate::baseline_interpreter) mod active_builtin_regressions {
    #[allow(unused_imports)]
    use super::*;
    #[allow(unused_imports)]
    use crate::baseline_interpreter::*;

    fn test_quickjs_config() -> InterpreterConfig {
        let mut config = InterpreterConfig::quickjs_defaults();
        config.granted_capabilities = BTreeSet::from([
            RuntimeCapability::VmDispatch,
            RuntimeCapability::HeapAllocate,
        ]);
        config
    }

    fn test_core() -> InterpreterCore {
        InterpreterCore::new(test_quickjs_config(), "test-trace")
    }

    /// Trace recording is bounded: iterations past `MAX_ITERATION_TRACES` are
    /// untraced and a trace stops at `MAX_ITERATION_TRACE_EVENTS`, while the
    /// iterations themselves still produce every value.
    #[test]
    fn iteration_trace_recording_is_bounded() {
        let mut core = test_core();
        let one = RegRange { start: 0, count: 1 };
        let long: Vec<Value> = (0..3_000).map(Value::Int).collect();
        let array = core.alloc_array_from_values(&long).unwrap();
        core.write_reg(0, Value::Object(array)).unwrap();
        let iterator = core
            .dispatch_builtin_hostcall("builtin:DestructureIteratorInit", one, None)
            .unwrap();
        core.write_reg(0, iterator).unwrap();
        for expected in 0..3_000 {
            assert_eq!(
                core.dispatch_builtin_hostcall("builtin:DestructureIteratorNext", one, None)
                    .unwrap(),
                Value::Int(expected)
            );
        }
        assert_eq!(
            core.iteration_traces[0].events.len(),
            MAX_ITERATION_TRACE_EVENTS
        );

        let short = core.alloc_array_from_values(&[Value::Int(7)]).unwrap();
        for _ in 0..MAX_ITERATION_TRACES + 100 {
            core.write_reg(0, Value::Object(short)).unwrap();
            let iterator = core
                .dispatch_builtin_hostcall("builtin:DestructureIteratorInit", one, None)
                .unwrap();
            core.write_reg(0, iterator).unwrap();
            assert_eq!(
                core.dispatch_builtin_hostcall("builtin:DestructureIteratorNext", one, None)
                    .unwrap(),
                Value::Int(7)
            );
        }
        assert_eq!(core.iteration_traces.len(), MAX_ITERATION_TRACES);
    }

    /// The RegExp cache reuses a compilation only for the same pattern and
    /// flags, keeps at most `REGEXP_CACHE_ENTRIES`, never keeps a pattern past
    /// its size limits, and reports invalid patterns as an uncached compile.
    #[test]
    fn regexp_cache_is_keyed_bounded_and_skips_large_patterns() {
        let core = test_core();
        let cached = |core: &InterpreterCore, source: &str| {
            core.regexp_cache
                .borrow()
                .iter()
                .any(|(pattern, _, _)| pattern == source)
        };
        let sensitive = core.compile_regexp_pattern("ab+c", "").unwrap();
        let insensitive = core.compile_regexp_pattern("ab+c", "i").unwrap();
        assert!(sensitive.is_match("xabbc").unwrap() && !sensitive.is_match("ABBC").unwrap());
        assert!(insensitive.is_match("ABBC").unwrap());
        assert!(
            core.compile_regexp_pattern("ab+c", "i")
                .unwrap()
                .is_match("ABBC")
                .unwrap()
        );
        assert_eq!(core.regexp_cache.borrow().len(), 2);

        for index in 0..REGEXP_CACHE_ENTRIES + 8 {
            let source = format!("p{index}q");
            assert!(
                core.compile_regexp_pattern(&source, "")
                    .unwrap()
                    .is_match(&source)
                    .unwrap()
            );
        }
        assert_eq!(core.regexp_cache.borrow().len(), REGEXP_CACHE_ENTRIES);
        assert!(!cached(&core, "ab+c"));

        // `\p{L}{50}` compiles past the cache limits: valid and matched, not
        // kept. (`\w` is ASCII in JavaScript, bd-9vouw.89, so `\w{50}` is small.)
        let large = core.compile_regexp_pattern(r"^\p{L}{50}$", "u").unwrap();
        assert!(large.is_match(&"\u{e9}".repeat(50)).unwrap());
        assert!(!cached(&core, r"^\p{L}{50}$"));
        let long_source = "a".repeat(REGEXP_CACHE_MAX_PATTERN_BYTES + 1);
        assert!(
            core.compile_regexp_pattern(&long_source, "")
                .unwrap()
                .is_match(&long_source)
                .unwrap()
        );
        assert!(!cached(&core, &long_source));

        // Look-around runs on the backtracking matcher; its small program is
        // kept like an automaton (bd-9vouw.89).
        let lookahead = core.compile_regexp_pattern("a(?=b)", "").unwrap();
        assert!(matches!(lookahead, CompiledRegExp::Backtracking(_)));
        assert!(lookahead.is_match("ab").unwrap() && !lookahead.is_match("ac").unwrap());
        assert!(cached(&core, "a(?=b)"));

        assert!(matches!(
            core.compile_regexp_pattern("(", ""),
            Err(InterpreterError::TypeError { ref expected, .. }) if expected == "valid RegExp pattern"
        ));
        assert!(matches!(
            core.compile_regexp_pattern("a", "x"),
            Err(InterpreterError::TypeError { ref expected, .. }) if expected == "supported RegExp flag"
        ));
        assert!(!cached(&core, "("));
        assert!(test_core().regexp_cache.borrow().is_empty());
    }

    /// bd-9vouw.83: repeated grants of an effect-free hostcall are counted,
    /// not recorded. The first grant per tag, every denial and the first
    /// grant after a denial are recorded; host effects record every call.
    #[test]
    fn effect_free_grants_fold_until_the_decision_changes() {
        let mut core = test_core();
        core.config
            .granted_capabilities
            .insert(RuntimeCapability::Builtin);
        core.config
            .granted_capabilities
            .insert(RuntimeCapability::Console);
        let decisions = |core: &InterpreterCore| {
            core.hostcall_decisions
                .iter()
                .map(|decision| (decision.capability.0.clone(), decision.allowed))
                .collect::<Vec<_>>()
        };
        let keys = "builtin:ObjectKeys";
        assert!(check_hostcall_capability_gate(&mut core, keys, 1).unwrap());
        assert!(!check_hostcall_capability_gate(&mut core, keys, 2).unwrap());
        assert!(!check_hostcall_capability_gate(&mut core, keys, 3).unwrap());
        assert!(check_hostcall_capability_gate(&mut core, "number:parseInt", 4).unwrap());
        assert!(check_hostcall_capability_gate(&mut core, "console:log", 5).unwrap());
        assert!(check_hostcall_capability_gate(&mut core, "console:log", 6).unwrap());
        assert_eq!(core.folded_hostcall_decisions, 2);

        core.config
            .granted_capabilities
            .remove(&RuntimeCapability::Builtin);
        for index in [7, 8] {
            assert!(matches!(
                check_hostcall_capability_gate(&mut core, keys, index),
                Err(InterpreterError::CapabilityDenied { .. })
            ));
        }
        core.config
            .granted_capabilities
            .insert(RuntimeCapability::Builtin);
        assert!(check_hostcall_capability_gate(&mut core, keys, 9).unwrap());
        assert!(!check_hostcall_capability_gate(&mut core, keys, 10).unwrap());
        assert_eq!(core.folded_hostcall_decisions, 3);
        assert_eq!(
            decisions(&core),
            [
                (keys, true),
                ("number:parseInt", true),
                ("console:log", true),
                ("console:log", true),
                (keys, false),
                (keys, false),
                (keys, true),
            ]
            .map(|(tag, allowed)| (tag.to_string(), allowed))
        );
        assert_eq!(
            core.hostcall_decisions
                .iter()
                .map(|decision| decision.instruction_index)
                .collect::<Vec<_>>(),
            [1, 4, 5, 6, 7, 8, 9]
        );
    }

    #[test]
    fn destructuring_iterator_intrinsics_keep_exhaustion_sticky() {
        let mut core = test_core();
        let array = core.alloc_array_from_values(&[Value::Int(10)]).unwrap();
        core.write_reg(0, Value::Object(array)).unwrap();
        let one = RegRange { start: 0, count: 1 };
        let iterator = core
            .dispatch_builtin_hostcall("builtin:DestructureIteratorInit", one, None)
            .unwrap();
        core.write_reg(0, iterator).unwrap();
        assert_eq!(
            core.dispatch_builtin_hostcall("builtin:DestructureIteratorNext", one, None)
                .unwrap(),
            Value::Int(10)
        );
        assert_eq!(
            core.dispatch_builtin_hostcall("builtin:DestructureIteratorNext", one, None)
                .unwrap(),
            Value::Undefined
        );
        let event_count = core.iteration_traces[0].events.len();
        assert_eq!(
            core.dispatch_builtin_hostcall("builtin:DestructureIteratorNext", one, None)
                .unwrap(),
            Value::Undefined
        );
        assert_eq!(core.iteration_traces[0].events.len(), event_count);
        assert_eq!(core.iteration_traces[0].kind, IterationKind::Destructuring);
        core.write_reg(1, Value::Undefined).unwrap();
        assert_eq!(
            core.dispatch_builtin_hostcall(
                "builtin:DestructureIteratorDone",
                RegRange { start: 0, count: 2 },
                None
            )
            .unwrap(),
            Value::Bool(true)
        );
    }

    #[test]
    fn destructuring_iterator_elision_advances_without_claiming_a_value_read() {
        let mut core = test_core();
        let array = core
            .alloc_array_from_values(&[Value::Int(10), Value::Int(20)])
            .unwrap();
        core.write_reg(0, Value::Object(array)).unwrap();
        let one = RegRange { start: 0, count: 1 };
        let iterator = core
            .dispatch_builtin_hostcall("builtin:DestructureIteratorInit", one, None)
            .unwrap();
        core.write_reg(0, iterator).unwrap();
        core.dispatch_builtin_hostcall("builtin:DestructureIteratorElide", one, None)
            .unwrap();
        let trace = &core.iteration_traces[0];
        assert_eq!(trace.values_produced, 1);
        assert!(trace.events.iter().any(|event| matches!(
            event.operation,
            IterationOperation::IteratorNext {
                result: IteratorResult {
                    value: IteratorValue::Unobserved,
                    done: false
                }
            }
        )));
        assert!(
            !trace
                .events
                .iter()
                .any(|event| matches!(event.operation, IterationOperation::IteratorValue { .. }))
        );
        assert_eq!(
            core.dispatch_builtin_hostcall("builtin:DestructureIteratorNext", one, None)
                .unwrap(),
            Value::Int(20)
        );
    }

    #[test]
    fn destructuring_iterator_intrinsics_reject_invalid_carriers_and_arities() {
        let mut core = test_core();
        for cap in [
            "builtin:DestructureIteratorInit",
            "builtin:DestructureIteratorNext",
            "builtin:DestructureIteratorElide",
            "builtin:DestructureIteratorDone",
        ] {
            assert!(matches!(
                core.dispatch_builtin_hostcall(cap, RegRange { start: 0, count: 0 }, None),
                Err(InterpreterError::TypeError { .. })
            ));
        }
        for value in [
            Value::Null,
            Value::Undefined,
            Value::Int(7),
            Value::Bool(false),
        ] {
            core.write_reg(0, value).unwrap();
            assert!(matches!(
                core.dispatch_builtin_hostcall(
                    "builtin:DestructureIteratorInit",
                    RegRange { start: 0, count: 1 },
                    None
                ),
                Err(InterpreterError::TypeError { .. })
            ));
            assert!(matches!(
                core.dispatch_builtin_hostcall(
                    "builtin:DestructureIteratorNext",
                    RegRange { start: 0, count: 1 },
                    None
                ),
                Err(InterpreterError::TypeError { .. })
            ));
        }
    }

    #[test]
    fn destructuring_iterator_unobserved_trace_round_trips_distinct_from_undefined() {
        let encoded = serde_json::to_string(&IteratorValue::Unobserved).unwrap();
        let decoded: IteratorValue = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, IteratorValue::Unobserved);
        assert_ne!(
            encoded,
            serde_json::to_string(&IteratorValue::Undefined).unwrap()
        );
        assert_eq!(decoded.to_string(), "<unobserved>");
    }

    #[test]
    fn destructuring_iterator_result_reads_preserve_stored_property_taint() {
        let mut core = test_core();
        let result = core
            .alloc_object_with_properties(&[
                ("done", Value::Bool(false)),
                ("value", Value::Int(17)),
            ])
            .unwrap();
        core.set_own_property_label(result, "value", &Label::Secret)
            .unwrap();
        let value = core
            .iterator_result_value(&halted_test_module(), &Value::Object(result))
            .unwrap();
        assert_eq!(value, Value::Int(17));
        assert_eq!(core.pending_hostcall_result_label, Some(Label::Secret));
    }

    #[test]
    fn destructuring_iterator_normal_close_has_destructuring_trace_reason() {
        let mut core = test_core();
        let array = core.alloc_array_from_values(&[Value::Int(1)]).unwrap();
        core.write_reg(0, Value::Object(array)).unwrap();
        let iterator = core
            .dispatch_builtin_hostcall(
                "builtin:DestructureIteratorInit",
                RegRange { start: 0, count: 1 },
                None,
            )
            .unwrap();
        core.close_iterator(&halted_test_module(), iterator, IteratorCloseReason::Break)
            .unwrap();
        assert!(core.iteration_traces[0].events.iter().any(|event| matches!(
            event.operation,
            IterationOperation::IteratorClose {
                reason: CloseReason::DestructuringExhausted,
                ..
            }
        )));
    }

    #[test]
    fn destructuring_iterator_elision_never_invokes_custom_value_getter() {
        let mut core = test_core();
        let result = core
            .alloc_object_with_properties(&[
                ("done", Value::Bool(false)),
                (
                    "value",
                    Value::Accessor {
                        get: Some(Arc::new(Value::Function(1))),
                        set: None,
                    },
                ),
            ])
            .unwrap();
        core.scope_chain.current_mut().unwrap().insert_binding(
            "result".to_string(),
            ScopeBinding::with_state(BindingKind::Var, Value::Object(result), true),
        );
        let mut module = iterator_return_value_module();
        module.instructions.extend([
            Ir3Instruction::LoadInt { dst: 0, value: 99 },
            Ir3Instruction::Throw { value: 0 },
        ]);
        module
            .function_table
            .push(crate::ir_contract::Ir3FunctionDesc {
                entry: 2,
                arity: 0,
                frame_size: 1,
                name: Some("throwing_value_getter".to_string()),
                is_generator: false,
                rest_param_index: None,
            });
        let object = core.alloc_object_with_properties(&[]).unwrap();
        let iterator = core
            .init_iterator_from_state(
                Value::Object(object),
                RuntimeForOfInit::from_custom(object, Value::Function(0)),
                IterationKind::Destructuring,
            )
            .unwrap();
        assert_eq!(
            core.advance_for_of_iterator_with_value_read(Some(&module), iterator.clone(), false)
                .unwrap(),
            Some(Value::Undefined)
        );
        assert!(matches!(
            core.advance_for_of_iterator_with_value_read(Some(&module), iterator, true),
            Err(InterpreterError::UncaughtException { .. })
        ));
    }

    #[test]
    fn destructuring_iterator_close_leaves_native_iterator_resumable() {
        let mut core = test_core();
        let module = halted_test_module();
        let array = core
            .alloc_array_from_values(&[Value::Int(1), Value::Int(2), Value::Int(3)])
            .unwrap();
        let native = core
            .array_prototype_iterator_for_receiver(Value::Object(array), "values")
            .unwrap();
        let init = core.prepare_for_of_state(Some(&module), &native).unwrap();
        let record = core
            .init_iterator_from_state(native.clone(), init, IterationKind::Destructuring)
            .unwrap();
        assert_ne!(
            record, native,
            "each consumer owns a distinct Done/close record"
        );
        assert_eq!(
            core.advance_for_of_iterator(Some(&module), record.clone())
                .unwrap(),
            Some(Value::Int(1))
        );
        core.close_iterator(&module, record.clone(), IteratorCloseReason::Break)
            .unwrap();
        assert_eq!(
            core.advance_for_of_iterator(Some(&module), record).unwrap(),
            None
        );
        assert_eq!(
            core.advance_for_of_iterator(Some(&module), native).unwrap(),
            Some(Value::Int(2))
        );
        let trace = core
            .iteration_traces
            .iter()
            .find(|trace| trace.kind == IterationKind::Destructuring)
            .unwrap();
        assert!(trace.events.iter().any(|event| matches!(
            event.operation,
            IterationOperation::IteratorClose {
                reason: CloseReason::DestructuringExhausted,
                return_called: false
            }
        )));
    }

    #[test]
    fn destructuring_iterator_delegated_native_value_keeps_heap_provenance() {
        let mut core = test_core();
        let module = halted_test_module();
        let array = core.alloc_array_from_values(&[Value::Int(19)]).unwrap();
        core.set_own_property_label(array, "0", &Label::Secret)
            .unwrap();
        let native = core
            .array_prototype_iterator_for_receiver(Value::Object(array), "values")
            .unwrap();
        let init = core.prepare_for_of_state(Some(&module), &native).unwrap();
        let record = core
            .init_iterator_from_state(native, init, IterationKind::Destructuring)
            .unwrap();
        core.clear_pending_hostcall_result_label();
        assert_eq!(
            core.advance_for_of_iterator(Some(&module), record).unwrap(),
            Some(Value::Int(19))
        );
        assert_eq!(core.pending_hostcall_result_label, Some(Label::Secret));
    }

    #[test]
    fn destructuring_iterator_native_done_decision_keeps_length_provenance() {
        let mut core = test_core();
        let module = halted_test_module();
        let array = core.alloc_array_from_values(&[]).unwrap();
        core.set_own_property_label(array, "length", &Label::TopSecret)
            .unwrap();
        let native = core
            .array_prototype_iterator_for_receiver(Value::Object(array), "values")
            .unwrap();
        let init = core.prepare_for_of_state(Some(&module), &native).unwrap();
        let record = core
            .init_iterator_from_state(native, init, IterationKind::Destructuring)
            .unwrap();
        core.clear_pending_hostcall_result_label();
        assert_eq!(
            core.advance_for_of_iterator(Some(&module), record).unwrap(),
            None
        );
        assert_eq!(core.pending_hostcall_result_label, Some(Label::TopSecret));
    }

    #[test]
    fn destructuring_iterator_rejects_array_like_objects_before_creating_a_record() {
        let mut core = test_core();
        let module = halted_test_module();
        let object = core
            .alloc_object_with_properties(&[("0", Value::Int(7)), ("length", Value::Int(1))])
            .unwrap();
        let count = core.iterators.len();
        assert!(matches!(
            core.prepare_for_of_state(Some(&module), &Value::Object(object)),
            Err(InterpreterError::TypeError { .. })
        ));
        assert_eq!(core.iterators.len(), count);
    }

    fn halted_test_module() -> Ir3Module {
        Ir3Module {
            header: crate::ir_contract::IrHeader {
                schema_version: crate::ir_contract::IrSchemaVersion::CURRENT,
                level: crate::ir_contract::IrLevel::Ir3,
                source_hash: None,
                source_label: "pipeline-test".to_string(),
            },
            instructions: vec![Ir3Instruction::Halt],
            constant_pool: Vec::new(),
            function_table: Vec::new(),
            specialization: None,
            required_capabilities: Vec::new(),
            function_lengths: Default::default(),
            function_sources: Default::default(),
            sloppy_functions: Default::default(),
        }
    }

    fn install_pending_pipeline_fixture(
        core: &mut InterpreterCore,
        token: u32,
    ) -> crate::promise_model::PromiseHandle {
        let promise = core
            .create_promise()
            .expect("pipeline fixture Promise allocation must fit");
        core.stream_pipelines.insert(
            token,
            StreamPipelineState {
                stages: Vec::new(),
                pending_close: Vec::new(),
                completion: StreamPipelineCompletion::Promise(promise),
                registration_label: Label::Custom {
                    name: "pipeline-owner".to_string(),
                    level: 2,
                },
                first_error: None,
                phase: StreamPipelinePhase::Running,
            },
        );
        core.sync_estimated_memory_bytes()
            .expect("pipeline fixture accounting must fit");
        promise
    }

    #[test]
    fn pipeline_reset_removes_owned_promise_and_preserves_process_token_bd_fw7zd_13() {
        let mut core = test_core();
        let seed = core
            .capture_execution_seed()
            .expect("reset fixture seed capture must fit");
        core.next_stream_pipeline_token = 41;
        let pipeline_promise = install_pending_pipeline_fixture(&mut core, 40);
        let retained_guest_promise = core
            .create_promise()
            .expect("later guest Promise allocation must fit");
        let before_reset = core.estimated_memory_bytes();

        core.reset_execution_state_from_seed(&seed)
            .expect("execution reset must dispose pipeline ownership");

        assert!(core.stream_pipelines.is_empty());
        assert_eq!(
            core.next_stream_pipeline_token, 41,
            "ObjectId reuse must not reset the process-lifetime pipeline nonce"
        );
        assert!(core.promise_store.get(pipeline_promise).is_err());
        assert!(core.promise_store.get(retained_guest_promise).is_ok());
        assert!(core.estimated_memory_bytes() < before_reset);
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes(),
            "reset must release the pipeline state, Promise record, and witness exactly"
        );
    }

    #[test]
    fn pipeline_setup_abandonment_removes_non_tail_promise_bd_fw7zd_13() {
        let mut core = test_core();
        core.next_stream_pipeline_token = 8;
        let pipeline_promise = install_pending_pipeline_fixture(&mut core, 7);

        // This later handle models Promise creation by guest code emitted
        // reentrantly from readable.pipe before setup reports its failure.
        let reentrant_promise = core
            .create_promise()
            .expect("reentrant guest Promise allocation must fit");
        assert!(reentrant_promise > pipeline_promise);
        let before_abandonment = core.estimated_memory_bytes();

        core.abandon_stream_pipeline(7)
            .expect("non-tail pipeline Promise must remain removable");

        assert!(core.promise_store.get(pipeline_promise).is_err());
        assert!(core.promise_store.get(reentrant_promise).is_ok());
        assert_eq!(core.next_stream_pipeline_token, 8);
        assert!(core.estimated_memory_bytes() < before_abandonment);
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes(),
            "non-tail cancellation must update the Promise and pipeline charges exactly"
        );
    }

    fn expect_object_id(value: Value) -> ObjectId {
        match value {
            Value::Object(id) => id,
            other => panic!("expected object value, got {other:?}"),
        }
    }

    pub(in crate::baseline_interpreter) fn call_builtin_for_test(
        core: &mut InterpreterCore,
        builtin: BuiltinFunction,
        receiver: ObjectId,
        args: &[Value],
    ) -> Result<Value, InterpreterError> {
        let count = u32::try_from(args.len()).expect("test argument count fits u32");
        // Accounted writes: a seeded string left in a register is live state
        // the memory walk counts.
        for (register, value) in (0..count).zip(args) {
            core.write_reg(register, value.clone())
                .expect("test argument register");
        }
        let module = halted_test_module();
        core.dispatch_builtin_function(
            &module,
            &builtin,
            RegRange { start: 0, count },
            Some(Value::Object(receiver)),
            None,
        )
    }

    #[test]
    fn direct_import_denies_before_resolution_with_canonical_evidence_bd_iyp3h() {
        let mut module = halted_test_module();
        module.constant_pool = vec!["./missing.mjs".into()];
        module.instructions = vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
                import_attributes: ImportAttributes::default(),
            },
        ];
        let mut core = test_core();

        let error = core
            .execute(&module)
            .expect_err("ImportModule must not reach resolution without ModuleLoad");
        assert_eq!(
            error,
            InterpreterError::CapabilityDenied {
                capability: "module_load".to_string(),
            }
        );
        assert_eq!(core.hostcall_decisions.len(), 1);
        assert_eq!(core.hostcall_decisions[0].capability.0, "module_load");
        assert!(!core.hostcall_decisions[0].allowed);
        assert!(core.witness_events.iter().any(|event| {
            event.kind == WitnessEventKind::CapabilityChecked
                && event.payload_hash == ContentHash::compute(b"denied:module_load")
        }));
        assert!(
            core.hostcall_telemetry().is_empty(),
            "authority denial must happen before module-resolution telemetry"
        );
    }

    #[test]
    fn first_class_require_uses_the_same_canonical_live_gate_bd_iyp3h() {
        let mut core = test_core();
        core.write_reg(0, Value::str("./missing.cjs"))
            .expect("test argument should fit");

        let error = core
            .dispatch_builtin_function(
                &halted_test_module(),
                &BuiltinFunction::require("/tmp/main.cjs"),
                RegRange { start: 0, count: 1 },
                None,
                None,
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
        assert!(core.witness_events.iter().any(|event| {
            event.kind == WitnessEventKind::CapabilityChecked
                && event.payload_hash == ContentHash::compute(b"denied:module_load")
        }));
    }

    #[test]
    fn dense_array_pop_updates_tail_length_without_state_drift() {
        let mut core = test_core();
        let array = core
            .alloc_array_from_values(&[Value::Int(10), Value::Int(20), Value::Int(30)])
            .expect("dense array allocation should succeed");
        let pop = BuiltinFunction::array_pop();

        for (expected_value, expected_length) in [
            (Value::Int(30), 2),
            (Value::Int(20), 1),
            (Value::Int(10), 0),
        ] {
            assert_eq!(
                call_builtin_for_test(&mut core, pop.clone(), array, &[])
                    .expect("dense Array.prototype.pop should succeed"),
                expected_value
            );
            let object = &core.heap[array.0 as usize];
            assert_eq!(
                object.properties.get("length"),
                Some(&Value::Int(expected_length))
            );
            assert_eq!(
                object.cached_dense_length,
                Some(u32::try_from(expected_length).expect("small test length fits u32"))
            );
            assert_eq!(
                object.properties.get(&expected_length.to_string()),
                None,
                "the removed tail must not remain visible"
            );
            assert_eq!(
                core.estimated_memory_bytes(),
                core.recompute_estimated_memory_bytes(),
                "dense pop must keep incremental memory accounting exact"
            );
        }

        let memory_at_empty = core.estimated_memory_bytes();
        assert_eq!(
            call_builtin_for_test(&mut core, pop, array, &[])
                .expect("popping an empty dense array should succeed"),
            Value::Undefined
        );
        assert_eq!(core.estimated_memory_bytes(), memory_at_empty);

        assert_eq!(
            call_builtin_for_test(
                &mut core,
                BuiltinFunction::array_push(),
                array,
                &[Value::Int(40)],
            )
            .expect("push after draining the array should succeed"),
            Value::Int(1)
        );
        let object = &core.heap[array.0 as usize];
        assert_eq!(object.properties.get("0"), Some(&Value::Int(40)));
        assert_eq!(object.properties.get("length"), Some(&Value::Int(1)));
        assert_eq!(object.cached_dense_length, Some(1));
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }

    #[test]
    fn builtin_array_push_persists_argument_label_bd_ojvo1() {
        let mut core = test_core();
        let array = core
            .alloc_array_with_prototype(None)
            .expect("array should allocate");
        core.write_reg_with_label(0, Value::str("classified"), Label::Secret)
            .expect("Secret argument should fit");
        let result = core
            .dispatch_builtin_function(
                &halted_test_module(),
                &BuiltinFunction::array_push(),
                RegRange { start: 0, count: 1 },
                Some(Value::Object(array)),
                None,
            )
            .expect("Array.prototype.push should succeed");
        assert_eq!(result, Value::Int(1));
        assert_eq!(
            core.runtime_property_label(array, &RuntimePropertyKey::String(JsString::from("0")),),
            Label::Secret
        );
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }

    #[test]
    fn sparse_array_pop_keeps_conservative_truncation_fallback() {
        let mut core = test_core();
        let array = core
            .alloc_array_from_values(&[Value::Int(1), Value::Int(2), Value::Int(3)])
            .expect("array allocation should succeed");
        core.set_object_property(array, "5".to_string(), Value::Int(99))
            .expect("low-level sparse index write should succeed");
        assert_eq!(core.heap[array.0 as usize].cached_dense_length, None);

        assert_eq!(
            call_builtin_for_test(&mut core, BuiltinFunction::array_pop(), array, &[])
                .expect("sparse Array.prototype.pop should use the general length setter"),
            Value::Int(3)
        );
        let object = &core.heap[array.0 as usize];
        assert_eq!(object.properties.get("2"), None);
        assert_eq!(
            object.properties.get("5"),
            None,
            "the conservative shrink path must delete a sparse index above the new length"
        );
        assert_eq!(object.properties.get("length"), Some(&Value::Int(2)));
        assert_eq!(object.cached_dense_length, Some(2));
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }

    #[test]
    fn boundary_index_array_pop_keeps_conservative_truncation_fallback() {
        let mut core = test_core();
        let array = core
            .alloc_array_from_values(&[Value::Int(1), Value::Int(2), Value::Int(3)])
            .expect("array allocation should succeed");
        core.set_object_property(array, "3".to_string(), Value::Int(99))
            .expect("low-level boundary index write should succeed");
        assert_eq!(
            core.heap[array.0 as usize].cached_dense_length,
            Some(3),
            "the boundary write is the trusted-cache escape this regression covers"
        );

        assert_eq!(
            call_builtin_for_test(&mut core, BuiltinFunction::array_pop(), array, &[])
                .expect("boundary-index Array.prototype.pop should use the general length setter"),
            Value::Int(3)
        );
        let object = &core.heap[array.0 as usize];
        assert_eq!(object.properties.get("2"), None);
        assert_eq!(
            object.properties.get("3"),
            None,
            "the conservative shrink path must delete the old-length boundary index"
        );
        assert_eq!(object.properties.get("length"), Some(&Value::Int(2)));
        assert_eq!(object.cached_dense_length, Some(2));
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }

    #[test]
    fn frozen_array_pop_preserves_error_and_state() {
        let mut writable = test_core();
        let writable_array = writable
            .alloc_array_from_values(&[Value::Int(7), Value::Int(8)])
            .expect("writable control array");
        assert_eq!(
            call_builtin_for_test(
                &mut writable,
                BuiltinFunction::array_pop(),
                writable_array,
                &[]
            )
            .expect("the same array without freezing must remain writable"),
            Value::Int(8)
        );
        assert_eq!(
            writable.heap[writable_array.0 as usize].properties.get("0"),
            Some(&Value::Int(7))
        );
        assert_eq!(
            writable.heap[writable_array.0 as usize].properties.get("1"),
            None
        );
        assert_eq!(
            writable.heap[writable_array.0 as usize]
                .properties
                .get("length"),
            Some(&Value::Int(1))
        );
        assert!(writable.pending_exception.is_none());
        assert_eq!(
            writable.estimated_memory_bytes(),
            writable.recompute_estimated_memory_bytes()
        );

        let mut core = test_core();
        let array = core
            .alloc_array_from_values(&[Value::Int(7), Value::Int(8)])
            .expect("array allocation should succeed");
        core.mutate_heap(|heap| heap[array.0 as usize].is_frozen = true);
        let memory_before = core.estimated_memory_bytes();

        let error = call_builtin_for_test(&mut core, BuiltinFunction::array_pop(), array, &[])
            .expect_err("popping a frozen array must fail");
        // The scoped builtin boundary materializes language errors before
        // restoring observation labels. The only permitted retained growth
        // is the same TypeError and intrinsic prototypes it requires.
        let mut reference = test_core();
        let reference_array = reference
            .alloc_array_from_values(&[Value::Int(7), Value::Int(8)])
            .expect("reference array allocation should succeed");
        reference.mutate_heap(|heap| heap[reference_array.0 as usize].is_frozen = true);
        assert_eq!(reference.estimated_memory_bytes(), memory_before);
        let expected_error = reference
            .scoped_native_error(&InterpreterError::TypeError {
                expected: "configurable property 1".to_string(),
                got: "a refused [[Delete]]".to_string(),
            })
            .expect("reference TypeError construction should fit the test budget");
        assert!(
            matches!((&error, &expected_error),
                (InterpreterError::UncaughtException { value },
                 InterpreterError::UncaughtException { value: expected }) if value == expected),
            "frozen pop error must remain TypeError; observed {error:?}"
        );
        let Some(Value::Object(error_object)) = core.pending_exception.as_ref() else {
            panic!("frozen pop must retain the actual TypeError object");
        };
        assert_eq!(
            core.chain_data_property(*error_object, "name"),
            Some(&Value::str("TypeError"))
        );
        assert_eq!(core.pending_exception_label, Label::Public);

        let object = &core.heap[array.0 as usize];
        assert_eq!(
            object.properties,
            reference.heap[reference_array.0 as usize].properties
        );
        assert!(object.is_frozen);
        assert_eq!(object.properties.get("1"), Some(&Value::Int(8)));
        assert_eq!(object.properties.get("length"), Some(&Value::Int(2)));
        assert_eq!(object.cached_dense_length, Some(2));
        assert_eq!(
            core.estimated_memory_bytes(),
            reference.estimated_memory_bytes()
        );
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }

    #[test]
    fn array_pop_callmethod_fast_and_forced_fallback_match_invariants() {
        fn execute_pop(force_fallback: bool) -> (InterpreterCore, ExecutionResult, ObjectId) {
            let mut core = test_core();
            core.decision_receipts = EvidenceLog::with_key([0x5A; 32]);
            let array = core
                .alloc_array_from_values(&[Value::Int(10), Value::Int(20), Value::Int(30)])
                .expect("array allocation should succeed");
            core.mutate_heap(|heap| {
                heap[array.0 as usize].cached_dense_length =
                    if force_fallback { None } else { Some(3) };
            });
            assert_eq!(
                core.heap[array.0 as usize].cached_dense_length,
                if force_fallback { None } else { Some(3) },
                "the two arms must differ only in fast-path eligibility"
            );
            core.mutate_registers(|registers| {
                registers[0] = Value::Object(array);
                registers[1] = Value::BuiltinFunction(BuiltinFunction::array_pop());
                registers[2] = Value::Undefined;
            });
            core.set_register_label(0, Label::Secret)
                .expect("receiver label should be settable");
            core.set_register_label(2, Label::Public)
                .expect("destination label should be settable");
            core.sync_estimated_memory_bytes()
                .expect("seeded pop registers should fit memory budget");

            let mut module = halted_test_module();
            module.instructions.insert(
                0,
                Ir3Instruction::CallMethod {
                    receiver: 0,
                    callee: 1,
                    args: RegRange { start: 3, count: 0 },
                    dst: 2,
                },
            );
            let result = core
                .execute(&module)
                .expect("Array.prototype.pop CallMethod should execute");
            (core, result, array)
        }

        let (fast, fast_result, fast_array) = execute_pop(false);
        let (fallback, fallback_result, fallback_array) = execute_pop(true);

        assert_eq!(fallback_array, fast_array);
        assert_eq!(fast.registers[2], Value::Int(30));
        assert_eq!(fallback.registers[2], fast.registers[2]);
        assert_eq!(
            fast.get_register_label(2)
                .expect("fast result label should exist"),
            &Label::Secret
        );
        assert_eq!(
            fallback
                .get_register_label(2)
                .expect("fallback result label should exist"),
            fast.get_register_label(2)
                .expect("fast result label should exist")
        );

        let fast_object = &fast.heap[fast_array.0 as usize];
        let fallback_object = &fallback.heap[fallback_array.0 as usize];
        let fast_properties: Vec<_> = fast_object
            .properties
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
        let fallback_properties: Vec<_> = fallback_object
            .properties
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
        assert_eq!(
            fast_properties,
            vec![
                ("0".to_string(), Value::Int(10)),
                ("1".to_string(), Value::Int(20)),
                ("length".to_string(), Value::Int(2)),
            ]
        );
        assert_eq!(fallback_properties, fast_properties);
        assert_eq!(fast_object.cached_dense_length, Some(2));
        assert_eq!(fallback_object.cached_dense_length, Some(2));
        assert_eq!(
            fast.object_mutation_labels.get(&fast_array),
            Some(&Label::Secret)
        );
        assert_eq!(
            fallback.object_mutation_labels.get(&fallback_array),
            Some(&Label::Secret)
        );

        assert_eq!(
            fast.estimated_memory_bytes(),
            fast.recompute_estimated_memory_bytes(),
            "fast CallMethod execution must preserve exact memory accounting"
        );
        assert_eq!(
            fallback.estimated_memory_bytes(),
            fallback.recompute_estimated_memory_bytes(),
            "fallback CallMethod execution must preserve exact memory accounting"
        );
        assert_eq!(
            fallback.estimated_memory_bytes(),
            fast.estimated_memory_bytes(),
            "fast and fallback arms must retain the same final live state"
        );

        assert_eq!(fast_result.value, Value::Object(fast_array));
        assert_eq!(fallback_result.value, Value::Object(fallback_array));
        assert_eq!(fast_result.completion_label, Label::Secret);
        assert_eq!(
            fallback_result.completion_label,
            fast_result.completion_label
        );
        assert_eq!(
            fallback_result.instructions_executed,
            fast_result.instructions_executed
        );
        assert_eq!(
            fallback_result.requested_hook_action,
            fast_result.requested_hook_action
        );
        assert!(fast_result.requested_hook_action.is_none());
        assert_eq!(fallback_result.witness_events, fast_result.witness_events);
        assert_eq!(
            fallback_result.hostcall_decisions,
            fast_result.hostcall_decisions
        );
        assert!(fast_result.hostcall_decisions.is_empty());
        assert_eq!(fallback_result.events, fast_result.events);
        assert_eq!(fallback_result.console_output, fast_result.console_output);
        assert_eq!(
            fallback_result.iteration_traces,
            fast_result.iteration_traces
        );
        assert_eq!(
            fallback_result.nondeterminism_trace,
            fast_result.nondeterminism_trace
        );
        assert_eq!(
            fallback_result.generated_code_audit,
            fast_result.generated_code_audit
        );
        assert_eq!(
            fallback.decision_receipts().receipts(),
            fast.decision_receipts().receipts()
        );
        assert!(fast.decision_receipts().is_empty());
        assert!(fast.verify_decision_receipt_chain());
        assert!(fallback.verify_decision_receipt_chain());
        assert_eq!(fallback.seed_epoch, fast.seed_epoch);
        assert!(fast.pending_exception.is_none());
        assert!(fallback.pending_exception.is_none());
        assert!(fast.pending_return.is_none());
        assert!(fallback.pending_return.is_none());
    }

    #[test]
    fn array_buffer_constructor_allocates_zero_filled_shared_backing() {
        let mut core = test_core();
        core.mutate_registers(|r| {
            r[0] = Value::Int(3);
        });

        let buffer_id = expect_object_id(
            core.dispatch_builtin_hostcall(
                "builtin:ArrayBuffer",
                RegRange { start: 0, count: 1 },
                None,
            )
            .expect("ArrayBuffer constructor should allocate"),
        );

        let object = core
            .heap
            .get(buffer_id.0 as usize)
            .expect("ArrayBuffer object must be published after successful allocation");
        assert_eq!(object.brand(), Some("ArrayBuffer"));
        assert_eq!(object.properties.get("byteLength"), Some(&Value::Int(3)));
        let backing = object
            .array_buffer
            .as_ref()
            .expect("ArrayBuffer object must carry backing bytes");
        assert_eq!(backing.byte_length(), 3);
        assert_eq!(backing.bytes, vec![0, 0, 0]);
        let object_bytes = InterpreterCore::estimate_heap_object_bytes(object);
        assert!(
            object_bytes >= MEMORY_ESTIMATE_HEAP_OBJECT_BASE_BYTES + 3,
            "ArrayBuffer bytes must be included in deterministic object memory accounting"
        );

        core.with_array_buffer_bytes_mut(buffer_id, |bytes| {
            bytes[1] = 7;
        })
        .expect("shared backing mutation should succeed");
        let observed = core
            .with_array_buffer_bytes(buffer_id, |bytes| bytes.to_vec())
            .expect("shared backing read should succeed");
        assert_eq!(observed, vec![0, 7, 0]);
    }

    #[test]
    fn array_buffer_constructor_rejects_invalid_lengths_without_publication() {
        // ES2020 7.1.22 ToIndex: below 0 or above 2^53 - 1 is a RangeError;
        // a BigInt is the TypeError ToNumber raises. (NaN and 1.5 are valid
        // lengths, 0 and 1: see the next test.)
        let invalid_lengths = [
            (Value::Int(-1), "RangeError"),
            (Value::Float(Float64::new(f64::INFINITY)), "RangeError"),
            (
                Value::Float(Float64::new(9_007_199_254_740_992.0)),
                "RangeError",
            ),
            (Value::BigInt(Arc::from("1")), "TypeError"),
        ];

        for (invalid_length, expected) in invalid_lengths {
            let mut core = test_core();
            core.mutate_registers(|r| {
                r[0] = invalid_length.clone();
            });

            let err = core
                .dispatch_builtin_hostcall(
                    "builtin:ArrayBuffer",
                    RegRange { start: 0, count: 1 },
                    None,
                )
                .expect_err("invalid ArrayBuffer length should fail closed");
            let got = match &err {
                InterpreterError::RangeError { .. } => "RangeError",
                InterpreterError::TypeError { .. } => "TypeError",
                _ => "other",
            };
            assert_eq!(
                got, expected,
                "expected {expected} for {invalid_length:?}, got {err:?}"
            );
            assert_eq!(
                core.heap_size(),
                0,
                "invalid ArrayBuffer length must not publish a partial object"
            );
        }
    }

    #[test]
    fn array_buffer_constructor_length_is_to_index() {
        // ES2020 7.1.22: NaN is 0 and a fraction truncates toward zero; Node
        // v22.2.0 gives byteLength 0, 1 and 2 for these.
        for (length, expected) in [
            (Value::Float(Float64::new(f64::NAN)), 0),
            (Value::Float(Float64::new(1.5)), 1),
            (Value::str("2.9"), 2),
        ] {
            let mut core = test_core();
            core.mutate_registers(|r| {
                r[0] = length.clone();
            });
            let buffer = core
                .dispatch_builtin_hostcall(
                    "builtin:ArrayBuffer",
                    RegRange { start: 0, count: 1 },
                    None,
                )
                .expect("a ToIndex-convertible length allocates");
            let Value::Object(buffer_id) = buffer else {
                panic!("ArrayBuffer constructor must return an object");
            };
            assert_eq!(
                core.array_buffer_byte_length(buffer_id)
                    .expect("byteLength of the new buffer"),
                expected,
                "byteLength for {length:?}"
            );
        }
    }

    #[test]
    fn array_buffer_constructor_respects_caps_and_budget_without_publication() {
        let mut per_buffer_core = test_core();
        per_buffer_core.mutate_registers(|r| {
            r[0] = Value::Int((MAX_ARRAY_BUFFER_BYTE_LENGTH + 1) as i64);
        });
        let per_buffer_err = per_buffer_core
            .dispatch_builtin_hostcall("builtin:ArrayBuffer", RegRange { start: 0, count: 1 }, None)
            .expect_err("oversized ArrayBuffer should fail per-buffer cap");
        assert!(
            matches!(per_buffer_err, InterpreterError::RangeError { .. }),
            "expected RangeError for per-buffer cap, got {per_buffer_err:?}"
        );
        assert_eq!(per_buffer_core.heap_size(), 0);

        let mut config = test_quickjs_config();
        config.max_total_memory_bytes = MEMORY_ESTIMATE_HEAP_OBJECT_BASE_BYTES;
        let mut total_budget_core = InterpreterCore::new(config, "arraybuffer-total-budget");
        total_budget_core.mutate_registers(|r| {
            r[0] = Value::Int(4);
        });
        let total_budget_err = total_budget_core
            .dispatch_builtin_hostcall("builtin:ArrayBuffer", RegRange { start: 0, count: 1 }, None)
            .expect_err("ArrayBuffer should honor total runtime memory budget");
        assert!(
            matches!(
                total_budget_err,
                InterpreterError::MemoryBudgetExceeded { .. }
            ),
            "expected MemoryBudgetExceeded for total cap, got {total_budget_err:?}"
        );
        assert_eq!(
            total_budget_core.heap_size(),
            0,
            "budget rejection must not publish a partial ArrayBuffer object"
        );
    }

    #[test]
    fn typed_array_numeric_length_constructor_allocates_metadata_and_backing() {
        let mut uint8_core = test_core();
        uint8_core.mutate_registers(|r| {
            r[0] = Value::Int(3);
        });
        let uint8_id = expect_object_id(
            uint8_core
                .dispatch_builtin_hostcall(
                    "builtin:Uint8Array",
                    RegRange { start: 0, count: 1 },
                    None,
                )
                .expect("Uint8Array length constructor should allocate"),
        );
        let uint8_object = uint8_core
            .heap
            .get(uint8_id.0 as usize)
            .expect("typed-array view object must be published");
        assert_eq!(uint8_object.brand(), Some("Uint8Array"));
        assert_eq!(uint8_object.properties.get("length"), Some(&Value::Int(3)));
        assert_eq!(
            uint8_object.properties.get("byteLength"),
            Some(&Value::Int(3))
        );
        assert_eq!(
            uint8_object.properties.get("byteOffset"),
            Some(&Value::Int(0))
        );
        let uint8_view = uint8_object
            .typed_array
            .as_ref()
            .expect("Uint8Array object must carry view metadata");
        assert_eq!(uint8_view.kind, TypedArrayKind::Uint8);
        assert_eq!(uint8_view.length, 3);
        assert_eq!(uint8_view.byte_length, 3);
        assert_eq!(
            uint8_core
                .with_array_buffer_bytes(uint8_view.buffer, |bytes| bytes.to_vec())
                .expect("fresh Uint8Array buffer should be readable"),
            vec![0, 0, 0]
        );

        let mut int32_core = test_core();
        int32_core.mutate_registers(|r| {
            r[0] = Value::Int(2);
        });
        let int32_id = expect_object_id(
            int32_core
                .dispatch_builtin_hostcall(
                    "builtin:Int32Array",
                    RegRange { start: 0, count: 1 },
                    None,
                )
                .expect("Int32Array length constructor should allocate"),
        );
        let int32_object = int32_core
            .heap
            .get(int32_id.0 as usize)
            .expect("Int32Array view object must be published");
        assert_eq!(int32_object.properties.get("length"), Some(&Value::Int(2)));
        assert_eq!(
            int32_object.properties.get("byteLength"),
            Some(&Value::Int(8))
        );
        assert_eq!(
            int32_object.properties.get("BYTES_PER_ELEMENT"),
            Some(&Value::Int(4))
        );
        assert_eq!(
            int32_object
                .typed_array
                .as_ref()
                .expect("Int32Array must carry view metadata")
                .kind,
            TypedArrayKind::Int32
        );
    }

    #[test]
    fn typed_array_arraybuffer_constructor_validates_offsets_and_alignment() {
        let mut core = test_core();
        core.mutate_registers(|r| {
            r[0] = Value::Int(12);
        });
        let buffer_id = expect_object_id(
            core.dispatch_builtin_hostcall(
                "builtin:ArrayBuffer",
                RegRange { start: 0, count: 1 },
                None,
            )
            .expect("ArrayBuffer allocation should succeed"),
        );

        core.mutate_registers(|r| {
            r[0] = Value::Object(buffer_id);
            r[1] = Value::Int(4);
            r[2] = Value::Int(2);
        });
        let view_id = expect_object_id(
            core.dispatch_builtin_hostcall(
                "builtin:Uint32Array",
                RegRange { start: 0, count: 3 },
                None,
            )
            .expect("aligned Uint32Array view should allocate"),
        );
        let view = core
            .heap
            .get(view_id.0 as usize)
            .and_then(|object| object.typed_array.as_deref())
            .expect("Uint32Array object must carry view metadata");
        assert_eq!(view.kind, TypedArrayKind::Uint32);
        assert_eq!(view.buffer, buffer_id);
        assert_eq!(view.byte_offset, 4);
        assert_eq!(view.byte_length, 8);
        assert_eq!(view.length, 2);

        let heap_size_before_bad_offset = core.heap_size();
        core.mutate_registers(|r| {
            r[0] = Value::Object(buffer_id);
            r[1] = Value::Int(1);
        });
        let bad_offset = core
            .dispatch_builtin_hostcall("builtin:Int32Array", RegRange { start: 0, count: 2 }, None)
            .expect_err("misaligned Int32Array byteOffset should fail closed");
        assert!(
            matches!(bad_offset, InterpreterError::RangeError { .. }),
            "expected RangeError for misaligned offset, got {bad_offset:?}"
        );
        assert_eq!(
            core.heap_size(),
            heap_size_before_bad_offset,
            "misaligned view must not publish a partial typed-array object"
        );

        core.mutate_registers(|r| {
            r[0] = Value::Int(5);
        });
        let odd_buffer = expect_object_id(
            core.dispatch_builtin_hostcall(
                "builtin:ArrayBuffer",
                RegRange { start: 0, count: 1 },
                None,
            )
            .expect("odd byteLength ArrayBuffer should allocate"),
        );
        let heap_size_before_bad_length = core.heap_size();
        core.mutate_registers(|r| {
            r[0] = Value::Object(odd_buffer);
        });
        let bad_length = core
            .dispatch_builtin_hostcall("builtin:Uint32Array", RegRange { start: 0, count: 1 }, None)
            .expect_err("implicit Uint32Array byteLength must align to element size");
        assert!(
            matches!(bad_length, InterpreterError::RangeError { .. }),
            "expected RangeError for non-multiple view byteLength, got {bad_length:?}"
        );
        assert_eq!(
            core.heap_size(),
            heap_size_before_bad_length,
            "invalid view byteLength must not publish a partial typed-array object"
        );
    }

    #[test]
    fn typed_array_views_share_arraybuffer_backing_store() {
        let mut core = test_core();
        core.mutate_registers(|r| {
            r[0] = Value::Int(4);
        });
        let buffer_id = expect_object_id(
            core.dispatch_builtin_hostcall(
                "builtin:ArrayBuffer",
                RegRange { start: 0, count: 1 },
                None,
            )
            .expect("ArrayBuffer allocation should succeed"),
        );

        core.mutate_registers(|r| {
            r[0] = Value::Object(buffer_id);
        });
        let full_view = expect_object_id(
            core.dispatch_builtin_hostcall(
                "builtin:Uint8Array",
                RegRange { start: 0, count: 1 },
                None,
            )
            .expect("full Uint8Array view should allocate"),
        );
        core.mutate_registers(|r| {
            r[0] = Value::Object(buffer_id);
            r[1] = Value::Int(1);
            r[2] = Value::Int(2);
        });
        let window_view = expect_object_id(
            core.dispatch_builtin_hostcall(
                "builtin:Uint8Array",
                RegRange { start: 0, count: 3 },
                None,
            )
            .expect("windowed Uint8Array view should allocate"),
        );

        let full = core
            .heap
            .get(full_view.0 as usize)
            .and_then(|object| object.typed_array.as_deref())
            .expect("full view metadata should exist");
        let window = core
            .heap
            .get(window_view.0 as usize)
            .and_then(|object| object.typed_array.as_deref())
            .expect("window view metadata should exist");
        assert_eq!(full.buffer, buffer_id);
        assert_eq!(window.buffer, buffer_id);
        assert_eq!(window.byte_offset, 1);
        assert_eq!(window.length, 2);

        core.with_array_buffer_bytes_mut(buffer_id, |bytes| {
            bytes[2] = 9;
        })
        .expect("shared backing mutation should succeed");
        assert_eq!(
            core.with_array_buffer_bytes(buffer_id, |bytes| bytes.to_vec())
                .expect("shared backing read should succeed"),
            vec![0, 0, 9, 0]
        );
    }

    #[test]
    fn binary_backing_labels_survive_aliases_and_copy_destinations() {
        let mut core = test_core();
        let source = core
            .alloc_fresh_buffer_object(4, None, 0)
            .expect("source Buffer should allocate");
        let source_buffer = core
            .typed_array_view_for_object(source)
            .expect("source lookup should succeed")
            .expect("source must be a typed-array view")
            .buffer;
        let alias = core
            .alloc_buffer_view_object(source_buffer, 1, 2)
            .expect("shared Buffer alias should allocate");

        core.join_binary_storage_label(source, &Label::Secret)
            .expect("binary label join fits test budget");
        assert_eq!(core.binary_storage_label(source), Label::Secret);
        assert_eq!(
            core.binary_storage_label(alias),
            Label::Secret,
            "a shared view must observe the backing store's IFC label"
        );

        let target = core
            .alloc_fresh_buffer_object(4, None, 0)
            .expect("copy target Buffer should allocate");
        core.mutate_registers(|registers| registers[0] = Value::Object(target));
        let copy = BuiltinFunction::new_kind(BuiltinFunctionKind::BufferCopy);
        core.propagate_builtin_binary_mutation_label(
            &copy,
            &Value::Object(source),
            RegRange { start: 0, count: 1 },
            &Label::Secret,
        )
        .expect("copy label propagation should succeed");
        assert_eq!(
            core.binary_storage_label(target),
            Label::Secret,
            "copying Secret bytes must taint the destination backing"
        );
    }

    /// bd-9vouw.245: an Atomics write joins its arguments' labels into the
    /// backing bytes, and an Atomics read answers with the bytes' label, as
    /// the typed array element paths do.
    #[test]
    fn atomics_writes_taint_and_reads_carry_the_backing_label_bd_9vouw_245() {
        let mut core = test_core();
        let module = halted_test_module();
        core.write_reg(0, Value::Int(4)).expect("length register");
        let view = expect_object_id(
            core.dispatch_builtin_hostcall(
                "builtin:Int32Array",
                RegRange { start: 0, count: 1 },
                None,
            )
            .expect("Int32Array allocates"),
        );
        core.write_reg(0, Value::Object(view))
            .expect("view register");
        core.write_reg(1, Value::Int(0)).expect("index register");
        core.write_reg_with_label(2, Value::Int(7), Label::Secret)
            .expect("Secret value register");
        let store = BuiltinFunction::atomics_method("store").expect("store is an Atomics method");
        core.clear_pending_hostcall_result_label();
        core.atomics_method_call(&module, &store, RegRange { start: 0, count: 3 })
            .expect("store succeeds");
        assert_eq!(
            core.binary_storage_label(view),
            Label::Secret,
            "a Secret store must taint the backing bytes"
        );

        core.write_reg_with_label(2, Value::Undefined, Label::Public)
            .expect("Public register");
        core.clear_pending_hostcall_result_label();
        let load = BuiltinFunction::atomics_method("load").expect("load is an Atomics method");
        let value = core
            .atomics_method_call(&module, &load, RegRange { start: 0, count: 2 })
            .expect("load succeeds");
        assert_eq!(value, Value::Int(7));
        assert_eq!(
            core.take_pending_hostcall_result_label(),
            Some(Label::Secret),
            "a load from Secret bytes must answer Secret"
        );
    }

    #[test]
    fn fresh_buffer_pair_allocation_is_atomic_and_capability_gated() {
        let mut heap_limited = test_core();
        let before_heap = heap_limited.heap_size();
        let before_memory = heap_limited.estimated_memory_bytes();
        heap_limited.config.max_heap_objects = before_heap as u32 + 1;
        let error = heap_limited
            .alloc_fresh_buffer_object(8, None, 0)
            .expect_err("a Buffer requires one backing plus one view object");
        assert!(matches!(
            error,
            InterpreterError::MemoryBudgetExceeded { .. }
        ));
        assert_eq!(heap_limited.heap_size(), before_heap);
        assert_eq!(heap_limited.estimated_memory_bytes(), before_memory);

        let mut denied = test_core();
        denied
            .config
            .granted_capabilities
            .remove(&RuntimeCapability::HeapAllocate);
        let error = denied
            .alloc_fresh_buffer_object(8, None, 0)
            .expect_err("Buffer allocation must require HeapAllocate");
        assert!(matches!(error, InterpreterError::CapabilityDenied { .. }));
        assert_eq!(denied.heap_size(), 0);
    }

    #[test]
    fn typed_array_array_like_constructor_copies_current_object_model_values() {
        let mut core = test_core();
        let source = core
            .alloc_array_from_values(&[Value::Int(-1), Value::Int(256), Value::Int(2)])
            .expect("source array allocation should succeed");
        core.mutate_registers(|r| {
            r[0] = Value::Object(source);
        });
        let view_id = expect_object_id(
            core.dispatch_builtin_hostcall(
                "builtin:Uint8Array",
                RegRange { start: 0, count: 1 },
                None,
            )
            .expect("Uint8Array array-like constructor should allocate"),
        );
        let buffer = core
            .heap
            .get(view_id.0 as usize)
            .and_then(|object| object.typed_array.as_deref())
            .map(|view| view.buffer)
            .expect("view metadata should expose backing buffer");
        assert_eq!(
            core.with_array_buffer_bytes(buffer, |bytes| bytes.to_vec())
                .expect("array-like copied backing should be readable"),
            vec![255, 0, 2]
        );
    }

    #[test]
    fn typed_array_indexed_get_set_routes_through_backing_store() {
        let mut core = test_core();
        core.mutate_registers(|r| {
            r[0] = Value::Int(3);
        });
        let view_id = expect_object_id(
            core.dispatch_builtin_hostcall(
                "builtin:Uint8Array",
                RegRange { start: 0, count: 1 },
                None,
            )
            .expect("Uint8Array constructor should allocate indexed storage"),
        );

        assert!(
            core.proxy_aware_set_property(
                None,
                view_id,
                "0",
                Value::Int(255),
                Value::Object(view_id),
                0,
            )
            .expect("typed-array index set should succeed")
        );
        assert!(
            core.proxy_aware_set_property(
                None,
                view_id,
                "1",
                Value::Int(1),
                Value::Object(view_id),
                0
            )
            .expect("typed-array second index set should succeed")
        );
        assert_eq!(
            core.proxy_aware_get_property(None, view_id, "0", Value::Object(view_id), 0)
                .expect("typed-array index read should succeed"),
            Value::Int(255)
        );
        assert_eq!(
            core.proxy_aware_get_property(None, view_id, "1", Value::Object(view_id), 0)
                .expect("typed-array second index read should succeed"),
            Value::Int(1)
        );

        let view = core
            .heap
            .get(view_id.0 as usize)
            .and_then(|object| object.typed_array.as_deref())
            .expect("view metadata must remain attached")
            .clone();
        assert_eq!(
            core.with_array_buffer_bytes(view.buffer, |bytes| bytes.to_vec())
                .expect("typed-array backing store should be readable"),
            vec![255, 1, 0]
        );
    }

    #[test]
    fn typed_array_numeric_coercion_wraps_uint8_int32_and_uint32() {
        let mut core = test_core();
        core.mutate_registers(|r| {
            r[0] = Value::Int(2);
        });
        let uint8_id = expect_object_id(
            core.dispatch_builtin_hostcall(
                "builtin:Uint8Array",
                RegRange { start: 0, count: 1 },
                None,
            )
            .expect("Uint8Array should allocate"),
        );
        core.typed_array_indexed_set_property(uint8_id, "0", &Value::Int(256))
            .expect("Uint8Array wrap write should succeed");
        core.typed_array_indexed_set_property(uint8_id, "1", &Value::Int(-1))
            .expect("Uint8Array negative wrap write should succeed");
        assert_eq!(
            core.typed_array_indexed_get_property(uint8_id, "0")
                .expect("Uint8Array wrapped zero should read")
                .expect("Uint8Array index should be handled"),
            Value::Int(0)
        );
        assert_eq!(
            core.typed_array_indexed_get_property(uint8_id, "1")
                .expect("Uint8Array wrapped 255 should read")
                .expect("Uint8Array index should be handled"),
            Value::Int(255)
        );

        core.mutate_registers(|r| {
            r[0] = Value::Int(2);
        });
        let int32_id = expect_object_id(
            core.dispatch_builtin_hostcall(
                "builtin:Int32Array",
                RegRange { start: 0, count: 1 },
                None,
            )
            .expect("Int32Array should allocate"),
        );
        core.typed_array_indexed_set_property(int32_id, "0", &Value::Int(2_147_483_648))
            .expect("Int32Array signed wrap write should succeed");
        core.typed_array_indexed_set_property(int32_id, "1", &Value::Int(-1))
            .expect("Int32Array negative write should succeed");
        assert_eq!(
            core.typed_array_indexed_get_property(int32_id, "0")
                .expect("Int32Array signed value should read")
                .expect("Int32Array index should be handled"),
            Value::Int(-2_147_483_648)
        );
        assert_eq!(
            core.typed_array_indexed_get_property(int32_id, "1")
                .expect("Int32Array -1 should read")
                .expect("Int32Array index should be handled"),
            Value::Int(-1)
        );

        core.mutate_registers(|r| {
            r[0] = Value::Int(2);
        });
        let uint32_id = expect_object_id(
            core.dispatch_builtin_hostcall(
                "builtin:Uint32Array",
                RegRange { start: 0, count: 1 },
                None,
            )
            .expect("Uint32Array should allocate"),
        );
        core.typed_array_indexed_set_property(uint32_id, "0", &Value::Int(-1))
            .expect("Uint32Array unsigned wrap write should succeed");
        core.typed_array_indexed_set_property(uint32_id, "1", &Value::Int(4_294_967_296))
            .expect("Uint32Array modulo write should succeed");
        assert_eq!(
            core.typed_array_indexed_get_property(uint32_id, "0")
                .expect("Uint32Array wrapped max should read")
                .expect("Uint32Array index should be handled"),
            Value::Int(4_294_967_295)
        );
        assert_eq!(
            core.typed_array_indexed_get_property(uint32_id, "1")
                .expect("Uint32Array wrapped zero should read")
                .expect("Uint32Array index should be handled"),
            Value::Int(0)
        );
    }

    #[test]
    fn typed_array_out_of_bounds_and_non_index_properties_are_spec_shaped() {
        let mut core = test_core();
        core.mutate_registers(|r| {
            r[0] = Value::Int(1);
        });
        let view_id = expect_object_id(
            core.dispatch_builtin_hostcall(
                "builtin:Uint8Array",
                RegRange { start: 0, count: 1 },
                None,
            )
            .expect("Uint8Array should allocate"),
        );

        assert_eq!(
            core.typed_array_indexed_set_property(view_id, "1", &Value::Int(7))
                .expect("out-of-bounds typed-array write should be accepted"),
            Some(true)
        );
        assert_eq!(
            core.typed_array_indexed_get_property(view_id, "1")
                .expect("out-of-bounds typed-array read should be accepted"),
            Some(Value::Undefined)
        );
        assert!(
            !core
                .heap
                .get(view_id.0 as usize)
                .expect("view object must exist")
                .properties
                .contains_key("1"),
            "out-of-bounds integer-indexed writes must not create ordinary object properties"
        );

        assert!(
            core.proxy_aware_set_property(
                None,
                view_id,
                "foo",
                Value::Int(9),
                Value::Object(view_id),
                0
            )
            .expect("non-index property write should succeed")
        );
        assert!(
            core.proxy_aware_set_property(
                None,
                view_id,
                "01",
                Value::Int(7),
                Value::Object(view_id),
                0
            )
            .expect("leading-zero non-index property write should succeed")
        );
        assert_eq!(
            core.proxy_aware_get_property(None, view_id, "foo", Value::Object(view_id), 0)
                .expect("non-index property read should succeed"),
            Value::Int(9)
        );
        assert_eq!(
            core.proxy_aware_get_property(None, view_id, "01", Value::Object(view_id), 0)
                .expect("leading-zero non-index property read should succeed"),
            Value::Int(7)
        );
        let buffer = core
            .heap
            .get(view_id.0 as usize)
            .and_then(|object| object.typed_array.as_deref())
            .map(|view| view.buffer)
            .expect("typed-array metadata should expose backing buffer");
        assert_eq!(
            core.with_array_buffer_bytes(buffer, |bytes| bytes.to_vec())
                .expect("backing store should remain readable"),
            vec![0],
            "ordinary non-index properties must not mutate typed-array element storage"
        );
    }

    #[test]
    fn data_view_constructor_allocates_byte_window_metadata() {
        let mut core = test_core();
        core.mutate_registers(|r| {
            r[0] = Value::Int(8);
        });
        let buffer_id = expect_object_id(
            core.dispatch_builtin_hostcall(
                "builtin:ArrayBuffer",
                RegRange { start: 0, count: 1 },
                None,
            )
            .expect("ArrayBuffer allocation should succeed"),
        );

        core.mutate_registers(|r| {
            r[0] = Value::Object(buffer_id);
            r[1] = Value::Int(2);
            r[2] = Value::Int(4);
        });
        let view_id = expect_object_id(
            core.dispatch_builtin_hostcall(
                "builtin:DataView",
                RegRange { start: 0, count: 3 },
                None,
            )
            .expect("DataView should allocate a byte-addressed view"),
        );
        let view_object = core
            .heap
            .get(view_id.0 as usize)
            .expect("DataView object must be published");
        assert_eq!(view_object.brand(), Some("DataView"));
        assert_eq!(
            view_object.properties.get("buffer"),
            Some(&Value::Object(buffer_id))
        );
        assert_eq!(
            view_object.properties.get("byteOffset"),
            Some(&Value::Int(2))
        );
        assert_eq!(
            view_object.properties.get("byteLength"),
            Some(&Value::Int(4))
        );
        let view = view_object
            .data_view
            .as_ref()
            .expect("DataView object must carry view metadata");
        assert_eq!(view.buffer, buffer_id);
        assert_eq!(view.byte_offset, 2);
        assert_eq!(view.byte_length, 4);

        let heap_size_before_bad_offset = core.heap_size();
        core.mutate_registers(|r| {
            r[0] = Value::Object(buffer_id);
            r[1] = Value::Int(9);
        });
        let bad_offset = core
            .dispatch_builtin_hostcall("builtin:DataView", RegRange { start: 0, count: 2 }, None)
            .expect_err("DataView byteOffset beyond buffer should fail closed");
        assert!(
            matches!(bad_offset, InterpreterError::RangeError { .. }),
            "expected RangeError for DataView byteOffset, got {bad_offset:?}"
        );
        assert_eq!(
            core.heap_size(),
            heap_size_before_bad_offset,
            "invalid DataView byteOffset must not publish a partial view"
        );

        core.mutate_registers(|r| {
            r[0] = Value::Object(buffer_id);
            r[1] = Value::Int(6);
            r[2] = Value::Int(3);
        });
        let bad_length = core
            .dispatch_builtin_hostcall("builtin:DataView", RegRange { start: 0, count: 3 }, None)
            .expect_err("DataView byteLength beyond buffer should fail closed");
        assert!(
            matches!(bad_length, InterpreterError::RangeError { .. }),
            "expected RangeError for DataView byteLength, got {bad_length:?}"
        );
        assert_eq!(
            core.heap_size(),
            heap_size_before_bad_offset,
            "invalid DataView byteLength must not publish a partial view"
        );
    }

    #[test]
    fn data_view_integer_accessors_obey_endianness_and_numeric_coercion() {
        let mut core = test_core();
        core.mutate_registers(|r| {
            r[0] = Value::Int(8);
        });
        let buffer_id = expect_object_id(
            core.dispatch_builtin_hostcall(
                "builtin:ArrayBuffer",
                RegRange { start: 0, count: 1 },
                None,
            )
            .expect("ArrayBuffer allocation should succeed"),
        );
        core.mutate_registers(|r| {
            r[0] = Value::Object(buffer_id);
        });
        let view_id = expect_object_id(
            core.dispatch_builtin_hostcall(
                "builtin:DataView",
                RegRange { start: 0, count: 1 },
                None,
            )
            .expect("DataView should allocate"),
        );

        assert_eq!(
            call_builtin_for_test(
                &mut core,
                BuiltinFunction::data_view_set_uint32(),
                view_id,
                &[Value::Int(0), Value::Int(16_909_060), Value::Bool(false)],
            )
            .expect("setUint32 big-endian should succeed"),
            Value::Undefined
        );
        assert_eq!(
            call_builtin_for_test(
                &mut core,
                BuiltinFunction::data_view_get_uint8(),
                view_id,
                &[Value::Int(0)],
            )
            .expect("getUint8 should read the first big-endian byte"),
            Value::Int(1)
        );
        assert_eq!(
            call_builtin_for_test(
                &mut core,
                BuiltinFunction::data_view_get_uint32(),
                view_id,
                &[Value::Int(0), Value::Bool(false)],
            )
            .expect("getUint32 big-endian should round-trip"),
            Value::Int(16_909_060)
        );

        call_builtin_for_test(
            &mut core,
            BuiltinFunction::data_view_set_uint32(),
            view_id,
            &[Value::Int(0), Value::Int(16_909_060), Value::Bool(true)],
        )
        .expect("setUint32 little-endian should succeed");
        assert_eq!(
            core.with_array_buffer_bytes(buffer_id, |bytes| bytes[0..4].to_vec())
                .expect("ArrayBuffer bytes should be readable"),
            vec![4, 3, 2, 1]
        );
        assert_eq!(
            call_builtin_for_test(
                &mut core,
                BuiltinFunction::data_view_get_uint32(),
                view_id,
                &[Value::Int(0), Value::Bool(true)],
            )
            .expect("getUint32 little-endian should round-trip"),
            Value::Int(16_909_060)
        );

        call_builtin_for_test(
            &mut core,
            BuiltinFunction::data_view_set_int32(),
            view_id,
            &[Value::Int(0), Value::Int(2_147_483_648), Value::Bool(false)],
        )
        .expect("setInt32 should apply Int32 coercion");
        assert_eq!(
            call_builtin_for_test(
                &mut core,
                BuiltinFunction::data_view_get_int32(),
                view_id,
                &[Value::Int(0), Value::Bool(false)],
            )
            .expect("getInt32 should read signed value"),
            Value::Int(-2_147_483_648)
        );

        call_builtin_for_test(
            &mut core,
            BuiltinFunction::data_view_set_uint8(),
            view_id,
            &[Value::Int(3), Value::Int(256)],
        )
        .expect("setUint8 should wrap modulo 256");
        assert_eq!(
            call_builtin_for_test(
                &mut core,
                BuiltinFunction::data_view_get_uint8(),
                view_id,
                &[Value::Int(3)],
            )
            .expect("getUint8 should read wrapped byte"),
            Value::Int(0)
        );
    }

    #[test]
    fn data_view_and_typed_arrays_share_arraybuffer_backing_store() {
        let mut core = test_core();
        core.mutate_registers(|r| {
            r[0] = Value::Int(4);
        });
        let buffer_id = expect_object_id(
            core.dispatch_builtin_hostcall(
                "builtin:ArrayBuffer",
                RegRange { start: 0, count: 1 },
                None,
            )
            .expect("ArrayBuffer allocation should succeed"),
        );
        core.mutate_registers(|r| {
            r[0] = Value::Object(buffer_id);
        });
        let data_view_id = expect_object_id(
            core.dispatch_builtin_hostcall(
                "builtin:DataView",
                RegRange { start: 0, count: 1 },
                None,
            )
            .expect("DataView should allocate"),
        );
        core.mutate_registers(|r| {
            r[0] = Value::Object(buffer_id);
        });
        let uint8_id = expect_object_id(
            core.dispatch_builtin_hostcall(
                "builtin:Uint8Array",
                RegRange { start: 0, count: 1 },
                None,
            )
            .expect("Uint8Array should allocate"),
        );

        call_builtin_for_test(
            &mut core,
            BuiltinFunction::data_view_set_uint8(),
            data_view_id,
            &[Value::Int(0), Value::Int(42)],
        )
        .expect("DataView write should succeed");
        assert_eq!(
            core.typed_array_indexed_get_property(uint8_id, "0")
                .expect("typed-array read should succeed")
                .expect("typed-array index should be handled"),
            Value::Int(42)
        );

        core.typed_array_indexed_set_property(uint8_id, "1", &Value::Int(7))
            .expect("typed-array write should succeed");
        assert_eq!(
            call_builtin_for_test(
                &mut core,
                BuiltinFunction::data_view_get_uint8(),
                data_view_id,
                &[Value::Int(1)],
            )
            .expect("DataView read should observe typed-array write"),
            Value::Int(7)
        );
    }

    #[test]
    fn typed_array_set_fill_and_copy_within_mutate_backing_store() {
        let mut core = test_core();
        core.mutate_registers(|r| {
            r[0] = Value::Int(5);
        });
        let view_id = expect_object_id(
            core.dispatch_builtin_hostcall(
                "builtin:Uint8Array",
                RegRange { start: 0, count: 1 },
                None,
            )
            .expect("Uint8Array should allocate"),
        );
        let source = core
            .alloc_array_from_values(&[Value::Int(9), Value::Int(8)])
            .expect("source array should allocate");

        assert_eq!(
            call_builtin_for_test(
                &mut core,
                BuiltinFunction::typed_array_fill(),
                view_id,
                &[Value::Int(1)],
            )
            .expect("fill should succeed"),
            Value::Object(view_id)
        );
        assert_eq!(
            call_builtin_for_test(
                &mut core,
                BuiltinFunction::typed_array_set(),
                view_id,
                &[Value::Object(source), Value::Int(1)],
            )
            .expect("set should succeed"),
            Value::Undefined
        );
        assert_eq!(
            call_builtin_for_test(
                &mut core,
                BuiltinFunction::typed_array_copy_within(),
                view_id,
                &[Value::Int(3), Value::Int(1), Value::Int(3)],
            )
            .expect("copyWithin should succeed"),
            Value::Object(view_id)
        );

        let view = core
            .heap
            .get(view_id.0 as usize)
            .and_then(|object| object.typed_array.as_deref())
            .expect("view metadata should exist")
            .clone();
        assert_eq!(
            core.with_array_buffer_bytes(view.buffer, |bytes| bytes.to_vec())
                .expect("backing store should be readable"),
            vec![1, 9, 8, 9, 8]
        );
    }

    #[test]
    fn typed_array_subarray_shares_and_slice_copies_backing_store() {
        let mut core = test_core();
        let source = core
            .alloc_array_from_values(&[
                Value::Int(10),
                Value::Int(20),
                Value::Int(30),
                Value::Int(40),
            ])
            .expect("source array should allocate");
        core.mutate_registers(|r| {
            r[0] = Value::Object(source);
        });
        let view_id = expect_object_id(
            core.dispatch_builtin_hostcall(
                "builtin:Uint8Array",
                RegRange { start: 0, count: 1 },
                None,
            )
            .expect("Uint8Array should copy source values"),
        );

        let subarray_id = expect_object_id(
            call_builtin_for_test(
                &mut core,
                BuiltinFunction::typed_array_subarray(),
                view_id,
                &[Value::Int(1), Value::Int(3)],
            )
            .expect("subarray should allocate shared view"),
        );
        let slice_id = expect_object_id(
            call_builtin_for_test(
                &mut core,
                BuiltinFunction::typed_array_slice(),
                view_id,
                &[Value::Int(1), Value::Int(3)],
            )
            .expect("slice should allocate copied view"),
        );

        core.typed_array_indexed_set_property(subarray_id, "0", &Value::Int(99))
            .expect("subarray write should succeed");
        assert_eq!(
            core.typed_array_indexed_get_property(view_id, "1")
                .expect("parent read should succeed")
                .expect("typed-array index should be handled"),
            Value::Int(99),
            "subarray writes must be visible through the parent backing store"
        );
        assert_eq!(
            core.typed_array_indexed_get_property(slice_id, "0")
                .expect("slice read should succeed")
                .expect("typed-array index should be handled"),
            Value::Int(20),
            "slice must preserve copied bytes after parent mutation"
        );

        core.typed_array_indexed_set_property(slice_id, "1", &Value::Int(77))
            .expect("slice write should succeed");
        assert_eq!(
            core.typed_array_indexed_get_property(view_id, "2")
                .expect("parent read should succeed")
                .expect("typed-array index should be handled"),
            Value::Int(30),
            "slice writes must not mutate the original backing store"
        );
    }

    #[test]
    fn typed_array_methods_cover_int32_and_array_conversion_hooks() {
        let mut core = test_core();
        core.mutate_registers(|r| {
            r[0] = Value::Int(3);
        });
        let view_id = expect_object_id(
            core.dispatch_builtin_hostcall(
                "builtin:Int32Array",
                RegRange { start: 0, count: 1 },
                None,
            )
            .expect("Int32Array should allocate"),
        );
        let source = core
            .alloc_array_from_values(&[Value::Int(2_147_483_648), Value::Int(-1)])
            .expect("source array should allocate");

        call_builtin_for_test(
            &mut core,
            BuiltinFunction::typed_array_fill(),
            view_id,
            &[Value::Int(1)],
        )
        .expect("Int32Array fill should succeed");
        call_builtin_for_test(
            &mut core,
            BuiltinFunction::typed_array_set(),
            view_id,
            &[Value::Object(source), Value::Int(1)],
        )
        .expect("Int32Array set should succeed");
        assert_eq!(
            core.typed_array_indexed_get_property(view_id, "1")
                .expect("Int32Array read should succeed")
                .expect("typed-array index should be handled"),
            Value::Int(-2_147_483_648)
        );
        assert_eq!(
            core.array_like_values(view_id)
                .expect("array-like conversion should read Int32Array bytes"),
            vec![Value::Int(1), Value::Int(-2_147_483_648), Value::Int(-1)]
        );

        let unsupported = call_builtin_for_test(
            &mut core,
            BuiltinFunction::typed_array_unsupported_method(),
            view_id,
            &[],
        )
        .expect_err("unsupported typed-array methods should fail clearly");
        assert!(
            matches!(unsupported, InterpreterError::TypeError { .. }),
            "expected deterministic TypeError for unsupported typed-array method, got {unsupported:?}"
        );
    }

    // -- bd-8enww.3.4 (YTBG-C4): generated-code provenance + security envelope --

    #[test]
    fn generated_provenance_is_deterministic_and_well_formed() {
        let a =
            InterpreterCore::derive_generated_function_provenance("<eval>", "x", "return x * 2;");
        let b =
            InterpreterCore::derive_generated_function_provenance("<eval>", "x", "return x * 2;");
        // Pure function of (site, params, body): identical inputs ⇒ identical id.
        assert_eq!(a, b);
        // Synthetic id shape: `genfn:` + 16 lowercase hex chars.
        assert!(a.source_id.starts_with("genfn:"), "{}", a.source_id);
        let hex = a.source_id.trim_start_matches("genfn:");
        assert_eq!(hex.len(), 16, "{}", a.source_id);
        assert!(
            hex.bytes().all(|b| b.is_ascii_hexdigit()),
            "{}",
            a.source_id
        );
        // The component hashes are full SHA-256 hex.
        assert_eq!(a.source_hash.len(), 64);
        assert_eq!(a.parameter_hash.len(), 64);
        assert_eq!(a.construction_site, "<eval>");
    }

    #[test]
    fn generated_provenance_distinguishes_body_params_and_site() {
        let base =
            InterpreterCore::derive_generated_function_provenance("<eval>", "x", "return x;");
        let other_body =
            InterpreterCore::derive_generated_function_provenance("<eval>", "x", "return x + 1;");
        let other_params =
            InterpreterCore::derive_generated_function_provenance("<eval>", "y", "return x;");
        let other_site =
            InterpreterCore::derive_generated_function_provenance("<mod-a>", "x", "return x;");
        // No two distinct (site, params, body) triples collide on the source id.
        assert_ne!(base.source_id, other_body.source_id);
        assert_ne!(base.source_id, other_params.source_id);
        assert_ne!(base.source_id, other_site.source_id);
        // The body hash is sensitive to the body, the parameter hash to params.
        assert_ne!(base.source_hash, other_body.source_hash);
        assert_ne!(base.parameter_hash, other_params.parameter_hash);
    }

    #[test]
    fn generated_provenance_length_prefix_prevents_field_collision() {
        // Without length-prefixing, ("ab", "c") and ("a", "bc") would mix to the
        // same byte stream. The canonical encoding must keep them distinct.
        let left = InterpreterCore::derive_generated_function_provenance("<eval>", "ab", "c");
        let right = InterpreterCore::derive_generated_function_provenance("<eval>", "a", "bc");
        assert_ne!(left.source_id, right.source_id);
    }

    #[test]
    fn contained_codegen_envelope_filters_out_dangerous_capabilities() {
        // A generated module that *declares* dangerous authority (fs/process/
        // network) is granted ONLY the safe subset. This is the security-
        // accounting core of AC#4: constructing code at runtime can never be an
        // authority-escalation vector beyond the safe ceiling.
        let declared = [
            CapabilityTag("builtin".to_string()),
            CapabilityTag("fs_read".to_string()),
            CapabilityTag("fs_write".to_string()),
            CapabilityTag("process_spawn".to_string()),
            CapabilityTag("network_egress".to_string()),
            CapabilityTag("console".to_string()),
            CapabilityTag("timer".to_string()),
        ];
        let granted = InterpreterCore::contained_codegen_capability_grant(&declared);
        assert!(granted.contains(&RuntimeCapability::Builtin));
        assert!(granted.contains(&RuntimeCapability::Console));
        assert!(granted.contains(&RuntimeCapability::Timer));
        for dangerous in [
            RuntimeCapability::FsRead,
            RuntimeCapability::FsWrite,
            RuntimeCapability::ProcessSpawn,
            RuntimeCapability::NetworkEgress,
        ] {
            assert!(
                !granted.contains(&dangerous),
                "dynamic code must never receive {dangerous} by declaring it"
            );
        }
        assert_eq!(granted.len(), 3);
    }

    #[test]
    fn contained_codegen_envelope_is_empty_for_no_or_unknown_tags() {
        assert!(InterpreterCore::contained_codegen_capability_grant(&[]).is_empty());
        let unknown = [CapabilityTag("not_a_real_capability".to_string())];
        assert!(InterpreterCore::contained_codegen_capability_grant(&unknown).is_empty());
    }

    #[test]
    fn contained_codegen_runtime_inference_is_canonical_name_bound_bd_fw7zd_8_4() {
        fn load_name_module(name: &str) -> Ir3Module {
            let mut module = halted_test_module();
            module.instructions = vec![
                Ir3Instruction::LoadName {
                    dst: 0,
                    name_pool_index: 0,
                    allow_missing: false,
                },
                Ir3Instruction::Halt,
            ];
            module.constant_pool = vec![name.into()];
            module
        }

        let mut core = test_core();
        core.ensure_generated_function_realm_globals()
            .expect("initialize canonical generated realm");
        let canonical_frame = core
            .generated_function_realm_scope_frame()
            .expect("clone canonical generated realm frame");

        for (name, expected) in [
            ("console", RuntimeCapability::Console),
            ("setTimeout", RuntimeCapability::Timer),
            ("Math", RuntimeCapability::Builtin),
        ] {
            assert_eq!(
                core.contained_codegen_effective_capability_grant(
                    &load_name_module(name),
                    &canonical_frame,
                )
                .expect("derive canonical runtime-name authority")
                .into_iter()
                .collect::<BTreeSet<_>>(),
                BTreeSet::from([
                    RuntimeCapability::VmDispatch,
                    RuntimeCapability::HeapAllocate,
                    expected,
                ]),
                "canonical generated-realm name {name}"
            );
        }

        let math_value = canonical_frame.bindings["Math"]
            .state()
            .expect("read canonical Math binding")
            .value
            .clone();
        let mut alias_frame = canonical_frame.clone();
        alias_frame.insert_binding(
            "userMathAlias".to_string(),
            ScopeBinding::with_state(BindingKind::Var, math_value, true),
        );
        assert_eq!(
            core.contained_codegen_effective_capability_grant(
                &load_name_module("userMathAlias"),
                &alias_frame,
            )
            .expect("derive user-alias authority")
            .into_iter()
            .collect::<BTreeSet<_>>(),
            BTreeSet::from([
                RuntimeCapability::VmDispatch,
                RuntimeCapability::HeapAllocate,
            ]),
            "a generated sloppy-global alias is not a capability declaration"
        );

        let mut overwritten_frame = canonical_frame;
        overwritten_frame.insert_binding(
            "Math".to_string(),
            ScopeBinding::with_state(BindingKind::Var, Value::Int(7), true),
        );
        assert_eq!(
            core.contained_codegen_effective_capability_grant(
                &load_name_module("Math"),
                &overwritten_frame,
            )
            .expect("derive overwritten canonical-name authority")
            .into_iter()
            .collect::<BTreeSet<_>>(),
            BTreeSet::from([
                RuntimeCapability::VmDispatch,
                RuntimeCapability::HeapAllocate,
            ]),
            "a writable canonical name whose value is no longer an intrinsic must not infer a grant"
        );
    }

    #[test]
    fn generated_code_fault_codes_are_stable_classifications() {
        // The audit `outcome` for a faulting invocation is a stable, payload-free
        // classification — never the raw (possibly adversarial) error text.
        assert_eq!(
            generated_code_fault_code(&InterpreterError::BudgetExhausted {
                executed: 100,
                budget: 100,
            }),
            "budget_exhausted"
        );
        assert_eq!(
            generated_code_fault_code(&InterpreterError::CapabilityDenied {
                capability: "fs_read".to_string(),
            }),
            "capability_denied"
        );
        assert_eq!(
            generated_code_fault_code(&InterpreterError::UncaughtException {
                value: "Error: boom".to_string(),
            }),
            "uncaught_exception"
        );
        assert_eq!(
            generated_code_fault_code(&InterpreterError::TypeError {
                expected: "a".to_string(),
                got: "b".to_string(),
            }),
            "type_error"
        );
        assert_eq!(
            generated_code_fault_code(&InterpreterError::RangeError {
                message: "x".to_string(),
            }),
            "range_error"
        );
        // A new/unmapped variant falls into the catch-all bucket.
        assert_eq!(
            generated_code_fault_code(&InterpreterError::DivisionByZero),
            "error"
        );
    }

    #[test]
    fn capability_denial_feeds_runtime_security_observability() {
        // A hostcall requiring `fs` while only the baseline execution
        // capabilities (VmDispatch + HeapAllocate) are granted: the live
        // capability gate must deny it AND feed the mandatory runtime security
        // observability surface (bd-unc29 wired record_capability_denial into
        // the real gate).
        let mut module = halted_test_module();
        module.instructions = vec![
            Ir3Instruction::HostCall {
                capability: CapabilityTag("fs".to_string()),
                args: RegRange { start: 0, count: 0 },
                dst: 0,
            },
            Ir3Instruction::Halt,
        ];
        module.required_capabilities = vec![CapabilityTag("fs".to_string())];

        // test_core() grants VmDispatch + HeapAllocate but NOT FsRead.
        let mut core = test_core();
        let result = core.execute(&module);
        assert!(
            matches!(result, Err(InterpreterError::CapabilityDenied { .. })),
            "withheld capability must be denied, got {result:?}"
        );

        // The mandatory counter is now populated from the real failure site.
        let metrics = core.security_metrics();
        let total_denials: u64 = metrics.capability_denial_total.values().sum();
        assert_eq!(
            total_denials, 1,
            "exactly one capability denial should be recorded by the runtime"
        );
        assert_eq!(
            metrics
                .capability_denial_total
                .get(&CapabilityDenialReason::InsufficientAuthority)
                .copied()
                .unwrap_or(0),
            1,
            "the denial must be classified as InsufficientAuthority"
        );

        // And the structured security log carries one complete denial event
        // naming the requested capability.
        let logs = core.security_observability().logs();
        assert_eq!(logs.len(), 1, "one structured security log event expected");
        assert!(
            logs[0].required_fields_present(),
            "structured security log event must have all required fields"
        );
        assert_eq!(
            logs[0]
                .metadata
                .get("requested_capability")
                .map(String::as_str),
            Some("fs"),
            "the denial event must record the requested capability tag"
        );
        assert_eq!(logs[0].event_type, "capability_denial");
        assert_eq!(logs[0].outcome, "denied");
    }

    #[test]
    fn no_capability_denial_recorded_on_clean_run() {
        // Negative control: a run with no denied hostcall leaves the mandatory
        // capability_denial counter at zero (no spurious increments).
        let mut core = test_core();
        core.execute(&halted_test_module())
            .expect("clean run without hostcalls should succeed");
        let total_denials: u64 = core
            .security_metrics()
            .capability_denial_total
            .values()
            .sum();
        assert_eq!(
            total_denials, 0,
            "no denial should be recorded on a clean run"
        );
        assert!(core.security_observability().logs().is_empty());
    }

    fn iterator_return_value_module() -> Ir3Module {
        let mut module = halted_test_module();
        module.constant_pool = vec!["result".into()];
        module.instructions = vec![
            Ir3Instruction::LoadScoped {
                dst: 0,
                name_pool_index: 0,
            },
            Ir3Instruction::Return { value: 0 },
        ];
        module.function_table = vec![crate::ir_contract::Ir3FunctionDesc {
            entry: 0,
            arity: 0,
            frame_size: 1,
            name: Some("iterator_return_value".to_string()),
            is_generator: false,
            rest_param_index: None,
        }];
        module
    }

    fn iterator_return_throw_module() -> Ir3Module {
        let mut module = halted_test_module();
        module.constant_pool = vec!["close-error".into()];
        module.instructions = vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::Throw { value: 0 },
        ];
        module.function_table = vec![crate::ir_contract::Ir3FunctionDesc {
            entry: 0,
            arity: 0,
            frame_size: 1,
            name: Some("iterator_return_throw".to_string()),
            is_generator: false,
            rest_param_index: None,
        }];
        module
    }

    fn closable_iterator_with_return_value(
        core: &mut InterpreterCore,
        result: Value,
        discriminator: &str,
    ) -> (u32, usize) {
        let iterator_object = core
            .alloc_object_with_prototype(None)
            .expect("test iterator object allocation should succeed");
        core.set_object_property(iterator_object, "return".to_string(), Value::Function(0))
            .expect("test iterator return method write should succeed");
        core.scope_chain
            .current_mut()
            .expect("global test scope should exist")
            .insert_binding(
                "result".to_string(),
                ScopeBinding::with_state(BindingKind::Var, result, true),
            );
        let trace_index = core.start_iteration_trace(IterationKind::ForOf, || {
            format!("test:iterator-return:{discriminator}")
        });
        let handle = core
            .alloc_iterator(RuntimeIteratorState::ForOf(RuntimeForOfState {
                values: vec![Value::Int(1)],
                next_index: 0,
                array: None,
                typed_array: None,
                collection: None,
                iterator_receiver: Some(Value::Object(iterator_object)),
                next_method: None,
                timers_interval: None,
                done: false,
                closed: false,
                return_called: false,
                trace_index,
            }))
            .expect("test iterator allocation should succeed");
        (handle, trace_index)
    }

    fn value_object_like_cases(core: &mut InterpreterCore) -> Vec<(&'static str, Value, bool)> {
        let object = core
            .alloc_object_with_prototype(None)
            .expect("test result object allocation should succeed");
        vec![
            ("undefined", Value::Undefined, false),
            ("null", Value::Null, false),
            ("boolean", Value::Bool(false), false),
            ("integer", Value::Int(0), false),
            ("bigint", Value::BigInt(Arc::from("0")), false),
            ("float", Value::Float(Float64::new(0.5)), false),
            ("string", Value::str(""), false),
            ("symbol", Value::Symbol(SymbolId(99)), false),
            ("object", Value::Object(object), true),
            ("function", Value::Function(0), true),
            ("closure", Value::Closure(0), true),
            ("iterator", Value::Iterator(0), true),
            ("generator-function", Value::GeneratorFunction(0), true),
            ("generator", Value::Generator(0), true),
            ("async-function", Value::AsyncFunction(0), true),
            ("async-function-object", Value::AsyncFunctionObject(0), true),
            (
                "async-generator-function",
                Value::AsyncGeneratorFunction(0),
                true,
            ),
            (
                "async-generator-object",
                Value::AsyncGeneratorObject(0),
                true,
            ),
            ("promise", Value::Promise(0), true),
            (
                "builtin-function",
                Value::BuiltinFunction(BuiltinFunction::function_constructor()),
                true,
            ),
            (
                "accessor",
                Value::Accessor {
                    get: Some(Arc::new(Value::Function(0))),
                    set: None,
                },
                true,
            ),
        ]
    }

    #[test]
    fn value_object_like_classifier_covers_every_variant_bd_7vfkc() {
        let mut core = test_core();
        for (name, value, expected) in value_object_like_cases(&mut core) {
            #[allow(clippy::match_like_matches_macro)]
            let exhaustive_expected = match &value {
                Value::Undefined
                | Value::Null
                | Value::Bool(_)
                | Value::Int(_)
                | Value::BigInt(_)
                | Value::Float(_)
                | Value::Str(_)
                | Value::Symbol(_) => false,
                Value::Object(_)
                | Value::Function(_)
                | Value::Closure(_)
                | Value::Iterator(_)
                | Value::GeneratorFunction(_)
                | Value::Generator(_)
                | Value::AsyncFunction(_)
                | Value::AsyncFunctionObject(_)
                | Value::AsyncGeneratorFunction(_)
                | Value::AsyncGeneratorObject(_)
                | Value::Promise(_)
                | Value::BuiltinFunction(_)
                | Value::Accessor { .. } => true,
            };
            assert_eq!(
                exhaustive_expected, expected,
                "fixture classification: {name}"
            );
            assert_eq!(
                value.is_object_like(),
                expected,
                "runtime classification: {name}"
            );
        }
    }

    #[test]
    fn iterator_close_accepts_every_object_like_value_carrier_bd_7vfkc() {
        let module = iterator_return_value_module();
        let mut core = test_core();
        for (name, result, object_like) in value_object_like_cases(&mut core) {
            if !object_like {
                continue;
            }
            let (handle, trace_index) =
                closable_iterator_with_return_value(&mut core, result, name);
            core.close_iterator(&module, Value::Iterator(handle), IteratorCloseReason::Break)
                .unwrap_or_else(|error| panic!("{name}: object-like result was rejected: {error}"));
            core.close_iterator(&module, Value::Iterator(handle), IteratorCloseReason::Break)
                .unwrap_or_else(|error| panic!("{name}: repeated close failed: {error}"));

            let trace = &core.iteration_traces[trace_index];
            let called_events = trace
                .events
                .iter()
                .filter(|event| {
                    matches!(
                        &event.operation,
                        IterationOperation::IteratorClose {
                            reason: CloseReason::Break,
                            return_called: true,
                        }
                    )
                })
                .count();
            assert_eq!(
                called_events, 1,
                "{name}: return must be called exactly once"
            );
            assert_eq!(
                trace.events[0].completion,
                IterationCompletion::Normal,
                "{name}"
            );
        }
    }

    #[test]
    fn iterator_close_rejects_every_primitive_value_carrier_bd_7vfkc() {
        let module = iterator_return_value_module();
        let mut core = test_core();
        for (name, result, object_like) in value_object_like_cases(&mut core) {
            if object_like {
                continue;
            }
            let expected_type = result.type_name();
            let (handle, trace_index) =
                closable_iterator_with_return_value(&mut core, result, name);
            let error = core
                .close_iterator(&module, Value::Iterator(handle), IteratorCloseReason::Break)
                .expect_err("primitive iterator.return result must be rejected");
            match error {
                InterpreterError::TypeError { expected, got } => {
                    assert_eq!(expected, "object returned by iterator.return", "{name}");
                    assert_eq!(got, expected_type, "{name}");
                }
                other => panic!("{name}: expected TypeError, got {other:?}"),
            }
            core.close_iterator(&module, Value::Iterator(handle), IteratorCloseReason::Break)
                .unwrap_or_else(|error| panic!("{name}: repeated close failed: {error}"));

            let trace = &core.iteration_traces[trace_index];
            assert!(matches!(
                trace.events.first(),
                Some(IterationEvent {
                    operation: IterationOperation::IteratorClose {
                        reason: CloseReason::Break,
                        return_called: true,
                    },
                    completion: IterationCompletion::InvalidResult,
                    ..
                })
            ));
            let called_events = trace
                .events
                .iter()
                .filter(|event| {
                    matches!(
                        &event.operation,
                        IterationOperation::IteratorClose {
                            return_called: true,
                            ..
                        }
                    )
                })
                .count();
            assert_eq!(
                called_events, 1,
                "{name}: return must be called exactly once"
            );
        }
    }

    #[test]
    fn iterator_close_traces_throwing_return_exactly_once_bd_7vfkc() {
        let module = iterator_return_throw_module();
        let mut core = test_core();
        let (handle, trace_index) =
            closable_iterator_with_return_value(&mut core, Value::Undefined, "throw");

        assert!(matches!(
            core.close_iterator(&module, Value::Iterator(handle), IteratorCloseReason::Break,),
            Err(InterpreterError::UncaughtException { .. })
        ));
        core.close_iterator(&module, Value::Iterator(handle), IteratorCloseReason::Break)
            .expect("a repeated close must not invoke iterator.return again");

        let trace = &core.iteration_traces[trace_index];
        assert!(matches!(
            trace.events.first(),
            Some(IterationEvent {
                operation: IterationOperation::IteratorClose {
                    reason: CloseReason::Break,
                    return_called: true,
                },
                completion: IterationCompletion::CloseThrew,
                ..
            })
        ));
        assert_eq!(
            trace
                .events
                .iter()
                .filter(|event| matches!(
                    &event.operation,
                    IterationOperation::IteratorClose {
                        return_called: true,
                        ..
                    }
                ))
                .count(),
            1,
            "a throwing iterator.return must be traced exactly once"
        );
    }

    #[test]
    fn iterator_close_calls_return_method_on_runtime_iterator() {
        let mut module = halted_test_module();
        module.constant_pool = vec!["closed".into(), "done".into()];
        module.instructions = vec![
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
            Ir3Instruction::NewObject { dst: 3 },
            Ir3Instruction::LoadStr {
                dst: 4,
                pool_index: 1,
            },
            Ir3Instruction::LoadBool {
                dst: 5,
                value: true,
            },
            Ir3Instruction::SetProperty {
                obj: 3,
                key: 4,
                val: 5,
            },
            Ir3Instruction::Return { value: 3 },
        ];
        module.function_table = vec![crate::ir_contract::Ir3FunctionDesc {
            entry: 0,
            arity: 0,
            frame_size: 6,
            name: Some("iterator_return".to_string()),
            is_generator: false,
            rest_param_index: None,
        }];

        let mut core = test_core();
        let iterator_object = core
            .alloc_object_with_prototype(None)
            .expect("test iterator object allocation should succeed");
        core.set_object_property(iterator_object, "return".to_string(), Value::Function(0))
            .expect("test iterator return method write should succeed");
        let trace_index =
            core.start_iteration_trace(IterationKind::ForOf, || "test:iterator-return".to_string());
        let handle = core
            .alloc_iterator(RuntimeIteratorState::ForOf(RuntimeForOfState {
                values: vec![Value::Int(1)],
                next_index: 0,
                array: None,
                typed_array: None,
                collection: None,
                iterator_receiver: Some(Value::Object(iterator_object)),
                next_method: None,
                timers_interval: None,
                done: false,
                closed: false,
                return_called: false,
                trace_index,
            }))
            .expect("test iterator allocation should succeed");

        core.close_iterator(&module, Value::Iterator(handle), IteratorCloseReason::Break)
            .expect("IteratorClose should dispatch iterator.return");

        let iterator_properties = &core
            .heap
            .get(iterator_object.0 as usize)
            .expect("iterator object should remain allocated")
            .properties;
        assert_eq!(iterator_properties.get("closed"), Some(&Value::Bool(true)));
        match core
            .iterator_state_mut(handle)
            .expect("runtime iterator should remain registered")
        {
            RuntimeIteratorState::ForOf(state) => {
                assert!(state.closed);
                assert!(state.done);
                assert!(state.return_called);
            }
            RuntimeIteratorState::ForIn(_) => panic!("expected for..of iterator state"),
        }
    }

    fn mixed_sort_fixture(core: &mut InterpreterCore) -> (ObjectId, ObjectId) {
        let array_id = core
            .alloc_object_with_prototype(None)
            .expect("test array allocation should succeed");
        let object_id = core
            .alloc_object_with_prototype(None)
            .expect("test object allocation should succeed");

        for (index, value) in [
            (0, Value::Int(3)),
            (1, Value::str("banana")),
            (2, Value::Bool(false)),
            (4, Value::Float(Float64::new(1.5))),
            (5, Value::Object(object_id)),
        ] {
            core.set_object_property(array_id, index.to_string(), value)
                .expect("test array element write should succeed");
        }
        core.set_object_property(array_id, "length".to_string(), Value::Int(6))
            .expect("test array length write should succeed");

        (array_id, object_id)
    }

    #[test]
    fn execute_pipeline_preserves_completion_artifacts() {
        let mut core = test_core();

        let result = core
            .execute(&halted_test_module())
            .expect("halt is normal execution completion");

        assert_eq!(result.value, Value::Undefined);
        assert!(result.instructions_executed > 0);
        assert!(
            result
                .events
                .iter()
                .any(|event| event.event == "execution_started" && event.outcome == "ok")
        );
        assert!(
            result
                .events
                .iter()
                .any(|event| event.event == "execution_halted" && event.outcome == "ok")
        );
        assert!(
            result
                .witness_events
                .iter()
                .any(|event| event.kind == WitnessEventKind::ExecutionCompleted)
        );
    }

    #[test]
    fn execute_builtin_call_rejects_u32_register_range_overflow() {
        let too_many_args = usize::try_from(u64::from(u32::MAX) + 1)
            .expect("64-bit test target should represent u32::MAX + 1");
        let err = InterpreterCore::checked_test_builtin_args(0, too_many_args)
            .expect_err("test builtin arg count overflow should fail closed");
        assert!(
            matches!(err, InterpreterError::TypeError { ref expected, .. }
                if expected == "u32-bounded builtin argument count")
        );

        let err = InterpreterCore::checked_test_builtin_args(u32::MAX, 2)
            .expect_err("test builtin register range overflow should fail closed");
        assert!(
            matches!(err, InterpreterError::TypeError { ref expected, .. }
                if expected == "u32-bounded builtin argument register range")
        );
    }

    #[test]
    fn allocate_function_rejects_u32_synthetic_id_overflow() {
        let last_safe_count = usize::try_from(u32::MAX - TEST_FUNCTION_ID_OFFSET)
            .expect("test target should represent last safe function count");
        assert_eq!(
            InterpreterCore::checked_test_function_id(last_safe_count)
                .expect("last safe synthetic function id should fit"),
            u32::MAX
        );

        let overflowing_count = last_safe_count + 1;
        let err = InterpreterCore::checked_test_function_id(overflowing_count)
            .expect_err("test function id overflow should fail closed");
        assert!(
            matches!(err, InterpreterError::TypeError { ref expected, .. }
                if expected == "u32-bounded test function id allocation")
        );
    }

    #[test]
    fn object_create_applies_descriptors_and_preserves_prototype() {
        let mut core = test_core();

        let prototype_id = core
            .alloc_object_with_prototype(None)
            .expect("test prototype allocation should succeed");
        core.set_object_property(
            prototype_id,
            "inherited".to_string(),
            Value::str("from-prototype"),
        )
        .expect("test prototype property write should succeed");

        let descriptors_id = core
            .alloc_object_with_prototype(None)
            .expect("test descriptor map allocation should succeed");
        let answer_descriptor_id = core
            .alloc_object_with_prototype(None)
            .expect("test answer descriptor allocation should succeed");
        core.set_object_property(answer_descriptor_id, "value".to_string(), Value::Int(42))
            .expect("test descriptor value write should succeed");
        core.set_object_property(
            descriptors_id,
            "answer".to_string(),
            Value::Object(answer_descriptor_id),
        )
        .expect("test descriptor map write should succeed");

        let empty_descriptor_id = core
            .alloc_object_with_prototype(None)
            .expect("test empty descriptor allocation should succeed");
        core.set_object_property(
            descriptors_id,
            "missing_value".to_string(),
            Value::Object(empty_descriptor_id),
        )
        .expect("test descriptor map write should succeed");

        core.mutate_registers(|r| {
            r[0] = Value::Object(prototype_id);
            r[1] = Value::Object(descriptors_id);
        });

        assert_eq!(
            core.builtin_name_from_id(5),
            Some("builtin:ObjectCreate".to_string())
        );
        let created_value = core
            .call_builtin_by_id(5, RegRange { start: 0, count: 2 })
            .expect("ObjectCreate should execute");
        let created_id = match created_value {
            Value::Object(id) => id,
            other => panic!("expected ObjectCreate to return object, got {other:?}"),
        };

        {
            let created = core
                .heap
                .get(created_id.0 as usize)
                .expect("created object should remain allocated");
            assert_eq!(created.prototype, Some(prototype_id));
            assert_eq!(created.properties.get("answer"), Some(&Value::Int(42)));
            assert_eq!(
                created.properties.get("missing_value"),
                Some(&Value::Undefined)
            );
        }

        let inherited = core
            .prototype_chain_get(created_id, "inherited")
            .expect("prototype-chain lookup should execute");
        assert_eq!(inherited, Value::str("from-prototype"));

        // A descriptor that is not an object is a TypeError (ES2020
        // 19.1.2.3.1 ObjectDefineProperties -> ToPropertyDescriptor; Node:
        // "Property description must be an object"), not an undefined value.
        let raw_descriptors_id = core
            .alloc_object_with_prototype(None)
            .expect("test descriptor map allocation should succeed");
        core.set_object_property(
            raw_descriptors_id,
            "raw_descriptor".to_string(),
            Value::Int(7),
        )
        .expect("test descriptor map write should succeed");
        core.mutate_registers(|r| {
            r[0] = Value::Object(prototype_id);
            r[1] = Value::Object(raw_descriptors_id);
        });
        assert!(matches!(
            core.call_builtin_by_id(5, RegRange { start: 0, count: 2 }),
            Err(InterpreterError::TypeError { .. })
        ));
    }

    #[test]
    fn array_prototype_sort_builtin_dispatch_deduplication_regression() {
        for builtin_id in [28_u32, 248_u32, 385_u32] {
            let mut core = test_core();
            let (array_id, object_id) = mixed_sort_fixture(&mut core);
            core.mutate_registers(|r| {
                r[0] = Value::Object(array_id);
            });

            assert_eq!(
                core.builtin_name_from_id(builtin_id),
                Some("builtin:ArrayPrototypeSort".to_string())
            );
            assert_eq!(
                core.call_builtin_by_id(builtin_id, RegRange { start: 0, count: 1 })
                    .expect("ArrayPrototypeSort builtin ID should execute"),
                Value::Object(array_id)
            );

            let properties = &core
                .heap
                .get(array_id.0 as usize)
                .expect("sorted test array should remain allocated")
                .properties;
            assert!(
                matches!(properties.get("0"), Some(Value::Float(value)) if value.inner() == 1.5)
            );
            assert_eq!(properties.get("1"), Some(&Value::Int(3)));
            assert_eq!(properties.get("2"), Some(&Value::Object(object_id)));
            assert_eq!(properties.get("3"), Some(&Value::str("banana")));
            assert_eq!(properties.get("4"), Some(&Value::Bool(false)));
            assert_eq!(properties.get("5"), Some(&Value::Undefined));
        }
    }

    #[test]
    fn string_prototype_normalize_builtin_dispatch_regression() {
        for builtin_id in [222_u32, 273_u32] {
            let mut core = test_core();

            assert_eq!(
                core.builtin_name_from_id(builtin_id),
                Some("builtin:StringPrototypeNormalize".to_string())
            );

            core.mutate_registers(|r| {
                r[0] = Value::str("Cafe\u{301}");
            });
            let default_result = core
                .call_builtin_by_id(builtin_id, RegRange { start: 0, count: 1 })
                .expect("StringPrototypeNormalize default NFC should execute");
            assert_eq!(default_result, Value::str("Café"));

            core.mutate_registers(|r| {
                r[0] = Value::str("Café");
                r[1] = Value::str("NFD");
            });
            let nfd_result = core
                .call_builtin_by_id(builtin_id, RegRange { start: 0, count: 2 })
                .expect("StringPrototypeNormalize NFD should execute");
            assert_eq!(nfd_result, Value::str("Cafe\u{301}"));

            core.mutate_registers(|r| {
                r[0] = Value::str("\u{fb01}");
                r[1] = Value::str("NFKC");
            });
            let nfkc_result = core
                .call_builtin_by_id(builtin_id, RegRange { start: 0, count: 2 })
                .expect("StringPrototypeNormalize NFKC should execute");
            assert_eq!(nfkc_result, Value::str("fi"));
        }
    }

    #[test]
    fn string_prototype_normalize_preserves_exact_units_across_builtin_ids() {
        for builtin_id in [222_u32, 273_u32] {
            let mut core = test_core();
            for (form, expected) in [
                ("NFC", vec![0xd800, 0x00e9, 0xdc00, 0xfb01, 0xd800]),
                ("NFD", vec![0xd800, 0x0065, 0x0301, 0xdc00, 0xfb01, 0xd800]),
                ("NFKC", vec![0xd800, 0x00e9, 0xdc00, 0x0066, 0x0069, 0xd800]),
                (
                    "NFKD",
                    vec![0xd800, 0x0065, 0x0301, 0xdc00, 0x0066, 0x0069, 0xd800],
                ),
            ] {
                core.mutate_registers(|registers| {
                    registers[0] = Value::Str(JsString::from_code_units(&[
                        0xd800, 0x0065, 0x0301, 0xdc00, 0xfb01, 0xd800,
                    ]));
                    registers[1] = Value::str(form);
                });
                let actual = core
                    .call_builtin_by_id(builtin_id, RegRange { start: 0, count: 2 })
                    .expect("exact string normalization should execute");
                assert_eq!(actual, Value::Str(JsString::from_code_units(&expected)));
            }
            core.mutate_registers(|registers| {
                registers[0] = Value::Str(JsString::from_code_units(&[0xd800]));
                registers[1] = Value::str("BAD");
            });
            assert!(matches!(
                core.call_builtin_by_id(builtin_id, RegRange { start: 0, count: 2 }),
                Err(InterpreterError::RangeError { .. })
            ));
        }
    }

    #[test]
    fn string_prototype_normalize_invalid_form_fails_closed() {
        for builtin_id in [222_u32, 273_u32] {
            let mut core = test_core();
            core.mutate_registers(|r| {
                r[0] = Value::str("hello");
                r[1] = Value::str("BAD");
            });

            let err = core
                .call_builtin_by_id(builtin_id, RegRange { start: 0, count: 2 })
                .expect_err("StringPrototypeNormalize should reject unknown forms");
            assert!(matches!(err, InterpreterError::RangeError { .. }));
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod execution_engine_contract_tests {
    #[allow(unused_imports)]
    use super::*;
    #[allow(unused_imports)]
    use crate::baseline_interpreter::*;

    fn accepts_engine_trait_object(_engine: &dyn ExecutionEngine) -> bool {
        true
    }

    #[test]
    fn lane_wrappers_are_swappable_execution_engines() {
        assert!(accepts_engine_trait_object(&QuickJsLane::new()));
        assert!(accepts_engine_trait_object(&V8Lane::new()));
    }
}

#[cfg(test)]
mod module_resolution_security_tests {
    #[allow(unused_imports)]
    use super::*;
    #[allow(unused_imports)]
    use crate::baseline_interpreter::*;
    use std::fs;
    use std::path::Path;

    #[test]
    fn captured_package_failure_codes_are_distinct_from_policy_and_absence() {
        for (code, require_code, import_code) in [
            (
                ResolutionErrorCode::ModuleNotFound,
                "MODULE_NOT_FOUND",
                "ERR_MODULE_NOT_FOUND",
            ),
            (
                ResolutionErrorCode::PackagePathNotExported,
                "ERR_PACKAGE_PATH_NOT_EXPORTED",
                "ERR_PACKAGE_PATH_NOT_EXPORTED",
            ),
            (
                ResolutionErrorCode::PackageImportNotDefined,
                "ERR_PACKAGE_IMPORT_NOT_DEFINED",
                "ERR_PACKAGE_IMPORT_NOT_DEFINED",
            ),
        ] {
            let reason = ModuleResolutionFailureReason::from_captured_code(code).unwrap();
            assert_eq!(reason.guest_error_code(ImportStyle::Require), require_code);
            assert_eq!(reason.guest_error_code(ImportStyle::Import), import_code);
            assert_eq!(
                serde_json::from_str::<ModuleResolutionFailureReason>(
                    &serde_json::to_string(&reason).unwrap()
                )
                .unwrap(),
                reason
            );
        }
        for code in [
            ResolutionErrorCode::PolicyDenied,
            ResolutionErrorCode::UnsupportedSpecifier,
            ResolutionErrorCode::InvalidReferrer,
            ResolutionErrorCode::EmptySpecifier,
        ] {
            assert!(ModuleResolutionFailureReason::from_captured_code(code).is_none());
        }
    }

    fn core_with_root(root: &Path, entry: &Path) -> InterpreterCore {
        let mut config = InterpreterConfig::quickjs_defaults();
        config.module_root = Some(root.display().to_string());
        let mut core = InterpreterCore::new(config, "module-resolution-security-test");
        core.current_module_specifier = Some(entry.display().to_string());
        core
    }

    fn core_no_root(entry: &Path) -> InterpreterCore {
        let config = InterpreterConfig::quickjs_defaults();
        let mut core = InterpreterCore::new(config, "module-resolution-security-test");
        core.current_module_specifier = Some(entry.display().to_string());
        core
    }

    #[test]
    fn module_resolution_keeps_extension_probe_inside_root()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let root = temp.path().join("app");
        fs::create_dir_all(&root)?;
        let entry = root.join("entry.js");
        let dep = root.join("dep.js");
        fs::write(&entry, "import './dep';")?;
        fs::write(&dep, "export const value = 1;")?;

        let core = core_with_root(&root, &entry);
        let resolved = core.resolve_module_specifier("./dep")?;

        assert_eq!(Path::new(&resolved), dep.canonicalize()?.as_path());
        Ok(())
    }

    #[test]
    fn module_resolution_rejects_parent_escape_from_module_root()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let root = temp.path().join("app");
        fs::create_dir_all(&root)?;
        let entry = root.join("entry.js");
        let outside = temp.path().join("outside.js");
        fs::write(&entry, "import '../outside';")?;
        fs::write(&outside, "export const secret = 1;")?;

        let core = core_with_root(&root, &entry);
        let err = core
            .resolve_module_specifier("../outside")
            .expect_err("parent import must not escape configured module root");

        assert!(matches!(
            err,
            InterpreterError::ModuleResolutionFailed {
                reason: ModuleResolutionFailureReason::Other(reason),
                ..
            } if reason.contains("escapes module root")
        ));
        Ok(())
    }

    #[test]
    fn module_resolution_rejects_absolute_specifiers() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let root = temp.path().join("app");
        fs::create_dir_all(&root)?;
        let entry = root.join("entry.js");
        let outside = temp.path().join("outside.js");
        fs::write(&entry, "import '/tmp/outside.js';")?;
        fs::write(&outside, "export const secret = 1;")?;

        let core = core_with_root(&root, &entry);
        let outside_specifier = outside.display().to_string();
        let err = core
            .resolve_module_specifier(&outside_specifier)
            .expect_err("absolute import must be rejected before filesystem probing");

        assert!(matches!(
            err,
            InterpreterError::ModuleResolutionFailed {
                reason: ModuleResolutionFailureReason::Other(reason),
                ..
            } if reason.contains("absolute paths not allowed")
        ));
        Ok(())
    }

    /// bd-zpn3w: when neither `canonical_module_root` nor `module_root` is set,
    /// the resolver must NOT silently bypass the escape-boundary check. The
    /// previous fail-open path returned the canonical path unconditionally,
    /// which let an extension with a relative specifier read files anywhere
    /// the host process could reach. The fix returns
    /// `ModuleResolutionFailed` with a descriptive reason instead.
    #[test]
    fn module_resolution_fails_closed_without_configured_root()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let entry = temp.path().join("entry.js");
        let neighbour = temp.path().join("neighbour.js");
        fs::write(&entry, "import './neighbour';")?;
        fs::write(&neighbour, "export const value = 1;")?;

        let core = core_no_root(&entry);
        let err = core
            .resolve_module_specifier("./neighbour")
            .expect_err("relative resolution without a module root must fail closed");

        assert!(
            matches!(
                &err,
                InterpreterError::ModuleResolutionFailed {
                    reason: ModuleResolutionFailureReason::Other(reason),
                    ..
                } if reason.contains("module root not configured")
            ),
            "expected 'module root not configured' fail-closed error, got: {err:?}"
        );
        Ok(())
    }

    /// bd-zpn3w: the post-canonical `metadata().is_file()` check rejects a
    /// canonical path that is a directory. The standard library's
    /// `Path::is_file()` already follows symlinks, so the
    /// `resolve_module_candidate` probe agrees with the post-canonical
    /// metadata for any *steady-state* setup; the post-canonical check is
    /// real defense-in-depth for a TOCTOU race where the file is swapped
    /// between the probe and `canonicalize()`. Race-based assertions are
    /// inherently non-deterministic for a unit test, so this test exercises
    /// the failure-shape contract directly: a deliberately-constructed
    /// candidate that bypasses the probe (via the index.{mjs,js}
    /// "directory has matching index" code path with a directory only
    /// containing a same-named subdirectory) confirms the post-canonical
    /// rejection still fires.
    #[test]
    fn module_resolution_rejects_canonical_non_regular_file()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let root = temp.path().join("app");
        fs::create_dir_all(&root)?;
        let entry = root.join("entry.js");
        fs::write(&entry, "import './dep';")?;
        // `./dep/` is a directory with no `index.{mjs,js}` and no
        // `dep.{mjs,js}` next to it, so `resolve_module_candidate` returns
        // `None` and the resolver short-circuits with `ModuleNotFound`. To
        // assert the post-canonical metadata path, we invoke
        // `canonicalize_module_candidate` directly with the directory
        // candidate and confirm it rejects.
        let dep_dir = root.join("dep");
        fs::create_dir_all(&dep_dir)?;

        let core = core_with_root(&root, &entry);
        let err = core
            .canonicalize_module_candidate("./dep", &dep_dir)
            .expect_err("canonical path that is a directory must be rejected post-canonicalize");

        assert!(
            matches!(
                &err,
                InterpreterError::ModuleResolutionFailed {
                    reason: ModuleResolutionFailureReason::Other(reason),
                    ..
                } if reason.contains("canonical module path is not a regular file")
            ),
            "expected post-canonical non-regular-file rejection, got: {err:?}"
        );
        Ok(())
    }
}

#[cfg(test)]
mod hostcall_capability_classification_tests {
    use super::{HostcallCapabilityClass, classify_hostcall_capability};

    /// bd-hxukn: every known `promise:*` sub-capability — the ones the
    /// dispatch table actually understands — must classify as
    /// `InternalAllowed`. Anything else `promise:*` must fall through
    /// to `Unknown`, even if it shares the prefix.
    #[test]
    fn known_promise_subcaps_remain_internal_allowed() {
        for known in [
            "promise:constructor",
            "promise:resolve",
            "promise:reject",
            "promise:then",
            "promise:catch",
            "promise:finally",
            "promise:all",
            "promise:race",
            "promise:allSettled",
            "promise:any",
            "promise:create",
        ] {
            assert_eq!(
                classify_hostcall_capability(known),
                HostcallCapabilityClass::InternalAllowed,
                "{known} should still classify as InternalAllowed",
            );
        }
    }

    /// bd-hxukn: unknown `promise:*` sub-capabilities must classify as
    /// `Unknown` (fail-closed at the gate) so an attacker who emits
    /// `HostCall { capability: CapabilityTag("promise:steal_admin_key") }`
    /// cannot write attacker-chosen strings into `hostcall_decisions`
    /// tagged `allowed: true`.
    #[test]
    fn unknown_promise_subcaps_fail_closed() {
        for attacker in [
            "promise:steal_admin_key",
            "promise:",
            "promise:Resolve", // case-sensitive — "promise:resolve" is the only allowed form
            "promise:resolve ", // trailing space — exact match required
            "promise: resolve",
            "promise:resolve_x",
        ] {
            assert_eq!(
                classify_hostcall_capability(attacker),
                HostcallCapabilityClass::Unknown,
                "{attacker} must classify as Unknown so the gate fails closed",
            );
        }
    }

    /// bd-hxukn: `ifc.check_flow` and the runtime-capability surface keep
    /// their prior classifications.
    #[test]
    fn non_promise_classifications_unchanged() {
        assert_eq!(
            classify_hostcall_capability("ifc.check_flow"),
            HostcallCapabilityClass::InternalAllowed,
        );
        // `unknown:cap` is intentionally not a `RuntimeCapability` tag.
        assert_eq!(
            classify_hostcall_capability("definitely-not-a-known-cap-xyz"),
            HostcallCapabilityClass::Unknown,
        );
    }
}

#[cfg(test)]
mod recordable_capability_tag_tests {
    use super::{
        CAPABILITY_TAG_DIGEST_PREFIX, CAPABILITY_TAG_RECORD_BYTE_CAP, ContentHash,
        capability_gate_key, recordable_capability_tag,
    };

    fn digest_marker(tag: &str) -> String {
        format!(
            "{CAPABILITY_TAG_DIGEST_PREFIX}{}>:",
            ContentHash::compute(tag.as_bytes()).to_hex()
        )
    }

    /// Ordinary short tags retain their exact serialized representation and
    /// do not allocate.
    #[test]
    fn recordable_tag_passthrough_for_short_tags() {
        let tag = "promise:resolve";
        let recorded = recordable_capability_tag(tag);
        assert_eq!(recorded.as_ref(), tag);
        assert!(matches!(recorded, std::borrow::Cow::Borrowed(_)));
    }

    /// Route-specific crypto builtins share one authority, so their live,
    /// pruned-dispatch, witness, and denial identities must stay identical.
    #[test]
    fn crypto_entropy_routes_share_random_read_gate_identity_bd_opsnv() {
        for route in [
            "builtin:CryptoRandomBytes",
            "builtin:CryptoRandomUUID",
            "builtin:CryptoRandomInt",
            "builtin:CryptoRandomFillSync",
        ] {
            assert_eq!(capability_gate_key(route), "random_read");
        }
    }

    #[test]
    fn native_fs_promise_route_shares_only_the_exact_read_gate_identity() {
        let tag = crate::capability::FS_READ_PROMISE_CAPABILITY;
        assert_eq!(capability_gate_key(tag), "fs:read");
        assert_eq!(recordable_capability_tag(tag).as_ref(), tag);
        for forged in [
            "fs:read:promise:suffix",
            "fs:read:promise ",
            "fs:read:Promise",
        ] {
            assert_eq!(capability_gate_key(forged), forged);
        }
    }

    /// Overlong tags remain bounded while committing their complete original
    /// bytes into the recorded representation.
    #[test]
    fn recordable_tag_hashes_and_truncates_overlong_tags() {
        let tag = "promise:".to_string() + &"X".repeat(CAPABILITY_TAG_RECORD_BYTE_CAP * 64);
        let marker = digest_marker(&tag);
        let recorded = recordable_capability_tag(&tag);

        assert!(recorded.len() <= CAPABILITY_TAG_RECORD_BYTE_CAP);
        assert!(recorded.starts_with(&marker));
        assert!(tag.starts_with(&recorded[marker.len()..]));
        assert!(matches!(recorded, std::borrow::Cow::Owned(_)));
    }

    /// The retained display prefix must stop on a UTF-8 character boundary.
    #[test]
    fn recordable_tag_truncation_respects_utf8_boundaries() {
        // U+1234 (ETHIOPIC SYLLABLE SEE) is 3 bytes in UTF-8 (E1 88 B4).
        let tag: String =
            std::iter::repeat_n('\u{1234}', CAPABILITY_TAG_RECORD_BYTE_CAP * 4).collect();
        let marker = digest_marker(&tag);
        let recorded = recordable_capability_tag(&tag);

        assert!(recorded.len() <= CAPABILITY_TAG_RECORD_BYTE_CAP);
        assert!(recorded.starts_with(&marker));
        assert!(tag.starts_with(&recorded[marker.len()..]));
    }

    /// Distinct complete tags with the same retained display prefix must
    /// remain distinct in decision logs and compression-sketch inputs.
    #[test]
    fn recordable_tag_digest_disambiguates_shared_long_prefix() {
        let shared = "X".repeat(CAPABILITY_TAG_RECORD_BYTE_CAP * 2);
        let first = format!("{shared}:first");
        let second = format!("{shared}:second");
        let first_marker = digest_marker(&first);
        let second_marker = digest_marker(&second);
        let first_recorded = recordable_capability_tag(&first);
        let second_recorded = recordable_capability_tag(&second);

        assert_ne!(first_marker, second_marker);
        assert_eq!(
            &first_recorded[first_marker.len()..],
            &second_recorded[second_marker.len()..]
        );
        assert_ne!(first_recorded, second_recorded);
    }

    /// An ordinary input equal to an encoded long-tag representation must be
    /// escaped rather than colliding with that long tag's identity.
    #[test]
    fn recordable_tag_reserved_prefix_cannot_impersonate_encoding() {
        let long_tag = "X".repeat(CAPABILITY_TAG_RECORD_BYTE_CAP * 2);
        let encoded_long = recordable_capability_tag(&long_tag).into_owned();
        assert!(encoded_long.starts_with(CAPABILITY_TAG_DIGEST_PREFIX));
        assert!(encoded_long.len() <= CAPABILITY_TAG_RECORD_BYTE_CAP);

        let escaped_short = recordable_capability_tag(&encoded_long);
        assert!(matches!(escaped_short, std::borrow::Cow::Owned(_)));
        assert_ne!(escaped_short.as_ref(), encoded_long);
        assert!(escaped_short.starts_with(&digest_marker(&encoded_long)));
    }
}

// ---------------------------------------------------------------------------
// Legacy tests
// ---------------------------------------------------------------------------
//
// The former legacy in-source `mod tests` module was written against an older
// lower-level `BaselineInterpreter` / `Ir3Instruction::CallBuiltin{,Id}` /
// `execute_instruction` API that was redesigned at merge-base into main. It was
// ported to the current IR/interpreter contract under bd-n0sap (successor to
// bd-2j7uk) and the `legacy_lib_tests_bd_2j7uk` opt-in gate was removed, so it
// now compiles and runs in the default `cargo test` pipeline.
