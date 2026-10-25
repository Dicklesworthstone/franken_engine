//! Provenance for native reductions and their callback/element observations.
//! Reuse ordinary callback and property-observation boundaries so reductions
//! cannot shed captured, inherited, or abruptly returned labels.

use super::*;

impl InterpreterCore {
    /// Keep observations local to this reduction and restore the caller on
    /// every exit. Completion values and exceptions retain the observations.
    pub(super) fn with_array_reduction_observation(
        &mut self,
        args: RegRange,
        receiver_register: Option<u32>,
        reduce: impl FnOnce(&mut Self) -> Result<Value, InterpreterError>,
    ) -> Result<Value, InterpreterError> {
        let end = args.start.checked_add(args.count.min(3)).ok_or(
            InterpreterError::RegisterOutOfBounds {
                register: args.start,
                max: self.config.max_registers,
            },
        )?;
        let saved = self.begin_property_observation((args.start..end).chain(receiver_register))?;
        let mut outcome = reduce(self);
        let completion_label = if outcome.is_ok() {
            match self.json_parse_context_label() {
                Ok(label) => Some(label),
                Err(error) => {
                    outcome = Err(error);
                    None
                }
            }
        } else {
            None
        };
        let (value, status) = match outcome {
            Ok(value) => (Some(value), Ok(())),
            Err(error) => (None, Err(error)),
        };
        // This boundary seals guest/native exceptions before restoring the
        // context and performs no fallible allocation in cleanup.
        self.finish_property_write_observation(saved, status)?;
        if let Some(label) = completion_label {
            self.join_pending_array_result_label(&label)?;
        }
        Ok(value.expect("successful reduction retained its completion value"))
    }

    pub(super) fn observe_array_reduction_length(
        &mut self,
        array: ObjectId,
        typed_array_method: bool,
    ) -> Result<(), InterpreterError> {
        if typed_array_method {
            // TypedArray methods use the view length, never a guest length
            // property. Observe only shape and backing storage here.
            self.reflect_observe_own_data_property(array, &Label::Public)
        } else {
            self.reflect_observe_selected_property(
                array,
                &RuntimePropertyKey::String(JsString::from("length")),
            )
        }
    }

    pub(super) fn array_reduction_element(
        &mut self,
        module: Option<&Ir3Module>,
        array: ObjectId,
        index: usize,
        typed_array_method: bool,
    ) -> Result<Option<Value>, InterpreterError> {
        // Observe descriptor/shape provenance before a getter can run.
        // Missing indices also decide callback count and the final result.
        let key = RuntimePropertyKey::String(JsString::from(index.to_string()));
        self.reflect_observe_selected_property(array, &key)?;
        let value = self.array_loop_element(module, array, index, typed_array_method)?;
        self.observe_scoped_callback_result()?;
        Ok(value)
    }

    pub(super) fn invoke_labeled_reduce_callback(
        &mut self,
        module: Option<&Ir3Module>,
        callee: Value,
        receiver: Value,
        arguments: Vec<Value>,
    ) -> Result<Value, InterpreterError> {
        // The active reduction context labels callback inputs. Preserve the
        // independently returned label too: captured cells need not appear
        // in the receiver/argument registers.
        let (value, label) = self.invoke_inline_method_call_with_argument_label(
            module, callee, receiver, arguments, None,
        )?;
        self.join_pending_array_result_label(&label)?;
        self.observe_scoped_callback_result()?;
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir_contract::{CapabilityTag, Ir3FunctionDesc};

    fn core() -> InterpreterCore {
        let mut config = InterpreterConfig::quickjs_defaults();
        config.granted_capabilities = BTreeSet::from([
            RuntimeCapability::VmDispatch,
            RuntimeCapability::HeapAllocate,
            RuntimeCapability::Builtin,
            RuntimeCapability::Console,
        ]);
        InterpreterCore::new(config, "reducer-provenance-bd-9vouw-487")
    }

    // Actual CallMethod and legacy HostCall dispatch, followed by the real
    // console IFC boundary; no static annotation supplies the denial.
    fn reduction_module(
        reverse: bool,
        legacy: bool,
        has_initial: bool,
        callback: Vec<Ir3Instruction>,
    ) -> Ir3Module {
        let mut module = Ir3Module::new(
            ContentHash::compute(b"reducer-provenance-bd-9vouw-487"),
            "reducer-provenance",
        );
        module.constant_pool = vec![
            if reverse { "reduceRight" } else { "reduce" }.into(),
            "classified_cell".into(),
        ];
        module.instructions = vec![
            Ir3Instruction::DeclareBinding {
                name_pool_index: 1,
                kind: BindingKind::Var as u8,
            },
            Ir3Instruction::StoreScoped {
                src: 10,
                name_pool_index: 1,
            },
        ];
        if legacy {
            module.instructions.extend([
                Ir3Instruction::Move { dst: 1, src: 8 },
                Ir3Instruction::Move { dst: 2, src: 9 },
                Ir3Instruction::HostCall {
                    capability: CapabilityTag(
                        if reverse {
                            "builtin:ArrayPrototypeReduceRight"
                        } else {
                            "builtin:ArrayPrototypeReduce"
                        }
                        .to_string(),
                    ),
                    args: RegRange {
                        start: 0,
                        count: if has_initial { 3 } else { 2 },
                    },
                    dst: 4,
                },
            ]);
        } else {
            module.instructions.extend([
                Ir3Instruction::LoadStr {
                    dst: 2,
                    pool_index: 0,
                },
                Ir3Instruction::GetProperty {
                    obj: 0,
                    key: 2,
                    dst: 3,
                },
                Ir3Instruction::CallMethod {
                    receiver: 0,
                    callee: 3,
                    args: RegRange {
                        start: 8,
                        count: if has_initial { 2 } else { 1 },
                    },
                    dst: 4,
                },
            ]);
        }
        module.instructions.extend([
            Ir3Instruction::HostCall {
                capability: CapabilityTag("console:log".into()),
                args: RegRange { start: 4, count: 1 },
                dst: 5,
            },
            Ir3Instruction::Halt,
        ]);
        module.function_table.push(Ir3FunctionDesc {
            entry: module.instructions.len() as u32,
            arity: 4,
            frame_size: 6,
            name: Some("reducer".to_string()),
            is_generator: false,
            rest_param_index: None,
        });
        module.instructions.extend(callback);
        module
    }

    fn seed(core: &mut InterpreterCore, array: ObjectId, label: Label) {
        core.write_reg_with_label(0, Value::Object(array), Label::Public)
            .unwrap();
        core.write_reg_with_label(8, Value::Function(0), Label::Public)
            .unwrap();
        core.write_reg_with_label(9, Value::Int(0), Label::Public)
            .unwrap();
        core.write_reg_with_label(10, Value::Int(42), label)
            .unwrap();
    }

    fn assert_console_result(
        core: &InterpreterCore,
        result: Result<ExecutionResult, InterpreterError>,
        label: &Label,
        expected: Value,
    ) {
        assert_eq!(core.read_reg(4).unwrap(), expected);
        assert_eq!(core.get_register_label(4).unwrap(), label);
        if label == &Label::Public {
            let result = result.expect("Public reduction remains executable");
            assert_eq!(result.console_output.len(), 1);
        } else {
            assert!(
                matches!(
                    result,
                    Err(InterpreterError::CapabilityDenied { capability })
                        if capability == "console:log:confidentiality"
                ),
                "the real console boundary must reject a classified reduction"
            );
            assert!(core.console_output().is_empty());
        }
        assert!(core.active_inline_callback_context_label.is_none());
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }

    #[test]
    fn reductions_keep_captured_return_labels_at_real_console_boundary_bd_9vouw_487() {
        for reverse in [false, true] {
            for legacy in [false, true] {
                for dynamic_name in [false, true] {
                    for label in [Label::Public, Label::Secret] {
                        let read = if dynamic_name {
                            Ir3Instruction::LoadName {
                                dst: 4,
                                name_pool_index: 1,
                                allow_missing: false,
                            }
                        } else {
                            Ir3Instruction::LoadScoped {
                                dst: 4,
                                name_pool_index: 1,
                            }
                        };
                        let module = reduction_module(
                            reverse,
                            legacy,
                            true,
                            vec![read, Ir3Instruction::Return { value: 4 }],
                        );
                        let mut core = core();
                        let array = core.alloc_array_from_values(&[Value::Int(1)]).unwrap();
                        seed(&mut core, array, label.clone());
                        let result = core.execute(&module);
                        assert_console_result(&core, result, &label, Value::Int(42));
                    }
                }
            }
        }
    }

    #[test]
    fn reduction_seed_keeps_own_and_inherited_labels_without_callback_bd_9vouw_487() {
        for reverse in [false, true] {
            for legacy in [false, true] {
                for inherited in [false, true] {
                    for label in [Label::Public, Label::Secret] {
                        let mut core = core();
                        let array = if inherited {
                            let prototype =
                                core.alloc_array_from_values(&[Value::Int(42)]).unwrap();
                            core.set_own_property_label(prototype, "0", &label)
                                .unwrap();
                            let array =
                                core.alloc_array_with_prototype(Some(prototype)).unwrap();
                            core.set_object_property(
                                array,
                                "length".to_string(),
                                Value::Int(1),
                            )
                            .unwrap();
                            array
                        } else {
                            let array = core.alloc_array_from_values(&[Value::Int(42)]).unwrap();
                            core.set_own_property_label(array, "0", &label)
                                .unwrap();
                            array
                        };
                        // No callback may run for one element with no initial
                        // value. This throw independently checks call count.
                        let module = reduction_module(
                            reverse,
                            legacy,
                            false,
                            vec![Ir3Instruction::Throw { value: 1 }],
                        );
                        seed(&mut core, array, Label::Public);
                        let result = core.execute(&module);
                        assert_console_result(&core, result, &label, Value::Int(42));
                    }
                }
            }
        }
    }

    #[test]
    fn reduction_throw_keeps_original_value_label_and_restores_context_bd_9vouw_487() {
        for reverse in [false, true] {
            for legacy in [false, true] {
                for label in [Label::Public, Label::Secret] {
                    let module = reduction_module(
                        reverse,
                        legacy,
                        true,
                        vec![
                            Ir3Instruction::LoadName {
                                dst: 4,
                                name_pool_index: 1,
                                allow_missing: false,
                            },
                            Ir3Instruction::Throw { value: 4 },
                        ],
                    );
                    let mut core = core();
                    let array = core.alloc_array_from_values(&[Value::Int(1)]).unwrap();
                    seed(&mut core, array, label.clone());
                    assert!(matches!(
                        core.execute(&module),
                        Err(InterpreterError::UncaughtException { .. })
                    ));
                    assert_eq!(core.pending_exception, Some(Value::Int(42)));
                    assert_eq!(core.pending_exception_label, label);
                    assert!(core.console_output().is_empty());
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
    fn arithmetic_reductions_keep_element_labels_and_the_mini_lane_bd_9vouw_487() {
        for reverse in [false, true] {
            for legacy in [false, true] {
                for label in [Label::Public, Label::Secret] {
                    let module = reduction_module(
                        reverse,
                        legacy,
                        true,
                        vec![
                            Ir3Instruction::Add {
                                dst: 4,
                                lhs: 0,
                                rhs: 1,
                            },
                            Ir3Instruction::Return { value: 4 },
                        ],
                    );
                    let mut core = core();
                    let array = core
                        .alloc_array_from_values(&[Value::Int(1), Value::Int(2)])
                        .unwrap();
                    core.set_own_property_label(array, "0", &label).unwrap();
                    seed(&mut core, array, Label::Public);
                    let result = core.execute(&module);
                    assert_console_result(&core, result, &label, Value::Int(3));
                    assert!(
                        !core.simple_callback_register_pool.is_empty(),
                        "primitive arithmetic must still execute the existing mini-lane"
                    );
                }
            }
        }
    }

    #[test]
    fn mini_lane_throw_keeps_element_provenance_bd_9vouw_487() {
        for reverse in [false, true] {
            for legacy in [false, true] {
                for label in [Label::Public, Label::Secret] {
                    let module = reduction_module(
                        reverse,
                        legacy,
                        true,
                        vec![Ir3Instruction::Throw { value: 1 }],
                    );
                    let mut core = core();
                    let array = core.alloc_array_from_values(&[Value::Int(42)]).unwrap();
                    core.set_own_property_label(array, "0", &label).unwrap();
                    seed(&mut core, array, Label::Public);
                    assert!(matches!(
                        core.execute(&module),
                        Err(InterpreterError::UncaughtException { .. })
                    ));
                    assert_eq!(core.pending_exception, Some(Value::Int(42)));
                    assert_eq!(core.pending_exception_label, label);
                    assert!(core.active_inline_callback_context_label.is_none());
                    assert!(!core.simple_callback_register_pool.is_empty());
                    assert_eq!(
                        core.estimated_memory_bytes(),
                        core.recompute_estimated_memory_bytes()
                    );
                }
            }
        }
    }

    #[test]
    fn mini_lane_uses_remaining_shared_budget_and_restores_context_bd_9vouw_487() {
        let module = reduction_module(
            false,
            false,
            true,
            vec![
                Ir3Instruction::Add {
                    dst: 4,
                    lhs: 0,
                    rhs: 1,
                },
                Ir3Instruction::Return { value: 4 },
            ],
        );
        let mut core = core();
        let array = core.alloc_array_from_values(&[Value::Int(2)]).unwrap();
        seed(&mut core, array, Label::Secret);
        core.config.instruction_budget = 10;
        core.instructions_executed = 9;
        let outcome = core.with_array_reduction_observation(
            RegRange { start: 10, count: 1 },
            None,
            |core| {
                core.invoke_simple_reduce_callback(
                    Some(&module),
                    &Value::Function(0),
                    Value::Int(1),
                    Value::Int(2),
                    0,
                    array,
                )
            },
        );
        assert!(matches!(
            outcome,
            Err(InterpreterError::BudgetExhausted {
                executed: 10,
                budget: 10,
            })
        ));
        assert_eq!(core.instructions_executed, 10);
        assert!(core.active_inline_callback_context_label.is_none());
        assert!(!core.simple_callback_register_pool.is_empty());
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );

        // The callback has exactly two instructions. After the refused return,
        // two newly available shared steps suffice; its earlier allowance is
        // not reset and a stale Secret callback context cannot escape.
        core.config.instruction_budget = 12;
        let value = core
            .with_array_reduction_observation(
                RegRange { start: 9, count: 1 },
                None,
                |core| {
                    core.invoke_simple_reduce_callback(
                        Some(&module),
                        &Value::Function(0),
                        Value::Int(1),
                        Value::Int(2),
                        0,
                        array,
                    )
                },
            )
            .unwrap();
        assert_eq!(value, Value::Int(3));
        assert_eq!(core.instructions_executed, 12);
        assert_eq!(core.take_pending_hostcall_result_label(), None);
        assert!(core.active_inline_callback_context_label.is_none());
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }

    #[test]
    fn sparse_reductions_stream_indices_and_refuse_at_shared_budget_bd_9vouw_487() {
        for reverse in [false, true] {
            for has_initial in [false, true] {
                let module = reduction_module(
                    reverse,
                    false,
                    has_initial,
                    vec![Ir3Instruction::Throw { value: 1 }],
                );
                let mut core = core();
                let array = core.alloc_array_from_values(&[]).unwrap();
                core.set_object_property(
                    array,
                    "length".into(),
                    Value::Int(i64::from(u32::MAX)),
                )
                .unwrap();
                seed(&mut core, array, Label::Public);
                core.config.instruction_budget = 32;
                let outcome = core.array_reduce_receiver(
                    &module,
                    Some(Value::Object(array)),
                    RegRange {
                        start: 8,
                        count: if has_initial { 2 } else { 1 },
                    },
                    reverse,
                    false,
                    Some(0),
                );
                assert!(
                    matches!(
                        &outcome,
                        Err(InterpreterError::BudgetExhausted {
                            executed: 32,
                            budget: 32,
                        })
                    ),
                    "sparse indices must be probed under the shared budget; observed {outcome:?}"
                );
                assert_eq!(core.instructions_executed, 32);
                assert!(
                    core.simple_callback_register_pool.is_empty(),
                    "holes never invoke the throwing callback"
                );
                assert!(core.pending_exception.is_none());
                assert!(core.active_inline_callback_context_label.is_none());
                assert_eq!(
                    core.estimated_memory_bytes(),
                    core.recompute_estimated_memory_bytes()
                );
            }
        }
    }

    #[test]
    fn closure_reductions_use_retained_owner_and_captured_labels_bd_9vouw_487() {
        for reverse in [false, true] {
            for legacy in [false, true] {
                for label in [Label::Public, Label::Secret] {
                    let mut owner = reduction_module(
                        false,
                        false,
                        true,
                        vec![
                            Ir3Instruction::LoadName {
                                dst: 4,
                                name_pool_index: 1,
                                allow_missing: false,
                            },
                            Ir3Instruction::Return { value: 4 },
                        ],
                    );
                    owner.header.source_label = "reducer-captured-owner.mjs".into();
                    // Function-table indices are local: caller function0 must
                    // never stand in for the closure owner's function0.
                    let caller = reduction_module(
                        reverse,
                        legacy,
                        true,
                        vec![
                            Ir3Instruction::LoadInt { dst: 4, value: 7 },
                            Ir3Instruction::Return { value: 4 },
                        ],
                    );
                    let mut core = core();
                    core.ensure_module_record(&owner, &owner.header.source_label)
                        .unwrap();
                    core.closures.push(ClosureValue {
                        function_index: 0,
                        captured_env: vec![ScopeFrame::from_bindings(BTreeMap::from([(
                            "classified_cell".into(),
                            ScopeBinding::with_labeled_state(
                                BindingKind::Const,
                                Value::Int(37),
                                label.clone(),
                                true,
                            ),
                        )]))],
                    });
                    core.closure_module_origins
                        .insert(0, owner.header.source_label.clone());
                    let array = core.alloc_array_from_values(&[Value::Int(1)]).unwrap();
                    seed(&mut core, array, Label::Public);
                    core.write_reg_with_label(8, Value::Closure(0), Label::Public)
                        .unwrap();
                    core.sync_estimated_memory_bytes().unwrap();
                    let outcome = core.execute(&caller);
                    assert_console_result(&core, outcome, &label, Value::Int(37));
                    assert!(
                        core.simple_callback_register_pool.is_empty(),
                        "closures must use the canonical owner/capture-aware callback boundary"
                    );
                }
            }
        }
    }

    #[test]
    fn reduction_array_argument_coercion_keeps_guest_effects_and_labels_bd_9vouw_487() {
        for reverse in [false, true] {
            for legacy in [false, true] {
                for through_move in [false, true] {
                    for label in [Label::Public, Label::Secret] {
                        let mut callback = Vec::new();
                        let operand = if through_move {
                            callback.push(Ir3Instruction::Move { dst: 5, src: 3 });
                            5
                        } else {
                            3
                        };
                        callback.extend([
                            Ir3Instruction::Add {
                                dst: 4,
                                lhs: 0,
                                rhs: operand,
                            },
                            Ir3Instruction::Return { value: 4 },
                        ]);
                        let mut module =
                            reduction_module(reverse, legacy, true, callback);
                        module.constant_pool.push("coercions".into());
                        module.function_table.push(Ir3FunctionDesc {
                            entry: module.instructions.len() as u32,
                            arity: 0,
                            frame_size: 2,
                            name: Some("array_value_of".into()),
                            is_generator: false,
                            rest_param_index: None,
                        });
                        module.instructions.extend([
                            Ir3Instruction::LoadName {
                                dst: 0,
                                name_pool_index: 2,
                                allow_missing: false,
                            },
                            Ir3Instruction::Inc { dst: 0, src: 0 },
                            Ir3Instruction::StoreScoped {
                                src: 0,
                                name_pool_index: 2,
                            },
                            Ir3Instruction::LoadName {
                                dst: 1,
                                name_pool_index: 1,
                                allow_missing: false,
                            },
                            Ir3Instruction::Return { value: 1 },
                        ]);
                        let mut core = core();
                        core.scope_chain.current_mut().unwrap().insert_binding(
                            "coercions".into(),
                            ScopeBinding::with_labeled_state(
                                BindingKind::Var,
                                Value::Int(0),
                                Label::Public,
                                true,
                            ),
                        );
                        let array = core.alloc_array_from_values(&[Value::Int(1)]).unwrap();
                        core.set_object_property(
                            array,
                            "valueOf".into(),
                            Value::Function(1),
                        )
                        .unwrap();
                        seed(&mut core, array, label.clone());
                        core.sync_estimated_memory_bytes().unwrap();
                        let result = core.execute(&module);
                        assert_console_result(&core, result, &label, Value::Int(42));
                        assert_eq!(
                            core.load_runtime_name("coercions", false).unwrap(),
                            Value::Int(1),
                            "the array argument must run its guest valueOf exactly once"
                        );
                        assert!(
                            core.simple_callback_register_pool.is_empty(),
                            "array argument reads select canonical dispatch before callback work"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn reductions_accept_specialized_callable_kinds_bd_9vouw_487() {
        for reverse in [false, true] {
            for legacy in [false, true] {
                for (kind, callback) in [
                    ("generator", Value::GeneratorFunction(0)),
                    ("async", Value::AsyncFunction(0)),
                    ("async_generator", Value::AsyncGeneratorFunction(0)),
                ] {
                    // Generator bodies must remain suspended. If either runs
                    // during reduce, this uncaught throw fails execution.
                    let body = if kind == "async" {
                        Ir3Instruction::Return { value: 1 }
                    } else {
                        Ir3Instruction::Throw { value: 1 }
                    };
                    let mut module = reduction_module(reverse, legacy, true, vec![body]);
                    module.function_table[0].is_generator = kind != "async";
                    let mut core = core();
                    core.closures.push(ClosureValue {
                        function_index: 0,
                        captured_env: Vec::new(),
                    });
                    let array = core.alloc_array_from_values(&[Value::Int(7)]).unwrap();
                    seed(&mut core, array, Label::Public);
                    core.write_reg_with_label(8, callback, Label::Public)
                        .unwrap();
                    core.sync_estimated_memory_bytes().unwrap();
                    let result = core.execute(&module).expect("callable reducer must execute");
                    assert_eq!(result.console_output.len(), 1);
                    let value = core.read_reg(4).unwrap();
                    match kind {
                        "generator" => assert!(matches!(value, Value::Generator(_))),
                        "async_generator" => {
                            assert!(matches!(value, Value::AsyncGeneratorObject(_)));
                        }
                        "async" => {
                            let Value::Promise(id) = value else {
                                panic!("async reducer must return a Promise, got {value:?}");
                            };
                            let promise = core
                                .promise_store
                                .get(crate::promise_model::PromiseHandle(id))
                                .expect("async reducer promise is retained");
                            assert_eq!(
                                promise.state,
                                crate::promise_model::PromiseState::Fulfilled(
                                    crate::object_model::JsValue::Int(7)
                                )
                            );
                        }
                        _ => unreachable!(),
                    }
                    assert!(core.simple_callback_register_pool.is_empty());
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
    fn raw_function_reductions_initialize_rest_arguments_bd_9vouw_487() {
        for reverse in [false, true] {
            for legacy in [false, true] {
                // function reducer(accumulator, ...rest) { return rest; }
                // Return r1 is otherwise eligible for the pure mini-lane.
                let mut module = reduction_module(
                    reverse,
                    legacy,
                    true,
                    vec![Ir3Instruction::Return { value: 1 }],
                );
                module.function_table[0].arity = 2;
                module.function_table[0].rest_param_index = Some(1);
                let mut core = core();
                let array = core.alloc_array_from_values(&[Value::Int(7)]).unwrap();
                seed(&mut core, array, Label::Public);
                let result = core.execute(&module).expect("rest reducer must execute");
                assert_eq!(result.console_output.len(), 1);
                let value = core.read_reg(4).unwrap();
                let Value::Object(rest) = value else {
                    panic!("rest parameter must be an array, got {value:?}");
                };
                assert_eq!(core.array_like_length(rest).unwrap(), 3);
                assert_eq!(core.array_index_value(rest, 0).unwrap(), Some(Value::Int(7)));
                assert_eq!(core.array_index_value(rest, 1).unwrap(), Some(Value::Int(0)));
                assert_eq!(
                    core.array_index_value(rest, 2).unwrap(),
                    Some(Value::Object(array))
                );
                assert!(core.simple_callback_register_pool.is_empty());
                assert!(core.active_inline_callback_context_label.is_none());
                assert_eq!(
                    core.estimated_memory_bytes(),
                    core.recompute_estimated_memory_bytes()
                );
            }
        }
    }
}
