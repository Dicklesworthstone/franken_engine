//! Receiver-sensitive Function call/apply through the ordinary callable path.

use super::*;
use crate::ifc_artifacts::Label;

const MAX_APPLY_LENGTH: f64 = 9_007_199_254_740_991.0;

impl InterpreterCore {
    /// Read the private dense list produced by argument lowering, retaining
    /// the final iterator labels even when a spread yielded no values. The
    /// list cannot invoke getters here: those ran during source evaluation.
    pub(super) fn read_spread_argument_array(
        &mut self,
        args: RegRange,
    ) -> Result<ConstructorArguments, InterpreterError> {
        if args.count == 0 {
            return Err(InterpreterError::TypeError {
                expected: "internal argument array and iterator provenance".into(),
                got: "no operands".into(),
            });
        }
        let value = self.read_reg(args.start)?;
        let object = self.expect_object(value, "internal argument array")?;
        if !self.heap[object.0 as usize].is_array {
            return Err(InterpreterError::TypeError {
                expected: "internal argument array".into(),
                got: "non-array object".into(),
            });
        }
        let count = self.array_like_length(object)?;
        let mut label =
            self.read_reg_label(args.start)?
                .join(&self.own_stored_runtime_property_label(
                    object,
                    &RuntimePropertyKey::String(JsString::from("length")),
                ));
        for offset in 1..args.count {
            self.charge_array_method_step()?;
            let (iterator, iterator_label) = self.promise_hostcall_argument(args, offset)?;
            let handle = self.expect_iterator_handle(iterator)?;
            label = label
                .join(&iterator_label)
                .join(&self.for_of_iterator_label(handle)?);
        }
        Ok(ConstructorArguments::Array {
            object,
            count,
            label,
        })
    }

    pub(super) fn enter_spread_constructor_call(
        &mut self,
        module: &Ir3Module,
        args: RegRange,
        dst: u32,
    ) -> Result<(), InterpreterError> {
        let mut label = Label::Public;
        let result = (|| {
            if args.count < 2 {
                return Err(InterpreterError::TypeError {
                    expected: "constructor and internal argument array".into(),
                    got: format!("{} operands", args.count),
                });
            }
            let (callee, callee_label) = self.promise_hostcall_argument(args, 0)?;
            label = label.join(&callee_label);
            let arguments = self.read_spread_argument_array(RegRange {
                start: args
                    .start
                    .checked_add(1)
                    .ok_or(InterpreterError::RegisterOutOfBounds {
                        register: args.start,
                        max: self.config.max_registers,
                    })?,
                count: args.count - 1,
            })?;
            if let ConstructorArguments::Array {
                label: list_label, ..
            } = &arguments
            {
                label = label.join(list_label);
            }
            self.enter_constructor_call(
                module,
                callee.clone(),
                callee_label.clone(),
                arguments,
                self.ip + 1,
                Some(dst),
                callee,
                callee_label,
                false,
            )?;
            Ok(Value::Undefined)
        })();
        self.finish_native_builtin_call(result, label).map(|_| ())
    }

    /// The ordinary inline callable boundary already handles closures,
    /// generators, async functions, builtins, exact exceptions and budgets.
    /// Feed it evaluated arguments without consulting a guest `apply` method.
    pub(super) fn dispatch_spread_call(
        &mut self,
        module: &Ir3Module,
        args: RegRange,
        hostcall: Option<&str>,
    ) -> Result<(Value, Label), InterpreterError> {
        let mut label = Label::Public;
        let result = (|| {
            let (callee, mut callee_label, receiver, mut receiver_label, prefix) =
                if hostcall.is_some() {
                    (
                        Value::Undefined,
                        Label::Public,
                        Value::Undefined,
                        Label::Public,
                        0,
                    )
                } else {
                    if args.count < 3 {
                        return Err(InterpreterError::TypeError {
                            expected: "callee, receiver and internal argument array".into(),
                            got: format!("{} operands", args.count),
                        });
                    }
                    let (callee, callee_label) = self.promise_hostcall_argument(args, 0)?;
                    let (receiver, receiver_label) = self.promise_hostcall_argument(args, 1)?;
                    (callee, callee_label, receiver, receiver_label, 2)
                };
            label = callee_label.join(&receiver_label);
            let arguments = self.read_spread_argument_array(RegRange {
                start: args.start.checked_add(prefix).ok_or(
                    InterpreterError::RegisterOutOfBounds {
                        register: args.start,
                        max: self.config.max_registers,
                    },
                )?,
                count: args.count - prefix,
            })?;
            if let ConstructorArguments::Array {
                label: list_label, ..
            } = &arguments
            {
                label = label.join(list_label);
                // Even an empty list controls defaults, rest length and body
                // effects. Carry that dependence into the callee activation.
                callee_label = callee_label.join(list_label);
            }
            // Concise async methods preserve their lexical home-object super
            // binding independently of the selected callee. Their activation
            // also reads receiver provenance, so carry invocation context
            // there rather than losing it when that binding replaces super.
            receiver_label = receiver_label.join(&label);
            // All argument expressions and iterator steps already executed.
            // Only now may IsCallable reject a non-callable reference.
            if hostcall.is_none() && !Self::is_sync_callable(&callee) {
                return Err(InterpreterError::TypeError {
                    expected: "function".into(),
                    got: callee.type_name().into(),
                });
            }
            let padding = match hostcall {
                Some("promise:constructor") if arguments.count() == 0 => Some(Value::Undefined),
                Some("timer:setTimeout" | "timer:setInterval") if arguments.count() == 1 => {
                    Some(Value::Int(0))
                }
                _ => None,
            };
            let count = u64::from(arguments.count()) + u64::from(padding.is_some());
            // The inline activation reserves receiver/callee/sentinel slots.
            // Keep the same configured limit as Function.prototype.apply.
            if count.saturating_add(3) > u64::from(self.config.max_registers) {
                return Err(InterpreterError::RegisterOutOfBounds {
                    register: u32::try_from(count.saturating_add(2)).unwrap_or(u32::MAX),
                    max: self.config.max_registers,
                });
            }
            let vector_bytes = count.saturating_mul(std::mem::size_of::<(Value, Label)>() as u64);
            let retained_bytes = Self::estimate_timer_value_bytes(&callee)
                .saturating_add(Self::estimate_timer_value_bytes(&receiver))
                .saturating_add(Self::estimate_label_bytes(&callee_label))
                .saturating_add(Self::estimate_label_bytes(&receiver_label))
                .saturating_add(Self::estimate_label_bytes(&label))
                .saturating_add(match &arguments {
                    ConstructorArguments::Array { label, .. } => Self::estimate_label_bytes(label),
                    ConstructorArguments::Registers(_) => 0,
                })
                .saturating_add(padding.as_ref().map_or(0, |value| {
                    Self::estimate_timer_value_bytes(value)
                        .saturating_add(Self::estimate_label_bytes(&label))
                }));
            self.with_array_method_temporary(vector_bytes.saturating_add(retained_bytes), |core| {
                let saved_bytes = core.array_method_temporary_bytes;
                let result = (|| {
                    let mut values = Vec::with_capacity(count as usize);
                    for offset in 0..arguments.count() {
                        core.charge_array_method_step()?;
                        let (value, argument_label) =
                            core.constructor_argument(&arguments, offset)?;
                        let bytes = Self::estimate_timer_value_bytes(&value)
                            .saturating_add(Self::estimate_label_bytes(&argument_label));
                        core.check_temporary_memory_budget(bytes)?;
                        core.array_method_temporary_bytes =
                            core.array_method_temporary_bytes.saturating_add(bytes);
                        core.estimated_memory_bytes =
                            core.estimated_memory_bytes.saturating_add(bytes);
                        values.push((value, argument_label));
                    }
                    if let Some(value) = padding {
                        values.push((value, label.clone()));
                    }
                    let invocation = match hostcall {
                        Some(capability) => InlineInvocation::HostCall(
                            crate::ir_contract::CapabilityTag(capability.to_string()),
                        ),
                        None => InlineInvocation::Call,
                    };
                    let (completion, completion_label) = core.invoke_inline_labeled_call(
                        module,
                        (callee, callee_label),
                        (receiver, receiver_label),
                        &values,
                        invocation,
                    )?;
                    label = label.join(&completion_label);
                    core.complete_inline_call(completion)
                })();
                core.array_method_temporary_bytes = saved_bytes;
                core.estimated_memory_bytes = core.recompute_estimated_memory_bytes();
                result
            })
        })();
        self.finish_native_builtin_call(result, label)
    }

    pub(super) fn intrinsic_function_property(
        &self,
        receiver: &Value,
        key: &RuntimePropertyKey,
    ) -> Option<Value> {
        if !Self::is_sync_callable(receiver) {
            return None;
        }
        if let Some(object_id) = self.function_object_id(receiver) {
            let object = self.heap.get(object_id.0 as usize)?;
            if object.prototype.is_some() || self.function_null_prototypes.contains(&object_id) {
                return None;
            }
        }
        let RuntimePropertyKey::String(key) = key else {
            return None;
        };
        let kind = match key.as_str()? {
            "call" => BuiltinFunctionKind::FunctionPrototypeCall,
            "apply" => BuiltinFunctionKind::FunctionPrototypeApply,
            _ => return None,
        };
        Some(Value::BuiltinFunction(BuiltinFunction {
            kind,
            module_specifier: String::new(),
            bound_object: None,
        }))
    }

    pub(super) fn set_function_prototype_metadata(
        &mut self,
        receiver: &Value,
        object_id: ObjectId,
        prototype: Option<ObjectId>,
    ) -> Result<(), InterpreterError> {
        if !Self::is_sync_callable(receiver) {
            return Ok(());
        }
        if prototype.is_none() {
            if !self.function_null_prototypes.contains(&object_id) {
                self.check_temporary_memory_budget(
                    MEMORY_ESTIMATE_MAP_ENTRY_BYTES + std::mem::size_of::<ObjectId>() as u64,
                )?;
                self.function_null_prototypes.insert(object_id);
            }
        } else {
            self.function_null_prototypes.remove(&object_id);
        }
        Ok(())
    }

    pub(super) fn dispatch_function_method(
        &mut self,
        module: &Ir3Module,
        kind: BuiltinFunctionKind,
        receiver: Option<&Value>,
        args: RegRange,
        mut label: Label,
    ) -> Result<(Value, Label), InterpreterError> {
        // Native calls can recursively invoke other native calls without a
        // guest CallFrame. Count that activation before observing getters so
        // recursive apply lists cannot exhaust the Rust stack.
        self.ensure_call_depth_available()?;
        let saved_depth = self.temporarily_suspended_call_depth;
        self.temporarily_suspended_call_depth = saved_depth.saturating_add(1);
        let result = (|| {
            self.charge_array_method_step()?;
            let callee = receiver.cloned().unwrap_or(Value::Undefined);
            if !Self::is_sync_callable(&callee) {
                return Err(InterpreterError::TypeError {
                    expected: "callable Function method receiver".into(),
                    got: callee.type_name().into(),
                });
            }
            let (this_arg, this_label) = self.promise_hostcall_argument(args, 0)?;
            label = label.join(&this_label);
            let (argument_list, list_label) = if kind == BuiltinFunctionKind::FunctionPrototypeApply
            {
                self.promise_hostcall_argument(args, 1)?
            } else {
                (Value::Undefined, Label::Public)
            };
            label = label.join(&list_label);
            let retained_bytes = Self::estimate_timer_value_bytes(&callee)
                .saturating_add(Self::estimate_timer_value_bytes(&this_arg))
                .saturating_add(Self::estimate_timer_value_bytes(&argument_list))
                .saturating_add(Self::estimate_label_bytes(&label));
            self.with_array_method_temporary(retained_bytes, |core| {
                let length = match kind {
                    BuiltinFunctionKind::FunctionPrototypeCall => {
                        u64::from(args.count.saturating_sub(1))
                    }
                    BuiltinFunctionKind::FunctionPrototypeApply if argument_list.is_nullish() => 0,
                    BuiltinFunctionKind::FunctionPrototypeApply => {
                        if !argument_list.is_object_like() {
                            return Err(InterpreterError::TypeError {
                                expected: "object Function.apply argument list".into(),
                                got: argument_list.type_name().into(),
                            });
                        }
                        let length = core.read_iterator_property(
                            module,
                            &argument_list,
                            &RuntimePropertyKey::String("length".into()),
                            &mut label,
                        )?;
                        let length = core.native_method_to_number(module, length, &mut label)?;
                        if length.is_nan() || length <= 0.0 {
                            0
                        } else {
                            length.floor().min(MAX_APPLY_LENGTH) as u64
                        }
                    }
                    _ => unreachable!("function method dispatcher only accepts call/apply"),
                };
                // The isolated callback wrapper uses registers 0..3 for its
                // receiver, callee and completion sentinel. Reject an
                // oversized list before any indexed reads or allocation.
                if length.saturating_add(3) > u64::from(core.config.max_registers) {
                    return Err(InterpreterError::RegisterOutOfBounds {
                        register: u32::try_from(length.saturating_add(2)).unwrap_or(u32::MAX),
                        max: core.config.max_registers,
                    });
                }
                let length = length as usize;
                let vector_bytes =
                    (length as u64).saturating_mul(std::mem::size_of::<(Value, Label)>() as u64);
                core.with_array_method_temporary(vector_bytes, |core| {
                    let mut arguments = Vec::with_capacity(length);
                    let saved_bytes = core.array_method_temporary_bytes;
                    let result = (|| {
                        for index in 0..length {
                            core.charge_array_method_step()?;
                            let (value, argument_label) =
                                if kind == BuiltinFunctionKind::FunctionPrototypeCall {
                                    core.promise_hostcall_argument(args, index as u32 + 1)?
                                } else {
                                    let value = core.read_iterator_property(
                                        module,
                                        &argument_list,
                                        &RuntimePropertyKey::String(index.to_string().into()),
                                        &mut label,
                                    )?;
                                    (value, label.clone())
                                };
                            label = label.join(&argument_label);
                            let argument_label = label.clone();
                            let bytes = Self::estimate_timer_value_bytes(&value)
                                .saturating_add(Self::estimate_label_bytes(&argument_label));
                            core.check_temporary_memory_budget(bytes)?;
                            core.array_method_temporary_bytes =
                                core.array_method_temporary_bytes.saturating_add(bytes);
                            core.estimated_memory_bytes =
                                core.estimated_memory_bytes.saturating_add(bytes);
                            arguments.push((value, argument_label));
                        }
                        let (completion, completion_label) = core
                            .invoke_inline_method_call_with_receiver_label(
                                module,
                                callee,
                                this_arg,
                                label.clone(),
                                &arguments,
                            )?;
                        label = label.join(&completion_label);
                        core.complete_inline_call(completion)
                    })();
                    // Both getter failures and callback failures release all
                    // retained arguments before returning to the caller.
                    core.array_method_temporary_bytes = saved_bytes;
                    core.estimated_memory_bytes = core.recompute_estimated_memory_bytes();
                    result
                })
            })
        })();
        self.temporarily_suspended_call_depth = saved_depth;
        self.finish_native_builtin_call(result, label)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn core(throughput: bool) -> InterpreterCore {
        let mut config = if throughput {
            InterpreterConfig::v8_defaults()
        } else {
            InterpreterConfig::quickjs_defaults()
        };
        config.max_registers = 1024;
        config.granted_capabilities = BTreeSet::from([
            RuntimeCapability::VmDispatch,
            RuntimeCapability::HeapAllocate,
        ]);
        InterpreterCore::new(config, "function-native-budgets")
    }

    fn module() -> Ir3Module {
        Ir3Module::new(
            ContentHash::compute(b"function-native-budgets"),
            "function-native-budgets",
        )
    }

    #[test]
    fn spread_argument_preflight_releases_native_accounting_on_refusal() {
        for throughput in [false, true] {
            let mut core = core(throughput);
            let list = core.alloc_array_with_prototype(None).unwrap();
            core.set_object_property(list, "length".into(), Value::Int(900))
                .unwrap();
            core.write_reg(0, Value::BuiltinFunction(BuiltinFunction::array_is_array()))
                .unwrap();
            core.write_reg(1, Value::Undefined).unwrap();
            core.write_reg(2, Value::Object(list)).unwrap();
            core.sync_estimated_memory_bytes().unwrap();
            let before = core.estimated_memory_bytes;
            core.config.max_total_memory_bytes =
                before + 450 * std::mem::size_of::<(Value, Label)>() as u64;
            let result =
                core.dispatch_spread_call(&module(), RegRange { start: 0, count: 3 }, None);
            assert!(matches!(
                result,
                Err(InterpreterError::MemoryBudgetExceeded { .. })
            ));
            assert_eq!(core.array_method_temporary_bytes, 0);
            assert_eq!(core.temporarily_suspended_call_depth, 0);
            assert_eq!(core.estimated_memory_bytes, before);
            assert_eq!(
                core.estimated_memory_bytes,
                core.recompute_estimated_memory_bytes()
            );

            core.config.max_total_memory_bytes = u64::MAX;
            core.set_object_property(list, "length".into(), Value::Int(1))
                .unwrap();
            core.set_object_property(list, "0".into(), Value::Int(9))
                .unwrap();
            core.config.instruction_budget = 0;
            let error = core
                .dispatch_spread_call(&module(), RegRange { start: 0, count: 3 }, None)
                .unwrap_err();
            assert!(matches!(error, InterpreterError::BudgetExhausted { .. }));
            assert_eq!(core.array_method_temporary_bytes, 0);
            assert_eq!(core.temporarily_suspended_call_depth, 0);
            assert_eq!(
                core.estimated_memory_bytes,
                core.recompute_estimated_memory_bytes()
            );
        }
    }

    #[test]
    fn argument_vector_preflight_and_failures_release_native_accounting() {
        for throughput in [false, true] {
            let mut core = core(throughput);
            let list = core
                .alloc_object_with_properties(&[("length", Value::Int(900))])
                .unwrap();
            core.write_reg(0, Value::Undefined).unwrap();
            core.write_reg(1, Value::Object(list)).unwrap();
            core.sync_estimated_memory_bytes().unwrap();
            let before = core.estimated_memory_bytes;
            core.config.max_total_memory_bytes =
                before + 450 * std::mem::size_of::<(Value, Label)>() as u64;
            let target = Value::BuiltinFunction(BuiltinFunction::array_is_array());
            let result = core.dispatch_function_method(
                &module(),
                BuiltinFunctionKind::FunctionPrototypeApply,
                Some(&target),
                RegRange { start: 0, count: 2 },
                Label::Public,
            );
            assert!(matches!(
                result,
                Err(InterpreterError::MemoryBudgetExceeded { .. })
            ));
            assert_eq!(core.array_method_temporary_bytes, 0);
            assert_eq!(core.temporarily_suspended_call_depth, 0);
            assert_eq!(core.estimated_memory_bytes, before);
            assert_eq!(
                core.estimated_memory_bytes,
                core.recompute_estimated_memory_bytes()
            );
        }
    }

    #[test]
    fn apply_expansion_consumes_budget_and_preserves_capability_denials() {
        for throughput in [false, true] {
            let mut core = core(throughput);
            let list = core
                .alloc_object_with_properties(&[("length", Value::Int(900))])
                .unwrap();
            core.write_reg(0, Value::Undefined).unwrap();
            core.write_reg(1, Value::Object(list)).unwrap();
            core.config.instruction_budget = 20;
            let target = Value::BuiltinFunction(BuiltinFunction::array_is_array());
            let result = core.dispatch_function_method(
                &module(),
                BuiltinFunctionKind::FunctionPrototypeApply,
                Some(&target),
                RegRange { start: 0, count: 2 },
                Label::Public,
            );
            assert!(matches!(
                result,
                Err(InterpreterError::BudgetExhausted { .. })
            ));
            assert_eq!(core.array_method_temporary_bytes, 0);
            assert_eq!(core.temporarily_suspended_call_depth, 0);
            assert_eq!(
                core.estimated_memory_bytes,
                core.recompute_estimated_memory_bytes()
            );

            core.config.instruction_budget = 10_000;
            core.write_reg(1, Value::str("./unavailable.cjs")).unwrap();
            let require = Value::BuiltinFunction(BuiltinFunction::require("owner.cjs"));
            let result = core.dispatch_function_method(
                &module(),
                BuiltinFunctionKind::FunctionPrototypeCall,
                Some(&require),
                RegRange { start: 0, count: 2 },
                Label::Public,
            );
            assert!(matches!(
                result,
                Err(InterpreterError::CapabilityDenied { .. })
            ));
            assert_eq!(core.array_method_temporary_bytes, 0);
            assert_eq!(core.temporarily_suspended_call_depth, 0);
            assert_eq!(
                core.estimated_memory_bytes,
                core.recompute_estimated_memory_bytes()
            );
        }
    }

    #[test]
    fn call_cancellation_remains_fatal_without_leaking_native_depth() {
        for throughput in [false, true] {
            let mut core = core(throughput);
            let cancellation = CancellationToken::new();
            cancellation.cancel();
            core.config.cancellation_token = Some(cancellation);
            let target = Value::BuiltinFunction(BuiltinFunction::array_is_array());
            let result = core.dispatch_function_method(
                &module(),
                BuiltinFunctionKind::FunctionPrototypeCall,
                Some(&target),
                RegRange { start: 0, count: 0 },
                Label::Public,
            );
            assert!(matches!(result, Err(InterpreterError::Cancelled)));
            assert_eq!(core.temporarily_suspended_call_depth, 0);
            assert_eq!(core.array_method_temporary_bytes, 0);
        }
    }
}
