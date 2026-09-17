//! Reflect invocation through observable, bounded CreateListFromArrayLike.
//!
//! Unlike Function.prototype.apply, Reflect requires an object argumentsList.
//! Validate the callable/constructor (and newTarget) before touching that list;
//! extract it once before invoking the existing native call/construct machinery.

use super::*;

impl InterpreterCore {
    pub(super) fn reflect_invocation_builtin(
        &mut self,
        module: Option<&Ir3Module>,
        args: RegRange,
        construct: bool,
    ) -> Result<Value, InterpreterError> {
        let target = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
        let valid_target = if construct {
            self.is_constructible_value(&target)
        } else {
            target.is_callable()
        };
        if !valid_target {
            return Err(InterpreterError::TypeError {
                expected: if construct { "constructor" } else { "callable" }.into(),
                got: target.type_name().into(),
            });
        }
        // Supplying undefined explicitly is not the same as omitting newTarget.
        // Its constructibility check precedes even Get(argumentsList, "length").
        let explicit_new_target = if construct && args.count >= 3 {
            let value = self.builtin_arg(args, 2)?.unwrap_or(Value::Undefined);
            if !self.is_constructible_value(&value) {
                return Err(InterpreterError::TypeError {
                    expected: "constructible Reflect.construct newTarget".into(),
                    got: value.type_name().into(),
                });
            }
            Some((
                value,
                self.clone_register_label_with_temporary_budget(args.start + 2)?,
            ))
        } else {
            None
        };
        let this_arg = if construct {
            Value::Undefined
        } else {
            self.builtin_arg(args, 1)?.unwrap_or(Value::Undefined)
        };
        let source = self
            .builtin_arg(args, if construct { 1 } else { 2 })?
            .unwrap_or(Value::Undefined);
        if !source.is_object_like() {
            return Err(InterpreterError::TypeError {
                expected: "Reflect argumentsList object".into(),
                got: source.type_name().into(),
            });
        }
        let mut labels = self.clone_isolated_call_labels_from_registers(
            Some(if construct {
                args.start
            } else {
                args.start + 1
            }),
            RegRange {
                start: args.start,
                count: 0,
            },
        )?;
        let context = self.join_arg_range_label(args)?;
        let context_bytes = Self::estimate_label_bytes(&context);
        let saved_bytes = self
            .active_inline_callback_context_label
            .as_ref()
            .map(Self::estimate_label_bytes)
            .unwrap_or(0);
        // Root references and label carriers survive every indexed getter and
        // nested invocation. Keep that ownership in the resync-safe component.
        let roots_bytes = Self::estimate_value_bytes(&target)
            .saturating_add(Self::estimate_value_bytes(&this_arg))
            .saturating_add(Self::estimate_value_bytes(&source))
            .saturating_add(Self::estimate_label_bytes(&labels.receiver))
            .saturating_add(explicit_new_target.as_ref().map_or(0, |(value, label)| {
                Self::estimate_value_bytes(value).saturating_add(Self::estimate_label_bytes(label))
            }));
        let scratch = saved_bytes.saturating_add(roots_bytes);
        self.json_reserve_temporary(scratch)?;
        if let Err(error) = self.apply_memory_component_delta(saved_bytes, context_bytes) {
            self.json_release_temporary(scratch);
            return Err(error);
        }
        let saved_context = self.active_inline_callback_context_label.replace(context);
        let mut reserved = 0;
        let mut outcome = (|| {
            self.json_charge_work()?;
            // Do not use the legacy recursive argument-provenance scan before
            // the native work/memory guards have had a chance to run.
            self.json_observe_reachable_value(&source)?;
            let source_label = self.json_parse_context_label()?;
            let (arguments, argument_labels, selection_label) = self.observable_apply_arguments(
                module,
                source,
                source_label,
                &mut reserved,
                false,
            )?;
            labels.arguments = IsolatedArgumentLabels::Exact(argument_labels);
            self.json_observe_label(selection_label)?;
            let (value, label) = if construct {
                self.invoke_inline_construct_with_labels(
                    module,
                    target,
                    arguments,
                    Some(labels),
                    explicit_new_target,
                )?
            } else {
                let context = self.json_parse_context_label()?;
                self.invoke_inline_method_call_with_labels(
                    module,
                    target,
                    this_arg,
                    arguments,
                    Some(context),
                    labels,
                )?
            };
            let context = self.json_parse_context_label()?;
            let label = self.join_owned_label_with_temporary_budget(label, &context)?;
            self.replace_pending_hostcall_result_label(Some(label))?;
            Ok(value)
        })();
        self.simple_callback_temporary_bytes = self
            .simple_callback_temporary_bytes
            .saturating_sub(reserved);
        let context = self
            .active_inline_callback_context_label
            .take()
            .expect("nested invocations restore the active callback context");
        if matches!(outcome, Err(InterpreterError::UncaughtException { .. }))
            && let Err(error) = self.join_pending_exception_label(&context)
        {
            outcome = Err(error);
        }
        self.active_inline_callback_context_label = saved_context;
        self.estimated_memory_bytes = self
            .estimated_memory_bytes
            .saturating_sub(Self::estimate_label_bytes(&context))
            .saturating_add(saved_bytes);
        self.json_release_temporary(scratch);
        outcome
    }
}

impl InterpreterCore {
    /// Proxy [[OwnPropertyKeys]] consumes an array-like result, not necessarily
    /// an Array, and applies its restricted elementTypes during indexed Get.
    pub(super) fn observable_proxy_own_keys_list(
        &mut self,
        module: Option<&Ir3Module>,
        source: Value,
    ) -> Result<Vec<Value>, InterpreterError> {
        if !source.is_object_like() {
            return Err(InterpreterError::TypeError {
                expected: "array-like object returned by Proxy.ownKeys".into(),
                got: source.type_name().into(),
            });
        }
        let context = self.json_parse_context_label()?;
        let saved_bytes = self
            .active_inline_callback_context_label
            .as_ref()
            .map(Self::estimate_label_bytes)
            .unwrap_or(0);
        let scratch = saved_bytes.saturating_add(Self::estimate_value_bytes(&source));
        self.json_reserve_temporary(scratch)?;
        if let Err(error) =
            self.apply_memory_component_delta(saved_bytes, Self::estimate_label_bytes(&context))
        {
            self.json_release_temporary(scratch);
            return Err(error);
        }
        let saved_context = self.active_inline_callback_context_label.replace(context);
        let mut reserved = 0;
        let mut outcome = (|| {
            self.json_observe_reachable_value(&source)?;
            let source_label = self.json_parse_context_label()?;
            let (keys, labels, selection_label) =
                self.observable_apply_arguments(module, source, source_label, &mut reserved, true)?;
            self.json_observe_label(selection_label)?;
            for label in labels {
                self.json_observe_label(label)?;
            }
            let label = self.json_parse_context_label()?;
            self.replace_pending_hostcall_result_label(Some(label))?;
            Ok(keys)
        })();
        self.simple_callback_temporary_bytes = self
            .simple_callback_temporary_bytes
            .saturating_sub(reserved);
        let context = self
            .active_inline_callback_context_label
            .take()
            .expect("nested key-list reads restore the active callback context");
        if matches!(outcome, Err(InterpreterError::UncaughtException { .. }))
            && let Err(error) = self.join_pending_exception_label(&context)
        {
            outcome = Err(error);
        }
        self.active_inline_callback_context_label = saved_context;
        self.estimated_memory_bytes = self
            .estimated_memory_bytes
            .saturating_sub(Self::estimate_label_bytes(&context))
            .saturating_add(saved_bytes);
        self.json_release_temporary(scratch);
        outcome
    }
}

impl InterpreterCore {
    // A private, domain-separated property cell reuses the existing seed-tracked
    // function-owner registry. It is not the default instance prototype: class
    // metadata and previously constructed instances must survive replacement.
    fn constructor_prototype_override_key(
        &self,
        module: &Ir3Module,
        function: &Value,
    ) -> Result<Option<(ContentHash, u32)>, InterpreterError> {
        let foreign = self.foreign_closure_module(function, module)?;
        let owner = foreign.as_deref().unwrap_or(module);
        let (owner, index) = match function {
            Value::Function(index) => (Self::function_prototype_owner_id(owner), *index),
            Value::Closure(index) => (Self::closure_prototype_owner_id(owner), *index),
            _ => return Ok(None),
        };
        let mut digest = Sha256::new();
        digest.update(b"FrankenEngine.ConstructorPrototypeProperty.v1");
        digest.update(owner.as_bytes());
        Ok(Some((
            ContentHash::from_bytes(digest.finalize().into()),
            index,
        )))
    }

    pub(super) fn constructor_prototype_override(
        &self,
        module: &Ir3Module,
        function: &Value,
    ) -> Result<Option<(Value, Label)>, InterpreterError> {
        let Some(key) = self.constructor_prototype_override_key(module, function)? else {
            return Ok(None);
        };
        let Some(cell) = self.function_prototypes.get(&key) else {
            return Ok(None);
        };
        let object = self
            .heap
            .get(cell.0 as usize)
            .ok_or(InterpreterError::ObjectNotFound { id: cell.0 })?;
        let value =
            object
                .properties
                .get("value")
                .ok_or_else(|| InterpreterError::InternalError {
                    details: "constructor prototype cell has no value".into(),
                })?;
        let label = object
            .property_labels
            .get("value")
            .unwrap_or(&Label::Public);
        self.check_temporary_memory_budget(
            Self::estimate_value_bytes(value).saturating_add(Self::estimate_label_bytes(label)),
        )?;
        Ok(Some((value.clone(), label.clone())))
    }

    pub(super) fn set_constructor_prototype_override(
        &mut self,
        module: &Ir3Module,
        function: &Value,
        value: Value,
        label: Label,
    ) -> Result<(), InterpreterError> {
        let key = self
            .constructor_prototype_override_key(module, function)?
            .ok_or_else(|| InterpreterError::TypeError {
                expected: "ordinary function prototype property".into(),
                got: function.type_name().into(),
            })?;
        let cell = match self.function_prototypes.get(&key) {
            Some(cell) => *cell,
            None => self.alloc_object_with_prototype(None)?,
        };
        let previous = &self.heap[cell.0 as usize];
        let previous_bytes = Self::estimate_heap_object_bytes(previous);
        self.check_temporary_memory_budget(
            previous_bytes
                .saturating_add(Self::estimate_value_bytes(&value))
                .saturating_add(Self::estimate_label_bytes(&label)),
        )?;
        let mut projected = previous.clone();
        projected.properties.insert("value".into(), value);
        projected.property_labels.insert("value".into(), label);
        self.apply_memory_component_delta(
            previous_bytes,
            Self::estimate_heap_object_bytes(&projected),
        )?;
        self.mutate_heap(|heap| heap[cell.0 as usize] = projected);
        self.mutate_function_prototypes(|registry| registry.insert(key, cell));
        Ok(())
    }
}
