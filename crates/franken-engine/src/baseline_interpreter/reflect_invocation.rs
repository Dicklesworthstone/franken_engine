//! Observable, bounded Reflect invocation and property operations.
//!
//! Unlike Function.prototype.apply, Reflect requires an object argumentsList.
//! Validate the callable/constructor (and newTarget) before touching that list;
//! extract it once before invoking the existing native call/construct machinery.

use super::*;

#[derive(Clone, Copy)]
pub(super) enum ReflectPropertyOperation {
    Get,
    Set,
    Has,
    Delete,
}

impl InterpreterCore {
    /// Validate the target before ToPropertyKey, then retain the converted key,
    /// receiver and callback provenance through the actual internal method.
    /// This uses the existing object/Proxy storage, not fabricated backing for
    /// function value carriers that do not implement ordinary properties yet.
    /// `Date` and `Promise` get an own `prototype` (the realm intrinsic that
    /// `Date.prototype` reads, bd-9vouw.34) before Reflect observes their
    /// property storage.
    pub(super) fn reflect_property_builtin(
        &mut self,
        module: Option<&Ir3Module>,
        args: RegRange,
        operation: ReflectPropertyOperation,
    ) -> Result<Value, InterpreterError> {
        let target_value = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
        let target = self.reflection_target_object(&target_value)?;
        if let Value::BuiltinFunction(builtin) = &target_value
            && let Some(name) = Self::materialized_global_prototype_name(builtin)
        {
            self.ensure_materialized_prototype_property(target, name)?;
        }
        let input_key = self.builtin_arg(args, 1)?.unwrap_or(Value::Undefined);
        let is_set = matches!(operation, ReflectPropertyOperation::Set);
        let value = if is_set {
            self.builtin_arg(args, 2)?.unwrap_or(Value::Undefined)
        } else {
            Value::Undefined
        };
        let receiver = if matches!(operation, ReflectPropertyOperation::Get) || is_set {
            // The storage object is not the callable's observable identity.
            self.builtin_arg(args, if is_set { 3 } else { 2 })?
                .unwrap_or_else(|| target_value.clone())
        } else {
            Value::Undefined
        };
        let context = self.join_arg_range_label(args)?;
        let saved_bytes = self
            .active_inline_callback_context_label
            .as_ref()
            .map(Self::estimate_label_bytes)
            .unwrap_or(0);
        let roots_bytes = Self::estimate_value_bytes(&target_value)
            .saturating_add(Self::estimate_value_bytes(&input_key))
            .saturating_add(Self::estimate_value_bytes(&value))
            .saturating_add(Self::estimate_value_bytes(&receiver));
        let scratch = saved_bytes.saturating_add(roots_bytes);
        self.json_reserve_temporary(scratch)?;
        if let Err(error) =
            self.apply_memory_component_delta(saved_bytes, Self::estimate_label_bytes(&context))
        {
            self.json_release_temporary(scratch);
            return Err(error);
        }
        let saved_context = self.active_inline_callback_context_label.replace(context);
        let mut key_bytes = 0;
        let mut outcome = (|| {
            self.json_charge_work()?;
            // No guest Get occurs here. A revoked target Proxy is checked by
            // its internal method only AFTER property conversion has run.
            if !matches!(&target_value, Value::Object(_)) {
                self.json_observe_reachable_value(&target_value)?;
            }
            for root in [&Value::Object(target), &input_key, &value, &receiver] {
                self.json_observe_reachable_value(root)?;
            }
            let converted = self.coerce_runtime_property_key(module, input_key)?;
            if let Value::Str(text) = &converted {
                self.check_string_limit(text.len())?;
                for _ in 0..text.len().div_ceil(64) {
                    self.json_charge_work()?;
                }
            }
            let bytes = Self::estimate_value_bytes(&converted);
            self.json_reserve_temporary(bytes)?;
            key_bytes = bytes;
            let key = self.executable_property_key_from_value(&converted);
            drop(converted);
            self.observe_scoped_callback_result()?;
            self.join_pending_hostcall_stream_label(target)?;
            self.observe_scoped_callback_result()?;
            self.reflect_observe_selected_property(target, &key)?;
            let result = match operation {
                ReflectPropertyOperation::Get => {
                    self.iterator_protocol_property(module, target, &key, receiver)?
                }
                ReflectPropertyOperation::Has => {
                    Value::Bool(self.proxy_aware_has_runtime_property(module, target, &key, 0)?)
                }
                ReflectPropertyOperation::Set => {
                    // Admit provenance BEFORE guest state can change. Refused
                    // writes may keep a conservative floor; successful writes
                    // must never outlive a refused label allocation.
                    self.reflect_admit_mutation_label(target)?;
                    if receiver.is_object_like()
                        && let Some(receiver_object) =
                            self.iterator_carrier_backing_id(&receiver, "Reflect receiver")?
                    {
                        self.reflect_admit_mutation_label(receiver_object)?;
                    }
                    let receiver = self.reflect_data_property_receiver(target, &key, receiver)?;
                    Value::Bool(self.proxy_aware_set_runtime_property(
                        module, target, &key, value, receiver, 0,
                    )?)
                }
                ReflectPropertyOperation::Delete => {
                    self.reflect_admit_mutation_label(target)?;
                    let deleted =
                        self.proxy_aware_delete_runtime_property(module, target, &key, 0)?;
                    Value::Bool(deleted)
                }
            };
            self.observe_scoped_callback_result()?;
            self.json_observe_reachable_value(&result)?;
            Ok(result)
        })();
        // Native TypeErrors caused by a getter's result must retain the same
        // observations as guest throws. Resource refusals stay uncatchable.
        if let Err(error) = self.observe_scoped_callback_result() {
            outcome = Err(error);
        }
        if let Err(error) = &outcome
            && Self::js_catchable_error_name(error).is_some()
        {
            outcome = match self.scoped_native_error(error) {
                Ok(error) | Err(error) => Err(error),
            };
        }
        let context = self
            .active_inline_callback_context_label
            .take()
            .expect("nested property operations restore callback context");
        if outcome.is_ok() {
            if let Err(error) = self
                .clone_dominant_label_with_temporary_budget(
                    &context,
                    self.pending_hostcall_result_label
                        .as_ref()
                        .unwrap_or(&Label::Public),
                    0,
                )
                .and_then(|label| self.replace_pending_hostcall_result_label(Some(label)))
            {
                outcome = Err(error);
            }
        } else if matches!(outcome, Err(InterpreterError::UncaughtException { .. }))
            && let Err(error) = self.join_pending_exception_label(&context)
        {
            outcome = Err(error);
        }
        self.active_inline_callback_context_label = saved_context;
        self.estimated_memory_bytes = self
            .estimated_memory_bytes
            .saturating_sub(Self::estimate_label_bytes(&context))
            .saturating_add(saved_bytes);
        self.json_release_temporary(key_bytes);
        self.json_release_temporary(scratch);
        outcome
    }

    /// Materialize `C.prototype` as an own ES2020 data property (non-writable,
    /// non-enumerable, non-configurable) on a materialized constructor's
    /// property storage, pointing at the intrinsic the direct read returns.
    fn ensure_materialized_prototype_property(
        &mut self,
        backing: ObjectId,
        name: &'static str,
    ) -> Result<(), InterpreterError> {
        let key = RuntimePropertyKey::String(JsString::from("prototype"));
        if self
            .heap
            .get(backing.0 as usize)
            .is_some_and(|object| object.contains_own_runtime_property(&key))
        {
            return Ok(());
        }
        let prototype = self.ensure_builtin_prototype(name)?;
        self.set_object_property(backing, "prototype".to_string(), Value::Object(prototype))?;
        self.set_own_property_attributes(
            backing,
            &key,
            PropertyAttributes {
                writable: false,
                enumerable: false,
                configurable: false,
            },
        )
    }

    /// The ordinary data-property write path stores through an ObjectId, while
    /// getters, setters and Proxy traps must observe the original callable.
    /// Normalize a backed builtin receiver only after a private, bounded walk
    /// proves that this Set cannot invoke an accessor or cross a Proxy boundary.
    /// The canonical setter still decides writability, extensibility and labels.
    fn reflect_data_property_receiver(
        &mut self,
        target: ObjectId,
        key: &RuntimePropertyKey,
        receiver: Value,
    ) -> Result<Value, InterpreterError> {
        let Value::BuiltinFunction(builtin) = &receiver else {
            return Ok(receiver);
        };
        let Some(backing) = Self::builtin_function_property_object(builtin) else {
            return Ok(receiver);
        };
        let mut current = target;
        for _ in 0..MAX_PROTOTYPE_CHAIN_DEPTH {
            self.json_charge_work()?;
            // Inspect private records without GetMethod or a revocation check.
            // The actual Set operation retains its validation and trap order.
            if self.proxy_record(current)?.is_some() {
                return Ok(receiver);
            }
            let object = self
                .heap
                .get(current.0 as usize)
                .ok_or(InterpreterError::ObjectNotFound { id: current.0 })?;
            // Inspect borrowed descriptors: a preflight must not clone a
            // potentially large data value or allocate accessor carriers.
            let own_accessor = match key {
                RuntimePropertyKey::String(key) => object
                    .properties
                    .get_exact(key)
                    .map(|value| matches!(value, Value::Accessor { .. })),
                RuntimePropertyKey::Symbol(symbol) => object
                    .properties
                    .baseline_symbol_property(core_symbol_id(*symbol))
                    .map(|property| match property {
                        BaselineSymbolProperty::Data(value) => {
                            matches!(value, Value::Accessor { .. })
                        }
                        BaselineSymbolProperty::Accessor { .. } => true,
                    }),
            };
            match own_accessor {
                Some(true) => return Ok(receiver),
                Some(false) => return Ok(Value::Object(backing)),
                None => match object.prototype {
                    Some(prototype) => current = prototype,
                    None => return Ok(Value::Object(backing)),
                },
            }
        }
        // Leave cycle/depth refusal to the canonical Set implementation.
        Ok(receiver)
    }

    /// Save selected callback/getter labels before nested invocation replaces
    /// the pending result carrier. Do not create unowned context for callers
    /// that have not installed a scoped boundary.
    pub(super) fn observe_scoped_callback_result(&mut self) -> Result<(), InterpreterError> {
        if self.active_inline_callback_context_label.is_some() {
            let label = self.json_parse_context_label()?;
            self.json_observe_label(label)?;
        }
        Ok(())
    }

    /// Materialize a language error while its observation context is live.
    /// Do not roll back the heap: conversion/getter effects and any intrinsic
    /// prototypes allocated by error construction must remain valid on every
    /// exit, including a subsequent resource refusal.
    pub(super) fn scoped_native_error(
        &mut self,
        error: &InterpreterError,
    ) -> Result<InterpreterError, InterpreterError> {
        let thrown = self.native_error_to_thrown_value(error)?;
        let label = self.json_parse_context_label()?;
        self.replace_pending_abrupt_slots(Some((thrown.clone(), label)), None)?;
        Ok(InterpreterError::UncaughtException {
            value: self.uncaught_exception_description(&thrown),
        })
    }

    /// A native fault can depend on observations that exist only in the
    /// callback scope (for example a secret array-like length). Materialize
    /// its exception before restoring that scope: the outer dispatch cannot
    /// reconstruct it from public argument aliases or a consumed result slot.
    /// Guest throws already carry their original value. Containment failures
    /// must remain uncatchable and must not allocate an Error object here.
    fn seal_scoped_native_failure<T>(
        &mut self,
        outcome: Result<T, InterpreterError>,
    ) -> Result<T, InterpreterError> {
        match outcome {
            Err(error) if Self::js_catchable_error_name(&error).is_some() => {
                self.observe_scoped_callback_result()?;
                Err(self.scoped_native_error(&error)?)
            }
            other => other,
        }
    }

    pub(super) fn reflect_observe_selected_property(
        &mut self,
        object: ObjectId,
        key: &RuntimePropertyKey,
    ) -> Result<(), InterpreterError> {
        let mut current = object;
        for _ in 0..MAX_PROTOTYPE_CHAIN_DEPTH {
            self.json_charge_work()?;
            // A secret definition key can label the owner's shape without
            // labelling its stored value. Inherited reads must retain that
            // shape floor as well as the eventual property's value label.
            let shape = self
                .object_mutation_labels
                .get(&current)
                .into_iter()
                .chain(self.binary_storage_label_ref(current))
                .max();
            if let Some(shape) = shape {
                self.check_temporary_memory_budget(Self::estimate_label_bytes(shape))?;
                let shape = shape.clone();
                self.json_observe_label(shape)?;
            }
            match self.proxy_record(current)? {
                Some((target, _, false)) => current = target,
                // Revocation is still checked by the requested internal
                // method, not by this non-observable provenance inspection.
                Some((_, _, true)) => return Ok(()),
                None => {
                    let object = self
                        .heap
                        .get(current.0 as usize)
                        .ok_or(InterpreterError::ObjectNotFound { id: current.0 })?;
                    if object.contains_own_runtime_property(key) {
                        let label = self.own_stored_runtime_property_label(current, key);
                        self.json_observe_label(label)?;
                        return Ok(());
                    }
                    match object.prototype {
                        Some(prototype) => current = prototype,
                        None => return Ok(()),
                    }
                }
            }
        }
        Err(InterpreterError::StackOverflow {
            depth: MAX_PROTOTYPE_CHAIN_DEPTH as usize,
            max: MAX_PROTOTYPE_CHAIN_DEPTH as usize,
        })
    }

    pub(super) fn reflect_admit_mutation_label(
        &mut self,
        object: ObjectId,
    ) -> Result<(), InterpreterError> {
        let label = self.json_parse_context_label()?;
        let bytes = Self::estimate_label_bytes(&label);
        self.json_reserve_temporary(bytes)?;
        let outcome = (|| {
            // Include transparent Proxy targets and aliased binary storage.
            // Inspect private slots only: receiver traps or revocation must
            // not run here, ahead of a possible inherited setter.
            let mut current = object;
            for _ in 0..MAX_PROTOTYPE_CHAIN_DEPTH {
                self.json_charge_work()?;
                self.join_direct_object_mutation_label(current, &label)?;
                self.join_binary_storage_label(current, &label)?;
                match self.proxy_record(current)? {
                    Some((target, _, false)) => current = target,
                    _ => return Ok(()),
                }
            }
            Err(InterpreterError::StackOverflow {
                depth: MAX_PROTOTYPE_CHAIN_DEPTH as usize,
                max: MAX_PROTOTYPE_CHAIN_DEPTH as usize,
            })
        })();
        drop(label);
        self.json_release_temporary(bytes);
        outcome
    }
}

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
            let limit = self.apply_argument_limit(&target);
            let (arguments, argument_labels, selection_label) = self.observable_apply_arguments(
                module,
                source,
                source_label,
                &mut reserved,
                false,
                limit,
            )?;
            labels.arguments = IsolatedArgumentLabels::Exact(argument_labels);
            self.json_observe_label(selection_label)?;
            // bd-9vouw.50: a list that does not fit a register frame goes to a
            // vector-variadic builtin as a vector.
            let vector_tag = (!construct)
                .then(|| Self::vector_variadic_builtin_tag(&target))
                .flatten()
                .filter(|_| arguments.len() > self.config.max_registers.saturating_sub(2) as usize);
            let (value, label) = if let Some(vector_tag) = vector_tag {
                let context = self.json_parse_context_label()?;
                self.apply_vector_variadic_builtin(
                    module,
                    vector_tag,
                    arguments,
                    &labels.arguments,
                    context,
                )?
            } else if construct {
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
        outcome = self.seal_scoped_native_failure(outcome);
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
            let limit = self.config.max_registers.saturating_sub(2);
            let (keys, labels, selection_label) = self.observable_apply_arguments(
                module,
                source,
                source_label,
                &mut reserved,
                true,
                limit,
            )?;
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
        outcome = self.seal_scoped_native_failure(outcome);
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

#[cfg(test)]
mod constructor_property_tests {
    use super::*;
    use crate::ast::ParseGoal;
    use crate::capability::RuntimeCapability;
    use crate::ir_contract::Ir0Module;
    use crate::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
    use crate::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};

    fn assert_native_true(source: &str) {
        let tree = CanonicalEs2020Parser
            .parse_with_options(
                ParserSource {
                    label: "constructor-reflect.js".into(),
                    text: source.into(),
                },
                ParseGoal::Script,
                &ParserOptions::default(),
            )
            .expect("constructor reflection source must parse");
        let module = lower_ir0_to_ir3(
            &Ir0Module::from_syntax_tree(tree, "constructor-reflect.js"),
            &LoweringContext::new("reflect-trace", "reflect-decision", "reflect-policy"),
        )
        .expect("constructor reflection source must lower")
        .ir3;
        for mut config in [
            InterpreterConfig::quickjs_defaults(),
            InterpreterConfig::v8_defaults(),
        ] {
            config.granted_capabilities = [
                RuntimeCapability::VmDispatch,
                RuntimeCapability::HeapAllocate,
                RuntimeCapability::Builtin,
            ]
            .into_iter()
            .collect();
            let mut core = InterpreterCore::new(config, "constructor-reflect");
            let result = core
                .execute(&module)
                .expect("constructor reflection must execute");
            assert_eq!(result.value, Value::Bool(true), "{source}");
            assert_eq!(
                core.estimated_memory_bytes(),
                core.recompute_estimated_memory_bytes(),
                "constructor reflection must release callback and key reservations"
            );
        }
    }

    #[test]
    fn reflect_reads_existing_constructor_property_storage() {
        assert_native_true(
            r#"
            Reflect.get(Date, 'now') === Date.now && Reflect.has(Date, 'now') &&
                Reflect.get(Promise, 'resolve') === Promise.resolve &&
                Reflect.has(Promise, 'resolve') && !Reflect.has(Promise, 'now') &&
                Reflect.get(Date, 'prototype') === Date.prototype;
            "#,
        );
    }

    #[test]
    fn constructor_getters_keep_default_and_explicit_receivers() {
        assert_native_true(
            r#"
            const parent = { get receiver() { return this; } };
            Object.setPrototypeOf(Date, parent);
            const other = {};
            Reflect.get(Date, 'receiver') === Date &&
                Reflect.get(Date, 'receiver', other) === other &&
                Reflect.has(Date, 'receiver') && typeof Date === 'function';
            "#,
        );
    }

    #[test]
    fn constructor_inherited_setters_keep_callable_this() {
        assert_native_true(
            r#"
            let seen;
            let argument;
            const parent = { set value(next) { seen = this; argument = next; } };
            Object.setPrototypeOf(Date, parent);
            const first = Reflect.set(Date, 'value', 17);
            const original = seen === Date && argument === 17;
            const other = {};
            const second = Reflect.set(Date, 'value', 23, other);
            first && original && second && seen === other && argument === 23;
            "#,
        );
    }

    #[test]
    fn constructor_data_writes_honor_distinct_object_receiver() {
        assert_native_true(
            r#"
            const other = {};
            const stored = Reflect.set(Date, 'extra', 42, other);
            const absent = !Reflect.has(Date, 'extra');
            const frozen = Object.preventExtensions(other);
            stored && absent && frozen === other && other.extra === 42 &&
                !Reflect.set(Date, 'newKey', 7, other) &&
                Reflect.set(Date, 'extra', 43, other) && other.extra === 43;
            "#,
        );
    }

    #[test]
    fn constructor_deletion_updates_the_same_live_property_store() {
        assert_native_true(
            r#"
            const present = Reflect.has(Date, 'now');
            const deleted = Reflect.deleteProperty(Date, 'now');
            present && deleted && !Reflect.has(Date, 'now') &&
                Reflect.get(Date, 'now') === undefined &&
                Reflect.deleteProperty(Date, 'now') &&
                Reflect.has(Promise, 'resolve') && typeof Date === 'function';
            "#,
        );
    }

    #[test]
    fn constructor_symbol_lookup_and_deletion_respect_inheritance() {
        assert_native_true(
            r#"
            const key = Symbol('inherited');
            const parent = { [key]: 33 };
            Object.setPrototypeOf(Promise, parent);
            Reflect.get(Promise, key) === 33 && Reflect.has(Promise, key) &&
                Reflect.deleteProperty(Promise, key) &&
                Reflect.get(Promise, key) === 33 && parent[key] === 33;
            "#,
        );
    }

    #[test]
    fn constructor_key_conversion_runs_once_after_target_validation() {
        assert_native_true(
            r#"
            let count = 0;
            const key = { [Symbol.toPrimitive](hint) { count += 1; return 'now'; } };
            const method = Reflect.get(Date, key);
            const valid = method === Date.now && count === 1;
            let rejected = 0;
            try { Reflect.get(1, key); } catch (e) { rejected += e.name === 'TypeError'; }
            try { Reflect.set(null, key, 7); } catch (e) { rejected += e.name === 'TypeError'; }
            try { Reflect.has(undefined, key); } catch (e) { rejected += e.name === 'TypeError'; }
            try { Reflect.deleteProperty(false, key); } catch (e) { rejected += e.name === 'TypeError'; }
            valid && rejected === 4 && count === 1;
            "#,
        );
    }

    #[test]
    fn constructor_getter_throw_preserves_identity_and_restores_context() {
        assert_native_true(
            r#"
            const failure = {};
            const parent = { get value() { throw failure; } };
            Object.setPrototypeOf(Promise, parent);
            let caught = false;
            try { Reflect.get(Promise, 'value'); } catch (error) { caught = error === failure; }
            caught && Reflect.has(Promise, 'value') &&
                Reflect.get(Date, 'now') === Date.now;
            "#,
        );
    }

    #[test]
    fn constructor_data_writes_preserve_identity_and_live_storage() {
        assert_native_true(
            r#"
            const first = Reflect.set(Date, 'extra', 17);
            const second = Reflect.set(Date, 'extra', 23);
            first && second && Reflect.get(Date, 'extra') === 23 &&
                Reflect.has(Date, 'extra') && typeof Date === 'function' &&
                Reflect.deleteProperty(Date, 'extra') && !Reflect.has(Date, 'extra');
            "#,
        );
    }

    #[test]
    fn constructor_non_extensibility_allows_only_existing_data_writes() {
        assert_native_true(
            r#"
            const stored = Reflect.set(Date, 'extra', 17);
            Object.preventExtensions(Date);
            stored && Reflect.set(Date, 'extra', 23) &&
                Reflect.get(Date, 'extra') === 23 &&
                !Reflect.set(Date, 'newKey', 7) && !Reflect.has(Date, 'newKey') &&
                !Reflect.isExtensible(Date);
            "#,
        );
    }

    #[test]
    fn constructor_symbol_data_writes_keep_exact_key_identity() {
        assert_native_true(
            r#"
            const first = Symbol('key');
            const second = Symbol('key');
            const stored = Reflect.set(Promise, first, 31);
            stored && Reflect.get(Promise, first) === 31 &&
                !Reflect.has(Promise, second) && Reflect.get(Promise, second) === undefined &&
                Reflect.deleteProperty(Promise, first) && !Reflect.has(Promise, first);
            "#,
        );
    }

    #[test]
    fn ordinary_target_can_write_to_a_distinct_constructor_receiver() {
        assert_native_true(
            r#"
            const target = { value: 1 };
            const stored = Reflect.set(target, 'value', 41, Promise);
            stored && target.value === 1 && Reflect.get(Promise, 'value') === 41 &&
                Reflect.get(Date, 'value') === undefined && typeof Promise === 'function' &&
                !Reflect.set(target, 'value', 2, 0) && target.value === 1;
            "#,
        );
    }

    #[test]
    fn constructor_data_writes_respect_frozen_inherited_properties() {
        assert_native_true(
            r#"
            const parent = Object.freeze({ value: 17 });
            Object.setPrototypeOf(Date, parent);
            !Reflect.set(Date, 'value', 23) && Reflect.get(Date, 'value') === 17 &&
                Reflect.deleteProperty(Date, 'value') && parent.value === 17;
            "#,
        );
    }

    #[test]
    fn constructor_proxy_prototype_traps_observe_the_callable_receiver() {
        assert_native_true(
            r#"
            let seen;
            let received;
            const parent = new Proxy({}, {
                set(target, key, value, receiver) { seen = receiver; received = value; return true; }
            });
            Object.setPrototypeOf(Date, parent);
            Reflect.set(Date, 'extra', 29) && seen === Date && received === 29 &&
                !Reflect.has(Date, 'extra') && typeof Date === 'function';
            "#,
        );
    }
}
