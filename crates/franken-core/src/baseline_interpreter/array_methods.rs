//! Receiver-sensitive array methods exposed through ordinary property lookup.

use super::*;
use crate::ifc_artifacts::Label;

const MAX_ARRAY_LIKE_LENGTH: u64 = 9_007_199_254_740_991;

impl InterpreterCore {
    pub(super) fn intrinsic_array_property(
        &self,
        object_id: ObjectId,
        key: &RuntimePropertyKey,
    ) -> Option<RuntimeProperty> {
        let object = self.heap.get(object_id.0 as usize)?;
        // A custom prototype replaces the implicit intrinsic prototype. A
        // separately recorded explicit null prototype also removes it.
        if !object.is_array
            || object.prototype.is_some()
            || self.array_null_prototypes.contains(&object_id)
        {
            return None;
        }
        let RuntimePropertyKey::String(key) = key else {
            return None;
        };
        let kind = match key.as_str()? {
            "push" => BuiltinFunctionKind::ArrayPrototypePush,
            "pop" => BuiltinFunctionKind::ArrayPrototypePop,
            "join" => BuiltinFunctionKind::ArrayPrototypeJoin,
            "map" => BuiltinFunctionKind::ArrayPrototypeMap,
            "filter" => BuiltinFunctionKind::ArrayPrototypeFilter,
            "forEach" => BuiltinFunctionKind::ArrayPrototypeForEach,
            "some" => BuiltinFunctionKind::ArrayPrototypeSome,
            "every" => BuiltinFunctionKind::ArrayPrototypeEvery,
            "find" => BuiltinFunctionKind::ArrayPrototypeFind,
            "findIndex" => BuiltinFunctionKind::ArrayPrototypeFindIndex,
            "reduce" => BuiltinFunctionKind::ArrayPrototypeReduce,
            "reduceRight" => BuiltinFunctionKind::ArrayPrototypeReduceRight,
            _ => return None,
        };
        Some(RuntimeProperty::Data(Value::BuiltinFunction(
            BuiltinFunction {
                kind,
                module_specifier: String::new(),
                bound_object: None,
            },
        )))
    }

    pub(super) fn set_array_prototype_metadata(
        &mut self,
        object_id: ObjectId,
        prototype: Option<ObjectId>,
    ) -> Result<(), InterpreterError> {
        let is_array = self
            .heap
            .get(object_id.0 as usize)
            .ok_or(InterpreterError::ObjectNotFound { id: object_id.0 })?
            .is_array;
        if is_array && prototype.is_none() {
            if !self.array_null_prototypes.contains(&object_id) {
                self.check_temporary_memory_budget(
                    MEMORY_ESTIMATE_MAP_ENTRY_BYTES + std::mem::size_of::<ObjectId>() as u64,
                )?;
                self.array_null_prototypes.insert(object_id);
            }
        } else {
            self.array_null_prototypes.remove(&object_id);
        }
        Ok(())
    }

    pub(super) fn dispatch_array_method(
        &mut self,
        module: &Ir3Module,
        kind: BuiltinFunctionKind,
        receiver: Option<&Value>,
        args: RegRange,
        mut label: Label,
    ) -> Result<(Value, Label), InterpreterError> {
        let receiver = receiver.cloned().unwrap_or(Value::Undefined);
        let result = (|| {
            if receiver.is_nullish() {
                return Err(InterpreterError::TypeError {
                    expected: "object-coercible array method receiver".into(),
                    got: receiver.type_name().into(),
                });
            }
            self.charge_array_method_step()?;
            let length_value =
                self.read_array_method_property(module, &receiver, "length", &mut label)?;
            let length_value =
                self.array_method_to_primitive(module, length_value, false, &mut label)?;
            if matches!(length_value, Value::Symbol(_)) {
                return Err(InterpreterError::TypeError {
                    expected: "numeric array-like length".into(),
                    got: "symbol".into(),
                });
            }
            let number = Self::coerce_to_float(&length_value).unwrap_or(f64::NAN);
            // A getter may produce a fresh owned string; no native local needs
            // to retain it while later separator or element callbacks run.
            drop(length_value);
            let length = if number.is_nan() || number <= 0.0 {
                0
            } else {
                number.floor().min(MAX_ARRAY_LIKE_LENGTH as f64) as u64
            };
            match kind {
                BuiltinFunctionKind::ArrayPrototypePush => {
                    let new_length = length
                        .checked_add(u64::from(args.count))
                        .filter(|length| *length <= MAX_ARRAY_LIKE_LENGTH)
                        .ok_or_else(|| InterpreterError::TypeError {
                            expected: "array-like length at most 2^53 - 1".into(),
                            got: "push would exceed the maximum safe length".into(),
                        })?;
                    for offset in 0..args.count {
                        self.charge_array_method_step()?;
                        let (value, value_label) = self.promise_hostcall_argument(args, offset)?;
                        let property_label = label.join(&value_label);
                        self.write_array_method_property(
                            module,
                            &receiver,
                            &(length + u64::from(offset)).to_string(),
                            value,
                            property_label,
                        )?;
                    }
                    self.write_array_method_property(
                        module,
                        &receiver,
                        "length",
                        Value::Int(new_length as i64),
                        label.clone(),
                    )?;
                    Ok(Value::Int(new_length as i64))
                }
                BuiltinFunctionKind::ArrayPrototypePop => {
                    let value = if length == 0 {
                        Value::Undefined
                    } else {
                        let key = (length - 1).to_string();
                        let value =
                            self.read_array_method_property(module, &receiver, &key, &mut label)?;
                        let object = self.array_method_write_object(&receiver)?;
                        let key = RuntimePropertyKey::String(JsString::from(key));
                        self.run_pre_runtime_property_access_hook(module, object, &key)?;
                        self.remove_object_runtime_property(object, &key)?;
                        if let RuntimePropertyKey::String(key) = &key {
                            self.mark_deleted_for_in_iterators(object, key);
                        }
                        value
                    };
                    let value_bytes = Self::estimate_timer_value_bytes(&value);
                    self.with_array_method_temporary(value_bytes, |core| {
                        core.write_array_method_property(
                            module,
                            &receiver,
                            "length",
                            Value::Int(length.saturating_sub(1) as i64),
                            label.clone(),
                        )
                    })?;
                    Ok(value)
                }
                BuiltinFunctionKind::ArrayPrototypeJoin => {
                    let (separator, separator_label) = self.promise_hostcall_argument(args, 0)?;
                    label = label.join(&separator_label);
                    let separator = if matches!(separator, Value::Undefined) {
                        JsString::from(",")
                    } else {
                        self.array_method_to_string(module, separator, &mut label)?
                    };
                    let value =
                        self.join_array_method(module, &receiver, length, separator, &mut label)?;
                    Ok(Value::Str(value))
                }
                BuiltinFunctionKind::ArrayPrototypeMap
                | BuiltinFunctionKind::ArrayPrototypeFilter
                | BuiltinFunctionKind::ArrayPrototypeForEach
                | BuiltinFunctionKind::ArrayPrototypeSome
                | BuiltinFunctionKind::ArrayPrototypeEvery
                | BuiltinFunctionKind::ArrayPrototypeFind
                | BuiltinFunctionKind::ArrayPrototypeFindIndex
                | BuiltinFunctionKind::ArrayPrototypeReduce
                | BuiltinFunctionKind::ArrayPrototypeReduceRight => {
                    self.dispatch_array_callback(module, kind, receiver, args, length, &mut label)
                }
                _ => unreachable!("array method dispatcher accepts only array methods"),
            }
        })();
        self.finish_native_builtin_call(result, label)
    }

    /// Carry native validation and guest callback failures through the same
    /// labeled exception path. Resource refusals remain fatal engine errors.
    pub(super) fn finish_native_builtin_call(
        &mut self,
        result: Result<Value, InterpreterError>,
        label: Label,
    ) -> Result<(Value, Label), InterpreterError> {
        match result {
            Ok(value) => Ok((value, label)),
            Err(
                error @ (InterpreterError::TypeError { .. } | InterpreterError::RangeError { .. }),
            ) => {
                if label == Label::Public {
                    return Err(error);
                }
                self.with_array_method_temporary(Self::estimate_label_bytes(&label), |core| {
                    let diagnostic = error.to_string();
                    let value = core.promise_error_value(&error)?;
                    let mut error = core.rearm_inline_throw(LabeledException { value, label });
                    if let InterpreterError::UncaughtException { value } = &mut error {
                        *value = diagnostic;
                    }
                    Err(error)
                })
            }
            Err(error @ InterpreterError::UncaughtException { .. }) => {
                // Preserve the thrown value's identity and its existing
                // provenance while adding the native algorithm's dependencies.
                if label != Label::Public {
                    self.check_temporary_memory_budget(Self::estimate_label_bytes(&label))?;
                    if let Some(exception) = self.pending_exception.as_mut()
                        && label > exception.label
                    {
                        // Label::join is the lattice maximum. Move the owned
                        // winner instead of cloning a potentially larger
                        // existing Custom label during exception handling.
                        exception.label = label;
                    }
                    self.sync_estimated_memory_bytes()?;
                }
                Err(error)
            }
            Err(error) => Err(error),
        }
    }

    fn dispatch_array_callback(
        &mut self,
        module: &Ir3Module,
        kind: BuiltinFunctionKind,
        receiver: Value,
        args: RegRange,
        length: u64,
        label: &mut Label,
    ) -> Result<Value, InterpreterError> {
        let (callback, callback_label) = self.promise_hostcall_argument(args, 0)?;
        *label = label.join(&callback_label);
        // IsCallable precedes ArraySpeciesCreate and is required even when
        // the receiver has no elements.
        if !Self::is_sync_callable(&callback) {
            return Err(InterpreterError::TypeError {
                expected: "callable array callback".into(),
                got: callback.type_name().into(),
            });
        }
        let reduce = matches!(
            kind,
            BuiltinFunctionKind::ArrayPrototypeReduce
                | BuiltinFunctionKind::ArrayPrototypeReduceRight
        );
        let reverse = kind == BuiltinFunctionKind::ArrayPrototypeReduceRight;
        let visit_holes = matches!(
            kind,
            BuiltinFunctionKind::ArrayPrototypeFind | BuiltinFunctionKind::ArrayPrototypeFindIndex
        );
        let (second, second_label) = self.promise_hostcall_argument(args, 1)?;
        *label = label.join(&second_label);
        let (this_arg, mut accumulator) = if reduce {
            (Value::Undefined, (args.count > 1).then_some(second))
        } else {
            (second, None)
        };
        let retained_bytes = Self::estimate_timer_value_bytes(&receiver)
            .saturating_add(Self::estimate_timer_value_bytes(&callback))
            .saturating_add(Self::estimate_timer_value_bytes(&this_arg))
            .saturating_add(Self::estimate_label_bytes(&callback_label))
            .saturating_add(Self::estimate_label_bytes(&second_label));
        self.with_array_method_temporary(retained_bytes, |core| {
            let target = match kind {
                BuiltinFunctionKind::ArrayPrototypeMap => {
                    Some(core.array_callback_species_create(module, &receiver, length, label)?)
                }
                BuiltinFunctionKind::ArrayPrototypeFilter => {
                    Some(core.array_callback_species_create(module, &receiver, 0, label)?)
                }
                _ => None,
            };
            let mut selected_count = 0u64;
            for offset in 0..length {
                let index = if reverse { length - 1 - offset } else { offset };
                // The fold accumulator is a native local between callback
                // activations. Charge it while getters and callbacks can
                // allocate, including an accumulator produced by a prior call.
                let live_bytes = accumulator
                    .as_ref()
                    .map_or(0, Self::estimate_timer_value_bytes)
                    .saturating_add(target.as_ref().map_or(0, Self::estimate_timer_value_bytes))
                    .saturating_add(Self::estimate_label_bytes(label));
                let early_return = core.with_array_method_temporary(live_bytes, |core| {
                    core.charge_array_method_step()?;
                    let key = index.to_string();
                    if !visit_holes
                        && !core.has_array_method_property(module, &receiver, &key, label)?
                    {
                        return Ok(None);
                    }
                    let value = core.read_array_method_property(module, &receiver, &key, label)?;
                    if reduce && accumulator.is_none() {
                        accumulator = Some(value);
                        return Ok(None);
                    }
                    let value_bytes = Self::estimate_timer_value_bytes(&value)
                        .saturating_add(Self::estimate_label_bytes(label));
                    core.with_array_method_temporary(value_bytes, |core| {
                        // Admit cloned argument payloads and labels before
                        // constructing them; the fixed call shape needs no Vec.
                        let argument_bytes = Self::estimate_timer_value_bytes(&value)
                            .saturating_add(Self::estimate_timer_value_bytes(&receiver))
                            .saturating_add(Self::estimate_timer_value_bytes(&callback))
                            .saturating_add(Self::estimate_timer_value_bytes(&this_arg))
                            .saturating_add(
                                accumulator
                                    .as_ref()
                                    .map_or(0, Self::estimate_timer_value_bytes),
                            )
                            .saturating_add(Self::estimate_label_bytes(label).saturating_mul(5))
                            .saturating_add(std::mem::size_of::<[(Value, Label); 4]>() as u64);
                        let (completion, completion_label) =
                            core.with_array_method_temporary(argument_bytes, |core| {
                                let arguments = [
                                    (
                                        accumulator.clone().unwrap_or(Value::Undefined),
                                        label.clone(),
                                    ),
                                    (value.clone(), label.clone()),
                                    (Value::Int(index as i64), label.clone()),
                                    (receiver.clone(), label.clone()),
                                ];
                                core.invoke_inline_method_call_with_receiver_label(
                                    module,
                                    callback.clone(),
                                    this_arg.clone(),
                                    label.clone(),
                                    if reduce { &arguments } else { &arguments[1..] },
                                )
                            })?;
                        *label = label.join(&completion_label);
                        let result = core.complete_inline_call(completion)?;
                        let result_bytes = Self::estimate_timer_value_bytes(&result)
                            .saturating_add(Self::estimate_label_bytes(label));
                        core.with_array_method_temporary(result_bytes, |core| {
                            match kind {
                                BuiltinFunctionKind::ArrayPrototypeMap => {
                                    core.create_array_method_property(
                                        module,
                                        target.as_ref().expect("map result object"),
                                        &key,
                                        result,
                                        label,
                                    )?;
                                }
                                BuiltinFunctionKind::ArrayPrototypeFilter if result.is_truthy() => {
                                    core.create_array_method_property(
                                        module,
                                        target.as_ref().expect("filter result object"),
                                        &selected_count.to_string(),
                                        value,
                                        label,
                                    )?;
                                    selected_count += 1;
                                }
                                BuiltinFunctionKind::ArrayPrototypeSome if result.is_truthy() => {
                                    return Ok(Some(Value::Bool(true)));
                                }
                                BuiltinFunctionKind::ArrayPrototypeEvery if !result.is_truthy() => {
                                    return Ok(Some(Value::Bool(false)));
                                }
                                BuiltinFunctionKind::ArrayPrototypeFind if result.is_truthy() => {
                                    return Ok(Some(value));
                                }
                                BuiltinFunctionKind::ArrayPrototypeFindIndex
                                    if result.is_truthy() =>
                                {
                                    return Ok(Some(Value::Int(index as i64)));
                                }
                                BuiltinFunctionKind::ArrayPrototypeReduce
                                | BuiltinFunctionKind::ArrayPrototypeReduceRight => {
                                    accumulator = Some(result);
                                }
                                _ => {}
                            }
                            Ok(None)
                        })
                    })
                })?;
                if let Some(value) = early_return {
                    return Ok(value);
                }
            }
            match kind {
                BuiltinFunctionKind::ArrayPrototypeMap
                | BuiltinFunctionKind::ArrayPrototypeFilter => Ok(target.expect("array result")),
                BuiltinFunctionKind::ArrayPrototypeSome => Ok(Value::Bool(false)),
                BuiltinFunctionKind::ArrayPrototypeEvery => Ok(Value::Bool(true)),
                BuiltinFunctionKind::ArrayPrototypeFindIndex => Ok(Value::Int(-1)),
                BuiltinFunctionKind::ArrayPrototypeReduce
                | BuiltinFunctionKind::ArrayPrototypeReduceRight => {
                    accumulator.ok_or_else(|| InterpreterError::TypeError {
                        expected: "nonempty reduce receiver or an initial value".into(),
                        got: "no present elements and no initial value".into(),
                    })
                }
                _ => Ok(Value::Undefined),
            }
        })
    }

    fn has_array_method_property(
        &mut self,
        module: &Ir3Module,
        receiver: &Value,
        key: &str,
        label: &mut Label,
    ) -> Result<bool, InterpreterError> {
        if let Value::Str(text) = receiver {
            return Ok(key == "length"
                || key
                    .parse::<usize>()
                    .is_ok_and(|index| index < text.utf16_len()));
        }
        if !receiver.is_object_like() {
            return Ok(false);
        }
        let Some(object) = self.iterator_carrier_backing_id(receiver, "array method receiver")?
        else {
            return Ok(false);
        };
        let key = RuntimePropertyKey::String(key.into());
        self.run_pre_runtime_property_access_hook(module, object, &key)?;
        *label = label.join(&self.runtime_property_label(object, &key));
        // HasProperty must neither invoke a getter nor clone a large data
        // value just to establish its presence.
        let mut current = Some(object);
        for _ in 0..MAX_PROTOTYPE_CHAIN_DEPTH {
            let Some(id) = current else { break };
            let object = self
                .heap
                .get(id.0 as usize)
                .ok_or(InterpreterError::ObjectNotFound { id: id.0 })?;
            if object.contains_own_runtime_property(&key) {
                return Ok(true);
            }
            current = object.prototype;
        }
        Ok(false)
    }

    fn create_array_method_property(
        &mut self,
        module: &Ir3Module,
        receiver: &Value,
        key: &str,
        value: Value,
        label: &Label,
    ) -> Result<(), InterpreterError> {
        let object = self.array_method_write_object(receiver)?;
        let key = RuntimePropertyKey::String(key.into());
        self.run_pre_runtime_property_access_hook(module, object, &key)?;
        let previous_label = self.own_stored_runtime_property_label(object, &key);
        self.set_own_runtime_property_label(object, &key, label)?;
        // map/filter use CreateDataPropertyOrThrow, never an inherited setter.
        if let Err(error) = self.set_plain_data_runtime_property(object, key.clone(), value) {
            self.set_own_runtime_property_label(object, &key, &previous_label)?;
            return Err(error);
        }
        self.grow_array_length_after_own_index_write(object, &key, label)
    }

    fn array_callback_species_create(
        &mut self,
        module: &Ir3Module,
        receiver: &Value,
        length: u64,
        label: &mut Label,
    ) -> Result<Value, InterpreterError> {
        let is_array = matches!(receiver, Value::Object(id)
            if self.heap.get(id.0 as usize).is_some_and(|object| object.is_array));
        let mut constructor = if is_array {
            self.read_array_method_property(module, receiver, "constructor", label)?
        } else {
            Value::Undefined
        };
        if constructor.is_object_like() {
            let retained_bytes = Self::estimate_timer_value_bytes(&constructor);
            constructor = self.with_array_method_temporary(retained_bytes, |core| {
                core.read_iterator_property(
                    module,
                    &constructor,
                    &RuntimePropertyKey::Symbol(WellKnownSymbol::Species.id()),
                    label,
                )
            })?;
            if matches!(constructor, Value::Null) {
                constructor = Value::Undefined;
            }
        }
        if matches!(constructor, Value::Undefined) {
            if length > u64::from(u32::MAX) {
                return Err(InterpreterError::RangeError {
                    message: "Invalid array length".into(),
                });
            }
            self.run_pre_allocation_hook(module, AllocKind::Array, length as usize)?;
            let result = Value::Object(self.alloc_array_with_prototype(None)?);
            self.create_array_method_property(
                module,
                &result,
                "length",
                Value::Int(length as i64),
                label,
            )?;
            return Ok(result);
        }
        if !matches!(constructor, Value::Function(_) | Value::Closure(_)) {
            return Err(InterpreterError::TypeError {
                expected: "constructible Array Symbol.species".into(),
                got: constructor.type_name().into(),
            });
        }
        let retained_bytes = Self::estimate_timer_value_bytes(&constructor)
            .saturating_add(Self::estimate_label_bytes(label));
        let (completion, result_label) =
            self.with_array_method_temporary(retained_bytes, |core| {
                core.invoke_inline_constructor_call(
                    module,
                    constructor,
                    label.clone(),
                    &[(Value::Int(length as i64), label.clone())],
                )
            })?;
        *label = label.join(&result_label);
        self.complete_inline_call(completion)
    }

    pub(super) fn charge_array_method_step(&mut self) -> Result<(), InterpreterError> {
        if self
            .config
            .cancellation_token
            .as_ref()
            .is_some_and(CancellationToken::is_cancelled)
        {
            return Err(InterpreterError::Cancelled);
        }
        if self.instructions_executed >= self.config.instruction_budget {
            return Err(InterpreterError::BudgetExhausted {
                executed: self.instructions_executed,
                budget: self.config.instruction_budget,
            });
        }
        self.instructions_executed += 1;
        Ok(())
    }

    fn read_array_method_property(
        &mut self,
        module: &Ir3Module,
        receiver: &Value,
        key: &str,
        label: &mut Label,
    ) -> Result<Value, InterpreterError> {
        if let Value::Str(text) = receiver {
            if key == "length" {
                return Ok(Value::Int(text.utf16_len() as i64));
            }
            if let Ok(index) = key.parse::<usize>() {
                return Ok(text.code_unit_at(index).map_or(Value::Undefined, |unit| {
                    Value::Str(JsString::from_code_units(&[unit]))
                }));
            }
            return Ok(Value::Undefined);
        }
        if !receiver.is_object_like() {
            return Ok(Value::Undefined);
        }
        self.read_iterator_property(
            module,
            receiver,
            &RuntimePropertyKey::String(key.into()),
            label,
        )
    }

    fn array_method_write_object(
        &mut self,
        receiver: &Value,
    ) -> Result<ObjectId, InterpreterError> {
        match receiver {
            Value::Object(id) => {
                self.heap
                    .get(id.0 as usize)
                    .ok_or(InterpreterError::ObjectNotFound { id: id.0 })?;
                Ok(*id)
            }
            value if Self::function_object_key(value).is_some() => self
                .ensure_function_object(value)?
                .ok_or_else(|| InterpreterError::TypeError {
                    expected: "array-like object receiver".into(),
                    got: value.type_name().into(),
                }),
            other => Err(InterpreterError::TypeError {
                expected: "writable array-like object receiver".into(),
                got: other.type_name().into(),
            }),
        }
    }

    fn write_array_method_property(
        &mut self,
        module: &Ir3Module,
        receiver: &Value,
        key: &str,
        value: Value,
        mut label: Label,
    ) -> Result<(), InterpreterError> {
        let object = self.array_method_write_object(receiver)?;
        let property_key = RuntimePropertyKey::String(JsString::from(key));
        self.run_pre_runtime_property_access_hook(module, object, &property_key)?;
        if let Some(RuntimeProperty::Accessor(accessor)) =
            self.prototype_chain_lookup_runtime_property(object, &property_key)?
        {
            let setter = accessor.set.ok_or_else(|| InterpreterError::TypeError {
                expected: "writable array method property".into(),
                got: format!("getter-only property {key}"),
            })?;
            label = label.join(&self.runtime_property_label(object, &property_key));
            let (completion, _) = self.invoke_inline_method_call_with_receiver_label(
                module,
                setter,
                receiver.clone(),
                label.clone(),
                &[(value, label)],
            )?;
            self.complete_inline_call(completion)?;
            return Ok(());
        }
        if self.heap[object.0 as usize].is_array
            && key == "length"
            && matches!(value, Value::Int(length) if length > i64::from(u32::MAX))
        {
            return Err(InterpreterError::RangeError {
                message: "Invalid array length".into(),
            });
        }
        let previous_label = self.own_stored_runtime_property_label(object, &property_key);
        self.set_own_runtime_property_label(object, &property_key, &label)?;
        if let Err(error) = self.set_object_runtime_property(object, property_key.clone(), value) {
            self.set_own_runtime_property_label(object, &property_key, &previous_label)?;
            return Err(error);
        }
        self.grow_array_length_after_own_index_write(object, &property_key, &label)
    }

    pub(super) fn grow_array_length_after_own_index_write(
        &mut self,
        object: ObjectId,
        key: &RuntimePropertyKey,
        label: &Label,
    ) -> Result<(), InterpreterError> {
        // An own array index grows length immediately; a later inherited
        // setter can observe the growth or throw before push's final Set.
        // Both callers reach here only after a successful own data write.
        let array_length_growth = if self.heap[object.0 as usize].is_array {
            match key {
                RuntimePropertyKey::String(key) => key.as_str().and_then(|key| {
                    key.parse::<u32>()
                        .ok()
                        .filter(|index| *index < u32::MAX && index.to_string() == key)
                        .and_then(|index| {
                            let old_length =
                                match self.heap[object.0 as usize].properties.get("length") {
                                    Some(Value::Int(length)) => (*length).max(0) as u64,
                                    Some(Value::Float(length))
                                        if length.inner().is_finite()
                                            && length.inner() >= 0.0
                                            && length.inner() <= f64::from(u32::MAX)
                                            && length.inner().fract() == 0.0 =>
                                    {
                                        length.inner() as u64
                                    }
                                    _ => 0,
                                };
                            (u64::from(index) >= old_length).then_some(u64::from(index) + 1)
                        })
                }),
                RuntimePropertyKey::Symbol(_) => None,
            }
        } else {
            None
        };
        if let Some(length) = array_length_growth {
            let length_key = RuntimePropertyKey::String("length".into());
            let previous_label = self.own_stored_runtime_property_label(object, &length_key);
            self.set_own_runtime_property_label(object, &length_key, label)?;
            if let Err(error) = self.set_object_runtime_property(
                object,
                length_key.clone(),
                Value::Int(length as i64),
            ) {
                self.set_own_runtime_property_label(object, &length_key, &previous_label)?;
                return Err(error);
            }
        }
        Ok(())
    }

    pub(super) fn array_method_to_primitive(
        &mut self,
        module: &Ir3Module,
        value: Value,
        string_hint: bool,
        label: &mut Label,
    ) -> Result<Value, InterpreterError> {
        if !value.is_object_like() {
            return Ok(value);
        }
        let exotic = self.read_iterator_property(
            module,
            &value,
            &RuntimePropertyKey::Symbol(WellKnownSymbol::ToPrimitive.id()),
            label,
        )?;
        if !exotic.is_nullish() {
            if !Self::is_sync_callable(&exotic) {
                return Err(InterpreterError::TypeError {
                    expected: "callable Symbol.toPrimitive".into(),
                    got: exotic.type_name().into(),
                });
            }
            let hint = Value::str(if string_hint { "string" } else { "number" });
            let (completion, result_label) = self.invoke_inline_method_call_with_receiver_label(
                module,
                exotic,
                value,
                label.clone(),
                &[(hint, label.clone())],
            )?;
            *label = label.join(&result_label);
            let result = self.complete_inline_call(completion)?;
            if !result.is_object_like() {
                return Ok(result);
            }
            return Err(InterpreterError::TypeError {
                expected: "primitive Symbol.toPrimitive result".into(),
                got: result.type_name().into(),
            });
        }
        let names = if string_hint {
            ["toString", "valueOf"]
        } else {
            ["valueOf", "toString"]
        };
        for name in names {
            let backing = self.iterator_carrier_backing_id(&value, "string-coercible object")?;
            let key = RuntimePropertyKey::String(name.into());
            let present = match backing {
                Some(object) => self
                    .prototype_chain_lookup_runtime_property(object, &key)?
                    .is_some(),
                None => false,
            };
            let method = self.read_iterator_property(module, &value, &key, label)?;
            if Self::is_sync_callable(&method) {
                let (completion, result_label) = self
                    .invoke_inline_method_call_with_receiver_label(
                        module,
                        method,
                        value.clone(),
                        label.clone(),
                        &[],
                    )?;
                *label = label.join(&result_label);
                let result = self.complete_inline_call(completion)?;
                if !result.is_object_like() {
                    return Ok(result);
                }
            } else if !present && name == "toString" {
                let Some(array_stringifier) = self.implicit_array_method_stringifier(backing)
                else {
                    continue;
                };
                if array_stringifier {
                    let join = self.read_array_method_property(module, &value, "join", label)?;
                    if Self::is_sync_callable(&join) {
                        let (completion, result_label) = self
                            .invoke_inline_method_call_with_receiver_label(
                                module,
                                join,
                                value.clone(),
                                label.clone(),
                                &[],
                            )?;
                        *label = label.join(&result_label);
                        let result = self.complete_inline_call(completion)?;
                        if !result.is_object_like() {
                            return Ok(result);
                        }
                        continue;
                    }
                }
                return Ok(Value::str(
                    if backing.is_some_and(|id| self.heap[id.0 as usize].is_array) {
                        "[object Array]"
                    } else {
                        "[object Object]"
                    },
                ));
            }
        }
        Err(InterpreterError::TypeError {
            expected: "primitive object conversion result".into(),
            got: "object".into(),
        })
    }

    // This runtime represents default prototypes implicitly. Determine which
    // default stringifier is reachable without overriding an explicit null or
    // custom prototype, and bound malformed/cyclic external heap chains.
    fn implicit_array_method_stringifier(&self, backing: Option<ObjectId>) -> Option<bool> {
        let Some(mut object_id) = backing else {
            return Some(false);
        };
        for _ in 0..MAX_PROTOTYPE_CHAIN_DEPTH {
            let object = self.heap.get(object_id.0 as usize)?;
            if let Some(prototype) = object.prototype {
                object_id = prototype;
            } else if self.array_null_prototypes.contains(&object_id) {
                return None;
            } else {
                return Some(object.is_array);
            }
        }
        None
    }

    pub(super) fn array_method_to_string(
        &mut self,
        module: &Ir3Module,
        value: Value,
        label: &mut Label,
    ) -> Result<JsString, InterpreterError> {
        let value = self.array_method_to_primitive(module, value, true, label)?;
        match value {
            Value::Str(text) => Ok(text),
            Value::Symbol(_) => Err(InterpreterError::TypeError {
                expected: "string-coercible array element or separator".into(),
                got: "symbol".into(),
            }),
            value => Ok(JsString::from(self.value_to_string(&value))),
        }
    }

    fn join_array_method(
        &mut self,
        module: &Ir3Module,
        receiver: &Value,
        length: u64,
        separator: JsString,
        label: &mut Label,
    ) -> Result<JsString, InterpreterError> {
        let object = if receiver.is_object_like() {
            self.iterator_carrier_backing_id(receiver, "array join receiver")?
        } else {
            None
        };
        if object.is_some_and(|object| self.array_join_stack.contains(&object)) {
            return Ok(JsString::from(""));
        }
        let depth = self
            .effective_call_depth()
            .saturating_add(self.array_join_stack.len());
        if depth >= self.config.max_call_depth {
            return Err(InterpreterError::StackOverflow {
                depth,
                max: self.config.max_call_depth,
            });
        }
        let separator_bytes = Self::estimate_js_string_bytes(&separator);
        self.check_temporary_memory_budget(
            separator_bytes + std::mem::size_of::<ObjectId>() as u64,
        )?;
        let previous_temporary = self.array_method_temporary_bytes;
        let previous_stack_depth = self.array_join_stack.len();
        self.array_method_temporary_bytes = previous_temporary.saturating_add(separator_bytes);
        if let Some(object) = object {
            self.array_join_stack.push(object);
        }
        self.estimated_memory_bytes = self.recompute_estimated_memory_bytes();
        let outcome = (|| {
            let mut units = Vec::new();
            let mut projected_bytes = 0usize;
            for index in 0..length {
                self.charge_array_method_step()?;
                if index != 0 {
                    self.append_array_join_units(&mut units, &mut projected_bytes, &separator)?;
                }
                let value =
                    self.read_array_method_property(module, receiver, &index.to_string(), label)?;
                if !value.is_nullish() {
                    let text = self.array_method_to_string(module, value, label)?;
                    self.append_array_join_units(&mut units, &mut projected_bytes, &text)?;
                }
            }
            self.check_temporary_memory_budget(
                (units.len() as u64)
                    .saturating_mul(5)
                    .saturating_add(MEMORY_ESTIMATE_STRING_BASE_BYTES),
            )?;
            Ok(JsString::from_code_units(&units))
        })();
        self.array_join_stack.truncate(previous_stack_depth);
        self.array_method_temporary_bytes = previous_temporary;
        self.estimated_memory_bytes = self.recompute_estimated_memory_bytes();
        outcome
    }

    fn append_array_join_units(
        &mut self,
        output: &mut Vec<u16>,
        projected_bytes: &mut usize,
        piece: &JsString,
    ) -> Result<(), InterpreterError> {
        let next_projected_bytes = projected_bytes.saturating_add(piece.len());
        self.check_string_limit(next_projected_bytes)?;
        let next_len = output
            .len()
            .checked_add(piece.utf16_len())
            .ok_or_else(|| self.memory_budget_error(u64::MAX, self.heap_object_count_u32()))?;
        let piece_bytes = (piece.utf16_len() as u64)
            .saturating_mul(2)
            .saturating_add(Self::estimate_js_string_bytes(piece));
        self.with_array_method_temporary(piece_bytes, |core| {
            if next_len > output.capacity() {
                let previous_capacity = output.capacity();
                // A growing Vec can briefly retain both its previous and new
                // allocation. Admit the full new buffer before reserving it.
                core.check_temporary_memory_budget((next_len as u64).saturating_mul(2))?;
                output.reserve_exact(next_len - output.len());
                let growth = ((output.capacity() - previous_capacity) as u64).saturating_mul(2);
                core.array_method_temporary_bytes =
                    core.array_method_temporary_bytes.saturating_add(growth);
                core.estimated_memory_bytes = core.estimated_memory_bytes.saturating_add(growth);
            }
            output.extend(piece.code_units_vec());
            *projected_bytes = next_projected_bytes;
            Ok(())
        })
    }

    pub(super) fn with_array_method_temporary<T>(
        &mut self,
        bytes: u64,
        action: impl FnOnce(&mut Self) -> Result<T, InterpreterError>,
    ) -> Result<T, InterpreterError> {
        self.check_temporary_memory_budget(bytes)?;
        self.array_method_temporary_bytes = self.array_method_temporary_bytes.saturating_add(bytes);
        self.estimated_memory_bytes = self.estimated_memory_bytes.saturating_add(bytes);
        let outcome = action(self);
        self.array_method_temporary_bytes = self.array_method_temporary_bytes.saturating_sub(bytes);
        self.estimated_memory_bytes = self.recompute_estimated_memory_bytes();
        outcome
    }
}
