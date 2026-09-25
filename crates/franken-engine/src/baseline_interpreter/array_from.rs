//! Array.from on the ordinary callback and property-read paths (bd-9vouw.42).
//!
//! A mapper is guest code, not a second, restricted instruction interpreter.
//! Its owner module, captures, exceptions, work budget and labels travel through
//! the same isolated call machinery as other native callbacks. Array-like
//! lengths are captured once, but indexed reads remain live and interleaved
//! with mapper calls. Temporary values stay charged across reentrant calls.

use super::*;

impl InterpreterCore {
    pub(super) fn array_from_builtin(
        &mut self,
        module: Option<&Ir3Module>,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let source = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
        let mapper = self.builtin_arg(args, 1)?.unwrap_or(Value::Undefined);
        let this_arg = self.builtin_arg(args, 2)?.unwrap_or(Value::Undefined);
        let context = self.join_arg_range_label(args)?;
        let previous_bytes = self
            .active_inline_callback_context_label
            .as_ref()
            .map(Self::estimate_label_bytes)
            .unwrap_or(0);
        let scratch = previous_bytes
            .saturating_add(Self::estimate_value_bytes(&source))
            .saturating_add(Self::estimate_value_bytes(&mapper))
            .saturating_add(Self::estimate_value_bytes(&this_arg));
        self.json_reserve_temporary(scratch)?;
        if let Err(error) =
            self.apply_memory_component_delta(previous_bytes, Self::estimate_label_bytes(&context))
        {
            self.json_release_temporary(scratch);
            return Err(error);
        }
        let previous = self.active_inline_callback_context_label.replace(context);
        let mut outcome = (|| {
            self.json_charge_work()?;
            // IsCallable precedes GetMethod(items, @@iterator), including for
            // nullish items. Never execute a getter to validate the mapper.
            if !matches!(mapper, Value::Undefined) && !mapper.is_callable() {
                return Err(InterpreterError::TypeError {
                    expected: "function".to_string(),
                    got: mapper.type_name().to_string(),
                });
            }
            if matches!(source, Value::Undefined | Value::Null) {
                return Err(InterpreterError::TypeError {
                    expected: "object-coercible Array.from source".to_string(),
                    got: source.type_name().to_string(),
                });
            }
            for value in [&source, &mapper, &this_arg] {
                self.json_observe_reachable_value(value)?;
            }
            self.array_from_source(module, source, &mapper, &this_arg)
        })();
        if let Err(error) = self.observe_scoped_callback_result() {
            outcome = Err(error);
        }
        // Seal language errors before restoring the context. Host resource
        // refusals must not be converted into catchable guest exceptions.
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
            .expect("reentrant Array.from restores its caller's observation scope");
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
        self.active_inline_callback_context_label = previous;
        self.estimated_memory_bytes = self
            .estimated_memory_bytes
            .saturating_sub(Self::estimate_label_bytes(&context))
            .saturating_add(previous_bytes);
        self.json_release_temporary(scratch);
        outcome
    }

    fn array_from_source(
        &mut self,
        module: Option<&Ir3Module>,
        source: Value,
        mapper: &Value,
        this_arg: &Value,
    ) -> Result<Value, InterpreterError> {
        let backing = match &source {
            value if value.is_object_like() => {
                self.iterator_carrier_backing_id(value, "Array.from source")?
            }
            Value::Str(_) => Some(self.ensure_builtin_prototype("String")?),
            Value::Int(_) | Value::Float(_) => Some(self.ensure_builtin_prototype("Number")?),
            Value::Bool(_) => Some(self.ensure_builtin_prototype("Boolean")?),
            Value::BigInt(_) => Some(self.ensure_builtin_prototype("BigInt")?),
            Value::Symbol(_) => Some(self.ensure_builtin_prototype("Symbol")?),
            _ => None,
        };
        // GetMethod occurs once, before allocating the destination. Nullish
        // methods permit the array-like branch; a noncallable method or a
        // throwing getter is an error, never a reason to silently fall back.
        let method = match backing {
            Some(object) => self.lookup_symbol_iterator_method(module, object, source.clone())?,
            None => None,
        };
        self.observe_scoped_callback_result()?;
        let target = self.alloc_array_with_prototype(None)?;
        let count = if let Some(method) = method {
            let module = module.ok_or_else(|| InterpreterError::TypeError {
                expected: "module-backed Array.from iterator invocation".to_string(),
                got: "missing module context".to_string(),
            })?;
            let context = self.json_parse_context_label()?;
            let (iterator, label) = self.invoke_inline_method_call_with_argument_label(
                Some(module),
                method,
                source.clone(),
                Vec::new(),
                Some(context),
            )?;
            self.json_observe_label(label)?;
            let init = self.prepare_custom_iterator_result(module, iterator)?;
            self.observe_scoped_callback_result()?;
            let iterator = self.init_iterator_from_state(source, init, IterationKind::ForOf)?;
            self.array_from_iterator(Some(module), iterator, mapper, this_arg, target)?
        } else if matches!(source, Value::Iterator(_) | Value::Generator(_)) {
            let iterator = self.init_for_of_iterator(module, source)?;
            self.array_from_iterator(module, iterator, mapper, this_arg, target)?
        } else {
            let explicit_iterator = match backing {
                Some(object) => self.array_from_has_explicit_iterator(object)?,
                None => false,
            };
            // The baseline currently supplies native collection iteration as
            // a private for-of fallback, not installed Map/Set iterator methods.
            // Reuse that same state rather than inventing a parallel key model.
            // This retains its existing key-identity and mutation limitations
            // (bd-9vouw.33); it does not claim complete Map/Set conformance.
            let collection_iterator = match &source {
                Value::Object(object) if !explicit_iterator => {
                    self.array_from_collection_iterator(*object)?
                }
                _ => None,
            };
            if let Some(iterator) = collection_iterator {
                self.array_from_iterator(module, iterator, mapper, this_arg, target)?
            } else if let Value::Str(text) = source {
                // The implicit native string iterator is code-point based.
                // An explicitly nullish @@iterator instead selects ToObject's
                // indexed UTF-16 code-unit view, including split surrogates.
                self.array_from_string(module, &text, mapper, this_arg, target, !explicit_iterator)?
            } else {
                self.array_from_array_like(module, source, backing, mapper, this_arg, target)?
            }
        };
        self.json_store_parsed_property(
            target,
            JsString::from("length"),
            Value::Int(count as i64),
        )?;
        Ok(Value::Object(target))
    }

    // This non-observable inspection only distinguishes a missing native
    // fallback from an explicitly installed nullish method. Never run `has`
    // traps, repeat the getter, or skip an exotic prototype boundary.
    fn array_from_has_explicit_iterator(
        &mut self,
        object: ObjectId,
    ) -> Result<bool, InterpreterError> {
        let key = RuntimePropertyKey::Symbol(WellKnownSymbol::Iterator.id());
        let mut current = Some(object);
        for _ in 0..MAX_PROTOTYPE_CHAIN_DEPTH {
            let Some(object) = current else {
                return Ok(false);
            };
            self.json_charge_work()?;
            if self.proxy_record(object)?.is_some() {
                return Ok(true);
            }
            let object = self
                .heap
                .get(object.0 as usize)
                .ok_or(InterpreterError::ObjectNotFound { id: object.0 })?;
            if object.contains_own_runtime_property(&key) {
                return Ok(true);
            }
            current = object.prototype;
        }
        if current.is_none() {
            Ok(false)
        } else {
            Err(InterpreterError::StackOverflow {
                depth: MAX_PROTOTYPE_CHAIN_DEPTH as usize,
                max: MAX_PROTOTYPE_CHAIN_DEPTH as usize,
            })
        }
    }

    fn array_from_collection_iterator(
        &mut self,
        object: ObjectId,
    ) -> Result<Option<Value>, InterpreterError> {
        let storage = self
            .collection_storage_id(object, "Set", "__values")
            .or_else(|| self.collection_storage_id(object, "Map", "__entries"));
        let Some(storage) = storage else {
            return Ok(None);
        };
        let storage = self
            .heap
            .get(storage.0 as usize)
            .ok_or(InterpreterError::ObjectNotFound { id: storage.0 })?;
        let count = storage.properties.len();
        // Covers the existing collection snapshot, decoded Map keys, and the
        // values vector while alloc_iterator admits its retained state. This
        // reservation remains live across all pair-array allocations.
        let scratch = Self::estimate_heap_object_bytes(storage)
            .saturating_mul(4)
            .saturating_add((count as u64).saturating_mul(4 * std::mem::size_of::<Value>() as u64));
        let work = (count as u64).saturating_add(scratch.div_ceil(64));
        for _ in 0..work {
            self.json_charge_work()?;
        }
        self.json_reserve_temporary(scratch)?;
        let outcome = (|| {
            let values = self.collection_iteration_values(object)?.ok_or_else(|| {
                InterpreterError::TypeError {
                    expected: "unchanged native collection storage".to_string(),
                    got: "missing collection storage".to_string(),
                }
            })?;
            self.init_iterator_from_state(
                Value::Object(object),
                RuntimeForOfInit::from_values(values),
                IterationKind::ForOf,
            )
            .map(Some)
        })();
        self.json_release_temporary(scratch);
        outcome
    }

    fn array_from_iterator(
        &mut self,
        module: Option<&Ir3Module>,
        iterator: Value,
        mapper: &Value,
        this_arg: &Value,
        target: ObjectId,
    ) -> Result<u64, InterpreterError> {
        let mut index = 0_u64;
        loop {
            self.json_charge_work()?;
            if index == 9_007_199_254_740_991 {
                let error = InterpreterError::TypeError {
                    expected: "Array.from index below the safe-integer limit".to_string(),
                    got: index.to_string(),
                };
                return self.array_from_close_after_error(module, iterator, error);
            }
            // IteratorStep/IteratorValue failures do NOT run IteratorClose.
            // Only the mapper and destination-property operation below own
            // the abrupt-completion cleanup boundary.
            let Some(element) = self.advance_for_of_iterator(module, iterator.clone())? else {
                return Ok(index);
            };
            self.observe_scoped_callback_result()?;
            if let Err(error) =
                self.array_from_append(module, mapper, this_arg, target, index, element)
            {
                return self.array_from_close_after_error(module, iterator, error);
            }
            index += 1;
        }
    }

    fn array_from_close_after_error<T>(
        &mut self,
        module: Option<&Ir3Module>,
        iterator: Value,
        error: InterpreterError,
    ) -> Result<T, InterpreterError> {
        let language_error = Self::js_catchable_error_name(&error).is_some();
        if !language_error && !matches!(error, InterpreterError::UncaughtException { .. }) {
            // Containment refusal is not a guest completion. Do not execute
            // arbitrary return() code after cancellation or budget exhaustion.
            return Err(error);
        }
        let error = if language_error {
            self.scoped_native_error(&error)?
        } else {
            error
        };
        let Some(module) = module else {
            return Err(error);
        };
        let Some(original) = self.pending_exception.as_ref() else {
            return Err(error);
        };
        let scratch = Self::estimate_value_bytes(original)
            .saturating_add(Self::estimate_label_bytes(&self.pending_exception_label));
        self.json_reserve_temporary(scratch)?;
        let original = self
            .pending_exception
            .clone()
            .expect("checked pending exception");
        let original_label = self.pending_exception_label.clone();
        let closed = self.close_iterator(module, iterator, IteratorCloseReason::Throw);
        let outcome = match closed {
            Err(close_error)
                if Self::js_catchable_error_name(&close_error).is_none()
                    && !matches!(close_error, InterpreterError::UncaughtException { .. }) =>
            {
                drop((original, original_label));
                Err(close_error)
            }
            _ => {
                // A throw completion wins over return-getter failures,
                // return() throws, and non-object return values. Preserve the
                // original guest value, not merely its formatted error text.
                self.replace_pending_abrupt_slots(Some((original, original_label)), None)
                    .and(Err(error))
            }
        };
        self.json_release_temporary(scratch);
        outcome
    }

    fn array_from_array_like(
        &mut self,
        module: Option<&Ir3Module>,
        receiver: Value,
        backing: Option<ObjectId>,
        mapper: &Value,
        this_arg: &Value,
        target: ObjectId,
    ) -> Result<u64, InterpreterError> {
        let Some(backing) = backing else {
            return Ok(0);
        };
        // LengthOfArrayLike: Get and ToLength each occur once. Reuse the
        // observable length coercion already used by the JSON native methods.
        let length = self.json_reviver_array_length(module, backing, receiver.clone())?;
        // This entry point constructs an ordinary Array, whose length is a
        // uint32. ArrayCreate must fail before the first indexed Get; do not
        // turn an invalid length into a long loop and a host budget refusal.
        if length > u64::from(u32::MAX) {
            return Err(InterpreterError::RangeError {
                message: "invalid Array.from array length".to_string(),
            });
        }
        for index in 0..length {
            self.json_charge_work()?;
            let key = RuntimePropertyKey::String(JsString::from(index.to_string()));
            let element =
                self.iterator_protocol_property(module, backing, &key, receiver.clone())?;
            self.observe_scoped_callback_result()?;
            self.array_from_append(module, mapper, this_arg, target, index, element)?;
        }
        Ok(length)
    }

    fn array_from_string(
        &mut self,
        module: Option<&Ir3Module>,
        text: &JsString,
        mapper: &Value,
        this_arg: &Value,
        target: ObjectId,
        code_points: bool,
    ) -> Result<u64, InterpreterError> {
        // Stream exact UTF-16 code points. No source-sized vector, and no
        // projection of an unpaired surrogate to the replacement character.
        let mut units = text.encode_utf16().peekable();
        let mut index = 0_u64;
        while let Some(first) = units.next() {
            self.json_charge_work()?;
            let mut pair = [first, 0];
            let length = if code_points
                && (0xd800..=0xdbff).contains(&first)
                && units
                    .peek()
                    .is_some_and(|unit| (0xdc00..=0xdfff).contains(unit))
            {
                pair[1] = units.next().expect("peeked trailing surrogate");
                2
            } else {
                1
            };
            // A single code point has a bounded constructor/Arc footprint.
            self.json_reserve_temporary(256)?;
            let element = Value::Str(JsString::from_code_units(&pair[..length]));
            let outcome = self.array_from_append(module, mapper, this_arg, target, index, element);
            self.json_release_temporary(256);
            outcome?;
            index += 1;
        }
        Ok(index)
    }

    fn array_from_append(
        &mut self,
        module: Option<&Ir3Module>,
        mapper: &Value,
        this_arg: &Value,
        target: ObjectId,
        index: u64,
        element: Value,
    ) -> Result<(), InterpreterError> {
        // Keep a live element and the call's explicit argument vector admitted
        // while an arbitrary nested callback allocates or resynchronizes state.
        let scratch = Self::estimate_value_bytes(&element)
            .saturating_add(Self::estimate_value_bytes(mapper))
            .saturating_add(Self::estimate_value_bytes(this_arg))
            .saturating_add(2 * std::mem::size_of::<Value>() as u64);
        self.json_reserve_temporary(scratch)?;
        let outcome = (|| {
            self.json_observe_reachable_value(&element)?;
            let mapped = if matches!(mapper, Value::Undefined) {
                element
            } else {
                let context = self.json_parse_context_label()?;
                let (value, label) = self.invoke_inline_method_call_with_argument_label(
                    module,
                    mapper.clone(),
                    this_arg.clone(),
                    vec![element, Value::Int(index as i64)],
                    Some(context),
                )?;
                // Do not discard a returned label or let a later public
                // callback replace observations from an earlier element.
                self.json_observe_label(label)?;
                value
            };
            self.observe_scoped_callback_result()?;
            let mapped_bytes = Self::estimate_value_bytes(&mapped);
            self.json_reserve_temporary(mapped_bytes)?;
            let stored = (|| {
                self.json_observe_reachable_value(&mapped)?;
                self.json_store_parsed_property(target, JsString::from(index.to_string()), mapped)
            })();
            self.json_release_temporary(mapped_bytes);
            stored
        })();
        self.json_release_temporary(scratch);
        outcome
    }
}
