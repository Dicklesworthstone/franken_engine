//! Array.from on the ordinary callback and property-read paths (bd-9vouw.42),
//! and Array.fromAsync as a promise-driven state machine over the same
//! iterator and array-like reads (bd-9vouw.172).
//!
//! A mapper is guest code, not a second, restricted instruction interpreter.
//! Its owner module, captures, exceptions, work budget and labels travel through
//! the same isolated call machinery as other native callbacks. Array-like
//! lengths are captured once, but indexed reads remain live and interleaved
//! with mapper calls. Temporary values stay charged across reentrant calls.

use super::*;

/// The object Array.from fills: a fresh Array, or the object `new C(...)`
/// returned for a constructor `this` (ES2020 22.1.2.1 steps 5.a and 12.a),
/// which gets its elements through [[DefineOwnProperty]] and its length
/// through [[Set]] (bd-9vouw.361).
#[derive(Clone, Copy)]
struct ArrayFromTarget {
    id: ObjectId,
    constructed: bool,
}

impl InterpreterCore {
    pub(super) fn array_from_builtin(
        &mut self,
        module: Option<&Ir3Module>,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        self.array_from_impl(module, args, false, None)
    }

    /// `C.from(items, mapfn, thisArg)` for a constructor `C` other than
    /// %Array% (a subclass, `Array.from.call(Object, ...)`): `new C()` before
    /// an iterable's iterator is taken, `new C(len)` once an array-like's
    /// length is read, each element defined on the result as it is read and
    /// mapped (a failing definition closes the iterator), then
    /// Set(A, "length", len, true). The result was a finished plain array
    /// copied into `new C()`: C saw no length, a `length` setter never ran,
    /// and a Proxy result's defineProperty trap was skipped (bd-9vouw.361).
    pub(super) fn array_from_with_constructor(
        &mut self,
        module: &Ir3Module,
        args: RegRange,
        constructor: Value,
    ) -> Result<Value, InterpreterError> {
        self.array_from_impl(Some(module), args, false, Some(constructor))
    }

    /// `C.of(...items)` for a constructor `C` other than %Array%:
    /// `new C(items.length)`, CreateDataPropertyOrThrow of each item, then
    /// Set(A, "length", len, true) (ES2020 22.1.2.3, bd-9vouw.361).
    pub(super) fn array_of_with_constructor(
        &mut self,
        module: &Ir3Module,
        args: RegRange,
        constructor: Value,
    ) -> Result<Value, InterpreterError> {
        let length = u64::from(args.count);
        let held = (0..args.count)
            .map(|offset| self.read_reg(args.start + offset))
            .collect::<Result<Vec<_>, _>>()?;
        let (instance, label) = self.with_gc_nested_request(held, |core| {
            core.invoke_inline_construct_with_labels(
                Some(module),
                constructor,
                vec![Value::Int(length as i64)],
                None,
                None,
            )
        })?;
        let label = self
            .pending_hostcall_result_label
            .as_ref()
            .unwrap_or(&Label::Public)
            .join(&label);
        self.replace_pending_hostcall_result_label(Some(label))?;
        let Value::Object(instance_id) = instance else {
            return Err(InterpreterError::TypeError {
                expected: "object from the Array.of constructor".to_string(),
                got: instance.type_name().to_string(),
            });
        };
        for offset in 0..args.count {
            let item = self.read_reg(args.start + offset)?;
            self.generic_create_data_property(Some(module), instance_id, u64::from(offset), item)?;
        }
        self.generic_set(
            Some(module),
            instance_id,
            &Self::generic_length_key(),
            Value::Int(length as i64),
        )?;
        Ok(Value::Object(instance_id))
    }

    /// IterableToList + CreateArrayFromList for builtins that take an
    /// iterable (AggregateError's `errors`, bd-9vouw.75): Array.from of the
    /// first argument without a mapper, where a non-iterable source is a
    /// TypeError instead of an array-like.
    pub(super) fn iterable_to_array(
        &mut self,
        module: Option<&Ir3Module>,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        self.array_from_impl(
            module,
            RegRange {
                start: args.start,
                count: args.count.min(1),
            },
            true,
            None,
        )
    }

    fn array_from_impl(
        &mut self,
        module: Option<&Ir3Module>,
        args: RegRange,
        iterable_only: bool,
        constructor: Option<Value>,
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
            if let Some(constructor) = &constructor {
                self.json_observe_reachable_value(constructor)?;
            }
            self.array_from_source(
                module,
                source,
                &mapper,
                &this_arg,
                iterable_only,
                constructor.as_ref(),
            )
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
        iterable_only: bool,
        constructor: Option<&Value>,
    ) -> Result<Value, InterpreterError> {
        let backing = self.array_from_source_backing(&source)?;
        // GetMethod occurs once, before allocating the destination. Nullish
        // methods permit the array-like branch; a noncallable method or a
        // throwing getter is an error, never a reason to silently fall back.
        let method = match backing {
            Some(object) => self.lookup_symbol_iterator_method(module, object, source.clone())?,
            None => None,
        };
        self.observe_scoped_callback_result()?;
        let (target, count) = if let Some(method) = method {
            let module = module.ok_or_else(|| InterpreterError::TypeError {
                expected: "module-backed Array.from iterator invocation".to_string(),
                got: "missing module context".to_string(),
            })?;
            // `new C()` precedes GetIteratorFromMethod (step 5.a).
            let target = self.array_from_target(Some(module), constructor, None)?;
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
            let count =
                self.array_from_iterator(Some(module), iterator, mapper, this_arg, target)?;
            (target, count)
        } else if matches!(source, Value::Iterator(_) | Value::Generator(_)) {
            let target = self.array_from_target(module, constructor, None)?;
            let iterator = self.init_for_of_iterator(module, source)?;
            let count = self.array_from_iterator(module, iterator, mapper, this_arg, target)?;
            (target, count)
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
            let collection = match &source {
                Value::Object(object) if !explicit_iterator => self
                    .collection_storage_id(*object, "Set", "__values")
                    .or_else(|| self.collection_storage_id(*object, "Map", "__entries"))
                    .map(|_| *object),
                _ => None,
            };
            if let Some(object) = collection {
                // `new C()` before the collection's entries are taken.
                let target = self.array_from_target(module, constructor, None)?;
                let iterator = self
                    .array_from_collection_iterator(object)?
                    .ok_or_else(|| InterpreterError::TypeError {
                        expected: "native collection storage".to_string(),
                        got: "missing collection storage".to_string(),
                    })?;
                let count = self.array_from_iterator(module, iterator, mapper, this_arg, target)?;
                (target, count)
            } else if let Value::Str(text) = source {
                // The implicit native string iterator is code-point based.
                // An explicitly nullish @@iterator instead selects ToObject's
                // indexed UTF-16 code-unit view, including split surrogates,
                // an array-like whose length `new C(len)` receives.
                let code_points = !explicit_iterator;
                let length = (!code_points).then(|| text.encode_utf16().count() as u64);
                let target = self.array_from_target(module, constructor, length)?;
                let count =
                    self.array_from_string(module, &text, mapper, this_arg, target, code_points)?;
                (target, count)
            } else if iterable_only {
                return Err(InterpreterError::TypeError {
                    expected: "iterable".to_string(),
                    got: source.type_name().to_string(),
                });
            } else {
                self.array_from_array_like(module, source, backing, mapper, this_arg, constructor)?
            }
        };
        if target.constructed {
            // Set(A, "length", len, true): a setter runs, a refusal throws.
            self.generic_set(
                module,
                target.id,
                &Self::generic_length_key(),
                Value::Int(count as i64),
            )?;
        } else {
            self.json_store_parsed_property(
                target.id,
                JsString::from("length"),
                Value::Int(count as i64),
            )?;
        }
        Ok(Value::Object(target.id))
    }

    /// The object Array.from fills: `new C()` (an iterable) or `new C(len)`
    /// (an array-like) for a constructor `this`, else a fresh Array.
    fn array_from_target(
        &mut self,
        module: Option<&Ir3Module>,
        constructor: Option<&Value>,
        length: Option<u64>,
    ) -> Result<ArrayFromTarget, InterpreterError> {
        let Some(constructor) = constructor else {
            return Ok(ArrayFromTarget {
                id: self.alloc_array_with_prototype(None)?,
                constructed: false,
            });
        };
        let arguments = length.map_or_else(Vec::new, |length| {
            vec![Value::Int(i64::try_from(length).unwrap_or(i64::MAX))]
        });
        let (instance, label) = self.invoke_inline_construct_with_labels(
            module,
            constructor.clone(),
            arguments,
            None,
            None,
        )?;
        self.json_observe_label(label)?;
        self.observe_scoped_callback_result()?;
        let Value::Object(id) = instance else {
            return Err(InterpreterError::TypeError {
                expected: "object from the Array.from constructor".to_string(),
                got: instance.type_name().to_string(),
            });
        };
        Ok(ArrayFromTarget {
            id,
            constructed: true,
        })
    }

    /// The object a source's property reads go to: an object-like value's
    /// backing, or a primitive's prototype (ToObject is not observable here).
    fn array_from_source_backing(
        &mut self,
        source: &Value,
    ) -> Result<Option<ObjectId>, InterpreterError> {
        Ok(match source {
            value if value.is_object_like() => {
                self.iterator_carrier_backing_id(value, "Array.from source")?
            }
            Value::Str(_) => Some(self.ensure_builtin_prototype("String")?),
            Value::Int(_) | Value::Float(_) => Some(self.ensure_builtin_prototype("Number")?),
            Value::Bool(_) => Some(self.ensure_builtin_prototype("Boolean")?),
            Value::BigInt(_) => Some(self.ensure_builtin_prototype("BigInt")?),
            Value::Symbol(_) => Some(self.ensure_builtin_prototype("Symbol")?),
            _ => None,
        })
    }

    // This non-observable inspection only distinguishes a missing native
    // fallback from an explicitly installed nullish method. Never run `has`
    // traps, repeat the getter, or skip an exotic prototype boundary.
    pub(super) fn array_from_has_explicit_iterator(
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
        target: ArrayFromTarget,
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

    pub(super) fn array_from_close_after_error<T>(
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
        constructor: Option<&Value>,
    ) -> Result<(ArrayFromTarget, u64), InterpreterError> {
        let Some(backing) = backing else {
            let target = self.array_from_target(module, constructor, Some(0))?;
            return Ok((target, 0));
        };
        // LengthOfArrayLike: Get and ToLength each occur once. Reuse the
        // observable length coercion already used by the JSON native methods.
        let length = self.json_reviver_array_length(module, backing, receiver.clone())?;
        // Without a constructor `this` this constructs an ordinary Array,
        // whose length is a uint32. ArrayCreate must fail before the first
        // indexed Get; do not turn an invalid length into a long loop and a
        // host budget refusal. `new C(len)` decides for itself (step 12.a).
        if constructor.is_none() && length > u64::from(u32::MAX) {
            return Err(InterpreterError::RangeError {
                message: "invalid Array.from array length".to_string(),
            });
        }
        let target = self.array_from_target(module, constructor, Some(length))?;
        for index in 0..length {
            self.json_charge_work()?;
            let key = RuntimePropertyKey::String(JsString::from(index.to_string()));
            let element =
                self.iterator_protocol_property(module, backing, &key, receiver.clone())?;
            self.observe_scoped_callback_result()?;
            self.array_from_append(module, mapper, this_arg, target, index, element)?;
        }
        Ok((target, length))
    }

    fn array_from_string(
        &mut self,
        module: Option<&Ir3Module>,
        text: &JsString,
        mapper: &Value,
        this_arg: &Value,
        target: ArrayFromTarget,
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
        target: ArrayFromTarget,
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
                if target.constructed {
                    // CreateDataPropertyOrThrow on `new C(...)`'s result: its
                    // [[DefineOwnProperty]] (a Proxy's trap) decides.
                    self.generic_create_data_property(module, target.id, index, mapped)
                } else {
                    self.json_store_parsed_property(
                        target.id,
                        JsString::from(index.to_string()),
                        mapped,
                    )
                }
            })();
            self.json_release_temporary(mapped_bytes);
            stored
        })();
        self.json_release_temporary(scratch);
        outcome
    }
}

/// Where an `Array.fromAsync` call reads its values (ES2024 23.1.2.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FromAsyncSource {
    /// The iterator `items[Symbol.asyncIterator]()` returned.
    AsyncIterator,
    /// A sync iterator, through CreateAsyncFromSyncIterator.
    SyncIterator,
    /// Indexed reads up to the source's length.
    ArrayLike,
}

const FROM_ASYNC_SOURCES: [FromAsyncSource; 3] = [
    FromAsyncSource::AsyncIterator,
    FromAsyncSource::SyncIterator,
    FromAsyncSource::ArrayLike,
];

/// What the pending await of an `Array.fromAsync` call waits for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FromAsyncAwait {
    /// The async iterator's `next()` result.
    Next,
    /// A sync step's value (%AsyncFromSyncIteratorPrototype%'s value
    /// wrapper).
    SyncValue,
    /// The async-from-sync `next()` promise the value wrapper settled.
    SyncStep,
    /// The mapper's result for an iterator value.
    Mapped,
    /// AsyncIteratorClose's await of `return()`; the call then rejects with
    /// the error that closed the iterator.
    Close,
    /// Array-like element `k`.
    Element,
    /// The mapper's result for an array-like element.
    MappedElement,
}

const FROM_ASYNC_AWAITS: [FromAsyncAwait; 7] = [
    FromAsyncAwait::Next,
    FromAsyncAwait::SyncValue,
    FromAsyncAwait::SyncStep,
    FromAsyncAwait::Mapped,
    FromAsyncAwait::Close,
    FromAsyncAwait::Element,
    FromAsyncAwait::MappedElement,
];

/// `Array.fromAsync` (ES2024 23.1.2.1, bd-9vouw.172). The spec runs the body
/// as an async function. Here it is a state machine: the state lives in a
/// holder object, and every Await registers the two resumption steps
/// (`ArrayFromAsyncFulfilled` / `ArrayFromAsyncRejected`, bound to the
/// holder) as reactions on the awaited promise. The microtask ticks match
/// the spec's: one per awaited value, and two per sync-iterator step (the
/// async-from-sync value wrapper, then the await of the step's promise).
/// Like Array.from here, the result is always an Array, never `new this()`.
impl InterpreterCore {
    pub(super) fn array_from_async_builtin(
        &mut self,
        module: Option<&Ir3Module>,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let items = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
        let mapper = self.builtin_arg(args, 1)?.unwrap_or(Value::Undefined);
        let this_arg = self.builtin_arg(args, 2)?.unwrap_or(Value::Undefined);
        let label = self.join_arg_range_label(args)?;
        let promise = self.create_promise()?;
        // Everything before the first Await runs now, as in AsyncFunctionStart;
        // a throw rejects the promise instead of escaping the call.
        if let Err(error) =
            self.array_from_async_start(module, promise, items, mapper, this_arg, &label)
        {
            let (reason, reason_label) = self.thrown_completion_value(error, &label)?;
            let reason = self.promise_value(&reason)?;
            self.reject_promise(promise, reason, reason_label)?;
        }
        Ok(Value::Promise(promise.0))
    }

    fn array_from_async_start(
        &mut self,
        module: Option<&Ir3Module>,
        promise: crate::promise_model::PromiseHandle,
        items: Value,
        mapper: Value,
        this_arg: Value,
        label: &Label,
    ) -> Result<(), InterpreterError> {
        // IsCallable(mapfn) precedes GetMethod(items, @@asyncIterator).
        if !matches!(mapper, Value::Undefined) && !mapper.is_callable() {
            return Err(InterpreterError::TypeError {
                expected: "function".to_string(),
                got: mapper.type_name().to_string(),
            });
        }
        if matches!(items, Value::Undefined | Value::Null) {
            return Err(InterpreterError::TypeError {
                expected: "object-coercible Array.fromAsync source".to_string(),
                got: items.type_name().to_string(),
            });
        }
        let module = module.ok_or_else(|| InterpreterError::TypeError {
            expected: "module-backed Array.fromAsync".to_string(),
            got: "missing module context".to_string(),
        })?;
        let async_method = self.array_from_async_get_method(
            module,
            &items,
            &RuntimePropertyKey::Symbol(WellKnownSymbol::AsyncIterator.id()),
        )?;
        let target = self.alloc_array_with_prototype(None)?;
        let holder = self.alloc_object_with_properties(&[
            ("__promise", Value::Promise(promise.0)),
            ("__target", Value::Object(target)),
            ("__mapper", mapper),
            ("__this", this_arg),
            ("__k", Value::Int(0)),
        ])?;
        // One pair of reaction callables serves every await of this call.
        for (name, kind) in [
            (
                "__onFulfilled",
                BuiltinFunctionKind::ArrayFromAsyncFulfilled,
            ),
            ("__onRejected", BuiltinFunctionKind::ArrayFromAsyncRejected),
        ] {
            let handler = self
                .promise_reaction_handler_from_value(
                    Value::BuiltinFunction(BuiltinFunction::bound_to(kind, holder)),
                    "Array.fromAsync step",
                )?
                .ok_or_else(|| InterpreterError::InternalError {
                    details: "Array.fromAsync step is not a reaction handler".to_string(),
                })?;
            self.array_from_async_set(holder, name, Value::Int(i64::from(handler.0)))?;
        }
        if let Some(method) = async_method {
            // GetIteratorFromMethod: the iterator must be an object; its
            // `next` is read once.
            let (iterator, _) = self.invoke_inline_method_call_with_argument_label(
                Some(module),
                method,
                items,
                Vec::new(),
                Some(label.clone()),
            )?;
            if !iterator.is_object_like() {
                return Err(InterpreterError::TypeError {
                    expected: "object returned by @@asyncIterator".to_string(),
                    got: iterator.type_name().to_string(),
                });
            }
            let next = self.get_v(
                module,
                &iterator,
                &RuntimePropertyKey::String(JsString::from("next")),
            )?;
            self.array_from_async_set_source(holder, FromAsyncSource::AsyncIterator)?;
            self.array_from_async_set(holder, "__iterator", iterator)?;
            self.array_from_async_set(holder, "__next", next)?;
            return self.array_from_async_request_next(module, holder, label);
        }
        if let Some(iterator) = self.array_from_async_sync_iterator(module, &items, label)? {
            self.array_from_async_set_source(holder, FromAsyncSource::SyncIterator)?;
            self.array_from_async_set(holder, "__iterator", iterator)?;
            return self.array_from_async_request_next(module, holder, label);
        }
        // Array-like: LengthOfArrayLike once, then each element in turn.
        let length = match self.array_from_source_backing(&items)? {
            Some(backing) => {
                self.json_reviver_array_length(Some(module), backing, items.clone())?
            }
            None => 0,
        };
        if length > u64::from(u32::MAX) {
            return Err(InterpreterError::RangeError {
                message: "invalid Array.fromAsync array length".to_string(),
            });
        }
        self.array_from_async_set_source(holder, FromAsyncSource::ArrayLike)?;
        self.array_from_async_set(holder, "__iterator", items)?;
        self.array_from_async_set(holder, "__length", Value::Int(length as i64))?;
        self.array_from_async_next_element(module, holder, label)
    }

    /// GetMethod(V, P): undefined or null is no method; anything else must
    /// be callable.
    fn array_from_async_get_method(
        &mut self,
        module: &Ir3Module,
        value: &Value,
        key: &RuntimePropertyKey,
    ) -> Result<Option<Value>, InterpreterError> {
        match self.get_v(module, value, key)? {
            Value::Undefined | Value::Null => Ok(None),
            method if method.is_callable() => Ok(Some(method)),
            other => Err(InterpreterError::TypeError {
                expected: format!("callable property '{}' or undefined", key.diagnostic()),
                got: other.type_name().to_string(),
            }),
        }
    }

    /// The sync iterator Array.from would iterate `items` with (its
    /// @@iterator, a generator or native iterator, the native collection and
    /// string fallbacks), or `None` for an array-like source.
    fn array_from_async_sync_iterator(
        &mut self,
        module: &Ir3Module,
        items: &Value,
        label: &Label,
    ) -> Result<Option<Value>, InterpreterError> {
        let backing = self.array_from_source_backing(items)?;
        let method = match backing {
            Some(object) => {
                self.lookup_symbol_iterator_method(Some(module), object, items.clone())?
            }
            None => None,
        };
        if let Some(method) = method {
            let (iterator, _) = self.invoke_inline_method_call_with_argument_label(
                Some(module),
                method,
                items.clone(),
                Vec::new(),
                Some(label.clone()),
            )?;
            let init = self.prepare_custom_iterator_result(module, iterator)?;
            return self
                .init_iterator_from_state(items.clone(), init, IterationKind::ForOf)
                .map(Some);
        }
        if matches!(items, Value::Iterator(_) | Value::Generator(_)) {
            return self
                .init_for_of_iterator(Some(module), items.clone())
                .map(Some);
        }
        if let Some(object) = backing
            && self.array_from_has_explicit_iterator(object)?
        {
            return Ok(None);
        }
        if let Value::Object(object) = items
            && let Some(iterator) = self.array_from_collection_iterator(*object)?
        {
            return Ok(Some(iterator));
        }
        if matches!(items, Value::Str(_)) {
            return self
                .init_for_of_iterator(Some(module), items.clone())
                .map(Some);
        }
        Ok(None)
    }

    /// Resume after an await (the bound holder names the call; the settled
    /// value or reason is the only argument). A completion that ends the
    /// call rejects its promise here, so the reaction itself never throws.
    pub(super) fn array_from_async_step(
        &mut self,
        module: &Ir3Module,
        builtin: &BuiltinFunction,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let holder =
            builtin
                .bound_object
                .map(ObjectId)
                .ok_or_else(|| InterpreterError::InternalError {
                    details: "Array.fromAsync step lost its state".to_string(),
                })?;
        let settled = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
        let label = self.join_arg_range_label(args)?;
        self.json_charge_work()?;
        let awaiting = match self.array_from_async_slot(holder, "__await")? {
            Value::Int(code) => usize::try_from(code)
                .ok()
                .and_then(|code| FROM_ASYNC_AWAITS.get(code).copied()),
            _ => None,
        }
        .ok_or_else(|| InterpreterError::InternalError {
            details: "Array.fromAsync step without a pending await".to_string(),
        })?;
        let outcome = if builtin.kind == BuiltinFunctionKind::ArrayFromAsyncFulfilled {
            self.array_from_async_resume(module, holder, awaiting, settled, &label)
        } else {
            self.array_from_async_resume_abrupt(module, holder, awaiting, settled, &label)
        };
        if let Err(error) = outcome {
            let (reason, reason_label) = self.thrown_completion_value(error, &label)?;
            self.array_from_async_reject(holder, reason, reason_label)?;
        }
        Ok(Value::Undefined)
    }

    fn array_from_async_resume(
        &mut self,
        module: &Ir3Module,
        holder: ObjectId,
        awaiting: FromAsyncAwait,
        settled: Value,
        label: &Label,
    ) -> Result<(), InterpreterError> {
        match awaiting {
            FromAsyncAwait::Next => {
                // IteratorComplete / IteratorValue of the awaited result.
                if !settled.is_object_like() {
                    return Err(InterpreterError::TypeError {
                        expected: "iterator result object".to_string(),
                        got: settled.type_name().to_string(),
                    });
                }
                let done = self
                    .get_v(
                        module,
                        &settled,
                        &RuntimePropertyKey::String(JsString::from("done")),
                    )?
                    .is_truthy();
                if done {
                    return self.array_from_async_finish(module, holder, label);
                }
                let value = self.get_v(
                    module,
                    &settled,
                    &RuntimePropertyKey::String(JsString::from("value")),
                )?;
                self.array_from_async_add(module, holder, value, label)
            }
            FromAsyncAwait::SyncValue => {
                // The value wrapper settled the step's promise; the loop's
                // Await of that promise resumes one tick later.
                self.array_from_async_set(holder, "__value", settled)?;
                self.array_from_async_await(
                    module,
                    holder,
                    Value::Undefined,
                    FromAsyncAwait::SyncStep,
                    label,
                )
            }
            FromAsyncAwait::SyncStep => {
                let value = self.array_from_async_slot(holder, "__value")?;
                self.array_from_async_set(holder, "__value", Value::Undefined)?;
                if self.array_from_async_slot(holder, "__done")?.is_truthy() {
                    return self.array_from_async_finish(module, holder, label);
                }
                self.array_from_async_add(module, holder, value, label)
            }
            FromAsyncAwait::Mapped => {
                if let Err(error) = self.array_from_async_store(holder, settled, label) {
                    return self.array_from_async_close(module, holder, error, label);
                }
                self.array_from_async_request_next(module, holder, label)
            }
            FromAsyncAwait::Close => self.array_from_async_reject_closed(holder),
            FromAsyncAwait::Element => {
                let mapper = self.array_from_async_slot(holder, "__mapper")?;
                if matches!(mapper, Value::Undefined) {
                    self.array_from_async_store(holder, settled, label)?;
                    return self.array_from_async_next_element(module, holder, label);
                }
                let this_arg = self.array_from_async_slot(holder, "__this")?;
                let k = self.array_from_async_slot(holder, "__k")?;
                let (mapped, _) = self.invoke_inline_method_call_with_argument_label(
                    Some(module),
                    mapper,
                    this_arg,
                    vec![settled, k],
                    None,
                )?;
                self.array_from_async_await(
                    module,
                    holder,
                    mapped,
                    FromAsyncAwait::MappedElement,
                    label,
                )
            }
            FromAsyncAwait::MappedElement => {
                self.array_from_async_store(holder, settled, label)?;
                self.array_from_async_next_element(module, holder, label)
            }
        }
    }

    fn array_from_async_resume_abrupt(
        &mut self,
        module: &Ir3Module,
        holder: ObjectId,
        awaiting: FromAsyncAwait,
        reason: Value,
        label: &Label,
    ) -> Result<(), InterpreterError> {
        match awaiting {
            FromAsyncAwait::SyncValue => {
                // ES2025 AsyncFromSyncIteratorContinuation: a rejected value
                // closes the sync iterator unless the step was its last; the
                // step's promise rejects, and the loop's Await sees it a
                // tick later.
                if !self.array_from_async_slot(holder, "__done")?.is_truthy() {
                    let iterator = self.array_from_async_slot(holder, "__iterator")?;
                    let closed = self.close_iterator(module, iterator, IteratorCloseReason::Throw);
                    self.array_from_async_discard_close_error(closed)?;
                }
                let reason = self.promise_value(&reason)?;
                let step = self.create_rejected_promise(reason, label.clone())?;
                self.array_from_async_await(
                    module,
                    holder,
                    Value::Promise(step.0),
                    FromAsyncAwait::SyncStep,
                    label,
                )
            }
            // IfAbruptCloseAsyncIterator(mappedValue).
            FromAsyncAwait::Mapped => {
                let error = self.throw_guest_value(reason, label.clone())?;
                self.array_from_async_close(module, holder, error, label)
            }
            FromAsyncAwait::Close => self.array_from_async_reject_closed(holder),
            FromAsyncAwait::Next
            | FromAsyncAwait::SyncStep
            | FromAsyncAwait::Element
            | FromAsyncAwait::MappedElement => {
                self.array_from_async_reject(holder, reason, label.clone())
            }
        }
    }

    /// A value read from the iterator: map it (and await the result) or
    /// store it, then take the next step. A mapper throw closes the iterator.
    fn array_from_async_add(
        &mut self,
        module: &Ir3Module,
        holder: ObjectId,
        value: Value,
        label: &Label,
    ) -> Result<(), InterpreterError> {
        let mapper = self.array_from_async_slot(holder, "__mapper")?;
        if matches!(mapper, Value::Undefined) {
            if let Err(error) = self.array_from_async_store(holder, value, label) {
                return self.array_from_async_close(module, holder, error, label);
            }
            return self.array_from_async_request_next(module, holder, label);
        }
        let this_arg = self.array_from_async_slot(holder, "__this")?;
        let k = self.array_from_async_slot(holder, "__k")?;
        match self.invoke_inline_method_call_with_argument_label(
            Some(module),
            mapper,
            this_arg,
            vec![value, k],
            None,
        ) {
            Ok((mapped, _)) => {
                self.array_from_async_await(module, holder, mapped, FromAsyncAwait::Mapped, label)
            }
            Err(error) => self.array_from_async_close(module, holder, error, label),
        }
    }

    /// The next iterator step: Await(Call(next, iterator)) for an async
    /// iterator; for a sync one, %AsyncFromSyncIteratorPrototype%.next takes
    /// a sync step now and awaits its value.
    fn array_from_async_request_next(
        &mut self,
        module: &Ir3Module,
        holder: ObjectId,
        label: &Label,
    ) -> Result<(), InterpreterError> {
        let iterator = self.array_from_async_slot(holder, "__iterator")?;
        match self.array_from_async_source(holder)? {
            FromAsyncSource::AsyncIterator => {
                let next = self.array_from_async_slot(holder, "__next")?;
                let (result, _) = self.invoke_inline_method_call_with_argument_label(
                    Some(module),
                    next,
                    iterator,
                    Vec::new(),
                    None,
                )?;
                self.array_from_async_await(module, holder, result, FromAsyncAwait::Next, label)
            }
            FromAsyncSource::SyncIterator => {
                let step = self.advance_for_of_iterator(Some(module), iterator)?;
                self.array_from_async_set(holder, "__done", Value::Bool(step.is_none()))?;
                self.array_from_async_await(
                    module,
                    holder,
                    step.unwrap_or(Value::Undefined),
                    FromAsyncAwait::SyncValue,
                    label,
                )
            }
            FromAsyncSource::ArrayLike => Err(InterpreterError::InternalError {
                details: "Array.fromAsync iterator step on an array-like source".to_string(),
            }),
        }
    }

    /// Await array-like element `k`, or finish once `k` reaches the length.
    fn array_from_async_next_element(
        &mut self,
        module: &Ir3Module,
        holder: ObjectId,
        label: &Label,
    ) -> Result<(), InterpreterError> {
        let k = self.array_from_async_index(holder, "__k")?;
        if k >= self.array_from_async_index(holder, "__length")? {
            return self.array_from_async_finish(module, holder, label);
        }
        let items = self.array_from_async_slot(holder, "__iterator")?;
        let element = match self.array_from_source_backing(&items)? {
            Some(backing) => self.iterator_protocol_property(
                Some(module),
                backing,
                &RuntimePropertyKey::String(JsString::from(k.to_string())),
                items,
            )?,
            None => Value::Undefined,
        };
        self.array_from_async_await(module, holder, element, FromAsyncAwait::Element, label)
    }

    /// Await(value): a native promise is awaited as it is; anything else
    /// through a new promise resolved with it (PromiseResolve).
    fn array_from_async_await(
        &mut self,
        module: &Ir3Module,
        holder: ObjectId,
        value: Value,
        awaiting: FromAsyncAwait,
        label: &Label,
    ) -> Result<(), InterpreterError> {
        let awaited = match value {
            Value::Promise(handle) => crate::promise_model::PromiseHandle(handle),
            other => {
                let handle = self.create_promise()?;
                self.resolve_promise_with_value(Some(module), handle, other, label.clone())?;
                handle
            }
        };
        let code = FROM_ASYNC_AWAITS
            .iter()
            .position(|candidate| *candidate == awaiting)
            .expect("every await state is listed");
        self.array_from_async_set(holder, "__await", Value::Int(code as i64))?;
        let on_fulfilled = self.array_from_async_index(holder, "__onFulfilled")?;
        let on_rejected = self.array_from_async_index(holder, "__onRejected")?;
        self.register_promise_then(
            awaited,
            Some(crate::closure_model::ClosureHandle(on_fulfilled as u32)),
            Some(crate::closure_model::ClosureHandle(on_rejected as u32)),
            label.clone(),
        )?;
        Ok(())
    }

    /// CreateDataPropertyOrThrow(A, k, value) with the label it was
    /// computed under, then k + 1.
    fn array_from_async_store(
        &mut self,
        holder: ObjectId,
        value: Value,
        label: &Label,
    ) -> Result<(), InterpreterError> {
        let Value::Object(target) = self.array_from_async_slot(holder, "__target")? else {
            return Err(InterpreterError::InternalError {
                details: "Array.fromAsync lost its result array".to_string(),
            });
        };
        let k = self.array_from_async_index(holder, "__k")?;
        let key = k.to_string();
        self.create_data_property_or_throw(target, key.clone(), value)?;
        self.set_own_runtime_property_label(
            target,
            &RuntimePropertyKey::String(JsString::from(key)),
            label,
        )?;
        self.array_from_async_set(holder, "__k", Value::Int(k as i64 + 1))
    }

    /// Set A.length to k and resolve the call's promise with A.
    fn array_from_async_finish(
        &mut self,
        module: &Ir3Module,
        holder: ObjectId,
        label: &Label,
    ) -> Result<(), InterpreterError> {
        let target = self.array_from_async_slot(holder, "__target")?;
        let Value::Object(target_id) = target else {
            return Err(InterpreterError::InternalError {
                details: "Array.fromAsync lost its result array".to_string(),
            });
        };
        let k = self.array_from_async_slot(holder, "__k")?;
        self.set_object_property(target_id, "length".to_string(), k)?;
        let promise = self.array_from_async_promise(holder)?;
        self.resolve_promise_with_value(Some(module), promise, target, label.clone())
    }

    /// AsyncIteratorClose(iterator, throw completion): call `return()` and
    /// await its result, then reject with the error that closed the
    /// iterator. A missing, throwing or non-callable `return` rejects at
    /// once (the throw completion wins). For a sync iterator the async-from-
    /// sync `return()` runs the sync one now; its result's value is not
    /// awaited, so the rejection comes one tick before the spec's.
    fn array_from_async_close(
        &mut self,
        module: &Ir3Module,
        holder: ObjectId,
        error: InterpreterError,
        label: &Label,
    ) -> Result<(), InterpreterError> {
        let (reason, reason_label) = self.thrown_completion_value(error, label)?;
        let iterator = self.array_from_async_slot(holder, "__iterator")?;
        if self.array_from_async_source(holder)? == FromAsyncSource::SyncIterator {
            let closed = self.close_iterator(module, iterator, IteratorCloseReason::Throw);
            self.array_from_async_discard_close_error(closed)?;
            self.array_from_async_keep_close_reason(holder, reason, &reason_label)?;
            return self.array_from_async_await(
                module,
                holder,
                Value::Undefined,
                FromAsyncAwait::Close,
                label,
            );
        }
        let return_method = self.array_from_async_get_method(
            module,
            &iterator,
            &RuntimePropertyKey::String(JsString::from("return")),
        );
        let inner = match return_method {
            Ok(Some(method)) => self
                .invoke_inline_method_call_with_argument_label(
                    Some(module),
                    method,
                    iterator,
                    Vec::new(),
                    None,
                )
                .map(|(inner, _)| Some(inner)),
            Ok(None) => Ok(None),
            Err(error) => Err(error),
        };
        match inner {
            Ok(Some(inner)) => {
                self.array_from_async_keep_close_reason(holder, reason, &reason_label)?;
                self.array_from_async_await(module, holder, inner, FromAsyncAwait::Close, label)
            }
            Ok(None) => self.array_from_async_reject(holder, reason, reason_label),
            Err(error) => {
                self.array_from_async_discard_close_error(Err(error))?;
                self.array_from_async_reject(holder, reason, reason_label)
            }
        }
    }

    /// The error that closed the iterator, kept with its label until the
    /// close's await resumes.
    fn array_from_async_keep_close_reason(
        &mut self,
        holder: ObjectId,
        reason: Value,
        reason_label: &Label,
    ) -> Result<(), InterpreterError> {
        self.array_from_async_set(holder, "__error", reason)?;
        self.set_own_runtime_property_label(
            holder,
            &RuntimePropertyKey::String(JsString::from("__error")),
            reason_label,
        )
    }

    fn array_from_async_reject_closed(&mut self, holder: ObjectId) -> Result<(), InterpreterError> {
        let reason = self.array_from_async_slot(holder, "__error")?;
        let reason_label = self.runtime_property_label(
            holder,
            &RuntimePropertyKey::String(JsString::from("__error")),
        );
        self.array_from_async_reject(holder, reason, reason_label)
    }

    /// A throw completion wins over a failing `return()`: drop a guest
    /// error the close raised; a host refusal (budget, containment) still
    /// propagates.
    fn array_from_async_discard_close_error(
        &mut self,
        closed: Result<(), InterpreterError>,
    ) -> Result<(), InterpreterError> {
        match closed {
            Ok(()) => Ok(()),
            Err(InterpreterError::UncaughtException { .. }) => {
                self.take_pending_exception_slot();
                Ok(())
            }
            Err(error) if Self::js_catchable_error_name(&error).is_some() => Ok(()),
            Err(error) => Err(error),
        }
    }

    /// The guest value of a throw completion: the thrown value of a guest
    /// `throw`, or the error object of a catchable native error. A host
    /// refusal (budget, cancellation, containment) is not a guest completion
    /// and keeps propagating.
    pub(super) fn thrown_completion_value(
        &mut self,
        error: InterpreterError,
        label: &Label,
    ) -> Result<(Value, Label), InterpreterError> {
        match error {
            InterpreterError::UncaughtException { value } => {
                Ok(match self.take_pending_exception_slot() {
                    Some((thrown, thrown_label)) => (thrown, thrown_label.join(label)),
                    None => (Value::str(value), label.clone()),
                })
            }
            error if Self::js_catchable_error_name(&error).is_some() => {
                let thrown = self.native_error_to_thrown_value(&error)?;
                Ok((thrown, label.clone()))
            }
            error => Err(error),
        }
    }

    fn array_from_async_reject(
        &mut self,
        holder: ObjectId,
        reason: Value,
        label: Label,
    ) -> Result<(), InterpreterError> {
        let promise = self.array_from_async_promise(holder)?;
        if self.promise_is_settled(promise) {
            return Ok(());
        }
        let reason = self.promise_value(&reason)?;
        self.reject_promise(promise, reason, label)
    }

    fn array_from_async_promise(
        &self,
        holder: ObjectId,
    ) -> Result<crate::promise_model::PromiseHandle, InterpreterError> {
        match self.array_from_async_slot(holder, "__promise")? {
            Value::Promise(handle) => Ok(crate::promise_model::PromiseHandle(handle)),
            _ => Err(InterpreterError::InternalError {
                details: "Array.fromAsync lost its promise".to_string(),
            }),
        }
    }

    fn array_from_async_source(
        &self,
        holder: ObjectId,
    ) -> Result<FromAsyncSource, InterpreterError> {
        let code = self.array_from_async_index(holder, "__source")?;
        FROM_ASYNC_SOURCES
            .get(code as usize)
            .copied()
            .ok_or_else(|| InterpreterError::InternalError {
                details: format!("Array.fromAsync source code {code}"),
            })
    }

    fn array_from_async_set_source(
        &mut self,
        holder: ObjectId,
        source: FromAsyncSource,
    ) -> Result<(), InterpreterError> {
        let code = FROM_ASYNC_SOURCES
            .iter()
            .position(|candidate| *candidate == source)
            .expect("every source is listed");
        self.array_from_async_set(holder, "__source", Value::Int(code as i64))
    }

    fn array_from_async_slot(
        &self,
        holder: ObjectId,
        name: &str,
    ) -> Result<Value, InterpreterError> {
        self.heap
            .get(holder.0 as usize)
            .and_then(|state| state.properties.get(name).cloned())
            .ok_or_else(|| InterpreterError::InternalError {
                details: format!("Array.fromAsync state lost its {name}"),
            })
    }

    fn array_from_async_index(
        &self,
        holder: ObjectId,
        name: &str,
    ) -> Result<u64, InterpreterError> {
        match self.array_from_async_slot(holder, name)? {
            Value::Int(value) if value >= 0 => Ok(value as u64),
            other => Err(InterpreterError::InternalError {
                details: format!("Array.fromAsync {name} is {}", other.type_name()),
            }),
        }
    }

    fn array_from_async_set(
        &mut self,
        holder: ObjectId,
        name: &str,
        value: Value,
    ) -> Result<(), InterpreterError> {
        self.set_object_property(holder, name.to_string(), value)
    }
}
