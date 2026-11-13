use super::*;

/// A synchronous publication carries one value through a finite export graph.
/// Keep the strongest label observed for each export, and revisit a completed
/// node only when a later path raises its provenance or promotes an own export.
#[derive(Default)]
struct ModuleExportCascade {
    pending: BTreeSet<(String, JsString)>,
    states: BTreeMap<(String, JsString), (Label, ExportPublication)>,
    temporary_bytes: u64,
}

impl InterpreterCore {
    #[inline(never)]
    pub(super) fn dispatch_builtin_function_inner(
        &mut self,
        module: &Ir3Module,
        builtin: &BuiltinFunction,
        args: RegRange,
        mut receiver: Option<Value>,
        receiver_register: Option<u32>,
    ) -> Result<Value, InterpreterError> {
        // ES2020 thisXValue: a Number/String/Boolean/BigInt/Symbol prototype
        // builtin called on a wrapper object works on its primitive.
        if let Some(Value::Object(object_id)) = receiver {
            receiver = Some(self.this_primitive_receiver(builtin, object_id));
        }
        // ES2020 22.2.3 ValidateTypedArray(this): `%TypedArray%.prototype.some`
        // (and its siblings sharing an Array.prototype algorithm) on anything
        // but a typed array is a TypeError; it ran as the Array method.
        if &*builtin.module_specifier == TYPED_ARRAY_PROTOTYPE_SPECIFIER
            && !matches!(
                receiver,
                Some(Value::Object(object_id))
                    if self
                        .heap
                        .get(object_id.0 as usize)
                        .is_some_and(|object| object.typed_array.is_some())
            )
        {
            return Err(InterpreterError::TypeError {
                expected: format!(
                    "typed array receiver for %TypedArray%.prototype.{}",
                    builtin.spec_name()
                ),
                got: receiver
                    .as_ref()
                    .map_or("undefined", Value::type_name)
                    .to_string(),
            });
        }
        if &*builtin.module_specifier == TYPED_ARRAY_PROTOTYPE_SPECIFIER
            && let Some(Value::Object(object_id)) = receiver
            && let Some(view) = self
                .heap
                .get(object_id.0 as usize)
                .and_then(|object| object.typed_array.as_deref())
        {
            Self::reject_out_of_bounds_typed_array(view, builtin.spec_name())?;
        }
        // ES2020 21.1.3: a String.prototype method (but toString/valueOf,
        // which require a String) starts with ToString(this), so another
        // object `this` is ToPrimitive'd with the string hint and its
        // toString runs; `String.prototype.toUpperCase.call({ toString() {
        // return 'ab' } })` read "[object Object]".
        // The pattern methods (replace, replaceAll, split, match, matchAll,
        // search) first look up the pattern's own @@replace/@@split/...
        // method and convert `this` only afterwards (string_pattern_this,
        // bd-9vouw.275).
        if let Some(object) = receiver.as_ref().filter(|value| value.is_object_like())
            && builtin.spec_owner() == Some("String.prototype")
            && !matches!(
                builtin.kind,
                BuiltinFunctionKind::StringToString
                    | BuiltinFunctionKind::StringValueOf
                    | BuiltinFunctionKind::StringReplace
                    | BuiltinFunctionKind::StringReplaceAll
                    | BuiltinFunctionKind::StringSplit
                    | BuiltinFunctionKind::StringMatch
                    | BuiltinFunctionKind::StringMatchAll
                    | BuiltinFunctionKind::StringSearch
            )
        {
            self.gc_nested_request = None;
            let primitive = self.coerce_runtime_primitive(Some(module), object.clone(), true)?;
            if matches!(primitive, Value::Symbol(_)) {
                return Err(InterpreterError::TypeError {
                    expected: format!("string-convertible this for {}", builtin.display_name()),
                    got: "symbol".to_string(),
                });
            }
            receiver = Some(primitive);
        }
        // A Symbol `this` has no ToString (ES2020 7.1.12) and no
        // [[StringData]], so every String.prototype method throws a TypeError
        // for it; `String.prototype.slice.call(Symbol())` threw nothing
        // (bd-9vouw.239).
        if matches!(receiver, Some(Value::Symbol(_)))
            && builtin.spec_owner() == Some("String.prototype")
        {
            return Err(InterpreterError::TypeError {
                expected: format!("string-convertible this for {}", builtin.display_name()),
                got: "symbol".to_string(),
            });
        }
        // Array.prototype methods on a Proxy, an array-like that is not an
        // Array or a primitive `this` run over [[Get]]/[[Set]]/[[HasProperty]]
        // /[[Delete]] (getters and traps see every step), and so does a concat
        // that spreads a Proxy or an @@isConcatSpreadable object.
        if Self::has_generic_array_path(builtin.kind)
            && let Some(object_id) = self.generic_array_receiver(
                module,
                builtin.kind,
                Self::is_typed_array_prototype_builtin(builtin),
                receiver.as_ref(),
                args,
            )?
        {
            // A function `this` stays the method's observable O (bd-9vouw.285).
            let function = receiver
                .as_ref()
                .filter(|value| value.is_callable())
                .map(|function| (object_id, function.clone()));
            let outer = std::mem::replace(&mut self.generic_function_receiver, function);
            let result = self.array_method_generic(module, builtin.kind, object_id, args);
            self.generic_function_receiver = outer;
            if let Some(result) = result? {
                return Ok(result);
            }
        }
        match builtin.kind {
            BuiltinFunctionKind::FunctionPrototype => Ok(Value::Undefined),
            BuiltinFunctionKind::NativeTimerPromisesGetter => {
                let holder = builtin
                    .bound_object
                    .map(ObjectId)
                    .filter(|holder| {
                        self.builtin_prototypes
                            .get("\0franken-engine/native-timers/promises")
                            == Some(holder)
                    })
                    .ok_or_else(|| InterpreterError::InternalError {
                        details: "native timer promises getter has no authenticated export carrier"
                            .to_string(),
                    })?;
                self.iterator_protocol_property(
                    Some(module),
                    holder,
                    &RuntimePropertyKey::String(JsString::from("exports")),
                    Value::Object(holder),
                )
            }
            BuiltinFunctionKind::AsyncGeneratorNext
            | BuiltinFunctionKind::AsyncGeneratorReturn
            | BuiltinFunctionKind::AsyncGeneratorThrow => self.dispatch_async_generator_resume(
                module, builtin.kind, args, receiver, receiver_register,
            ),
            BuiltinFunctionKind::GeneratorNext
            | BuiltinFunctionKind::GeneratorReturn
            | BuiltinFunctionKind::GeneratorThrow => self.dispatch_generator_resume(
                module, builtin.kind, args, receiver, receiver_register,
            ),
            BuiltinFunctionKind::FunctionPrototypeCall
            | BuiltinFunctionKind::FunctionPrototypeApply => self.forward_function_invocation(
                Some(module),
                receiver.unwrap_or(Value::Undefined),
                receiver_register,
                args,
                builtin.kind == BuiltinFunctionKind::FunctionPrototypeApply,
            ),
            BuiltinFunctionKind::FunctionPrototypeBind => self.function_prototype_bind(
                module,
                receiver.unwrap_or(Value::Undefined),
                receiver_register,
                args,
            ),
            BuiltinFunctionKind::BoundFunction => self.invoke_bound_function(module, builtin, args),
            BuiltinFunctionKind::CallableProxy => {
                self.call_callable_proxy(module, builtin, args, receiver)
            }
            BuiltinFunctionKind::UrlSearchParamsKeys
            | BuiltinFunctionKind::UrlSearchParamsValues
            | BuiltinFunctionKind::UrlSearchParamsEntries => {
                self.url_search_params_iterator(builtin.kind, receiver)
            }
            BuiltinFunctionKind::UrlSearchParamsForEach => {
                self.url_search_params_for_each(module, receiver, args)
            }
            BuiltinFunctionKind::MapForEach | BuiltinFunctionKind::SetForEach => self
                .collection_for_each(
                    module,
                    builtin.kind == BuiltinFunctionKind::MapForEach,
                    receiver.unwrap_or(Value::Undefined),
                    args,
                ),
            BuiltinFunctionKind::MapKeys
            | BuiltinFunctionKind::MapValues
            | BuiltinFunctionKind::MapEntries
            | BuiltinFunctionKind::SetValues
            | BuiltinFunctionKind::SetEntries => {
                self.collection_iterator(builtin.kind, receiver.unwrap_or(Value::Undefined))
            }
            BuiltinFunctionKind::StringPrototypeConcat => {
                // ES2020 21.1.3.4: RequireObjectCoercible(this), then append
                // ToString of every argument.
                let receiver = receiver.unwrap_or(Value::Undefined);
                if matches!(receiver, Value::Undefined | Value::Null) {
                    return Err(InterpreterError::TypeError {
                        expected: "object-coercible String.prototype.concat receiver"
                            .to_string(),
                        got: receiver.type_name().to_string(),
                    });
                }
                let mut text = self.value_to_string(&receiver);
                for index in 0..args.count {
                    let argument = self.builtin_arg(args, index)?.unwrap_or(Value::Undefined);
                    // An object argument's toString runs (ToString).
                    let argument = if argument.is_object_like() {
                        self.gc_nested_request = None;
                        self.coerce_runtime_primitive(Some(module), argument, true)?
                    } else {
                        argument
                    };
                    if matches!(argument, Value::Symbol(_)) {
                        return Err(InterpreterError::TypeError {
                            expected: "string-convertible String.prototype.concat argument"
                                .to_string(),
                            got: "symbol".to_string(),
                        });
                    }
                    text.push_str(&self.value_to_string(&argument));
                    self.check_string_limit(text.len())?;
                }
                Ok(Value::str(text))
            }
            BuiltinFunctionKind::DateUtc => {
                // Date.UTC(year[, month[, date[, hours[, minutes[, seconds[, ms]]]]]])
                // (ES2020 20.4.3.4); a two-digit year maps to 19xx. Each
                // argument is ToNumber'd in order, an object's valueOf
                // included; an object counted as NaN (bd-9vouw.368).
                let mut parts = Vec::with_capacity(7);
                for index in 0..args.count.min(7) {
                    let value = self
                        .builtin_number_arg(module, args, index)?
                        .unwrap_or(Value::Undefined);
                    parts.push(Self::coerce_to_float(&value).unwrap_or(f64::NAN));
                }
                let part = |index: usize, fallback: f64| parts.get(index).copied().unwrap_or(fallback);
                let mut year = part(0, f64::NAN);
                if year.is_finite() && (0.0..=99.0).contains(&year.trunc()) {
                    year = 1900.0 + year.trunc();
                }
                let time = date_math::time_clip(date_math::make_date(
                    date_math::make_day(year, part(1, 0.0), part(2, 1.0)),
                    date_math::make_time(part(3, 0.0), part(4, 0.0), part(5, 0.0), part(6, 0.0)),
                ));
                Ok(js_number_to_value(time))
            }
            BuiltinFunctionKind::DateParse => {
                let text = self.builtin_arg_text(Some(module), args, 0)?;
                Ok(js_number_to_value(Self::parse_date_string(&text)))
            }
            BuiltinFunctionKind::RegExpPrototypeExec => {
                let receiver = receiver.unwrap_or(Value::Undefined);
                // ES2020 21.2.5.2.1: after the receiver check, ToString(string)
                // runs an object argument's @@toPrimitive, toString or valueOf
                // (bd-9vouw.213: is-regex tells a RegExp by an exec that must
                // throw from its argument's toString).
                // ToString keeping the string itself (shared, lone surrogates
                // included): the UTF-8 text copied the whole subject on every
                // exec of a loop (bd-9vouw.475).
                let input = if self.regexp_source_flags_from_value(&receiver).is_some() {
                    Value::Str(self.builtin_arg_js_text(Some(module), args, 0)?)
                } else {
                    Value::Undefined
                };
                let last_index = self.regexp_coerced_last_index(module, &receiver)?;
                self.regexp_prototype_exec_from(receiver, &input, last_index)
            }
            BuiltinFunctionKind::RegExpSymbolMethod => self.regexp_symbol_method_call(
                module,
                builtin,
                receiver.unwrap_or(Value::Undefined),
                args,
            ),
            BuiltinFunctionKind::TypedArrayStaticMethod => self.typed_array_static_call(
                module,
                builtin,
                receiver.unwrap_or(Value::Undefined),
                args,
            ),
            BuiltinFunctionKind::RegExpPrototypeCompile => {
                self.regexp_prototype_compile(module, receiver.unwrap_or(Value::Undefined), args)
            }
            BuiltinFunctionKind::RegExpPrototypeToString => {
                // ES2020 21.2.5.14: generic over any object, through
                // ToString(Get(R, "source")) and ToString(Get(R, "flags")),
                // so an own `source` or a flag getter override shows
                // (bd-9vouw.150 phase 2).
                let receiver = receiver.unwrap_or(Value::Undefined);
                if !receiver.is_object_like() {
                    return Err(InterpreterError::TypeError {
                        expected: "object receiver for RegExp.prototype.toString".to_string(),
                        got: receiver.type_name().to_string(),
                    });
                }
                let mut parts = Vec::with_capacity(2);
                for key in ["source", "flags"] {
                    let value = self.get_v(
                        module,
                        &receiver,
                        &RuntimePropertyKey::String(JsString::from(key)),
                    )?;
                    let primitive = self.object_to_string_primitive(Some(module), value)?;
                    if matches!(primitive, Value::Symbol(_)) {
                        return Err(Self::symbol_to_string_error());
                    }
                    parts.push(self.value_to_string(&primitive));
                }
                Ok(Value::str(format!("/{}/{}", parts[0], parts[1])))
            }
            BuiltinFunctionKind::WeakMapMethod => {
                let method = builtin
                    .module_specifier
                    .0
                    .as_deref()
                    .unwrap_or_default()
                    .to_string();
                self.weakmap_method(module, &method, receiver.unwrap_or(Value::Undefined), args)
            }
            BuiltinFunctionKind::WeakSetMethod => {
                let method = builtin
                    .module_specifier
                    .0
                    .as_deref()
                    .unwrap_or_default()
                    .to_string();
                self.weakset_method(&method, receiver.unwrap_or(Value::Undefined), args)
            }
            BuiltinFunctionKind::TextCodecMethod => {
                let method = builtin
                    .module_specifier
                    .0
                    .as_deref()
                    .unwrap_or_default()
                    .to_string();
                self.text_codec_method(&method, receiver.unwrap_or(Value::Undefined), args)
            }
            BuiltinFunctionKind::TimersPromisesIntervalNext
            | BuiltinFunctionKind::TimersPromisesIntervalReturn => self
                .timers_promises_interval_step(
                    receiver,
                    receiver_register,
                    args,
                    builtin.kind == BuiltinFunctionKind::TimersPromisesIntervalReturn,
                ),
            BuiltinFunctionKind::FunctionPrototypeToString => match receiver {
                Some(function) if function.is_callable() => {
                    Ok(Value::str(self.function_native_source_text(Some(module), &function)))
                }
                other => Err(InterpreterError::TypeError {
                    expected: "Function.prototype.toString receiver that is a function"
                        .to_string(),
                    got: other.as_ref().map_or("undefined", Value::type_name).to_string(),
                }),
            },
            BuiltinFunctionKind::DatePrototypeMethod => {
                let method = builtin
                    .module_specifier
                    .0
                    .as_deref()
                    .unwrap_or_default()
                    .to_string();
                let receiver = receiver.unwrap_or(Value::Undefined);
                // toLocale*String with options is a DateTimeFormat (intl.rs).
                let caller = match method.as_str() {
                    "toLocaleDateString" => Some(intl::DateOptionsFor::DateString),
                    "toLocaleTimeString" => Some(intl::DateOptionsFor::TimeString),
                    "toLocaleString" => Some(intl::DateOptionsFor::String),
                    _ => None,
                };
                let options = self.builtin_arg(args, 1)?.unwrap_or(Value::Undefined);
                let time = match &receiver {
                    Value::Object(id) => self
                        .heap
                        .get(id.0 as usize)
                        .and_then(HeapObject::date_time),
                    _ => None,
                };
                if let (Some(caller), Some(time)) = (caller, time)
                    && !matches!(options, Value::Undefined)
                {
                    if !time.is_finite() {
                        return Ok(Value::str("Invalid Date"));
                    }
                    let locales = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
                    return self.date_to_locale_with_options(
                        module, caller, time, &locales, &options,
                    );
                }
                self.date_prototype_method(Some(module), &method, receiver, args)
            }
            BuiltinFunctionKind::NumberToPrecision | BuiltinFunctionKind::NumberToExponential => {
                let exponential = builtin.kind == BuiltinFunctionKind::NumberToExponential;
                let number = self.this_number_value(&receiver.unwrap_or(Value::Undefined))?;
                let argument = self.builtin_number_arg(module, args, 0)?.unwrap_or(Value::Undefined);
                // toPrecision(undefined) is ToString(x); toExponential(undefined)
                // uses as many digits as needed to represent x uniquely.
                let digits = (!matches!(argument, Value::Undefined))
                    .then(|| Self::value_as_integer(&argument));
                if !number.is_finite() || (digits.is_none() && !exponential) {
                    return Ok(Value::str(self.value_to_string(&js_number_to_value(number))));
                }
                let (low, high) = if exponential { (0, 100) } else { (1, 100) };
                if let Some(digits) = digits
                    && !(low..=high).contains(&digits)
                {
                    return Err(InterpreterError::RangeError {
                        message: format!(
                            "{}() argument must be between {low} and {high}",
                            if exponential { "toExponential" } else { "toPrecision" }
                        ),
                    });
                }
                let significant = digits.map(|digits| {
                    usize::try_from(digits).unwrap_or(0) + usize::from(exponential)
                });
                Ok(Value::str(Self::format_number_significant(
                    number,
                    significant,
                    exponential,
                )))
            }
            BuiltinFunctionKind::ModuleCreateRequire => {
                check_hostcall_capability_gate(self, "module_load", self.ip as u32)?;
                let args_label = self.join_arg_range_label(args)?;
                let result = self.create_require(module, args)?;
                self.replace_pending_hostcall_result_label(Some(args_label))?;
                Ok(result)
            }
            BuiltinFunctionKind::Require => {
                check_hostcall_capability_gate(self, "module_load", self.ip as u32)?;
                let args_label = self.join_arg_range_label(args)?;
                let previous_module_specifier = self.current_module_specifier.clone();
                if !builtin.module_specifier.is_empty() {
                    self.current_module_specifier = Some(builtin.module_specifier.to_string());
                }
                // First-class `require` values (`const req = require`) and
                // `module.require(...)` arrive as ordinary Call/CallMethod
                // instructions, so they do not pass through the IR3 HostCall
                // arm. Apply that same gate here before any module-state or
                // resolver work, and emit the canonical module-load identity.
                self.emit_witness(
                    WitnessEventKind::HostcallDispatched,
                    Some("cap:module_load"),
                );
                let mut native_effect = false;
                let result = self.dispatch_require_hostcall_with_native_effect_provenance(
                    args,
                    Some(module),
                    &mut native_effect,
                );
                self.current_module_specifier = previous_module_specifier;
                if let Ok(value) = &result {
                    // An authenticated engine-local effect namespace reads no
                    // host module bytes. Its initial contents are Public, but
                    // a cached load must retain all guest-written state and
                    // opaque accessors. Ordinary source loads keep their
                    // existing Internal floor, including source re-exports.
                    let result_label = if native_effect {
                        let Value::Object(object) = value else {
                            return Err(InterpreterError::InternalError {
                                details: "native effect provider returned a non-object".to_string(),
                            });
                        };
                        args_label.join(&self.native_builtin_state_label_with_floor(
                            module,
                            *object,
                            Label::Public,
                        )?)
                    } else {
                        hostcall_result_contract("module_load")
                            .result_label(&args_label, None)
                            .join(
                                self.pending_hostcall_result_label
                                    .as_ref()
                                    .unwrap_or(&Label::Public),
                            )
                    };
                    self.replace_pending_hostcall_result_label(Some(result_label))?;
                }
                result
            }
            BuiltinFunctionKind::RequireResolve | BuiltinFunctionKind::ImportMetaResolve => {
                check_hostcall_capability_gate(self, "module_load", self.ip as u32)?;
                let args_label = self.join_arg_range_label(args)?;
                let previous_module_specifier = self.current_module_specifier.clone();
                if builtin.kind == BuiltinFunctionKind::ImportMetaResolve {
                    self.current_module_specifier = (!builtin.module_specifier.is_empty())
                        .then(|| builtin.module_specifier.to_string());
                } else if !builtin.module_specifier.is_empty() {
                    self.current_module_specifier = Some(builtin.module_specifier.to_string());
                }
                let result = if builtin.kind == BuiltinFunctionKind::ImportMetaResolve {
                    self.import_meta_resolve(Some(module), args)
                } else {
                    self.require_resolve(args)
                };
                self.current_module_specifier = previous_module_specifier;
                if result.is_ok() {
                    let result_label = hostcall_result_contract("module_load")
                        .result_label(&args_label, None)
                        .join(self.pending_hostcall_result_label.as_ref().unwrap_or(&Label::Public));
                    self.replace_pending_hostcall_result_label(Some(result_label))?;
                }
                result
            }
            BuiltinFunctionKind::FunctionConstructor => {
                self.construct_generated_function(module, args)
            }
            BuiltinFunctionKind::GeneratedFunction => {
                let (value, label) = self.call_generated_function_artifact(
                    builtin,
                    args,
                    receiver,
                    receiver_register,
                )?;
                self.replace_pending_hostcall_result_label(Some(label))?;
                Ok(value)
            }
            BuiltinFunctionKind::IteratorNext => {
                // %ArrayIteratorPrototype%, %MapIteratorPrototype% and
                // %SetIteratorPrototype% next (ES2020 22.1.5.2.1, 23.1.5.2.1,
                // 23.2.5.2.1 steps 1-3): `this` must be an iterator of the
                // method's kind. A bound `it.next` used its own iterator
                // whatever the receiver, so `next.call({})` and a Map
                // iterator's next on a Set iterator advanced it; now they are
                // TypeErrors and an iterator receiver is the one advanced.
                // So is a detached `next()` (no receiver) and
                // `next.call(undefined)`, which stepped the iterator the
                // method was read from (bd-9vouw.310); the iteration
                // statements advance iterators directly, not through here.
                let incompatible = |name: &str| {
                    let tag = match name {
                        MAP_ITERATOR_PROTOTYPE => "Map Iterator",
                        SET_ITERATOR_PROTOTYPE => "Set Iterator",
                        _ => "Array Iterator",
                    };
                    format!("Method {tag}.prototype.next called on incompatible receiver")
                };
                let iterator_handle = match (&receiver, builtin.iterator_handle) {
                    (Some(Value::Iterator(handle)), Some(bound)) => {
                        let method_kind = self.iterator_intrinsic_prototype_name(bound);
                        if self.iterator_intrinsic_prototype_name(*handle) != method_kind {
                            return Err(self.throw_js_error("TypeError", incompatible(method_kind)));
                        }
                        *handle
                    }
                    (Some(Value::Iterator(handle)), None) => *handle,
                    (_, Some(bound)) => {
                        let method_kind = self.iterator_intrinsic_prototype_name(bound);
                        return Err(self.throw_js_error("TypeError", incompatible(method_kind)));
                    }
                    (_, None) => {
                        return Err(self.throw_js_error(
                            "TypeError",
                            incompatible(ARRAY_ITERATOR_PROTOTYPE),
                        ));
                    }
                };
                let next_value =
                    self.advance_for_of_iterator(Some(module), Value::Iterator(iterator_handle))?;
                self.alloc_iterator_result_object(next_value)
            }
            BuiltinFunctionKind::IteratorSelf => {
                let iterator_handle =
                    builtin
                        .iterator_handle
                        .ok_or_else(|| InterpreterError::TypeError {
                            expected: "iterator-bound builtin".to_string(),
                            got: "missing iterator handle".to_string(),
                        })?;
                Ok(Value::Iterator(iterator_handle))
            }
            // The String.prototype arms below delegate to the shared
            // `string_*_impl` fns (E4.T3, `bd-fqlfw.4.3`): semantics live once,
            // served by both this legacy seam and the intrinsic-table path
            // (`dispatch_string_intrinsic`). The receiver coercion here mirrors
            // the table rows' declared `ThisCoercion::ToString`.
            // Receiver coercion below keeps exact UTF-16 code units
            // (`require_object_coercible_to_js_string`), so a lone-surrogate
            // receiver reaches charAt/charCodeAt/at without collapsing to
            // the lossy projection (bd-neika). The intrinsic-table path
            // applies the identical coercion; the parity tests pin the two
            // seams against each other.
            BuiltinFunctionKind::StringCharAt => {
                let receiver = receiver.unwrap_or(Value::Undefined);
                let value = Self::require_object_coercible_to_js_string(&receiver)?;
                self.string_char_at_impl(module, &value, args)
            }
            BuiltinFunctionKind::StringCharCodeAt => {
                let receiver = receiver.unwrap_or(Value::Undefined);
                let value = Self::require_object_coercible_to_js_string(&receiver)?;
                self.string_char_code_at_impl(module, &value, args)
            }
            BuiltinFunctionKind::StringAt => {
                let receiver = receiver.unwrap_or(Value::Undefined);
                let value = Self::require_object_coercible_to_js_string(&receiver)?;
                self.string_at_impl(module, &value, args)
            }
            BuiltinFunctionKind::StringIsWellFormed => {
                let receiver = receiver.unwrap_or(Value::Undefined);
                let value = Self::require_object_coercible_to_js_string(&receiver)?;
                Ok(Value::Bool(value.is_well_formed()))
            }
            BuiltinFunctionKind::StringToWellFormed => {
                let receiver = receiver.unwrap_or(Value::Undefined);
                let value = Self::require_object_coercible_to_js_string(&receiver)?;
                Ok(Value::str(value.as_utf8_projection()))
            }
            BuiltinFunctionKind::StringToString | BuiltinFunctionKind::StringValueOf => {
                let receiver = receiver.unwrap_or(Value::Undefined);
                match receiver {
                    Value::Str(value) => Ok(Value::Str(value)),
                    other => Err(InterpreterError::TypeError {
                        expected: "String receiver".to_string(),
                        got: other.type_name().to_string(),
                    }),
                }
            }
            BuiltinFunctionKind::StringToUpperCase => {
                let receiver = receiver.unwrap_or(Value::Undefined);
                let value = Self::require_object_coercible_to_js_string(&receiver)?;
                self.string_to_upper_case_impl(&value, args)
            }
            BuiltinFunctionKind::StringToLowerCase => {
                let receiver = receiver.unwrap_or(Value::Undefined);
                let value = Self::require_object_coercible_to_js_string(&receiver)?;
                self.string_to_lower_case_impl(&value, args)
            }
            BuiltinFunctionKind::StringTrim => {
                let receiver = receiver.unwrap_or(Value::Undefined);
                let value = Self::require_object_coercible_to_js_string(&receiver)?;
                self.string_trim_impl(&value, args)
            }
            BuiltinFunctionKind::StringTrimStart => {
                let receiver = receiver.unwrap_or(Value::Undefined);
                let value = Self::require_object_coercible_to_js_string(&receiver)?;
                self.string_trim_start_impl(&value, args)
            }
            BuiltinFunctionKind::StringTrimEnd => {
                let receiver = receiver.unwrap_or(Value::Undefined);
                let value = Self::require_object_coercible_to_js_string(&receiver)?;
                self.string_trim_end_impl(&value, args)
            }
            BuiltinFunctionKind::StringReplaceAll => {
                let receiver = receiver.unwrap_or(Value::Undefined);
                self.string_global_regexp_observable_flags_check(
                    module,
                    &receiver,
                    args,
                    "replaceAll",
                )?;
                if let Some(result) = self.string_pattern_protocol_call(
                    module,
                    &receiver,
                    args,
                    WellKnownSymbol::Replace,
                )? {
                    return Ok(result);
                }
                let value = self.string_pattern_this(module, &receiver)?;
                // ES2021 22.1.3.19 steps 2.c-4: a RegExp whose @@replace is
                // undefined or null is searched for as its ToString text
                // ("/./g"), not matched as a pattern.
                if let Some(Value::Object(pattern_id)) = self.builtin_arg(args, 0)?
                    && self
                        .regexp_source_flags_from_value(&Value::Object(pattern_id))
                        .is_some()
                    && !self.regexp_uses_builtin_symbol_method(
                        pattern_id,
                        &RuntimePropertyKey::Symbol(WellKnownSymbol::Replace.id()),
                    )
                {
                    let search = self.scoped_conversion(|this| {
                        this.conversion_to_string(Some(module), Value::Object(pattern_id))
                    })?;
                    let (_, replacement) = self.string_replace_args(Some(module), args)?;
                    let label = self.join_arg_range_label(args)?;
                    return self.string_replace_js(
                        Some(module),
                        &value,
                        &Value::Str(search),
                        &replacement,
                        true,
                        label,
                    );
                }
                self.string_replace_all_method(module, &value, args)
            }
            BuiltinFunctionKind::StringCodePointAt => {
                let receiver = receiver.unwrap_or(Value::Undefined);
                let value = Self::require_object_coercible_to_js_string(&receiver)?;
                self.string_code_point_at_impl(module, &value, args)
            }
            BuiltinFunctionKind::StringLocaleCompare => {
                let receiver = receiver.unwrap_or(Value::Undefined);
                let value = Self::require_object_coercible_to_js_string(&receiver)?;
                self.string_locale_compare_impl(&value, args)
            }
            BuiltinFunctionKind::StringNormalize => {
                let receiver = receiver.unwrap_or(Value::Undefined);
                let value = Self::require_object_coercible_to_js_string(&receiver)?;
                self.string_normalize_impl(module, &value, args)
            }
            BuiltinFunctionKind::StringIncludes => {
                let receiver = receiver.unwrap_or(Value::Undefined);
                let value = Self::require_object_coercible_to_js_string(&receiver)?;
                self.string_search_rejects_regexp(module, args, "includes")?;
                self.string_includes_impl(module, &value, args)
            }
            BuiltinFunctionKind::StringStartsWith => {
                let receiver = receiver.unwrap_or(Value::Undefined);
                let value = Self::require_object_coercible_to_js_string(&receiver)?;
                self.string_search_rejects_regexp(module, args, "startsWith")?;
                self.string_starts_with_impl(module, &value, args)
            }
            BuiltinFunctionKind::StringEndsWith => {
                let receiver = receiver.unwrap_or(Value::Undefined);
                let value = Self::require_object_coercible_to_js_string(&receiver)?;
                self.string_search_rejects_regexp(module, args, "endsWith")?;
                self.string_ends_with_impl(module, &value, args)
            }
            BuiltinFunctionKind::StringSplit => {
                let receiver = receiver.unwrap_or(Value::Undefined);
                if let Some(result) = self.string_pattern_protocol_call(
                    module,
                    &receiver,
                    args,
                    WellKnownSymbol::Split,
                )? {
                    return Ok(result);
                }
                let value = self.string_pattern_this(module, &receiver)?;
                self.string_split_impl(module, &value, args)
            }
            BuiltinFunctionKind::StringIndexOf => {
                let receiver = receiver.unwrap_or(Value::Undefined);
                let value = Self::require_object_coercible_to_js_string(&receiver)?;
                self.string_index_of_impl(module, &value, args)
            }
            BuiltinFunctionKind::StringLastIndexOf => {
                let receiver = receiver.unwrap_or(Value::Undefined);
                let value = Self::require_object_coercible_to_js_string(&receiver)?;
                self.string_last_index_of_impl(module, &value, args)
            }
            BuiltinFunctionKind::StringSlice => {
                let receiver = receiver.unwrap_or(Value::Undefined);
                let value = Self::require_object_coercible_to_js_string(&receiver)?;
                self.string_slice_impl(module, &value, args)
            }
            BuiltinFunctionKind::StringSubstring => {
                let receiver = receiver.unwrap_or(Value::Undefined);
                let value = Self::require_object_coercible_to_js_string(&receiver)?;
                self.string_substring_impl(module, &value, args)
            }
            BuiltinFunctionKind::StringSubstr => {
                let receiver = receiver.unwrap_or(Value::Undefined);
                let value = Self::require_object_coercible_to_js_string(&receiver)?;
                self.string_substr_impl(module, &value, args)
            }
            BuiltinFunctionKind::StringHtmlMethod => {
                let receiver = receiver.unwrap_or(Value::Undefined);
                self.string_html_method(module, builtin.display_name(), receiver, args)
            }
            BuiltinFunctionKind::StringReplace => {
                let receiver = receiver.unwrap_or(Value::Undefined);
                if let Some(result) = self.string_pattern_protocol_call(
                    module,
                    &receiver,
                    args,
                    WellKnownSymbol::Replace,
                )? {
                    return Ok(result);
                }
                let value = self.string_pattern_this(module, &receiver)?;
                self.string_replace_method(module, &value, args)
            }
            BuiltinFunctionKind::StringMatch => {
                let receiver = receiver.unwrap_or(Value::Undefined);
                if let Some(result) = self.string_pattern_protocol_call(
                    module,
                    &receiver,
                    args,
                    WellKnownSymbol::Match,
                )? {
                    return Ok(result);
                }
                let value = self.string_pattern_this(module, &receiver)?;
                self.string_match_impl(module, &value, args)
            }
            BuiltinFunctionKind::StringMatchAll => {
                let receiver = receiver.unwrap_or(Value::Undefined);
                self.string_global_regexp_observable_flags_check(
                    module,
                    &receiver,
                    args,
                    "matchAll",
                )?;
                if let Some(result) = self.string_pattern_protocol_call(
                    module,
                    &receiver,
                    args,
                    WellKnownSymbol::MatchAll,
                )? {
                    return Ok(result);
                }
                let value = self.string_pattern_this(module, &receiver)?;
                let label = self.join_arg_range_label(args)?;
                let pattern = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
                // A pristine RegExp whose @@matchAll is the intrinsic one
                // (the protocol call above left it to us) runs on the
                // matcher; any other pattern supplied no @@matchAll, so
                // steps 4-5 create a RegExp and Invoke its @@matchAll
                // (bd-9vouw.498).
                let key = RuntimePropertyKey::Symbol(WellKnownSymbol::MatchAll.id());
                if let Value::Object(pattern_id) = pattern
                    && self.regexp_is_pristine(&pattern)
                    && self.regexp_uses_builtin_symbol_method(pattern_id, &key)
                {
                    return self.string_match_all_value(&value, &pattern, &label);
                }
                self.string_match_all_created_regexp(module, value, pattern, &label)
            }
            BuiltinFunctionKind::StringSearch => {
                let receiver = receiver.unwrap_or(Value::Undefined);
                if let Some(result) = self.string_pattern_protocol_call(
                    module,
                    &receiver,
                    args,
                    WellKnownSymbol::Search,
                )? {
                    return Ok(result);
                }
                let value = self.string_pattern_this(module, &receiver)?;
                self.string_search_impl(module, &value, args)
            }
            BuiltinFunctionKind::StringRepeat => {
                let receiver = receiver.unwrap_or(Value::Undefined);
                let value = Self::require_object_coercible_to_js_string(&receiver)?;
                self.string_repeat_impl(module, &value, args)
            }
            BuiltinFunctionKind::StringPadStart => {
                let receiver = receiver.unwrap_or(Value::Undefined);
                let value = Self::require_object_coercible_to_js_string(&receiver)?;
                self.string_pad_start_impl(module, &value, args)
            }
            BuiltinFunctionKind::StringPadEnd => {
                let receiver = receiver.unwrap_or(Value::Undefined);
                let value = Self::require_object_coercible_to_js_string(&receiver)?;
                self.string_pad_end_impl(module, &value, args)
            }
            BuiltinFunctionKind::NumberToFixed => {
                // ES2020 20.1.3.3: fixed-point notation with `digits` fraction
                // digits. `ToIntegerOrInfinity(digits)` must be in 0..=100 or a
                // RangeError is thrown. This path previously clamped instead, so
                // `(1).toFixed(101)` produced a 100-digit string and
                // `(1).toFixed(-1)` returned "1". (bd-i08nh, bd-cxmtb)
                let receiver = receiver.unwrap_or(Value::Undefined);
                let num = self.this_number_value(&receiver)?;
                let digits = match self.builtin_number_arg(module, args, 0)? {
                    Some(arg) => Self::value_as_integer(&arg),
                    None => 0,
                };
                if !(0..=100).contains(&digits) {
                    return Err(InterpreterError::RangeError {
                        message: format!("toFixed() digits must be between 0 and 100 (got {digits})"),
                    });
                }
                Ok(Value::str(number_to_fixed_string(num, digits as usize)))
            }
            // ECMA-402 15.4.1: formatted as `new Intl.NumberFormat(locales,
            // options).format(x)`, so the two share option reading, defaults
            // and refusals. Its own option table refused `currencyDisplay:
            // 'symbol'` (dinero) and the `fullwide` fallback
            // (temporal-polyfill) that NumberFormat accepts.
            BuiltinFunctionKind::NumberToLocaleString => {
                let receiver = receiver.unwrap_or(Value::Undefined);
                let num = self.this_number_value(&receiver)?;
                let locales = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
                let options = self.builtin_arg(args, 1)?.unwrap_or(Value::Undefined);
                self.intl_format_number(module, num, &locales, &options)
            }
            BuiltinFunctionKind::NumberToString => {
                // ES2020 20.1.3.6: string form, optional radix, default 10.
                // `ToIntegerOrInfinity(radix)` must be in 2..=36 or a RangeError is
                // thrown. This path previously returned the literal string
                // "RangeError" for an out-of-range radix and silently defaulted
                // a non-finite radix to 10. (bd-i08nh, bd-cxmtb)
                // thisNumberValue: a non-Number receiver is a TypeError
                // (`Number.prototype.toString.call('x')`), not NaN.
                let receiver = receiver.unwrap_or(Value::Undefined);
                let num = self.this_number_value(&receiver)?;
                let radix = match self.builtin_number_arg(module, args, 0)? {
                    Some(Value::Undefined) | None => 10,
                    Some(arg) => Self::value_as_integer(&arg),
                };
                if !(2..=36).contains(&radix) {
                    return Err(InterpreterError::RangeError {
                        message: format!("toString() radix must be between 2 and 36 (got {radix})"),
                    });
                }
                match self.number_to_string_impl(num, radix as i32) {
                    Ok(result) => Ok(Value::str(result)),
                    Err(_) => Err(InterpreterError::RangeError {
                        message: format!("toString() radix must be between 2 and 36 (got {radix})"),
                    }),
                }
            }
            BuiltinFunctionKind::NumberValueOf => {
                // ES2020 20.1.3.7 thisNumberValue: a number (a Number wrapper
                // arrives unwrapped) is returned as it is; any other receiver,
                // such as a Boolean wrapper borrowing the method, is a
                // TypeError.
                let receiver = receiver.unwrap_or(Value::Undefined);
                match receiver {
                    Value::Int(_) | Value::Float(_) => Ok(receiver),
                    other => {
                        let number = self.this_number_value(&other)?;
                        Ok(Value::Float(number.into()))
                    }
                }
            }
            BuiltinFunctionKind::BooleanPrototypeToString
            | BuiltinFunctionKind::BooleanPrototypeValueOf => {
                let value = self.this_boolean_value(receiver.unwrap_or(Value::Undefined))?;
                Ok(
                    if builtin.kind == BuiltinFunctionKind::BooleanPrototypeToString {
                        Value::str(if value { "true" } else { "false" })
                    } else {
                        Value::Bool(value)
                    },
                )
            }
            BuiltinFunctionKind::ArrayIsArray => {
                let arg = self.builtin_arg(args, 0)?;
                self.array_is_array_value(arg)
            }
            BuiltinFunctionKind::StreamReadablePause => {
                self.readable_pause(receiver.unwrap_or(Value::Undefined))
            }
            BuiltinFunctionKind::StreamReadableResume => {
                self.readable_resume(receiver.unwrap_or(Value::Undefined))
            }
            BuiltinFunctionKind::StreamReadableIsPaused => {
                self.readable_is_paused(receiver.unwrap_or(Value::Undefined))
            }
            BuiltinFunctionKind::StreamReadablePush => {
                self.readable_push(receiver.unwrap_or(Value::Undefined), args)
            }
            BuiltinFunctionKind::StreamReadableToArray => {
                self.readable_to_array(receiver.unwrap_or(Value::Undefined))
            }
            BuiltinFunctionKind::StreamReadableRead => {
                self.readable_read(receiver.unwrap_or(Value::Undefined), args)
            }
            BuiltinFunctionKind::StreamReadableUnshift => {
                self.readable_unshift(receiver.unwrap_or(Value::Undefined), args)
            }
            BuiltinFunctionKind::StreamReadablePipe => {
                self.readable_pipe(module, receiver.unwrap_or(Value::Undefined), args)
            }
            BuiltinFunctionKind::StreamReadableUnpipe => {
                self.readable_unpipe(module, receiver.unwrap_or(Value::Undefined), args)
            }
            BuiltinFunctionKind::StreamReadablePipeData => self.readable_pipe_data(
                module,
                receiver.unwrap_or(Value::Undefined),
                builtin,
                args,
            ),
            BuiltinFunctionKind::StreamReadablePipeEnd => self.readable_pipe_end(
                module,
                receiver.unwrap_or(Value::Undefined),
                builtin,
                args,
            ),
            BuiltinFunctionKind::StreamReadableSetEncoding => {
                self.readable_set_encoding(receiver.unwrap_or(Value::Undefined), args)
            }
            BuiltinFunctionKind::StreamReadableDestroy => {
                self.readable_destroy(receiver.unwrap_or(Value::Undefined), args)
            }
            BuiltinFunctionKind::StreamWritableWrite => {
                self.writable_write(module, receiver.unwrap_or(Value::Undefined), args)
            }
            BuiltinFunctionKind::StreamWritableEnd => {
                self.writable_end(module, receiver.unwrap_or(Value::Undefined), args)
            }
            BuiltinFunctionKind::StreamWritableWriteDone => {
                self.writable_write_done(module, builtin, args)
            }
            BuiltinFunctionKind::StreamWritableFinalDone => {
                self.writable_final_done(module, builtin, args)
            }
            BuiltinFunctionKind::StreamWritableCork => {
                self.writable_cork(receiver.unwrap_or(Value::Undefined), args)
            }
            BuiltinFunctionKind::StreamWritableUncork => {
                self.writable_uncork(module, receiver.unwrap_or(Value::Undefined), args)
            }
            BuiltinFunctionKind::StreamWritableDestroy => {
                self.writable_destroy(receiver.unwrap_or(Value::Undefined), args)
            }
            BuiltinFunctionKind::StreamPassThroughWrite => self.stream_passthrough_write(
                module,
                receiver.unwrap_or(Value::Undefined),
                args,
            ),
            BuiltinFunctionKind::StreamPassThroughFinal => self.stream_passthrough_final(
                module,
                receiver.unwrap_or(Value::Undefined),
                args,
            ),
            BuiltinFunctionKind::StreamPassThroughDestroy => {
                self.stream_passthrough_destroy(receiver.unwrap_or(Value::Undefined), args)
            }
            BuiltinFunctionKind::StreamTransformWriteDone => {
                self.stream_transform_write_done(module, builtin, args)
            }
            BuiltinFunctionKind::StreamTransformFinal => self.stream_transform_final(
                module,
                receiver.unwrap_or(Value::Undefined),
                args,
            ),
            BuiltinFunctionKind::StreamTransformFinalDone => {
                self.stream_transform_final_done(module, builtin, args)
            }
            BuiltinFunctionKind::StreamPipelineFinish => {
                self.stream_pipeline_listener_settle(
                    module,
                    receiver.unwrap_or(Value::Undefined),
                    builtin,
                    false,
                    args,
                )
            }
            BuiltinFunctionKind::StreamPipelineError => {
                self.stream_pipeline_listener_settle(
                    module,
                    receiver.unwrap_or(Value::Undefined),
                    builtin,
                    true,
                    args,
                )
            }
            BuiltinFunctionKind::NetServerListen => {
                self.loopback_server_listen(receiver.unwrap_or(Value::Undefined), args)
            }
            BuiltinFunctionKind::NetServerAddress => {
                self.loopback_server_address(receiver.unwrap_or(Value::Undefined))
            }
            BuiltinFunctionKind::NetServerClose => {
                self.loopback_server_close(receiver.unwrap_or(Value::Undefined), args)
            }
            BuiltinFunctionKind::NetSocketWrite => {
                self.loopback_socket_write(receiver.unwrap_or(Value::Undefined), args)
            }
            BuiltinFunctionKind::ChildProcessKill => {
                self.child_process_kill(receiver.unwrap_or(Value::Undefined), args)
            }
            BuiltinFunctionKind::ChildProcessStdinWrite => {
                self.child_process_stdin_write(receiver.unwrap_or(Value::Undefined), args)
            }
            BuiltinFunctionKind::ChildProcessStdinEnd => {
                self.child_process_stdin_end(receiver.unwrap_or(Value::Undefined))
            }
            BuiltinFunctionKind::NetSocketEnd => self.loopback_socket_end(
                module,
                receiver.unwrap_or(Value::Undefined),
                args,
            ),
            BuiltinFunctionKind::NetSocketDestroy => {
                self.loopback_socket_destroy(receiver.unwrap_or(Value::Undefined), args)
            }
            BuiltinFunctionKind::NetSocketSetEncoding => {
                self.loopback_socket_set_encoding(receiver.unwrap_or(Value::Undefined), args)
            }
            BuiltinFunctionKind::NetSocketPause => {
                self.loopback_socket_pause(receiver.unwrap_or(Value::Undefined), args)
            }
            BuiltinFunctionKind::NetSocketResume => {
                self.loopback_socket_resume(receiver.unwrap_or(Value::Undefined), args)
            }
            BuiltinFunctionKind::NetSocketRef
            | BuiltinFunctionKind::NetSocketUnref
            | BuiltinFunctionKind::NetSocketSetNoDelay
            | BuiltinFunctionKind::NetSocketSetKeepAlive => {
                self.loopback_socket_chainable(receiver.unwrap_or(Value::Undefined), args)
            }
            BuiltinFunctionKind::TlsSocketGetPeerCertificate => self
                .tls_socket_get_peer_certificate(receiver.unwrap_or(Value::Undefined)),
            BuiltinFunctionKind::TlsSocketGetProtocol => {
                self.tls_socket_get_protocol(receiver.unwrap_or(Value::Undefined))
            }
            BuiltinFunctionKind::TlsSocketGetCipher => {
                self.tls_socket_get_cipher(receiver.unwrap_or(Value::Undefined))
            }
            BuiltinFunctionKind::TlsSocketIsSessionReused => self
                .tls_socket_is_session_reused(receiver.unwrap_or(Value::Undefined)),
            BuiltinFunctionKind::TlsSocketGetSession => {
                self.tls_socket_get_session(receiver.unwrap_or(Value::Undefined))
            }
            BuiltinFunctionKind::ArrayPush => {
                // ES2020 23.1.3.20: append each argument to `this` at the
                // current length and return the new length. The receiver is
                // the array the method was invoked on (`arr.push(x)`), threaded
                // through `CallMethod`. The receiver-less `builtin:Array...`
                // hostcall path is a separate, detached-function fallback.
                let receiver = receiver.unwrap_or(Value::Undefined);
                let Value::Object(arr_id) = receiver else {
                    return Err(InterpreterError::TypeError {
                        expected: "array receiver for Array.prototype.push".to_string(),
                        got: receiver.type_name().to_string(),
                    });
                };
                let mut next_index = self.array_like_length(arr_id)?;
                // Only preserve a proof already established by a guarded
                // move. A standalone push must not scan the existing array.
                let mut preserves_plain_moves = self
                    .heap
                    .slot(arr_id.0 as usize)
                    .is_some_and(|slot| slot.dense_moves_plain.get() == Some(true))
                    && self.array_cache_matches_visible_length(arr_id, next_index);
                // ES2020 23.1.3.20 step 4: the new length must stay a safe
                // integer.
                if (next_index as u64).saturating_add(u64::from(args.count)) > (1 << 53) - 1 {
                    return Err(InterpreterError::TypeError {
                        expected: "an array length of at most 2^53 - 1 after push".to_string(),
                        got: format!("{next_index} + {}", args.count),
                    });
                }
                for i in 0..args.count {
                    let reg =
                        args.start
                            .checked_add(i)
                            .ok_or(InterpreterError::RegisterOutOfBounds {
                                register: args.start,
                                max: self.config.max_registers,
                    })?;
                    let element = self.read_reg(reg)?;
                    let element_label = self.get_register_label(reg)?.clone();
                    preserves_plain_moves &= !matches!(element, Value::Accessor { .. })
                        && element_label == Label::Public;
                    let element_key = RuntimePropertyKey::String(JsString::from(
                        next_index.to_string(),
                    ));
                    let previous_label =
                        self.own_stored_runtime_property_label(arr_id, &element_key);
                    self.set_own_runtime_property_label(
                        arr_id,
                        &element_key,
                        &element_label,
                    )?;
                    if let Err(error) =
                        self.set_object_property(arr_id, next_index.to_string(), element)
                    {
                        self.set_own_runtime_property_label(
                            arr_id,
                            &element_key,
                            &previous_label,
                        )?;
                        return Err(error);
                    }
                    next_index = next_index.saturating_add(1);
                }
                let new_len = i64::try_from(next_index).unwrap_or(i64::MAX);
                self.set_object_property(arr_id, "length".to_string(), Value::Int(new_len))?;
                // Keep the dense-length cache coherent with the IR ArrayPush
                // fast path (set_object_property does not maintain it).
                let arr_index = arr_id.0 as usize;
                let cached_len = u32::try_from(next_index).ok();
                self.mutate_heap(|heap| {
                    if let Some(obj) = heap.get_mut(arr_index)
                        && obj.is_array
                        && obj.cached_dense_length.is_some()
                    {
                        obj.cached_dense_length = cached_len;
                    }
                });
                if preserves_plain_moves
                    && self.array_cache_matches_visible_length(arr_id, next_index)
                {
                    self.heap
                        .slot(arr_index)
                        .expect("appended array remains live")
                        .dense_moves_plain
                        .set(Some(true));
                }
                Ok(Value::Int(new_len))
            }
            BuiltinFunctionKind::ArrayPop => {
                // ES2020 23.1.3.18: remove and return the last element,
                // decrementing `length`; an empty array yields `undefined`
                // and leaves `length` at 0. Receiver threaded via `CallMethod`.
                let receiver = receiver.unwrap_or(Value::Undefined);
                let Value::Object(arr_id) = receiver else {
                    return Err(InterpreterError::TypeError {
                        expected: "array receiver for Array.prototype.pop".to_string(),
                        got: receiver.type_name().to_string(),
                    });
                };
                let len = self.array_like_length(arr_id)?;
                if len == 0 {
                    return Ok(Value::Undefined);
                }
                let last = len - 1;
                let element = self
                    .array_index_get(Some(module), arr_id, last)?
                    .unwrap_or(Value::Undefined);
                self.join_element_stored_label(arr_id, last as u64)?;
                // Sample trust immediately before the destructive mutation.
                let was_dense = self.array_cache_is_dense(arr_id);
                let trusted_dense_length = self.array_cache_matches_visible_length(arr_id, len);
                // An accessor read above may have reentered and changed the
                // array. Never carry a proof sampled before that [[Get]].
                let preserves_plain_moves = self
                    .heap
                    .slot(arr_id.0 as usize)
                    .is_some_and(|slot| slot.dense_moves_plain.get() == Some(true));
                let last_key = last.to_string();
                let removed_tail = self.array_delete_or_throw(arr_id, &last_key)?;
                let updated_without_scan = trusted_dense_length
                    && removed_tail
                    && self.set_array_length_after_dense_tail_removal(
                        arr_id,
                        len,
                        last,
                        &last_key,
                    )?;
                if !updated_without_scan {
                    let new_len = i64::try_from(last).unwrap_or(i64::MAX);
                    self.set_object_property(arr_id, "length".to_string(), Value::Int(new_len))?;
                    self.refresh_dense_length_cache(arr_id, last, was_dense);
                }
                if preserves_plain_moves && updated_without_scan {
                    self.heap
                        .slot(arr_id.0 as usize)
                        .expect("popped array remains live")
                        .dense_moves_plain
                        .set(Some(true));
                }
                Ok(element)
            }
            BuiltinFunctionKind::ArrayShift => {
                // ES2020 23.1.3.24: remove and return the first element, moving
                // every remaining element down one index and decrementing
                // `length`; an empty array yields `undefined`.
                let receiver = receiver.unwrap_or(Value::Undefined);
                let Value::Object(arr_id) = receiver else {
                    return Err(InterpreterError::TypeError {
                        expected: "array receiver for Array.prototype.shift".to_string(),
                        got: receiver.type_name().to_string(),
                    });
                };
                let len = self.array_like_length(arr_id)?;
                if len == 0 {
                    return Ok(Value::Undefined);
                }
                if let Some(first) = self.shift_dense_array_in_place(arr_id, len)? {
                    return Ok(first);
                }
                let was_dense = self.array_cache_is_dense(arr_id);
                let first = self
                    .array_index_get(Some(module), arr_id, 0)?
                    .unwrap_or(Value::Undefined);
                // A hole moves as a hole: its target is deleted (step 6.d.iv).
                let mut moved_hole = false;
                for i in 1..len {
                    self.array_move_element(module, arr_id, i, i - 1, &mut moved_hole)?;
                }
                let last = len - 1;
                self.array_delete_or_throw(arr_id, &last.to_string())?;
                let new_len = i64::try_from(last).unwrap_or(i64::MAX);
                self.set_object_property(arr_id, "length".to_string(), Value::Int(new_len))?;
                self.refresh_dense_length_cache(arr_id, last, was_dense && !moved_hole);
                Ok(first)
            }
            BuiltinFunctionKind::ArrayUnshift => {
                // ES2020 23.1.3.28: prepend the arguments, shifting existing
                // elements up by the argument count, and return the new length.
                let receiver = receiver.unwrap_or(Value::Undefined);
                let Value::Object(arr_id) = receiver else {
                    return Err(InterpreterError::TypeError {
                        expected: "array receiver for Array.prototype.unshift".to_string(),
                        got: receiver.type_name().to_string(),
                    });
                };
                let len = self.array_like_length(arr_id)?;
                let mut items = Vec::with_capacity(args.count as usize);
                for i in 0..args.count {
                    let reg =
                        args.start
                            .checked_add(i)
                            .ok_or(InterpreterError::RegisterOutOfBounds {
                                register: args.start,
                                max: self.config.max_registers,
                            })?;
                    items.push(self.read_reg(reg)?);
                }
                let arg_count = items.len();
                let new_len = len.saturating_add(arg_count);
                let items = if arg_count > 0 {
                    match self.unshift_dense_array_in_place(arr_id, len, items)? {
                        Ok(new_len) => return Ok(Value::Int(i64::try_from(new_len).unwrap_or(i64::MAX))),
                        Err(items) => items,
                    }
                } else {
                    items
                };
                if arg_count > 0 {
                    let was_dense = self.array_cache_is_dense(arr_id);
                    // Move existing elements up, top-down, so a source index is
                    // read before its destination overwrites a later source. A
                    // hole moves as a hole (step 4.b.v: delete the target).
                    let mut moved_hole = false;
                    for i in (0..len).rev() {
                        self.array_move_element(module, arr_id, i, i + arg_count, &mut moved_hole)?;
                    }
                    for (offset, item) in items.into_iter().enumerate() {
                        self.set_object_property(arr_id, offset.to_string(), item)?;
                    }
                    let new_len_int = i64::try_from(new_len).unwrap_or(i64::MAX);
                    self.set_object_property(
                        arr_id,
                        "length".to_string(),
                        Value::Int(new_len_int),
                    )?;
                    self.refresh_dense_length_cache(arr_id, new_len, was_dense && !moved_hole);
                }
                Ok(Value::Int(i64::try_from(new_len).unwrap_or(i64::MAX)))
            }
            BuiltinFunctionKind::ArrayIndexOf => {
                // ES2020 23.1.3.12: return the first index whose element is
                // strictly equal (`values_equal`) to the search argument,
                // starting at the optional `fromIndex`, or -1.
                let receiver = receiver.unwrap_or(Value::Undefined);
                let Value::Object(arr_id) = receiver else {
                    return Err(InterpreterError::TypeError {
                        expected: "array receiver for Array.prototype.indexOf".to_string(),
                        got: receiver.type_name().to_string(),
                    });
                };
                let len =
                    self.array_method_length(arr_id, Self::is_typed_array_prototype_builtin(builtin))?;
                // Step 3: an empty receiver answers -1 before fromIndex
                // converts.
                if len == 0 {
                    return Ok(Value::Int(-1));
                }
                let search = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
                let from = match self.builtin_number_arg(module, args, 1)? {
                    Some(value) => {
                        Self::require_number_coercible_index(&value, "Array.prototype.indexOf")?;
                        Self::clamp_relative_index(Self::value_as_integer(&value), len)
                    }
                    None => 0,
                };
                let mut found = -1i64;
                for i in from..len {
                    // A hole is skipped (HasProperty is false), so
                    // `[1, , 3].indexOf(undefined)` is -1; `includes` below
                    // reads holes as undefined.
                    let Some(element) = self.array_index_get(Some(module), arr_id, i)? else {
                        continue;
                    };
                    self.join_element_stored_label(arr_id, i as u64)?;
                    if Self::values_equal(&element, &search) {
                        found = i64::try_from(i).unwrap_or(i64::MAX);
                        break;
                    }
                }
                Ok(Value::Int(found))
            }
            BuiltinFunctionKind::ArrayIncludes => {
                // ES2020 23.1.3.13: SameValueZero membership test (NaN matches
                // NaN, unlike strict equality), honoring an optional fromIndex.
                let receiver = receiver.unwrap_or(Value::Undefined);
                let Value::Object(arr_id) = receiver else {
                    return Err(InterpreterError::TypeError {
                        expected: "array receiver for Array.prototype.includes".to_string(),
                        got: receiver.type_name().to_string(),
                    });
                };
                let len =
                    self.array_method_length(arr_id, Self::is_typed_array_prototype_builtin(builtin))?;
                // Step 3: an empty receiver answers false before fromIndex
                // converts.
                if len == 0 {
                    return Ok(Value::Bool(false));
                }
                let search = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
                let from = match self.builtin_number_arg(module, args, 1)? {
                    Some(value) => {
                        Self::require_number_coercible_index(&value, "Array.prototype.includes")?;
                        Self::clamp_relative_index(Self::value_as_integer(&value), len)
                    }
                    None => 0,
                };
                let mut present = false;
                for i in from..len {
                    let element = self
                        .array_index_get(Some(module), arr_id, i)?
                        .unwrap_or(Value::Undefined);
                    self.join_element_stored_label(arr_id, i as u64)?;
                    if Self::values_equal(&element, &search) || Self::both_nan(&element, &search) {
                        present = true;
                        break;
                    }
                }
                Ok(Value::Bool(present))
            }
            BuiltinFunctionKind::ArrayReverse => {
                // ES2020 23.1.3.21: reverse the elements in place and return the
                // array itself.
                let receiver = receiver.unwrap_or(Value::Undefined);
                let Value::Object(arr_id) = receiver else {
                    return Err(InterpreterError::TypeError {
                        expected: "array receiver for Array.prototype.reverse".to_string(),
                        got: receiver.type_name().to_string(),
                    });
                };
                let len = self.array_like_length(arr_id)?;
                if len > 1 {
                    let was_dense = self.array_cache_is_dense(arr_id);
                    let mut moved_hole = false;
                    for i in 0..(len / 2) {
                        let j = len - 1 - i;
                        let lo = self.array_index_get(Some(module), arr_id, i)?;
                        let hi = self.array_index_get(Some(module), arr_id, j)?;
                        // Step 7.h-k: a present element moves to the other
                        // index and a hole deletes it, so holes swap too.
                        moved_hole |= lo.is_none() || hi.is_none();
                        self.array_store_or_delete(arr_id, i, hi)?;
                        self.array_store_or_delete(arr_id, j, lo)?;
                    }
                    self.refresh_dense_length_cache(arr_id, len, was_dense && !moved_hole);
                }
                Ok(Value::Object(arr_id))
            }
            BuiltinFunctionKind::ArrayFill => {
                // ES2020 23.1.3.6: fill `[start, end)` with the value in place;
                // negative bounds count from the end. Returns the array.
                let receiver = receiver.unwrap_or(Value::Undefined);
                let Value::Object(arr_id) = receiver else {
                    return Err(InterpreterError::TypeError {
                        expected: "array receiver for Array.prototype.fill".to_string(),
                        got: receiver.type_name().to_string(),
                    });
                };
                let len = self.array_like_length(arr_id)?;
                let fill_value = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
                let start = match self.builtin_number_arg(module, args, 1)? {
                    Some(value) => Self::clamp_relative_index(Self::value_as_integer(&value), len),
                    None => 0,
                };
                // An undefined end is the length (ES2020 22.1.3.6 step 7):
                // `a.fill(v, 0, undefined)` filled nothing.
                let end = match self.builtin_number_arg(module, args, 2)? {
                    Some(Value::Undefined) | None => len,
                    Some(value) => Self::clamp_relative_index(Self::value_as_integer(&value), len),
                };
                if start < end {
                    let was_dense = self.array_cache_is_dense(arr_id);
                    for i in start..end {
                        self.set_object_property(arr_id, i.to_string(), fill_value.clone())?;
                    }
                    self.refresh_dense_length_cache(arr_id, len, was_dense);
                }
                Ok(Value::Object(arr_id))
            }
            BuiltinFunctionKind::ArrayAt => {
                // ES2022 23.1.3.1: `at(index)` returns the element at `index`;
                // a negative index counts from the end; out-of-range returns
                // `undefined`. `index` is coerced to an integer (default 0).
                let receiver = receiver.unwrap_or(Value::Undefined);
                let Value::Object(arr_id) = receiver else {
                    return Err(InterpreterError::TypeError {
                        expected: "array receiver for Array.prototype.at".to_string(),
                        got: receiver.type_name().to_string(),
                    });
                };
                let len = self
                    .array_method_length(arr_id, Self::is_typed_array_prototype_builtin(builtin))?
                    as i64;
                let raw = match self.builtin_number_arg(module, args, 0)? {
                    Some(value) => Self::value_as_integer(&value),
                    None => 0,
                };
                let idx = if raw < 0 { raw + len } else { raw };
                if idx < 0 || idx >= len {
                    return Ok(Value::Undefined);
                }
                let element = self
                    .array_index_get(Some(module), arr_id, idx as usize)?
                    .unwrap_or(Value::Undefined);
                self.join_element_stored_label(arr_id, idx as u64)?;
                Ok(element)
            }
            BuiltinFunctionKind::ArrayFlat => {
                // ES2019 23.1.3.10: `flat(depth)` returns a new array with
                // sub-array elements concatenated into it recursively up to
                // `depth` levels (default 1; `Infinity` => fully flatten, which
                // falls out of the saturating `inf as i64` cast). A negative or
                // NaN depth flattens zero levels (a shallow copy).
                let receiver = receiver.unwrap_or(Value::Undefined);
                let Value::Object(arr_id) = receiver else {
                    return Err(InterpreterError::TypeError {
                        expected: "array receiver for Array.prototype.flat".to_string(),
                        got: receiver.type_name().to_string(),
                    });
                };
                let depth = match self.builtin_number_arg(module, args, 0)? {
                    None | Some(Value::Undefined) => 1,
                    Some(value) => Self::value_as_integer(&value).max(0),
                };
                let result = self.array_species_result(module, arr_id, 0)?;
                let mut out = 0usize;
                let source_label = match receiver_register {
                    Some(register) => self.clone_register_label_with_temporary_budget(register)?,
                    None => self.clone_active_execution_context_label()?,
                };
                self.array_flatten_into(
                    module,
                    arr_id,
                    depth,
                    result,
                    &mut out,
                    &source_label,
                )?;
                // An array result keeps its length in step; another
                // species object gets only the data properties.
                if self.generic_is_array(result)? {
                    self.set_object_property(
                        result,
                        "length".to_string(),
                        Value::Int(i64::try_from(out).unwrap_or(i64::MAX)),
                    )?;
                }
                Ok(Value::Object(result))
            }
            BuiltinFunctionKind::ArrayToLocaleString => {
                self.array_to_locale_string(module, receiver.unwrap_or(Value::Undefined))
            }
            BuiltinFunctionKind::ArrayJoin => {
                // ES2020 23.1.3.13(join): concatenate elements with `separator`
                // (default ","); `undefined`/`null` elements render as "".
                let receiver = receiver.unwrap_or(Value::Undefined);
                let Value::Object(arr_id) = receiver else {
                    return Err(InterpreterError::TypeError {
                        expected: "array receiver for Array.prototype.join".to_string(),
                        got: receiver.type_name().to_string(),
                    });
                };
                // %TypedArray%.prototype.join validates and converts its
                // separator first; Array.prototype.join called on a typed
                // array stays generic (an out-of-bounds view has length 0).
                if Self::is_typed_array_prototype_builtin(builtin)
                    && let Some(view) = self.typed_array_view_for_object(arr_id)?
                {
                    return self.typed_array_join(module, arr_id, &view, args);
                }
                let separator = match self.builtin_arg(args, 0)? {
                    None | Some(Value::Undefined) => JsString::from(","),
                    Some(Value::Str(text)) => text,
                    Some(value) => {
                        self.observe_date_value_label(&value)?;
                        JsString::from(self.value_to_string(&value))
                    }
                };
                Ok(Value::Str(self.array_join_observable(
                    module,
                    arr_id,
                    &separator,
                )?))
            }
            BuiltinFunctionKind::ArrayToString => {
                // ES2020 23.1.3.30: Array.prototype.toString invokes the
                // receiver's `join` if callable (an own override wins), else
                // the default "," join; arguments are ignored. A typed array
                // inherits %TypedArray%.prototype.join, the same "," join
                // (22.2.3.29). Any other receiver keeps the ordinary object tag.
                let receiver = receiver.unwrap_or(Value::Undefined);
                match receiver {
                    Value::Object(arr_id) => {
                        let own_join = self
                            .heap
                            .get(arr_id.0 as usize)
                            .and_then(|object| object.properties.get("join"))
                            .cloned();
                        if let Some(
                            callable @ (Value::Closure(_)
                            | Value::Function(_)
                            | Value::BuiltinFunction(_)),
                        ) = own_join
                        {
                            return self.invoke_inline_method_call(
                                Some(module),
                                callable,
                                Value::Object(arr_id),
                                Vec::new(),
                            );
                        }
                        if self.heap.get(arr_id.0 as usize).is_some_and(|object| {
                            object.is_array
                                || object
                                    .brand()
                                    .is_some_and(|tag| TypedArrayKind::from_type_name(tag).is_some())
                        }) {
                            Ok(Value::Str(self.array_join_observable(
                                module,
                                arr_id,
                                &JsString::from(","),
                            )?))
                        } else {
                            Ok(self.object_prototype_to_string_value(&Value::Object(arr_id)))
                        }
                    }
                    other => Ok(self.object_prototype_to_string_value(&other)),
                }
            }
            BuiltinFunctionKind::ArrayEntries => {
                let receiver = receiver.unwrap_or(Value::Undefined);
                self.array_prototype_iterator_for_receiver(receiver, "entries")
            }
            BuiltinFunctionKind::ArrayKeys => {
                let receiver = receiver.unwrap_or(Value::Undefined);
                self.array_prototype_iterator_for_receiver(receiver, "keys")
            }
            BuiltinFunctionKind::ArrayValues => {
                let receiver = receiver.unwrap_or(Value::Undefined);
                self.array_prototype_iterator_for_receiver(receiver, "values")
            }
            BuiltinFunctionKind::ArrayForEach => {
                // ES2020 23.1.3.12: call the callback for each element (holes
                // skipped); returns undefined. Callback receives
                // (element, index, array) with the optional thisArg.
                let (arr_id, callback, this_arg, len) =
                    self.array_callback_receiver(
                        receiver,
                        args,
                        Self::is_typed_array_prototype_builtin(builtin),
                        "Array.prototype.forEach",
                    )?;
                let typed_array_method = Self::is_typed_array_prototype_builtin(builtin);
                for index in 0..len {
                    let Some(element) =
                        self.array_loop_element(Some(module), arr_id, index, typed_array_method)?
                    else {
                        continue;
                    };
                    self.invoke_array_callback(
                        Some(module),
                        &callback,
                        this_arg.clone(),
                        element,
                        index,
                        arr_id,
                    )?;
                }
                Ok(Value::Undefined)
            }
            BuiltinFunctionKind::ArrayMap => {
                // ES2020 23.1.3.18: new array of callback results, one per
                // element (holes skipped).
                let (arr_id, callback, this_arg, len) =
                    self.array_callback_receiver(
                        receiver,
                        args,
                        Self::is_typed_array_prototype_builtin(builtin),
                        "Array.prototype.map",
                    )?;
                let allocation = self.array_species_allocation(module, arr_id, len as u64)?;
                let result = allocation.object;
                if !allocation.intrinsic {
                    return self.with_custom_array_species_result(
                        arr_id,
                        result,
                        args,
                        receiver_register,
                        |core| {
                            core.generic_iterate_result(
                                module,
                                arr_id,
                                BuiltinFunctionKind::ArrayMap,
                                len as u64,
                                &callback,
                                &this_arg,
                                Some(result),
                            )
                        },
                    );
                }
                for index in 0..len {
                    let Some(element) = self.array_index_get(Some(module), arr_id, index)? else {
                        continue;
                    };
                    let (mapped, mapped_label) =
                        self.with_gc_nested_request(vec![Value::Object(result)], |core| {
                            core.invoke_labeled_array_callback(
                                Some(module),
                                &callback,
                                this_arg.clone(),
                                element,
                                index,
                                arr_id,
                            )
                        })?;
                    self.create_labeled_data_property_or_throw(
                        result,
                        index.to_string(),
                        mapped,
                        &mapped_label,
                    )?;
                }
                // ArraySpeciesCreate initialized an intrinsic result's length.
                // A custom result receives only element definitions: map must
                // not truncate an aliased Array or write its length property.
                Ok(Value::Object(result))
            }
            BuiltinFunctionKind::ArrayFilter => {
                // ES2020 23.1.3.7: new array of elements for which the callback
                // is truthy, with compacted indices.
                let (arr_id, callback, this_arg, len) =
                    self.array_callback_receiver(
                        receiver,
                        args,
                        Self::is_typed_array_prototype_builtin(builtin),
                        "Array.prototype.filter",
                    )?;
                let allocation = self.array_species_allocation(module, arr_id, 0)?;
                let result = allocation.object;
                if !allocation.intrinsic {
                    return self.with_custom_array_species_result(
                        arr_id,
                        result,
                        args,
                        receiver_register,
                        |core| {
                            core.generic_iterate_result(
                                module,
                                arr_id,
                                BuiltinFunctionKind::ArrayFilter,
                                len as u64,
                                &callback,
                                &this_arg,
                                Some(result),
                            )
                        },
                    );
                }
                let mut prefix_label = {
                    let mut source_label = self.join_arg_range_label(args)?;
                    if let Some(register) = receiver_register {
                        source_label = self.join_owned_label_with_temporary_budget(
                            source_label,
                            self.get_register_label(register)?,
                        )?;
                    }
                    self.array_result_prefix_label(arr_id, result, &source_label)?
                };
                self.record_array_result_prefix_label(result, &prefix_label)?;
                let mut out = 0usize;
                for index in 0..len {
                    let Some(element) = self.array_index_get(Some(module), arr_id, index)? else {
                        continue;
                    };
                    let (keep, predicate_label) =
                        self.with_gc_nested_request(vec![Value::Object(result)], |core| {
                            core.invoke_labeled_array_callback(
                                Some(module),
                                &callback,
                                this_arg.clone(),
                                element.clone(),
                                index,
                                arr_id,
                            )
                        })?;
                    // Every earlier selection controls this output position.
                    // Label length even when the predicate rejects the element,
                    // so an existing species alias observes that dependency.
                    prefix_label = std::cmp::max(prefix_label, predicate_label);
                    prefix_label =
                        self.array_result_prefix_label(arr_id, result, &prefix_label)?;
                    self.record_array_result_prefix_label(result, &prefix_label)?;
                    if keep.is_truthy() {
                        self.create_labeled_data_property_or_throw(
                            result,
                            out.to_string(),
                            element,
                            &prefix_label,
                        )?;
                        out += 1;
                    }
                }
                // Only the unexposed intrinsic result uses raw storage.
                self.set_object_property(
                    result,
                    "length".to_string(),
                    Value::Int(i64::try_from(out).unwrap_or(i64::MAX)),
                )?;
                Ok(Value::Object(result))
            }
            BuiltinFunctionKind::ArrayFind => {
                // ES2020 23.1.3.8: first element for which the callback is
                // truthy (holes visited as undefined), else undefined.
                let (arr_id, callback, this_arg, len) =
                    self.array_callback_receiver(
                        receiver,
                        args,
                        Self::is_typed_array_prototype_builtin(builtin),
                        "Array.prototype.find",
                    )?;
                for index in 0..len {
                    let element = self
                        .array_index_get(Some(module), arr_id, index)?
                        .unwrap_or(Value::Undefined);
                    let hit = self.invoke_array_callback(
                        Some(module),
                        &callback,
                        this_arg.clone(),
                        element.clone(),
                        index,
                        arr_id,
                    )?;
                    if hit.is_truthy() {
                        return Ok(element);
                    }
                }
                Ok(Value::Undefined)
            }
            BuiltinFunctionKind::ArrayFindIndex => {
                // ES2020 23.1.3.9: index of the first element for which the
                // callback is truthy, else -1.
                let (arr_id, callback, this_arg, len) =
                    self.array_callback_receiver(
                        receiver,
                        args,
                        Self::is_typed_array_prototype_builtin(builtin),
                        "Array.prototype.findIndex",
                    )?;
                for index in 0..len {
                    let element = self
                        .array_index_get(Some(module), arr_id, index)?
                        .unwrap_or(Value::Undefined);
                    let hit = self.invoke_array_callback(
                        Some(module),
                        &callback,
                        this_arg.clone(),
                        element,
                        index,
                        arr_id,
                    )?;
                    if hit.is_truthy() {
                        return Ok(Value::Int(i64::try_from(index).unwrap_or(i64::MAX)));
                    }
                }
                Ok(Value::Int(-1))
            }
            BuiltinFunctionKind::ArrayFindLast => {
                // ES2023 23.1.3.9: the LAST element for which the callback is
                // truthy (iterating in reverse), else undefined.
                let (arr_id, callback, this_arg, len) =
                    self.array_callback_receiver(
                        receiver,
                        args,
                        Self::is_typed_array_prototype_builtin(builtin),
                        "Array.prototype.findLast",
                    )?;
                for index in (0..len).rev() {
                    let element = self
                        .array_index_get(Some(module), arr_id, index)?
                        .unwrap_or(Value::Undefined);
                    let hit = self.invoke_array_callback(
                        Some(module),
                        &callback,
                        this_arg.clone(),
                        element.clone(),
                        index,
                        arr_id,
                    )?;
                    if hit.is_truthy() {
                        return Ok(element);
                    }
                }
                Ok(Value::Undefined)
            }
            BuiltinFunctionKind::ArrayFindLastIndex => {
                // ES2023 23.1.3.10: index of the last element for which the
                // callback is truthy (reverse), else -1.
                let (arr_id, callback, this_arg, len) =
                    self.array_callback_receiver(
                        receiver,
                        args,
                        Self::is_typed_array_prototype_builtin(builtin),
                        "Array.prototype.findLastIndex",
                    )?;
                for index in (0..len).rev() {
                    let element = self
                        .array_index_get(Some(module), arr_id, index)?
                        .unwrap_or(Value::Undefined);
                    let hit = self.invoke_array_callback(
                        Some(module),
                        &callback,
                        this_arg.clone(),
                        element,
                        index,
                        arr_id,
                    )?;
                    if hit.is_truthy() {
                        return Ok(Value::Int(i64::try_from(index).unwrap_or(i64::MAX)));
                    }
                }
                Ok(Value::Int(-1))
            }
            BuiltinFunctionKind::ArrayFlatMap => {
                // ES2019 23.1.3.11: map each element through the callback, then
                // flatten the result one level (a returned array's elements are
                // spread; a non-array result is appended as-is).
                let (arr_id, callback, this_arg, len) =
                    self.array_callback_receiver(
                        receiver,
                        args,
                        Self::is_typed_array_prototype_builtin(builtin),
                        "Array.prototype.flatMap",
                    )?;
                let result = self.array_species_result(module, arr_id, 0)?;
                let mut prefix_label = {
                    let mut source_label = self.join_arg_range_label(args)?;
                    if let Some(register) = receiver_register {
                        source_label = self.join_owned_label_with_temporary_budget(
                            source_label,
                            self.get_register_label(register)?,
                        )?;
                    }
                    self.array_result_prefix_label(arr_id, result, &source_label)?
                };
                self.record_array_result_prefix_label(result, &prefix_label)?;
                let mut out = 0usize;
                for index in 0..len {
                    let Some(element) = self.array_index_get(Some(module), arr_id, index)? else {
                        continue;
                    };
                    let (mapped, mapped_label) =
                        self.with_gc_nested_request(vec![Value::Object(result)], |core| {
                            core.invoke_labeled_array_callback(
                                Some(module),
                                &callback,
                                this_arg.clone(),
                                element,
                                index,
                                arr_id,
                            )
                        })?;
                    // A previous callback or empty nested array can still
                    // determine where this value is written and the final length.
                    prefix_label = std::cmp::max(prefix_label, mapped_label);
                    prefix_label =
                        self.array_result_prefix_label(arr_id, result, &prefix_label)?;
                    self.record_array_result_prefix_label(result, &prefix_label)?;
                    let nested = if let Value::Object(eid) = &mapped {
                        self.heap
                            .get(eid.0 as usize)
                            .map(|object| object.is_array)
                            .unwrap_or(false)
                    } else {
                        false
                    };
                    if nested {
                        if let Value::Object(eid) = mapped {
                            // depth 0 => copy the mapped array's elements one
                            // level without recursing further.
                            self.array_flatten_into(
                                module,
                                eid,
                                0,
                                result,
                                &mut out,
                                &prefix_label,
                            )?;
                        }
                    } else {
                        self.create_labeled_data_property_or_throw(
                            result,
                            out.to_string(),
                            mapped,
                            &prefix_label,
                        )?;
                        out += 1;
                    }
                }
                // An array result keeps its length in step; another
                // species object gets only the data properties.
                if self.generic_is_array(result)? {
                    self.set_object_property(
                        result,
                        "length".to_string(),
                        Value::Int(i64::try_from(out).unwrap_or(i64::MAX)),
                    )?;
                }
                Ok(Value::Object(result))
            }
            BuiltinFunctionKind::ArrayCopyWithin => {
                // ES2020 22.1.3.3: copy the subsequence `[start, end)` to
                // `target`, in place; negative indices count from the end;
                // returns the array. Overlapping ranges copy back to front, so
                // each source is read before it is overwritten, and a hole
                // deletes its target. The count is guest-chosen (bd-9vouw.112):
                // nothing is buffered, and hole reads count against the budget.
                let receiver = receiver.unwrap_or(Value::Undefined);
                let Value::Object(arr_id) = receiver else {
                    return Err(InterpreterError::TypeError {
                        expected: "array receiver for Array.prototype.copyWithin".to_string(),
                        got: receiver.type_name().to_string(),
                    });
                };
                let len = self.array_like_length(arr_id)?;
                let target = match self.builtin_number_arg(module, args, 0)? {
                    Some(value) => Self::clamp_relative_index(Self::value_as_integer(&value), len),
                    None => 0,
                };
                let start = match self.builtin_number_arg(module, args, 1)? {
                    Some(value) => Self::clamp_relative_index(Self::value_as_integer(&value), len),
                    None => 0,
                };
                let end = match self.builtin_number_arg(module, args, 2)? {
                    None | Some(Value::Undefined) => len,
                    Some(value) => Self::clamp_relative_index(Self::value_as_integer(&value), len),
                };
                let count = end.saturating_sub(start).min(len.saturating_sub(target));
                let backward = start < target && target < start + count;
                let was_dense = self.array_cache_is_dense(arr_id);
                for step in 0..count {
                    let offset = if backward { count - 1 - step } else { step };
                    let to = (target + offset).to_string();
                    match self.array_index_get(Some(module), arr_id, start + offset)? {
                        Some(value) => self.set_object_property(arr_id, to, value)?,
                        None => {
                            self.remove_object_property(arr_id, &to)?;
                        }
                    }
                }
                self.refresh_dense_length_cache(arr_id, len, was_dense);
                Ok(Value::Object(arr_id))
            }
            BuiltinFunctionKind::ArraySome => {
                // ES2020 23.1.3.24: true if the callback is truthy for any
                // element (holes skipped).
                let (arr_id, callback, this_arg, len) =
                    self.array_callback_receiver(
                        receiver,
                        args,
                        Self::is_typed_array_prototype_builtin(builtin),
                        "Array.prototype.some",
                    )?;
                let typed_array_method = Self::is_typed_array_prototype_builtin(builtin);
                for index in 0..len {
                    let Some(element) =
                        self.array_loop_element(Some(module), arr_id, index, typed_array_method)?
                    else {
                        continue;
                    };
                    let result = self.invoke_array_callback(
                        Some(module),
                        &callback,
                        this_arg.clone(),
                        element,
                        index,
                        arr_id,
                    )?;
                    if result.is_truthy() {
                        return Ok(Value::Bool(true));
                    }
                }
                Ok(Value::Bool(false))
            }
            BuiltinFunctionKind::ArrayEvery => {
                // ES2020 23.1.3.6: true if the callback is truthy for every
                // element (holes skipped); short-circuits on the first falsy.
                let (arr_id, callback, this_arg, len) =
                    self.array_callback_receiver(
                        receiver,
                        args,
                        Self::is_typed_array_prototype_builtin(builtin),
                        "Array.prototype.every",
                    )?;
                let typed_array_method = Self::is_typed_array_prototype_builtin(builtin);
                for index in 0..len {
                    let Some(element) =
                        self.array_loop_element(Some(module), arr_id, index, typed_array_method)?
                    else {
                        continue;
                    };
                    let result = self.invoke_array_callback(
                        Some(module),
                        &callback,
                        this_arg.clone(),
                        element,
                        index,
                        arr_id,
                    )?;
                    if !result.is_truthy() {
                        return Ok(Value::Bool(false));
                    }
                }
                Ok(Value::Bool(true))
            }
            BuiltinFunctionKind::ArrayReduce => self.array_reduce_receiver(
                module,
                receiver,
                args,
                false,
                Self::is_typed_array_prototype_builtin(builtin),
                receiver_register,
            ),
            BuiltinFunctionKind::ArrayReduceRight => self.array_reduce_receiver(
                module,
                receiver,
                args,
                true,
                Self::is_typed_array_prototype_builtin(builtin),
                receiver_register,
            ),
            BuiltinFunctionKind::ArraySort => {
                // ES2020 23.1.3.27: in-place sort. With a comparator, order by
                // the sign of comparator(a, b) (a merge sort, since the
                // comparator re-enters the interpreter); otherwise by the
                // UTF-16 code units of ToString. Returns the array. An Array
                // with holes, accessors, read-only elements or (without a
                // comparator) object elements sorts generically
                // (`array_sorts_on_element_storage`).
                let receiver = receiver.unwrap_or(Value::Undefined);
                let Value::Object(arr_id) = receiver else {
                    return Err(InterpreterError::TypeError {
                        expected: "array receiver for Array.prototype.sort".to_string(),
                        got: receiver.type_name().to_string(),
                    });
                };
                let len = self.array_like_length(arr_id)?;
                let comparator = match self.builtin_arg(args, 0)? {
                    Some(Value::Undefined) | None => None,
                    Some(callback) => Some(callback),
                };
                if len > 1 {
                    let mut elements = self.element_buffer(len)?;
                    for index in 0..len {
                        elements.push(
                            self.array_index_get(Some(module), arr_id, index)?
                                .unwrap_or(Value::Undefined),
                        );
                    }
                    // SortCompare (ES2020 22.1.3.27.1): undefined sorts last
                    // and never reaches the comparator.
                    let undefined_count = elements
                        .iter()
                        .filter(|element| matches!(element, Value::Undefined))
                        .count();
                    elements.retain(|element| !matches!(element, Value::Undefined));
                    if let Some(comparator) = comparator {
                        elements =
                            self.merge_sort_with_comparator(module, &comparator, elements)?;
                    } else {
                        let mut keyed = elements
                            .into_iter()
                            .map(|element| (Self::sort_utf16_key(&element), element))
                            .collect::<Vec<_>>();
                        keyed.sort_by(|(a, _), (b, _)| a.cmp(b));
                        elements = keyed.into_iter().map(|(_, element)| element).collect();
                    }
                    elements.extend(std::iter::repeat_n(Value::Undefined, undefined_count));
                    let was_dense = self.array_cache_is_dense(arr_id);
                    for (index, element) in elements.into_iter().enumerate() {
                        self.set_object_property(arr_id, index.to_string(), element)?;
                    }
                    self.refresh_dense_length_cache(arr_id, len, was_dense);
                }
                Ok(Value::Object(arr_id))
            }
            BuiltinFunctionKind::ArrayConcat => {
                let receiver = receiver.unwrap_or(Value::Undefined);
                let Value::Object(arr_id) = receiver else {
                    return Err(InterpreterError::TypeError {
                        expected: "array receiver for Array.prototype.concat".to_string(),
                        got: receiver.type_name().to_string(),
                    });
                };
                let allocation = self.array_species_allocation(module, arr_id, 0)?;
                let result = allocation.object;
                if !allocation.intrinsic {
                    let mut items = vec![Value::Object(arr_id)];
                    for index in 0..args.count {
                        items.push(self.builtin_arg(args, index)?.unwrap_or(Value::Undefined));
                    }
                    return self.with_custom_array_species_result(
                        arr_id,
                        result,
                        args,
                        receiver_register,
                        |core| core.generic_concat_result(module, items, result),
                    );
                }

                // Only a fresh intrinsic result can use raw output writes.
                // No guest code runs in this prefix: revalidate each item,
                // then hand off BEFORE the first element accessor is invoked.
                let mut out = 0u64;
                for item_index in 0..=args.count {
                    let item = if item_index == 0 {
                        Value::Object(arr_id)
                    } else {
                        self.builtin_arg(args, item_index - 1)?
                            .unwrap_or(Value::Undefined)
                    };
                    if self.concat_item_requires_generic(&item)? {
                        let mut items = vec![item];
                        for tail in item_index..args.count {
                            items.push(self.builtin_arg(args, tail)?.unwrap_or(Value::Undefined));
                        }
                        return self.with_custom_array_species_result(
                            arr_id,
                            result,
                            args,
                            receiver_register,
                            |core| core.generic_concat_tail(module, items, result, out, None),
                        );
                    }
                    let array = match &item {
                        Value::Object(id) if self.generic_is_array(*id)? => Some(*id),
                        _ => None,
                    };
                    if let Some(source) = array {
                        let len = self.array_like_length(source)?;
                        Self::concat_result_end(out, len as u64)?;
                        for index in 0..len {
                            // array_index_get uses this same read and returns
                            // non-accessors unchanged. Do not read twice: a
                            // missing slot charges its hole budget here.
                            let element = self.array_index_value(source, index)?;
                            if matches!(&element, Some(Value::Accessor { .. })) {
                                let mut items = Vec::new();
                                for tail in item_index..args.count {
                                    items.push(
                                        self.builtin_arg(args, tail)?.unwrap_or(Value::Undefined),
                                    );
                                }
                                return self.with_custom_array_species_result(
                                    arr_id,
                                    result,
                                    args,
                                    receiver_register,
                                    |core| {
                                        core.generic_concat_tail(
                                            module,
                                            items,
                                            result,
                                            out,
                                            Some((source, index as u64, len as u64)),
                                        )
                                    },
                                );
                            }
                            if let Some(element) = element {
                                self.create_data_property_or_throw(
                                    result,
                                    out.to_string(),
                                    element,
                                )?;
                            }
                            out += 1;
                        }
                    } else {
                        let end = Self::concat_result_end(out, 1)?;
                        self.create_data_property_or_throw(result, out.to_string(), item)?;
                        out = end;
                    }
                }
                self.set_object_property(
                    result,
                    "length".to_string(),
                    Value::Int(i64::try_from(out).unwrap_or(i64::MAX)),
                )?;
                Ok(Value::Object(result))
            }
            BuiltinFunctionKind::ArraySliceMethod => {
                // ES2020 23.1.3.25: new array for `[start, end)`; negative
                // indices count from the end (start default 0, end default len).
                let receiver = receiver.unwrap_or(Value::Undefined);
                let Value::Object(arr_id) = receiver else {
                    return Err(InterpreterError::TypeError {
                        expected: "array receiver for Array.prototype.slice".to_string(),
                        got: receiver.type_name().to_string(),
                    });
                };
                let len = self.array_like_length(arr_id)?;
                let start = match self.builtin_number_arg(module, args, 0)? {
                    Some(value) => Self::clamp_relative_index(Self::value_as_integer(&value), len),
                    None => 0,
                };
                let end = match self.builtin_number_arg(module, args, 1)? {
                    None | Some(Value::Undefined) => len,
                    Some(value) => Self::clamp_relative_index(Self::value_as_integer(&value), len),
                };
                let allocation =
                    self.array_species_allocation(module, arr_id, end.saturating_sub(start) as u64)?;
                let result = allocation.object;
                if !allocation.intrinsic {
                    return self.with_custom_array_species_result(
                        arr_id,
                        result,
                        args,
                        receiver_register,
                        |core| {
                            core.generic_slice_result(
                                module,
                                arr_id,
                                start as u64,
                                end as u64,
                                result,
                            )
                        },
                    );
                }
                let mut out = 0usize;
                let mut index = start;
                while index < end {
                    // A hole stays a hole in the result (step 10.c: only a
                    // present element is created); `length` counts it.
                    if let Some(element) = self.array_index_get(Some(module), arr_id, index)? {
                        self.create_data_property_or_throw(result, out.to_string(), element)?;
                    }
                    out += 1;
                    index += 1;
                }
                self.set_object_property(
                    result,
                    "length".to_string(),
                    Value::Int(i64::try_from(out).unwrap_or(i64::MAX)),
                )?;
                Ok(Value::Object(result))
            }
            BuiltinFunctionKind::ArrayLastIndexOf => {
                // ES2020 22.1.3.17: last index strictly equal to the search
                // element, scanning backward from fromIndex (default len - 1;
                // a negative one counts from the end, one below -len finds
                // nothing), else -1. fromIndex was ignored, so
                // `[1, 2, 1].lastIndexOf(1, 1)` answered 2, and a Symbol or
                // BigInt fromIndex did not throw.
                let receiver = receiver.unwrap_or(Value::Undefined);
                let Value::Object(arr_id) = receiver else {
                    return Err(InterpreterError::TypeError {
                        expected: "array receiver for Array.prototype.lastIndexOf".to_string(),
                        got: receiver.type_name().to_string(),
                    });
                };
                let len = i64::try_from(
                    self.array_method_length(arr_id, Self::is_typed_array_prototype_builtin(builtin))?,
                )
                .unwrap_or(i64::MAX);
                // Step 3: an empty receiver answers -1 before fromIndex
                // converts.
                if len == 0 {
                    return Ok(Value::Int(-1));
                }
                let search = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
                let start = match self.builtin_number_arg(module, args, 1)? {
                    Some(value) => {
                        Self::require_number_coercible_index(
                            &value,
                            "Array.prototype.lastIndexOf",
                        )?;
                        let from = Self::value_as_integer(&value);
                        if from >= 0 {
                            from.min(len - 1)
                        } else {
                            len.saturating_add(from)
                        }
                    }
                    None => len - 1,
                };
                let mut found = -1i64;
                let mut index = start;
                while index >= 0 {
                    // Holes are skipped, as in indexOf.
                    let element = self.array_index_get(Some(module), arr_id, index as usize)?;
                    if element.is_some() {
                        self.join_element_stored_label(arr_id, index as u64)?;
                    }
                    if element.is_some_and(|element| Self::values_equal(&element, &search)) {
                        found = index;
                        break;
                    }
                    index -= 1;
                }
                Ok(Value::Int(found))
            }
            BuiltinFunctionKind::ArraySplice => {
                // ES2020 23.1.3.28: in-place remove `deleteCount` elements at
                // `start` and insert the given items; returns an array of the
                // removed elements.
                let receiver = receiver.unwrap_or(Value::Undefined);
                let Value::Object(arr_id) = receiver else {
                    return Err(InterpreterError::TypeError {
                        expected: "array receiver for Array.prototype.splice".to_string(),
                        got: receiver.type_name().to_string(),
                    });
                };
                let len = self.array_like_length(arr_id)?;
                let start = match self.builtin_number_arg(module, args, 0)? {
                    Some(value) => Self::clamp_relative_index(Self::value_as_integer(&value), len),
                    None => 0,
                };
                let delete_count = match self.builtin_number_arg(module, args, 1)? {
                    // Step 8: with no start at all, nothing is deleted;
                    // `[1, 2].splice()` emptied the array.
                    None if args.count == 0 => 0,
                    None => len - start,
                    Some(value) => {
                        let raw = Self::value_as_integer(&value);
                        if raw < 0 {
                            0
                        } else {
                            (raw as usize).min(len - start)
                        }
                    }
                };
                let removed_arr = self.array_species_result(module, arr_id, delete_count as u64)?;
                let mut items = Vec::new();
                let mut k = 2u32;
                while k < args.count {
                    items.push(self.builtin_arg(args, k)?.unwrap_or(Value::Undefined));
                    k += 1;
                }
                let items =
                    match self.splice_dense_array_in_place(arr_id, len, start, delete_count, items)? {
                        Ok(removed) => {
                            let removed_len = removed.len();
                            for (i, element) in removed.into_iter().enumerate() {
                                self.create_data_property_or_throw(
                                    removed_arr,
                                    i.to_string(),
                                    element,
                                )?;
                            }
                            self.set_object_property(
                                removed_arr,
                                "length".to_string(),
                                Value::Int(i64::try_from(removed_len).unwrap_or(i64::MAX)),
                            )?;
                            return Ok(Value::Object(removed_arr));
                        }
                        Err(items) => items,
                    };
                // ES2020 23.1.3.28 steps 11-18 in their order, so a Set or
                // DeletePropertyOrThrow that throws (a sealed, frozen or
                // non-extensible array) leaves exactly the writes before it
                // (bd-9vouw.477). A hole stays a hole in the removed array
                // and moves as a hole (its target is deleted).
                for k in 0..delete_count {
                    if let Some(element) = self.array_index_get(Some(module), arr_id, start + k)? {
                        self.create_data_property_or_throw(removed_arr, k.to_string(), element)?;
                    }
                }
                self.set_object_property(
                    removed_arr,
                    "length".to_string(),
                    Value::Int(i64::try_from(delete_count).unwrap_or(i64::MAX)),
                )?;
                let item_count = items.len();
                let new_len = len - delete_count + item_count;
                let was_dense = self.array_cache_is_dense(arr_id);
                let mut moved_hole = false;
                if item_count < delete_count {
                    // Step 15: move the tail down, then delete the top.
                    for k in start..len - delete_count {
                        self.array_move_element(
                            module,
                            arr_id,
                            k + delete_count,
                            k + item_count,
                            &mut moved_hole,
                        )?;
                    }
                    for k in (new_len..len).rev() {
                        self.array_delete_or_throw(arr_id, &k.to_string())?;
                    }
                } else if item_count > delete_count {
                    // Step 16: move the tail up, from the top. Its first
                    // write is a new top index, which a non-extensible
                    // array refuses before anything else changes.
                    for k in (start + 1..=len - delete_count).rev() {
                        self.array_move_element(
                            module,
                            arr_id,
                            k + delete_count - 1,
                            k + item_count - 1,
                            &mut moved_hole,
                        )?;
                    }
                }
                // Step 17: the items.
                for (offset, item) in items.into_iter().enumerate() {
                    self.set_object_property(arr_id, (start + offset).to_string(), item)?;
                }
                self.set_object_property(
                    arr_id,
                    "length".to_string(),
                    Value::Int(i64::try_from(new_len).unwrap_or(i64::MAX)),
                )?;
                self.refresh_dense_length_cache(arr_id, new_len, was_dense && !moved_hole);
                Ok(Value::Object(removed_arr))
            }
            BuiltinFunctionKind::ArrayToReversed => {
                // ES2023 23.1.3.33: return a reversed COPY; the receiver is left
                // unchanged (bd-ib0ue).
                let receiver = receiver.unwrap_or(Value::Undefined);
                let Value::Object(arr_id) = receiver else {
                    return Err(InterpreterError::TypeError {
                        expected: "array receiver for Array.prototype.toReversed".to_string(),
                        got: receiver.type_name().to_string(),
                    });
                };
                let len = self.array_like_length(arr_id)?;
                let result = self.alloc_array_with_prototype(None)?;
                for i in 0..len {
                    let element = self
                        .array_index_get(Some(module), arr_id, len - 1 - i)?
                        .unwrap_or(Value::Undefined);
                    self.set_object_property(result, i.to_string(), element)?;
                }
                self.set_object_property(
                    result,
                    "length".to_string(),
                    Value::Int(i64::try_from(len).unwrap_or(i64::MAX)),
                )?;
                Ok(Value::Object(result))
            }
            BuiltinFunctionKind::ArrayToSorted => {
                // ES2023 23.1.3.34: return a sorted COPY using the same ordering
                // as `sort` (optional comparator); receiver unchanged (bd-ib0ue).
                // Step 1: a comparator that is neither undefined nor callable
                // is a TypeError before the receiver's length is read; an
                // empty or one-element array never called it, so
                // `[].toSorted(null)` returned [] (bd-9vouw.456).
                let comparator = match self.builtin_arg(args, 0)? {
                    Some(Value::Undefined) | None => None,
                    Some(callback) if callback.is_callable() => Some(callback),
                    Some(other) => {
                        return Err(InterpreterError::TypeError {
                            expected: "a function or undefined comparator for Array.prototype.toSorted"
                                .to_string(),
                            got: format!("{} is not a function", other.type_name()),
                        });
                    }
                };
                let receiver = receiver.unwrap_or(Value::Undefined);
                let Value::Object(arr_id) = receiver else {
                    return Err(InterpreterError::TypeError {
                        expected: "array receiver for Array.prototype.toSorted".to_string(),
                        got: receiver.type_name().to_string(),
                    });
                };
                let len = self.array_like_length(arr_id)?;
                let mut elements = self.element_buffer(len)?;
                for index in 0..len {
                    elements.push(
                        self.array_index_get(Some(module), arr_id, index)?
                            .unwrap_or(Value::Undefined),
                    );
                }
                if let Some(comparator) = comparator {
                    // Insertion sort: keep the comparator's re-entrant call
                    // outside any closure borrowing `self` (mirrors `sort`).
                    for i in 1..elements.len() {
                        let mut j = i;
                        while j > 0 {
                            let ordering = self.sort_compare(
                                module,
                                &comparator,
                                &elements[j - 1],
                                &elements[j],
                            )?;
                            if ordering == std::cmp::Ordering::Greater {
                                elements.swap(j - 1, j);
                                j -= 1;
                            } else {
                                break;
                            }
                        }
                    }
                } else {
                    elements.sort_by_cached_key(Self::sort_utf16_key);
                }
                let result = self.alloc_array_with_prototype(None)?;
                for (index, element) in elements.into_iter().enumerate() {
                    self.set_object_property(result, index.to_string(), element)?;
                }
                self.set_object_property(
                    result,
                    "length".to_string(),
                    Value::Int(i64::try_from(len).unwrap_or(i64::MAX)),
                )?;
                Ok(Value::Object(result))
            }
            BuiltinFunctionKind::ArrayWith => {
                // ES2023 23.1.3.39: return a COPY with index `i` replaced by
                // `value`; negative `i` counts from the end; out-of-range throws
                // RangeError (bd-ib0ue).
                let receiver = receiver.unwrap_or(Value::Undefined);
                let Value::Object(arr_id) = receiver else {
                    return Err(InterpreterError::TypeError {
                        expected: "array receiver for Array.prototype.with".to_string(),
                        got: receiver.type_name().to_string(),
                    });
                };
                let len = self.array_like_length(arr_id)?;
                let relative =
                    Self::value_as_integer(&self.builtin_number_arg(module, args, 0)?.unwrap_or(Value::Undefined));
                let actual = if relative < 0 {
                    relative + len as i64
                } else {
                    relative
                };
                if actual < 0 || actual >= len as i64 {
                    return Err(InterpreterError::RangeError {
                        message: format!(
                            "Array.prototype.with: index {relative} is out of range for length {len}"
                        ),
                    });
                }
                let actual = actual as usize;
                let value = self.builtin_arg(args, 1)?.unwrap_or(Value::Undefined);
                let result = self.alloc_array_with_prototype(None)?;
                for i in 0..len {
                    let element = if i == actual {
                        value.clone()
                    } else {
                        self.array_index_get(Some(module), arr_id, i)?
                            .unwrap_or(Value::Undefined)
                    };
                    self.set_object_property(result, i.to_string(), element)?;
                }
                self.set_object_property(
                    result,
                    "length".to_string(),
                    Value::Int(i64::try_from(len).unwrap_or(i64::MAX)),
                )?;
                Ok(Value::Object(result))
            }
            BuiltinFunctionKind::ArrayToSpliced => {
                // ES2023 23.1.3.35: return a COPY with `splice(start, skipCount,
                // ...items)` applied; the receiver is unchanged and the NEW
                // array (not the removed elements) is returned (bd-ib0ue).
                let receiver = receiver.unwrap_or(Value::Undefined);
                let Value::Object(arr_id) = receiver else {
                    return Err(InterpreterError::TypeError {
                        expected: "array receiver for Array.prototype.toSpliced".to_string(),
                        got: receiver.type_name().to_string(),
                    });
                };
                let len = self.array_like_length(arr_id)?;
                let start = match self.builtin_number_arg(module, args, 0)? {
                    Some(value) => Self::clamp_relative_index(Self::value_as_integer(&value), len),
                    None => 0,
                };
                // Steps 8-10: no start skips nothing (`a.toSpliced()` is a
                // copy; it returned []), a start alone skips to the end.
                let delete_count = if args.count == 0 {
                    0
                } else {
                    match self.builtin_number_arg(module, args, 1)? {
                        None => len - start,
                        Some(value) => {
                            let raw = Self::value_as_integer(&value);
                            if raw < 0 {
                                0
                            } else {
                                (raw as usize).min(len - start)
                            }
                        }
                    }
                };
                let mut items = Vec::new();
                let mut k = 2u32;
                while k < args.count {
                    items.push(self.builtin_arg(args, k)?.unwrap_or(Value::Undefined));
                    k += 1;
                }
                // Steps 15-18: the skipped elements are never read (an accessor
                // there must not run).
                let mut elements: Vec<Value> =
                    self.element_buffer(len - delete_count + items.len())?;
                for i in (0..start).chain(start + delete_count..len) {
                    if i == start + delete_count {
                        elements.append(&mut items);
                    }
                    elements.push(
                        self.array_index_get(Some(module), arr_id, i)?
                            .unwrap_or(Value::Undefined),
                    );
                }
                elements.append(&mut items);
                let new_len = elements.len();
                let result = self.alloc_array_with_prototype(None)?;
                for (i, element) in elements.into_iter().enumerate() {
                    self.set_object_property(result, i.to_string(), element)?;
                }
                self.set_object_property(
                    result,
                    "length".to_string(),
                    Value::Int(i64::try_from(new_len).unwrap_or(i64::MAX)),
                )?;
                Ok(Value::Object(result))
            }
            // Map/Set receiver-aware methods (bd-juodx). The receiver is the
            // collection object; `.size` is a plain data property handled by the
            // normal property walk, so it is not a method here.
            BuiltinFunctionKind::MapSet => {
                let receiver = receiver.unwrap_or(Value::Undefined);
                let map_id = self.collection_receiver(&receiver, "Map", "set")?;
                let key = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
                let value = self.builtin_arg(args, 1)?.unwrap_or(Value::Undefined);
                self.map_collection_set(map_id, key, value)
            }
            BuiltinFunctionKind::MapGet => {
                let receiver = receiver.unwrap_or(Value::Undefined);
                let map_id = self.collection_receiver(&receiver, "Map", "get")?;
                let key = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
                Ok(self.collection_get(map_id, "Map", &key))
            }
            BuiltinFunctionKind::MapHas => {
                let receiver = receiver.unwrap_or(Value::Undefined);
                let map_id = self.collection_receiver(&receiver, "Map", "has")?;
                let key = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
                Ok(Value::Bool(self.collection_has(
                    map_id,
                    "Map",
                    &key,
                )))
            }
            BuiltinFunctionKind::MapDelete => {
                let receiver = receiver.unwrap_or(Value::Undefined);
                let map_id = self.collection_receiver(&receiver, "Map", "delete")?;
                let key = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
                Ok(Value::Bool(self.collection_delete(
                    map_id,
                    "Map",
                    &key,
                )?))
            }
            BuiltinFunctionKind::SetAdd => {
                let receiver = receiver.unwrap_or(Value::Undefined);
                let set_id = self.collection_receiver(&receiver, "Set", "add")?;
                let value = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
                self.set_collection_add(set_id, value)
            }
            BuiltinFunctionKind::SetHas => {
                let receiver = receiver.unwrap_or(Value::Undefined);
                let set_id = self.collection_receiver(&receiver, "Set", "has")?;
                let value = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
                Ok(Value::Bool(
                    self.collection_has(set_id, "Set", &value),
                ))
            }
            BuiltinFunctionKind::SetDelete => {
                let receiver = receiver.unwrap_or(Value::Undefined);
                let set_id = self.collection_receiver(&receiver, "Set", "delete")?;
                let value = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
                Ok(Value::Bool(self.collection_delete(
                    set_id, "Set", &value,
                )?))
            }
            BuiltinFunctionKind::MapClear => {
                let receiver = receiver.unwrap_or(Value::Undefined);
                let map_id = self.collection_receiver(&receiver, "Map", "clear")?;
                self.collection_clear(map_id, "Map")
            }
            BuiltinFunctionKind::SetClear => {
                let receiver = receiver.unwrap_or(Value::Undefined);
                let set_id = self.collection_receiver(&receiver, "Set", "clear")?;
                self.collection_clear(set_id, "Set")
            }
            BuiltinFunctionKind::PromiseThenFinally | BuiltinFunctionKind::PromiseCatchFinally => {
                self.promise_finally_step(module, builtin, args)
            }
            BuiltinFunctionKind::ArrayFromAsyncFulfilled
            | BuiltinFunctionKind::ArrayFromAsyncRejected => {
                self.array_from_async_step(module, builtin, args)
            }
            BuiltinFunctionKind::PromiseFinallyValueThunk => {
                self.promise_finally_bound_property(builtin, "__value")
            }
            BuiltinFunctionKind::PromiseFinallyThrower => {
                let reason = self.promise_finally_bound_property(builtin, "__value")?;
                Err(self.throw_guest_value(reason, Label::Public)?)
            }
            // ES2020 20.4.2 step 1: called rather than constructed, Date
            // ignores its arguments and returns ToDateString of the current
            // time, as `new Date().toString()` would.
            BuiltinFunctionKind::DateConstructor => {
                let no_arguments = RegRange {
                    start: args.start,
                    count: 0,
                };
                let now = self.dispatch_builtin_hostcall("builtin:Date", no_arguments, Some(module))?;
                self.date_prototype_method(Some(module), "toString", now, no_arguments)
            }
            BuiltinFunctionKind::PromiseConstructor => self.construct_promise(module, args),
            BuiltinFunctionKind::EventEmitterConstructor => {
                self.dispatch_builtin_hostcall("builtin:EventEmitter", args, Some(module))
            }
            BuiltinFunctionKind::StandardConstructor => {
                self.call_standard_constructor(module, builtin, args)
            }
            BuiltinFunctionKind::StaticHostcall => {
                // bd-9vouw.94/172: `C.from(...)`, `C.of(...)`, and
                // `C.fromAsync(...)` with a constructor
                // `C` other than %Array% (a subclass of Array inherits them;
                // `Array.from.call(Object, ...)`) construct a C (ES2020
                // 22.1.2.1 steps 5.a and 12.a, 22.1.2.3 step 4), in the
                // specification's order (bd-9vouw.361).
                let array_static = matches!(
                    &*builtin.module_specifier,
                    "builtin:ArrayFrom" | "builtin:ArrayOf" | "builtin:ArrayFromAsync"
                );
                if array_static
                    && let Some(constructor) = receiver.clone()
                    && !Self::is_intrinsic_array_constructor(&constructor)
                    && self.is_constructible_value(&constructor)
                {
                    let tag = builtin.module_specifier.to_string();
                    let instruction_index = u32::try_from(self.ip).unwrap_or(u32::MAX);
                    check_hostcall_capability_gate(self, &tag, instruction_index)?;
                    if tag == "builtin:ArrayFrom" {
                        self.array_from_with_constructor(module, args, constructor)
                    } else if tag == "builtin:ArrayFromAsync" {
                        self.array_from_async_with_constructor(module, args, constructor)
                    } else {
                        self.array_of_with_constructor(module, args, constructor)
                    }
                } else {
                    self.call_static_hostcall(module, builtin, args)
                }
            }
            BuiltinFunctionKind::NativeHttpFunction => {
                let (tag, _, _) = native_http_function_metadata(&builtin.module_specifier)
                    .ok_or_else(|| InterpreterError::TypeError {
                        expected: "known native HTTP function".to_string(),
                        got: builtin.module_specifier.to_string(),
                    })?;
                let inputs = self.join_arg_range_with_object_mutation_label(args)?;
                let input_bytes = Self::estimate_label_bytes(&inputs);
                self.apply_memory_component_delta(0, input_bytes)?;
                // This value call is the underlying hostcall, so it owns one
                // builtin frame. Keep the input label charged until the
                // delegated publication has copied its winner.
                self.gc_exit_builtin();
                let result = self.dispatch_builtin_hostcall(tag, args, Some(module));
                self.gc_enter_builtin();
                let result = result.and_then(|value| {
                    self.publish_delegated_hostcall_result_label(tag, &inputs)?;
                    Ok(value)
                });
                drop(inputs);
                self.estimated_memory_bytes =
                    self.estimated_memory_bytes.saturating_sub(input_bytes);
                result
            }
            BuiltinFunctionKind::NativeChildProcessFunction => {
                let (operation, _, _) =
                    native_child_process_function_metadata(&builtin.module_specifier)
                        .ok_or_else(|| InterpreterError::TypeError {
                            expected: "known native child_process function".to_string(),
                            got: builtin.module_specifier.to_string(),
                        })?;
                let inputs = self.join_arg_range_with_object_mutation_label(args)?;
                let input_bytes = Self::estimate_label_bytes(&inputs);
                self.apply_memory_component_delta(0, input_bytes)?;
                let result = self.dispatch_process_spawn_operation(operation, args);
                let result = result.and_then(|value| {
                    self.publish_delegated_hostcall_result_label("process_spawn", &inputs)?;
                    Ok(value)
                });
                drop(inputs);
                self.estimated_memory_bytes =
                    self.estimated_memory_bytes.saturating_sub(input_bytes);
                result
            }
            BuiltinFunctionKind::PrototypeGetter => {
                self.call_prototype_getter(module, builtin, receiver.unwrap_or(Value::Undefined))
            }
            BuiltinFunctionKind::ObjectProtoSetter => {
                let proto = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
                self.object_proto_setter_call(
                    Some(module),
                    receiver.unwrap_or(Value::Undefined),
                    proto,
                )
            }
            BuiltinFunctionKind::ErrorPrototypeToString => {
                self.error_prototype_to_string(module, receiver.unwrap_or(Value::Undefined))
            }
            BuiltinFunctionKind::ArrayBufferSlice => {
                self.array_buffer_slice(module, receiver.unwrap_or(Value::Undefined), args, false)
            }
            BuiltinFunctionKind::AtomicsMethod => self.atomics_method_call(module, builtin, args),
            BuiltinFunctionKind::SharedArrayBufferMethod => {
                let receiver = receiver.unwrap_or(Value::Undefined);
                if builtin.module_specifier.0.as_deref() == Some("grow") {
                    return self.shared_array_buffer_grow(module, receiver, args);
                }
                self.array_buffer_slice(module, receiver, args, true)
            }
            BuiltinFunctionKind::ArrayBufferMethod => {
                let method = builtin
                    .module_specifier
                    .0
                    .as_deref()
                    .unwrap_or_default()
                    .to_string();
                self.array_buffer_method(module, &method, receiver.unwrap_or(Value::Undefined), args)
            }
            BuiltinFunctionKind::WeakRefDeref => {
                self.weak_ref_deref(&receiver.unwrap_or(Value::Undefined))
            }
            BuiltinFunctionKind::IntlConstructor => {
                let service = builtin
                    .module_specifier
                    .0
                    .as_deref()
                    .unwrap_or_default()
                    .to_string();
                self.construct_intl_service(module, &service, args)
            }
            BuiltinFunctionKind::IntlMethod => self.intl_method(module, builtin, args),
            BuiltinFunctionKind::IntlGetCanonicalLocales => {
                self.intl_get_canonical_locales(args)
            }
            BuiltinFunctionKind::FinalizationRegistryMethod => {
                let method = builtin
                    .module_specifier
                    .0
                    .as_deref()
                    .unwrap_or_default()
                    .to_string();
                self.finalization_registry_method(
                    &method,
                    receiver.unwrap_or(Value::Undefined),
                    args,
                )
            }
            BuiltinFunctionKind::ErrorCaptureStackTrace => {
                // V8 Error.captureStackTrace(target[, constructorOpt]): give
                // `target` a non-enumerable `stack` whose first line is
                // Error.prototype.toString of the target ("Error" for a
                // plain object, "Name: message" otherwise) above the current
                // frames. A non-object target is a TypeError, as in V8.
                let target = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
                let Value::Object(object_id) = target else {
                    return Err(InterpreterError::TypeError {
                        expected: "object target for Error.captureStackTrace".to_string(),
                        got: target.type_name().to_string(),
                    });
                };
                let header = match self.error_prototype_to_string(module, Value::Object(object_id))? {
                    Value::Str(header) => header.to_string(),
                    other => self.value_to_string(&other),
                };
                let frames = self.format_stack_trace();
                let stack = if frames.is_empty() {
                    header
                } else {
                    format!("{header}\n{frames}")
                };
                self.set_object_property(object_id, "stack".to_string(), Value::str(stack))?;
                self.set_own_property_attributes(
                    object_id,
                    &RuntimePropertyKey::String(JsString::from("stack")),
                    NON_ENUMERABLE_DATA_ATTRIBUTES,
                )?;
                Ok(Value::Undefined)
            }
            BuiltinFunctionKind::DateNow => {
                self.dispatch_builtin_hostcall("builtin:DateNow", args, Some(module))
            }
            BuiltinFunctionKind::MathAbs => {
                self.dispatch_builtin_hostcall("builtin:MathAbs", args, Some(module))
            }
            BuiltinFunctionKind::MathCeil => {
                self.dispatch_builtin_hostcall("builtin:MathCeil", args, Some(module))
            }
            BuiltinFunctionKind::MathFloor => {
                self.dispatch_builtin_hostcall("builtin:MathFloor", args, Some(module))
            }
            BuiltinFunctionKind::MathRound => {
                self.dispatch_builtin_hostcall("builtin:MathRound", args, Some(module))
            }
            BuiltinFunctionKind::MathMax => {
                self.dispatch_builtin_hostcall("builtin:MathMax", args, Some(module))
            }
            BuiltinFunctionKind::MathMin => {
                self.dispatch_builtin_hostcall("builtin:MathMin", args, Some(module))
            }
            BuiltinFunctionKind::MathRandom => {
                self.dispatch_builtin_hostcall("builtin:MathRandom", args, Some(module))
            }
            BuiltinFunctionKind::MathPow => {
                self.dispatch_builtin_hostcall("builtin:MathPow", args, Some(module))
            }
            BuiltinFunctionKind::MathSqrt => {
                self.dispatch_builtin_hostcall("builtin:MathSqrt", args, Some(module))
            }
            BuiltinFunctionKind::MathSin => {
                self.dispatch_builtin_hostcall("builtin:MathSin", args, Some(module))
            }
            BuiltinFunctionKind::MathCos => {
                self.dispatch_builtin_hostcall("builtin:MathCos", args, Some(module))
            }
            BuiltinFunctionKind::MathLog => {
                self.dispatch_builtin_hostcall("builtin:MathLog", args, Some(module))
            }
            BuiltinFunctionKind::MathExp => {
                self.dispatch_builtin_hostcall("builtin:MathExp", args, Some(module))
            }
            BuiltinFunctionKind::MathTan => {
                self.dispatch_builtin_hostcall("builtin:MathTan", args, Some(module))
            }
            BuiltinFunctionKind::MathTrunc => {
                self.dispatch_builtin_hostcall("builtin:MathTrunc", args, Some(module))
            }
            BuiltinFunctionKind::MathSign => {
                self.dispatch_builtin_hostcall("builtin:MathSign", args, Some(module))
            }
            BuiltinFunctionKind::MathAtan2 => {
                self.dispatch_builtin_hostcall("builtin:MathAtan2", args, Some(module))
            }
            BuiltinFunctionKind::MathAsin => {
                self.dispatch_builtin_hostcall("builtin:MathAsin", args, Some(module))
            }
            BuiltinFunctionKind::MathAcos => {
                self.dispatch_builtin_hostcall("builtin:MathAcos", args, Some(module))
            }
            BuiltinFunctionKind::MathHypot => {
                self.dispatch_builtin_hostcall("builtin:MathHypot", args, Some(module))
            }
            BuiltinFunctionKind::MathImul => {
                self.dispatch_builtin_hostcall("builtin:MathImul", args, Some(module))
            }
            BuiltinFunctionKind::MathAtan => {
                self.dispatch_builtin_hostcall("builtin:MathAtan", args, Some(module))
            }
            BuiltinFunctionKind::MathLog10 => {
                self.dispatch_builtin_hostcall("builtin:MathLog10", args, Some(module))
            }
            BuiltinFunctionKind::MathLog2 => {
                self.dispatch_builtin_hostcall("builtin:MathLog2", args, Some(module))
            }
            BuiltinFunctionKind::MathCbrt => {
                self.dispatch_builtin_hostcall("builtin:MathCbrt", args, Some(module))
            }
            BuiltinFunctionKind::MathClz32 => {
                self.dispatch_builtin_hostcall("builtin:MathClz32", args, Some(module))
            }
            BuiltinFunctionKind::MathFround => {
                self.dispatch_builtin_hostcall("builtin:MathFround", args, Some(module))
            }
            BuiltinFunctionKind::MathAcosh => {
                self.dispatch_builtin_hostcall("builtin:MathAcosh", args, Some(module))
            }
            BuiltinFunctionKind::MathAsinh => {
                self.dispatch_builtin_hostcall("builtin:MathAsinh", args, Some(module))
            }
            BuiltinFunctionKind::MathAtanh => {
                self.dispatch_builtin_hostcall("builtin:MathAtanh", args, Some(module))
            }
            BuiltinFunctionKind::MathSinh
            | BuiltinFunctionKind::MathCosh
            | BuiltinFunctionKind::MathTanh
            | BuiltinFunctionKind::MathExpm1
            | BuiltinFunctionKind::MathLog1p => {
                // ToNumber of the argument (ToPrimitive first), then the
                // correctly rounded libm function, as the other Math ones.
                let x = if args.count == 0 {
                    f64::NAN
                } else {
                    let number = self.math_argument_value(args.start, Some(module))?;
                    Self::coerce_to_float(&number).unwrap_or(f64::NAN)
                };
                let result = match builtin.kind {
                    BuiltinFunctionKind::MathSinh => x.sinh(),
                    BuiltinFunctionKind::MathCosh => x.cosh(),
                    BuiltinFunctionKind::MathTanh => x.tanh(),
                    BuiltinFunctionKind::MathExpm1 => x.exp_m1(),
                    _ => x.ln_1p(),
                };
                Ok(Value::Float(Float64::new(result)))
            }
            BuiltinFunctionKind::DateGetTime => {
                // `Date.prototype.getTime()` — the receiver's [[DateValue]];
                // thisTimeValue throws for a receiver that is not a Date, as
                // every other Date.prototype method does (bd-9vouw.150).
                let receiver = receiver.unwrap_or(Value::Undefined);
                let time = match &receiver {
                    Value::Object(date_id) => self
                        .heap
                        .get(date_id.0 as usize)
                        .and_then(HeapObject::date_time),
                    _ => None,
                };
                let Some(time) = time else {
                    return Err(InterpreterError::TypeError {
                        expected: "Date receiver for Date.prototype.getTime".to_string(),
                        got: receiver.type_name().to_string(),
                    });
                };
                Ok(Value::Float(Float64::new(time)))
            }
            BuiltinFunctionKind::UrlSearchParamsGet => {
                let object_id = self.url_search_params_receiver_id(receiver, "get")?;
                let name_value = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
                let name_bound = self.url_value_to_string_upper_bound(&name_value);
                self.check_temporary_memory_budget(
                    name_bound.saturating_add(Self::estimate_url_search_params_state_bytes(
                        &self.url_search_params[&object_id],
                    )),
                )?;
                let name = self.value_to_string(&name_value);
                let value = self.url_search_params[&object_id]
                    .pairs
                    .iter()
                    .find_map(|(candidate, value)| (candidate == &name).then(|| value.clone()))
                    .map(Value::str)
                    .unwrap_or(Value::Null);
                Ok(value)
            }
            BuiltinFunctionKind::UrlSearchParamsHas => {
                let object_id = self.url_search_params_receiver_id(receiver, "has")?;
                let name_value = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
                self.check_temporary_memory_budget(
                    self.url_value_to_string_upper_bound(&name_value),
                )?;
                let name = self.value_to_string(&name_value);
                Ok(Value::Bool(
                    self.url_search_params[&object_id]
                        .pairs
                        .iter()
                        .any(|(candidate, _)| candidate == &name),
                ))
            }
            BuiltinFunctionKind::UrlSearchParamsGetAll => {
                let object_id = self.url_search_params_receiver_id(receiver, "getAll")?;
                let name_value = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
                let name_bound = self.url_value_to_string_upper_bound(&name_value);
                self.check_temporary_memory_budget(
                    name_bound.saturating_add(
                        Self::estimate_url_search_params_state_bytes(
                            &self.url_search_params[&object_id],
                        )
                        .saturating_mul(2),
                    ),
                )?;
                let name = self.value_to_string(&name_value);
                let values: Vec<Value> = self.url_search_params[&object_id]
                    .pairs
                    .iter()
                    .filter(|&(candidate, _)| candidate == &name)
                    .map(|(_, value)| Value::str(value))
                    .collect();
                Ok(Value::Object(self.alloc_array_from_values(&values)?))
            }
            BuiltinFunctionKind::UrlSearchParamsAppend
            | BuiltinFunctionKind::UrlSearchParamsSort
            | BuiltinFunctionKind::UrlSearchParamsDelete
            | BuiltinFunctionKind::UrlSearchParamsSet => {
                let object_id =
                    self.url_search_params_receiver_id(receiver, builtin.display_name())?;
                let mutation = match builtin.kind {
                    BuiltinFunctionKind::UrlSearchParamsAppend => {
                        let name_value =
                            self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
                        let value_value =
                            self.builtin_arg(args, 1)?.unwrap_or(Value::Undefined);
                        self.check_temporary_memory_budget(
                            self.url_value_to_string_upper_bound(&name_value)
                                .saturating_add(
                                    self.url_value_to_string_upper_bound(&value_value),
                                ),
                        )?;
                        UrlSearchParamsMutation::Append(
                            self.value_to_string(&name_value),
                            self.value_to_string(&value_value),
                        )
                    }
                    BuiltinFunctionKind::UrlSearchParamsSort => UrlSearchParamsMutation::Sort,
                    BuiltinFunctionKind::UrlSearchParamsDelete => {
                        let name_value =
                            self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
                        self.check_temporary_memory_budget(
                            self.url_value_to_string_upper_bound(&name_value),
                        )?;
                        UrlSearchParamsMutation::Delete(self.value_to_string(&name_value))
                    }
                    BuiltinFunctionKind::UrlSearchParamsSet => {
                        let name_value =
                            self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
                        let value_value =
                            self.builtin_arg(args, 1)?.unwrap_or(Value::Undefined);
                        self.check_temporary_memory_budget(
                            self.url_value_to_string_upper_bound(&name_value)
                                .saturating_add(
                                    self.url_value_to_string_upper_bound(&value_value),
                                ),
                        )?;
                        UrlSearchParamsMutation::Set(
                            self.value_to_string(&name_value),
                            self.value_to_string(&value_value),
                        )
                    }
                    _ => unreachable!("URLSearchParams mutation arm was filtered"),
                };
                let args_label = self.join_arg_range_label(args)?;
                let state_label = self
                    .url_state_label_ref(object_id)
                    .unwrap_or(&Label::Public);
                let mutation_label =
                    self.join_owned_label_with_temporary_budget(args_label, state_label)?;
                self.mutate_url_search_params(object_id, mutation, &mutation_label)?;
                Ok(Value::Undefined)
            }
            BuiltinFunctionKind::UrlSearchParamsToString => {
                let object_id = self.url_search_params_receiver_id(receiver, "toString")?;
                let pairs = &self.url_search_params[&object_id].pairs;
                self.check_temporary_memory_budget(
                    Self::url_serialization_upper_bound(pairs).saturating_mul(2),
                )?;
                Ok(Value::str(Self::serialize_url_search_params(pairs)))
            }
            BuiltinFunctionKind::FsStatsIsFile
            | BuiltinFunctionKind::FsStatsIsDirectory
            | BuiltinFunctionKind::FsEntryIsSymbolicLink
            | BuiltinFunctionKind::FsDirentIsFile
            | BuiltinFunctionKind::FsDirentIsDirectory => {
                let receiver = receiver.unwrap_or(Value::Undefined);
                let Value::Object(object_id) = receiver else {
                    return Ok(Value::Bool(false));
                };
                let property = match builtin.kind {
                    BuiltinFunctionKind::FsStatsIsFile
                    | BuiltinFunctionKind::FsDirentIsFile => "__isFile",
                    BuiltinFunctionKind::FsStatsIsDirectory
                    | BuiltinFunctionKind::FsDirentIsDirectory => "__isDirectory",
                    BuiltinFunctionKind::FsEntryIsSymbolicLink => "__isSymbolicLink",
                    _ => unreachable!("filesystem predicate arm only contains fs predicates"),
                };
                let value = self
                    .heap
                    .get(object_id.0 as usize)
                    .and_then(|object| object.properties.get(property))
                    .and_then(|value| match value {
                        Value::Bool(value) => Some(*value),
                        _ => None,
                    })
                    .unwrap_or(false);
                Ok(Value::Bool(value))
            }
            BuiltinFunctionKind::HttpClientRequestWrite => {
                self.http_client_write(receiver, args, receiver_register)
            }
            BuiltinFunctionKind::HttpClientRequestEnd => {
                self.http_client_end(receiver, args, receiver_register)
            }
            BuiltinFunctionKind::HttpClientRequestSetHeader => {
                self.http_set_header(receiver, args, true, receiver_register)
            }
            BuiltinFunctionKind::HttpIncomingMessageSetEncoding => {
                self.http_incoming_set_encoding(receiver, args)
            }
            BuiltinFunctionKind::HttpIncomingMessageResume => {
                self.http_incoming_resume(receiver)
            }
            BuiltinFunctionKind::HttpServerResponseSetHeader => {
                self.http_set_header(receiver, args, false, receiver_register)
            }
            BuiltinFunctionKind::HttpServerResponseGetHeader => {
                self.http_get_header(receiver, args)
            }
            BuiltinFunctionKind::HttpServerResponseHasHeader => {
                self.http_has_header(receiver, args)
            }
            BuiltinFunctionKind::HttpServerResponseRemoveHeader => {
                self.http_remove_header(receiver, args)
            }
            BuiltinFunctionKind::HttpServerResponseWriteHead => {
                self.http_write_head(receiver, args)
            }
            BuiltinFunctionKind::HttpServerResponseWrite => {
                self.http_response_write(receiver, args)
            }
            BuiltinFunctionKind::HttpServerResponseEnd => {
                self.http_response_end(receiver, args)
            }
            BuiltinFunctionKind::ClientRequestWrite => {
                // bd-3894s slice (2b): `req.write(chunk)` — append the chunk to the
                // receiver ClientRequest's writable `__body` buffer; the egress is
                // deferred until `.end()`. Returns `true` (the Node writable-stream
                // backpressure signal; our buffered model never applies
                // backpressure). A non-string/number chunk contributes nothing (a
                // faithful Buffer/Uint8Array body is a follow-up).
                let receiver = receiver.unwrap_or(Value::Undefined);
                let Value::Object(req_id) = receiver else {
                    return Err(InterpreterError::TypeError {
                        expected: "ClientRequest receiver for ClientRequest.prototype.write"
                            .to_string(),
                        got: receiver.type_name().to_string(),
                    });
                };
                let chunk_label =
                    self.writable_invocation_label_with_receiver(args, receiver_register)?;
                let chunk = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
                self.append_legacy_client_request_body(req_id, &chunk, &chunk_label)?;
                Ok(Value::Bool(true))
            }
            BuiltinFunctionKind::ClientRequestEnd => {
                // bd-3894s slice (2b)+(2c)+(2d): `req.end([chunk][, cb])` — append an
                // optional final chunk, then perform the deferred `net:request` egress
                // with the method/headers captured at construction and the accumulated
                // body. After the egress the response is delivered to the
                // `http.request(url[, opts], cb)` response callback (`__response_cb`,
                // slice 2c) AND to every `req.on('response', …)` listener (slice 2d),
                // and the `IncomingMessage` readable stream is driven (`'data'`/`'end'`
                // on later turns). A trailing closure passed to `.end()` ITSELF is the
                // `end(cb)` FINISH callback (distinct from the response callback),
                // fired once the request is sent. A denied/failed egress fires the
                // request's `'error'` listeners instead of any response. With no async
                // consumer `.end()` returns the response synchronously (slice 4).
                // Idempotent: a second `.end()` is a no-op that returns `undefined`.
                let receiver = receiver.unwrap_or(Value::Undefined);
                let Value::Object(req_id) = receiver else {
                    return Err(InterpreterError::TypeError {
                        expected: "ClientRequest receiver for ClientRequest.prototype.end"
                            .to_string(),
                        got: receiver.type_name().to_string(),
                    });
                };
                if self.heap.get(req_id.0 as usize).is_none_or(|request| {
                    matches!(request.properties.get("__ended"), Some(Value::Bool(true)))
                }) {
                    return Ok(Value::Undefined);
                }
                // Construction authorized a request object, not a future
                // effect. Recheck the live membrane before appending the final
                // chunk or consuming the request so containment preserves a
                // retryable prefix and cannot publish to the host provider.
                check_hostcall_capability_gate(self, "net:request", self.ip as u32)?;
                let end_label =
                    self.writable_invocation_label_with_receiver(args, receiver_register)?;
                // bd-3894s slice (2d): `req.end([data][, cb])` — a trailing closure is
                // the `end(cb)` FINISH callback (fired once the request is sent), NOT a
                // body chunk; a leading non-closure arg is the final body chunk
                // (`end(data)`). Detect the finish callback from the last arg and
                // append any leading data chunk to the writable `__body`.
                let arg0 = self.builtin_arg(args, 0)?;
                let arg1 = self.builtin_arg(args, 1)?;
                // The finish callback is the last closure argument (`end(cb)` or
                // `end(data, cb)`); the or-pattern prefers the arg1 binding when both
                // are closures.
                let finish_cb: Option<u32> = match (&arg0, &arg1) {
                    (_, Some(Value::Closure(cid))) | (Some(Value::Closure(cid)), _) => Some(*cid),
                    _ => None,
                };
                if let Some(chunk) = arg0.as_ref()
                    && !matches!(chunk, Value::Closure(_))
                {
                    self.append_legacy_client_request_body(req_id, chunk, &end_label)?;
                }
                self.join_object_mutation_label(req_id, &end_label)?;
                let reachable_request_label = self.process_dynamic_value_label(
                    &Value::Object(req_id),
                    &mut BTreeSet::new(),
                );
                let request_label = self.join_owned_label_with_temporary_budget(
                    end_label,
                    &reachable_request_label,
                )?;
                let response_label = hostcall_result_contract("net:request")
                    .result_label(&request_label, None);
                // Capture the request state (immutable reads) before the mutable
                // egress. `None` => already ended (idempotent no-op).
                let req_index = req_id.0 as usize;
                let captured = {
                    let Some(req) = self.heap.get(req_index) else {
                        return Ok(Value::Undefined);
                    };
                    if matches!(req.properties.get("__ended"), Some(Value::Bool(true))) {
                        None
                    } else {
                        let url = match req.properties.get("__url") {
                            Some(Value::Str(s)) => s.to_string(),
                            _ => String::new(),
                        };
                        let method = match req.properties.get("__method") {
                            Some(Value::Str(s)) => s.to_string(),
                            _ => "GET".to_string(),
                        };
                        let headers: Vec<(String, String)> = match req.properties.get("__headers") {
                            Some(Value::Object(hid)) => self
                                .heap
                                .get(hid.0 as usize)
                                .map(|h| {
                                    h.properties
                                        .iter()
                                        .filter_map(|(name, value)| {
                                            Self::net_header_value(value).map(|v| (name.clone(), v))
                                        })
                                        .collect()
                                })
                                .unwrap_or_default(),
                            _ => Vec::new(),
                        };
                        let body_str = match req.properties.get("__body") {
                            Some(Value::Str(s)) => {
                                if s.len() > MAX_HTTP_BODY_BYTES {
                                    return Err(InterpreterError::RangeError {
                                        message: format!(
                                            "HTTP request body exceeds {MAX_HTTP_BODY_BYTES} bytes"
                                        ),
                                    });
                                }
                                self.check_temporary_memory_budget(
                                    u64::try_from(s.len())
                                        .unwrap_or(u64::MAX)
                                        .saturating_mul(3)
                                        .saturating_add(64 * 1024),
                                )?;
                                s.to_string()
                            }
                            _ => String::new(),
                        };
                        // bd-3894s slice (2c): the response callback captured by
                        // `http.request(url[, opts], cb)` at construction. Delivered
                        // `cb(res)` below, after the deferred egress produces the
                        // response (on the first `.end()` only).
                        let response_cb = match req.properties.get("__response_cb") {
                            Some(Value::Closure(cid)) => Some(*cid),
                            _ => None,
                        };
                        Some((url, method, headers, body_str, response_cb))
                    }
                };
                let Some((url, method, headers, body_str, response_cb)) = captured else {
                    return Ok(Value::Undefined);
                };
                let body = if body_str.is_empty() {
                    None
                } else {
                    Some(body_str.into_bytes())
                };
                if !request_label.can_flow_to(&Label::Public) {
                    self.record_deferred_network_ifc_denial(
                        &url,
                        &method,
                        &headers,
                        body.as_deref(),
                    )?;
                    // A missing or mismatched evidence sink is a failed refusal,
                    // not a consumed request. Only commit the one-shot state after
                    // the typed denial has been accepted by the configured
                    // journal or transcript.
                    self.set_object_property(req_id, "__ended".to_string(), Value::Bool(true))?;
                    let err = self.build_request_error_value()?;
                    self.schedule_http_task(PendingHttpTask::EmitLegacyEvent {
                        target: req_id,
                        event: "error".to_string(),
                        arguments: vec![err],
                        leading_callback: None,
                        label: response_label,
                    })?;
                    return Ok(Value::Undefined);
                }
                // Mark ended BEFORE live egress so a re-entrant `.end()` is a no-op.
                self.set_object_property(req_id, "__ended".to_string(), Value::Bool(true))?;
                let response = self.perform_net_request_effect(url, method, headers, body)?;
                match response {
                    Value::Object(rid) => {
                        // bd-3894s slice (2d): the request's own event
                        // listeners, registered synchronously before `.end()`.
                        // Retain the logical event until its I/O turn so once
                        // wrappers are consumed there, with their stable identity,
                        // captured emitter receiver, and removeListener ordering.
                        let has_response_consumers = !self
                            .event_listener_records_for(req_id, "response")
                            .is_empty()
                            || self
                                .event_promise_waiters
                                .get(&req_id)
                                .and_then(|events| events.get(&RuntimePropertyKey::from("response")))
                                .is_some_and(|waiters| !waiters.is_empty());
                        // bd-3894s slice (2c)+(2d): deliver the response to the
                        // `http.request(url[, opts], cb)` callback AND to every
                        // `req.on('response', …)` listener on the next event-loop turn.
                        // The `end(cb)` finish callback (request sent) fires first.
                        if let Some(cid) = finish_cb {
                            self.schedule_io_callback_with_label(
                                cid,
                                Vec::new(),
                                response_label.clone(),
                            )?;
                        }
                        self.schedule_http_task(PendingHttpTask::EmitLegacyEvent {
                            target: req_id,
                            event: "response".to_string(),
                            arguments: vec![Value::Object(rid)],
                            leading_callback: response_cb,
                            label: response_label.clone(),
                        })?;
                        // Drive the `IncomingMessage` readable stream (`'data'`/`'end'`)
                        // after those deliveries (higher registration seq => later turn
                        // => the `res.on('data'|'end', …)` listeners they register
                        // exist). Scheduled unconditionally for a real response so a
                        // synchronous `const res = http.request(url).end(); res.on(...)`
                        // also streams.
                        self.schedule_stream_emission(
                            rid,
                            StreamEventPhase::Data,
                            response_label.clone(),
                        )?;
                        // An async consumer (response callback / `'response'` listener /
                        // finish callback) makes `.end()` evaluate to `undefined`; with
                        // none, the response is returned synchronously (slice-4 model).
                        if response_cb.is_some()
                            || has_response_consumers
                            || finish_cb.is_some()
                        {
                            Ok(Value::Undefined)
                        } else {
                            self.replace_pending_hostcall_result_label(Some(response_label))?;
                            Ok(Value::Object(rid))
                        }
                    }
                    _ => {
                        // Denied/failed egress: surface it to the request's `'error'`
                        // listeners (deferred) instead of firing any response/data/end.
                        // The signed DENIED `EffectReceipt` is already recorded.
                        let err = self.build_request_error_value()?;
                        self.schedule_http_task(PendingHttpTask::EmitLegacyEvent {
                            target: req_id,
                            event: "error".to_string(),
                            arguments: vec![err],
                            leading_callback: None,
                            label: response_label,
                        })?;
                        Ok(Value::Undefined)
                    }
                }
            }
            BuiltinFunctionKind::EmitterOn => {
                let receiver = receiver.unwrap_or(Value::Undefined);
                let Value::Object(target_id) = receiver else {
                    return Err(InterpreterError::TypeError {
                        expected: "EventEmitter receiver for .on(event, listener)".to_string(),
                        got: receiver.type_name().to_string(),
                    });
                };
                let event = self.event_name_arg(args, 0)?;
                let listener = self.builtin_arg(args, 1)?.unwrap_or(Value::Undefined);
                if event
                    .as_ref()
                    .is_some_and(|event| matches!(event.as_str(), Some("data" | "end")))
                    && self.readable_pipe_links.contains_key(&target_id)
                {
                    return Err(InterpreterError::TypeError {
                        expected: "stable Readable.pipe listener set".to_string(),
                        got: "data/end listener registration while pipe is active".to_string(),
                    });
                }
                if Self::is_internal_readable_pipe_listener(&listener) {
                    return Err(InterpreterError::TypeError {
                        expected: "guest EventEmitter listener".to_string(),
                        got: "engine-owned Readable.pipe listener".to_string(),
                    });
                }
                let listener_label = self.join_arg_range_label(args)?;
                if let Some(event) = event
                    && listener.is_callable()
                {
                    // Only native string event names drive host lifecycle hooks;
                    // a symbol (even Symbol("data")) is an independent event.
                    let native_event = event.as_str().unwrap_or_default();
                    let pump_reserved =
                        self.reserve_readable_activation_pump(target_id, native_event)?;
                    let new_listener_emission = self.emit_event_listener_records(
                        module,
                        target_id,
                        "newListener",
                        vec![event.value(), listener.clone()],
                        listener_label,
                    );
                    if let Err(error) = new_listener_emission {
                        return self.readable_error_after_reservation(
                            target_id,
                            pump_reserved,
                            error,
                        );
                    }
                    let insertion = self.insert_event_listener(
                        target_id,
                        &event,
                        EventListenerRecord {
                            listener,
                            once: false,
                        },
                        false,
                    );
                    if let Err(error) = insertion {
                        return self.readable_error_after_reservation(
                            target_id,
                            pump_reserved,
                            error,
                        );
                    }
                    if let Err(error) = self.activate_readable_from_data_flow_with_reservation(
                        target_id,
                        native_event,
                        pump_reserved,
                    ) {
                        self.rollback_inserted_event_listener(target_id, &event, false);
                        return Err(error);
                    }
                    if let Err(error) =
                        self.activate_completed_child_process_event(target_id, native_event)
                    {
                        self.rollback_inserted_event_listener(target_id, &event, false);
                        return Err(error);
                    }
                }
                Ok(Value::Object(target_id))
            }
            BuiltinFunctionKind::EmitterOnce
            | BuiltinFunctionKind::EmitterPrependListener
            | BuiltinFunctionKind::EmitterPrependOnceListener => {
                let receiver = receiver.unwrap_or(Value::Undefined);
                let Value::Object(target_id) = receiver else {
                    return Err(InterpreterError::TypeError {
                        expected: "EventEmitter receiver for listener registration".to_string(),
                        got: receiver.type_name().to_string(),
                    });
                };
                let event = self.event_name_arg(args, 0)?;
                let listener = self.builtin_arg(args, 1)?.unwrap_or(Value::Undefined);
                if event
                    .as_ref()
                    .is_some_and(|event| matches!(event.as_str(), Some("data" | "end")))
                    && self.readable_pipe_links.contains_key(&target_id)
                {
                    return Err(InterpreterError::TypeError {
                        expected: "stable Readable.pipe listener set".to_string(),
                        got: "data/end listener registration while pipe is active".to_string(),
                    });
                }
                if Self::is_internal_readable_pipe_listener(&listener) {
                    return Err(InterpreterError::TypeError {
                        expected: "guest EventEmitter listener".to_string(),
                        got: "engine-owned Readable.pipe listener".to_string(),
                    });
                }
                let listener_label = self.join_arg_range_label(args)?;
                if let Some(event) = event
                    && listener.is_callable()
                {
                    let prepend = matches!(
                        builtin.kind,
                        BuiltinFunctionKind::EmitterPrependListener
                            | BuiltinFunctionKind::EmitterPrependOnceListener
                    );
                    let native_event = event.as_str().unwrap_or_default();
                    let pump_reserved =
                        self.reserve_readable_activation_pump(target_id, native_event)?;
                    let new_listener_emission = self.emit_event_listener_records(
                        module,
                        target_id,
                        "newListener",
                        vec![event.value(), listener.clone()],
                        listener_label,
                    );
                    if let Err(error) = new_listener_emission {
                        return self.readable_error_after_reservation(
                            target_id,
                            pump_reserved,
                            error,
                        );
                    }
                    let once = matches!(
                        builtin.kind,
                        BuiltinFunctionKind::EmitterOnce
                            | BuiltinFunctionKind::EmitterPrependOnceListener
                    );
                    let (stored_listener, wrapper_allocation) = if once {
                        match self.create_event_once_wrapper(
                            target_id,
                            &event,
                            listener.clone(),
                            None,
                        ) {
                            Ok((wrapper, property_object, previous_heap_len)) => (
                                wrapper,
                                Some((property_object, previous_heap_len)),
                            ),
                            Err(error) => {
                                return self.readable_error_after_reservation(
                                    target_id,
                                    pump_reserved,
                                    error,
                                );
                            }
                        }
                    } else {
                        (listener, None)
                    };
                    let insertion = self.insert_event_listener(
                        target_id,
                        &event,
                        EventListenerRecord {
                            listener: stored_listener,
                            once,
                        },
                        prepend,
                    );
                    if let Err(error) = insertion {
                        if let Some((property_object, previous_heap_len)) = wrapper_allocation {
                            self.rollback_event_once_wrapper(
                                property_object,
                                previous_heap_len,
                            );
                        }
                        return self.readable_error_after_reservation(
                            target_id,
                            pump_reserved,
                            error,
                        );
                    }
                    if let Err(error) = self.activate_readable_from_data_flow_with_reservation(
                        target_id,
                        native_event,
                        pump_reserved,
                    ) {
                        self.rollback_inserted_event_listener(target_id, &event, prepend);
                        if let Some((property_object, previous_heap_len)) = wrapper_allocation {
                            self.rollback_event_once_wrapper(
                                property_object,
                                previous_heap_len,
                            );
                        }
                        return Err(error);
                    }
                    if let Err(error) =
                        self.activate_completed_child_process_event(target_id, native_event)
                    {
                        self.rollback_inserted_event_listener(target_id, &event, prepend);
                        if let Some((property_object, previous_heap_len)) = wrapper_allocation {
                            self.rollback_event_once_wrapper(property_object, previous_heap_len);
                        }
                        return Err(error);
                    }
                }
                Ok(Value::Object(target_id))
            }
            BuiltinFunctionKind::EmitterOff => {
                let receiver = receiver.unwrap_or(Value::Undefined);
                let Value::Object(target_id) = receiver else {
                    return Err(InterpreterError::TypeError {
                        expected: "EventEmitter receiver for removeListener".to_string(),
                        got: receiver.type_name().to_string(),
                    });
                };
                let event = self.event_name_arg(args, 0)?;
                let listener = self.builtin_arg(args, 1)?.unwrap_or(Value::Undefined);
                let listener_label = self.join_arg_range_label(args)?;
                if let Some(event) = event && listener.is_callable() {
                    let removal_meta_listener =
                        self.event_remove_listener_meta_value(target_id, &event, &listener);
                    if let Some(removed) =
                        self.remove_event_listener(target_id, &event, &listener)
                    {
                    if Self::is_internal_readable_pipe_listener(&removed.listener) {
                        self.detach_current_readable_pipe(target_id);
                    }
                    let _ = self.emit_event_listener_records(
                        module,
                        target_id,
                        "removeListener",
                            vec![event.value(), removal_meta_listener],
                        listener_label,
                    )?;
                    }
                }
                Ok(Value::Object(target_id))
            }
            BuiltinFunctionKind::EmitterRemoveAllListeners => {
                let receiver = receiver.unwrap_or(Value::Undefined);
                let Value::Object(target_id) = receiver else {
                    return Err(InterpreterError::TypeError {
                        expected: "EventEmitter receiver for removeAllListeners".to_string(),
                        got: receiver.type_name().to_string(),
                    });
                };
                let event = self.event_name_arg(args, 0)?;
                let invalidates_pipe = event
                    .as_ref()
                    .is_none_or(|event| matches!(event.as_str(), Some("data" | "end")));
                // bd-asw4m.6: Node emits a `removeListener` meta-event for every
                // listener dropped by removeAllListeners, but ONLY when a
                // `removeListener` handler is registered — otherwise it takes the
                // silent fast clear. Mirror that split so the common case stays
                // allocation-free and the observed case matches donor order.
                let has_remove_listener_handler = !self
                    .event_listener_records_for(target_id, "removeListener")
                    .is_empty();
                if has_remove_listener_handler {
                    let meta_label = self.join_arg_range_label(args)?;
                    if let Some(event) = event.as_ref() {
                        self.remove_all_listeners_for_event_with_meta(
                            module, target_id, event, meta_label,
                        )?;
                    } else {
                        // All-events form: drain every event except
                        // `removeListener`, then `removeListener` itself last so
                        // its own handlers observe the other removals (Node
                        // ordering). Snapshot the key set first — the meta
                        // handlers may mutate the live map.
                        let keys: Vec<RuntimePropertyKey> = self
                            .event_listeners
                            .get(&target_id)
                            .map(|by_event| by_event.keys().cloned().collect())
                            .unwrap_or_default();
                        for key in keys {
                            if key.as_str() == Some("removeListener") {
                                continue;
                            }
                            self.remove_all_listeners_for_event_with_meta(
                                module,
                                target_id,
                                &key,
                                meta_label.clone(),
                            )?;
                        }
                        self.remove_all_listeners_for_event_with_meta(
                            module,
                            target_id,
                            &RuntimePropertyKey::from("removeListener"),
                            meta_label,
                        )?;
                    }
                }
                // Hard clear (Node resets the bucket): also drops internal
                // listeners removed silently above and anything a meta handler
                // re-registered, keeping memory accounting exact.
                if let Some(event) = event {
                    self.clear_event_listeners(target_id, Some(&event));
                } else {
                    self.clear_event_listeners(target_id, None);
                }
                if invalidates_pipe {
                    self.detach_current_readable_pipe(target_id);
                }
                Ok(Value::Object(target_id))
            }
            BuiltinFunctionKind::EmitterListenerCount => {
                let receiver = receiver.unwrap_or(Value::Undefined);
                let Value::Object(target_id) = receiver else {
                    return Err(InterpreterError::TypeError {
                        expected: "EventEmitter receiver for listenerCount".to_string(),
                        got: receiver.type_name().to_string(),
                    });
                };
                let count = if let Some(event) = self.event_name_arg(args, 0)? {
                    let records = self.guest_event_listener_records_for(target_id, &event);
                    if let Some(listener) = self.builtin_arg(args, 1)? {
                        records
                            .iter()
                            .filter(|record| self.event_listener_matches(record, &listener))
                            .count()
                    } else {
                        records.len()
                    }
                } else {
                    0
                };
                Ok(Value::Int(i64::try_from(count).unwrap_or(i64::MAX)))
            }
            BuiltinFunctionKind::EmitterEventNames => {
                let receiver = receiver.unwrap_or(Value::Undefined);
                let Value::Object(target_id) = receiver else {
                    return Err(InterpreterError::TypeError {
                        expected: "EventEmitter receiver for eventNames".to_string(),
                        got: receiver.type_name().to_string(),
                    });
                };
                let names = self
                    .event_listeners
                    .get(&target_id)
                    .map(|by_event| {
                        by_event
                            .iter()
                            .filter(|(_, records)| {
                                records.iter().any(|record| {
                                    !Self::is_internal_readable_pipe_listener(&record.listener)
                                })
                            })
                            .map(|(event, _)| event.value())
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                Ok(Value::Object(self.alloc_array_from_values(&names)?))
            }
            BuiltinFunctionKind::EmitterEmit => {
                let receiver = receiver.unwrap_or(Value::Undefined);
                let Value::Object(target_id) = receiver else {
                    return Err(InterpreterError::TypeError {
                        expected: "EventEmitter receiver for emit".to_string(),
                        got: receiver.type_name().to_string(),
                    });
                };
                let Some(event) = self.event_name_arg(args, 0)? else {
                    return Ok(Value::Bool(false));
                };
                let mut arguments = Vec::with_capacity(args.count.saturating_sub(1) as usize);
                for index in 1..args.count {
                    arguments.push(
                        self.builtin_arg(args, index)?
                            .unwrap_or(Value::Undefined),
                    );
                }
                let emission_label = self.join_arg_range_label(args)?;
                Ok(Value::Bool(self.emit_event_listener_records(
                    module,
                    target_id,
                    &event,
                    arguments,
                    emission_label,
                )?))
            }
            BuiltinFunctionKind::EmitterGetMaxListeners => {
                let receiver = receiver.unwrap_or(Value::Undefined);
                let Value::Object(target_id) = receiver else {
                    return Err(InterpreterError::TypeError {
                        expected: "EventEmitter receiver for getMaxListeners".to_string(),
                        got: receiver.type_name().to_string(),
                    });
                };
                Ok(self
                    .heap
                    .get(target_id.0 as usize)
                    .and_then(|object| object.properties.get("__maxListeners"))
                    .cloned()
                    .unwrap_or(Value::Int(10)))
            }
            BuiltinFunctionKind::EmitterSetMaxListeners => {
                let receiver = receiver.unwrap_or(Value::Undefined);
                let Value::Object(target_id) = receiver else {
                    return Err(InterpreterError::TypeError {
                        expected: "EventEmitter receiver for setMaxListeners".to_string(),
                        got: receiver.type_name().to_string(),
                    });
                };
                let value = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
                let valid = match &value {
                    Value::Int(number) => *number >= 0,
                    Value::Float(number) => {
                        let number = number.inner();
                        number >= 0.0 && (number.is_infinite() || number.fract() == 0.0)
                    }
                    _ => false,
                };
                if !valid {
                    return Err(InterpreterError::RangeError {
                        message: "max listeners must be a non-negative number".to_string(),
                    });
                }
                self.set_object_property(target_id, "__maxListeners".to_string(), value)?;
                Ok(Value::Object(target_id))
            }
            BuiltinFunctionKind::EmitterListeners => {
                let receiver = receiver.unwrap_or(Value::Undefined);
                let Value::Object(target_id) = receiver else {
                    return Err(InterpreterError::TypeError {
                        expected: "EventEmitter receiver for listeners".to_string(),
                        got: receiver.type_name().to_string(),
                    });
                };
                let listeners = self
                    .event_name_arg(args, 0)?
                    .map(|event| {
                        let records = self.guest_event_listener_records_for(target_id, &event);
                        let scalar = records.len() == 1;
                        records
                            .into_iter()
                            .map(|record| {
                                if scalar {
                                    self.exposed_event_listener(&record.listener)
                                } else {
                                    self.exposed_event_listener_in_array(&record.listener)
                                }
                            })
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                Ok(Value::Object(self.alloc_array_from_values(&listeners)?))
            }
            BuiltinFunctionKind::EmitterRawListeners => {
                let receiver = receiver.unwrap_or(Value::Undefined);
                let Value::Object(target_id) = receiver else {
                    return Err(InterpreterError::TypeError {
                        expected: "EventEmitter receiver for rawListeners".to_string(),
                        got: receiver.type_name().to_string(),
                    });
                };
                let listeners = self
                    .event_name_arg(args, 0)?
                    .map(|event| {
                        self.guest_event_listener_records_for(target_id, &event)
                            .into_iter()
                            .map(|record| record.listener)
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                Ok(Value::Object(self.alloc_array_from_values(&listeners)?))
            }
            BuiltinFunctionKind::EmitterOnceWrapper => {
                self.invoke_event_once_wrapper(module, builtin, args)
            }
            BuiltinFunctionKind::ClusterSetup => {
                self.cluster_setup(receiver, builtin.bound_object, args)
            }
            BuiltinFunctionKind::ClusterDisconnect => {
                self.cluster_receiver_id(receiver, builtin.bound_object, "disconnect")?;
                let callback = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
                match callback {
                    Value::Undefined => Ok(Value::Undefined),
                    Value::Closure(closure_id) => {
                        let callback_label = self.writable_invocation_label(args)?;
                        self.schedule_io_callback_with_label(
                            closure_id,
                            Vec::new(),
                            callback_label,
                        )?;
                        Ok(Value::Undefined)
                    }
                    other => Err(InterpreterError::TypeError {
                        expected: "cluster.disconnect callback function".to_string(),
                        got: other.type_name().to_string(),
                    }),
                }
            }
            BuiltinFunctionKind::ClusterFork | BuiltinFunctionKind::ClusterWorker => {
                Err(InterpreterError::CapabilityDenied {
                    capability:
                        "process_spawn (cluster.fork/Worker unavailable in hermetic primary facade)"
                            .to_string(),
                })
            }
            BuiltinFunctionKind::PerformanceNow => {
                self.dispatch_builtin_hostcall("builtin:PerformanceNow", args, Some(module))
            }
            BuiltinFunctionKind::DataViewGetUint8 => self.data_view_get_integer(
                module,
                receiver.unwrap_or(Value::Undefined),
                args,
                DataViewIntegerKind::Uint8,
            ),
            BuiltinFunctionKind::DataViewSetUint8 => self.data_view_set_integer(
                module,
                receiver.unwrap_or(Value::Undefined),
                args,
                DataViewIntegerKind::Uint8,
            ),
            BuiltinFunctionKind::DataViewGetInt32 => self.data_view_get_integer(
                module,
                receiver.unwrap_or(Value::Undefined),
                args,
                DataViewIntegerKind::Int32,
            ),
            BuiltinFunctionKind::DataViewSetInt32 => self.data_view_set_integer(
                module,
                receiver.unwrap_or(Value::Undefined),
                args,
                DataViewIntegerKind::Int32,
            ),
            BuiltinFunctionKind::DataViewGetUint32 => self.data_view_get_integer(
                module,
                receiver.unwrap_or(Value::Undefined),
                args,
                DataViewIntegerKind::Uint32,
            ),
            BuiltinFunctionKind::DataViewSetUint32 => self.data_view_set_integer(
                module,
                receiver.unwrap_or(Value::Undefined),
                args,
                DataViewIntegerKind::Uint32,
            ),
            BuiltinFunctionKind::TypedArrayMethod => {
                let method = builtin
                    .module_specifier
                    .0
                    .as_deref()
                    .unwrap_or_default()
                    .to_string();
                self.typed_array_method(module, &method, receiver.unwrap_or(Value::Undefined), args)
            }
            BuiltinFunctionKind::DataViewMethod => {
                let name = builtin.module_specifier.0.as_deref().unwrap_or_default();
                let Some((kind, setter)) = DataViewIntegerKind::from_method_name(name) else {
                    return Err(InterpreterError::TypeError {
                        expected: "DataView accessor".to_string(),
                        got: name.to_string(),
                    });
                };
                let receiver = receiver.unwrap_or(Value::Undefined);
                if setter {
                    self.data_view_set_integer(module, receiver, args, kind)
                } else {
                    self.data_view_get_integer(module, receiver, args, kind)
                }
            }
            BuiltinFunctionKind::TypedArraySet => {
                self.typed_array_set(module, receiver.unwrap_or(Value::Undefined), args)
            }
            BuiltinFunctionKind::TypedArraySubarray => {
                self.typed_array_subarray(module, receiver.unwrap_or(Value::Undefined), args)
            }
            BuiltinFunctionKind::TypedArraySlice => {
                self.typed_array_slice(module, receiver.unwrap_or(Value::Undefined), args)
            }
            BuiltinFunctionKind::TypedArrayFill => {
                self.typed_array_fill(module, receiver.unwrap_or(Value::Undefined), args)
            }
            BuiltinFunctionKind::TypedArrayCopyWithin => {
                self.typed_array_copy_within(module, receiver.unwrap_or(Value::Undefined), args)
            }
            BuiltinFunctionKind::TypedArrayEntries => self
                .typed_array_iterator_for_receiver(receiver.unwrap_or(Value::Undefined), "entries"),
            BuiltinFunctionKind::TypedArrayKeys => {
                self.typed_array_iterator_for_receiver(receiver.unwrap_or(Value::Undefined), "keys")
            }
            BuiltinFunctionKind::TypedArrayValues => self
                .typed_array_iterator_for_receiver(receiver.unwrap_or(Value::Undefined), "values"),
            BuiltinFunctionKind::TypedArrayUnsupportedMethod => Err(InterpreterError::TypeError {
                expected:
                    "supported TypedArray v1 BotGuard method (set/subarray/slice/fill/copyWithin/entries/keys/values)"
                        .to_string(),
                got: "unsupported TypedArray method".to_string(),
            }),
            BuiltinFunctionKind::BufferToString => {
                self.buffer_to_string(receiver.unwrap_or(Value::Undefined), args)
            }
            BuiltinFunctionKind::BufferSharedSlice => {
                self.buffer_shared_slice(module, receiver.unwrap_or(Value::Undefined), args)
            }
            BuiltinFunctionKind::BufferIndexOf => {
                self.buffer_index_of(receiver.unwrap_or(Value::Undefined), args)
            }
            BuiltinFunctionKind::BufferIncludes => {
                self.buffer_includes(receiver.unwrap_or(Value::Undefined), args)
            }
            BuiltinFunctionKind::BufferEquals => {
                self.buffer_equals(receiver.unwrap_or(Value::Undefined), args)
            }
            BuiltinFunctionKind::BufferCompare => {
                self.buffer_compare_method(receiver.unwrap_or(Value::Undefined), args)
            }
            BuiltinFunctionKind::BufferReadUInt8 => self.buffer_read_integer(
                receiver.unwrap_or(Value::Undefined),
                args,
                BufferIntegerKind::UInt8,
                true,
            ),
            BuiltinFunctionKind::BufferWriteUInt8 => self.buffer_write_integer(
                receiver.unwrap_or(Value::Undefined),
                args,
                BufferIntegerKind::UInt8,
                true,
            ),
            BuiltinFunctionKind::BufferReadUInt16Le => self.buffer_read_integer(
                receiver.unwrap_or(Value::Undefined),
                args,
                BufferIntegerKind::UInt16,
                true,
            ),
            BuiltinFunctionKind::BufferReadUInt16Be => self.buffer_read_integer(
                receiver.unwrap_or(Value::Undefined),
                args,
                BufferIntegerKind::UInt16,
                false,
            ),
            BuiltinFunctionKind::BufferWriteUInt16Le => self.buffer_write_integer(
                receiver.unwrap_or(Value::Undefined),
                args,
                BufferIntegerKind::UInt16,
                true,
            ),
            BuiltinFunctionKind::BufferWriteUInt16Be => self.buffer_write_integer(
                receiver.unwrap_or(Value::Undefined),
                args,
                BufferIntegerKind::UInt16,
                false,
            ),
            BuiltinFunctionKind::BufferReadInt32Le => self.buffer_read_integer(
                receiver.unwrap_or(Value::Undefined),
                args,
                BufferIntegerKind::Int32,
                true,
            ),
            BuiltinFunctionKind::BufferReadInt32Be => self.buffer_read_integer(
                receiver.unwrap_or(Value::Undefined),
                args,
                BufferIntegerKind::Int32,
                false,
            ),
            BuiltinFunctionKind::BufferWriteInt32Le => self.buffer_write_integer(
                receiver.unwrap_or(Value::Undefined),
                args,
                BufferIntegerKind::Int32,
                true,
            ),
            BuiltinFunctionKind::BufferWriteInt32Be => self.buffer_write_integer(
                receiver.unwrap_or(Value::Undefined),
                args,
                BufferIntegerKind::Int32,
                false,
            ),
            BuiltinFunctionKind::BufferReadUInt32Le => self.buffer_read_integer(
                receiver.unwrap_or(Value::Undefined),
                args,
                BufferIntegerKind::UInt32,
                true,
            ),
            BuiltinFunctionKind::BufferReadUInt32Be => self.buffer_read_integer(
                receiver.unwrap_or(Value::Undefined),
                args,
                BufferIntegerKind::UInt32,
                false,
            ),
            BuiltinFunctionKind::BufferWriteUInt32Le => self.buffer_write_integer(
                receiver.unwrap_or(Value::Undefined),
                args,
                BufferIntegerKind::UInt32,
                true,
            ),
            BuiltinFunctionKind::BufferWriteUInt32Be => self.buffer_write_integer(
                receiver.unwrap_or(Value::Undefined),
                args,
                BufferIntegerKind::UInt32,
                false,
            ),
            BuiltinFunctionKind::BufferCopy => {
                self.buffer_copy(receiver.unwrap_or(Value::Undefined), args)
            }
            BuiltinFunctionKind::BufferToJson => {
                self.buffer_to_json(receiver.unwrap_or(Value::Undefined))
            }
            BuiltinFunctionKind::BufferSwap16 => {
                self.buffer_swap(receiver.unwrap_or(Value::Undefined), 2)
            }
            BuiltinFunctionKind::BufferSwap32 => {
                self.buffer_swap(receiver.unwrap_or(Value::Undefined), 4)
            }
            BuiltinFunctionKind::BufferSwap64 => {
                self.buffer_swap(receiver.unwrap_or(Value::Undefined), 8)
            }
            BuiltinFunctionKind::BufferNumericMethod => {
                let name = builtin
                    .module_specifier
                    .0
                    .as_deref()
                    .unwrap_or_default()
                    .to_string();
                self.buffer_numeric_method(receiver.unwrap_or(Value::Undefined), args, &name)
            }
            BuiltinFunctionKind::PromiseResolve => {
                if let Some(handle_id) = builtin.bound_object {
                    // A bound handle marks a resolve capability (from
                    // CreateResolvingFunctions), not the static
                    // `Promise.resolve` constructor method (bd-iio0f).
                    return self.apply_promise_capability(
                        Some(module),
                        crate::promise_model::PromiseHandle(handle_id),
                        builtin.iterator_handle,
                        args,
                        true,
                    );
                }
                // bd-9vouw.137, bd-9vouw.282: PromiseResolve(C, x) for the
                // `this` C, which must be an object.
                let constructor = Self::promise_static_this(receiver.as_ref(), "resolve")?;
                let value = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
                if Self::is_intrinsic_promise_constructor(&constructor)
                    && !matches!(value, Value::Promise(_))
                {
                    return self.dispatch_promise_hostcall("promise:resolve", args, Some(module));
                }
                let label = self.join_arg_range_with_object_mutation_label(args)?;
                self.promise_resolve_with_constructor(module, constructor, value, label)
            }
            BuiltinFunctionKind::PromiseReject => {
                if let Some(handle_id) = builtin.bound_object {
                    return self.apply_promise_capability(
                        Some(module),
                        crate::promise_model::PromiseHandle(handle_id),
                        builtin.iterator_handle,
                        args,
                        false,
                    );
                }
                let constructor = Self::promise_static_this(receiver.as_ref(), "reject")?;
                if Self::is_intrinsic_promise_constructor(&constructor) {
                    return self.dispatch_promise_hostcall("promise:reject", args, Some(module));
                }
                let reason = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
                self.promise_reject_with_constructor(module, constructor, reason)
            }
            BuiltinFunctionKind::PromiseAll => self.promise_combinator_call(
                module,
                PromiseCombinatorKind::All,
                "promise:all",
                "all",
                args,
                receiver.as_ref(),
            ),
            BuiltinFunctionKind::PromiseRace => self.promise_combinator_call(
                module,
                PromiseCombinatorKind::Race,
                "promise:race",
                "race",
                args,
                receiver.as_ref(),
            ),
            BuiltinFunctionKind::PromiseAllSettled => self.promise_combinator_call(
                module,
                PromiseCombinatorKind::AllSettled,
                "promise:allSettled",
                "allSettled",
                args,
                receiver.as_ref(),
            ),
            BuiltinFunctionKind::PromiseAny => self.promise_combinator_call(
                module,
                PromiseCombinatorKind::Any,
                "promise:any",
                "any",
                args,
                receiver.as_ref(),
            ),
            // ES2024 27.2.4.8: NewPromiseCapability(this) as an object, for
            // any constructor `this` (bd-9vouw.137, bd-9vouw.282).
            BuiltinFunctionKind::PromiseWithResolvers => {
                let constructor = Self::promise_static_this(receiver.as_ref(), "withResolvers")?;
                let capability =
                    self.new_promise_capability_record(module, constructor, Vec::new())?;
                let result = self.alloc_object_with_properties(&[
                    ("promise", capability.promise),
                    ("resolve", capability.resolve),
                    ("reject", capability.reject),
                ])?;
                Ok(Value::Object(result))
            }
            BuiltinFunctionKind::PromiseThen => self.dispatch_promise_reaction_builtin(
                module,
                args,
                receiver,
                PromiseReactionKind::Then,
            ),
            BuiltinFunctionKind::PromiseCatch => self.dispatch_promise_reaction_builtin(
                module,
                args,
                receiver,
                PromiseReactionKind::Catch,
            ),
            BuiltinFunctionKind::PromiseFinally => self.dispatch_promise_reaction_builtin(
                module,
                args,
                receiver,
                PromiseReactionKind::Finally,
            ),
            BuiltinFunctionKind::PromiseCapabilityExecutor => {
                self.promise_capability_executor_call(builtin, args)
            }
            BuiltinFunctionKind::PromiseAllResolveElement
            | BuiltinFunctionKind::PromiseAllSettledResolveElement
            | BuiltinFunctionKind::PromiseAllSettledRejectElement
            | BuiltinFunctionKind::PromiseAnyRejectElement => {
                self.promise_combinator_element_call(module, builtin, args)
            }
            BuiltinFunctionKind::RegExpTest => {
                let receiver = receiver.unwrap_or(Value::Undefined);
                // ES2020 21.2.5.13: `this` must be an object, then
                // ToString(S) (bd-9vouw.213), then RegExpExec(R, S): a
                // callable `exec` other than the intrinsic one runs, and an
                // object without one that is no RegExp is a TypeError
                // (bd-9vouw.257).
                if !receiver.is_object_like() {
                    return Err(InterpreterError::TypeError {
                        expected: "object receiver for RegExp.prototype.test".to_string(),
                        got: receiver.type_name().to_string(),
                    });
                }
                // ToString keeping the string itself, as exec takes it
                // (bd-9vouw.475).
                let input = Value::Str(self.builtin_arg_js_text(Some(module), args, 0)?);
                if let Some(exec) = self.regexp_user_exec(module, &receiver)? {
                    let label = self.join_arg_range_label(args)?;
                    let result =
                        self.regexp_call_user_exec(module, exec, &receiver, &input, Some(label))?;
                    return Ok(Value::Bool(!matches!(result, Value::Null)));
                }
                if self.regexp_source_flags_from_value(&receiver).is_none() {
                    return Err(InterpreterError::TypeError {
                        expected: "RegExp receiver or callable exec for RegExp.prototype.test"
                            .to_string(),
                        got: receiver.type_name().to_string(),
                    });
                }
                let last_index = self.regexp_coerced_last_index(module, &receiver)?;
                self.regexp_test_value_from(&receiver, &input, last_index)
            }
            BuiltinFunctionKind::BigIntToString => {
                // ES2020 20.2.3.3: thisBigIntValue, then a radix in 2..=36.
                let Some(Value::BigInt(digits)) = &receiver else {
                    return Err(InterpreterError::TypeError {
                        expected: "BigInt receiver".to_string(),
                        got: receiver.as_ref().map_or("undefined", Value::type_name).to_string(),
                    });
                };
                let radix = match self.builtin_number_arg(module, args, 0)? {
                    Some(Value::Undefined) | None => 10,
                    Some(arg) => Self::value_as_integer(&arg),
                };
                if !(2..=36).contains(&radix) {
                    return Err(InterpreterError::RangeError {
                        message: format!("toString() radix must be between 2 and 36 (got {radix})"),
                    });
                }
                Ok(Value::str(bigint_ops::to_string_radix(digits, radix as u32)))
            }
            BuiltinFunctionKind::BigIntValueOf => match receiver {
                Some(value @ Value::BigInt(_)) => Ok(value),
                other => Err(InterpreterError::TypeError {
                    expected: "BigInt receiver".to_string(),
                    got: other.as_ref().map_or("undefined", Value::type_name).to_string(),
                }),
            },
            BuiltinFunctionKind::BigIntAsUintN | BuiltinFunctionKind::BigIntAsIntN => {
                // ES2020 20.2.2.1-2: ToIndex(bits), then ToBigInt(bigint). An
                // object `bits` converts through ToPrimitive first, so one
                // whose valueOf returns a BigInt is the TypeError ToIndex
                // raises (it read as 0).
                let bits = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
                let bits = self.object_to_number_primitive(Some(module), bits)?;
                let Some(bits) = Self::to_index_value(&bits)? else {
                    return Err(InterpreterError::RangeError {
                        message: "Invalid value: not (convertible to) a safe integer".to_string(),
                    });
                };
                let value = self.builtin_arg(args, 1)?.unwrap_or(Value::Undefined);
                // ToBigInt (ES2020 7.1.13) starts with ToPrimitive(value,
                // number): a wrapped or valueOf-bearing object converts.
                let value = if value.is_object_like() {
                    self.coerce_runtime_primitive(Some(module), value, false)?
                } else {
                    value
                };
                let Value::BigInt(digits) = self.coerce_to_bigint(value)? else {
                    unreachable!("coerce_to_bigint returns a BigInt");
                };
                let result = if builtin.kind == BuiltinFunctionKind::BigIntAsUintN {
                    bigint_ops::as_uint_n(bits, &digits)
                } else {
                    bigint_ops::as_int_n(bits, &digits)
                };
                Self::bigint_result(result)
            }
            BuiltinFunctionKind::ObjectPrototypeToLocaleString => {
                // ES2020 19.1.3.5: Invoke(this, "toString"); it was missing,
                // so `obj.toLocaleString` was undefined.
                let receiver = receiver.unwrap_or(Value::Undefined);
                let method = self.get_v(
                    module,
                    &receiver,
                    &RuntimePropertyKey::String(JsString::from("toString")),
                )?;
                if !method.is_callable() {
                    return Err(InterpreterError::TypeError {
                        expected: "callable toString for Object.prototype.toLocaleString"
                            .to_string(),
                        got: method.type_name().to_string(),
                    });
                }
                self.call_conversion_method(module, method, &receiver, Vec::new())
            }
            BuiltinFunctionKind::ObjectPrototypeIsPrototypeOf => {
                // ES2020 19.1.3.3: a primitive V is never inherited from;
                // otherwise walk V's chain for this (ToObject'd) receiver.
                let value = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
                if !value.is_object_like() {
                    return Ok(Value::Bool(false));
                }
                let receiver = receiver.unwrap_or(Value::Undefined);
                if matches!(receiver, Value::Undefined | Value::Null) {
                    return Err(InterpreterError::TypeError {
                        expected: "object-coercible this for isPrototypeOf".to_string(),
                        got: receiver.type_name().to_string(),
                    });
                }
                if !receiver.is_object_like() {
                    return Ok(Value::Bool(false));
                }
                Ok(Value::Bool(self.value_prototype_chain_contains(
                    Some(module),
                    &value,
                    &receiver,
                )?))
            }
            BuiltinFunctionKind::ObjectHasOwnProperty => {
                let receiver = receiver.unwrap_or(Value::Undefined);
                // ES2020 19.1.3.2 step 1: ToPropertyKey(V), whose object
                // hooks run before the receiver check (bd-9vouw.279); a
                // missing V is the key "undefined".
                let property = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
                let property = self.coerce_to_property_key(Some(module), property)?;
                // Step 2: ToObject(this value).
                if matches!(receiver, Value::Undefined | Value::Null) {
                    return Err(InterpreterError::TypeError {
                        expected: "object receiver for Object.prototype.hasOwnProperty".to_string(),
                        got: receiver.type_name().to_string(),
                    });
                }
                Ok(Value::Bool(self.value_has_own_property(
                    Some(module),
                    &receiver,
                    &property,
                )?))
            }
            BuiltinFunctionKind::ObjectPrototypePropertyIsEnumerable => {
                let receiver = receiver.unwrap_or(Value::Undefined);
                // ES2020 19.1.3.4 step 1: ToPropertyKey(V) (bd-9vouw.279); a
                // missing V is the key "undefined".
                let property = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
                let property = self.coerce_to_property_key(Some(module), property)?;
                // Step 2: ToObject(this value).
                if matches!(receiver, Value::Undefined | Value::Null) {
                    return Err(InterpreterError::TypeError {
                        expected: "object receiver for Object.prototype.propertyIsEnumerable"
                            .to_string(),
                        got: receiver.type_name().to_string(),
                    });
                }
                if let Value::Object(object_id) = &receiver {
                    self.join_pending_hostcall_stream_label(*object_id)?;
                    // A Proxy answers through [[GetOwnProperty]] (its
                    // getOwnPropertyDescriptor trap, else its target's), as
                    // hasOwnProperty does (bd-9vouw.236); every key read false.
                    if self.active_proxy_record(*object_id)?.is_some() {
                        let key = self.executable_property_key_from_value(&property);
                        let descriptor = self.proxy_aware_own_property_descriptor(
                            Some(module),
                            *object_id,
                            &key,
                            0,
                        )?;
                        if matches!(descriptor, Value::Undefined) {
                            return Ok(Value::Bool(false));
                        }
                        let fields = self.read_property_descriptor(Some(module), &descriptor)?;
                        return Ok(Value::Bool(fields.enumerable == Some(true)));
                    }
                }
                // A function's own `prototype` is never enumerable (ES2020
                // 9.2.10 MakeConstructor, and the built-in constructors'
                // non-configurable `prototype`); getOwnPropertyDescriptor
                // answers it on its own path, which this now agrees with
                // (`String.propertyIsEnumerable('prototype')` was true).
                if !matches!(receiver, Value::Object(_))
                    && receiver.is_callable()
                    && matches!(&property, Value::Str(name) if name.as_str() == Some("prototype"))
                    && self.function_has_intrinsic_prototype(&receiver)
                {
                    return Ok(Value::Bool(false));
                }
                let enumerable = self.object_own_property_is_enumerable(&receiver, &property)
                    || self
                        .own_property_holder(Some(module), &receiver, false)?
                        .is_some_and(|backing| {
                            self.object_own_property_is_enumerable(
                                &Value::Object(backing),
                                &property,
                            )
                        });
                Ok(Value::Bool(enumerable))
            }
            BuiltinFunctionKind::ObjectPrototypeValueOf => {
                let receiver = receiver.unwrap_or(Value::Undefined);
                self.object_prototype_value_of_value(receiver)
            }
            BuiltinFunctionKind::ObjectPrototypeToString => {
                let receiver = receiver.unwrap_or(Value::Undefined);
                self.object_prototype_to_string_with_getters(module, &receiver)
            }
            BuiltinFunctionKind::SymbolPrototypeToString => {
                let Value::Symbol(symbol) = receiver.unwrap_or(Value::Undefined) else {
                    return Err(InterpreterError::TypeError {
                        expected: "Symbol receiver".to_string(),
                        got: "non-Symbol receiver".to_string(),
                    });
                };
                Ok(Value::Str(self.symbol_to_string(symbol)))
            }
            BuiltinFunctionKind::BlobMethod => {
                self.blob_method(module, builtin, args, receiver, receiver_register)
            }
            // thisSymbolValue (ES2020 19.4.3.4): a wrapper object arrives here
            // already unwrapped (`this_primitive_receiver`).
            BuiltinFunctionKind::SymbolPrototypeValueOf
            | BuiltinFunctionKind::SymbolPrototypeToPrimitive => match receiver {
                Some(symbol @ Value::Symbol(_)) => Ok(symbol),
                other => Err(InterpreterError::TypeError {
                    expected: format!("Symbol receiver for Symbol.prototype.{}", builtin.spec_name()),
                    got: other.as_ref().map_or("undefined", Value::type_name).to_string(),
                }),
            },
            // %ThrowTypeError% (ES2020 9.2.9.1), with V8's message.
            BuiltinFunctionKind::ThrowTypeError => Err(InterpreterError::TypeError {
                expected: "no access to a strict arguments object's callee".to_string(),
                got: "'caller', 'callee', and 'arguments' properties may not be accessed on \
                      strict mode functions or the arguments objects for calls to them"
                    .to_string(),
            }),
            // Function.prototype[@@hasInstance](V) (ES2020 19.2.3.6):
            // OrdinaryHasInstance(this, V), which answers false for a
            // non-callable `this` instead of throwing as `instanceof` does.
            BuiltinFunctionKind::FunctionPrototypeHasInstance => {
                let constructor = receiver.unwrap_or(Value::Undefined);
                if !constructor.is_callable() {
                    return Ok(Value::Bool(false));
                }
                let candidate = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
                self.ordinary_instanceof(module, candidate, constructor)
            }
            // Date.prototype[@@toPrimitive](hint) (ES2020 20.3.4.45): any
            // object `this`, a hint of exactly "string", "default" or
            // "number", then OrdinaryToPrimitive (bd-9vouw.259).
            BuiltinFunctionKind::DatePrototypeToPrimitive => {
                let receiver = receiver.unwrap_or(Value::Undefined);
                if !receiver.is_object_like() {
                    return Err(InterpreterError::TypeError {
                        expected: "object receiver for Date.prototype[Symbol.toPrimitive]"
                            .to_string(),
                        got: receiver.type_name().to_string(),
                    });
                }
                let hint = match self.builtin_arg(args, 0)? {
                    Some(Value::Str(hint)) => hint.to_string(),
                    _ => String::new(),
                };
                let prefer_string = match hint.as_str() {
                    "string" | "default" => true,
                    "number" => false,
                    _ => {
                        return Err(InterpreterError::TypeError {
                            expected: "hint \"string\", \"number\" or \"default\" for Date.prototype[Symbol.toPrimitive]".to_string(),
                            got: hint,
                        });
                    }
                };
                match &receiver {
                    Value::Object(object_id) => {
                        self.ordinary_to_primitive(Some(module), *object_id, &receiver, prefer_string)
                    }
                    _ => self.coerce_runtime_primitive_with_hint(
                        Some(module),
                        receiver,
                        if prefer_string { "string" } else { "number" },
                    ),
                }
            }
            // String.prototype[@@iterator] (ES2020 21.1.3.29) iterates
            // ToString(RequireObjectCoercible(this)): a String wrapper (core-js
            // feature detection calls it on `new String`, which aborted
            // xregexp's load), a number, or an object whose toString runs.
            BuiltinFunctionKind::StringIterator => {
                let receiver = match receiver.unwrap_or(Value::Undefined) {
                    object if object.is_object_like() => {
                        let primitive = self.coerce_runtime_primitive(Some(module), object, true)?;
                        if matches!(primitive, Value::Symbol(_)) {
                            return Err(InterpreterError::TypeError {
                                expected: "string-convertible this for String.prototype[@@iterator]"
                                    .to_string(),
                                got: "symbol".to_string(),
                            });
                        }
                        primitive
                    }
                    other => other,
                };
                let string = Self::require_object_coercible_to_js_string(&receiver)?;
                self.init_for_of_iterator(None, Value::Str(string))
            }
            // %IteratorPrototype%[@@iterator] (ES2020 25.1.2.1), which
            // generators inherit: it returns its receiver, whatever it is.
            BuiltinFunctionKind::GeneratorIteratorSelf => Ok(receiver.unwrap_or(Value::Undefined)),
            BuiltinFunctionKind::AsyncGeneratorIteratorSelf => {
                Ok(receiver.unwrap_or(Value::Undefined))
            }
            BuiltinFunctionKind::CryptoUpdate => {
                self.crypto_update(receiver, builtin, args)
            }
            BuiltinFunctionKind::CryptoDigest => {
                self.crypto_digest(receiver, builtin, args)
            }
            BuiltinFunctionKind::CryptoCopy => self.crypto_copy(receiver, builtin, args),
            BuiltinFunctionKind::CryptoCipherUpdate => {
                self.crypto_cipher_update(receiver, builtin, args)
            }
            BuiltinFunctionKind::CryptoCipherFinal => {
                self.crypto_cipher_final(receiver, builtin, args)
            }
            BuiltinFunctionKind::CryptoGetAuthTag => {
                self.crypto_get_auth_tag(receiver, builtin, args)
            }
            BuiltinFunctionKind::CryptoSetAuthTag => {
                self.crypto_set_auth_tag(receiver, builtin, args)
            }
            BuiltinFunctionKind::ConsoleLog => self.dispatch_console_hostcall("console:log", args, Some(module)),
            BuiltinFunctionKind::ConsoleError => {
                self.dispatch_console_hostcall("console:error", args, Some(module))
            }
            BuiltinFunctionKind::ConsoleWarn => {
                self.dispatch_console_hostcall("console:warn", args, Some(module))
            }
            BuiltinFunctionKind::ConsoleInfo => {
                self.dispatch_console_hostcall("console:info", args, Some(module))
            }
            BuiltinFunctionKind::ConsoleMethod => {
                let method = builtin.display_name();
                self.dispatch_console_hostcall(&format!("console:{method}"), args, Some(module))
            }
            BuiltinFunctionKind::UrlStatic => self.url_static(builtin.display_name(), args),
            BuiltinFunctionKind::ObjectLegacyAccessor => {
                let method = builtin.display_name();
                self.legacy_accessor_method(module, method, receiver.unwrap_or(Value::Undefined), args)
            }
            BuiltinFunctionKind::SetMethod => {
                let method = builtin.display_name();
                self.set_algebra_method(module, method, receiver.unwrap_or(Value::Undefined), args)
            }
            BuiltinFunctionKind::EventTargetMethod => {
                self.event_target_method(module, builtin, args, receiver)
            }
            BuiltinFunctionKind::IteratorHelperMethod => {
                self.iterator_helper_method(module, builtin, args, receiver)
            }
            // URL.prototype.toString / toJSON: the receiver URL's href
            // (bd-9vouw.157).
            BuiltinFunctionKind::UrlMethod => {
                let method = builtin.display_name();
                let receiver = receiver.unwrap_or(Value::Undefined);
                let href = match &receiver {
                    Value::Object(id) => self.url_object_property_value(*id, "href")?,
                    _ => None,
                };
                href.ok_or_else(|| InterpreterError::TypeError {
                    expected: format!("URL receiver for URL.prototype.{method}"),
                    got: receiver.type_name().to_string(),
                })
            }
            BuiltinFunctionKind::ProxyRevoke => {
                let proxy_id = builtin.bound_object.map(ObjectId).ok_or_else(|| {
                    InterpreterError::TypeError {
                        expected: "Proxy revoker bound object".to_string(),
                        got: "missing proxy object".to_string(),
                    }
                })?;
                self.revoke_proxy_object(proxy_id)?;
                Ok(Value::Undefined)
            }
            BuiltinFunctionKind::SetTimeout
            | BuiltinFunctionKind::SetInterval
            | BuiltinFunctionKind::SetImmediate => {
                // bd-suwvw: first-class timer globals stored in variables /
                // passed as values dispatch to the same scheduling core as
                // the lowering-recognized hostcalls. Args here follow the
                // builtin-call convention (real args from index 0).
                let is_interval = matches!(builtin.kind, BuiltinFunctionKind::SetInterval);
                let is_immediate = matches!(builtin.kind, BuiltinFunctionKind::SetImmediate);
                let callback = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
                let delay = if is_immediate {
                    None
                } else {
                    self.builtin_arg(args, 1)?
                };
                let extra_start: u32 = if is_immediate { 1 } else { 2 };
                let mut extra_args = Vec::new();
                let mut index = extra_start;
                while index < args.count {
                    extra_args.push(self.builtin_arg(args, index)?.unwrap_or(Value::Undefined));
                    index += 1;
                }
                let registration_label = self.join_arg_range_label(args)?;
                self.timer_schedule_from_values(
                    callback,
                    delay,
                    extra_args,
                    is_interval,
                    is_immediate,
                    registration_label,
                )
            }
            BuiltinFunctionKind::ClearTimeout
            | BuiltinFunctionKind::ClearInterval
            | BuiltinFunctionKind::ClearImmediate => {
                let witness_tag = match builtin.kind {
                    BuiltinFunctionKind::ClearTimeout => "builtin:clearTimeout",
                    BuiltinFunctionKind::ClearInterval => "builtin:clearInterval",
                    _ => "builtin:clearImmediate",
                };
                let handle = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
                let operation = match builtin.kind {
                    BuiltinFunctionKind::ClearTimeout => Some(TimerOperation::ClearTimeout),
                    BuiltinFunctionKind::ClearInterval => Some(TimerOperation::ClearInterval),
                    _ => None,
                };
                let ifc_label = self.join_arg_range_label(args)?;
                self.timer_clear_from_value(&handle, witness_tag, operation, ifc_label)
            }
            BuiltinFunctionKind::QueueMicrotask => {
                let callback = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
                self.queue_microtask_from_value(&callback)
            }
            BuiltinFunctionKind::TimerHasRef
            | BuiltinFunctionKind::TimerRef
            | BuiltinFunctionKind::TimerUnref => {
                // bd-suwvw: handle-bound Timeout/Immediate methods. The bound
                // object carries `__timerId`; `unref`/`ref` toggle exit
                // permission and return the handle (chaining, like Node).
                let handle_id = builtin.bound_object.map(ObjectId).ok_or_else(|| {
                    InterpreterError::TypeError {
                        expected: "timer handle bound object".to_string(),
                        got: "missing timer handle".to_string(),
                    }
                })?;
                let timer_id = match self
                    .heap
                    .get(handle_id.0 as usize)
                    .and_then(|object| object.properties.get("__timerId"))
                {
                    Some(Value::Int(id)) => *id as u32,
                    _ => {
                        return Err(InterpreterError::TypeError {
                            expected: "timer handle with __timerId".to_string(),
                            got: "malformed timer handle".to_string(),
                        });
                    }
                };
                match builtin.kind {
                    BuiltinFunctionKind::TimerHasRef => Ok(Value::Bool(
                        self.active_timers.contains_key(&timer_id)
                            && !self.unref_timer_ids.contains(&timer_id),
                    )),
                    BuiltinFunctionKind::TimerUnref => {
                        if self.active_timers.contains_key(&timer_id) {
                            self.unref_timer_ids.insert(timer_id);
                        }
                        Ok(Value::Object(handle_id))
                    }
                    _ => {
                        self.unref_timer_ids.remove(&timer_id);
                        Ok(Value::Object(handle_id))
                    }
                }
            }
        }
    }

    pub(super) fn evaluate_module_ir3(
        &mut self,
        module: &Ir3Module,
        specifier: &str,
    ) -> Result<bool, InterpreterError> {
        let snapshot = self.snapshot_module_execution()?;
        let previous_cjs_context = self.active_cjs_context.take();
        if let Err(err) = self.prepare_module_execution(specifier) {
            self.active_cjs_context = previous_cjs_context;
            self.restore_module_execution(snapshot, false);
            return Err(err);
        }
        let result = self.run_nested_module_execution(module);
        let suspended = result.is_ok()
            && self
                .top_level_await_resumption_contexts
                .values()
                .any(|context| context.module_specifier == specifier);
        let suspended_execution = if suspended {
            match self.snapshot_module_execution() {
                Ok(execution) => Some(execution),
                Err(error) => {
                    self.restore_module_execution(snapshot, true);
                    self.active_cjs_context = previous_cjs_context;
                    return Err(error);
                }
            }
        } else {
            None
        };
        let async_settlement_failure =
            self.module_state
                .modules
                .get(specifier)
                .and_then(|record| match &record.status {
                    ModuleRuntimeStatus::Failed(reason) => Some(reason.clone()),
                    _ => None,
                });
        let thrown = self.take_nested_module_throw(&result);
        self.restore_module_execution(snapshot, true);
        self.active_cjs_context = previous_cjs_context;
        self.rearm_nested_module_throw(thrown)?;
        result?;
        if let Some(reason) = async_settlement_failure {
            return Err(InterpreterError::ModuleEvaluationFailed {
                specifier: specifier.to_string(),
                reason,
            });
        }
        if let Some(execution) = suspended_execution {
            let record = self
                .module_state
                .modules
                .get_mut(specifier)
                .ok_or_else(|| InterpreterError::ModuleEvaluationFailed {
                    specifier: specifier.to_string(),
                    reason: "module record disappeared while parking async evaluation".to_string(),
                })?;
            record.async_execution = Some(execution);
        }
        Ok(suspended)
    }

    pub(super) fn evaluate_cjs_ir3(
        &mut self,
        module: &Ir3Module,
        specifier: &str,
    ) -> Result<(), InterpreterError> {
        let snapshot = self.snapshot_module_execution()?;
        let previous_cjs_context = self.active_cjs_context.take();
        let parent_module_object = previous_cjs_context
            .as_ref()
            .map(|context| context.module_object);
        if let Err(err) = self.prepare_module_execution(specifier) {
            self.active_cjs_context = previous_cjs_context;
            self.restore_module_execution(snapshot, false);
            return Err(err);
        }
        let cjs_context = match self.init_cjs_environment(module, specifier, parent_module_object) {
            Ok(context) => context,
            Err(err) => {
                self.active_cjs_context = previous_cjs_context;
                self.restore_module_execution(snapshot, true);
                return Err(err);
            }
        };
        if let Some(record) = self.module_state.modules.get_mut(specifier) {
            record.cjs_module_object = Some(cjs_context.module_object);
        }
        self.active_cjs_context = Some(cjs_context.clone());
        let gc_armed = self.gc_arm_cjs_entry(&snapshot);
        let eval_outcome = self.run_nested_module_execution(module);
        if let Some(previous) = gc_armed {
            self.gc_restore_safe_depth(previous);
        }
        let finalize_outcome = if eval_outcome.is_ok() {
            self.finalize_cjs_exports(Some(module), &cjs_context)
        } else {
            Ok(())
        };
        let loaded_outcome = if eval_outcome.is_ok() && finalize_outcome.is_ok() {
            self.set_object_property(
                cjs_context.module_object,
                "loaded".to_string(),
                Value::Bool(true),
            )
        } else {
            Ok(())
        };
        let outcome = eval_outcome.and(finalize_outcome).and(loaded_outcome);
        let thrown = self.take_nested_module_throw(&outcome);
        self.restore_module_execution(snapshot, true);
        self.active_cjs_context = previous_cjs_context;
        self.rearm_nested_module_throw(thrown)?;
        outcome
    }

    /// A module namespace lists its exports in code-unit order of their names
    /// (ES2020 9.4.6.11 [[OwnPropertyKeys]]); they register while the module
    /// evaluates, so the namespace is put in that order once it has finished.
    /// The Symbol-keyed properties (its @@toStringTag) are carried over: the
    /// reorder cleared the whole map, so a namespace whose exports arrived
    /// out of order (a hoisted function before an earlier-sorting `let`)
    /// lost "Module" while its bytes stayed charged (bd-9vouw.471).
    pub(super) fn sort_module_namespace_keys(
        &mut self,
        specifier: &str,
    ) -> Result<(), InterpreterError> {
        let Some(namespace) = self
            .module_state
            .modules
            .get(specifier)
            .map(|record| record.namespace_object)
        else {
            return Ok(());
        };
        let Some(object) = self.heap.get(namespace.0 as usize) else {
            return Ok(());
        };
        let mut entries: Vec<(Vec<u16>, JsString, Value)> = object
            .properties
            .exact_entries()
            .into_iter()
            .map(|(key, value)| (key.code_units_vec(), key, value.clone()))
            .collect();
        if entries.is_sorted_by(|a, b| a.0 <= b.0) {
            return Ok(());
        }
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        let previous_bytes = Self::estimate_ordered_property_map_bytes(&object.properties);
        let mut sorted = OrderedStringMap::new();
        for (_, key, value) in entries {
            sorted.insert_exact(key, value);
        }
        for (symbol, property) in object.properties.baseline_symbol_properties() {
            sorted.insert_baseline_symbol_property(symbol, property.clone());
        }
        let next_bytes = Self::estimate_ordered_property_map_bytes(&sorted);
        self.apply_memory_component_delta(previous_bytes, next_bytes)?;
        self.mutate_heap(|heap| heap[namespace.0 as usize].properties = sorted);
        Ok(())
    }

    /// The value a nested module evaluation threw, taken from its pending-
    /// exception slot before the importer's execution is restored, which
    /// would discard it.
    pub(super) fn take_nested_module_throw<T>(
        &mut self,
        outcome: &Result<T, InterpreterError>,
    ) -> Option<(Value, Label)> {
        if matches!(outcome, Err(InterpreterError::UncaughtException { .. })) {
            self.take_pending_exception_slot()
        } else {
            None
        }
    }

    /// Re-arm a nested module's thrown value as the importer's pending
    /// exception, so `try { require(m) } catch (e)` and an ImportCall's
    /// rejection receive the value itself rather than its description.
    pub(super) fn rearm_nested_module_throw(
        &mut self,
        thrown: Option<(Value, Label)>,
    ) -> Result<(), InterpreterError> {
        match thrown {
            Some(slot) => self.replace_pending_abrupt_slots(Some(slot), None),
            None => Ok(()),
        }
    }

    pub(super) fn run_nested_module_execution(
        &mut self,
        module: &Ir3Module,
    ) -> Result<(), InterpreterError> {
        let result = match self.run_loop(module) {
            // Imported code shares the execution's jobs and authority. A
            // terminal failure must not run that shared queue before the
            // loader restores the caller and propagates the original error.
            Err(error) if Self::stops_guest_execution(&error) => return Err(error),
            result => result,
        };
        self.drain_runtime_checkpoint(Some(module))?;
        match result {
            Ok(_) | Err(InterpreterError::Halted) => Ok(()),
            Err(err) => Err(err),
        }
    }

    pub(super) fn register_module_export(
        &mut self,
        name: &str,
        value: Value,
    ) -> Result<(), InterpreterError> {
        self.register_module_export_exact_labeled(JsString::from(name), value, Label::Public)
    }

    pub(super) fn register_module_export_exact(
        &mut self,
        name: JsString,
        value: Value,
    ) -> Result<(), InterpreterError> {
        self.register_module_export_exact_labeled(name, value, Label::Public)
    }

    pub(super) fn register_module_export_exact_labeled(
        &mut self,
        name: JsString,
        value: Value,
        label: Label,
    ) -> Result<(), InterpreterError> {
        let Some(specifier) = self.current_module_specifier.clone() else {
            return Err(InterpreterError::ExportOutsideModule {
                name: name.to_string(),
            });
        };
        self.publish_module_export(&specifier, name, value, label, ExportPublication::Own)
    }

    /// Publish `value` as export `name` of module `specifier`: its export
    /// record, its namespace object's property and every importer's binding
    /// cell of that name (bd-1lsy.4.10.1). The cells stay registered, so each
    /// later publication writes them too: imports are live. A cell keeps the
    /// join of every label published to it. A cell that itself backs an
    /// export (a re-exported import) republishes that export in turn.
    pub(super) fn publish_module_export(
        &mut self,
        specifier: &str,
        name: JsString,
        value: Value,
        label: Label,
        publication: ExportPublication,
    ) -> Result<(), InterpreterError> {
        let mut cascade = ModuleExportCascade::default();
        let outcome = (|| {
            self.queue_module_export(&mut cascade, specifier, &name, &label, publication)?;
            self.drain_module_export_cascade(&mut cascade, &value)
        })();
        let temporary_bytes = cascade.temporary_bytes;
        drop(cascade);
        self.json_release_temporary(temporary_bytes);
        outcome
    }

    fn module_export_key_bytes(specifier: &str, name: &JsString) -> u64 {
        MEMORY_ESTIMATE_MAP_ENTRY_BYTES
            .saturating_add(std::mem::size_of::<(String, JsString)>() as u64)
            .saturating_add(Self::estimate_string_bytes(specifier))
            .saturating_add(Self::estimate_js_string_bytes(name))
    }

    fn queue_module_export(
        &mut self,
        cascade: &mut ModuleExportCascade,
        specifier: &str,
        name: &JsString,
        label: &Label,
        publication: ExportPublication,
    ) -> Result<(), InterpreterError> {
        // Meter edges as well as publications: repeated diamond paths must not
        // create unbounded native work outside the guest instruction budget.
        self.json_charge_work()?;
        let key_bytes = Self::module_export_key_bytes(specifier, name);
        self.json_reserve_temporary(key_bytes)?;
        let key = (specifier.to_string(), name.clone());
        let outcome = (|| {
            let previous = cascade.states.get(&key);
            let next_publication = if publication == ExportPublication::Own
                || previous.is_some_and(|(_, prior)| *prior == ExportPublication::Own)
            {
                ExportPublication::Own
            } else {
                ExportPublication::Star
            };
            if previous.is_some_and(|(prior_label, prior_publication)| {
                prior_label >= label && *prior_publication == next_publication
            }) {
                return Ok(());
            }
            let next_label = previous.map(|(prior, _)| prior.max(label)).unwrap_or(label);
            let previous_label_bytes = previous
                .map(|(prior, _)| Self::estimate_label_bytes(prior))
                .unwrap_or(0);
            let next_label_bytes = Self::estimate_label_bytes(next_label);
            let new_state_bytes = if previous.is_none() {
                key_bytes.saturating_add(std::mem::size_of::<(Label, ExportPublication)>() as u64)
            } else {
                0
            };
            let new_pending_bytes = if cascade.pending.contains(&key) {
                0
            } else {
                key_bytes
            };
            let additional = new_state_bytes
                .saturating_add(new_pending_bytes)
                .saturating_add(next_label_bytes.saturating_sub(previous_label_bytes));
            // The replacement label can coexist with the old map entry until
            // insert returns. Reserve that temporary copy before cloning it.
            self.json_reserve_temporary(additional.saturating_add(next_label_bytes))?;
            let next_label = next_label.clone();
            if let Some(state) = cascade.states.get_mut(&key) {
                *state = (next_label, next_publication);
            } else {
                cascade
                    .states
                    .insert(key.clone(), (next_label, next_publication));
            }
            if new_pending_bytes != 0 {
                cascade.pending.insert(key.clone());
            }
            cascade.temporary_bytes = cascade.temporary_bytes.saturating_add(additional);
            let released = previous_label_bytes.saturating_sub(next_label_bytes);
            cascade.temporary_bytes = cascade.temporary_bytes.saturating_sub(released);
            self.json_release_temporary(next_label_bytes.saturating_add(released));
            Ok(())
        })();
        drop(key);
        self.json_release_temporary(key_bytes);
        outcome
    }

    fn drain_module_export_cascade(
        &mut self,
        cascade: &mut ModuleExportCascade,
        value: &Value,
    ) -> Result<(), InterpreterError> {
        while let Some(key) = cascade.pending.pop_first() {
            let key_bytes = Self::module_export_key_bytes(&key.0, &key.1);
            let (label, publication) = cascade
                .states
                .get(&key)
                .expect("queued export has publication state");
            let label_bytes = Self::estimate_label_bytes(label);
            self.json_reserve_temporary(label_bytes)?;
            let label = label.clone();
            let publication = *publication;
            let outcome = self.publish_module_export_step(
                &key.0,
                key.1.clone(),
                value.clone(),
                label,
                publication,
                cascade,
            );
            drop(key);
            cascade.temporary_bytes = cascade.temporary_bytes.saturating_sub(key_bytes);
            self.json_release_temporary(key_bytes.saturating_add(label_bytes));
            outcome?;
        }
        Ok(())
    }

    fn publish_module_export_step(
        &mut self,
        specifier: &str,
        name: JsString,
        value: Value,
        label: Label,
        publication: ExportPublication,
        cascade: &mut ModuleExportCascade,
    ) -> Result<(), InterpreterError> {
        let diagnostic_name = name.to_string();
        let (namespace_object, previous_export_bytes, pending_cells) = {
            let record = self
                .module_state
                .modules
                .get_mut(specifier)
                .ok_or_else(|| InterpreterError::ExportOutsideModule {
                    name: diagnostic_name.clone(),
                })?;
            let previous_export_bytes = record
                .exports
                .get(&name)
                .map(|previous| Self::estimate_js_string_map_entry_bytes(&name, previous))
                .unwrap_or(0);
            // An importer whose scope and closures are gone drops out.
            let mut cells: Vec<Rc<RefCell<ScopeBindingState>>> = Vec::new();
            if let Some(watchers) = record.import_bindings.get_mut(&name) {
                watchers.retain(|watcher| watcher.strong_count() > 0);
                for cell in watchers.iter().filter_map(Weak::upgrade) {
                    if !cells.iter().any(|seen| Rc::ptr_eq(seen, &cell)) {
                        cells.push(cell);
                    }
                }
            }
            (record.namespace_object, previous_export_bytes, cells)
        };
        let next_export_bytes = Self::estimate_js_string_map_entry_bytes(&name, &value);
        let mut previous_cell_states = Vec::with_capacity(pending_cells.len());
        let mut next_cell_labels = Vec::with_capacity(pending_cells.len());
        let mut previous_cell_payload_bytes = 0u64;
        for cell in &pending_cells {
            let old_state = cell
                .try_borrow()
                .map_err(|_| InterpreterError::InternalError {
                    details: "module import binding is already mutably borrowed".to_string(),
                })?
                .clone();
            previous_cell_payload_bytes = previous_cell_payload_bytes
                .saturating_add(Self::estimate_binding_cell_payload_bytes(cell));
            next_cell_labels.push(
                self.join_owned_label_with_temporary_budget(old_state.label.clone(), &label)?,
            );
            previous_cell_states.push((Rc::clone(cell), old_state));
        }
        // Acquire every cell before publishing any value. A borrowed later
        // cell must not leave earlier imports partially initialized.
        let mut states = pending_cells
            .iter()
            .map(|cell| {
                cell.try_borrow_mut()
                    .map_err(|_| InterpreterError::InternalError {
                        details: "module import binding is already borrowed".to_string(),
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        for (state, next_label) in states.iter_mut().zip(next_cell_labels) {
            state.value = value.clone();
            state.label = next_label;
            state.initialized = true;
        }
        drop(states);
        for cell in &pending_cells {
            self.closures.refresh_cell(cell);
        }
        // Each cell is charged once wherever it is reachable (an importer's
        // scope frame, a closure's cold ledger), so its payload change is the
        // whole delta, as for a scoped store (bd-9vouw.31): publishing does
        // not walk every live cell.
        let next_cell_payload_bytes = pending_cells.iter().fold(0u64, |total, cell| {
            total.saturating_add(Self::estimate_binding_cell_payload_bytes(cell))
        });
        if let Err(error) =
            self.apply_memory_component_delta(previous_cell_payload_bytes, next_cell_payload_bytes)
        {
            for (cell, previous) in &previous_cell_states {
                *cell.borrow_mut() = previous.clone();
                self.closures.refresh_cell(cell);
            }
            return Err(error);
        }
        if let Err(error) =
            self.apply_memory_component_delta(previous_export_bytes, next_export_bytes)
        {
            for (cell, previous) in &previous_cell_states {
                *cell.borrow_mut() = previous.clone();
                self.closures.refresh_cell(cell);
            }
            self.sync_estimated_memory_bytes()?;
            return Err(error);
        }
        let previous_export = {
            let record = self
                .module_state
                .modules
                .get_mut(specifier)
                .expect("module record was validated before export preflight");
            record.exports.insert(name.clone(), value.clone())
        };
        // A star re-exporter republishes the value below.
        match self.set_module_namespace_export(
            namespace_object,
            name.clone(),
            value.clone(),
            &label,
        ) {
            Ok(()) => {
                let record = self
                    .module_state
                    .modules
                    .get_mut(specifier)
                    .expect("module export record existed after namespace update");
                // The module's own export of this name wins over any star
                // re-export (module_export_star re-marks its own names).
                if publication == ExportPublication::Own {
                    record.star_exports.remove(&name);
                }
                let star_reexporters = record.star_reexporters.clone();
                for cell in &pending_cells {
                    let live_export = cell
                        .try_borrow()
                        .map_err(|_| InterpreterError::InternalError {
                            details: "module import binding is already mutably borrowed"
                                .to_string(),
                        })?
                        .live_export;
                    if let Some(live_export) = live_export {
                        self.queue_live_export(cascade, cell, live_export)?;
                    }
                }
                // A module that still provides this name through
                // `export * from` this one republishes it.
                for reexporter in star_reexporters {
                    let provided =
                        self.module_state
                            .modules
                            .get(&reexporter)
                            .is_some_and(|record| {
                                record.star_exports.get(&name) == Some(&StarExportOrigin::Provided)
                            });
                    if provided {
                        self.queue_module_export(
                            cascade,
                            &reexporter,
                            &name,
                            &label,
                            ExportPublication::Star,
                        )?;
                    }
                }
                Ok(())
            }
            Err(error) => {
                let record = self
                    .module_state
                    .modules
                    .get_mut(specifier)
                    .expect("module export record existed before namespace update");
                match previous_export {
                    Some(previous) => {
                        record.exports.insert(name.clone(), previous);
                    }
                    None => {
                        record.exports.remove(&name);
                    }
                }
                self.estimated_memory_bytes = self
                    .estimated_memory_bytes
                    .saturating_sub(next_export_bytes)
                    .saturating_add(previous_export_bytes);
                for (cell, previous) in &previous_cell_states {
                    *cell.borrow_mut() = previous.clone();
                    self.closures.refresh_cell(cell);
                }
                self.sync_estimated_memory_bytes()?;
                Err(error)
            }
        }
    }

    /// Publish an exported binding into its namespace's private carrier.
    /// Guests see a non-extensible exotic object with writable, enumerable,
    /// non-configurable data descriptors; only the exporting module can
    /// change their values. Project the value, label and descriptor together
    /// so a budget refusal cannot leave a partially published property.
    pub(super) fn set_module_namespace_export(
        &mut self,
        namespace: ObjectId,
        name: JsString,
        value: Value,
        label: &Label,
    ) -> Result<(), InterpreterError> {
        let key = RuntimePropertyKey::String(name.clone());
        self.validate_executable_property_key(&key)?;
        validate_symbol_value(&self.symbol_state, &value).map_err(|got| {
            InterpreterError::TypeError {
                expected: "resolved Symbol value".to_string(),
                got,
            }
        })?;
        let object = self
            .heap
            .get(namespace.0 as usize)
            .ok_or(InterpreterError::ObjectNotFound { id: namespace.0 })?;
        let previous_bytes = Self::estimate_ordered_property_map_bytes(&object.properties)
            .saturating_add(Self::estimate_execution_seed_ordered_label_map_bytes(
                &object.property_labels,
            ));
        let attribute_bytes = if object.property_attributes.contains_key(&key) {
            0
        } else {
            Self::estimate_property_attributes_entry_bytes(&key)
        };
        self.check_temporary_memory_budget(previous_bytes)?;
        let mut properties = object.properties.clone();
        let mut labels = object.property_labels.clone();
        properties.insert_exact(name.clone(), value);
        if matches!(label, Label::Public) {
            labels.remove_exact(&name);
        } else {
            labels.insert_exact(name, label.clone());
        }
        let next_bytes = Self::estimate_ordered_property_map_bytes(&properties).saturating_add(
            Self::estimate_execution_seed_ordered_label_map_bytes(&labels),
        );
        self.check_temporary_memory_budget(next_bytes.saturating_add(attribute_bytes))?;
        self.apply_memory_component_delta(
            previous_bytes,
            next_bytes.saturating_add(attribute_bytes),
        )?;
        self.mutate_heap(|heap| {
            let object = &mut heap[namespace.0 as usize];
            object.properties = properties;
            object.property_labels = labels;
            object.property_attributes.insert(
                key,
                PropertyAttributes {
                    writable: true,
                    enumerable: true,
                    configurable: false,
                },
            );
        });
        self.gc_write_barrier(namespace);
        Ok(())
    }

    /// Record `cell`, a scope binding of module `specifier` that an
    /// `ExportBinding` just published as `name`, as that export's local
    /// binding (bd-1lsy.4.10.1): its later writes republish the export.
    pub(super) fn track_live_export(
        &mut self,
        cell: &Rc<RefCell<ScopeBindingState>>,
        specifier: String,
        name: JsString,
    ) -> Result<(), InterpreterError> {
        let borrow_error = || InterpreterError::InternalError {
            details: "exported module binding is already borrowed".to_string(),
        };
        let existing = cell.try_borrow().map_err(|_| borrow_error())?.live_export;
        let target = (specifier, name);
        if let Some(existing) = existing
            && let Some(entry) = self
                .module_state
                .live_exports
                .get_mut(existing.get() as usize - 1)
            && Rc::ptr_eq(&entry.cell, cell)
        {
            if !entry.exports.contains(&target) {
                entry.exports.push(target);
            }
            return Ok(());
        }
        let slot = u32::try_from(self.module_state.live_exports.len() + 1)
            .ok()
            .and_then(std::num::NonZeroU32::new)
            .ok_or_else(|| InterpreterError::InternalError {
                details: "too many exported module bindings".to_string(),
            })?;
        self.closures.cold_cells.register_cell(cell);
        self.module_state.live_exports.push(LiveExport {
            cell: Rc::clone(cell),
            exports: vec![target],
        });
        cell.try_borrow_mut()
            .map_err(|_| borrow_error())?
            .live_export = Some(slot);
        Ok(())
    }

    /// Register an importer's binding `cell`, initialized from export
    /// `export_name` of the module whose namespace object is
    /// `namespace_object`, with that module's record (bd-1lsy.4.10.1).
    /// In a cycle the module may not have published the export yet: its
    /// function and var exports are published before its imports run, so
    /// the export is a lexical binding (`let`, `const`, `class`, a default
    /// expression) still in its temporal dead zone, and the import is too
    /// until the publication initializes it.
    pub(super) fn watch_module_export(
        &mut self,
        namespace_object: ObjectId,
        export_name: JsString,
        cell: &Rc<RefCell<ScopeBindingState>>,
    ) -> Result<(), InterpreterError> {
        let Some(record) = self
            .module_state
            .modules
            .values_mut()
            .find(|record| record.namespace_object == namespace_object)
        else {
            return Ok(());
        };
        if matches!(record.status, ModuleRuntimeStatus::Evaluating)
            && !record.exports.contains_key(&export_name)
        {
            cell.try_borrow_mut()
                .map_err(|_| InterpreterError::InternalError {
                    details: "module import binding is already borrowed".to_string(),
                })?
                .initialized = false;
        }
        let watchers = record.import_bindings.entry(export_name).or_default();
        watchers.retain(|watcher| watcher.strong_count() > 0);
        if !watchers
            .iter()
            .any(|watcher| watcher.as_ptr() == Rc::as_ptr(cell))
        {
            watchers.push(Rc::downgrade(cell));
        }
        Ok(())
    }

    /// `cell`, a module binding that backs exports (`live_export` names its
    /// entry), was written: publish its value as each of those exports
    /// (bd-1lsy.4.10.1). A stale index (a cell of an earlier execution)
    /// publishes nothing.
    pub(super) fn publish_live_export(
        &mut self,
        cell: &Rc<RefCell<ScopeBindingState>>,
        live_export: std::num::NonZeroU32,
    ) -> Result<(), InterpreterError> {
        let mut cascade = ModuleExportCascade::default();
        let outcome = (|| {
            self.queue_live_export(&mut cascade, cell, live_export)?;
            if cascade.pending.is_empty() {
                return Ok(());
            }
            let value = cell
                .try_borrow()
                .map_err(|_| InterpreterError::InternalError {
                    details: "exported module binding is already mutably borrowed".to_string(),
                })?
                .value
                .clone();
            self.drain_module_export_cascade(&mut cascade, &value)
        })();
        let temporary_bytes = cascade.temporary_bytes;
        drop(cascade);
        self.json_release_temporary(temporary_bytes);
        outcome
    }

    fn queue_live_export(
        &mut self,
        cascade: &mut ModuleExportCascade,
        cell: &Rc<RefCell<ScopeBindingState>>,
        live_export: std::num::NonZeroU32,
    ) -> Result<(), InterpreterError> {
        let Some(entry) = self
            .module_state
            .live_exports
            .get(live_export.get() as usize - 1)
        else {
            return Ok(());
        };
        if !Rc::ptr_eq(&entry.cell, cell) {
            return Ok(());
        }
        let export_bytes = entry.exports.iter().fold(0u64, |total, (specifier, name)| {
            total.saturating_add(Self::module_export_key_bytes(specifier, name))
        });
        let label_bytes = {
            let state = cell
                .try_borrow()
                .map_err(|_| InterpreterError::InternalError {
                    details: "exported module binding is already mutably borrowed".to_string(),
                })?;
            Self::estimate_label_bytes(&state.label)
        };
        let temporary_bytes = export_bytes.saturating_add(label_bytes);
        self.json_reserve_temporary(temporary_bytes)?;
        let outcome = (|| {
            let exports = self.module_state.live_exports[live_export.get() as usize - 1]
                .exports
                .clone();
            let label = cell
                .try_borrow()
                .map_err(|_| InterpreterError::InternalError {
                    details: "exported module binding is already mutably borrowed".to_string(),
                })?
                .label
                .clone();
            for (specifier, name) in &exports {
                self.queue_module_export(cascade, specifier, name, &label, ExportPublication::Own)?;
            }
            Ok(())
        })();
        self.json_release_temporary(temporary_bytes);
        outcome
    }

    /// `export * from m` (bd-332pq): every export of `m` except `default`
    /// becomes an export of the current module unless the module exports
    /// that name itself. When two star sources provide one name with
    /// different values the name is ambiguous (ES2020 ResolveExport) and the
    /// module does not export it; the same value through two paths (a
    /// diamond) is not ambiguous. Values are copied when the statement runs,
    /// as named re-exports are.
    pub(super) fn module_export_star(&mut self, args: RegRange) -> Result<Value, InterpreterError> {
        if args.count != 1 {
            return Err(InterpreterError::TypeError {
                expected: "one module namespace for export *".to_string(),
                got: format!("{} argument(s)", args.count),
            });
        }
        let namespace = self.read_reg(args.start)?;
        let label = self.get_register_label(args.start)?.clone();
        let Value::Object(namespace_object) = namespace else {
            return Err(InterpreterError::TypeError {
                expected: "module namespace object".to_string(),
                got: namespace.type_name().to_string(),
            });
        };
        let Some(specifier) = self.current_module_specifier.clone() else {
            return Err(InterpreterError::ExportOutsideModule {
                name: "*".to_string(),
            });
        };
        let source = self
            .module_state
            .modules
            .values_mut()
            .find(|record| record.namespace_object == namespace_object)
            .ok_or_else(|| InterpreterError::TypeError {
                expected: "export * source with a module record".to_string(),
                got: "a namespace without module exports".to_string(),
            })?;
        // bd-1lsy.4.10.1: the source's later publications reach this module.
        source.star_reexporters.insert(specifier.clone());
        let source_exports: Vec<(JsString, Value)> = source
            .exports
            .iter()
            .filter(|(name, _)| name.as_str() != Some("default"))
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect();
        for (name, value) in source_exports {
            // Decide under a shared borrow of the module record, then act.
            let (withdraw, register) = {
                let record = self.module_state.modules.get(&specifier).ok_or_else(|| {
                    InterpreterError::ExportOutsideModule {
                        name: name.to_string(),
                    }
                })?;
                match (record.star_exports.get(&name), record.exports.get(&name)) {
                    (Some(StarExportOrigin::Ambiguous), _) => (false, false),
                    (Some(StarExportOrigin::Provided), Some(existing)) => {
                        (!Self::same_value(existing, &value), false)
                    }
                    // The module's own export of this name wins.
                    (None, Some(_)) => (false, false),
                    (_, None) => (false, true),
                }
            };
            if withdraw {
                self.withdraw_ambiguous_star_export(&specifier, &name)?;
            }
            if register {
                self.register_module_export_exact_labeled(name.clone(), value, label.clone())?;
                if let Some(record) = self.module_state.modules.get_mut(&specifier) {
                    record.star_exports.insert(name, StarExportOrigin::Provided);
                }
            }
        }
        Ok(Value::Undefined)
    }

    /// Remove a star-provided export that a second star source contradicts.
    pub(super) fn withdraw_ambiguous_star_export(
        &mut self,
        specifier: &str,
        name: &JsString,
    ) -> Result<(), InterpreterError> {
        let record = self
            .module_state
            .modules
            .get_mut(specifier)
            .ok_or_else(|| InterpreterError::ExportOutsideModule {
                name: name.to_string(),
            })?;
        record
            .star_exports
            .insert(name.clone(), StarExportOrigin::Ambiguous);
        let namespace_object = record.namespace_object;
        let Some(previous) = record.exports.remove(name) else {
            return Ok(());
        };
        let previous_bytes = Self::estimate_js_string_map_entry_bytes(name, &previous);
        self.remove_object_runtime_property(
            namespace_object,
            &RuntimePropertyKey::String(name.clone()),
        )?;
        self.apply_memory_component_delta(previous_bytes, 0)
            .map(|_| ())
    }

    pub(super) fn complete_return(
        &mut self,
        module: Option<&Ir3Module>,
        return_val: Value,
        return_label: Label,
    ) -> Result<Option<LabeledReturn>, InterpreterError> {
        let return_label = if let Some(context) = self.active_execution_context_label().cloned() {
            self.join_owned_label_with_temporary_budget(return_label, &context)?
        } else {
            return_label
        };
        let current_depth = self.call_stack.len();
        // A function can return from inside an active try block before `EndTry`
        // executes. Those catch frames belong to the returning callee and must
        // not leak into the caller's unwind state.
        self.catch_frames
            .retain(|frame| frame.call_depth < current_depth);
        let scope_inert_activation = self
            .call_stack
            .last()
            .is_some_and(|frame| frame.scope_inert_virtual_scope_bytes > 0);
        // bd-9vouw.31: returning swaps the callee's chain for the caller's
        // saved one. Only structural bytes and the cells of frames the callee
        // pushed change, so neither side is re-walked.
        let previous_scope_bytes =
            (!scope_inert_activation).then(|| self.scope_chain_structural_bytes());
        #[cfg(debug_assertions)]
        let walked_scope_before =
            (!scope_inert_activation).then(|| self.scope_chain_memory_bytes());
        let previous_closure_bytes =
            (!scope_inert_activation).then(|| self.closures_memory_bytes());
        let previous_call_stack_bytes = self.call_stack_memory_bytes();
        if let Some(mut frame) = self.call_stack.pop(&mut self.closures.cold_cells) {
            let new_depth = self.call_stack.len();
            while self
                .pc_label_stack
                .last()
                .is_some_and(|pc| pc.call_depth > new_depth)
            {
                self.pc_label_stack.pop();
            }
            let completion = if frame.derived_constructor {
                if return_val.is_object_like() {
                    Ok((return_val, return_label))
                } else if !matches!(&return_val, Value::Undefined) {
                    Err(InterpreterError::TypeError {
                        expected: "object or undefined from derived constructor".to_string(),
                        got: return_val.type_name().to_string(),
                    })
                } else if frame.this_initialized {
                    Ok((frame.this_value.clone(), frame.this_label.clone()))
                } else {
                    Err(InterpreterError::UninitializedBinding {
                        name: "this".to_string(),
                    })
                }
            } else {
                Ok(match &frame.construct_this {
                    Some(this_obj) if !return_val.is_object_like() => {
                        (this_obj.clone(), frame.this_label.clone())
                    }
                    _ => (return_val, return_label),
                })
            };
            let async_function_id = frame.async_function_id;
            let async_failure_label = async_function_id.map(|_| {
                let label = completion
                    .as_ref()
                    .map(|(_, label)| label)
                    .unwrap_or(&Label::Public);
                Self::terminal_async_failure_label(label)
            });
            let return_ip = frame.return_ip;
            let callee_frames = if scope_inert_activation {
                self.restore_call_frame_state(&mut frame);
                Vec::new()
            } else {
                self.restore_call_frame_control_state(&mut frame);
                self.swap_back_returning_scope_chain(&mut frame)
            };
            self.ip = return_ip;
            let frame_memory_result = match (previous_scope_bytes, previous_closure_bytes) {
                (Some(previous_scope_bytes), Some(previous_closure_bytes)) => {
                    let released_cell_bytes =
                        self.released_frame_cell_payload_bytes(&callee_frames);
                    #[cfg(debug_assertions)]
                    self.debug_assert_scope_swap_delta(
                        walked_scope_before.expect("ordinary scope accounting"),
                        previous_scope_bytes,
                        released_cell_bytes,
                    );
                    self.apply_structural_scope_closure_call_stack_memory_delta(
                        previous_scope_bytes.saturating_add(released_cell_bytes),
                        previous_closure_bytes,
                        previous_call_stack_bytes,
                    )
                }
                (None, None) => self.apply_call_stack_memory_delta(previous_call_stack_bytes),
                _ => unreachable!("scope and closure accounting share one activation proof"),
            };
            if let Err(error) = frame_memory_result {
                if let (Some(async_id), Some(label)) = (async_function_id, async_failure_label) {
                    self.terminally_reject_abandoned_async_functions(&[async_id], label);
                }
                return Err(error);
            }
            let (effective_val, effective_label) = completion?;
            if frame.initialize_derived_this_on_return {
                let derived_frame =
                    self.call_stack
                        .last_mut()
                        .ok_or_else(|| InterpreterError::TypeError {
                            expected: "enclosing derived constructor".to_string(),
                            got: "missing caller frame after super()".to_string(),
                        })?;
                if !derived_frame.derived_constructor || derived_frame.this_initialized {
                    return Err(InterpreterError::TypeError {
                        expected: "uninitialized enclosing derived-constructor this binding"
                            .to_string(),
                        got: "super() attempted to initialize this twice".to_string(),
                    });
                }
                derived_frame.this_value = effective_val.clone();
                derived_frame.this_label = effective_label.clone();
                derived_frame.this_initialized = true;
            }
            if let Some(async_id) = async_function_id {
                if let Err(error) =
                    self.settle_async_function(module, async_id, Ok(effective_val), effective_label)
                {
                    self.terminally_reject_abandoned_async_functions(
                        &[async_id],
                        async_failure_label.expect("async completion retained its failure label"),
                    );
                    return Err(error);
                }
            } else {
                self.write_reg_with_label(frame.return_reg, effective_val, effective_label)?;
            }
            if frame.initialize_derived_this_on_return {
                self.run_derived_class_instance_fields(module)?;
            }
            Ok(None)
        } else {
            self.clear_pending_abrupt_slots();
            self.clear_suspended_abrupt_completions();
            self.clear_finally_frames();
            self.pending_finally_entry = None;
            Ok(Some(LabeledReturn {
                value: return_val,
                label: return_label,
            }))
        }
    }

    pub(super) fn restore_call_frame_state(&mut self, frame: &mut CallFrame) {
        self.restore_call_frame_control_state(frame);
        self.restore_scope_chain_for_frame(frame);
    }

    /// Everything [`Self::restore_call_frame_state`] restores but the scope
    /// chain.
    pub(super) fn restore_call_frame_control_state(&mut self, frame: &mut CallFrame) {
        self.register_base = frame.register_base;
        self.register_width = frame.register_width;
        self.suspended_abrupt_completions
            .truncate(frame.saved_suspended_abrupt_depth);
        self.finally_frames.truncate(frame.saved_finally_mode_depth);
        self.pending_exception = frame.saved_pending_exception.take();
        self.pending_exception_label =
            std::mem::replace(&mut frame.saved_pending_exception_label, Label::Public);
        self.pending_return = frame.saved_pending_return.take();
    }

    /// The scope half of [`Self::restore_call_frame_state`] for the frame
    /// `complete_return` pops from an activation that replaced the chain,
    /// giving back the callee frames that leave the chain for
    /// `released_frame_cell_payload_bytes`. They were cloned before the swap:
    /// a Vec and a reference count per frame on every return (bd-9vouw.504).
    /// A plain return also moves the saved chain back instead of cloning it.
    /// An async settle or a derived constructor's field initializers run code
    /// before the frame drops, so those keep the frame's copy, and with it
    /// every map's sharing count, until then, as before.
    pub(super) fn swap_back_returning_scope_chain(
        &mut self,
        frame: &mut CallFrame,
    ) -> Vec<ScopeFrame> {
        debug_assert_eq!(frame.scope_inert_virtual_scope_bytes, 0);
        let runs_code_before_drop =
            frame.async_function_id.is_some() || frame.initialize_derived_this_on_return;
        let saved = if runs_code_before_drop {
            frame.saved_scope_chain.clone()
        } else {
            frame.saved_scope_chain.take()
        };
        match saved {
            Some(saved) => std::mem::replace(&mut self.scope_chain.frames, saved),
            None => {
                let mut left = Vec::new();
                while self.scope_chain.depth() > frame.saved_scope_depth {
                    let Some(popped) = self.scope_chain.pop() else {
                        break;
                    };
                    left.push(popped);
                }
                left
            }
        }
    }

    pub(super) fn settle_async_function(
        &mut self,
        module: Option<&Ir3Module>,
        async_id: u32,
        resolution: Result<Value, Value>,
        label: Label,
    ) -> Result<(), InterpreterError> {
        let result_promise = self
            .async_functions
            .get(async_id as usize)
            .ok_or_else(|| InterpreterError::TypeError {
                expected: "valid async function".to_string(),
                got: format!("async#{async_id} not found"),
            })?
            .result_promise;
        let promise_handle = crate::promise_model::PromiseHandle(result_promise);

        match resolution {
            // `return <promise or thenable>` from an async function adopts its
            // state (ES2020 25.7.5.1 step 4.g calls the resolve function), not
            // fulfills with it.
            Ok(value) => self.resolve_promise_with_value(module, promise_handle, value, label)?,
            Err(error_value) => {
                let js_reason = self.promise_value(&error_value)?;
                self.reject_promise(promise_handle, js_reason, label)?;
            }
        }
        self.async_functions[async_id as usize].phase = AsyncFunctionPhase::Completed;
        Ok(())
    }

    pub(super) fn complete_async_frame(
        &mut self,
        module: Option<&Ir3Module>,
        mut frame: CallFrame,
        resolution: Result<Value, Value>,
        label: Label,
    ) -> Result<Option<LabeledReturn>, InterpreterError> {
        let async_id = frame
            .async_function_id
            .ok_or_else(|| InterpreterError::TypeError {
                expected: "async function frame".to_string(),
                got: "missing async function id".to_string(),
            })?;
        // The frame is already popped: add back what it was charged as the
        // top frame, its own bytes and its saved chain's walked maps.
        let previous_scope_bytes = self
            .scope_chain_memory_bytes()
            .saturating_add(self.popped_frame_unwalked_map_key_bytes(&frame));
        let previous_closure_bytes = self.closures_memory_bytes();
        let previous_call_stack_bytes = self
            .call_stack_memory_bytes()
            .saturating_add(Self::estimate_live_call_frame_bytes(&frame));
        let return_ip = frame.return_ip;
        let failure_label = Self::terminal_async_failure_label(&label);
        self.restore_call_frame_state(&mut frame);
        self.ip = return_ip;
        let completion = self
            .apply_scope_closure_call_stack_memory_delta(
                previous_scope_bytes,
                previous_closure_bytes,
                previous_call_stack_bytes,
            )
            .and_then(|_| self.settle_async_function(module, async_id, resolution, label));
        match completion {
            Ok(()) => Ok(None),
            Err(error) => {
                self.terminally_reject_abandoned_async_functions(&[async_id], failure_label);
                Err(error)
            }
        }
    }

    pub(super) fn complete_current_async_frame(
        &mut self,
        module: Option<&Ir3Module>,
        resolution: Result<Value, Value>,
        label: Label,
    ) -> Result<Option<LabeledReturn>, InterpreterError> {
        let current_depth = self.call_stack.len();
        self.catch_frames
            .retain(|frame| frame.call_depth < current_depth);
        let is_async_top = self
            .call_stack
            .last()
            .and_then(|frame| frame.async_function_id)
            .is_some();
        if !is_async_top {
            return Err(InterpreterError::TypeError {
                expected: "async function context tracking".to_string(),
                got: "async completion without active async frame".to_string(),
            });
        }
        let frame = self
            .call_stack
            .pop(&mut self.closures.cold_cells)
            .ok_or_else(|| InterpreterError::TypeError {
                expected: "async function frame".to_string(),
                got: "missing call frame".to_string(),
            })?;
        self.complete_async_frame(module, frame, resolution, label)
    }

    pub(super) fn reject_nearest_async_boundary(
        &mut self,
        error_value: Value,
        error_label: Label,
    ) -> Result<bool, InterpreterError> {
        let Some(async_frame_index) = self.innermost_async_frame_index() else {
            return Ok(false);
        };

        let async_depth = async_frame_index + 1;
        self.catch_frames
            .retain(|frame| frame.call_depth < async_depth);
        let _ = self.unwind_call_stack_to(async_depth)?;
        let frame = self
            .call_stack
            .pop(&mut self.closures.cold_cells)
            .ok_or_else(|| InterpreterError::TypeError {
                expected: "async function frame".to_string(),
                got: "missing async boundary".to_string(),
            })?;
        self.complete_async_frame(None, frame, Err(error_value), error_label)?;
        Ok(true)
    }

    pub(super) fn suspend_async_function_for_await(
        &mut self,
        promise_handle: crate::promise_model::PromiseHandle,
        result_reg: u32,
        await_label: Label,
    ) -> Result<(), InterpreterError> {
        // Find the current async function from the call stack
        let async_frame_index =
            self.innermost_async_frame_index()
                .ok_or_else(|| InterpreterError::TypeError {
                    expected: "async function context".to_string(),
                    got: "await outside of async function".to_string(),
                })?;

        let current_frame = &self.call_stack[async_frame_index];
        let async_function_id =
            current_frame
                .async_function_id
                .ok_or_else(|| InterpreterError::TypeError {
                    expected: "async function id".to_string(),
                    got: "missing async function id".to_string(),
                })?;

        let async_function = self
            .async_functions
            .get(async_function_id as usize)
            .ok_or_else(|| InterpreterError::TypeError {
                expected: "valid async function".to_string(),
                got: format!("async#{async_function_id} not found"),
            })?;
        let reg_start = self.register_base;
        let window_end =
            (self.register_base + self.config.max_registers as usize).min(self.registers.len());
        // Only the window's live prefix is saved; its tail is in the state the
        // frame's entry reset left it, which resume restores (bd-9vouw.167). A
        // full V8-lane window is 4,096 registers, about 268 KB per pending call.
        let reg_end = self.register_window_live_end(reg_start, window_end);
        let saved_label_bytes = self
            .register_labels
            .get(reg_start..reg_end)
            .map(Self::estimate_label_vec_bytes)
            .ok_or_else(|| InterpreterError::TypeError {
                expected: "parallel async register-label capacity".to_string(),
                got: format!(
                    "register range {reg_start}..{reg_end}, label length {}",
                    self.register_labels.len()
                ),
            })?;
        let previous_async_bytes = Self::estimate_async_function_bytes(async_function);
        let next_async_bytes = MEMORY_ESTIMATE_GENERATOR_BASE_BYTES
            .saturating_add(MEMORY_ESTIMATE_CONTINUATION_OWNER_BYTES)
            .saturating_add(
                async_function
                    .isolated_execution
                    .as_ref()
                    .map(Self::estimate_generator_execution_bytes)
                    .unwrap_or(0),
            )
            .saturating_add(Self::estimate_value_vec_bytes(
                &self.registers[reg_start..reg_end],
            ))
            .saturating_add(saved_label_bytes);
        self.apply_memory_component_delta(previous_async_bytes, next_async_bytes)?;

        // Register the internal await reactions with the awaited Promise.
        let result_promise = match self.register_promise_then_for_await(promise_handle, await_label)
        {
            Ok(result_promise) => result_promise,
            Err(error) => {
                self.estimated_memory_bytes = self
                    .estimated_memory_bytes
                    .saturating_sub(next_async_bytes)
                    .saturating_add(previous_async_bytes);
                return Err(error);
            }
        };

        let async_function = self
            .async_functions
            .get_mut(async_function_id as usize)
            .expect("async function was validated before await preflight");
        async_function.saved_ip = self.ip + 1;
        async_function.saved_register_base = self.register_base;
        async_function.phase = AsyncFunctionPhase::SuspendedAwait;
        async_function.saved_registers = self.registers[reg_start..reg_end].to_vec();
        async_function.saved_register_labels = self.register_labels[reg_start..reg_end].to_vec();

        // Promise reactions resume through the promise returned by `.then()`.
        self.async_resumption_contexts.insert(
            result_promise.0,
            AsyncResumptionContext {
                async_function_id,
                result_register: result_reg,
            },
        );

        Ok(())
    }

    pub(super) fn suspend_top_level_await(
        &mut self,
        promise_handle: crate::promise_model::PromiseHandle,
        result_reg: u32,
        promise_label: Label,
    ) -> Result<(), InterpreterError> {
        let module_specifier = self.current_module_specifier.clone().ok_or_else(|| {
            InterpreterError::ModuleEvaluationFailed {
                specifier: "<unknown>".to_string(),
                reason: "top-level await has no owning module".to_string(),
            }
        })?;
        self.ensure_module_evaluation_promise(&module_specifier)?;
        let result_promise = self.register_promise_then_for_await(promise_handle, promise_label)?;

        self.top_level_await_resumption_contexts.insert(
            result_promise.0,
            TopLevelAwaitResumptionContext {
                module_specifier,
                continuation: ModuleAwaitContinuation::AwaitValue {
                    result_register: result_reg,
                },
            },
        );
        self.ip += 1;
        self.push_event("top_level_await_suspended", "ok", None);
        Ok(())
    }

    pub(super) fn ensure_module_evaluation_promise(
        &mut self,
        specifier: &str,
    ) -> Result<crate::promise_model::PromiseHandle, InterpreterError> {
        if let Some(promise) = self
            .module_state
            .modules
            .get(specifier)
            .and_then(|record| record.evaluation_promise)
        {
            return Ok(promise);
        }
        let promise = self.create_promise()?;
        let record = self
            .module_state
            .modules
            .get_mut(specifier)
            .ok_or_else(|| InterpreterError::ModuleEvaluationFailed {
                specifier: specifier.to_string(),
                reason: "module record missing while creating evaluation Promise".to_string(),
            })?;
        record.evaluation_promise = Some(promise);
        Ok(promise)
    }

    pub(super) fn suspend_on_async_module_dependency(
        &mut self,
        dependency_promise: crate::promise_model::PromiseHandle,
        dependency: String,
    ) -> Result<(), InterpreterError> {
        let module_specifier = self.current_module_specifier.clone().ok_or_else(|| {
            InterpreterError::ModuleEvaluationFailed {
                specifier: "<unknown>".to_string(),
                reason: "async module dependency has no importing module".to_string(),
            }
        })?;
        self.ensure_module_evaluation_promise(&module_specifier)?;
        let result_promise =
            self.register_promise_then_for_await(dependency_promise, Label::Public)?;
        self.top_level_await_resumption_contexts.insert(
            result_promise.0,
            TopLevelAwaitResumptionContext {
                module_specifier,
                continuation: ModuleAwaitContinuation::Dependency {
                    specifier: dependency,
                },
            },
        );
        self.push_event("module_dependency_suspended", "ok", None);
        Ok(())
    }

    pub(super) fn resume_async_function_after_await(
        &mut self,
        resumption_context: AsyncResumptionContext,
        settled: Result<crate::object_model::JsValue, crate::object_model::JsValue>,
        settlement_label: Label,
    ) -> Result<(), InterpreterError> {
        let async_function_id = resumption_context.async_function_id;
        let result_register = resumption_context.result_register;

        // Only this async function object changes below, so its own bytes are
        // the component delta (bd-9vouw.31: no walk over every async object).
        let previous_async_bytes = self
            .async_functions
            .get(async_function_id as usize)
            .map_or(0, Self::estimate_async_function_bytes);
        // Extract the suspension payload by move. Cloning here retained a
        // duplicate register snapshot after resumption and made every String
        // payload appear live in both stores.
        let (saved_ip, saved_register_base, saved_register_count) = {
            let async_function = self
                .async_functions
                .get(async_function_id as usize)
                .ok_or_else(|| InterpreterError::TypeError {
                    expected: "valid async function".to_string(),
                    got: format!("async#{async_function_id} not found"),
                })?;

            if async_function.phase != AsyncFunctionPhase::SuspendedAwait {
                return Err(InterpreterError::TypeError {
                    expected: "suspended async function".to_string(),
                    got: format!("async function phase: {:?}", async_function.phase),
                });
            }
            if async_function.saved_registers.len() != async_function.saved_register_labels.len() {
                return Err(InterpreterError::TypeError {
                    expected: "equal async register and label snapshot lengths".to_string(),
                    got: format!(
                        "{} values and {} labels",
                        async_function.saved_registers.len(),
                        async_function.saved_register_labels.len()
                    ),
                });
            }

            (
                async_function.saved_ip,
                async_function.saved_register_base,
                async_function.saved_registers.len(),
            )
        };

        let reg_end = saved_register_base.saturating_add(saved_register_count);
        // The saved prefix is the window's live part; the rest of the window
        // goes back to its cleared state (bd-9vouw.167).
        let window_end = saved_register_base
            .saturating_add(self.config.max_registers as usize)
            .min(self.registers.len())
            .min(self.register_labels.len())
            .max(reg_end);
        if reg_end > self.registers.len() {
            return Err(InterpreterError::TypeError {
                expected: "sufficient register capacity".to_string(),
                got: format!("need {} registers, have {}", reg_end, self.registers.len()),
            });
        }
        if reg_end > self.register_labels.len() {
            return Err(InterpreterError::TypeError {
                expected: "sufficient register-label capacity".to_string(),
                got: format!(
                    "need {} register labels, have {}",
                    reg_end,
                    self.register_labels.len()
                ),
            });
        }
        let (saved_registers, saved_register_labels) = {
            let async_function = self
                .async_functions
                .get_mut(async_function_id as usize)
                .expect("async function was validated before suspension move");
            (
                std::mem::take(&mut async_function.saved_registers),
                std::mem::take(&mut async_function.saved_register_labels),
            )
        };

        // Restore execution state. Async activations enter a full-width
        // window, so that is the width they resume with.
        self.ip = saved_ip;
        self.register_base = saved_register_base;
        self.register_width = self.config.max_registers as usize;

        // Restore register file
        let reg_start = self.register_base;

        // Only the restored window changes, so the bytes leaving and entering
        // it are the register component delta, and they move the cached file
        // sums. One pass writes the saved prefix and clears the rest of the
        // window: summing the window before and after and dropping the caches
        // walked it twice and the whole file at the next read (bd-9vouw.500).
        let mut previous_value_bytes = 0u64;
        let mut next_value_bytes = 0u64;
        self.note_registers_written_to(reg_end);
        let cached_value_bytes = self.registers_value_bytes.get();
        self.mutate_registers(|r| {
            let mut saved = saved_registers.into_iter();
            for slot in &mut r[reg_start..window_end] {
                let value = saved.next().unwrap_or(Value::Undefined);
                previous_value_bytes =
                    previous_value_bytes.saturating_add(Self::estimate_value_bytes(slot));
                next_value_bytes =
                    next_value_bytes.saturating_add(Self::estimate_value_bytes(&value));
                *slot = value;
            }
        });
        self.registers_value_bytes
            .set(cached_value_bytes.map(|bytes| {
                bytes
                    .saturating_sub(previous_value_bytes)
                    .saturating_add(next_value_bytes)
            }));
        let mut previous_label_bytes = 0u64;
        let mut next_label_bytes = 0u64;
        let mut saved_labels = saved_register_labels.into_iter();
        for slot in &mut self.register_labels[reg_start..window_end] {
            let label = saved_labels.next().unwrap_or(Label::Public);
            if !matches!(&label, Label::Public) {
                self.all_register_labels_public = false;
            }
            previous_label_bytes =
                previous_label_bytes.saturating_add(Self::estimate_label_bytes(slot));
            next_label_bytes = next_label_bytes.saturating_add(Self::estimate_label_bytes(&label));
            *slot = label;
        }
        self.adjust_register_labels_bytes(previous_label_bytes, next_label_bytes);
        let previous_register_bytes = previous_value_bytes.saturating_add(previous_label_bytes);
        let next_register_bytes = next_value_bytes.saturating_add(next_label_bytes);

        // Resume execution - now we can safely get the mutable reference
        let async_function = self
            .async_functions
            .get_mut(async_function_id as usize)
            .ok_or_else(|| InterpreterError::TypeError {
                expected: "valid async function".to_string(),
                got: format!("async#{async_function_id} not found"),
            })?;
        async_function.phase = AsyncFunctionPhase::Executing;
        let next_async_bytes = Self::estimate_async_function_bytes(async_function);
        self.estimated_memory_bytes = self
            .estimated_memory_bytes
            .saturating_sub(previous_register_bytes)
            .saturating_sub(previous_async_bytes)
            .saturating_add(next_register_bytes)
            .saturating_add(next_async_bytes);

        match settled {
            Ok(argument) => {
                self.write_reg_with_label(
                    result_register,
                    self.js_value_to_value(&argument),
                    settlement_label,
                )?;
            }
            Err(reason) => {
                let error_value = self.js_value_to_value(&reason);
                let _ = self.raise_await_rejection_with_label(error_value, settlement_label)?;
            }
        }

        Ok(())
    }

    pub(super) fn continue_resumed_async_function(
        &mut self,
        module: Option<&Ir3Module>,
    ) -> Result<(), InterpreterError> {
        let module = module.ok_or_else(|| InterpreterError::TypeError {
            expected: "module context for async function resumption".to_string(),
            got: "missing module context".to_string(),
        })?;
        match self.run_loop(module) {
            Ok(_) | Err(InterpreterError::Halted) => Ok(()),
            Err(err) => Err(err),
        }
    }

    pub(super) fn resume_async_function_task(
        &mut self,
        resumption_context: AsyncResumptionContext,
        settled: Result<crate::object_model::JsValue, crate::object_model::JsValue>,
        settlement_label: Label,
        fallback_module: Option<&Ir3Module>,
    ) -> Result<(), InterpreterError> {
        // Set by the event loop when collection may run in the resumed body
        // (bd-9vouw.77): the values its frame holds.
        let gc_request = self.gc_nested_request.take();
        let async_function_id = resumption_context.async_function_id;
        let (owner_module, has_isolated_execution) = {
            let function = self
                .async_functions
                .get(async_function_id as usize)
                .ok_or_else(|| InterpreterError::TypeError {
                    expected: "valid async function".to_string(),
                    got: format!("async#{async_function_id} not found"),
                })?;
            (
                Arc::clone(&function.owner_module),
                function.isolated_execution.is_some(),
            )
        };

        if !has_isolated_execution {
            let async_function_count_before_run = self.async_functions.len();
            let mut abandoned_async_ids =
                Self::async_function_ids_in_call_stack(&self.call_stack, 0);
            Self::extend_unique_async_function_ids(
                &mut abandoned_async_ids,
                std::iter::once(async_function_id),
            );
            let failure_label = Self::terminal_async_failure_label(&settlement_label);
            let result = self
                .resume_async_function_after_await(resumption_context, settled, settlement_label)
                .and_then(|()| {
                    // The resumed frame runs on the live stack. Records it
                    // creates are read back if it fails.
                    let gc_arm = gc_request.as_ref().and_then(|held| {
                        let pins = held
                            .iter()
                            .map(GcPin::Value)
                            .chain(std::iter::once(GcPin::AsyncFunctionsFrom(
                                async_function_count_before_run,
                            )))
                            .collect::<Vec<_>>();
                        self.gc_arm_nested(&pins)
                    });
                    let result = self.continue_resumed_async_function(Some(owner_module.as_ref()));
                    self.gc_disarm_nested(gc_arm);
                    result
                });
            if let Err(error) = result {
                Self::extend_unique_async_function_ids(
                    &mut abandoned_async_ids,
                    Self::async_function_ids_in_call_stack(&self.call_stack, 0),
                );
                Self::extend_unique_async_function_ids(
                    &mut abandoned_async_ids,
                    self.async_function_ids_created_since(async_function_count_before_run),
                );
                self.discard_abandoned_async_call_stack(&abandoned_async_ids);
                self.terminally_reject_abandoned_async_functions(
                    &abandoned_async_ids,
                    failure_label,
                );
                return Err(error);
            }
            return Ok(());
        }

        let failure_label = Self::terminal_async_failure_label(&settlement_label);
        let async_function_count_before_run = self.async_functions.len();
        // bd-j9r60: the setup transfer below is accounted as one delta.
        let setup_transfer_bytes = self
            .activation_transfer_memory_bytes()
            .saturating_add(self.async_function_memory_bytes_at(async_function_id));
        #[cfg(test)]
        let setup_drift = self.memory_walk_drift();
        let activation = self
            .closures
            .replace_activation(
                &mut self.async_functions[async_function_id as usize].isolated_execution,
                None,
            )
            .expect("isolated async execution was checked");
        let contained_codegen_grant = activation.contained_codegen_grant;
        let owner_is_foreign = fallback_module
            .is_some_and(|module| module.header.source_label != owner_module.header.source_label);

        let caller_generator_yielded = std::mem::replace(&mut self.generator_yielded, false);
        let caller_generator_resume_dst = self.generator_resume_dst.take();
        let caller_generator_result_label =
            std::mem::replace(&mut self.generator_result_label, Label::Public);
        let caller_execution = self.take_generator_execution();
        let previous_granted_capabilities =
            self.replace_with_contained_codegen_grant(contained_codegen_grant);
        let caller_execution_bytes = Self::estimate_generator_execution_bytes(&caller_execution);
        let previous_suspended_bytes = self.temporarily_suspended_execution_bytes;
        let previous_reentrant_depth = self.module_reentrant_call_depth;
        let previous_foreign_call_depth = self.active_foreign_module_call_depth;
        self.temporarily_suspended_execution_bytes =
            previous_suspended_bytes.saturating_add(caller_execution_bytes);
        self.module_reentrant_call_depth =
            previous_reentrant_depth.saturating_add(caller_execution.call_stack.len());
        if owner_is_foreign {
            self.active_foreign_module_call_depth = previous_foreign_call_depth.saturating_add(1);
        }
        self.install_generator_execution(activation);
        let initial_async_ids = Self::async_function_ids_in_call_stack(&self.call_stack, 0);

        let result = self
            .apply_memory_component_delta(
                setup_transfer_bytes,
                self.activation_transfer_memory_bytes()
                    .saturating_add(self.async_function_memory_bytes_at(async_function_id)),
            )
            .and_then(|_| {
                #[cfg(test)]
                debug_assert_eq!(
                    self.memory_walk_drift(),
                    setup_drift,
                    "async resume setup transfer drifted from the full walk (bd-j9r60)"
                );
                self.resume_async_function_after_await(
                    resumption_context,
                    settled,
                    settlement_label,
                )
                .and_then(|()| {
                    // The caller's execution waits in `caller_execution`.
                    let gc_arm = gc_request.as_ref().and_then(|held| {
                        let pins = held
                            .iter()
                            .map(GcPin::Value)
                            .chain(std::iter::once(GcPin::GeneratorExecution(
                                &caller_execution,
                            )))
                            .chain(std::iter::once(GcPin::AsyncFunctionsFrom(
                                async_function_count_before_run,
                            )))
                            .collect::<Vec<_>>();
                        self.gc_arm_nested(&pins)
                    });
                    let result = self.continue_resumed_async_function(Some(owner_module.as_ref()));
                    self.gc_disarm_nested(gc_arm);
                    result
                })
            });
        // bd-j9r60: the completion transfer below (caller reinstalled, the
        // continuation parked or dropped) is accounted as one delta.
        let completion_live_bytes = self.activation_transfer_memory_bytes();
        #[cfg(test)]
        let completion_drift = self.memory_walk_drift();
        let mut continuation_execution = self.take_generator_execution();
        continuation_execution.contained_codegen_grant = contained_codegen_grant;
        let mut continuation = Some(continuation_execution);
        let mut active_async_ids = initial_async_ids;
        Self::extend_unique_async_function_ids(
            &mut active_async_ids,
            Self::async_function_ids_in_call_stack(
                &continuation
                    .as_ref()
                    .expect("isolated continuation is present")
                    .call_stack,
                0,
            ),
        );
        Self::extend_unique_async_function_ids(
            &mut active_async_ids,
            self.async_function_ids_created_since(async_function_count_before_run),
        );
        let post_run_stack_async_ids = Self::async_function_ids_in_call_stack(
            &continuation
                .as_ref()
                .expect("isolated continuation is present")
                .call_stack,
            0,
        );
        let suspended_async_id = self.suspended_async_function_id_in_call_stack(
            &continuation
                .as_ref()
                .expect("isolated continuation is present")
                .call_stack,
            0,
        );
        let result = if result.is_ok()
            && suspended_async_id.is_none()
            && !post_run_stack_async_ids.is_empty()
        {
            Err(InterpreterError::InternalError {
                details: "isolated async execution exited without completing or suspending its active async frames"
                    .to_string(),
            })
        } else {
            result
        };

        self.temporarily_suspended_execution_bytes = previous_suspended_bytes;
        self.module_reentrant_call_depth = previous_reentrant_depth;
        self.active_foreign_module_call_depth = previous_foreign_call_depth;
        self.restore_replaced_codegen_grants(previous_granted_capabilities);
        self.install_generator_execution(caller_execution);
        self.generator_yielded = caller_generator_yielded;
        self.generator_resume_dst = caller_generator_resume_dst;
        self.generator_result_label = caller_generator_result_label;

        let parked_async_id = suspended_async_id.filter(|_| result.is_ok());
        let parked_previous_bytes =
            parked_async_id.map_or(0, |id| self.async_function_memory_bytes_at(id));
        if let Some(suspended_id) = parked_async_id {
            self.closures.replace_activation(
                &mut self.async_functions[suspended_id as usize].isolated_execution,
                continuation.take(),
            );
        }
        drop(continuation);
        let completion_previous_bytes = completion_live_bytes.saturating_add(parked_previous_bytes);
        let completion_next_bytes = self.activation_transfer_memory_bytes().saturating_add(
            parked_async_id.map_or(0, |id| self.async_function_memory_bytes_at(id)),
        );

        match result {
            Ok(()) => {
                if let Err(error) = self
                    .apply_memory_component_delta(completion_previous_bytes, completion_next_bytes)
                {
                    let mut abandoned_async_ids = active_async_ids.clone();
                    let retained_async_ids = suspended_async_id
                        .and_then(|suspended_id| {
                            self.closures.replace_activation(
                                &mut self.async_functions[suspended_id as usize].isolated_execution,
                                None,
                            )
                        })
                        .map(|execution| {
                            Self::async_function_ids_in_call_stack(&execution.call_stack, 0)
                        })
                        .unwrap_or_default();
                    Self::extend_unique_async_function_ids(
                        &mut abandoned_async_ids,
                        retained_async_ids,
                    );
                    self.terminally_reject_abandoned_async_functions(
                        &abandoned_async_ids,
                        failure_label,
                    );
                    return Err(error);
                }
                #[cfg(test)]
                debug_assert_eq!(
                    self.memory_walk_drift(),
                    completion_drift,
                    "async resume completion transfer drifted from the full walk (bd-j9r60)"
                );
                Ok(())
            }
            Err(error) => {
                // The run already failed and its continuation was dropped;
                // account the transfer without raising a second refusal.
                self.estimated_memory_bytes = self
                    .estimated_memory_bytes
                    .saturating_sub(completion_previous_bytes)
                    .saturating_add(completion_next_bytes);
                #[cfg(test)]
                debug_assert_eq!(
                    self.memory_walk_drift(),
                    completion_drift,
                    "async resume failure transfer drifted from the full walk (bd-j9r60)"
                );
                self.terminally_reject_abandoned_async_functions(&active_async_ids, failure_label);
                Err(error)
            }
        }
    }

    pub(super) fn resume_module_evaluation_task(
        &mut self,
        resumption_context: TopLevelAwaitResumptionContext,
        settled: Result<crate::object_model::JsValue, crate::object_model::JsValue>,
        label: Label,
        fallback_module: Option<&Ir3Module>,
    ) -> Result<(), InterpreterError> {
        let specifier = resumption_context.module_specifier.clone();
        if self.current_module_specifier.as_deref() == Some(specifier.as_str()) {
            let owned_module = if fallback_module
                .is_some_and(|module| module.header.source_label == specifier)
            {
                None
            } else {
                Some(
                    self.module_state
                        .modules
                        .get(&specifier)
                        .and_then(|record| record.compiled_module.as_ref())
                        .cloned()
                        .ok_or_else(|| InterpreterError::ModuleEvaluationFailed {
                            specifier: specifier.clone(),
                            reason: "async module continuation has no retained program".to_string(),
                        })?,
                )
            };
            let module = owned_module.as_deref().or(fallback_module);
            if let Err(error) =
                self.resume_top_level_after_await(resumption_context, settled, label.clone())
            {
                if self.entry_module_specifier.as_deref() == Some(specifier.as_str()) {
                    self.replace_top_level_await_outcome(Err(error));
                } else {
                    self.settle_imported_module_evaluation(&specifier, Err(error), label)?;
                }
            } else {
                self.continue_resumed_top_level(module, &specifier, label);
            }
            return Ok(());
        }

        let (owner_module, suspended_execution) = {
            let record = self
                .module_state
                .modules
                .get_mut(&specifier)
                .ok_or_else(|| InterpreterError::ModuleEvaluationFailed {
                    specifier: specifier.clone(),
                    reason: "async continuation owner module is not retained".to_string(),
                })?;
            let owner_module = record.compiled_module.as_ref().cloned().ok_or_else(|| {
                InterpreterError::ModuleEvaluationFailed {
                    specifier: specifier.clone(),
                    reason: "async continuation owner has no retained program".to_string(),
                }
            })?;
            let suspended_execution = record.async_execution.take().ok_or_else(|| {
                InterpreterError::ModuleEvaluationFailed {
                    specifier: specifier.clone(),
                    reason: "async continuation owner has no parked activation".to_string(),
                }
            })?;
            (owner_module, suspended_execution)
        };

        let caller_execution = self.snapshot_module_execution()?;
        self.restore_module_execution(suspended_execution, true);
        let resume_result =
            self.resume_top_level_after_await(resumption_context, settled, label.clone());
        if let Err(error) = resume_result {
            self.settle_imported_module_evaluation(&specifier, Err(error), label.clone())?;
        } else {
            self.continue_resumed_top_level(Some(owner_module.as_ref()), &specifier, label.clone());
        }

        let still_suspended = self
            .top_level_await_resumption_contexts
            .values()
            .any(|context| context.module_specifier == specifier);
        let parked_execution = if still_suspended {
            Some(self.snapshot_module_execution()?)
        } else {
            None
        };
        self.restore_module_execution(caller_execution, true);
        if let Some(execution) = parked_execution {
            let record = self
                .module_state
                .modules
                .get_mut(&specifier)
                .ok_or_else(|| InterpreterError::ModuleEvaluationFailed {
                    specifier: specifier.clone(),
                    reason: "async module record disappeared while re-parking continuation"
                        .to_string(),
                })?;
            record.status = ModuleRuntimeStatus::AsyncEvaluating;
            record.async_execution = Some(execution);
        }
        Ok(())
    }

    pub(super) fn resume_top_level_after_await(
        &mut self,
        resumption_context: TopLevelAwaitResumptionContext,
        settled: Result<crate::object_model::JsValue, crate::object_model::JsValue>,
        label: Label,
    ) -> Result<(), InterpreterError> {
        self.push_event("top_level_await_resumed", "ok", None);
        match (resumption_context.continuation, settled) {
            (ModuleAwaitContinuation::AwaitValue { result_register }, Ok(argument)) => {
                self.write_reg_with_label(
                    result_register,
                    self.js_value_to_value(&argument),
                    label,
                )?;
            }
            (ModuleAwaitContinuation::AwaitValue { .. }, Err(reason)) => {
                let error_value = self.js_value_to_value(&reason);
                let _ = self.raise_await_rejection_with_label(error_value, label)?;
            }
            (ModuleAwaitContinuation::Dependency { .. }, Ok(_)) => {}
            (ModuleAwaitContinuation::Dependency { specifier }, Err(reason)) => {
                return Err(InterpreterError::ModuleEvaluationFailed {
                    specifier,
                    reason: format!("async dependency rejected: {reason:?}"),
                });
            }
        }
        Ok(())
    }

    pub(super) fn continue_resumed_top_level(
        &mut self,
        module: Option<&Ir3Module>,
        module_specifier: &str,
        settlement_label: Label,
    ) {
        let outcome = match module {
            Some(module) => self.run_loop_labeled(module),
            None => Err(InterpreterError::TypeError {
                expected: "module context for top-level await resumption".to_string(),
                got: "missing module context".to_string(),
            }),
        };

        let module_still_suspended = self
            .top_level_await_resumption_contexts
            .values()
            .any(|context| context.module_specifier == module_specifier);
        if !module_still_suspended {
            let outcome = match outcome {
                Err(InterpreterError::Halted) => self.read_reg(0).map(|value| {
                    let label = self.get_register_label(0).cloned().unwrap_or(Label::Public);
                    LabeledReturn { value, label }
                }),
                other => other,
            };
            if self.entry_module_specifier.as_deref() == Some(module_specifier) {
                self.replace_top_level_await_outcome(outcome);
            } else if let Err(error) =
                self.settle_imported_module_evaluation(module_specifier, outcome, settlement_label)
            {
                self.replace_top_level_await_outcome(Err(error));
            }
        } else if let Err(error) = outcome {
            if self.entry_module_specifier.as_deref() == Some(module_specifier) {
                self.replace_top_level_await_outcome(Err(error));
            } else if let Err(settlement_error) = self.settle_imported_module_evaluation(
                module_specifier,
                Err(error),
                settlement_label,
            ) {
                self.replace_top_level_await_outcome(Err(settlement_error));
            }
        }
    }

    pub(super) fn settle_imported_module_evaluation(
        &mut self,
        specifier: &str,
        outcome: Result<LabeledReturn, InterpreterError>,
        label: Label,
    ) -> Result<(), InterpreterError> {
        let evaluation_promise = self
            .module_state
            .modules
            .get(specifier)
            .and_then(|record| record.evaluation_promise)
            .ok_or_else(|| InterpreterError::ModuleEvaluationFailed {
                specifier: specifier.to_string(),
                reason: "async module completion has no evaluation Promise".to_string(),
            })?;
        match outcome {
            Ok(_) => {
                // Static importers ignore the fulfillment value; an `import()`
                // of the module follows this promise to its namespace.
                self.sort_module_namespace_keys(specifier)?;
                let mut namespace = crate::object_model::JsValue::Undefined;
                if let Some(record) = self.module_state.modules.get_mut(specifier) {
                    record.status = ModuleRuntimeStatus::Evaluated;
                    record.async_execution = None;
                    namespace = Self::value_to_js_value(&Value::Object(record.namespace_object));
                }
                self.fulfill_promise(evaluation_promise, namespace, label)
            }
            Err(error) => {
                let reason = Self::promise_rejection_from_error(&error);
                if let Some(record) = self.module_state.modules.get_mut(specifier) {
                    record.status = ModuleRuntimeStatus::Failed(error.to_string());
                    record.async_execution = None;
                }
                self.reject_promise(evaluation_promise, reason, label)
            }
        }
    }

    pub(super) fn raise_await_rejection_with_label(
        &mut self,
        error_value: Value,
        label: Label,
    ) -> Result<bool, InterpreterError> {
        self.pending_finally_entry = None;
        self.suspend_current_abrupt_completion()?;
        self.replace_pending_abrupt_slots(Some((error_value.clone(), label.clone())), None)?;
        if let Some(frame) = self.pop_exception_target_frame()? {
            self.select_exception_target(None, frame);
            Ok(false)
        } else if self.reject_nearest_async_boundary(error_value.clone(), label)? {
            Ok(true)
        } else {
            self.clear_finally_frames();
            self.pending_finally_entry = None;
            Err(InterpreterError::UncaughtException {
                value: self.uncaught_exception_description(&error_value),
            })
        }
    }

    pub(super) fn uncaught_exception_description(&self, value: &Value) -> String {
        match value {
            Value::Str(s) => s.to_string(),
            Value::Int(n) => n.to_string(),
            Value::BigInt(n) => n.to_string(),
            Value::Bool(b) => b.to_string(),
            Value::Undefined => "undefined".to_string(),
            Value::Null => "null".to_string(),
            Value::Object(id) => self.error_object_to_string(*id).unwrap_or_else(|| {
                // Non-Error throwables (Test262's `Test262Error`, plain
                // `{ message }` objects) still carry a message; surface it so
                // the failure is diagnosable.
                match self.chain_data_property(*id, "message") {
                    Some(Value::Str(message)) if !message.is_empty() => {
                        format!("[object]: {message}")
                    }
                    _ => "[object]".to_string(),
                }
            }),
            _ => "[object]".to_string(),
        }
    }

    /// First own-or-inherited plain data property `key` of `object_id`
    /// (no accessor or proxy invocation).
    pub(super) fn chain_data_property(&self, object_id: ObjectId, key: &str) -> Option<&Value> {
        let mut current = Some(object_id);
        let mut depth = 0u32;
        while let Some(id) = current {
            if depth >= MAX_PROTOTYPE_CHAIN_DEPTH {
                return None;
            }
            let object = self.heap.get(id.0 as usize)?;
            if let Some(value) = object.properties.get(key) {
                return Some(value);
            }
            current = self.observable_prototype_link(object, id);
            depth += 1;
        }
        None
    }

    pub(super) fn restore_scope_chain_for_frame(&mut self, frame: &CallFrame) {
        if frame.scope_inert_virtual_scope_bytes > 0 {
            // The optimized activation never replaced the caller's active
            // chain. Its saved chain is the retained captured environment,
            // not a caller snapshot, and is released with the frame.
            return;
        }
        // Closure and caller scope snapshots share lexical binding cells, so
        // assignments are already visible in the saved chain. Restoring the
        // caller is therefore a structural frame swap, not a value merge.
        if let Some(saved) = &frame.saved_scope_chain {
            self.scope_chain.frames = saved.clone();
        } else {
            while self.scope_chain.depth() > frame.saved_scope_depth {
                self.scope_chain.pop();
            }
        }
    }

    pub(super) fn materialize_scope_inert_terminal_frame(
        &mut self,
    ) -> Result<(), InterpreterError> {
        let Some(frame) = self.call_stack.last() else {
            return Ok(());
        };
        if frame.scope_inert_virtual_scope_bytes == 0 {
            return Ok(());
        }

        let materialized_depth = self
            .call_stack
            .last()
            .expect("scope-inert frame was checked")
            .saved_scope_chain
            .as_ref()
            .map_or(self.scope_chain.depth(), |environment| environment.len());
        ScopeChain::preflight_push_depth(materialized_depth, self.config.max_scope_depth)?;
        let captured_env = self
            .call_stack
            .last_mut()
            .expect("scope-inert frame was checked")
            .saved_scope_chain
            .take();

        if let Some(captured_env) = captured_env {
            // Move the already-owned caller structure into the frame. A
            // terminal failure may occur after the leaf consumed all remaining
            // guest memory; cloning here would add an unaccounted transient
            // allocation at a boundary where Tier-R performs none.
            let caller_scope = std::mem::replace(&mut self.scope_chain.frames, captured_env);
            self.call_stack
                .last_mut()
                .expect("scope-inert frame was checked")
                .saved_scope_chain = Some(caller_scope);
        }
        self.scope_chain
            .push(self.config.max_scope_depth)
            .expect("scope-inert entry preflight already admitted this exact depth");
        self.call_stack
            .last_mut()
            .expect("scope-inert frame was checked")
            .scope_inert_virtual_scope_bytes = 0;
        debug_assert_eq!(
            self.estimated_memory_bytes(),
            self.recompute_estimated_memory_bytes(),
            "materializing a virtual leaf frame must preserve logical ownership"
        );
        Ok(())
    }

    pub(super) fn unwind_call_stack_to(
        &mut self,
        target_depth: usize,
    ) -> Result<RestoredAbruptCompletionState, InterpreterError> {
        let previous_scope_bytes = self.scope_chain_memory_bytes();
        let previous_closure_bytes = self.closures_memory_bytes();
        let previous_call_stack_bytes = self.call_stack_memory_bytes();
        let mut restored_pending_exception = None;
        let mut restored_pending_return = None;
        let mut restored_suspended_abrupt_depth = None;
        while self.call_stack.len() > target_depth {
            if let Some(frame) = self.call_stack.pop(&mut self.closures.cold_cells) {
                self.register_base = frame.register_base;
                self.register_width = frame.register_width;
                self.finally_frames.truncate(frame.saved_finally_mode_depth);
                self.restore_scope_chain_for_frame(&frame);
                let label = frame.saved_pending_exception_label;
                restored_pending_exception = frame.saved_pending_exception.map(|v| (v, label));
                restored_pending_return = frame.saved_pending_return;
                restored_suspended_abrupt_depth = Some(frame.saved_suspended_abrupt_depth);
            }
        }
        if let Some(depth) = restored_suspended_abrupt_depth {
            self.suspended_abrupt_completions.truncate(depth);
        }
        self.pc_label_stack
            .retain(|frame| frame.call_depth <= target_depth);
        self.apply_scope_closure_call_stack_memory_delta(
            previous_scope_bytes,
            previous_closure_bytes,
            previous_call_stack_bytes,
        )?;
        Ok((restored_pending_exception, restored_pending_return))
    }

    pub(super) fn pop_current_try_frame(&mut self) -> Option<CatchFrame> {
        let current_depth = self.call_stack.len();
        let idx = self
            .catch_frames
            .iter()
            .rposition(|f| f.call_depth == current_depth)?;
        let frame = self.catch_frames[idx].clone();
        self.catch_frames.truncate(idx);
        Some(frame)
    }

    pub(super) fn nearest_async_call_depth(&self) -> Option<usize> {
        self.innermost_async_frame_index().map(|index| index + 1)
    }

    /// The innermost native call boundary frame, if a builtin is running a
    /// nested guest callback.
    pub(super) fn native_boundary_frame(&self) -> Option<&CallFrame> {
        self.call_stack
            .iter()
            .rev()
            .find(|frame| frame.native_boundary)
    }

    /// Call-stack depth at and below which frames belong to the native
    /// caller of a nested callback (0 when none is active).
    pub(super) fn native_boundary_depth(&self) -> usize {
        self.call_stack
            .iter()
            .rposition(|frame| frame.native_boundary)
            .map_or(0, |index| index + 1)
    }

    /// Index of the innermost async activation frame above the native
    /// boundary: an async function below a nested callback's builtin caller
    /// is not the callback's to reject or suspend.
    pub(super) fn innermost_async_frame_index(&self) -> Option<usize> {
        let floor = self.native_boundary_depth();
        self.call_stack[floor..]
            .iter()
            .rposition(|frame| frame.async_function_id.is_some())
            .map(|index| index + floor)
    }

    pub(super) fn pop_exception_target_frame(
        &mut self,
    ) -> Result<Option<CatchFrame>, InterpreterError> {
        // An async function converts every uncaught body exception into a
        // rejected Promise. A caller's catch frame sits below that async call
        // frame and therefore cannot be selected during synchronous unwinding.
        let minimum_call_depth = self.nearest_async_call_depth().unwrap_or(0);
        self.pop_exception_target_frame_at_or_above(minimum_call_depth)
    }

    pub(super) fn pop_exception_target_frame_at_or_above(
        &mut self,
        minimum_call_depth: usize,
    ) -> Result<Option<CatchFrame>, InterpreterError> {
        let minimum_call_depth = minimum_call_depth.max(self.native_boundary_depth());
        let current_depth = self.call_stack.len();
        let Some(idx) = self
            .catch_frames
            .iter()
            .rposition(|f| f.call_depth >= minimum_call_depth && f.call_depth <= current_depth)
        else {
            return Ok(None);
        };
        let frame = self.catch_frames[idx].clone();
        self.catch_frames.truncate(idx);
        self.truncate_finally_frames(frame.finally_frame_depth);
        let (restored_pending_exception, restored_pending_return) =
            self.unwind_call_stack_to(frame.call_depth)?;
        self.suspend_abrupt_completion(restored_pending_exception, restored_pending_return)?;
        Ok(Some(frame))
    }

    pub(super) fn select_exception_target(
        &mut self,
        module: Option<&Ir3Module>,
        frame: CatchFrame,
    ) {
        let target = frame.catch_target;
        let target_is_finally = frame.finally_target == Some(target)
            || module.is_some_and(|module| {
                matches!(
                    module.instructions.get(target),
                    Some(Ir3Instruction::EnterFinally)
                )
            });
        self.pending_finally_entry = target_is_finally.then_some(PendingFinallyEntry {
            target,
            mode: FinallyMode::Exception,
        });
        self.ip = target;
    }

    pub(super) fn enter_finally_frame(&mut self) -> Result<(), InterpreterError> {
        let owns_pending_completion = self
            .pending_finally_entry
            .as_ref()
            .is_some_and(|entry| entry.target == self.ip);
        let mode = if owns_pending_completion {
            self.pending_finally_entry
                .as_ref()
                .map_or(FinallyMode::Normal, |entry| entry.mode.clone())
        } else {
            FinallyMode::Normal
        };
        let entry_is_consistent = match &mode {
            FinallyMode::Exception => {
                self.pending_exception.is_some() && self.pending_return.is_none()
            }
            FinallyMode::Return => {
                self.pending_return.is_some() && self.pending_exception.is_none()
            }
            FinallyMode::Normal => true,
        };
        if !entry_is_consistent {
            return Err(InterpreterError::InternalError {
                details: "finally entry lost or mixed its owned abrupt completion".to_string(),
            });
        }
        let frame_bytes = std::mem::size_of::<FinallyFrame>() as u64;
        self.apply_memory_component_delta(0, frame_bytes)?;
        if self.finally_frames.try_reserve(1).is_err() {
            self.estimated_memory_bytes = self.estimated_memory_bytes.saturating_sub(frame_bytes);
            return Err(self.memory_budget_error(u64::MAX, self.heap_object_count_u32()));
        }

        let completion = match mode {
            FinallyMode::Exception => {
                let exception = self
                    .pending_exception
                    .take()
                    .expect("exception-mode finally entry was validated above");
                let label = std::mem::replace(&mut self.pending_exception_label, Label::Public);
                Some(AbruptCompletion::Exception(exception, label))
            }
            FinallyMode::Return => self.pending_return.take().map(AbruptCompletion::Return),
            FinallyMode::Normal => None,
        };
        if owns_pending_completion {
            self.pending_finally_entry = None;
        }
        self.finally_frames.push(FinallyFrame { completion });
        Ok(())
    }

    /// Pop a finalizer frame while retaining its completion's dynamic charge.
    /// The caller either moves that completion back into a pending slot or
    /// explicitly releases its dynamic bytes before completing/discarding it.
    pub(super) fn take_finally_completion(&mut self) -> Option<AbruptCompletion> {
        let frame = self.finally_frames.pop()?;
        self.estimated_memory_bytes = self
            .estimated_memory_bytes
            .saturating_sub(std::mem::size_of::<FinallyFrame>() as u64);
        frame.completion
    }

    pub(super) fn finally_frame_memory_bytes(frame: &FinallyFrame) -> u64 {
        (std::mem::size_of::<FinallyFrame>() as u64).saturating_add(
            frame
                .completion
                .as_ref()
                .map(Self::estimate_abrupt_completion_bytes)
                .unwrap_or(0),
        )
    }

    pub(super) fn finally_frames_memory_bytes(&self) -> u64 {
        Self::saturating_sum(
            self.finally_frames
                .iter()
                .map(Self::finally_frame_memory_bytes),
        )
    }

    pub(super) fn truncate_finally_frames(&mut self, target_depth: usize) {
        let released_bytes = self
            .finally_frames
            .get(target_depth..)
            .map(|frames| Self::saturating_sum(frames.iter().map(Self::finally_frame_memory_bytes)))
            .unwrap_or(0);
        self.finally_frames.truncate(target_depth);
        self.estimated_memory_bytes = self.estimated_memory_bytes.saturating_sub(released_bytes);
    }

    pub(super) fn clear_finally_frames(&mut self) {
        let floor = self
            .native_boundary_frame()
            .map_or(0, |frame| frame.saved_finally_mode_depth);
        self.truncate_finally_frames(floor);
    }

    pub(super) fn discard_current_finally_frame(&mut self) {
        if let Some(frame) = self.finally_frames.pop() {
            self.estimated_memory_bytes = self
                .estimated_memory_bytes
                .saturating_sub(Self::finally_frame_memory_bytes(&frame));
        }
    }

    pub(super) fn take_current_abrupt_completion(&mut self) -> Option<AbruptCompletion> {
        if let Some(exception) = self.pending_exception.take() {
            debug_assert!(
                self.pending_return.is_none(),
                "only one abrupt completion should be active at a time"
            );
            let label = std::mem::replace(&mut self.pending_exception_label, Label::Public);
            Some(AbruptCompletion::Exception(exception, label))
        } else {
            self.pending_return.take().map(AbruptCompletion::Return)
        }
    }

    pub(super) fn suspend_abrupt_completion(
        &mut self,
        pending_exception: Option<(Value, Label)>,
        pending_return: Option<LabeledReturn>,
    ) -> Result<(), InterpreterError> {
        debug_assert!(
            pending_exception.is_none() || pending_return.is_none(),
            "only one abrupt completion should be active at a time"
        );

        let completions = match (pending_exception, pending_return) {
            (Some((exception, label)), None) => {
                [Some(AbruptCompletion::Exception(exception, label)), None]
            }
            (None, Some(return_val)) => [Some(AbruptCompletion::Return(return_val)), None],
            (None, None) => [None, None],
            (Some((exception, label)), Some(return_val)) => [
                Some(AbruptCompletion::Exception(exception, label)),
                Some(AbruptCompletion::Return(return_val)),
            ],
        };
        let completion_count = completions.iter().flatten().count();
        let added_bytes = u64::try_from(completion_count)
            .unwrap_or(u64::MAX)
            .saturating_mul(std::mem::size_of::<AbruptCompletion>() as u64)
            .saturating_add(Self::saturating_sum(
                completions
                    .iter()
                    .flatten()
                    .map(Self::estimate_abrupt_completion_bytes),
            ));
        self.apply_memory_component_delta(0, added_bytes)?;
        if self
            .suspended_abrupt_completions
            .try_reserve(completion_count)
            .is_err()
        {
            self.estimated_memory_bytes = self.estimated_memory_bytes.saturating_sub(added_bytes);
            return Err(self.memory_budget_error(u64::MAX, self.heap_object_count_u32()));
        }
        self.suspended_abrupt_completions
            .extend(completions.into_iter().flatten());
        Ok(())
    }

    pub(super) fn suspend_current_abrupt_completion(&mut self) -> Result<(), InterpreterError> {
        if self.pending_exception.is_none() && self.pending_return.is_none() {
            return Ok(());
        }
        self.apply_memory_component_delta(0, std::mem::size_of::<AbruptCompletion>() as u64)?;
        if self.suspended_abrupt_completions.try_reserve(1).is_err() {
            self.estimated_memory_bytes = self
                .estimated_memory_bytes
                .saturating_sub(std::mem::size_of::<AbruptCompletion>() as u64);
            return Err(self.memory_budget_error(u64::MAX, self.heap_object_count_u32()));
        }
        if let Some(completion) = self.take_current_abrupt_completion() {
            self.suspended_abrupt_completions.push(completion);
        }
        Ok(())
    }

    pub(super) fn restore_suspended_abrupt_completion(&mut self) {
        if self.pending_exception.is_some() || self.pending_return.is_some() {
            return;
        }

        let previous_bytes = self.call_stack_memory_bytes();
        if let Some(completion) = self.suspended_abrupt_completions.pop() {
            match completion {
                AbruptCompletion::Exception(exception, label) => {
                    self.pending_exception = Some(exception);
                    self.pending_exception_label = label;
                }
                AbruptCompletion::Return(return_val) => {
                    self.pending_return = Some(return_val);
                }
            }
            self.estimated_memory_bytes = self
                .estimated_memory_bytes
                .saturating_sub(previous_bytes.saturating_sub(self.call_stack_memory_bytes()));
        }
    }

    pub(super) fn pop_current_finally_target(&mut self) -> Option<usize> {
        let current_depth = self.call_stack.len();
        let idx = self
            .catch_frames
            .iter()
            .rposition(|f| f.call_depth == current_depth && f.finally_target.is_some())?;
        let frame = self.catch_frames[idx].clone();
        self.catch_frames.truncate(idx);
        self.truncate_finally_frames(frame.finally_frame_depth);
        frame.finally_target
    }

    pub(super) fn hook_context(&self, module: &Ir3Module) -> HookContext {
        // IR3 modules do not yet expose a dedicated extension id at interpreter
        // runtime, so source_label is the deterministic provenance token
        // available at the hook boundary today.
        HookContext {
            extension_id: module.header.source_label.clone(),
            instruction_count: self.instructions_executed,
            current_ip: self.ip,
        }
    }

    pub(super) fn callable_closure_id(callee: &Value) -> Option<u32> {
        match callee {
            Value::Closure(id)
            | Value::GeneratorFunction(id)
            | Value::AsyncFunction(id)
            | Value::AsyncGeneratorFunction(id) => Some(*id),
            _ => None,
        }
    }

    pub(super) fn record_closure_program_provenance(
        &mut self,
        closure_id: u32,
        module: &Ir3Module,
    ) {
        self.closure_module_origins.insert(
            closure_id,
            self.current_module_specifier
                .clone()
                .unwrap_or_else(|| module.header.source_label.clone()),
        );
        if let Some(handle) = self.active_generated_function_artifact {
            self.closure_generated_function_artifacts
                .insert(closure_id, handle);
        }
    }

    pub(super) fn remove_closure_program_provenance(&mut self, closure_id: u32) {
        self.closure_module_origins.remove(&closure_id);
        self.closure_generated_function_artifacts
            .remove(&closure_id);
    }

    /// Return the ordinary module-resolution specifier and generated program
    /// occurrence, if any, that must be installed by an isolated wrapper.
    pub(super) fn closure_execution_provenance(
        &self,
        callee: &Value,
        current_module: &Ir3Module,
    ) -> Result<(String, Option<GeneratedFunctionArtifactHandle>), InterpreterError> {
        let Some(closure_id) = Self::callable_closure_id(callee) else {
            return Ok((
                self.current_module_specifier
                    .clone()
                    .unwrap_or_else(|| current_module.header.source_label.clone()),
                self.active_generated_function_artifact,
            ));
        };
        let generated_artifact = self
            .closure_generated_function_artifacts
            .get(&closure_id)
            .copied();
        let module_specifier = match self.closure_module_origins.get(&closure_id) {
            Some(origin) => origin.clone(),
            None if generated_artifact.is_none() => current_module.header.source_label.clone(),
            None => {
                return Err(InterpreterError::InternalError {
                    details: format!(
                        "generated closure#{closure_id} has artifact provenance without a module-resolution origin"
                    ),
                });
            }
        };
        Ok((module_specifier, generated_artifact))
    }

    pub(super) fn retained_generated_closure_module(
        &self,
        closure_id: u32,
        handle: GeneratedFunctionArtifactHandle,
    ) -> Result<Arc<Ir3Module>, InterpreterError> {
        let origin = self
            .closure_module_origins
            .get(&closure_id)
            .ok_or_else(|| InterpreterError::InternalError {
                details: format!(
                    "generated closure#{closure_id} has no ordinary module-resolution origin"
                ),
            })?;
        let artifact =
            self.resolve_generated_function_artifact(handle.owner_program_id, handle.artifact_id)?;
        if &artifact.owner_specifier != origin {
            return Err(InterpreterError::InternalError {
                details: format!(
                    "generated closure#{closure_id} resolution origin `{origin}` does not match artifact owner `{}`",
                    artifact.owner_specifier
                ),
            });
        }
        Ok(Arc::clone(&artifact.compiled_module))
    }

    /// Return the retained program for a closure owned by another module or by
    /// a different generated artifact occurrence.
    ///
    /// Function-table indices are local to one `Ir3Module`; treating an
    /// imported closure's index as if it belonged to the caller can silently
    /// jump into an unrelated same-numbered function.
    pub(super) fn foreign_closure_module(
        &self,
        callee: &Value,
        current_module: &Ir3Module,
    ) -> Result<Option<Arc<Ir3Module>>, InterpreterError> {
        let Some(closure_id) = Self::callable_closure_id(callee) else {
            return Ok(None);
        };
        if let Some(handle) = self
            .closure_generated_function_artifacts
            .get(&closure_id)
            .copied()
        {
            let artifact_module = self.retained_generated_closure_module(closure_id, handle)?;
            if self.active_generated_function_artifact == Some(handle) {
                return Ok(None);
            }
            return Ok(Some(artifact_module));
        }
        let Some(origin) = self.closure_module_origins.get(&closure_id) else {
            return Ok(None);
        };
        if origin == &current_module.header.source_label {
            return Ok(None);
        }
        self.retained_closure_module(closure_id, origin).map(Some)
    }

    /// Resolve the immutable retained program for a closure provenance key.
    pub(super) fn retained_closure_module(
        &self,
        closure_id: u32,
        origin: &str,
    ) -> Result<Arc<Ir3Module>, InterpreterError> {
        let record = self.module_state.modules.get(origin).ok_or_else(|| {
            InterpreterError::ModuleEvaluationFailed {
                specifier: origin.to_string(),
                reason: format!(
                    "closure#{closure_id} refers to a module program that is not retained"
                ),
            }
        })?;
        let compiled_module = record.compiled_module.as_ref().ok_or_else(|| {
            InterpreterError::ModuleEvaluationFailed {
                specifier: origin.to_string(),
                reason: format!(
                    "closure#{closure_id} refers to a module record without retained code"
                ),
            }
        })?;
        if compiled_module.header.source_label != origin {
            return Err(InterpreterError::ModuleEvaluationFailed {
                specifier: origin.to_string(),
                reason: format!(
                    "closure#{closure_id} owner mismatch: registry key `{origin}` retained program `{}`",
                    compiled_module.header.source_label
                ),
            });
        }
        Ok(Arc::clone(compiled_module))
    }

    /// Return the program that must own a newly-created continuation object.
    ///
    /// Live closure creation always records an origin whose module program was
    /// retained during evaluation. The fallback preserves private unit
    /// fixtures that seed closure tables directly without an origin record.
    pub(super) fn continuation_owner_module(
        &self,
        closure_id: u32,
        current_module: &Ir3Module,
    ) -> Result<Arc<Ir3Module>, InterpreterError> {
        if let Some(handle) = self
            .closure_generated_function_artifacts
            .get(&closure_id)
            .copied()
        {
            return self.retained_generated_closure_module(closure_id, handle);
        }
        match self.closure_module_origins.get(&closure_id) {
            Some(origin) => self.retained_closure_module(closure_id, origin),
            None => Ok(Arc::new(current_module.clone())),
        }
    }

    pub(super) fn effective_call_depth(&self) -> usize {
        self.call_stack
            .len()
            .saturating_add(self.module_reentrant_call_depth)
    }

    pub(super) fn check_module_reentrant_call_depth(&self) -> Result<(), InterpreterError> {
        let depth = self.effective_call_depth();
        if depth >= self.config.max_call_depth {
            return Err(InterpreterError::StackOverflow {
                depth,
                max: self.config.max_call_depth,
            });
        }
        Ok(())
    }

    pub(super) fn call_arguments(&self, args: RegRange) -> Result<Vec<Value>, InterpreterError> {
        let mut values = Vec::with_capacity(args.count as usize);
        for offset in 0..args.count {
            let register =
                args.start
                    .checked_add(offset)
                    .ok_or(InterpreterError::RegisterOutOfBounds {
                        register: args.start,
                        max: self.config.max_registers,
                    })?;
            values.push(self.read_reg(register)?);
        }
        Ok(values)
    }

    pub(super) fn isolated_call_label_transport_bytes(
        labels: &IsolatedCallLabels,
        argument_count: usize,
    ) -> u64 {
        let receiver_bytes = Self::estimate_label_bytes(&labels.receiver);
        let argument_bytes = match &labels.arguments {
            IsolatedArgumentLabels::Public => 0,
            IsolatedArgumentLabels::Exact(argument_labels) => {
                u64::try_from(argument_labels.capacity())
                    .unwrap_or(u64::MAX)
                    .saturating_mul(std::mem::size_of::<Label>() as u64)
                    .saturating_add(Self::saturating_sum(
                        argument_labels.iter().map(Self::estimate_label_bytes),
                    ))
            }
            // The owned uniform label coexists with one clone per isolated
            // argument register. Reserve all clones before making the first
            // one so a long Custom name cannot cross the physical peak.
            IsolatedArgumentLabels::Uniform(label) => {
                let copies = u64::try_from(argument_count)
                    .unwrap_or(u64::MAX)
                    .saturating_add(1);
                Self::estimate_label_bytes(label).saturating_mul(copies)
            }
        };
        receiver_bytes.saturating_add(argument_bytes)
    }

    /// Clone receiver and argument labels only after preflighting the complete
    /// transport carrier. The returned ownership is charged by the isolated
    /// wrapper before it clones any module or caller snapshot.
    pub(super) fn isolated_call_label_transport_bytes_from_registers(
        &self,
        receiver_register: Option<u32>,
        args: RegRange,
    ) -> Result<u64, InterpreterError> {
        let receiver_label = receiver_register
            .map(|register| self.get_register_label(register))
            .transpose()?;
        let mut transport_bytes = receiver_label
            .map(Self::estimate_label_bytes)
            .unwrap_or(0)
            .saturating_add(
                u64::from(args.count).saturating_mul(std::mem::size_of::<Label>() as u64),
            );
        for offset in 0..args.count {
            let register =
                args.start
                    .checked_add(offset)
                    .ok_or(InterpreterError::RegisterOutOfBounds {
                        register: args.start,
                        max: self.config.max_registers,
                    })?;
            transport_bytes = transport_bytes.saturating_add(Self::estimate_label_bytes(
                self.get_register_label(register)?,
            ));
        }
        Ok(transport_bytes)
    }

    pub(super) fn clone_isolated_call_labels_from_registers(
        &self,
        receiver_register: Option<u32>,
        args: RegRange,
    ) -> Result<IsolatedCallLabels, InterpreterError> {
        let transport_bytes =
            self.isolated_call_label_transport_bytes_from_registers(receiver_register, args)?;
        self.check_temporary_memory_budget(transport_bytes)?;

        let receiver_label = receiver_register
            .map(|register| self.get_register_label(register))
            .transpose()?;
        let mut argument_labels = Vec::with_capacity(args.count as usize);
        for offset in 0..args.count {
            let register =
                args.start
                    .checked_add(offset)
                    .ok_or(InterpreterError::RegisterOutOfBounds {
                        register: args.start,
                        max: self.config.max_registers,
                    })?;
            argument_labels.push(self.get_register_label(register)?.clone());
        }
        Ok(IsolatedCallLabels {
            receiver: receiver_label.cloned().unwrap_or(Label::Public),
            arguments: IsolatedArgumentLabels::Exact(argument_labels),
        })
    }

    pub(super) fn release_isolated_label_transport_charge(
        &mut self,
        remaining_transport_bytes: &mut u64,
        released_bytes: u64,
    ) {
        *remaining_transport_bytes = remaining_transport_bytes.saturating_sub(released_bytes);
        self.estimated_memory_bytes = self.estimated_memory_bytes.saturating_sub(released_bytes);
    }

    pub(super) fn seed_isolated_receiver(
        &mut self,
        register: u32,
        value: Value,
        label: Option<Label>,
        remaining_transport_bytes: &mut u64,
    ) -> Result<(), InterpreterError> {
        let Some(label) = label else {
            return self.write_reg(register, value);
        };
        let label_bytes = Self::estimate_label_bytes(&label);
        self.release_isolated_label_transport_charge(remaining_transport_bytes, label_bytes);
        self.write_reg_with_label(register, value, label)
    }

    /// bd-9vouw.50: register `reg`, at or past `max_registers`, of the active
    /// frame, when the call site that owns the frame staged its trailing
    /// arguments there. Any other register there is out of bounds.
    #[cold]
    pub(super) fn overflow_argument(&self, reg: u32) -> Result<(&Value, &Label), InterpreterError> {
        let out_of_bounds = InterpreterError::RegisterOutOfBounds {
            register: reg,
            max: self.config.max_registers,
        };
        let Some(overflow) = self
            .argument_overflow
            .last()
            .filter(|overflow| overflow.register_base == self.register_base)
        else {
            return Err(out_of_bounds);
        };
        let index = (reg - self.config.max_registers) as usize;
        match (overflow.values.get(index), overflow.labels.get(index)) {
            (Some(value), Some(label)) => Ok((value, label)),
            _ => Err(out_of_bounds),
        }
    }

    /// bd-9vouw.50: make `values`/`labels` registers `max_registers..` of the
    /// active frame, charging `bytes` (a list's entry charges its own size as
    /// well; an empty entry, pushed by every call site whose list fits, is
    /// bounded by the native call depth and charged nothing). Returns the
    /// stack depth to hand to [`Self::restore_argument_overflow`] when the
    /// call site is done.
    pub(super) fn install_argument_overflow(
        &mut self,
        values: Vec<Value>,
        labels: Vec<Label>,
        bytes: u64,
    ) -> usize {
        let depth = self.argument_overflow.len();
        let bytes = if values.is_empty() {
            bytes
        } else {
            bytes.saturating_add(std::mem::size_of::<ArgumentOverflow>() as u64)
        };
        self.argument_overflow_bytes = self.argument_overflow_bytes.saturating_add(bytes);
        self.argument_overflow.push(ArgumentOverflow {
            register_base: self.register_base,
            values,
            labels,
            bytes,
        });
        depth
    }

    /// bd-9vouw.50: end the out-of-band lists of every call site from `depth`
    /// up, releasing their charge; the caller's list is readable again.
    pub(super) fn restore_argument_overflow(&mut self, depth: usize) {
        for staged in self.argument_overflow.drain(depth..) {
            self.argument_overflow_bytes =
                self.argument_overflow_bytes.saturating_sub(staged.bytes);
        }
    }

    /// bd-9vouw.50: a synthetic call site about to stage `arguments` from
    /// `start_register` moves whatever does not fit the register frame, with
    /// its labels, out of band. It always pushes an entry (empty when
    /// everything fits), so a register past the frame only ever reads the
    /// innermost call site's own arguments. The moved labels stay under the
    /// call's label-transport charge; the values and both carriers are
    /// charged here. Returns the depth for [`Self::restore_argument_overflow`].
    pub(super) fn stage_argument_overflow(
        &mut self,
        start_register: u32,
        arguments: &mut Vec<Value>,
        labels: &mut IsolatedArgumentLabels,
    ) -> Result<usize, InterpreterError> {
        let in_frame = self.config.max_registers.saturating_sub(start_register) as usize;
        if arguments.len() <= in_frame {
            return Ok(self.install_argument_overflow(Vec::new(), Vec::new(), 0));
        }
        let values = arguments.split_off(in_frame);
        let tail_labels = match labels {
            IsolatedArgumentLabels::Public => vec![Label::Public; values.len()],
            IsolatedArgumentLabels::Exact(labels) => labels.split_off(in_frame.min(labels.len())),
            IsolatedArgumentLabels::Uniform(label) => vec![label.clone(); values.len()],
        };
        let bytes = Self::estimate_value_vec_bytes(&values).saturating_add(
            u64::try_from(tail_labels.len())
                .unwrap_or(u64::MAX)
                .saturating_mul(std::mem::size_of::<Label>() as u64),
        );
        self.check_temporary_memory_budget(bytes)?;
        Ok(self.install_argument_overflow(values, tail_labels, bytes))
    }

    pub(super) fn seed_isolated_arguments(
        &mut self,
        start_register: u32,
        arguments: Vec<Value>,
        labels: IsolatedArgumentLabels,
        remaining_transport_bytes: &mut u64,
        register_description: &str,
    ) -> Result<(), InterpreterError> {
        match labels {
            IsolatedArgumentLabels::Public => {
                for (index, argument) in arguments.into_iter().enumerate() {
                    let register = start_register
                        .checked_add(u32::try_from(index).map_err(|_| {
                            InterpreterError::TypeError {
                                expected: format!("u32-bounded {register_description}"),
                                got: format!("argument index {index}"),
                            }
                        })?)
                        .ok_or_else(|| InterpreterError::TypeError {
                            expected: format!("u32-bounded {register_description}"),
                            got: format!("r{start_register} + argument index {index}"),
                        })?;
                    self.write_reg(register, argument)?;
                }
            }
            IsolatedArgumentLabels::Exact(argument_labels) => {
                let structural_bytes = u64::try_from(argument_labels.capacity())
                    .unwrap_or(u64::MAX)
                    .saturating_mul(std::mem::size_of::<Label>() as u64);
                let mut labels = argument_labels.into_iter();
                for (index, argument) in arguments.into_iter().enumerate() {
                    let register = start_register
                        .checked_add(u32::try_from(index).map_err(|_| {
                            InterpreterError::TypeError {
                                expected: format!("u32-bounded {register_description}"),
                                got: format!("argument index {index}"),
                            }
                        })?)
                        .ok_or_else(|| InterpreterError::TypeError {
                            expected: format!("u32-bounded {register_description}"),
                            got: format!("r{start_register} + argument index {index}"),
                        })?;
                    let label = labels.next().expect(
                        "isolated exact argument-label count was validated before state mutation",
                    );
                    let label_bytes = Self::estimate_label_bytes(&label);
                    self.release_isolated_label_transport_charge(
                        remaining_transport_bytes,
                        label_bytes,
                    );
                    self.write_reg_with_label(register, argument, label)?;
                }
                drop(labels);
                self.release_isolated_label_transport_charge(
                    remaining_transport_bytes,
                    structural_bytes,
                );
            }
            IsolatedArgumentLabels::Uniform(label) => {
                let label_bytes = Self::estimate_label_bytes(&label);
                for (index, argument) in arguments.into_iter().enumerate() {
                    let register = start_register
                        .checked_add(u32::try_from(index).map_err(|_| {
                            InterpreterError::TypeError {
                                expected: format!("u32-bounded {register_description}"),
                                got: format!("argument index {index}"),
                            }
                        })?)
                        .ok_or_else(|| InterpreterError::TypeError {
                            expected: format!("u32-bounded {register_description}"),
                            got: format!("r{start_register} + argument index {index}"),
                        })?;
                    let argument_label = label.clone();
                    self.release_isolated_label_transport_charge(
                        remaining_transport_bytes,
                        label_bytes,
                    );
                    self.write_reg_with_label(register, argument, argument_label)?;
                }
                drop(label);
                self.release_isolated_label_transport_charge(
                    remaining_transport_bytes,
                    label_bytes,
                );
            }
        }
        Ok(())
    }

    pub(super) fn function_ref(
        &self,
        module: &Ir3Module,
        callee: &Value,
        function_index: u32,
    ) -> FunctionRef {
        let name = module
            .function_table
            .get(function_index as usize)
            .and_then(|desc| desc.name.clone());
        match callee {
            Value::Function(_) => FunctionRef::Function {
                function_index,
                name,
            },
            Value::Closure(closure_id) => FunctionRef::Closure {
                closure_id: *closure_id,
                function_index,
                name,
            },
            _ => FunctionRef::Function {
                function_index,
                name,
            },
        }
    }

    pub(super) fn enforce_hook_action(&self, action: HookAction) -> Result<(), InterpreterError> {
        match action {
            HookAction::Allow => Ok(()),
            HookAction::Challenge(token) => Err(InterpreterError::ContainmentActionRequested {
                action: "challenge".to_string(),
                reason: Some(token.token),
            }),
            HookAction::Sandbox => {
                if self.active_sandbox.get().is_none() {
                    let configured_ceiling = self.config.sandbox_policy.max_memory_bytes;
                    let memory_ceiling_bytes = if configured_ceiling == 0 {
                        self.sandbox_memory_usage()
                    } else {
                        configured_ceiling
                    }
                    .min(self.config.max_total_memory_bytes);
                    self.active_sandbox.set(Some(ActiveSandbox {
                        memory_ceiling_bytes,
                        instruction_index: self.ip as u32,
                        timestamp_tick: self.instructions_executed,
                    }));
                    self.sandbox_witness_pending.set(true);
                }
                // A tighter policy may already be below the live footprint.
                // Install it first, then stop before the triggering operation;
                // subsequent Allow decisions must not undo the restriction.
                if self.sandbox_memory_usage()
                    > self
                        .active_sandbox
                        .get()
                        .expect("sandbox activated")
                        .memory_ceiling_bytes
                {
                    return Err(Self::sandbox_interruption());
                }
                Ok(())
            }
            HookAction::Suspend => Err(InterpreterError::ContainmentActionRequested {
                action: "suspend".to_string(),
                reason: None,
            }),
            HookAction::Terminate(reason) => Err(InterpreterError::ContainmentActionRequested {
                action: "terminate".to_string(),
                reason: Some(reason),
            }),
            HookAction::Quarantine(reason) => Err(InterpreterError::ContainmentActionRequested {
                action: "quarantine".to_string(),
                reason: Some(reason),
            }),
        }
    }

    pub(super) fn sandbox_interruption() -> InterpreterError {
        InterpreterError::ContainmentActionRequested {
            action: "sandbox".to_string(),
            reason: None,
        }
    }

    /// Cached/pruned grants and generated-code grant restoration only describe
    /// the original authority. A live sandbox is an independent intersection.
    pub(super) fn sandbox_allows_hostcall(&self, tag: &str) -> bool {
        self.active_sandbox.get().is_none()
            || match classify_hostcall_capability(tag) {
                HostcallCapabilityClass::InternalAllowed => true,
                HostcallCapabilityClass::Runtime(capability) => self
                    .config
                    .sandbox_policy
                    .allows_runtime_capability(capability),
                HostcallCapabilityClass::Unknown => false,
            }
    }

    /// Instruction hooks use an immutable core borrow. Flush their activation
    /// before the next recorded event, preserving the original logical tick.
    /// Actual risk and signatures belong to the live guardplane report; this
    /// witness commits only to the policy that the interpreter applied.
    pub(super) fn flush_sandbox_witness(&mut self) {
        if !self.sandbox_witness_pending.replace(false) {
            return;
        }
        let sandbox = self.active_sandbox.get().expect("pending active sandbox");
        let payload = format!(
            "sandbox_v1:{}:{}",
            self.config.sandbox_policy.content_hash().to_hex(),
            sandbox.memory_ceiling_bytes,
        );
        self.witness_events.push(WitnessEvent {
            seq: self.witness_seq,
            kind: WitnessEventKind::ContainmentAction,
            instruction_index: sandbox.instruction_index,
            payload_hash: ContentHash::compute(payload.as_bytes()),
            timestamp_tick: sandbox.timestamp_tick,
        });
        self.witness_seq = self.witness_seq.saturating_add(1);
    }

    /// Get the decision receipts log for export or testing.
    pub fn decision_receipts(&self) -> &EvidenceLog {
        &self.decision_receipts
    }

    /// Export decision receipts as JSON evidence bundle.
    pub fn export_decision_receipts(&self) -> Result<String, serde_json::Error> {
        self.decision_receipts.export_json()
    }

    /// Verify the integrity of the decision receipt chain.
    pub fn verify_decision_receipt_chain(&self) -> bool {
        self.decision_receipts.verify_chain()
    }

    pub(super) fn property_hook_compatibility_error(
        error: HookPropertyKeyCompatibilityError,
    ) -> InterpreterError {
        InterpreterError::TypeError {
            expected: "property key supported by the installed interpreter hook".to_string(),
            got: error.to_string(),
        }
    }

    /// Preserve fail-closed behavior in legacy-only internal property paths
    /// that do not have a module-backed object target to present to a hook.
    pub(super) fn preflight_legacy_property_key_for_hook(
        &self,
        key: &RuntimePropertyKey,
    ) -> Result<(), InterpreterError> {
        if !self
            .hook
            .as_ref()
            .is_some_and(|hook| hook.instruction_hooks_enabled())
        {
            return Ok(());
        }
        let hook_key = match key {
            RuntimePropertyKey::String(key) => HookPropertyKey::String(key.clone()),
            RuntimePropertyKey::Symbol(symbol) => HookPropertyKey::Symbol(*symbol),
        };
        hook_key
            .as_legacy_str()
            .map(|_| ())
            .map_err(Self::property_hook_compatibility_error)
    }

    pub(super) fn run_pre_runtime_property_access_hook(
        &self,
        module: &Ir3Module,
        target: ObjectId,
        key: &RuntimePropertyKey,
    ) -> Result<(), InterpreterError> {
        self.validate_executable_property_key(key)?;
        let Some(hook) = self
            .hook
            .as_ref()
            .filter(|hook| hook.instruction_hooks_enabled())
        else {
            return Ok(());
        };
        let ctx = self.hook_context(module);
        let hook_key = match key {
            RuntimePropertyKey::String(key) => HookPropertyKey::String(key.clone()),
            RuntimePropertyKey::Symbol(symbol) => HookPropertyKey::Symbol(*symbol),
        };
        let action = hook
            .pre_property_access_typed(&ctx, &target, &hook_key)
            .map_err(Self::property_hook_compatibility_error)?;
        self.enforce_hook_action(action)
    }

    pub(super) fn run_pre_call_hook(
        &self,
        module: &Ir3Module,
        callee: &Value,
        function_index: u32,
        args: &[Value],
    ) -> Result<(), InterpreterError> {
        let Some(hook) = self
            .hook
            .as_ref()
            .filter(|hook| hook.instruction_hooks_enabled())
        else {
            return Ok(());
        };
        let ctx = self.hook_context(module);
        let function_ref = self.function_ref(module, callee, function_index);
        self.enforce_hook_action(hook.pre_call(&ctx, &function_ref, args))
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn enter_constructor_call(
        &mut self,
        module: &Ir3Module,
        callee_value: Value,
        callee_label: Label,
        args: RegRange,
        return_ip: usize,
        return_reg: u32,
        new_target_value: Value,
        new_target_label: Label,
        initialize_derived_this_on_return: bool,
        compact_tier1: Option<&CompactTier1Program>,
    ) -> Result<(), InterpreterError> {
        self.enter_constructor_call_with_prototype(
            module,
            callee_value,
            callee_label,
            args,
            return_ip,
            return_reg,
            new_target_value,
            new_target_label,
            initialize_derived_this_on_return,
            compact_tier1,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn enter_constructor_call_with_prototype(
        &mut self,
        module: &Ir3Module,
        callee_value: Value,
        callee_label: Label,
        args: RegRange,
        return_ip: usize,
        return_reg: u32,
        new_target_value: Value,
        mut new_target_label: Label,
        initialize_derived_this_on_return: bool,
        compact_tier1: Option<&CompactTier1Program>,
        resolved_prototype: Option<ObjectId>,
    ) -> Result<(), InterpreterError> {
        if resolved_prototype.is_none()
            && let Some((_, label)) =
                self.constructor_prototype_override(module, &new_target_value)?
        {
            new_target_label =
                self.join_owned_label_with_temporary_budget(new_target_label, &label)?;
        }
        let mut active_callee = callee_value;
        let mut active_callee_label = callee_label;
        // The active callee's default prototype object, which holds its
        // constructor metadata, field list and HomeObject (bd-9vouw.504).
        let mut active_default_prototype = None;
        let mut forwarding_depth = 0usize;
        loop {
            if matches!(&active_callee, Value::Str(_)) {
                break;
            }
            let default_prototype =
                self.default_constructor_prototype_for_value(module, &active_callee)?;
            let (_, default_derived, parent, parent_label) =
                self.derived_constructor_metadata_of_prototype(default_prototype)?;
            if !default_derived {
                active_default_prototype = Some(default_prototype);
                break;
            }
            if forwarding_depth >= self.config.max_call_depth {
                return Err(InterpreterError::StackOverflow {
                    depth: forwarding_depth,
                    max: self.config.max_call_depth,
                });
            }
            active_callee = parent;
            active_callee_label =
                self.join_owned_label_with_temporary_budget(active_callee_label, &parent_label)?;
            forwarding_depth += 1;
        }

        // Builtin parents are represented by their canonical constructor name
        // in the child prototype metadata. Their construction is synchronous,
        // but still allocates from the original `new.target.prototype`.
        // Builtin parents without a name record (`extends Date`, `extends
        // Uint8Array`, `extends WeakMap`, ...) are constructed natively and
        // given new.target's prototype, as `Reflect.construct(parent, args,
        // new.target)` is; the implicit constructor and `super(x)` failed on
        // them with "expected constructor function".
        let builtin_parent_object = match &active_callee {
            Value::Str(parent_name) => {
                let parent_name = parent_name.to_string();
                let prototype = self.constructor_prototype_for_value(module, &new_target_value)?;
                let object_id = if parent_name == "Array" {
                    self.alloc_array_with_prototype(Some(prototype))?
                } else {
                    self.alloc_object_with_prototype(Some(prototype))?
                };
                let constructor_index = self.constructor_function_index(&new_target_value)?;
                self.mutate_heap(|heap| {
                    if let Some(object) = heap.get_mut(object_id.0 as usize) {
                        object.constructor_function = Some(constructor_index);
                    }
                });
                self.initialize_builtin_subclass_instance(
                    Some(module),
                    object_id,
                    &parent_name,
                    args,
                )?;
                if parent_name == "Array" {
                    self.initialize_array_subclass_instance(object_id, args)?;
                }
                Some(Value::Object(object_id))
            }
            Value::BuiltinFunction(builtin)
                if !matches!(
                    builtin.kind,
                    BuiltinFunctionKind::BoundFunction | BuiltinFunctionKind::GeneratedFunction
                ) =>
            {
                Some(self.construct_builtin_with_new_target_and_labels(
                    module,
                    builtin,
                    args,
                    &new_target_value,
                    &active_callee_label,
                    &new_target_label,
                )?)
            }
            _ => None,
        };
        // A parent of another module (`class C extends require('./base')`, a
        // constructor function from a package) is constructed in its own
        // module, with new.target, as Reflect.construct does: its function
        // index means nothing in this module's table, where it ran whatever
        // function had that index ("super() in a base constructor", a
        // silently missing base initialization, "function#5 not found")
        // (bd-9vouw.203).
        let (builtin_parent_object, foreign_parent_label) = match builtin_parent_object {
            Some(result) => (Some(result), None),
            None if matches!(&active_callee, Value::BuiltinFunction(builtin)
                if builtin.kind == BuiltinFunctionKind::GeneratedFunction) =>
            {
                let Value::BuiltinFunction(builtin) = &active_callee else {
                    unreachable!("generated constructor matched above");
                };
                let (result, label) = self.construct_generated_function_artifact(
                    module,
                    builtin,
                    args,
                    new_target_value.clone(),
                    new_target_label.clone(),
                )?;
                (Some(result), Some(label))
            }
            None if matches!(active_callee, Value::Closure(_))
                && self
                    .foreign_closure_module(&active_callee, module)?
                    .is_some() =>
            {
                let call_labels = self.clone_isolated_call_labels_from_registers(None, args)?;
                let arguments = self.call_arguments(args)?;
                let (result, label) = self.invoke_inline_construct_with_labels(
                    Some(module),
                    active_callee.clone(),
                    arguments,
                    Some(call_labels),
                    Some((new_target_value.clone(), new_target_label.clone())),
                )?;
                (Some(result), Some(label))
            }
            None => (None, None),
        };
        if let Some(result) = builtin_parent_object {
            let args_label = self.join_arg_range_label(args)?;
            let result_label =
                self.join_owned_label_with_temporary_budget(args_label, &new_target_label)?;
            let result_label =
                self.join_owned_label_with_temporary_budget(result_label, &active_callee_label)?;
            let result_label = match &foreign_parent_label {
                Some(label) => self.join_owned_label_with_temporary_budget(result_label, label)?,
                None => result_label,
            };
            let result_label = if matches!(&active_callee, Value::BuiltinFunction(builtin)
                if builtin.kind.observes_host_effect_selection())
            {
                let observed = self
                    .take_pending_hostcall_result_label()
                    .unwrap_or(Label::Public);
                self.join_owned_label_with_temporary_budget(observed, &result_label)?
            } else {
                result_label
            };
            if initialize_derived_this_on_return {
                let frame =
                    self.call_stack
                        .last_mut()
                        .ok_or_else(|| InterpreterError::TypeError {
                            expected: "enclosing derived constructor".to_string(),
                            got: "missing caller frame after super()".to_string(),
                        })?;
                if !frame.derived_constructor || frame.this_initialized {
                    return Err(InterpreterError::TypeError {
                        expected: "uninitialized enclosing derived-constructor this binding"
                            .to_string(),
                        got: "super() attempted to initialize this twice".to_string(),
                    });
                }
                frame.this_value = result.clone();
                frame.this_label = result_label.clone();
                frame.this_initialized = true;
            }
            self.write_reg_with_label(return_reg, result, result_label)?;
            self.ip = return_ip;
            if initialize_derived_this_on_return {
                self.run_derived_class_instance_fields(Some(module))?;
            }
            return Ok(());
        }

        let default_prototype = match active_default_prototype {
            Some(prototype) => prototype,
            None => self.default_constructor_prototype_for_value(module, &active_callee)?,
        };
        let (derived_constructor, _, super_value, super_label) =
            self.derived_constructor_metadata_of_prototype(default_prototype)?;
        let function_index = self.constructor_function_index(&active_callee)?;
        let captured_env = match &active_callee {
            Value::Function(_) => None,
            Value::Closure(closure_id) => {
                let closure = self.closures.get(*closure_id as usize).ok_or_else(|| {
                    InterpreterError::TypeError {
                        expected: "valid closure".to_string(),
                        got: format!("closure#{closure_id} not found"),
                    }
                })?;
                Some(self.clone_scope_frames_with_budget(&closure.captured_env)?)
            }
            _ => unreachable!("constructor_function_index validated the active callee"),
        };
        let function = module.function_table.get(function_index as usize).ok_or(
            InterpreterError::FunctionNotFound {
                index: function_index,
                table_size: module.function_table.len() as u32,
            },
        )?;
        let effective_depth = self.effective_call_depth();
        if effective_depth >= self.config.max_call_depth {
            return Err(InterpreterError::StackOverflow {
                depth: effective_depth,
                max: self.config.max_call_depth,
            });
        }

        let this_label = self.join_owned_label_with_temporary_budget(
            active_callee_label.clone(),
            &new_target_label,
        )?;
        let (this_value, construct_this, this_initialized) = if derived_constructor {
            (Value::Undefined, None, false)
        } else {
            let prototype = match resolved_prototype {
                Some(prototype) => prototype,
                None => self.constructor_prototype_for_value(module, &new_target_value)?,
            };
            let builtin_parent = self.builtin_subclass_ancestor_name(prototype)?;
            // ES2020 9.1.13 OrdinaryCreateFromConstructor: `new F()` makes an
            // ordinary object even when F.prototype inherits from
            // Array.prototype; only an Array constructor call (a class's
            // super()) makes an Array exotic object. Treating it as an array
            // made `this[this.length] = x; this.length++` count twice
            // (cytoscape's collections, bd-9vouw.152).
            let object_id = self.alloc_object_with_prototype(Some(prototype))?;
            self.mutate_heap(|heap| {
                if let Some(object) = heap.get_mut(object_id.0 as usize) {
                    object.constructor_function = Some(function_index);
                }
            });
            if let Some(parent_name) = builtin_parent.as_deref() {
                self.initialize_builtin_subclass_instance(
                    Some(module),
                    object_id,
                    parent_name,
                    args,
                )?;
            }
            let this_value = Value::Object(object_id);
            (this_value.clone(), Some(this_value), true)
        };
        // ES2022 [[Construct]]: a base class's instance fields initialize on
        // the new object before its constructor body (and parameter
        // initializers) run; a derived class's once its super() returns.
        let class_instance_fields = self.class_instance_field_list(default_prototype);
        let class_instance_fields = match (&class_instance_fields, &construct_this) {
            (Some(fields), Some(Value::Object(object_id))) if !derived_constructor => {
                self.run_class_field_initializers(
                    module,
                    Value::Object(*object_id),
                    *object_id,
                    fields,
                )?;
                None
            }
            _ => class_instance_fields.filter(|_| derived_constructor),
        };

        let mut argument_values = Vec::new();
        let mut argument_labels = Vec::new();
        for offset in 0..args.count.min(function.arity) {
            let register =
                args.start
                    .checked_add(offset)
                    .ok_or(InterpreterError::RegisterOutOfBounds {
                        register: args.start,
                        max: self.config.max_registers,
                    })?;
            argument_values.push(self.read_reg(register)?);
            argument_labels.push(self.get_register_label(register)?.clone());
        }
        self.apply_rest_param(&mut argument_values, function.rest_param_index, args)?;
        self.apply_rest_param_labels(&mut argument_labels, function.rest_param_index, args)?;
        self.stage_arguments_object(module, function, function_index, &active_callee, args)?;
        self.run_pre_call_hook(module, &active_callee, function_index, &argument_values)?;
        let super_home_object =
            self.constructor_super_home_object(module, function_index, default_prototype)?;

        let scope_depth = self.scope_chain.depth();
        let captured_env_bytes = captured_env
            .as_ref()
            .map(|environment| Self::estimate_scope_chain_bytes(environment))
            .unwrap_or(0);
        if captured_env.is_some() {
            self.preflight_scope_chain_snapshot_with_temporary_budget(captured_env_bytes)?;
        }
        let previous_scope_bytes = self.scope_chain_memory_bytes();
        let previous_closure_bytes = self.closures_memory_bytes();
        let previous_call_stack_bytes = self.call_stack_memory_bytes();
        // The callee's environment replaces the caller's chain below, so the
        // frame takes the chain itself rather than a copy (bd-9vouw.504);
        // nothing reads the chain until the environment is in place.
        let saved_scope_chain = captured_env
            .is_some()
            .then(|| std::mem::take(&mut self.scope_chain.frames));
        let pushed_frame = CallFrame {
            return_ip,
            return_reg,
            register_base: self.register_base,
            register_width: self.register_width,
            function_index: Some(function_index),
            this_value,
            this_label,
            new_target_value,
            new_target_label,
            super_value,
            super_label,
            super_home_object,
            construct_this,
            derived_constructor,
            this_initialized,
            initialize_derived_this_on_return,
            class_instance_fields,
            saved_pending_exception: self.pending_exception.take(),
            saved_pending_exception_label: std::mem::replace(
                &mut self.pending_exception_label,
                Label::Public,
            ),
            saved_pending_return: self.pending_return.take(),
            saved_suspended_abrupt_depth: self.suspended_abrupt_completions.len(),
            saved_finally_mode_depth: self.finally_frames.len(),
            saved_scope_depth: scope_depth,
            saved_scope_chain,
            scope_inert_virtual_scope_bytes: 0,
            async_function_id: None,
            native_boundary: false,
        };
        self.call_stack
            .push(pushed_frame, &mut self.closures.cold_cells);

        if let Some(environment) = captured_env {
            self.scope_chain.frames = environment;
        }
        if let Err(error) = self.scope_chain.push(self.config.max_scope_depth) {
            self.rollback_call_setup_state();
            return Err(error);
        }
        if let Err(error) = self.apply_scope_closure_call_stack_memory_delta(
            previous_scope_bytes,
            previous_closure_bytes,
            previous_call_stack_bytes,
        ) {
            self.rollback_call_setup_state();
            return Err(error);
        }

        self.enter_stacked_register_frame_for_function(module, compact_tier1, function_index)?;
        for (index, (value, label)) in argument_values.into_iter().zip(argument_labels).enumerate()
        {
            let register = index as u32;
            if register < self.config.max_registers {
                self.write_reg_with_label(register, value, label)?;
            }
        }
        self.ip = function.entry as usize;
        Ok(())
    }

    pub(super) fn run_pre_allocation_hook(
        &self,
        module: &Ir3Module,
        kind: AllocKind,
        size_hint: usize,
    ) -> Result<(), InterpreterError> {
        // Engine-internal prepare-phase allocations are exempt from hooks: no extension
        // instruction has executed yet, so there is nothing for a containment
        // policy to attribute (bd-gug3l). Mid-execution module allocations
        // (dynamic import / require) still run the hook — this flag is only
        // set inside prepare_execution.
        // A sandbox carried across a seed/repeat reset still applies during
        // preparation; the exemption cannot revive allocation authority.
        if !self.preparing_execution
            && let Some(hook) = self
                .hook
                .as_ref()
                .filter(|hook| hook.instruction_hooks_enabled())
        {
            let ctx = self.hook_context(module);
            self.enforce_hook_action(hook.pre_allocation(&ctx, kind, size_hint))?;
        }
        self.ensure_heap_allocation_allowed()
    }

    pub(super) fn run_pre_import_hook(
        &self,
        module: &Ir3Module,
        specifier: &str,
    ) -> Result<(), InterpreterError> {
        if let Some(hook) = self
            .hook
            .as_ref()
            .filter(|hook| hook.instruction_hooks_enabled())
        {
            let ctx = self.hook_context(module);
            self.enforce_hook_action(hook.pre_import(&ctx, specifier))?;
        }
        // The import hook runs after the outer HostCall gate. Recheck the
        // narrowed authority before resolver/provider work or cache access.
        if !self.sandbox_allows_hostcall("module:import") {
            return Err(Self::sandbox_interruption());
        }
        Ok(())
    }

    pub(super) fn generator_result_object(
        &mut self,
        value: Value,
        done: bool,
    ) -> Result<Value, InterpreterError> {
        self.generator_result_object_labeled(value, &Label::Public, done)
    }

    pub(super) fn generator_result_object_labeled(
        &mut self,
        value: Value,
        value_label: &Label,
        done: bool,
    ) -> Result<Value, InterpreterError> {
        let result_id = self.alloc_object_with_prototype(None)?;
        self.set_object_property(result_id, "value".to_string(), value)?;
        if *value_label != Label::Public {
            self.set_own_runtime_property_label(
                result_id,
                &RuntimePropertyKey::String(JsString::from("value")),
                value_label,
            )?;
        }
        self.set_object_property(result_id, "done".to_string(), Value::Bool(done))?;
        Ok(Value::Object(result_id))
    }

    pub(super) fn capture_generator_arguments(
        &self,
        args: RegRange,
    ) -> Result<(Vec<Value>, Vec<Label>), InterpreterError> {
        let mut arguments = Vec::new();
        let mut labels = Vec::new();
        for offset in 0..args.count {
            let reg =
                args.start
                    .checked_add(offset)
                    .ok_or(InterpreterError::RegisterOutOfBounds {
                        register: args.start,
                        max: self.config.max_registers,
                    })?;
            arguments.push(self.read_reg(reg)?);
            labels.push(self.get_register_label(reg)?.clone());
        }
        Ok((arguments, labels))
    }

    pub(super) fn materialize_generator_arguments(
        &mut self,
        func: &crate::ir_contract::Ir3FunctionDesc,
        mut arguments: Vec<Value>,
        mut labels: Vec<Label>,
    ) -> Result<(Vec<Value>, Vec<Label>), InterpreterError> {
        if arguments.len() != labels.len() {
            return Err(InterpreterError::InternalError {
                details: format!(
                    "generator invocation value/label length mismatch: values={}, labels={}",
                    arguments.len(),
                    labels.len()
                ),
            });
        }

        let Some(rest_index) = func.rest_param_index else {
            arguments.truncate(func.arity as usize);
            labels.truncate(func.arity as usize);
            return Ok((arguments, labels));
        };
        if rest_index.checked_add(1) != Some(func.arity) || rest_index >= self.config.max_registers
        {
            return Err(InterpreterError::TypeError {
                expected: format!(
                    "final generator rest parameter index for arity {} below register limit {}",
                    func.arity, self.config.max_registers
                ),
                got: format!("rest index {rest_index}"),
            });
        }

        let rest_slot = rest_index as usize;
        let rest_values = arguments
            .get(rest_slot..)
            .map_or_else(Vec::new, |values| values.to_vec());
        let rest_label = labels
            .get(rest_slot..)
            .unwrap_or(&[])
            .iter()
            .fold(Label::Public, |joined, label| joined.join(label));
        let array_id = self.alloc_array_with_prototype(None)?;
        for (index, value) in rest_values.into_iter().enumerate() {
            self.set_object_property(array_id, index.to_string(), value)?;
        }
        let length = arguments.len().saturating_sub(rest_slot);
        self.set_object_property(
            array_id,
            "length".to_string(),
            Value::Int(i64::try_from(length).unwrap_or(i64::MAX)),
        )?;
        let dense_length = u32::try_from(length).unwrap_or(u32::MAX);
        self.mutate_heap(|heap| {
            if let Some(object) = heap.get_mut(array_id.0 as usize) {
                object.cached_dense_length = Some(dense_length);
            }
        });

        arguments.resize(rest_slot + 1, Value::Undefined);
        arguments.truncate(rest_slot + 1);
        arguments[rest_slot] = Value::Object(array_id);
        labels.resize(rest_slot + 1, Label::Public);
        labels.truncate(rest_slot + 1);
        labels[rest_slot] = rest_label;
        Ok((arguments, labels))
    }

    pub(super) fn prepare_generator_execution(
        &mut self,
        module: &Ir3Module,
        invocation: GeneratorInvocation,
    ) -> Result<GeneratorExecutionSnapshot, InterpreterError> {
        let func = module
            .function_table
            .get(invocation.function_index as usize)
            .cloned()
            .ok_or(InterpreterError::FunctionNotFound {
                index: invocation.function_index,
                table_size: module.function_table.len() as u32,
            })?;
        let contained_codegen_grant = invocation
            .generated_function_artifact
            .map(|handle| self.contained_codegen_grant_for_artifact(handle))
            .transpose()?;
        // A generator body that reads `arguments` gets the object of its
        // invocation's full argument list (bd-9vouw.25): the call only
        // created the generator, so no call setup staged it, and the body
        // saw an empty arguments object. Staged below, once this activation
        // is complete, for the generator's single frame.
        let arguments_object = if matches!(
            module.instructions.get(func.entry as usize),
            Some(Ir3Instruction::HostCall { capability, .. })
                if capability.0 == crate::lowering_pipeline::ARGUMENTS_OBJECT_CAPABILITY
        ) {
            let label = invocation
                .argument_labels
                .iter()
                .fold(Label::Public, |joined, label| joined.join(label));
            // bd-9vouw.272: a strict generator's or one with a non-simple
            // parameter list's `callee` is the %ThrowTypeError% accessor.
            // No-claim: a sloppy generator with a simple parameter list gets
            // no `callee` (Node: the generator function).
            let callee = match module.sloppy_functions.get(&invocation.function_index) {
                Some(true) => ArgumentsCallee::Omitted,
                _ => ArgumentsCallee::ThrowTypeError,
            };
            Some((
                self.alloc_arguments_object(&invocation.arguments, callee)?,
                label,
            ))
        } else {
            None
        };
        let (arguments, argument_labels) = self.materialize_generator_arguments(
            &func,
            invocation.arguments,
            invocation.argument_labels,
        )?;

        let captured_env = if let Some(closure_id) = invocation.closure_index {
            let closure = self.closures.get(closure_id as usize).ok_or_else(|| {
                InterpreterError::TypeError {
                    expected: "valid closure".into(),
                    got: format!("closure#{closure_id} not found"),
                }
            })?;
            self.clone_scope_frames_with_budget(&closure.captured_env)?
        } else {
            Vec::new()
        };
        let mut scope_chain = if captured_env.is_empty() {
            ScopeChain::new()
        } else {
            ScopeChain {
                frames: captured_env,
            }
        };
        let saved_scope_depth = scope_chain.depth();
        scope_chain.push(self.config.max_scope_depth)?;

        let max_registers = self.config.max_registers as usize;
        let mut registers = vec![Value::Undefined; max_registers];
        let mut register_labels = vec![Label::Public; max_registers];
        // Only materialized parameters are written below. Starting at the
        // physical window's end would make every later park scan that whole
        // cleared tail even when the generator only uses a few registers.
        let register_dirty_end = arguments.len().min(max_registers);
        for (index, (value, label)) in arguments
            .into_iter()
            .zip(argument_labels)
            .enumerate()
            .take(max_registers)
        {
            registers[index] = value;
            register_labels[index] = label;
        }

        // A generator method's body reads `super` through its [[HomeObject]]
        // (LoadSuper takes the home object's prototype when the read runs).
        let (super_label, super_home_object) = match invocation
            .closure_index
            .and_then(|closure_id| self.closure_method_metadata.get(&closure_id))
        {
            Some(metadata) => (
                metadata.definition_label.clone(),
                Some(metadata.home_object),
            ),
            None => (Label::Public, None),
        };
        let mut execution = GeneratorExecutionSnapshot {
            registers,
            register_labels,
            register_len: max_registers,
            register_label_len: max_registers,
            register_dirty_end,
            registers_value_bytes: None,
            register_labels_bytes: None,
            delegation: None,
            active_inline_callback_context_label: invocation.inline_context_label,
            pc_label_stack: Vec::new(),
            call_stack: vec![CallFrame {
                return_ip: module.instructions.len(),
                return_reg: 0,
                register_base: 0,
                register_width: max_registers,
                function_index: Some(invocation.function_index),
                this_value: invocation.this_value,
                this_label: invocation.this_label,
                new_target_value: Value::Undefined,
                new_target_label: Label::Public,
                super_value: Value::Undefined,
                super_label,
                super_home_object,
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
                saved_scope_depth,
                saved_scope_chain: None,
                scope_inert_virtual_scope_bytes: 0,
                async_function_id: None,
                native_boundary: false,
            }],
            ip: func.entry as usize,
            register_base: 0,
            register_width: max_registers,
            catch_frames: Vec::new(),
            pending_exception: None,
            pending_exception_label: Label::Public,
            pending_hostcall_result_label: None,
            pending_return: None,
            suspended_abrupt_completions: Vec::new(),
            finally_frames: Vec::new(),
            pending_finally_entry: None,
            scope_chain,
            pending_captures: Vec::new(),
            current_module_specifier: invocation.module_specifier,
            active_generated_function_artifact: invocation.generated_function_artifact,
            contained_codegen_grant,
        };
        execution.trim_cleared_register_tail();
        self.check_temporary_memory_budget(Self::estimate_generator_execution_bytes(&execution))?;
        if let Some((object, label)) = arguments_object {
            self.pending_arguments_object = Some((1, Value::Object(object), label));
        }
        Ok(execution)
    }

    pub(super) fn take_generator_execution(&mut self) -> GeneratorExecutionSnapshot {
        self.before_seed_surface_write();
        let register_len = self.registers.len();
        let register_label_len = self.register_labels.len();
        // The snapshot takes the files' live prefix (the trim of
        // bd-9vouw.167) by moving each value out, which leaves the core's
        // files cleared throughout: they become the spare the next install
        // refills, instead of being truncated, reallocated and padded back
        // to full windows on every step (bd-9vouw.500).
        let live = live_register_prefix_len(
            &self.registers,
            &self.register_labels,
            self.register_dirty_end,
        );
        let registers: Vec<Value> = self.registers.value[..live.min(register_len)]
            .iter_mut()
            .map(|value| std::mem::replace(value, Value::Undefined))
            .collect();
        let register_labels: Vec<Label> = if self.all_register_labels_public {
            vec![Label::Public; live.min(register_label_len)]
        } else {
            self.register_labels[..live.min(register_label_len)]
                .iter_mut()
                .map(|label| std::mem::replace(label, Label::Public))
                .collect()
        };
        let registers_value_bytes = self.registers_value_bytes.replace(Some(0));
        let register_labels_bytes = self.register_labels_bytes.replace(Some(0));
        let cleared_registers = std::mem::take(&mut self.registers.value);
        let cleared_labels = std::mem::take(&mut self.register_labels);
        self.all_register_labels_public = true;
        self.keep_spare_register_files(cleared_registers, cleared_labels);
        GeneratorExecutionSnapshot {
            register_len,
            register_label_len,
            // The core's files are empty now, so nothing past 0 is dirty.
            register_dirty_end: std::mem::take(&mut self.register_dirty_end),
            registers_value_bytes,
            register_labels_bytes,
            registers,
            register_labels,
            delegation: self.generator_delegation.take(),
            active_inline_callback_context_label: self.active_inline_callback_context_label.take(),
            pc_label_stack: std::mem::take(&mut self.pc_label_stack),
            call_stack: self.call_stack.take(&mut self.closures.cold_cells),
            ip: std::mem::take(&mut self.ip),
            register_base: std::mem::take(&mut self.register_base),
            register_width: std::mem::replace(
                &mut self.register_width,
                self.config.max_registers as usize,
            ),
            catch_frames: std::mem::take(&mut self.catch_frames),
            pending_exception: self.pending_exception.take(),
            pending_exception_label: std::mem::replace(
                &mut self.pending_exception_label,
                Label::Public,
            ),
            pending_hostcall_result_label: self.pending_hostcall_result_label.take(),
            pending_return: self.pending_return.take(),
            suspended_abrupt_completions: std::mem::take(&mut self.suspended_abrupt_completions),
            finally_frames: std::mem::take(&mut self.finally_frames),
            pending_finally_entry: self.pending_finally_entry.take(),
            scope_chain: std::mem::replace(&mut self.scope_chain, ScopeChain::new()),
            pending_captures: std::mem::take(&mut self.pending_captures),
            current_module_specifier: self.current_module_specifier.take(),
            active_generated_function_artifact: self.active_generated_function_artifact.take(),
            contained_codegen_grant: None,
        }
    }

    /// Keep `registers` and `labels`, every slot cleared, as spare files
    /// (`spare_register_files`) unless they are longer than the cap; the
    /// oldest spare goes once there are more than SPARE_REGISTER_FILES.
    pub(super) fn keep_spare_register_files(&mut self, registers: Vec<Value>, labels: Vec<Label>) {
        let cap = SPARE_REGISTER_FILE_WINDOWS.saturating_mul(self.config.max_registers as usize);
        if registers.len() <= cap && labels.len() <= cap {
            debug_assert_eq!(
                live_register_prefix_len_by_walk(&registers, &labels),
                0,
                "a spare register file holds a value or a label (bd-9vouw.500)"
            );
            self.spare_register_files.push((registers, labels));
            if self.spare_register_files.len() > SPARE_REGISTER_FILES {
                self.spare_register_files.remove(0);
            }
        }
    }

    /// The spare files to refill into a file of `len` values: those of that
    /// length if any, else new empty ones. A spare of another length stays:
    /// a step takes one file and installs one, so a spare handed out for
    /// the wrong length was cut or regrown on every install, and the pool
    /// never held one of each length (bd-9vouw.500).
    pub(super) fn take_spare_register_files(&mut self, len: usize) -> (Vec<Value>, Vec<Label>) {
        self.spare_register_files
            .iter()
            .position(|(registers, _)| registers.len() == len)
            .map_or_else(Default::default, |index| {
                self.spare_register_files.remove(index)
            })
    }

    pub(super) fn async_function_ids_in_call_stack(
        call_stack: &[CallFrame],
        minimum_index: usize,
    ) -> Vec<u32> {
        let mut ids = Vec::new();
        for async_id in call_stack
            .iter()
            .filter_map(|frame| frame.async_function_id)
        {
            if async_id as usize >= minimum_index && !ids.contains(&async_id) {
                ids.push(async_id);
            }
        }
        ids
    }

    pub(super) fn extend_unique_async_function_ids(
        ids: &mut Vec<u32>,
        additional_ids: impl IntoIterator<Item = u32>,
    ) {
        for async_id in additional_ids {
            if !ids.contains(&async_id) {
                ids.push(async_id);
            }
        }
    }

    pub(super) fn async_function_ids_created_since(&self, minimum_index: usize) -> Vec<u32> {
        (minimum_index..self.async_functions.len())
            .map(|index| {
                u32::try_from(index)
                    .expect("async function table capacity is checked before every insertion")
            })
            .collect()
    }

    pub(super) fn suspended_async_function_id_in_call_stack(
        &self,
        call_stack: &[CallFrame],
        minimum_index: usize,
    ) -> Option<u32> {
        call_stack
            .iter()
            .rev()
            .filter_map(|frame| frame.async_function_id)
            .find(|async_id| {
                *async_id as usize >= minimum_index
                    && self
                        .async_functions
                        .get(*async_id as usize)
                        .is_some_and(|function| {
                            function.phase == AsyncFunctionPhase::SuspendedAwait
                                && function.isolated_execution.is_none()
                        })
            })
    }

    pub(super) fn discard_abandoned_async_call_stack(&mut self, async_ids: &[u32]) {
        let Some(first_async_frame_index) = self.call_stack.iter().position(|frame| {
            frame
                .async_function_id
                .is_some_and(|async_id| async_ids.contains(&async_id))
        }) else {
            return;
        };
        let return_ip = self.call_stack[first_async_frame_index].return_ip;
        let _ = self.unwind_call_stack_to(first_async_frame_index);
        self.catch_frames
            .retain(|frame| frame.call_depth <= first_async_frame_index);
        self.clear_pending_abrupt_slots();
        self.clear_suspended_abrupt_completions();
        self.clear_finally_frames();
        self.pending_finally_entry = None;
        self.ip = return_ip;
        self.estimated_memory_bytes = self.recompute_base_estimated_memory_bytes();
    }

    /// Preserve the raw IFC level in an allocation-free terminal carrier. The
    /// tombstone cannot re-enter join/name-sensitive execution: the same fatal
    /// repair removes its reaction jobs, await contexts, and combinator owners.
    /// This keeps `can_flow_to` confidentiality intact even when the original
    /// Custom name is attacker-sized or its exact clone cannot fit the ceiling.
    pub(super) fn terminal_async_failure_label(label: &Label) -> Label {
        match label {
            Label::Public => Label::Public,
            Label::Internal => Label::Internal,
            Label::Confidential => Label::Confidential,
            Label::Secret => Label::Secret,
            Label::TopSecret => Label::TopSecret,
            Label::Custom { level, .. } => Label::Custom {
                name: String::new(),
                level: *level,
            },
        }
    }

    /// Close every Promise/await/combinator dependency made unreachable by an
    /// allocation-free terminal rejection. The epoch marker lives inline in
    /// Promise records, so each pass can prune owners without allocating a
    /// worklist after a resource failure.
    pub(super) fn close_terminal_async_promise_dependencies(
        &mut self,
        terminal_epoch: u64,
        label: &Label,
    ) {
        loop {
            let mut changed = false;

            {
                let promise_store = &mut self.promise_store;
                let async_functions = &mut self.async_functions;
                let closures = &mut self.closures;
                self.async_resumption_contexts
                    .retain(|result_promise, context| {
                        let result_promise = crate::promise_model::PromiseHandle(*result_promise);
                        if !promise_store
                            .was_terminally_rejected_in_epoch(result_promise, terminal_epoch)
                        {
                            return true;
                        }
                        if let Some(async_function) =
                            async_functions.get_mut(context.async_function_id as usize)
                        {
                            async_function.phase = AsyncFunctionPhase::Completed;
                            closures
                                .replace_activation(&mut async_function.isolated_execution, None);
                            async_function.saved_registers = Vec::new();
                            async_function.saved_register_labels = Vec::new();
                            let published_promise =
                                crate::promise_model::PromiseHandle(async_function.result_promise);
                            let _ = promise_store.extend_terminal_rejection_without_jobs(
                                published_promise,
                                label,
                                terminal_epoch,
                            );
                        }
                        changed = true;
                        false
                    });
            }

            {
                let promise_store = &self.promise_store;
                self.top_level_await_resumption_contexts
                    .retain(|result_promise, _| {
                        let retain = !promise_store.was_terminally_rejected_in_epoch(
                            crate::promise_model::PromiseHandle(*result_promise),
                            terminal_epoch,
                        );
                        changed |= !retain;
                        retain
                    });
            }

            {
                let promise_store = &mut self.promise_store;
                let combinators = &mut self.promise_combinators;
                for (input_promise, entries) in &self.promise_combinator_watchers {
                    if !promise_store
                        .was_terminally_rejected_in_epoch(*input_promise, terminal_epoch)
                    {
                        continue;
                    }
                    for entry in entries {
                        let Some(state) = combinators.remove(&entry.combinator_id) else {
                            continue;
                        };
                        let result_promise = match &state {
                            PromiseCombinatorState::All(tracker) => tracker.result_promise,
                            PromiseCombinatorState::AllSettled(tracker) => tracker.result_promise,
                            PromiseCombinatorState::Race(tracker) => tracker.result_promise,
                            PromiseCombinatorState::Any(tracker) => tracker.result_promise,
                        };
                        let _ = promise_store.extend_terminal_rejection_without_jobs(
                            result_promise,
                            label,
                            terminal_epoch,
                        );
                        changed = true;
                    }
                }
            }

            {
                let combinators = &self.promise_combinators;
                self.promise_combinator_watchers.retain(|_, entries| {
                    entries.retain(|entry| combinators.contains_key(&entry.combinator_id));
                    !entries.is_empty()
                });
            }

            // Native element reactions carry a direct PromiseStore edge to
            // their aggregate. The terminal walk may therefore have rejected
            // that result without traversing a legacy watcher entry (including
            // results whose inputs already queued their jobs).
            {
                let store = &self.promise_store;
                self.promise_combinators.retain(|_, state| {
                    let keep = !store
                        .was_terminally_rejected_in_epoch(state.result_promise(), terminal_epoch);
                    changed |= !keep;
                    keep
                });
            }

            // Every changing round removes at least one await context or
            // combinator owner. Watchers are scanned once per round, so this
            // allocation-free fixed point has a finite owner-removal bound.
            if !changed {
                break;
            }
        }
        // Bulk removals above: recount the running totals once.
        self.resync_promise_combinator_bytes();
    }

    /// Fail closed when an isolated owner-module activation cannot continue.
    /// Every active async boundary can have published its own Promise before
    /// the resource fault, so terminally reject all of them and remove their
    /// now-unreachable await contexts.
    pub(super) fn terminally_reject_abandoned_async_functions(
        &mut self,
        async_ids: &[u32],
        label: Label,
    ) {
        self.async_resumption_contexts
            .retain(|_, context| !async_ids.contains(&context.async_function_id));

        let mut terminal_epoch = None;
        for async_id in async_ids.iter().rev().copied() {
            let Some(async_function) = self.async_functions.get_mut(async_id as usize) else {
                continue;
            };
            let result_promise = crate::promise_model::PromiseHandle(async_function.result_promise);
            let promise_is_pending = self
                .promise_store
                .get(result_promise)
                .is_ok_and(|record| record.state == crate::promise_model::PromiseState::Pending);
            if async_function.phase == AsyncFunctionPhase::Completed && !promise_is_pending {
                continue;
            }
            async_function.phase = AsyncFunctionPhase::Completed;
            self.closures
                .replace_activation(&mut async_function.isolated_execution, None);
            async_function.saved_registers = Vec::new();
            async_function.saved_register_labels = Vec::new();

            // Reconcile after releasing the activation before asking the
            // ordinary Promise path to admit the bounded terminal record.
            self.estimated_memory_bytes = self.recompute_base_estimated_memory_bytes();
            if promise_is_pending
                && self
                    .reject_promise(
                        result_promise,
                        crate::object_model::JsValue::Undefined,
                        label.clone(),
                    )
                    .is_err()
                && self
                    .promise_store
                    .get(result_promise)
                    .is_ok_and(|record| record.state == crate::promise_model::PromiseState::Pending)
            {
                // A resource fault can leave no headroom for even one witness
                // or reaction job. The Promise store's emergency transition is
                // allocation-free, closes the `.then` descendant graph, and
                // leaves unrelated event-loop work untouched.
                let result = match terminal_epoch {
                    Some(epoch) => self.promise_store.extend_terminal_rejection_without_jobs(
                        result_promise,
                        &label,
                        epoch,
                    ),
                    None => self
                        .promise_store
                        .terminally_reject_without_jobs(result_promise, &label)
                        .map(|epoch| {
                            terminal_epoch = Some(epoch);
                            1
                        }),
                };
                let _ = result;
            }
        }
        if let Some(epoch) = terminal_epoch {
            self.close_terminal_async_promise_dependencies(epoch, &label);
        }
        self.estimated_memory_bytes = self.recompute_base_estimated_memory_bytes();
        debug_assert!(
            self.estimated_memory_bytes() <= self.config.max_total_memory_bytes,
            "fatal async repair must not exceed its configured memory ceiling"
        );
    }

    /// Retain the complete owner-module wrapper activation for a foreign async
    /// call that stopped at a pending `await`. The published Promise belongs to
    /// the outer imported call in absolute wrapper register zero, while a
    /// nested async function may own the suspended activation.
    pub(super) fn retain_isolated_async_execution(
        &mut self,
        published_async_index: usize,
        contained_codegen_grant: Option<ContainedCodegenGrant>,
    ) -> Result<Option<(u32, Label, u32)>, InterpreterError> {
        let published_promise = self
            .async_functions
            .get(published_async_index)
            .ok_or_else(|| InterpreterError::InternalError {
                details: format!(
                    "foreign async call did not create object at index {published_async_index}"
                ),
            })?
            .result_promise;
        let Some(suspended_async_id) =
            self.suspended_async_function_id_in_call_stack(&self.call_stack, published_async_index)
        else {
            return Ok(None);
        };
        match self.registers.first() {
            Some(Value::Promise(handle)) if *handle == published_promise => {}
            other => {
                return Err(InterpreterError::InternalError {
                    details: format!(
                        "foreign async wrapper lost published Promise {published_promise} in register zero: {other:?}"
                    ),
                });
            }
        }

        let mut execution = self.take_generator_execution();
        execution.contained_codegen_grant = contained_codegen_grant;
        // The synthetic caller's destination is absolute register zero. Move
        // its label out instead of cloning an attacker-sized Custom label; the
        // resumed wrapper's Return value is internal and discarded.
        let result_label = execution
            .register_labels
            .first_mut()
            .map(|label| std::mem::replace(label, Label::Public))
            .unwrap_or(Label::Public);
        let moved_label_bytes = Self::estimate_label_bytes(&result_label);
        execution.register_labels_bytes = execution
            .register_labels_bytes
            .map(|bytes| bytes.saturating_sub(moved_label_bytes));
        self.closures.replace_activation(
            &mut self.async_functions[suspended_async_id as usize].isolated_execution,
            Some(execution),
        );
        Ok(Some((published_promise, result_label, suspended_async_id)))
    }

    /// Memory components a generator activation transfer moves between the
    /// live execution state, the generator's suspended slot and the
    /// temporarily suspended caller (bd-j9r60): registers and their labels,
    /// the scope chain, the call stack with its abrupt-completion slots, the
    /// yield* delegation, the one generator object and
    /// `temporarily_suspended_execution_bytes`. Every other component is
    /// untouched by the transfer, so bracketing it with this sum replaces a
    /// whole-state re-derivation, which walks every heap object and made
    /// each resume O(iterations so far).
    pub(super) fn generator_transfer_memory_bytes(&self, generator_index: usize) -> u64 {
        self.activation_transfer_memory_bytes().saturating_add(
            self.generators
                .get(generator_index)
                .map_or(0, Self::estimate_generator_bytes),
        )
    }

    /// The live-execution side of an activation transfer (see
    /// [`Self::generator_transfer_memory_bytes`]), shared by generator and
    /// isolated async resumptions.
    pub(super) fn activation_transfer_memory_bytes(&self) -> u64 {
        self.registers_memory_bytes()
            .saturating_add(self.register_context_labels_memory_bytes())
            .saturating_add(self.scope_chain_memory_bytes())
            .saturating_add(self.call_stack_memory_bytes())
            .saturating_add(self.generator_delegation_memory_bytes())
            .saturating_add(self.temporarily_suspended_execution_bytes)
    }

    pub(super) fn async_function_memory_bytes_at(&self, async_function_id: u32) -> u64 {
        self.async_functions
            .get(async_function_id as usize)
            .map_or(0, Self::estimate_async_function_bytes)
    }

    /// Unit-test oracle for a transfer bracket: the incremental estimate's
    /// distance from the full walk must be the same after the bracket as
    /// before it, i.e. the bracket itself introduced no drift (bd-j9r60).
    #[cfg(test)]
    pub(super) fn memory_walk_drift(&self) -> i128 {
        i128::from(self.estimated_memory_bytes)
            - i128::from(self.recompute_base_estimated_memory_bytes_by_walk())
    }

    pub(super) fn apply_generator_transfer_delta(
        &mut self,
        generator_index: usize,
        previous_transfer_bytes: u64,
    ) -> Result<u64, InterpreterError> {
        self.apply_memory_component_delta(
            previous_transfer_bytes,
            self.generator_transfer_memory_bytes(generator_index),
        )
    }

    pub(super) fn install_generator_execution(&mut self, execution: GeneratorExecutionSnapshot) {
        self.before_seed_surface_write();
        // The spare files are cleared throughout, so only the parked prefix
        // and any difference in length are written (bd-9vouw.500).
        let (mut registers, mut register_labels) =
            self.take_spare_register_files(execution.register_len);
        refill_cleared_file(
            &mut registers,
            execution.registers,
            execution.register_len,
            Value::Undefined,
        );
        refill_cleared_file(
            &mut register_labels,
            execution.register_labels,
            execution.register_label_len,
            Label::Public,
        );
        self.registers.value = registers;
        self.registers_value_bytes
            .set(execution.registers_value_bytes);
        self.install_register_labels(register_labels, execution.register_labels_bytes);
        self.register_dirty_end = execution.register_dirty_end;
        self.generator_delegation = execution.delegation;
        self.active_inline_callback_context_label = execution.active_inline_callback_context_label;
        self.pc_label_stack = execution.pc_label_stack;
        self.call_stack
            .replace(execution.call_stack, &mut self.closures.cold_cells);
        self.ip = execution.ip;
        self.register_base = execution.register_base;
        self.register_width = execution.register_width;
        self.catch_frames = execution.catch_frames;
        self.pending_exception = execution.pending_exception;
        self.pending_exception_label = execution.pending_exception_label;
        self.pending_hostcall_result_label = execution.pending_hostcall_result_label;
        self.pending_return = execution.pending_return;
        self.suspended_abrupt_completions = execution.suspended_abrupt_completions;
        self.finally_frames = execution.finally_frames;
        self.pending_finally_entry = execution.pending_finally_entry;
        self.scope_chain = execution.scope_chain;
        self.pending_captures = execution.pending_captures;
        self.current_module_specifier = execution.current_module_specifier;
        self.active_generated_function_artifact = execution.active_generated_function_artifact;
    }

    /// Inject a return through the same finally stack for direct `.return()`
    /// and a completed yield* return request.
    pub(super) fn inject_generator_return(
        &mut self,
        completion: LabeledReturn,
    ) -> Result<Option<LabeledReturn>, InterpreterError> {
        self.pending_finally_entry = None;
        self.suspend_current_abrupt_completion()?;
        self.replace_pending_abrupt_slots(None, Some(completion))?;
        if let Some(target) = self.pop_current_finally_target() {
            self.pending_finally_entry = Some(PendingFinallyEntry {
                target,
                mode: FinallyMode::Return,
            });
            self.ip = target;
            Ok(None)
        } else {
            let completion = self
                .take_pending_return_slot()
                .expect("injected return remains pending");
            // A generator frame is never a constructor entered by super().
            self.complete_return(None, completion.value, completion.label)
        }
    }

    pub(super) fn replace_generator_delegation(
        &mut self,
        delegation: GeneratorDelegation,
    ) -> Result<(), InterpreterError> {
        self.apply_memory_component_delta(
            self.generator_delegation_memory_bytes(),
            Self::estimate_generator_delegation_bytes(&delegation),
        )?;
        self.generator_delegation = Some(delegation);
        Ok(())
    }

    pub(super) fn take_generator_delegation(&mut self) -> Option<GeneratorDelegation> {
        let delegation = self.generator_delegation.take()?;
        self.estimated_memory_bytes = self
            .estimated_memory_bytes
            .saturating_sub(Self::estimate_generator_delegation_bytes(&delegation));
        Some(delegation)
    }

    /// ES2020 YieldExpression evaluation for a synchronous yield*. In
    /// particular, non-done results are yielded *as objects*: reading their
    /// value here would invoke a getter too early and lose result identity.
    pub(super) fn step_generator_delegation(
        &mut self,
        module: &Ir3Module,
        source_reg: u32,
        resume_dst: u32,
    ) -> Result<GeneratorDelegationStep, InterpreterError> {
        if self.generator_delegation.is_none() {
            let source = self.read_reg(source_reg)?;
            let label = self.unary_operation_label(source_reg)?;
            self.replace_pending_hostcall_result_label(Some(label.clone()))?;
            let init = self.prepare_for_of_state(Some(module), &source)?;
            let iterator =
                self.init_iterator_from_state(source, init, IterationKind::YieldDelegate)?;
            let label = label.join(
                &self
                    .take_pending_hostcall_result_label()
                    .unwrap_or(Label::Public),
            );
            self.replace_generator_delegation(GeneratorDelegation {
                iterator: self.expect_iterator_handle(iterator)?,
                label,
                resume_kind: GeneratorResumeKind::Next,
                started: false,
            })?;
        }

        self.check_temporary_memory_budget(self.generator_delegation_memory_bytes())?;
        let delegation = self
            .generator_delegation
            .as_ref()
            .expect("delegation initialized");
        let (handle, kind, started, mut label) = (
            delegation.iterator,
            delegation.resume_kind,
            delegation.started,
            delegation.label.clone(),
        );
        let argument = if started {
            label = label.join(&self.unary_operation_label(resume_dst)?);
            self.read_reg(resume_dst)?
        } else {
            // The first next sent to the delegate has exactly one argument,
            // undefined, irrespective of the outer generator's first next.
            Value::Undefined
        };
        self.replace_generator_delegation(GeneratorDelegation {
            iterator: handle,
            label: label.clone(),
            resume_kind: kind,
            started,
        })?;
        self.replace_pending_hostcall_result_label(Some(label.clone()))?;

        let (receiver, cached_next, trace_index) = match self.iterator_state_mut(handle)? {
            RuntimeIteratorState::ForOf(state) => (
                state.iterator_receiver.clone(),
                state.next_method.clone(),
                state.trace_index,
            ),
            RuntimeIteratorState::ForIn(_) => {
                return Err(InterpreterError::InternalError {
                    details: "yield* retained a for-in iterator".to_string(),
                });
            }
        };
        let native_next = receiver.is_none() && kind == GeneratorResumeKind::Next;
        let method = if kind == GeneratorResumeKind::Next {
            cached_next
        } else {
            match &receiver {
                Some(Value::Generator(_)) => Some(Value::BuiltinFunction(
                    BuiltinFunction::new_kind(if kind == GeneratorResumeKind::Return {
                        BuiltinFunctionKind::GeneratorReturn
                    } else {
                        BuiltinFunctionKind::GeneratorThrow
                    }),
                )),
                Some(Value::Iterator(_)) | None => None,
                Some(receiver) => {
                    match self.iterator_carrier_backing_id(receiver, "iterator receiver")? {
                        Some(object_id) => self.optional_callable_property(
                            Some(module),
                            object_id,
                            if kind == GeneratorResumeKind::Return {
                                "return"
                            } else {
                                "throw"
                            },
                            receiver.clone(),
                        )?,
                        None => None,
                    }
                }
            }
        };

        if kind != GeneratorResumeKind::Next && method.is_none() {
            if kind == GeneratorResumeKind::Throw {
                // This close has a NORMAL completion. Any return getter/call
                // failure replaces the missing-throw TypeError; the original
                // argument is not an outer pending exception yet.
                self.close_iterator(module, Value::Iterator(handle), IteratorCloseReason::Throw)?;
                return Err(InterpreterError::TypeError {
                    expected: "callable iterator.throw method for yield*".to_string(),
                    got: "null or undefined iterator.throw".to_string(),
                });
            }
            label = label.join(
                self.pending_hostcall_result_label
                    .as_ref()
                    .unwrap_or(&Label::Public),
            );
            if let RuntimeIteratorState::ForOf(state) = self.iterator_state_mut(handle)? {
                state.done = true;
            }
            self.record_iterator_close_event(
                trace_index,
                CloseReason::Return,
                false,
                IterationCompletion::Normal,
            );
            return Ok(GeneratorDelegationStep::Return(LabeledReturn {
                value: argument,
                label,
            }));
        }

        let result = if native_next {
            let value = self.advance_for_of_iterator(Some(module), Value::Iterator(handle))?;
            let done = value.is_none();
            self.generator_result_object(value.unwrap_or(Value::Undefined), done)?
        } else {
            let lookup_label = label.join(
                self.pending_hostcall_result_label
                    .as_ref()
                    .unwrap_or(&Label::Public),
            );
            let (result, callback_label) = self.invoke_inline_method_call_with_argument_label(
                Some(module),
                method.unwrap_or(Value::Undefined),
                receiver.unwrap_or(Value::Undefined),
                vec![argument],
                Some(lookup_label.clone()),
            )?;
            label = lookup_label.join(&callback_label);
            self.replace_pending_hostcall_result_label(Some(label.clone()))?;
            result
        };
        let done = self.iterator_result_done(module, &result)?;
        if !native_next {
            if kind == GeneratorResumeKind::Next {
                // No IteratorValue observation on a non-done delegated
                // result: the recipient, not yield*, performs that Get.
                self.record_iteration_next_result_impl(
                    trace_index,
                    (!done).then_some(Value::Undefined),
                    false,
                    false,
                );
            } else {
                self.record_iteration_event(trace_index, |record_id, step_index| IterationEvent {
                    record_id,
                    step_index,
                    operation: IterationOperation::IteratorComplete { done },
                    completion: IterationCompletion::Normal,
                });
                if let Some(trace) = self.iteration_traces.get_mut(trace_index) {
                    trace.completed = done;
                    if !done {
                        trace.values_produced = trace.values_produced.saturating_add(1);
                    }
                }
            }
        }
        if done {
            let value = self.iterator_result_value(module, &result)?;
            label = label.join(
                &self
                    .take_pending_hostcall_result_label()
                    .unwrap_or(Label::Public),
            );
            if let RuntimeIteratorState::ForOf(state) = self.iterator_state_mut(handle)? {
                state.done = true;
            }
            if self.iteration_traced(trace_index) {
                let observed = self.iterator_value_from_runtime(&value);
                self.record_iteration_event(trace_index, |record_id, step_index| IterationEvent {
                    record_id,
                    step_index,
                    operation: IterationOperation::IteratorValue { value: observed },
                    completion: IterationCompletion::Normal,
                });
            }
            let completion = LabeledReturn { value, label };
            return Ok(if kind == GeneratorResumeKind::Return {
                GeneratorDelegationStep::Return(completion)
            } else {
                GeneratorDelegationStep::Complete(completion)
            });
        }

        label = label.join(
            &self
                .take_pending_hostcall_result_label()
                .unwrap_or(Label::Public),
        );
        self.replace_generator_delegation(GeneratorDelegation {
            iterator: handle,
            label: label.clone(),
            resume_kind: GeneratorResumeKind::Next,
            started: true,
        })?;
        Ok(GeneratorDelegationStep::Yield(LabeledReturn {
            value: result,
            label,
        }))
    }

    /// Step a generator by swapping its complete isolated activation into the
    /// interpreter. Returns the `{value, done}` object and the exact label of
    /// the yielded/returned value that the object carries.
    pub(super) fn generator_next(
        &mut self,
        module: &Ir3Module,
        gen_id: u32,
        argument: Value,
        argument_label: Label,
    ) -> Result<(Value, Label), InterpreterError> {
        self.generator_resume(
            module,
            gen_id,
            GeneratorResumeKind::Next,
            argument,
            argument_label,
        )
    }

    /// bd-9vouw.49: run a generator a call just created through its
    /// parameter prologue, up to the `generator:prologue` marker the lowering
    /// places after it. FunctionDeclarationInstantiation precedes
    /// GeneratorStart (ES2020 14.4.10), so a throwing parameter initializer or
    /// destructuring pattern throws from the call, not from the first
    /// `next()`. Modules lowered without the marker keep the lazy start.
    pub(super) fn start_generator_through_prologue(
        &mut self,
        module: &Ir3Module,
        gen_id: u32,
    ) -> Result<(), InterpreterError> {
        // The marker is in the module that lowered the generator function,
        // which is where the generator runs (a required module's generator
        // called from the main module, a `new Function` body).
        let lowered_with_marker = self
            .generators
            .get(gen_id as usize)
            .is_some_and(|generator| {
                generator
                    .owner_module
                    .required_capabilities
                    .iter()
                    .any(|capability| {
                        capability.0 == crate::capability::GENERATOR_PROLOGUE_CAPABILITY
                    })
            });
        if !lowered_with_marker {
            return Ok(());
        }
        let previous = self.generator_prologue_pending.replace(gen_id);
        let outcome = self.generator_resume(
            module,
            gen_id,
            GeneratorResumeKind::Next,
            Value::Undefined,
            Label::Public,
        );
        self.generator_prologue_pending = previous;
        outcome.map(|_| ())
    }

    pub(super) fn generator_resume_with_async(
        &mut self,
        module: &Ir3Module,
        gen_id: u32,
        resume_kind: GeneratorResumeKind,
        argument: Value,
        argument_label: Label,
        async_generator: Option<u32>,
    ) -> Result<(Value, Label), InterpreterError> {
        let generator_index = gen_id as usize;
        let owner_module = Arc::clone(
            &self
                .generators
                .get(generator_index)
                .ok_or_else(|| InterpreterError::TypeError {
                    expected: "valid generator".into(),
                    got: format!("generator#{gen_id} not found"),
                })?
                .owner_module,
        );
        let owner_is_foreign = owner_module.header.source_label != module.header.source_label;
        let phase = self
            .generators
            .get(generator_index)
            .ok_or_else(|| InterpreterError::TypeError {
                expected: "valid generator".into(),
                got: format!("generator#{gen_id} not found"),
            })?
            .phase
            .clone();

        if phase == GeneratorPhase::Executing {
            return Err(InterpreterError::TypeError {
                expected: "suspended generator".into(),
                got: "generator already executing".into(),
            });
        }
        if phase == GeneratorPhase::Completed
            || (phase == GeneratorPhase::SuspendedStart && resume_kind != GeneratorResumeKind::Next)
        {
            // Abrupt resumption before the first yield does not enter the body
            // or its finally blocks. A completed generator retains no frame.
            let outcome = match resume_kind {
                GeneratorResumeKind::Next => Ok((
                    self.generator_result_object(Value::Undefined, true)?,
                    Label::Public,
                )),
                GeneratorResumeKind::Return => Ok((
                    self.generator_result_object_labeled(argument, &argument_label, true)?,
                    argument_label,
                )),
                GeneratorResumeKind::Throw => {
                    let description = self.uncaught_exception_description(&argument);
                    self.suspend_current_abrupt_completion()?;
                    self.replace_pending_abrupt_slots(Some((argument, argument_label)), None)?;
                    Err(InterpreterError::UncaughtException { value: description })
                }
            };
            let generator = &mut self.generators[generator_index];
            generator.phase = GeneratorPhase::Completed;
            generator.invocation = None;
            self.closures
                .replace_activation(&mut generator.execution, None);
            generator.resume_dst = None;
            self.sync_estimated_memory_bytes()?;
            return outcome;
        }
        let mut resume_completion = Some(LabeledReturn {
            value: argument,
            label: argument_label,
        });

        let caller_depth = self.effective_call_depth();
        if caller_depth >= self.config.max_call_depth {
            return Err(InterpreterError::StackOverflow {
                depth: caller_depth,
                max: self.config.max_call_depth,
            });
        }

        let mut start_heap_checkpoint = None;
        // bd-j9r60: the setup transfer below is accounted as one delta.
        let setup_transfer_bytes = self.generator_transfer_memory_bytes(generator_index);
        #[cfg(test)]
        let setup_drift = self.memory_walk_drift();
        let (activation, resume_dst) = if phase == GeneratorPhase::SuspendedStart {
            let invocation = self.generators[generator_index]
                .invocation
                .as_ref()
                .ok_or_else(|| InterpreterError::InternalError {
                    details: format!("generator#{gen_id} lost its invocation state"),
                })?;
            self.check_temporary_memory_budget(Self::estimate_generator_invocation_bytes(
                invocation,
            ))?;
            let previous_heap_len = self.heap.len();
            let previous_estimated_bytes = self.estimated_memory_bytes;
            start_heap_checkpoint = Some(previous_heap_len);
            let activation =
                match self.prepare_generator_execution(owner_module.as_ref(), invocation.clone()) {
                    Ok(activation) => activation,
                    Err(error) => {
                        self.rollback_heap_to_len(previous_heap_len);
                        self.estimated_memory_bytes = previous_estimated_bytes;
                        return Err(error);
                    }
                };
            (activation, None)
        } else {
            let generator = &mut self.generators[generator_index];
            let activation = self
                .closures
                .replace_activation(&mut generator.execution, None)
                .ok_or_else(|| InterpreterError::InternalError {
                    details: format!("generator#{gen_id} lost its suspended activation"),
                })?;
            (activation, generator.resume_dst.take())
        };
        if activation.registers.len() != activation.register_labels.len() {
            let value_count = activation.registers.len();
            let label_count = activation.register_labels.len();
            if phase == GeneratorPhase::SuspendedYield {
                let generator = &mut self.generators[generator_index];
                self.closures
                    .replace_activation(&mut generator.execution, Some(activation));
                generator.resume_dst = resume_dst;
            }
            return Err(InterpreterError::InternalError {
                details: format!(
                    "generator#{gen_id} value/label snapshot mismatch: values={}, labels={}",
                    value_count, label_count
                ),
            });
        }
        let contained_codegen_grant = activation.contained_codegen_grant;

        {
            let generator = &mut self.generators[generator_index];
            generator.phase = GeneratorPhase::Executing;
        }

        let caller_async_generator =
            std::mem::replace(&mut self.async_generator_runtime.active, async_generator);
        let caller_generator_yielded = std::mem::replace(&mut self.generator_yielded, false);
        let caller_generator_resume_dst = self.generator_resume_dst.take();
        let caller_generator_result_label =
            std::mem::replace(&mut self.generator_result_label, Label::Public);
        let prologue_start = self.generator_prologue_pending.take() == Some(gen_id);
        let caller_suspend_at_prologue =
            std::mem::replace(&mut self.suspend_at_generator_prologue, prologue_start);
        let caller_execution = self.take_generator_execution();
        let previous_granted_capabilities =
            self.replace_with_contained_codegen_grant(contained_codegen_grant);
        let caller_execution_bytes = Self::estimate_generator_execution_bytes(&caller_execution);
        let previous_suspended_bytes = self.temporarily_suspended_execution_bytes;
        let previous_reentrant_depth = self.module_reentrant_call_depth;
        self.temporarily_suspended_execution_bytes =
            previous_suspended_bytes.saturating_add(caller_execution_bytes);
        self.module_reentrant_call_depth =
            previous_reentrant_depth.saturating_add(caller_execution.call_stack.len());
        self.install_generator_execution(activation);

        let setup_result = (|| -> Result<(), InterpreterError> {
            self.apply_generator_transfer_delta(generator_index, setup_transfer_bytes)?;
            #[cfg(test)]
            debug_assert_eq!(
                self.memory_walk_drift(),
                setup_drift,
                "generator setup transfer drifted from the full walk (bd-j9r60)"
            );
            if phase == GeneratorPhase::SuspendedYield
                && (resume_kind == GeneratorResumeKind::Next || self.generator_delegation.is_some())
                && let Some(resume_dst) = resume_dst
            {
                let completion = resume_completion.take().expect("one generator resumption");
                self.write_reg_with_label(resume_dst, completion.value, completion.label)?;
                if let Some(delegation) = &mut self.generator_delegation {
                    delegation.resume_kind = resume_kind;
                }
            }
            Ok(())
        })();
        if let Err(error) = setup_result {
            let mut activation = self.take_generator_execution();
            activation.contained_codegen_grant = contained_codegen_grant;
            self.temporarily_suspended_execution_bytes = previous_suspended_bytes;
            self.module_reentrant_call_depth = previous_reentrant_depth;
            self.restore_replaced_codegen_grants(previous_granted_capabilities);
            self.install_generator_execution(caller_execution);
            self.generator_yielded = caller_generator_yielded;
            self.generator_resume_dst = caller_generator_resume_dst;
            self.generator_result_label = caller_generator_result_label;
            self.suspend_at_generator_prologue = caller_suspend_at_prologue;
            self.async_generator_runtime.active = caller_async_generator;
            let generator = &mut self.generators[generator_index];
            if phase == GeneratorPhase::SuspendedYield {
                self.closures
                    .replace_activation(&mut generator.execution, Some(activation));
                generator.resume_dst = resume_dst;
            }
            generator.phase = phase;
            if let Some(previous_heap_len) = start_heap_checkpoint {
                self.rollback_heap_to_len(previous_heap_len);
            }
            self.sync_estimated_memory_bytes()?;
            return Err(error);
        }
        if phase == GeneratorPhase::SuspendedStart {
            // The started activation now owns the arguments; release the
            // retained invocation as its own delta (bd-j9r60).
            #[cfg(test)]
            let start_drift = self.memory_walk_drift();
            let released_invocation_bytes = self.generators[generator_index]
                .invocation
                .take()
                .as_ref()
                .map_or(0, Self::estimate_generator_invocation_bytes);
            self.estimated_memory_bytes = self
                .estimated_memory_bytes
                .saturating_sub(released_invocation_bytes);
            #[cfg(test)]
            debug_assert_eq!(
                self.memory_walk_drift(),
                start_drift,
                "generator invocation release drifted from the full walk (bd-j9r60)"
            );
        }

        let previous_foreign_call_depth = self.active_foreign_module_call_depth;
        if owner_is_foreign {
            self.active_foreign_module_call_depth = previous_foreign_call_depth.saturating_add(1);
        }
        // Keep all fallible injection inside this closure: the caller's full
        // activation must be restored even if completion transport is refused.
        let result = (|| -> Result<LabeledReturn, InterpreterError> {
            // A suspended yield* receives abrupt completions before the outer
            // generator unwinds. Its delegate may handle throw or defer return.
            if self.generator_delegation.is_some() {
                return self.run_loop_labeled(owner_module.as_ref());
            }
            match resume_kind {
                GeneratorResumeKind::Next => {}
                GeneratorResumeKind::Return => {
                    let completion = resume_completion.take().expect("one generator return");
                    if let Some(completion) = self.inject_generator_return(completion)? {
                        return Ok(completion);
                    }
                }
                GeneratorResumeKind::Throw => {
                    let completion = resume_completion.take().expect("one generator throw");
                    self.pending_finally_entry = None;
                    self.suspend_current_abrupt_completion()?;
                    self.replace_pending_abrupt_slots(
                        Some((completion.value, completion.label)),
                        None,
                    )?;
                    if let Some(frame) = self.pop_exception_target_frame()? {
                        self.select_exception_target(Some(owner_module.as_ref()), frame);
                    } else {
                        return Err(InterpreterError::UncaughtException {
                            value: self.uncaught_exception_description(
                                self.pending_exception
                                    .as_ref()
                                    .expect("injected throw remains pending"),
                            ),
                        });
                    }
                }
            }
            self.run_loop_labeled(owner_module.as_ref())
        })();
        self.active_foreign_module_call_depth = previous_foreign_call_depth;
        // bd-j9r60: the completion transfer below is accounted as one delta
        // on the yield and return paths.
        let completion_transfer_bytes = self.generator_transfer_memory_bytes(generator_index);
        #[cfg(test)]
        let completion_drift = self.memory_walk_drift();
        let yielded = std::mem::replace(&mut self.generator_yielded, false);
        let yielded_resume_dst = self.generator_resume_dst.take();
        let yielded_label = std::mem::replace(&mut self.generator_result_label, Label::Public);
        let mut activation = self.take_generator_execution();
        activation.contained_codegen_grant = contained_codegen_grant;
        let escaped_exception =
            if matches!(&result, Err(InterpreterError::UncaughtException { .. })) {
                activation.pending_exception.take().map(|value| {
                    let label =
                        std::mem::replace(&mut activation.pending_exception_label, Label::Public);
                    (value, label)
                })
            } else {
                None
            };

        self.temporarily_suspended_execution_bytes = previous_suspended_bytes;
        self.module_reentrant_call_depth = previous_reentrant_depth;
        self.restore_replaced_codegen_grants(previous_granted_capabilities);
        self.install_generator_execution(caller_execution);
        self.generator_yielded = caller_generator_yielded;
        self.generator_resume_dst = caller_generator_resume_dst;
        self.generator_result_label = caller_generator_result_label;
        self.suspend_at_generator_prologue = caller_suspend_at_prologue;
        self.async_generator_runtime.active = caller_async_generator;

        match result {
            Ok(yielded_value) if yielded => {
                let generator = &mut self.generators[generator_index];
                self.closures
                    .replace_activation(&mut generator.execution, Some(activation));
                generator.resume_dst = yielded_resume_dst;
                generator.phase = GeneratorPhase::SuspendedYield;
                self.apply_generator_transfer_delta(generator_index, completion_transfer_bytes)?;
                #[cfg(test)]
                debug_assert_eq!(
                    self.memory_walk_drift(),
                    completion_drift,
                    "generator yield transfer drifted from the full walk (bd-j9r60)"
                );
                Ok((yielded_value.value, yielded_label))
            }
            Ok(return_value) => {
                let generator = &mut self.generators[generator_index];
                self.closures
                    .replace_activation(&mut generator.execution, None);
                generator.resume_dst = None;
                generator.phase = GeneratorPhase::Completed;
                self.apply_generator_transfer_delta(generator_index, completion_transfer_bytes)?;
                #[cfg(test)]
                debug_assert_eq!(
                    self.memory_walk_drift(),
                    completion_drift,
                    "generator return transfer drifted from the full walk (bd-j9r60)"
                );
                Ok((
                    self.generator_result_object_labeled(
                        return_value.value,
                        &return_value.label,
                        true,
                    )?,
                    return_value.label,
                ))
            }
            Err(InterpreterError::Halted) => {
                let generator = &mut self.generators[generator_index];
                self.closures
                    .replace_activation(&mut generator.execution, None);
                generator.resume_dst = None;
                generator.phase = GeneratorPhase::Completed;
                self.sync_estimated_memory_bytes()?;
                Ok((
                    self.generator_result_object(Value::Undefined, true)?,
                    Label::Public,
                ))
            }
            Err(error) => {
                let generator = &mut self.generators[generator_index];
                self.closures
                    .replace_activation(&mut generator.execution, None);
                generator.resume_dst = None;
                generator.phase = GeneratorPhase::Completed;
                if let Some((value, label)) = escaped_exception {
                    self.suspend_current_abrupt_completion()?;
                    self.replace_pending_abrupt_slots(Some((value, label)), None)?;
                }
                self.sync_estimated_memory_bytes()?;
                Err(error)
            }
        }
    }

    /// Is there a catch frame in the *current* run-loop invocation that can
    /// handle an exception raised at the current call depth? Recursive
    /// `run_loop` invocations (callbacks, `Reflect.construct`) clear and later
    /// restore `catch_frames`, so this only ever observes frames belonging to
    /// the active invocation — an enclosing try/catch in a caller is correctly
    /// invisible here and is reached by re-propagating the host error upward.
    pub(super) fn has_active_catch_frame(&self) -> bool {
        let depth = self.call_stack.len();
        let minimum_depth = self
            .nearest_async_call_depth()
            .unwrap_or(0)
            .max(self.native_boundary_depth());
        self.catch_frames
            .iter()
            .any(|frame| frame.call_depth >= minimum_depth && frame.call_depth <= depth)
    }

    /// Route an explicit `throw` that escaped an *isolated re-entrant run* into
    /// the caller's catch frames (bd-8enww.4.7).
    ///
    /// A `Function`-constructor-generated function
    /// ([`Self::call_generated_function_artifact`]) and an inline method/callback
    /// call ([`Self::invoke_inline_method_call`]) both execute the callee in a
    /// *cleared* catch-frame context, so an enclosing `try`/`catch` in the caller
    /// is invisible to the inner [`Self::run_loop`]. On an uncaught explicit
    /// `throw` those paths return [`InterpreterError::UncaughtException`] while
    /// preserving the thrown value+label in `pending_exception` (re-armed after
    /// the snapshot restore) precisely so the enclosing frame can re-raise it.
    ///
    /// This re-raises that preserved value into the caller's frames, mirroring
    /// the `Throw` instruction's unwinding exactly (and the `ForOfNext` iterator
    /// re-raise, bd-bg9l1.27.7). It deliberately fires only for
    /// `UncaughtException` paired with a preserved `pending_exception`: a *native*
    /// runtime fault is already routed by [`Self::run_loop`] (it stays a
    /// JS-catchable variant, e.g. `TypeError`), and a same-frame `throw` already
    /// consulted the catch stack before returning — so neither is disturbed.
    ///
    /// Returns `Ok(None)` when the throw was routed to a handler (or rejected
    /// into an async boundary): `ip` is positioned and the dispatch loop should
    /// `continue`. Returns `Ok(Some(err))` when the error is not a routable
    /// cross-boundary throw, or no eligible handler remained — the dispatch loop
    /// should propagate `err` unchanged (identical surfacing to today).
    pub(super) fn route_isolated_explicit_throw(
        &mut self,
        module: &Ir3Module,
        err: InterpreterError,
    ) -> Result<Option<InterpreterError>, InterpreterError> {
        if !matches!(err, InterpreterError::UncaughtException { .. }) {
            return Ok(Some(err));
        }
        let Some((thrown, thrown_label)) = self.take_pending_exception_slot() else {
            return Ok(Some(err));
        };
        // The isolated run already re-armed this exact exception after its
        // caller snapshot was restored. Move it back into the routing slot;
        // suspending it here would duplicate and later resurrect the same
        // completion after `EnterCatch` consumed it.
        self.pending_finally_entry = None;
        self.replace_pending_abrupt_slots(Some((thrown, thrown_label)), None)?;
        if let Some(frame) = self.pop_exception_target_frame()? {
            self.select_exception_target(Some(module), frame);
            Ok(None)
        } else if self.nearest_async_call_depth().is_some() {
            let (thrown, thrown_label) = self
                .take_pending_exception_slot()
                .expect("isolated throw remained pending for async rejection");
            if !self.reject_nearest_async_boundary(thrown, thrown_label)? {
                return Err(InterpreterError::InternalError {
                    details: "async boundary disappeared while routing isolated throw".to_string(),
                });
            }
            Ok(None)
        } else {
            // No enclosing handler: surface as an uncaught exception carrying the
            // original thrown value — byte-identical to the inner `Throw` arm's
            // own `UncaughtException` value (both use `uncaught_exception_description`).
            self.clear_suspended_abrupt_completions();
            self.clear_finally_frames();
            self.pending_finally_entry = None;
            Ok(Some(InterpreterError::UncaughtException {
                value: self.uncaught_exception_description(
                    self.pending_exception
                        .as_ref()
                        .expect("isolated throw remained pending for uncaught propagation"),
                ),
            }))
        }
    }

    /// Route a failing `iterator.return()` as the replacing throw completion.
    /// Explicit throws arrive re-armed by the isolated callback; native JS
    /// faults are materialized here so both forms reach the same catch or async
    /// rejection boundary without allowing the displaced return to resurrect.
    pub(super) fn route_iterator_close_failure(
        &mut self,
        module: &Ir3Module,
        err: InterpreterError,
    ) -> Result<Option<InterpreterError>, InterpreterError> {
        let (thrown, thrown_label) = if matches!(err, InterpreterError::UncaughtException { .. }) {
            let Some((thrown, thrown_label)) = self.take_pending_exception_slot() else {
                return Ok(Some(err));
            };
            (thrown, thrown_label)
        } else if Self::js_catchable_error_name(&err).is_some() {
            (
                self.native_error_to_thrown_value(&err)?,
                self.clone_active_execution_context_label()?,
            )
        } else {
            return Ok(Some(err));
        };

        self.pending_finally_entry = None;
        self.replace_pending_abrupt_slots(Some((thrown, thrown_label)), None)?;
        if let Some(async_depth) = self.nearest_async_call_depth() {
            if let Some(frame) = self.pop_exception_target_frame_at_or_above(async_depth)? {
                self.select_exception_target(Some(module), frame);
                return Ok(None);
            }
            let (rejection, rejection_label) =
                self.take_pending_exception_slot().ok_or_else(|| {
                    InterpreterError::UncaughtException {
                        value: "iterator close lost its pending exception".to_string(),
                    }
                })?;
            if self.reject_nearest_async_boundary(rejection, rejection_label)? {
                return Ok(None);
            }
            self.clear_suspended_abrupt_completions();
            self.clear_finally_frames();
            self.pending_finally_entry = None;
            return Ok(Some(err));
        }
        if let Some(frame) = self.pop_exception_target_frame()? {
            self.select_exception_target(Some(module), frame);
            Ok(None)
        } else {
            self.clear_suspended_abrupt_completions();
            self.clear_finally_frames();
            self.pending_finally_entry = None;
            Ok(Some(err))
        }
    }

    /// Drive the bytecode dispatch loop, converting *native* runtime errors
    /// (TypeError from `null.x`, ReferenceError from TDZ access, …) into JS
    /// exceptions that are catchable by JS `try`/`catch` (bd-8enww.4.3).
    ///
    /// The actual instruction loop lives in [`Self::run_loop_dispatch`]. When
    /// that returns a JS-catchable host error AND the current invocation has an
    /// active catch frame, we route the error through the exact same unwinding
    /// path as the `Throw` instruction (build an error object, suspend the
    /// prior abrupt completion, set `pending_exception`, unwind to the handler
    /// via `pop_exception_target_frame`) and re-enter the dispatch loop at the
    /// catch target. Errors with no eligible handler — and all engine
    /// faults/resource limits, which are not JS-catchable — propagate
    /// unchanged.
    /// Value-only view of [`Self::run_loop_labeled`] for engine-internal
    /// callers (generator/async resumption, nested drivers) whose label flow
    /// travels through the register file and generator/async side channels.
    pub(super) fn run_loop(&mut self, module: &Ir3Module) -> Result<Value, InterpreterError> {
        self.run_loop_labeled(module)
            .map(|completion| completion.value)
    }

    /// `run_loop` with `trampoline` executing at instruction indices
    /// `module.instructions.len()..`: the synthetic call site of an isolated
    /// call, without cloning the module to append it.
    pub(super) fn run_loop_with_trampoline(
        &mut self,
        module: &Ir3Module,
        trampoline: &[Ir3Instruction],
    ) -> Result<Value, InterpreterError> {
        self.run_loop_labeled_with_trampoline(module, None, trampoline)
            .map(|completion| completion.value)
    }

    /// The instruction at `ip`: the module's own, else the trampoline's.
    pub(super) fn instruction_with_trampoline<'a>(
        module: &'a Ir3Module,
        trampoline: &'a [Ir3Instruction],
        ip: usize,
    ) -> Result<&'a Ir3Instruction, InterpreterError> {
        module
            .instructions
            .get(ip)
            .or_else(|| {
                ip.checked_sub(module.instructions.len())
                    .and_then(|offset| trampoline.get(offset))
            })
            .ok_or_else(|| InterpreterError::InstructionOutOfBounds {
                ip,
                count: module.instructions.len() + trampoline.len(),
            })
    }

    /// Run the dispatch loop, carrying the completion value's IFC label on
    /// every exit (bd-5ilh1). The labeled type forces each dispatch exit site
    /// to state its completion provenance explicitly — a new exit path cannot
    /// silently default to `Public`.
    pub(super) fn run_loop_labeled(
        &mut self,
        module: &Ir3Module,
    ) -> Result<LabeledReturn, InterpreterError> {
        self.run_loop_labeled_with_compact_tier1(module, None)
    }

    /// Finish a builtin call after the dispatch frame has returned. Generator
    /// methods and user callbacks can re-enter execution, so retaining that
    /// frame here would exhaust a small embedding-thread stack before the
    /// logical call-depth guard can fire.
    #[inline(never)]
    pub(super) fn finish_builtin_dispatch(
        &mut self,
        module: &Ir3Module,
        builtin: BuiltinFunction,
        callee: u32,
        args: RegRange,
        dst: u32,
        receiver: Option<(Value, u32)>,
    ) -> Result<(), InterpreterError> {
        if let Some((receiver_val, receiver)) = receiver {
            // Mirror the plain-`Call` arm: an explicit `throw` that
            // escapes a generated function or an inline callback the
            // builtin runs (e.g. `arr.forEach(() => { throw … })`)
            // must be catchable by an enclosing try/catch in this
            // frame (bd-8enww.4.7).
            self.clear_pending_hostcall_result_label();
            self.mark_inline_callback_started();
            let result = match self.dispatch_builtin_function_with_callee_register(
                module,
                &builtin,
                args,
                Some(receiver_val.clone()),
                Some(receiver),
                callee,
            ) {
                Ok(value) => value,
                Err(err) => match self.route_isolated_explicit_throw(module, err)? {
                    None => {
                        // IFC (bd-8enww.4.8): mirror the success-path
                        // receiver+args label join (below) onto an
                        // explicit throw escaping the builtin's
                        // callback lane, so a Secret array's reducer
                        // that throws one of its elements cannot
                        // launder to a Public catch binding now that
                        // the legacy mini-lane preserves the original
                        // thrown value.
                        let escaped = self
                            .join_arg_range_label(args)?
                            .join(self.get_register_label(receiver)?)
                            .join(self.get_register_label(callee)?);
                        self.join_pending_exception_label(&escaped)?;
                        return Ok(());
                    }
                    Some(err) => return Err(err),
                },
            };
            let callback_result_label = self
                .take_pending_hostcall_result_label()
                .unwrap_or(Label::Public);
            // IFC: a receiver-aware builtin's result derives from
            // the receiver and the arg registers (e.g. a Secret
            // array's reduce/map/from result is at least Secret) —
            // join both onto dst (bd-ooaka.1; the callback mini-
            // lanes see only values seeded from these registers,
            // so this join is a sound upper bound for anything
            // they compute).
            let binary_storage_label = match &receiver_val {
                Value::Object(object_id) => self.binary_storage_label(*object_id),
                _ => Label::Public,
            };
            let stream_state_label = match &receiver_val {
                Value::Object(object_id) => self.stream_state_label(*object_id),
                _ => Label::Public,
            };
            let url_state_label = match &receiver_val {
                Value::Object(object_id) => self.url_state_label(*object_id),
                _ => Label::Public,
            };
            let cluster_state_label = match &receiver_val {
                Value::Object(object_id) => self.cluster_state_label(*object_id),
                _ => Label::Public,
            };
            let result_label = self
                .join_arg_range_label(args)?
                .join(self.get_register_label(receiver)?)
                .join(self.get_register_label(callee)?)
                .join(&binary_storage_label)
                .join(&stream_state_label)
                .join(&url_state_label)
                .join(&cluster_state_label)
                .join(&callback_result_label);
            self.propagate_builtin_binary_mutation_label(
                &builtin,
                &receiver_val,
                args,
                &result_label,
            )?;
            self.write_reg_with_label(dst, result, result_label)?;
            self.ip += 1;
            return Ok(());
        }
        // An explicit `throw` inside a generated function (or an
        // inline callback the builtin runs) escapes the isolated
        // run as `UncaughtException` with the thrown value
        // preserved; route it into THIS frame's catch handler
        // rather than letting `?` escape the caller's try/catch
        // (bd-8enww.4.7).
        self.clear_pending_hostcall_result_label();
        let result = match self.dispatch_builtin_function_with_callee_register(
            module, &builtin, args, None, None, callee,
        ) {
            Ok(value) => value,
            Err(err) => match self.route_isolated_explicit_throw(module, err)? {
                None => {
                    // IFC (bd-8enww.4.8): an explicit throw
                    // escaping the builtin's callback lane
                    // carries a value seeded from the arg
                    // registers, so join their labels onto the
                    // re-armed exception label — the throw-path
                    // mirror of the success-path join below.
                    // Required now that the legacy reduce /
                    // Array.from mini-lanes preserve the
                    // original thrown value (not a Public
                    // engine error), so a Secret arg cannot
                    // launder to a Public catch binding.
                    let escaped = self
                        .join_arg_range_label(args)?
                        .join(self.get_register_label(callee)?);
                    self.join_pending_exception_label(&escaped)?;
                    return Ok(());
                }
                Some(err) => return Err(err),
            },
        };
        let callback_result_label = self
            .take_pending_hostcall_result_label()
            .unwrap_or(Label::Public);
        // IFC: builtin results derive entirely from the arg
        // registers (incl. any callback lanes the builtin runs,
        // which see only values seeded from these args), so the
        // dst label is the join of the arg labels — mirrors the
        // HostCall propagation (bd-ooaka.1, fourth member of
        // the bd-n2mjy/bd-0zybl under-tainting family).
        let args_label = self
            .join_arg_range_label(args)?
            .join(self.get_register_label(callee)?);
        self.write_reg_with_label(dst, result, args_label.join(&callback_result_label))?;
        self.ip += 1;
        Ok(())
    }

    #[inline(never)]
    pub(super) fn finish_generator_delegate_dispatch(
        &mut self,
        module: &Ir3Module,
        value: u32,
        resume_dst: u32,
    ) -> Result<Option<LabeledReturn>, InterpreterError> {
        if let Some(id) = self.async_generator_runtime.active {
            return self.finish_async_generator_delegate_dispatch(module, id, value, resume_dst);
        }
        match self.step_generator_delegation(module, value, resume_dst) {
            Ok(GeneratorDelegationStep::Yield(result)) => {
                // Re-enter this same opcode on the next resume;
                // neither the iterable nor next is reacquired.
                self.generator_yielded = true;
                self.generator_resume_dst = Some(resume_dst);
                self.generator_result_label = result.label.clone();
                Ok(Some(result))
            }
            Ok(GeneratorDelegationStep::Complete(completion)) => {
                self.take_generator_delegation();
                self.write_reg_with_label(resume_dst, completion.value, completion.label)?;
                self.ip += 1;
                Ok(None)
            }
            Ok(GeneratorDelegationStep::Return(completion)) => {
                self.take_generator_delegation();
                self.inject_generator_return(completion)
            }
            Err(error) => {
                if let Some(delegation) = self.take_generator_delegation() {
                    let label = delegation.label.join(
                        self.pending_hostcall_result_label
                            .as_ref()
                            .unwrap_or(&Label::Public),
                    );
                    if self.pending_exception.is_some() {
                        self.join_pending_exception_label(&label)?;
                    }
                    self.replace_pending_hostcall_result_label(Some(label))?;
                }
                // The outer dispatch wrapper routes native
                // faults and exact callback throws alike.
                Err(error)
            }
        }
    }

    /// Run iterator and hostcall operations after releasing the bytecode
    /// dispatch frame. These paths can resume generators through for-of,
    /// destructuring, spread, and user-defined iterator methods.
    #[inline(never)]
    pub(super) fn finish_reentrant_instruction(
        &mut self,
        module: &Ir3Module,
        trampoline: &[Ir3Instruction],
        instruction_ip: usize,
        profile_start: Option<std::time::Instant>,
    ) -> Result<(), InterpreterError> {
        let instruction = Self::instruction_with_trampoline(module, trampoline, instruction_ip)?;
        match *instruction {
            Ir3Instruction::ForInInit { src, dst } => {
                let result_label = self.unary_operation_label(src)?;
                let value = self.read_reg(src)?;
                let iterator = self.init_for_in_iterator(Some(module), value)?;
                // Carry the iterable's IFC label onto the iterator register
                // so the keys it yields stay tainted.
                self.write_reg_with_label(dst, iterator, result_label)?;
                self.ip += 1;
            }
            Ir3Instruction::ForInNext {
                iterator,
                value_dst,
                done_target,
            } => {
                let iterator_reg = iterator;
                let result_label = self.unary_operation_label(iterator_reg)?;
                let iterator = self.read_reg(iterator_reg)?;
                if let Some(value) = self.advance_for_in_iterator(iterator)? {
                    // Each bound key derives from the iterable; carry its
                    // IFC label onto the loop variable (sibling of the
                    // reduce/array-from callback-lane fix, bd-ooaka.1).
                    self.write_reg_with_label(value_dst, value, result_label)?;
                    self.ip += 1;
                } else {
                    self.ip = done_target as usize;
                }
            }
            Ir3Instruction::ForOfInit { src, dst } => {
                let result_label = self.unary_operation_label(src)?;
                let value = self.read_reg(src)?;
                let iterator = self.init_for_of_iterator(Some(module), value)?;
                // Carry the iterable's IFC label onto the iterator register.
                self.write_reg_with_label(dst, iterator, result_label)?;
                self.ip += 1;
            }
            Ir3Instruction::ForOfNext {
                iterator,
                value_dst,
                done_target,
            } => {
                let iterator_reg = iterator;
                let result_label = self.unary_operation_label(iterator_reg)?;
                let iterator = self.read_reg(iterator_reg)?;
                self.clear_pending_hostcall_result_label();
                match self.advance_for_of_iterator(Some(module), iterator) {
                    Ok(Some(value)) => {
                        // Each bound element derives from the iterable; carry
                        // its label onto the loop variable so a
                        // `for (const x of secret) egress(x)` cannot launder
                        // the taint (sibling of bd-ooaka.1).
                        let result_label = result_label.join(
                            &self
                                .take_pending_hostcall_result_label()
                                .unwrap_or(Label::Public),
                        );
                        self.write_reg_with_label(value_dst, value, result_label)?;
                        self.ip += 1;
                    }
                    Ok(None) => {
                        self.clear_pending_hostcall_result_label();
                        self.ip = done_target as usize;
                    }
                    Err(err) => {
                        // A throw from the iterator's `next()` (or `@@iterator`)
                        // must be catchable by an enclosing try/catch
                        // (bd-bg9l1.27.7). `invoke_inline_method_call` ran the
                        // method in isolation and re-armed `pending_exception`
                        // with the thrown value; route it into the in-loop
                        // unwinding exactly like the `Throw` instruction, instead
                        // of letting `?` escape the loop. Non-throw errors (e.g.
                        // a missing `next` TypeError) leave `pending_exception`
                        // unset and propagate unchanged.
                        let Some((thrown, thrown_label)) = self.take_pending_exception_slot()
                        else {
                            return Err(err);
                        };
                        // The isolated iterator call already re-armed this
                        // exception. Route that one owned completion without
                        // suspending a duplicate that a catch could revive.
                        self.pending_finally_entry = None;
                        self.replace_pending_abrupt_slots(Some((thrown, thrown_label)), None)?;
                        if let Some(frame) = self.pop_exception_target_frame()? {
                            self.select_exception_target(Some(module), frame);
                        } else if self.nearest_async_call_depth().is_some() {
                            let (thrown, thrown_label) = self
                                .take_pending_exception_slot()
                                .expect("iterator throw remained pending for async rejection");
                            if !self.reject_nearest_async_boundary(thrown, thrown_label)? {
                                return Err(InterpreterError::InternalError {
                                    details:
                                        "async boundary disappeared while routing iterator throw"
                                            .to_string(),
                                });
                            }
                            return Ok(());
                        } else {
                            self.clear_suspended_abrupt_completions();
                            self.clear_finally_frames();
                            self.pending_finally_entry = None;
                            return Err(InterpreterError::UncaughtException {
                                value: self.uncaught_exception_description(
                                    self.pending_exception.as_ref().expect(
                                        "iterator throw remained pending for uncaught propagation",
                                    ),
                                ),
                            });
                        }
                    }
                }
            }
            Ir3Instruction::IteratorClose { iterator, reason } => {
                let label = self.clone_register_label_with_temporary_budget(iterator)?;
                self.replace_pending_hostcall_result_label(Some(label))?;
                let iterator = self.read_reg(iterator)?;
                // A canonical throw-close handler owns the original throw
                // in its active finalizer frame. Retain the pending-slot
                // fallback for hand-authored legacy IR that reaches this
                // instruction without `EnterFinally`.
                let frame_owns_original_throw = reason == IteratorCloseReason::Throw
                    && self.finally_frames.last().is_some_and(|frame| {
                        matches!(
                            frame.completion.as_ref(),
                            Some(AbruptCompletion::Exception(_, _))
                        )
                    });
                let suspended_original_throw = reason == IteratorCloseReason::Throw
                    && !frame_owns_original_throw
                    && self.pending_exception.is_some();
                if suspended_original_throw {
                    self.suspend_current_abrupt_completion()?;
                }
                // A non-canonical pending completion still needs the legacy
                // suspension path. Canonical source-finally completions stay
                // isolated in `finally_frames` across the callback snapshot.
                let suspended_inherited_completion = matches!(
                    reason,
                    IteratorCloseReason::Break | IteratorCloseReason::Continue
                ) && (self.pending_exception.is_some()
                    || self.pending_return.is_some());
                if suspended_inherited_completion {
                    self.suspend_current_abrupt_completion()?;
                }
                match self.close_iterator(module, iterator, reason) {
                    Ok(()) => {
                        if suspended_original_throw {
                            self.restore_suspended_abrupt_completion();
                        }
                        if suspended_inherited_completion {
                            self.restore_suspended_abrupt_completion();
                        }
                        self.ip += 1;
                    }
                    Err(err) => {
                        // IteratorClose(iterator, throwCompletion) preserves
                        // the original throw even when `return` itself throws
                        // or returns a non-object. Suppress only ordinary JS
                        // close failures; engine/resource faults still escape.
                        let explicit_throw =
                            matches!(&err, InterpreterError::UncaughtException { .. })
                                && self.pending_exception.is_some();
                        if reason == IteratorCloseReason::Throw
                            && (explicit_throw || Self::js_catchable_error_name(&err).is_some())
                            && (frame_owns_original_throw || suspended_original_throw)
                        {
                            self.clear_pending_abrupt_slots();
                            if suspended_original_throw {
                                self.restore_suspended_abrupt_completion();
                            }
                            self.ip += 1;
                            return Ok(());
                        }
                        if frame_owns_original_throw || suspended_original_throw {
                            // Resource/engine faults are not suppressible JS
                            // completions. Keep the owned frame (or restore
                            // the legacy pending completion) while the engine
                            // fault propagates.
                            self.clear_pending_abrupt_slots();
                            if suspended_original_throw {
                                self.restore_suspended_abrupt_completion();
                            }
                            return Err(err);
                        }
                        match self.route_iterator_close_failure(module, err)? {
                            None => return Ok(()),
                            Some(err) => return Err(err),
                        }
                    }
                }
            }
            Ir3Instruction::ArraySlice { array, start, dst } => {
                let result_label = self.binary_operation_label(array, start)?;
                let array_value = self.read_reg(array)?;
                let start_value = self.read_reg(start)?;
                match self.slice_array_suffix(Some(module), array_value, start_value) {
                    Ok(result) => {
                        self.write_reg_with_label(dst, result, result_label)?;
                        self.ip += 1;
                    }
                    Err(error) => {
                        if let Some(error) = self.route_iterator_close_failure(module, error)? {
                            return Err(error);
                        }
                    }
                }
            }
            Ir3Instruction::SpreadIntoArray { array, iterable } => {
                match self.spread_into_array_transaction(module, array, iterable) {
                    Ok(()) => self.ip += 1,
                    Err(error) => {
                        // Guest throws from @@iterator, next, done, or
                        // value cross an isolated callback boundary. Route
                        // their original value through the surrounding
                        // catch/finally/async boundary; resource refusals
                        // remain uncatchable interpreter failures.
                        if let Some(error) = self.route_iterator_close_failure(module, error)? {
                            return Err(error);
                        }
                    }
                }
            }
            Ir3Instruction::HostCall {
                ref capability,
                args,
                dst,
            } => {
                // Apply shared capability gate logic
                if check_hostcall_capability_gate(self, &capability.0, self.ip as u32)? {
                    self.emit_witness(
                        WitnessEventKind::HostcallDispatched,
                        Some(&format!("cap:{}", capability_gate_key(&capability.0))),
                    );
                }

                // bd-n2mjy: capture the join of arg labels BEFORE dispatch so
                // hostcalls that mutate their arg slots don't strip the
                // input taint we owe to the dst register.
                let args_label = if capability.0 == "builtin:ApplyHostCall"
                    || capability.0.starts_with(APPLY_HOSTCALL_TARGET_PREFIX)
                {
                    self.join_arg_range_with_object_mutation_label(args)?
                } else {
                    self.join_arg_range_label(args)?
                };

                self.clear_pending_hostcall_result_label();
                let dispatch = hostcall_registry_row(&capability.0)
                    .map(|row| row.dispatch)
                    .ok_or_else(|| InterpreterError::CapabilityDenied {
                        capability: recordable_capability_tag(&capability.0).into_owned(),
                    })?;
                let result = match dispatch {
                    HostcallDispatchBinding::Promise => {
                        self.dispatch_promise_hostcall(&capability.0, args, Some(module))?
                    }
                    HostcallDispatchBinding::ModuleRequire => {
                        self.dispatch_require_hostcall(args, Some(module))?
                    }
                    HostcallDispatchBinding::ModuleImport => {
                        self.dispatch_import_hostcall(&capability.0, args, Some(module))?
                    }
                    HostcallDispatchBinding::Number => {
                        self.dispatch_number_hostcall(&capability.0, args)?
                    }
                    HostcallDispatchBinding::Console => {
                        self.dispatch_console_hostcall(&capability.0, args, Some(module))?
                    }
                    HostcallDispatchBinding::Timer => {
                        self.dispatch_timer_hostcall(&capability.0, args)?
                    }
                    HostcallDispatchBinding::ProcessSpawn => {
                        self.dispatch_process_spawn_hostcall(args)?
                    }
                    HostcallDispatchBinding::Builtin => {
                        // bd-8enww.4.10: a `builtin:` hostcall can run a user
                        // callback whose explicit `throw` escapes its isolated
                        // lane as `UncaughtException` with the thrown value
                        // preserved — e.g. `Array.from(xs, x => { throw v })` via
                        // the `builtin:ArrayFrom` mapper mini-lane, or an
                        // array-literal `[…].some(x => { throw v })` via the
                        // `builtin:ArrayPrototypeSome` fast-path. Route it into
                        // THIS frame's catch handler exactly like the `Call` /
                        // `CallMethod` builtin arms, rather than letting `?` escape
                        // an enclosing `try`/`catch` — the AC#3 catchability
                        // follow-up in the bd-8enww.4.7 / bd-8enww.4.8 family.
                        // (Non-throw hostcall errors are a no-op through the
                        // router and propagate unchanged.)
                        let legacy_regexp_generation = self.legacy_regexp_generation;
                        match self.dispatch_builtin_hostcall(&capability.0, args, Some(module)) {
                            Ok(value) => {
                                // bd-9vouw.113: a match this call recorded
                                // carries its operands' label.
                                self.label_legacy_regexp_match(
                                    legacy_regexp_generation,
                                    &args_label,
                                );
                                value
                            }
                            Err(err) => {
                                match self.route_isolated_explicit_throw(module, err)? {
                                    None => {
                                        // IFC (bd-8enww.4.8 throw-path mirror): the
                                        // escaping value is seeded from the arg
                                        // registers (which include the receiver array /
                                        // source as arg 0), so join their labels onto
                                        // the re-armed exception label — mirrors the
                                        // success-path `dst` join below so a Secret
                                        // receiver/arg cannot launder to a Public catch
                                        // binding now that the mini-lane preserves the
                                        // original thrown value.
                                        self.join_pending_exception_label(&args_label)?;
                                        return Ok(());
                                    }
                                    Some(err) => return Err(err),
                                }
                            }
                        }
                    }
                    HostcallDispatchBinding::ClientRequest => {
                        // bd-3894s slice (2b): `http.request(url[, opts])` builds a
                        // writable `ClientRequest` object here WITHOUT egressing —
                        // the body is accumulated via `req.write`/`req.end` and the
                        // deferred egress fires from `.end()`. The capability gate
                        // above authorizes construction through NetworkEgress.
                        // The deferred `.end()` checks the live `net:request`
                        // gate again before mutation or egress, followed by the
                        // provider's endpoint policy at dispatch.
                        self.dispatch_client_request_create(args)?
                    }
                    HostcallDispatchBinding::HostIo => {
                        // bd-f5b04.2.7: when a sandboxed host-I/O provider is
                        // installed, dispatch the (already-authorized) fs hostcall
                        // through the algebraic-effects stack to perform a real,
                        // recorded host effect; otherwise it returns undefined.
                        // bd-656a2: the http leg routes `net:request` (emitted by
                        // the JS http.get/http.request lowering) through the SAME
                        // seam — it performs+records a real NetworkSend host effect
                        // via the sandboxed provider's network mechanism. The gate
                        // above (`check_hostcall_capability_gate`) has already
                        // authorized it against the granted NetworkEgress capability.
                        self.check_host_io_confidentiality(&capability.0, args)?;
                        if capability.0 == crate::capability::FS_READ_PROMISE_CAPABILITY {
                            self.dispatch_fs_promise_read(args)?
                        } else {
                            self.dispatch_host_io_hostcall(&capability.0, args)?
                        }
                    }
                    HostcallDispatchBinding::Internal => {
                        if capability.0 == crate::lowering_pipeline::IFC_RUNTIME_GUARD_CAPABILITY {
                            if let Some(Ir3Instruction::HostCall {
                                capability: sink_cap,
                                ..
                            }) = module.instructions.get(self.ip + 1)
                            {
                                self.check_host_io_confidentiality(&sink_cap.0, args)?;
                            } else {
                                self.check_sink_confidentiality(
                                    args,
                                    &capability.0,
                                    &Label::Public,
                                )?;
                            }
                        }
                        Value::Undefined
                    }
                    HostcallDispatchBinding::DeterministicNoop => {
                        if !capability.0.starts_with("declassify.")
                            && !capability.0.starts_with("declassify:")
                        {
                            self.check_host_io_confidentiality(&capability.0, args)?;
                        }
                        Value::Undefined
                    }
                };
                let runtime_result_label = self.take_pending_hostcall_result_label();
                let result_label = hostcall_result_contract(&capability.0)
                    .result_label(&args_label, runtime_result_label.as_ref());
                self.write_reg_with_label(dst, result, result_label)?;
                self.ip += 1;
            }
            // bd-9vouw.37: `+` with an object operand (ES2020 12.8.3.1):
            // ToPrimitive(lhs) then ToPrimitive(rhs) with the default hint,
            // then string concatenation or numeric addition. The conversion
            // methods' result labels join the operand labels.
            Ir3Instruction::Add { dst, lhs, rhs } => {
                let operand_label = self.binary_operation_label(lhs, rhs)?;
                self.clear_pending_hostcall_result_label();
                let left = match self.observable_to_primitive_operand(module, lhs, false) {
                    Ok(value) => value,
                    Err(error) => return self.route_reentrant_guest_error(module, error),
                };
                let right = match self.observable_to_primitive_operand(module, rhs, false) {
                    Ok(value) => value,
                    Err(error) => return self.route_reentrant_guest_error(module, error),
                };
                let label = operand_label.join(
                    &self
                        .take_pending_hostcall_result_label()
                        .unwrap_or(Label::Public),
                );
                let result = self.eval_add_values(Some(module), &left, &right)?;
                self.write_reg_with_label(dst, result, label)?;
                self.ip += 1;
            }
            // bd-9vouw.37: template substitutions are ToString(ToPrimitive(
            // hint string)) (ES2020 12.2.9.6).
            Ir3Instruction::TemplateLiteral { parts, dst } => {
                let parts_label = self.join_arg_range_label(parts)?;
                self.clear_pending_hostcall_result_label();
                let mut result = JsString::empty();
                for i in 0..parts.count {
                    let reg = parts.start.checked_add(i).ok_or(
                        InterpreterError::RegisterOutOfBounds {
                            register: parts.start,
                            max: self.config.max_registers,
                        },
                    )?;
                    let part = match self.observable_to_primitive_operand(module, reg, true) {
                        Ok(value) => value,
                        Err(error) => return self.route_reentrant_guest_error(module, error),
                    };
                    let part_str = self.template_part_js_string(part)?;
                    self.check_string_limit(result.len().saturating_add(part_str.len()))?;
                    result = result.concat(&part_str);
                }
                let label = parts_label.join(
                    &self
                        .take_pending_hostcall_result_label()
                        .unwrap_or(Label::Public),
                );
                self.write_reg_with_label(dst, Value::Str(result), label)?;
                self.ip += 1;
            }
            // bd-9vouw.37: loose equality between an object and a primitive
            // converts the object with ToPrimitive (hint "default"), then
            // compares (ES2020 7.2.14).
            Ir3Instruction::Eq { dst, lhs, rhs } | Ir3Instruction::NotEq { dst, lhs, rhs } => {
                let negate = matches!(*instruction, Ir3Instruction::NotEq { .. });
                let operand_label = self.binary_operation_label(lhs, rhs)?;
                self.clear_pending_hostcall_result_label();
                let mut operands = [Value::Undefined, Value::Undefined];
                for (slot, register) in operands.iter_mut().zip([lhs, rhs]) {
                    *slot = if self.register_needs_observable_to_primitive(register) {
                        match self.observable_to_primitive_operand(module, register, false) {
                            Ok(value) => value,
                            Err(error) => return self.route_reentrant_guest_error(module, error),
                        }
                    } else {
                        self.read_reg(register)?
                    };
                }
                let label = operand_label.join(
                    &self
                        .take_pending_hostcall_result_label()
                        .unwrap_or(Label::Public),
                );
                let equal = Self::abstract_eq_values(&operands[0], &operands[1]);
                self.write_reg_with_label(dst, Value::Bool(equal != negate), label)?;
                self.ip += 1;
            }
            // bd-9vouw.37: numeric operators with an object operand. Each
            // operand, left then right, converts through ToPrimitive with hint
            // "number" (ES2020 12.6-12.12; Abstract Relational Comparison
            // evaluates the left operand first too); the conversion methods'
            // result labels join the operand labels.
            ref numeric if Self::numeric_conversion_operands(numeric).is_some() => {
                let (lhs, rhs) = Self::numeric_conversion_operands(numeric)
                    .expect("guard checked the operator shape");
                let operand_label = match rhs {
                    Some(rhs) => self.binary_operation_label(lhs, rhs)?,
                    None => self.unary_operation_label(lhs)?,
                };
                self.clear_pending_hostcall_result_label();
                let left = match self.observable_to_numeric_primitive_operand(module, lhs) {
                    Ok(value) => value,
                    Err(error) => return self.route_reentrant_guest_error(module, error),
                };
                // ES2020 12.15.3 ApplyStringOrNumericBinaryOperator: ToNumeric
                // of the left operand completes, throwing for a Symbol, before
                // the right one converts. A relational comparison converts both
                // operands to primitives first (7.2.13).
                let relational = matches!(
                    numeric,
                    Ir3Instruction::Lt { .. }
                        | Ir3Instruction::Lte { .. }
                        | Ir3Instruction::Gt { .. }
                        | Ir3Instruction::Gte { .. }
                );
                if rhs.is_some() && !relational && matches!(left, Value::Symbol(_)) {
                    self.clear_pending_hostcall_result_label();
                    return Err(InterpreterError::TypeError {
                        expected: "value convertible to a number".to_string(),
                        got: "Symbol (Cannot convert a Symbol value to a number)".to_string(),
                    });
                }
                let right = match rhs {
                    Some(rhs) => match self.observable_to_numeric_primitive_operand(module, rhs) {
                        Ok(value) => Some(value),
                        Err(error) => return self.route_reentrant_guest_error(module, error),
                    },
                    None => None,
                };
                let label = operand_label.join(
                    &self
                        .take_pending_hostcall_result_label()
                        .unwrap_or(Label::Public),
                );
                let right = || right.clone().unwrap_or(Value::Undefined);
                let (dst, result) = match numeric {
                    Ir3Instruction::Sub { dst, .. } => {
                        (*dst, self.eval_arith_operands(left, right(), "sub")?)
                    }
                    Ir3Instruction::Mul { dst, .. } => {
                        (*dst, self.eval_arith_operands(left, right(), "mul")?)
                    }
                    Ir3Instruction::Div { dst, .. } => {
                        (*dst, self.eval_div_operands(left, right())?)
                    }
                    Ir3Instruction::Mod { dst, .. } => {
                        (*dst, self.eval_mod_operands(left, right())?)
                    }
                    Ir3Instruction::Exp { dst, .. } => {
                        (*dst, self.eval_exp_operands(left, right())?)
                    }
                    Ir3Instruction::Lt { dst, .. } => {
                        (*dst, self.eval_relational_operands(left, right(), "<")?)
                    }
                    Ir3Instruction::Lte { dst, .. } => {
                        (*dst, self.eval_relational_operands(left, right(), "<=")?)
                    }
                    Ir3Instruction::Gt { dst, .. } => {
                        (*dst, self.eval_relational_operands(left, right(), ">")?)
                    }
                    Ir3Instruction::Gte { dst, .. } => {
                        (*dst, self.eval_relational_operands(left, right(), ">=")?)
                    }
                    Ir3Instruction::BitAnd { dst, .. } => {
                        (*dst, self.eval_bitwise_operands(left, right(), "&")?)
                    }
                    Ir3Instruction::BitOr { dst, .. } => {
                        (*dst, self.eval_bitwise_operands(left, right(), "|")?)
                    }
                    Ir3Instruction::BitXor { dst, .. } => {
                        (*dst, self.eval_bitwise_operands(left, right(), "^")?)
                    }
                    Ir3Instruction::Shl { dst, .. } => {
                        (*dst, self.eval_bitwise_operands(left, right(), "<<")?)
                    }
                    Ir3Instruction::Shr { dst, .. } => {
                        (*dst, self.eval_bitwise_operands(left, right(), ">>")?)
                    }
                    Ir3Instruction::Ushr { dst, .. } => {
                        (*dst, self.eval_bitwise_operands(left, right(), ">>>")?)
                    }
                    Ir3Instruction::UnaryNeg { dst, .. } => {
                        (*dst, self.eval_unary_neg_operand(left)?)
                    }
                    Ir3Instruction::UnaryPlus { dst, .. } => {
                        (*dst, self.eval_unary_plus_operand(left)?)
                    }
                    Ir3Instruction::BitNot { dst, .. } => (*dst, self.eval_bit_not_operand(left)?),
                    Ir3Instruction::Inc { dst, .. } => (*dst, Self::step_numeric(&left, 1)?),
                    Ir3Instruction::Dec { dst, .. } => (*dst, Self::step_numeric(&left, -1)?),
                    _ => unreachable!("numeric_conversion_operands covers exactly these operators"),
                };
                self.write_reg_with_label(dst, result, label)?;
                self.ip += 1;
            }
            _ => unreachable!("non-reentrant opcode crossed the iterator/hostcall boundary"),
        }
        if let (Some(profiler), Some(profile_start)) = (&mut self.profiling_data, profile_start) {
            profiler.record_instruction(instruction);
            profiler.record_instruction_time(instruction, profile_start.elapsed());
        }
        Ok(())
    }

    pub(super) fn run_loop_labeled_with_compact_tier1(
        &mut self,
        module: &Ir3Module,
        compact_tier1: Option<&CompactTier1Program>,
    ) -> Result<LabeledReturn, InterpreterError> {
        self.run_loop_labeled_with_trampoline(module, compact_tier1, &[])
    }

    pub(super) fn run_loop_labeled_with_trampoline(
        &mut self,
        module: &Ir3Module,
        compact_tier1: Option<&CompactTier1Program>,
        trampoline: &[Ir3Instruction],
    ) -> Result<LabeledReturn, InterpreterError> {
        // bd-9vouw.72: each run loop below the first is a native recursion (a
        // builtin callback, accessor or cross-module call); JS-to-JS calls
        // stay in the loop they were made from. The provisioned stack covers
        // the first loop plus this many nested ones.
        let native_limit = self.config.max_call_depth.min(MAX_NATIVE_RUN_LOOP_DEPTH);
        if self.native_run_loop_depth > native_limit {
            return Err(InterpreterError::StackOverflow {
                depth: self.native_run_loop_depth,
                max: native_limit,
            });
        }
        self.native_run_loop_depth += 1;
        // The collector may run only in an armed loop: the top-level script's
        // own loop, or a nested loop a caller armed (`gc_arm_nested`). See
        // `collector::GcState::safe_depth`.
        self.gc_enter_run_loop();
        let result = self.run_loop_labeled_with_trampoline_inner(module, compact_tier1, trampoline);
        self.gc_exit_run_loop();
        self.native_run_loop_depth -= 1;
        match result {
            Ok(mut completion) => {
                if let Some(artifact_label) = self.active_generated_artifact_source_label() {
                    completion.label = self.join_owned_label_with_temporary_budget(
                        completion.label,
                        &artifact_label,
                    )?;
                    if self.generator_yielded {
                        self.generator_result_label = completion.label.clone();
                    }
                }
                Ok(completion)
            }
            Err(error) => {
                if self.pending_exception.is_some()
                    && let Some(artifact_label) = self.active_generated_artifact_source_label()
                {
                    let prev_label =
                        std::mem::replace(&mut self.pending_exception_label, Label::Public);
                    self.pending_exception_label =
                        self.join_owned_label_with_temporary_budget(prev_label, &artifact_label)?;
                }
                Err(error)
            }
        }
    }

    pub(super) fn run_loop_labeled_with_trampoline_inner(
        &mut self,
        module: &Ir3Module,
        compact_tier1: Option<&CompactTier1Program>,
        trampoline: &[Ir3Instruction],
    ) -> Result<LabeledReturn, InterpreterError> {
        // Initialize CheckpointGuard if cancellation token is provided
        let mut checkpoint_guard = if let Some(ref token) = self.config.cancellation_token {
            Some(CheckpointGuard::new(
                LoopSite::BytecodeDispatch,
                "baseline_interpreter",
                &self.trace_id,
                DensityConfig {
                    max_iterations: self.config.checkpoint_density,
                    max_total_iterations: self.config.instruction_budget,
                },
                token.clone(),
            ))
        } else {
            None
        };

        loop {
            let result = match self.run_loop_dispatch(
                module,
                compact_tier1,
                trampoline,
                &mut checkpoint_guard,
            ) {
                Ok(DispatchOutcome::Complete(completion)) => Ok(Some(completion)),
                Ok(DispatchOutcome::BuiltinCall {
                    builtin,
                    callee,
                    args,
                    dst,
                    receiver,
                }) => self
                    .finish_builtin_dispatch(module, builtin, callee, args, dst, receiver)
                    .map(|()| None),
                Ok(DispatchOutcome::GeneratorDelegate { source, resume_dst }) => {
                    self.finish_generator_delegate_dispatch(module, source, resume_dst)
                }
                Ok(DispatchOutcome::ReentrantInstruction {
                    instruction_ip,
                    profile_start,
                }) => self
                    .finish_reentrant_instruction(module, trampoline, instruction_ip, profile_start)
                    .map(|()| None),
                Err(error) => Err(error),
            };
            match result {
                Ok(None) => continue,
                Ok(Some(completion)) => return Ok(completion),
                Err(err @ InterpreterError::UncaughtException { .. }) => {
                    // Accessors, Proxy traps, and conversion callbacks can
                    // leave dispatch through `?`, not only through Call. The
                    // isolated driver restores the caller and re-arms the
                    // original value and label; route that completion here so
                    // every instruction observes the enclosing catch/finally.
                    if self.pending_exception.is_some()
                        && let Ok(Ir3Instruction::GetProperty { obj, key, .. }) =
                            Self::instruction_with_trampoline(module, trampoline, self.ip)
                    {
                        // A sealed Proxy invariant error also reveals the
                        // selected receiver and key. Their operand labels live
                        // in dispatch locals, outside the callback's scope.
                        let operands = self.binary_operation_label(*obj, *key)?;
                        let bytes = Self::estimate_label_bytes(&operands);
                        self.json_reserve_temporary(bytes)?;
                        let joined = self.join_pending_exception_label(&operands);
                        drop(operands);
                        self.json_release_temporary(bytes);
                        joined?;
                    }
                    if let Some(err) = self.route_isolated_explicit_throw(module, err)? {
                        return Err(err);
                    }
                }
                Err(err)
                    if Self::js_catchable_error_name(&err).is_some()
                        && (self.has_active_catch_frame()
                            || self.nearest_async_call_depth().is_some()) =>
                {
                    let thrown = self.native_error_to_thrown_value(&err)?;
                    let thrown_label = self.clone_active_execution_context_label()?.join(
                        &self
                            .take_pending_hostcall_result_label()
                            .unwrap_or(Label::Public),
                    );
                    self.pending_finally_entry = None;
                    self.suspend_current_abrupt_completion()?;
                    // A native fault is control-dependent on the active method
                    // or callback PC even when its Error object is engine-built.
                    self.replace_pending_abrupt_slots(
                        Some((thrown.clone(), thrown_label.clone())),
                        None,
                    )?;
                    match self.pop_exception_target_frame()? {
                        Some(frame) => {
                            self.select_exception_target(Some(module), frame);
                            // Re-enter dispatch at the handler.
                        }
                        None => {
                            if self.reject_nearest_async_boundary(
                                thrown.clone(),
                                thrown_label.clone(),
                            )? {
                                continue;
                            }
                            // `has_active_catch_frame` raced/changed: surface
                            // an uncaught exception rather than the host error.
                            self.clear_suspended_abrupt_completions();
                            self.clear_finally_frames();
                            self.pending_finally_entry = None;
                            return Err(InterpreterError::UncaughtException {
                                value: self.uncaught_exception_description(&thrown),
                            });
                        }
                    }
                }
                Err(error) => return Err(error),
            }
        }
    }

    #[inline(never)]
    pub(super) fn run_loop_dispatch(
        &mut self,
        module: &Ir3Module,
        compact_tier1: Option<&CompactTier1Program>,
        trampoline: &[Ir3Instruction],
        checkpoint_guard: &mut Option<CheckpointGuard>,
    ) -> Result<DispatchOutcome, InterpreterError> {
        loop {
            // Collector safe point (bd-9vouw.57): every live value is in
            // interpreter state here, before this iteration moves anything
            // into Rust locals.
            if self.gc_safe_point_due() {
                self.gc_safe_point();
            }
            // Time-travel debugger state capture at the instruction boundary
            // (bd-fqlfw.3.5.5). O(1) branch when disarmed.
            self.check_state_capture_boundary();

            if !self.pc_label_stack.is_empty() {
                let depth = self.call_stack.len();
                let ip = self.ip;
                while self.pc_label_stack.last().is_some_and(|frame| {
                    depth < frame.call_depth
                        || (depth == frame.call_depth && ip == frame.reconvergence_ip)
                }) {
                    self.pc_label_stack.pop();
                }
            }

            if self.ip >= module.instructions.len() + trampoline.len() {
                // Fell off the end of the instruction stream.
                if !self.call_stack.is_empty() {
                    if let Some(completion) =
                        self.complete_return(Some(module), Value::Undefined, Label::Public)?
                    {
                        return Ok(DispatchOutcome::Complete(completion));
                    }
                    continue;
                } else {
                    let value = self.read_reg(0)?;
                    let label = self.get_register_label(0).cloned().unwrap_or(Label::Public);
                    return Ok(DispatchOutcome::Complete(LabeledReturn { value, label }));
                }
            }

            if self.instructions_executed >= self.config.instruction_budget {
                return Err(InterpreterError::BudgetExhausted {
                    executed: self.instructions_executed,
                    budget: self.config.instruction_budget,
                });
            }

            // [RC-E1 / g2vrp.15] Tarjan SCC loop-header AARA iteration hoisting:
            // hoist budget, safepoint, PC-label, and trampoline checks across up to
            // 2048 verified single-entry acyclic-body Compact Tier-I loop iterations.
            if self.all_register_labels_public
                && self.profiling_data.is_none()
                && checkpoint_guard.is_none()
                && self.state_capture_tick.is_none()
                && self.pc_label_stack.is_empty()
                && !self.gc_safe_point_due()
                && let Some(program) = compact_tier1
                && let Some(quantum) = program.loop_quantum_at(self.ip)
            {
                let budget_limit = self.config.instruction_budget;
                let max_iter_cost = u64::from(quantum.max_iter_cost);
                let mut iters_left = budget_limit
                    .saturating_sub(self.instructions_executed)
                    .checked_div(max_iter_cost)
                    .unwrap_or(0)
                    .min(2048);
                if iters_left > 0 {
                    let header_ip = self.ip;
                    let mut ran_any = false;
                    while let Some(cell) = program.raw_cell_at(self.ip) {
                        if matches!(
                            cell.opcode,
                            CompactTier1Opcode::Baseline | CompactTier1Opcode::Halt
                        ) || self.compact_operator_needs_to_primitive(&cell)
                        {
                            break;
                        }
                        ran_any = true;
                        self.instructions_executed += 1;
                        self.tier_i_instructions_executed =
                            self.tier_i_instructions_executed.saturating_add(1);
                        self.execute_compact_tier1_instruction(module, cell)?;
                        if !self.all_register_labels_public
                            || !self.pc_label_stack.is_empty()
                            || !program.ip_in_loop_scc(quantum.header_scc_id, self.ip)
                        {
                            break;
                        }
                        if self.ip == header_ip {
                            iters_left -= 1;
                            if iters_left == 0
                                || self.gc_safe_point_due()
                                || self.instructions_executed.saturating_add(max_iter_cost)
                                    > budget_limit
                            {
                                break;
                            }
                        }
                    }
                    if ran_any {
                        continue;
                    }
                }
            }

            // [RC-E1] Hoist budget, safepoint, PC-label, and trampoline checks
            // to basic-block entry for straight-line Compact Tier-I runs.
            if self.profiling_data.is_none()
                && checkpoint_guard.is_none()
                && self.state_capture_tick.is_none()
                && self.pc_label_stack.is_empty()
                && !self.gc_safe_point_due()
                && let Some(block) = compact_tier1.and_then(|p| p.block_slice_at(self.ip))
                && self
                    .instructions_executed
                    .saturating_add(block.len() as u64)
                    <= self.config.instruction_budget
            {
                let mut ran_any = false;
                for &cell in block {
                    if self.compact_operator_needs_to_primitive(&cell) {
                        break;
                    }
                    let ip_before = self.ip;
                    ran_any = true;
                    self.instructions_executed += 1;
                    self.tier_i_instructions_executed =
                        self.tier_i_instructions_executed.saturating_add(1);
                    self.execute_compact_tier1_instruction(module, cell)?;
                    if self.ip != ip_before + 1 || !self.pc_label_stack.is_empty() {
                        break;
                    }
                }
                if ran_any {
                    continue;
                }
            }

            let instr_ref = Self::instruction_with_trampoline(module, trampoline, self.ip)?;
            // Profiling retains the canonical Tier-R handler so its existing
            // per-opcode recorder observes the original IR3 instruction. The
            // production lanes do not install this profiler today.
            let compact_instruction = if self.profiling_data.is_none() {
                compact_tier1
                    .and_then(|program| program.instruction_at(self.ip))
                    // bd-9vouw.37: an object operand of `+` needs the
                    // observable ToPrimitive, which only the Tier-R handler
                    // (reentrant path) performs.
                    // bd-9vouw.37: likewise every numeric operator.
                    .filter(|compact| !self.compact_operator_needs_to_primitive(compact))
            } else {
                None
            };
            if compact_instruction.is_none()
                && let Ir3Instruction::LoadBigInt { dst, value } = instr_ref
            {
                self.preflight_bigint_literal_write(*dst, value)?;
            }
            // An instruction Tier-R always hands to the reentrant path is not
            // cloned: that path reads it in place, and the clone of a HostCall
            // allocated its capability tag only to drop it (bd-9vouw.348).
            let reentrant_only =
                compact_instruction.is_none() && self.tier_r_always_reentrant(instr_ref);
            let mut instr =
                (compact_instruction.is_none() && !reentrant_only).then(|| instr_ref.clone());
            let mut spread_apply_arguments = None;
            self.instructions_executed += 1;

            // Checkpoint guard integration: tick on each instruction
            if let Some(guard) = checkpoint_guard.as_mut() {
                guard.tick();

                // Check at checkpoint density interval
                if self
                    .instructions_executed
                    .is_multiple_of(self.config.checkpoint_density)
                {
                    match guard.check() {
                        CheckpointAction::Continue => {
                            // Continue execution normally
                        }
                        CheckpointAction::Drain => {
                            // Cancellation requested, return Cancelled error
                            return Err(InterpreterError::Cancelled);
                        }
                        CheckpointAction::Abort => {
                            // Budget exhausted via checkpoint, defer to existing budget check
                            // (This will be caught by the budget check above)
                        }
                    }
                }
            }

            // Start profiling timing for this instruction
            let profile_start = if self.profiling_data.is_some() {
                Some(std::time::Instant::now())
            } else {
                None
            };

            if let Some(compact_instruction) = compact_instruction {
                self.tier_i_instructions_executed =
                    self.tier_i_instructions_executed.saturating_add(1);
                self.execute_compact_tier1_instruction(module, compact_instruction)?;
                continue;
            }
            if reentrant_only {
                // bd-9vouw.501: a spread call `f(...list)` is the Reflect.apply
                // hostcall over a fresh array; when building the argument list
                // is unobservable it runs as the method call `undefined.f(...)`,
                // the list handed to the CallMethod handler as
                // `apply_arguments`. Only the reentrant instructions reach this
                // check: made before the dispatch, it cost every instruction.
                match self.spread_call_as_method_call(module, instr_ref)? {
                    Some((call, values)) => {
                        instr = Some(call);
                        spread_apply_arguments = Some(values);
                    }
                    None => {
                        return Ok(DispatchOutcome::ReentrantInstruction {
                            instruction_ip: self.ip,
                            profile_start,
                        });
                    }
                }
            }

            // bd-9vouw.37: a numeric operator with an object operand runs its
            // observable ToPrimitive on the reentrant path.
            if instr
                .as_ref()
                .is_some_and(|source| self.numeric_operator_needs_to_primitive(source))
            {
                return Ok(DispatchOutcome::ReentrantInstruction {
                    instruction_ip: self.ip,
                    profile_start,
                });
            }
            match instr.expect("Tier-R dispatch owns the cloned source instruction") {
                Ir3Instruction::LoadInt { dst, value } => {
                    let val = if value >= MIN_SAFE_INTEGER && value <= MAX_SAFE_INTEGER {
                        Value::Int(value)
                    } else {
                        Value::Float(Float64::new(value as f64))
                    };
                    self.write_reg(dst, val)?;
                    self.ip += 1;
                }
                Ir3Instruction::LoadBigInt { dst, value } => {
                    self.write_reg(dst, Value::BigInt(Arc::from(value)))?;
                    self.ip += 1;
                }
                Ir3Instruction::LoadFloat { dst, bits } => {
                    let value = f64::from_bits(bits);
                    self.write_reg(dst, Value::Float(Float64::new(value)))?;
                    self.ip += 1;
                }
                Ir3Instruction::LoadStr { dst, pool_index } => {
                    let s = module.constant_pool.get(pool_index as usize).ok_or(
                        InterpreterError::StringPoolOutOfBounds {
                            index: pool_index,
                            pool_size: module.constant_pool.len() as u32,
                        },
                    )?;
                    self.write_reg(dst, Value::Str(s.clone()))?;
                    self.ip += 1;
                }
                Ir3Instruction::LoadBool { dst, value } => {
                    self.write_reg(dst, Value::Bool(value))?;
                    self.ip += 1;
                }
                Ir3Instruction::LoadNull { dst } => {
                    self.write_reg(dst, Value::Null)?;
                    self.ip += 1;
                }
                Ir3Instruction::LoadUndefined { dst } => {
                    self.write_reg(dst, Value::Undefined)?;
                    self.ip += 1;
                }
                Ir3Instruction::Add { dst, lhs, rhs } => {
                    if self.register_needs_observable_to_primitive(lhs)
                        || self.register_needs_observable_to_primitive(rhs)
                    {
                        return Ok(DispatchOutcome::ReentrantInstruction {
                            instruction_ip: self.ip,
                            profile_start,
                        });
                    }
                    let _bigint_peak = self.preflight_bigint_add(dst, lhs, rhs)?;
                    let result_label = self.binary_operation_label(lhs, rhs)?;
                    let result = self.eval_add(Some(module), lhs, rhs)?;
                    self.write_reg_with_label(dst, result, result_label)?;
                    self.ip += 1;
                }
                Ir3Instruction::Sub { dst, lhs, rhs } => {
                    let result_label = self.binary_operation_label(lhs, rhs)?;
                    let result = self.eval_arith(lhs, rhs, "sub")?;
                    self.write_reg_with_label(dst, result, result_label)?;
                    self.ip += 1;
                }
                Ir3Instruction::Mul { dst, lhs, rhs } => {
                    let result_label = self.binary_operation_label(lhs, rhs)?;
                    let result = self.eval_arith(lhs, rhs, "mul")?;
                    self.write_reg_with_label(dst, result, result_label)?;
                    self.ip += 1;
                }
                Ir3Instruction::Div { dst, lhs, rhs } => {
                    let result_label = self.binary_operation_label(lhs, rhs)?;
                    let result = self.eval_div(lhs, rhs)?;
                    self.write_reg_with_label(dst, result, result_label)?;
                    self.ip += 1;
                }
                Ir3Instruction::ForInInit { .. }
                | Ir3Instruction::ForInNext { .. }
                | Ir3Instruction::ForOfInit { .. }
                | Ir3Instruction::ForOfNext { .. }
                | Ir3Instruction::IteratorClose { .. } => {
                    return Ok(DispatchOutcome::ReentrantInstruction {
                        instruction_ip: self.ip,
                        profile_start,
                    });
                }
                Ir3Instruction::Move { dst, src } => {
                    if !self.static_move(dst, src) {
                        let result_label = self.unary_operation_label(src)?;
                        let val = self.read_reg(src)?;
                        self.write_reg_with_label(dst, val, result_label)?;
                    }
                    self.ip += 1;
                }
                Ir3Instruction::Jump { target } => {
                    let target_ip = target as usize;

                    // JIT: Record loop iteration if this is a backedge (backward jump)
                    if target_ip < self.ip {
                        if self.jit_record_loop_iteration(self.ip) {
                            let iteration_count = self.jit_get_loop_iteration_count(self.ip);
                            self.emit_tier_promotion_event(0, iteration_count); // 0 = loop context, not function-specific
                        }
                    }

                    self.ip = target_ip;
                }
                Ir3Instruction::JumpIf { cond, target } => {
                    self.push_branch_pc_label_if_tainted(module, cond)?;
                    let val = self.read_reg(cond)?;
                    if val.is_truthy() {
                        let target_ip = target as usize;

                        // JIT: Record loop iteration if this is a backedge (backward jump)
                        if target_ip < self.ip {
                            if self.jit_record_loop_iteration(self.ip) {
                                let iteration_count = self.jit_get_loop_iteration_count(self.ip);
                                self.emit_tier_promotion_event(0, iteration_count); // 0 = loop context, not function-specific
                            }
                        }

                        self.ip = target_ip;
                    } else {
                        self.ip += 1;
                    }
                }
                Ir3Instruction::JumpIfNullish { cond, target } => {
                    self.push_branch_pc_label_if_tainted(module, cond)?;
                    let val = self.read_reg(cond)?;
                    if val.is_nullish() {
                        let target_ip = target as usize;

                        // JIT: Record loop iteration if this is a backedge (backward jump)
                        if target_ip < self.ip {
                            if self.jit_record_loop_iteration(self.ip) {
                                let iteration_count = self.jit_get_loop_iteration_count(self.ip);
                                self.emit_tier_promotion_event(0, iteration_count); // 0 = loop context, not function-specific
                            }
                        }

                        self.ip = target_ip;
                    } else {
                        self.ip += 1;
                    }
                }
                Ir3Instruction::Call { callee, args, dst } => {
                    let callee_val = self.read_reg(callee)?;

                    if let Value::BuiltinFunction(builtin) = callee_val {
                        // `Promise(...)` without `new` throws (ES2020 25.6.3.1
                        // step 1, bd-auy04); only [[Construct]] reaches
                        // `construct_promise`.
                        if builtin.kind == BuiltinFunctionKind::PromiseConstructor {
                            return Err(InterpreterError::TypeError {
                                expected: "new Promise(executor)".to_string(),
                                got: "Promise constructor called without new".to_string(),
                            });
                        }
                        return Ok(DispatchOutcome::BuiltinCall {
                            builtin,
                            callee,
                            args,
                            dst,
                            receiver: None,
                        });
                    }

                    // bd-9vouw.26: an async call runs in its own isolated
                    // activation (see `isolated_async_entry_pending`).
                    let isolate_async_call = matches!(callee_val, Value::AsyncFunction(_))
                        && !std::mem::take(&mut self.isolated_async_entry_pending);
                    if isolate_async_call
                        || self.foreign_closure_module(&callee_val, module)?.is_some()
                    {
                        let call_labels =
                            self.clone_isolated_call_labels_from_registers(None, args)?;
                        let callee_reg_label = self.get_register_label(callee)?.clone();
                        let isolated_context_label = match self.active_execution_context_label() {
                            Some(active) => Some(active.join(&callee_reg_label)),
                            None if callee_reg_label > Label::Public => Some(callee_reg_label),
                            None => None,
                        };
                        let arguments = self.call_arguments(args)?;
                        // An async call from the armed loop may collect inside
                        // the callee: this handler holds nothing the snapshot
                        // and the call's pins do not (bd-9vouw.77).
                        let call = |this: &mut Self| {
                            this.invoke_inline_method_call_with_labels(
                                Some(module),
                                callee_val.clone(),
                                Value::Undefined,
                                arguments,
                                isolated_context_label,
                                call_labels,
                            )
                        };
                        let call_result = if isolate_async_call {
                            self.with_gc_nested_request(Vec::new(), call)
                        } else {
                            call(self)
                        };
                        let (result, result_label) = match call_result {
                            Ok(value) => value,
                            Err(err) => match self.route_isolated_explicit_throw(module, err)? {
                                None => continue,
                                Some(err) => return Err(err),
                            },
                        };
                        // The isolated wrapper installs `argument_label` as its
                        // active context, so every successful result register
                        // and every re-armed explicit throw already carries the
                        // aggregate. Moving it into the wrapper avoids retaining
                        // a second attacker-sized String in the caller.
                        self.write_reg_with_label(dst, result, result_label)?;
                        self.ip += 1;
                        continue;
                    }

                    // Resolve function index and optional captured environment.
                    let (func_idx, mut captured_env) = match &callee_val {
                        Value::Function(idx) => (*idx, None),
                        Value::Closure(closure_id)
                        | Value::GeneratorFunction(closure_id)
                        | Value::AsyncFunction(closure_id)
                        | Value::AsyncGeneratorFunction(closure_id) => {
                            let closure =
                                self.closures.get(*closure_id as usize).ok_or_else(|| {
                                    InterpreterError::TypeError {
                                        expected: "valid closure".to_string(),
                                        got: format!("closure#{closure_id} not found"),
                                    }
                                })?;
                            (
                                closure.function_index,
                                Some(self.clone_scope_frames_with_budget(&closure.captured_env)?),
                            )
                        }
                        _ => {
                            return Err(InterpreterError::TypeError {
                                expected: "function".to_string(),
                                got: callee_val.type_name().to_string(),
                            });
                        }
                    };

                    // JIT: Record function call for hot path detection
                    if self.jit_record_function_call(func_idx) {
                        let call_count = self.jit_get_function_call_count(func_idx);
                        self.emit_tier_promotion_event(func_idx, call_count);
                    }

                    // Generator function call: create a suspended GeneratorObject.
                    if let Value::GeneratorFunction(cid) = &callee_val {
                        let (arguments, argument_labels) =
                            self.capture_generator_arguments(args)?;
                        let callee_reg_label = self.get_register_label(callee)?.clone();
                        let gen_context_label = match self.active_execution_context_label() {
                            Some(active) => Some(active.join(&callee_reg_label)),
                            None if callee_reg_label > Label::Public => {
                                Some(callee_reg_label.clone())
                            }
                            None => None,
                        };
                        let owner_module = self.continuation_owner_module(*cid, module)?;
                        let (module_specifier, generated_function_artifact) =
                            self.closure_execution_provenance(&callee_val, module)?;
                        let prototype = self.generator_instance_prototype(module, &callee_val)?;
                        let gen_id = self.push_generator_object(GeneratorObject {
                            owner_module,
                            invocation: Some(GeneratorInvocation {
                                function_index: func_idx,
                                closure_index: Some(*cid),
                                arguments,
                                argument_labels,
                                this_value: Value::Undefined,
                                this_label: Label::Public,
                                inline_context_label: gen_context_label.clone(),
                                module_specifier: Some(module_specifier),
                                generated_function_artifact,
                            }),
                            execution: None,
                            resume_dst: None,
                            phase: GeneratorPhase::SuspendedStart,
                            prototype,
                        })?;
                        let gen_dst_label = gen_context_label.unwrap_or(callee_reg_label);
                        if let Err(error) =
                            self.write_reg_with_label(dst, Value::Generator(gen_id), gen_dst_label)
                        {
                            self.pop_generator_object_and_release();
                            return Err(error);
                        }
                        if let Err(error) = self.start_generator_through_prologue(module, gen_id) {
                            match self.route_isolated_explicit_throw(module, error)? {
                                None => continue,
                                Some(error) => return Err(error),
                            }
                        }
                        self.ip += 1;
                        continue;
                    }

                    // Async function call: create a suspended AsyncFunctionObject and result Promise.
                    if let Value::AsyncFunction(cid) = &callee_val {
                        let owner_module = self.continuation_owner_module(*cid, module)?;
                        let func = module.function_table.get(func_idx as usize).ok_or(
                            InterpreterError::FunctionNotFound {
                                index: func_idx,
                                table_size: module.function_table.len() as u32,
                            },
                        )?;

                        let effective_depth = self.effective_call_depth();
                        if effective_depth >= self.config.max_call_depth {
                            // Capture stack limit enforcement for deterministic replay
                            self.nondeterminism_trace.capture(
                                NondeterminismSource::StackLimitEnforcement,
                                format!(
                                    "async_stack_overflow:depth={},max={}",
                                    effective_depth, self.config.max_call_depth
                                )
                                .into_bytes(),
                                self.instructions_executed,
                                "baseline_interpreter",
                            );
                            return Err(InterpreterError::StackOverflow {
                                depth: effective_depth,
                                max: self.config.max_call_depth,
                            });
                        }

                        let mut arg_vals = Vec::new();
                        let mut arg_labels = Vec::new();
                        for i in 0..args.count.min(func.arity) {
                            let reg = args.start.checked_add(i).ok_or(
                                InterpreterError::RegisterOutOfBounds {
                                    register: args.start,
                                    max: self.config.max_registers,
                                },
                            )?;
                            arg_vals.push(self.read_reg(reg)?);
                            arg_labels.push(self.get_register_label(reg)?.clone());
                        }
                        self.apply_rest_param(&mut arg_vals, func.rest_param_index, args)?;
                        self.apply_rest_param_labels(&mut arg_labels, func.rest_param_index, args)?;
                        self.stage_arguments_object(module, func, func_idx, &callee_val, args)?;

                        self.run_pre_call_hook(module, &callee_val, func_idx, &arg_vals)?;
                        let captured_env_bytes = captured_env
                            .as_ref()
                            .map(|env| Self::estimate_scope_chain_bytes(env))
                            .unwrap_or(0);

                        // Everything after Promise creation is one instruction
                        // transaction. A later scope/register refusal must not
                        // publish the Promise, async object, destination value,
                        // or a partial callee frame.
                        let previous_estimated_bytes = self.estimated_memory_bytes;
                        let setup_snapshot = self.snapshot_module_execution()?;
                        let mut created_promise = None;
                        let mut async_object_created = false;
                        let setup_result = (|| -> Result<(), InterpreterError> {
                            let result_promise_handle = self.create_promise()?;
                            created_promise = Some(result_promise_handle);
                            let result_promise = result_promise_handle.0;
                            let async_id =
                                self.push_async_function_object(AsyncFunctionObject {
                                    owner_module,
                                    isolated_execution: None,
                                    function_index: func_idx,
                                    closure_index: Some(*cid),
                                    saved_ip: 0,
                                    saved_registers: Vec::new(),
                                    saved_register_labels: Vec::new(),
                                    saved_register_base: 0,
                                    phase: AsyncFunctionPhase::Executing,
                                    result_promise,
                                })?;
                            async_object_created = true;
                            let callee_reg_label = self.get_register_label(callee)?.clone();
                            let (super_value, super_label, super_home_object) = self
                                .closure_super_binding(&callee_val, callee, captured_env_bytes)?;
                            self.write_reg_with_label(
                                dst,
                                Value::Promise(result_promise),
                                super_label.join(&callee_reg_label),
                            )?;
                            let super_label = self
                                .clone_register_label_with_additional_temporary_budget(
                                    dst,
                                    captured_env_bytes,
                                )?;
                            let binding_temporary_bytes = captured_env_bytes
                                .saturating_add(Self::estimate_label_bytes(&super_label));
                            let lexical_this = self.clone_closure_lexical_this_binding(
                                &callee_val,
                                binding_temporary_bytes,
                            )?;
                            // A plain call's `this` is undefined (ES2020 9.2.1.2
                            // OrdinaryCallBindThis; sloppy functions' global object
                            // is not modeled). Only an arrow has a lexical `this`,
                            // recorded at its creation; every other closure used to
                            // inherit the caller frame's, so `g()` inside a method
                            // saw the method's receiver and the
                            // `if (!(this instanceof F)) return new F()` factory
                            // ran its body on that receiver instead.
                            let (call_this, call_this_label) =
                                lexical_this.unwrap_or((Value::Undefined, Label::Public));
                            let call_this_temporary_bytes = Self::estimate_value_bytes(&call_this)
                                .saturating_add(Self::estimate_label_bytes(&call_this_label));

                            let scope_depth = self.scope_chain.depth();
                            let saved_chain = if captured_env.is_some() {
                                Some(
                                    self.snapshot_scope_chain_with_temporary_budget(
                                        binding_temporary_bytes
                                            .saturating_add(call_this_temporary_bytes),
                                    )?,
                                )
                            } else {
                                None
                            };
                            let previous_scope_bytes = self.scope_chain_memory_bytes();
                            let previous_closure_bytes = self.closures_memory_bytes();
                            let previous_call_stack_bytes = self.call_stack_memory_bytes();

                            let pushed_frame = CallFrame {
                                return_ip: self.ip + 1,
                                return_reg: dst,
                                register_base: self.register_base,
                                register_width: self.register_width,
                                function_index: Some(func_idx),
                                this_value: call_this,
                                this_label: call_this_label,
                                new_target_value: Value::Undefined,
                                new_target_label: Label::Public,
                                super_value,
                                super_label,
                                super_home_object,
                                construct_this: None,
                                derived_constructor: false,
                                this_initialized: true,
                                initialize_derived_this_on_return: false,
                                class_instance_fields: None,
                                saved_pending_exception: self.pending_exception.take(),
                                saved_pending_exception_label: std::mem::replace(
                                    &mut self.pending_exception_label,
                                    Label::Public,
                                ),
                                saved_pending_return: self.pending_return.take(),
                                saved_suspended_abrupt_depth: self
                                    .suspended_abrupt_completions
                                    .len(),
                                saved_finally_mode_depth: self.finally_frames.len(),
                                saved_scope_depth: scope_depth,
                                saved_scope_chain: saved_chain,
                                scope_inert_virtual_scope_bytes: 0,
                                async_function_id: Some(async_id),
                                native_boundary: false,
                            };
                            self.call_stack
                                .push(pushed_frame, &mut self.closures.cold_cells);

                            if let Some(env) = captured_env {
                                self.scope_chain.frames = env;
                            }
                            self.scope_chain.push(self.config.max_scope_depth)?;
                            self.apply_scope_closure_call_stack_memory_delta(
                                previous_scope_bytes,
                                previous_closure_bytes,
                                previous_call_stack_bytes,
                            )?;

                            // Async suspension snapshots retain the historical
                            // full register window. Keep their entry reset
                            // unchanged until snapshot width is independently
                            // verified and measured.
                            self.enter_stacked_register_frame(None)?;
                            self.push_callee_pc_label(callee_reg_label);
                            for (i, (val, label)) in
                                arg_vals.into_iter().zip(arg_labels).enumerate()
                            {
                                let reg = i as u32;
                                if reg < self.config.max_registers {
                                    self.write_reg_with_label(reg, val, label)?;
                                }
                            }
                            self.ip = func.entry as usize;
                            Ok(())
                        })();
                        if let Err(error) = setup_result {
                            if async_object_created {
                                self.pop_async_function_object_and_release();
                            }
                            if let Some(handle) = created_promise {
                                self.rollback_fresh_promise(handle);
                            }
                            self.restore_module_execution(setup_snapshot, false);
                            self.estimated_memory_bytes = previous_estimated_bytes;
                            return Err(error);
                        }
                        self.discard_module_execution_snapshot(setup_snapshot);
                        continue;
                    }

                    // Async generator function call: create a suspended AsyncGeneratorObject.
                    if let Value::AsyncGeneratorFunction(cid) = &callee_val {
                        let (arguments, argument_labels) =
                            self.capture_generator_arguments(args)?;
                        let callee_reg_label = self.get_register_label(callee)?.clone();
                        let async_gen_context_label = match self.active_execution_context_label() {
                            Some(active) => Some(active.join(&callee_reg_label)),
                            None if callee_reg_label > Label::Public => {
                                Some(callee_reg_label.clone())
                            }
                            None => None,
                        };
                        let owner_module = self.continuation_owner_module(*cid, module)?;
                        let (module_specifier, generated_function_artifact) =
                            self.closure_execution_provenance(&callee_val, module)?;
                        let prototype = self.generator_instance_prototype(module, &callee_val)?;
                        let async_gen_id = self.create_async_generator(
                            owner_module,
                            GeneratorInvocation {
                                function_index: func_idx,
                                closure_index: Some(*cid),
                                arguments,
                                argument_labels,
                                this_value: Value::Undefined,
                                this_label: Label::Public,
                                inline_context_label: async_gen_context_label.clone(),
                                module_specifier: Some(module_specifier),
                                generated_function_artifact,
                            },
                            prototype,
                        )?;
                        let async_gen_dst_label =
                            async_gen_context_label.unwrap_or(callee_reg_label);
                        if let Err(error) = self.write_reg_with_label(
                            dst,
                            Value::AsyncGeneratorObject(async_gen_id),
                            async_gen_dst_label,
                        ) {
                            self.pop_async_generator_object_and_release();
                            self.pop_generator_object_and_release();
                            return Err(error);
                        }
                        // bd-9vouw.49: an async generator binds its parameters
                        // at the call too, and a parameter error throws from
                        // the call (it does not reject a later next()).
                        let backing = self.async_generators[async_gen_id as usize].generator_id;
                        if let Err(error) = self.start_generator_through_prologue(module, backing) {
                            self.complete_async_generator_activation(async_gen_id);
                            match self.route_isolated_explicit_throw(module, error)? {
                                None => continue,
                                Some(error) => return Err(error),
                            }
                        }
                        self.ip += 1;
                        continue;
                    }

                    match &callee_val {
                        Value::Function(_) | Value::Closure(_) => {
                            // Try to get the function from the module's function table
                            let func_result = module.function_table.get(func_idx as usize);

                            // If the function is not found, check if it's a builtin
                            let func = if let Some(f) = func_result {
                                f
                            } else {
                                // Function not found in module table - check if it's a builtin
                                if let Some(builtin_cap) =
                                    self.map_function_index_to_builtin_capability(func_idx)
                                {
                                    // Apply capability gate - same security check as HostCall
                                    check_hostcall_capability_gate(
                                        self,
                                        &builtin_cap,
                                        self.ip as u32,
                                    )?;

                                    // Capability granted - dispatch as a builtin hostcall
                                    self.clear_pending_hostcall_result_label();
                                    let result = self.dispatch_builtin_hostcall(
                                        &builtin_cap,
                                        args,
                                        Some(module),
                                    )?;
                                    let result_label = self
                                        .take_pending_hostcall_result_label()
                                        .unwrap_or(Label::Public)
                                        .join(&self.join_arg_range_label(args)?)
                                        .join(self.get_register_label(callee)?);
                                    self.write_reg_with_label(dst, result, result_label)?;
                                    self.ip += 1;
                                    continue;
                                } else {
                                    // Not a builtin either - return original error
                                    return Err(InterpreterError::FunctionNotFound {
                                        index: func_idx,
                                        table_size: module.function_table.len() as u32,
                                    });
                                }
                            };
                            let scope_inert_activation = compact_tier1
                                .is_some_and(|plan| plan.scope_inert_leaf_function(func_idx));
                            let has_captured_env = captured_env.is_some();

                            let effective_depth = self.effective_call_depth();
                            if effective_depth >= self.config.max_call_depth {
                                return Err(InterpreterError::StackOverflow {
                                    depth: effective_depth,
                                    max: self.config.max_call_depth,
                                });
                            }

                            let (mut arg_vals, mut arg_labels) = self.take_call_argument_scratch();
                            for i in 0..args.count.min(func.arity) {
                                let reg = args.start.checked_add(i).ok_or(
                                    InterpreterError::RegisterOutOfBounds {
                                        register: args.start,
                                        max: self.config.max_registers,
                                    },
                                )?;
                                arg_vals.push(self.read_reg(reg)?);
                                arg_labels.push(self.get_register_label(reg)?.clone());
                            }
                            self.apply_rest_param(&mut arg_vals, func.rest_param_index, args)?;
                            self.apply_rest_param_labels(
                                &mut arg_labels,
                                func.rest_param_index,
                                args,
                            )?;
                            self.stage_arguments_object(module, func, func_idx, &callee_val, args)?;

                            self.run_pre_call_hook(module, &callee_val, func_idx, &arg_vals)?;

                            // Push frame. For closure calls, save the
                            // entire caller scope chain so it can be
                            // restored on return (the closure replaces
                            // the chain with its captured environment).
                            let captured_env_bytes = captured_env
                                .as_ref()
                                .map(|env| Self::estimate_scope_chain_bytes(env))
                                .unwrap_or(0);
                            let callee_reg_label = self.get_register_label(callee)?.clone();
                            let (super_value, super_label, super_home_object) = self
                                .closure_super_binding(&callee_val, callee, captured_env_bytes)?;
                            let binding_temporary_bytes = captured_env_bytes
                                .saturating_add(Self::estimate_label_bytes(&super_label));
                            let lexical_this = self.clone_closure_lexical_this_binding(
                                &callee_val,
                                binding_temporary_bytes,
                            )?;
                            // A plain call's `this` is undefined; only an arrow's
                            // creation-time `this` is lexical (see the Call arm).
                            let (call_this, call_this_label) =
                                lexical_this.unwrap_or((Value::Undefined, Label::Public));
                            let call_this_temporary_bytes = Self::estimate_value_bytes(&call_this)
                                .saturating_add(Self::estimate_label_bytes(&call_this_label));
                            let scope_depth = self.scope_chain.depth();
                            let virtual_scope_depth = captured_env
                                .as_ref()
                                .map_or(scope_depth, |environment| environment.len());
                            let saved_chain = if has_captured_env {
                                if scope_inert_activation {
                                    self.preflight_scope_chain_snapshot_with_temporary_budget(
                                        binding_temporary_bytes
                                            .saturating_add(call_this_temporary_bytes),
                                    )?;
                                    // Retain the already-budgeted captured
                                    // structure in the frame. It is not active
                                    // on the hot path, but its shallow snapshot
                                    // projection exactly replaces the captured
                                    // chain that Tier-R would have installed.
                                    captured_env.take()
                                } else {
                                    Some(
                                        self.snapshot_scope_chain_with_temporary_budget(
                                            binding_temporary_bytes
                                                .saturating_add(call_this_temporary_bytes),
                                        )?,
                                    )
                                }
                            } else {
                                None
                            };
                            if scope_inert_activation {
                                ScopeChain::preflight_push_depth(
                                    virtual_scope_depth,
                                    self.config.max_scope_depth,
                                )?;
                            }
                            // bd-9vouw.31: every cell of a closure's captured
                            // environment is in the cold ledger, and the
                            // caller's chain stays reachable as the new frame's
                            // saved chain, so installing the callee's chain
                            // changes only structural scope bytes.
                            let previous_scope_bytes = (!scope_inert_activation)
                                .then(|| self.scope_chain_structural_bytes());
                            #[cfg(debug_assertions)]
                            let walked_scope_before =
                                (!scope_inert_activation).then(|| self.scope_chain_memory_bytes());
                            let previous_closure_bytes =
                                (!scope_inert_activation).then(|| self.closures_memory_bytes());
                            let previous_call_stack_bytes = self.call_stack_memory_bytes();

                            let pushed_frame = CallFrame {
                                return_ip: self.ip + 1,
                                return_reg: dst,
                                register_base: self.register_base,
                                register_width: self.register_width,
                                function_index: Some(func_idx),
                                this_value: call_this,
                                this_label: call_this_label,
                                new_target_value: Value::Undefined,
                                new_target_label: Label::Public,
                                super_value,
                                super_label,
                                super_home_object,
                                construct_this: None,
                                derived_constructor: false,
                                this_initialized: true,
                                initialize_derived_this_on_return: false,
                                class_instance_fields: None,
                                saved_pending_exception: self.pending_exception.take(),
                                saved_pending_exception_label: std::mem::replace(
                                    &mut self.pending_exception_label,
                                    Label::Public,
                                ),
                                saved_pending_return: self.pending_return.take(),
                                saved_suspended_abrupt_depth: self
                                    .suspended_abrupt_completions
                                    .len(),
                                saved_finally_mode_depth: self.finally_frames.len(),
                                saved_scope_depth: scope_depth,
                                saved_scope_chain: saved_chain,
                                scope_inert_virtual_scope_bytes: if scope_inert_activation {
                                    MEMORY_ESTIMATE_SCOPE_FRAME_BASE_BYTES
                                } else {
                                    0
                                },
                                async_function_id: None,
                                native_boundary: false,
                            };
                            self.call_stack
                                .push(pushed_frame, &mut self.closures.cold_cells);

                            if scope_inert_activation {
                                if let Err(err) =
                                    self.apply_call_stack_memory_delta(previous_call_stack_bytes)
                                {
                                    self.rollback_call_setup_state();
                                    return Err(err);
                                }
                            } else {
                                // If calling a closure, restore its captured environment.
                                if let Some(env) = captured_env {
                                    self.scope_chain.frames = env;
                                }

                                // Push a fresh scope for the callee's locals.
                                if let Err(err) = self.scope_chain.push(self.config.max_scope_depth)
                                {
                                    self.rollback_call_setup_state();
                                    return Err(err);
                                }
                                let previous_scope_bytes =
                                    previous_scope_bytes.expect("ordinary scope accounting");
                                #[cfg(debug_assertions)]
                                self.debug_assert_scope_swap_delta(
                                    walked_scope_before.expect("ordinary scope accounting"),
                                    previous_scope_bytes,
                                    0,
                                );
                                if let Err(err) = self
                                    .apply_structural_scope_closure_call_stack_memory_delta(
                                        previous_scope_bytes,
                                        previous_closure_bytes
                                            .expect("ordinary closure accounting"),
                                        previous_call_stack_bytes,
                                    )
                                {
                                    self.rollback_call_setup_state();
                                    return Err(err);
                                }
                            }

                            self.enter_stacked_register_frame_for_function(
                                module,
                                compact_tier1,
                                func_idx,
                            )?;
                            self.push_callee_pc_label(callee_reg_label);

                            // Copy arguments into registers for the callee.
                            for (i, (val, label)) in
                                arg_vals.drain(..).zip(arg_labels.drain(..)).enumerate()
                            {
                                let reg = i as u32;
                                if reg < self.config.max_registers {
                                    self.write_reg_with_label(reg, val, label)?;
                                }
                            }
                            self.restore_call_argument_scratch(arg_vals, arg_labels);

                            self.ip = func.entry as usize;
                        }
                        _ => {
                            return Err(InterpreterError::TypeError {
                                expected: "function".to_string(),
                                got: callee_val.type_name().to_string(),
                            });
                        }
                    }
                }
                Ir3Instruction::CallMethod {
                    receiver,
                    callee,
                    args,
                    dst,
                } => {
                    let mut receiver_val = self.read_reg(receiver)?;
                    let mut callee_val = self.read_reg(callee)?;
                    let (mut receiver, mut callee, mut args) = (receiver, callee, args);

                    // `f.call(t, ...xs)` on an ordinary same-module function is
                    // the call `t.f(...xs)` whose operands already sit in
                    // registers: re-dispatch it in place rather than through an
                    // isolated activation, which snapshots the execution state
                    // and clones the whole module on every call. Generator,
                    // async and foreign callees keep the isolated path.
                    if let Value::BuiltinFunction(builtin) = &callee_val
                        && builtin.kind == BuiltinFunctionKind::FunctionPrototypeCall
                        && builtin.bound_object.is_none()
                        && args.count > 0
                        && matches!(receiver_val, Value::Closure(_) | Value::Function(_))
                        && self
                            .foreign_closure_module(&receiver_val, module)?
                            .is_none()
                    {
                        callee = receiver;
                        callee_val = receiver_val;
                        receiver = args.start;
                        receiver_val = self.read_reg(receiver)?;
                        args = RegRange {
                            start: args.start + 1,
                            count: args.count - 1,
                        };
                    }

                    // bd-9vouw.501: `f.apply(t, list)` and `Reflect.apply(f,
                    // t, list)` likewise, when building the list is
                    // unobservable (`unobservable_apply_arguments`): the list
                    // reaches the frame as overflow registers instead of an
                    // isolated activation running `f` in a nested run loop,
                    // which also capped a recursion through apply at the
                    // reentrant depth. A spread call arrives here rewritten
                    // from its Reflect.apply hostcall, its list taken.
                    let mut apply_arguments = spread_apply_arguments.take();
                    if apply_arguments.is_none()
                        && let Value::BuiltinFunction(builtin) = &callee_val
                        && builtin.bound_object.is_none()
                    {
                        let operands = match builtin.kind {
                            BuiltinFunctionKind::FunctionPrototypeApply if args.count >= 2 => {
                                Some((receiver, args.start, args.start + 1))
                            }
                            BuiltinFunctionKind::StaticHostcall
                                if args.count >= 3
                                    && &*builtin.module_specifier == "builtin:ReflectApply" =>
                            {
                                Some((args.start, args.start + 1, args.start + 2))
                            }
                            _ => None,
                        };
                        if let Some((function, this, list)) = operands
                            && let Some(values) = self.unobservable_apply_arguments(
                                module,
                                &[receiver, callee],
                                function,
                                this,
                                list,
                            )?
                        {
                            callee = function;
                            callee_val = self.read_reg(callee)?;
                            receiver = this;
                            receiver_val = self.read_reg(receiver)?;
                            args = RegRange {
                                start: self.config.max_registers,
                                count: values.len() as u32,
                            };
                            apply_arguments = Some(values);
                        }
                    }

                    if let Value::BuiltinFunction(builtin) = callee_val {
                        return Ok(DispatchOutcome::BuiltinCall {
                            builtin,
                            callee,
                            args,
                            dst,
                            receiver: Some((receiver_val, receiver)),
                        });
                    }

                    // bd-9vouw.26: an async call runs in its own isolated
                    // activation (see `isolated_async_entry_pending`).
                    let isolate_async_call = matches!(callee_val, Value::AsyncFunction(_))
                        && !std::mem::take(&mut self.isolated_async_entry_pending);
                    if isolate_async_call
                        || self.foreign_closure_module(&callee_val, module)?.is_some()
                    {
                        let call_labels =
                            self.clone_isolated_call_labels_from_registers(Some(receiver), args)?;
                        let callee_reg_label = self.get_register_label(callee)?.clone();
                        let isolated_context_label = match self.active_execution_context_label() {
                            Some(active) => Some(active.join(&callee_reg_label)),
                            None if callee_reg_label > Label::Public => Some(callee_reg_label),
                            None => None,
                        };
                        let arguments = self.call_arguments(args)?;
                        // An async call from the armed loop may collect inside
                        // the callee: this handler holds nothing the snapshot
                        // and the call's pins do not (bd-9vouw.77).
                        let call = |this: &mut Self| {
                            this.invoke_inline_method_call_with_labels(
                                Some(module),
                                callee_val.clone(),
                                receiver_val,
                                arguments,
                                isolated_context_label,
                                call_labels,
                            )
                        };
                        let call_result = if isolate_async_call {
                            self.with_gc_nested_request(Vec::new(), call)
                        } else {
                            call(self)
                        };
                        let (result, result_label) = match call_result {
                            Ok(value) => value,
                            Err(err) => match self.route_isolated_explicit_throw(module, err)? {
                                None => continue,
                                Some(err) => return Err(err),
                            },
                        };
                        self.write_reg_with_label(dst, result, result_label)?;
                        self.ip += 1;
                        continue;
                    }

                    let (func_idx, mut captured_env) = match &callee_val {
                        Value::Function(idx) => (*idx, None),
                        Value::Closure(closure_id)
                        | Value::GeneratorFunction(closure_id)
                        | Value::AsyncFunction(closure_id)
                        | Value::AsyncGeneratorFunction(closure_id) => {
                            let closure =
                                self.closures.get(*closure_id as usize).ok_or_else(|| {
                                    InterpreterError::TypeError {
                                        expected: "valid closure".to_string(),
                                        got: format!("closure#{closure_id} not found"),
                                    }
                                })?;
                            (
                                closure.function_index,
                                Some(self.clone_scope_frames_with_budget(&closure.captured_env)?),
                            )
                        }
                        _ => {
                            return Err(InterpreterError::TypeError {
                                expected: "function".to_string(),
                                got: callee_val.type_name().to_string(),
                            });
                        }
                    };

                    if let Value::GeneratorFunction(cid) = &callee_val {
                        self.mark_inline_callback_started();
                        let (arguments, argument_labels) =
                            self.capture_generator_arguments(args)?;
                        let receiver_label =
                            self.clone_register_label_with_temporary_budget(receiver)?;
                        let callee_reg_label = self.get_register_label(callee)?.clone();
                        let gen_context_label = match self.active_execution_context_label() {
                            Some(active) => Some(active.join(&callee_reg_label)),
                            None if callee_reg_label > Label::Public => {
                                Some(callee_reg_label.clone())
                            }
                            None => None,
                        };
                        let owner_module = self.continuation_owner_module(*cid, module)?;
                        let (module_specifier, generated_function_artifact) =
                            self.closure_execution_provenance(&callee_val, module)?;
                        let prototype = self.generator_instance_prototype(module, &callee_val)?;
                        let gen_id = self.push_generator_object(GeneratorObject {
                            owner_module,
                            invocation: Some(GeneratorInvocation {
                                function_index: func_idx,
                                closure_index: Some(*cid),
                                arguments,
                                argument_labels,
                                this_value: receiver_val.clone(),
                                this_label: receiver_label,
                                inline_context_label: gen_context_label.clone(),
                                module_specifier: Some(module_specifier),
                                generated_function_artifact,
                            }),
                            execution: None,
                            resume_dst: None,
                            phase: GeneratorPhase::SuspendedStart,
                            prototype,
                        })?;
                        let gen_dst_label = gen_context_label.unwrap_or(callee_reg_label);
                        if let Err(error) =
                            self.write_reg_with_label(dst, Value::Generator(gen_id), gen_dst_label)
                        {
                            self.pop_generator_object_and_release();
                            return Err(error);
                        }
                        if let Err(error) = self.start_generator_through_prologue(module, gen_id) {
                            match self.route_isolated_explicit_throw(module, error)? {
                                None => continue,
                                Some(error) => return Err(error),
                            }
                        }
                        self.ip += 1;
                        continue;
                    }

                    if let Value::AsyncFunction(cid) = &callee_val {
                        let owner_module = self.continuation_owner_module(*cid, module)?;
                        let func = module.function_table.get(func_idx as usize).ok_or(
                            InterpreterError::FunctionNotFound {
                                index: func_idx,
                                table_size: module.function_table.len() as u32,
                            },
                        )?;

                        let effective_depth = self.effective_call_depth();
                        if effective_depth >= self.config.max_call_depth {
                            return Err(InterpreterError::StackOverflow {
                                depth: effective_depth,
                                max: self.config.max_call_depth,
                            });
                        }

                        let mut arg_vals = Vec::new();
                        let mut arg_labels = Vec::new();
                        for i in 0..args.count.min(func.arity) {
                            let reg = args.start.checked_add(i).ok_or(
                                InterpreterError::RegisterOutOfBounds {
                                    register: args.start,
                                    max: self.config.max_registers,
                                },
                            )?;
                            arg_vals.push(self.read_reg(reg)?);
                            arg_labels.push(self.get_register_label(reg)?.clone());
                        }
                        self.mark_inline_callback_started();
                        self.apply_rest_param(&mut arg_vals, func.rest_param_index, args)?;
                        self.apply_rest_param_labels(&mut arg_labels, func.rest_param_index, args)?;
                        self.stage_arguments_object(module, func, func_idx, &callee_val, args)?;

                        self.run_pre_call_hook(module, &callee_val, func_idx, &arg_vals)?;
                        let captured_env_bytes = captured_env
                            .as_ref()
                            .map(|env| Self::estimate_scope_chain_bytes(env))
                            .unwrap_or(0);

                        let previous_estimated_bytes = self.estimated_memory_bytes;
                        let setup_snapshot = self.snapshot_module_execution()?;
                        let mut created_promise = None;
                        let mut async_object_created = false;
                        let setup_result = (|| -> Result<(), InterpreterError> {
                            let result_promise_handle = self.create_promise()?;
                            created_promise = Some(result_promise_handle);
                            let result_promise = result_promise_handle.0;
                            let async_id =
                                self.push_async_function_object(AsyncFunctionObject {
                                    owner_module,
                                    isolated_execution: None,
                                    function_index: func_idx,
                                    closure_index: Some(*cid),
                                    saved_ip: 0,
                                    saved_registers: Vec::new(),
                                    saved_register_labels: Vec::new(),
                                    saved_register_base: 0,
                                    phase: AsyncFunctionPhase::Executing,
                                    result_promise,
                                })?;
                            async_object_created = true;
                            let callee_reg_label = self.get_register_label(callee)?.clone();
                            let (super_value, super_label, super_home_object) = self
                                .closure_super_binding(&callee_val, callee, captured_env_bytes)?;
                            let binding_temporary_bytes = captured_env_bytes
                                .saturating_add(Self::estimate_label_bytes(&super_label));
                            let lexical_this = self.clone_closure_lexical_this_binding(
                                &callee_val,
                                binding_temporary_bytes,
                            )?;
                            let (call_this, call_this_label) = if let Some(binding) = lexical_this {
                                binding
                            } else {
                                self.clone_receiver_this_binding(
                                    &receiver_val,
                                    receiver,
                                    binding_temporary_bytes,
                                )?
                            };
                            let call_this_temporary_bytes = Self::estimate_value_bytes(&call_this)
                                .saturating_add(Self::estimate_label_bytes(&call_this_label));
                            self.write_reg_with_label(
                                dst,
                                Value::Promise(result_promise),
                                super_label.join(&callee_reg_label),
                            )?;
                            let super_label = self
                                .clone_register_label_with_additional_temporary_budget(
                                    dst,
                                    captured_env_bytes.saturating_add(call_this_temporary_bytes),
                                )?;

                            let scope_depth = self.scope_chain.depth();
                            let saved_chain = if captured_env.is_some() {
                                Some(
                                    self.snapshot_scope_chain_with_temporary_budget(
                                        captured_env_bytes
                                            .saturating_add(call_this_temporary_bytes)
                                            .saturating_add(Self::estimate_label_bytes(
                                                &super_label,
                                            )),
                                    )?,
                                )
                            } else {
                                None
                            };
                            let previous_scope_bytes = self.scope_chain_memory_bytes();
                            let previous_closure_bytes = self.closures_memory_bytes();
                            let previous_call_stack_bytes = self.call_stack_memory_bytes();
                            let pushed_frame = CallFrame {
                                return_ip: self.ip + 1,
                                return_reg: dst,
                                register_base: self.register_base,
                                register_width: self.register_width,
                                function_index: Some(func_idx),
                                this_value: call_this,
                                this_label: call_this_label,
                                new_target_value: Value::Undefined,
                                new_target_label: Label::Public,
                                super_value,
                                super_label,
                                super_home_object,
                                construct_this: None,
                                derived_constructor: false,
                                this_initialized: true,
                                initialize_derived_this_on_return: false,
                                class_instance_fields: None,
                                saved_pending_exception: self.pending_exception.take(),
                                saved_pending_exception_label: std::mem::replace(
                                    &mut self.pending_exception_label,
                                    Label::Public,
                                ),
                                saved_pending_return: self.pending_return.take(),
                                saved_suspended_abrupt_depth: self
                                    .suspended_abrupt_completions
                                    .len(),
                                saved_finally_mode_depth: self.finally_frames.len(),
                                saved_scope_depth: scope_depth,
                                saved_scope_chain: saved_chain,
                                scope_inert_virtual_scope_bytes: 0,
                                async_function_id: Some(async_id),
                                native_boundary: false,
                            };
                            self.call_stack
                                .push(pushed_frame, &mut self.closures.cold_cells);

                            if let Some(env) = captured_env {
                                self.scope_chain.frames = env;
                            }
                            self.scope_chain.push(self.config.max_scope_depth)?;
                            self.apply_scope_closure_call_stack_memory_delta(
                                previous_scope_bytes,
                                previous_closure_bytes,
                                previous_call_stack_bytes,
                            )?;

                            // Async suspension snapshots retain the historical
                            // full register window. Keep their entry reset
                            // unchanged until snapshot width is independently
                            // verified and measured.
                            self.enter_stacked_register_frame(None)?;
                            self.push_callee_pc_label(callee_reg_label);
                            for (i, (val, label)) in
                                arg_vals.into_iter().zip(arg_labels).enumerate()
                            {
                                let reg = i as u32;
                                if reg < self.config.max_registers {
                                    self.write_reg_with_label(reg, val, label)?;
                                }
                            }
                            self.ip = func.entry as usize;
                            Ok(())
                        })();
                        if let Err(error) = setup_result {
                            if async_object_created {
                                self.pop_async_function_object_and_release();
                            }
                            if let Some(handle) = created_promise {
                                self.rollback_fresh_promise(handle);
                            }
                            self.restore_module_execution(setup_snapshot, false);
                            self.estimated_memory_bytes = previous_estimated_bytes;
                            return Err(error);
                        }
                        self.discard_module_execution_snapshot(setup_snapshot);
                        continue;
                    }

                    if let Value::AsyncGeneratorFunction(cid) = &callee_val {
                        self.mark_inline_callback_started();
                        let (arguments, argument_labels) =
                            self.capture_generator_arguments(args)?;
                        let receiver_label =
                            self.clone_register_label_with_temporary_budget(receiver)?;
                        let callee_reg_label = self.get_register_label(callee)?.clone();
                        let async_gen_context_label = match self.active_execution_context_label() {
                            Some(active) => Some(active.join(&callee_reg_label)),
                            None if callee_reg_label > Label::Public => {
                                Some(callee_reg_label.clone())
                            }
                            None => None,
                        };
                        let owner_module = self.continuation_owner_module(*cid, module)?;
                        let (module_specifier, generated_function_artifact) =
                            self.closure_execution_provenance(&callee_val, module)?;
                        let prototype = self.generator_instance_prototype(module, &callee_val)?;
                        let async_gen_id = self.create_async_generator(
                            owner_module,
                            GeneratorInvocation {
                                function_index: func_idx,
                                closure_index: Some(*cid),
                                arguments,
                                argument_labels,
                                this_value: receiver_val.clone(),
                                this_label: receiver_label,
                                inline_context_label: async_gen_context_label.clone(),
                                module_specifier: Some(module_specifier),
                                generated_function_artifact,
                            },
                            prototype,
                        )?;
                        let async_gen_dst_label =
                            async_gen_context_label.unwrap_or(callee_reg_label);
                        if let Err(error) = self.write_reg_with_label(
                            dst,
                            Value::AsyncGeneratorObject(async_gen_id),
                            async_gen_dst_label,
                        ) {
                            self.pop_async_generator_object_and_release();
                            self.pop_generator_object_and_release();
                            return Err(error);
                        }
                        // bd-9vouw.49: an async generator binds its parameters
                        // at the call too, and a parameter error throws from
                        // the call (it does not reject a later next()).
                        let backing = self.async_generators[async_gen_id as usize].generator_id;
                        if let Err(error) = self.start_generator_through_prologue(module, backing) {
                            self.complete_async_generator_activation(async_gen_id);
                            match self.route_isolated_explicit_throw(module, error)? {
                                None => continue,
                                Some(error) => return Err(error),
                            }
                        }
                        self.ip += 1;
                        continue;
                    }

                    let func = module.function_table.get(func_idx as usize).ok_or(
                        InterpreterError::FunctionNotFound {
                            index: func_idx,
                            table_size: module.function_table.len() as u32,
                        },
                    )?;

                    let effective_depth = self.effective_call_depth();
                    if effective_depth >= self.config.max_call_depth {
                        return Err(InterpreterError::StackOverflow {
                            depth: effective_depth,
                            max: self.config.max_call_depth,
                        });
                    }

                    let (mut arg_vals, mut arg_labels) = self.take_call_argument_scratch();
                    // An apply list (bd-9vouw.501) is registers
                    // max_registers.. of this frame while the parameters,
                    // the rest parameter and `arguments` take it, and only
                    // then, whatever their outcome.
                    let overflow_depth = match apply_arguments.take() {
                        Some(values) => Some(self.install_apply_argument_overflow(values)?),
                        None => None,
                    };
                    let bound = (|| -> Result<(), InterpreterError> {
                        for i in 0..args.count.min(func.arity) {
                            let reg = args.start.checked_add(i).ok_or(
                                InterpreterError::RegisterOutOfBounds {
                                    register: args.start,
                                    max: self.config.max_registers,
                                },
                            )?;
                            arg_vals.push(self.read_reg(reg)?);
                            arg_labels.push(self.get_register_label(reg)?.clone());
                        }
                        self.mark_inline_callback_started();
                        self.apply_rest_param(&mut arg_vals, func.rest_param_index, args)?;
                        self.apply_rest_param_labels(&mut arg_labels, func.rest_param_index, args)?;
                        self.stage_arguments_object(module, func, func_idx, &callee_val, args)
                    })();
                    if let Some(depth) = overflow_depth {
                        self.restore_argument_overflow(depth);
                    }
                    bound?;

                    self.run_pre_call_hook(module, &callee_val, func_idx, &arg_vals)?;

                    // The callback trampoline, Function.prototype.call/apply,
                    // and ordinary methods all enter through CallMethod. Use
                    // the same verified scope-inert activation as Call: a
                    // leaf that cannot observe bindings needs no scope swap,
                    // while its virtual scope retains the exact budget charge
                    // and is materialized at a terminal error boundary.
                    let scope_inert_activation =
                        compact_tier1.is_some_and(|plan| plan.scope_inert_leaf_function(func_idx));
                    let has_captured_env = captured_env.is_some();
                    let captured_env_bytes = captured_env
                        .as_ref()
                        .map(|env| Self::estimate_scope_chain_bytes(env))
                        .unwrap_or(0);
                    let callee_reg_label = self.get_register_label(callee)?.clone();
                    let (super_value, super_label, super_home_object) =
                        self.closure_super_binding(&callee_val, callee, captured_env_bytes)?;
                    let binding_temporary_bytes =
                        captured_env_bytes.saturating_add(Self::estimate_label_bytes(&super_label));
                    let lexical_this = self
                        .clone_closure_lexical_this_binding(&callee_val, binding_temporary_bytes)?;
                    let (call_this, call_this_label) = if let Some(binding) = lexical_this {
                        binding
                    } else {
                        self.clone_receiver_this_binding(
                            &receiver_val,
                            receiver,
                            binding_temporary_bytes,
                        )?
                    };
                    let call_this_temporary_bytes = Self::estimate_value_bytes(&call_this)
                        .saturating_add(Self::estimate_label_bytes(&call_this_label));
                    let scope_depth = self.scope_chain.depth();
                    let virtual_scope_depth = captured_env
                        .as_ref()
                        .map_or(scope_depth, |environment| environment.len());
                    let saved_chain = if has_captured_env {
                        if scope_inert_activation {
                            self.preflight_scope_chain_snapshot_with_temporary_budget(
                                binding_temporary_bytes.saturating_add(call_this_temporary_bytes),
                            )?;
                            captured_env.take()
                        } else {
                            Some(self.snapshot_scope_chain_with_temporary_budget(
                                binding_temporary_bytes.saturating_add(call_this_temporary_bytes),
                            )?)
                        }
                    } else {
                        None
                    };
                    if scope_inert_activation {
                        ScopeChain::preflight_push_depth(
                            virtual_scope_depth,
                            self.config.max_scope_depth,
                        )?;
                    }
                    let previous_scope_bytes =
                        (!scope_inert_activation).then(|| self.scope_chain_memory_bytes());
                    let previous_closure_bytes =
                        (!scope_inert_activation).then(|| self.closures_memory_bytes());
                    let previous_call_stack_bytes = self.call_stack_memory_bytes();
                    let pushed_frame = CallFrame {
                        return_ip: self.ip + 1,
                        return_reg: dst,
                        register_base: self.register_base,
                        register_width: self.register_width,
                        function_index: Some(func_idx),
                        this_value: call_this,
                        this_label: call_this_label,
                        new_target_value: Value::Undefined,
                        new_target_label: Label::Public,
                        super_value,
                        super_label,
                        super_home_object,
                        construct_this: None,
                        derived_constructor: false,
                        this_initialized: true,
                        initialize_derived_this_on_return: false,
                        class_instance_fields: None,
                        saved_pending_exception: self.pending_exception.take(),
                        saved_pending_exception_label: std::mem::replace(
                            &mut self.pending_exception_label,
                            Label::Public,
                        ),
                        saved_pending_return: self.pending_return.take(),
                        saved_suspended_abrupt_depth: self.suspended_abrupt_completions.len(),
                        saved_finally_mode_depth: self.finally_frames.len(),
                        saved_scope_depth: scope_depth,
                        saved_scope_chain: saved_chain,
                        scope_inert_virtual_scope_bytes: if scope_inert_activation {
                            MEMORY_ESTIMATE_SCOPE_FRAME_BASE_BYTES
                        } else {
                            0
                        },
                        async_function_id: None,
                        native_boundary: false,
                    };
                    self.call_stack
                        .push(pushed_frame, &mut self.closures.cold_cells);

                    if scope_inert_activation {
                        if let Err(err) =
                            self.apply_call_stack_memory_delta(previous_call_stack_bytes)
                        {
                            self.rollback_call_setup_state();
                            return Err(err);
                        }
                    } else {
                        if let Some(env) = captured_env {
                            self.scope_chain.frames = env;
                        }
                        if let Err(err) = self.scope_chain.push(self.config.max_scope_depth) {
                            self.rollback_call_setup_state();
                            return Err(err);
                        }
                        if let Err(err) = self.apply_scope_closure_call_stack_memory_delta(
                            previous_scope_bytes.expect("ordinary scope accounting"),
                            previous_closure_bytes.expect("ordinary closure accounting"),
                            previous_call_stack_bytes,
                        ) {
                            self.rollback_call_setup_state();
                            return Err(err);
                        }
                    }

                    self.enter_stacked_register_frame_for_function(
                        module,
                        compact_tier1,
                        func_idx,
                    )?;
                    self.push_callee_pc_label(callee_reg_label);

                    for (i, (val, label)) in
                        arg_vals.drain(..).zip(arg_labels.drain(..)).enumerate()
                    {
                        let reg = i as u32;
                        if reg < self.config.max_registers {
                            self.write_reg_with_label(reg, val, label)?;
                        }
                    }
                    self.restore_call_argument_scratch(arg_vals, arg_labels);

                    self.ip = func.entry as usize;
                }
                Ir3Instruction::Return { value } => {
                    let return_val = self.read_reg(value)?;
                    let mut return_label =
                        self.clone_register_label_with_temporary_budget(value)?;
                    if let Some(context) = self.active_execution_context_label().cloned() {
                        return_label =
                            self.join_owned_label_with_temporary_budget(return_label, &context)?;
                    }
                    // A return from inside a finally overrides any in-flight
                    // exception, and a return from inside try/catch must still
                    // unwind through enclosing finally blocks before it can
                    // complete.
                    self.pending_finally_entry = None;
                    self.suspend_current_abrupt_completion()?;
                    self.replace_pending_abrupt_slots(
                        None,
                        Some(LabeledReturn {
                            value: return_val,
                            label: return_label,
                        }),
                    )?;
                    if let Some(finally_target) = self.pop_current_finally_target() {
                        self.pending_finally_entry = Some(PendingFinallyEntry {
                            target: finally_target,
                            mode: FinallyMode::Return,
                        });
                        self.ip = finally_target;
                    } else {
                        let pending_return = self
                            .take_pending_return_slot()
                            .expect("Return installed a pending completion before direct return");
                        match self.complete_return(
                            Some(module),
                            pending_return.value,
                            pending_return.label,
                        ) {
                            Ok(Some(completion)) => {
                                return Ok(DispatchOutcome::Complete(completion));
                            }
                            Ok(None) => {}
                            Err(error) => {
                                match self.route_isolated_explicit_throw(module, error)? {
                                    None => continue,
                                    Some(error) => return Err(error),
                                }
                            }
                        }
                    }
                }
                Ir3Instruction::HostCall {
                    capability, dst, ..
                } if self.suspend_at_generator_prologue
                    && capability.0 == crate::capability::GENERATOR_PROLOGUE_CAPABILITY =>
                {
                    // bd-9vouw.49: the call that created this generator ran its
                    // parameter prologue; suspend here as a yield that produces
                    // no result. The first next() resumes at the next
                    // instruction (its argument is discarded, as ES requires).
                    self.ip += 1;
                    self.write_reg(dst, Value::Undefined)?;
                    self.generator_yielded = true;
                    self.generator_resume_dst = Some(dst);
                    self.generator_result_label = Label::Public;
                    return Ok(DispatchOutcome::Complete(LabeledReturn {
                        value: Value::Undefined,
                        label: Label::Public,
                    }));
                }
                Ir3Instruction::HostCall { .. } => {
                    return Ok(DispatchOutcome::ReentrantInstruction {
                        instruction_ip: self.ip,
                        profile_start,
                    });
                }
                Ir3Instruction::ImportModule {
                    specifier,
                    dst,
                    import_attributes,
                } => {
                    self.pending_async_module_import = None;
                    check_hostcall_capability_gate(self, "module_load", self.ip as u32)?;
                    let specifier_label = self.join_arg_range_label(RegRange {
                        start: specifier,
                        count: 1,
                    })?;
                    self.emit_witness(
                        WitnessEventKind::HostcallDispatched,
                        Some("cap:module_load"),
                    );
                    let mut native_effect = false;
                    self.clear_pending_hostcall_result_label();
                    let namespace = self.dispatch_import_hostcall_with_native_effect_provenance(
                        "module_load",
                        RegRange {
                            start: specifier,
                            count: 1,
                        },
                        Some(module),
                        &import_attributes,
                        &mut native_effect,
                    )?;
                    let result_label = if native_effect && let Value::Object(object) = &namespace {
                        // Authentication and the import-bound checks already
                        // completed. A pure engine-owned effect namespace is
                        // not a source read, but its cached export graph and
                        // every getter observation still contribute provenance.
                        let state = self.native_builtin_state_label_with_floor(
                            module,
                            *object,
                            Label::Public,
                        )?;
                        let result =
                            self.join_owned_label_with_temporary_budget(state, &specifier_label)?;
                        let observed = self
                            .take_pending_hostcall_result_label()
                            .unwrap_or(Label::Public);
                        self.join_owned_label_with_temporary_budget(result, &observed)?
                    } else {
                        let observed = self
                            .take_pending_hostcall_result_label()
                            .unwrap_or(Label::Public);
                        hostcall_result_contract("module_load")
                            .result_label(&specifier_label, None)
                            .join(&observed)
                    };
                    self.write_reg_with_label(dst, namespace, result_label)?;
                    self.ip += 1;
                    if let Some((dependency, evaluation_promise)) =
                        self.pending_async_module_import.take()
                    {
                        self.suspend_on_async_module_dependency(evaluation_promise, dependency)?;
                        return Ok(DispatchOutcome::Complete(LabeledReturn {
                            value: Value::Undefined,
                            label: Label::Public,
                        }));
                    }
                }
                Ir3Instruction::ExportBinding {
                    name_pool_index,
                    src,
                } => {
                    let name = module
                        .constant_pool
                        .get(name_pool_index as usize)
                        .map(ToString::to_string)
                        .unwrap_or_else(|| format!("__export_{name_pool_index}"));
                    let value = self.read_reg(src)?;
                    let label = self.get_register_label(src)?.clone();
                    let export_name = JsString::from(name);
                    self.register_module_export_exact_labeled(export_name.clone(), value, label)?;
                    // bd-1lsy.4.10.1: the export of a scope-resident module
                    // binding (read, or initialized, just before) stays live:
                    // later writes to that binding republish it.
                    let local = match self
                        .ip
                        .checked_sub(1)
                        .and_then(|read| module.instructions.get(read))
                    {
                        Some(Ir3Instruction::LoadScoped {
                            dst,
                            name_pool_index,
                        }) if *dst == src => Some(*name_pool_index),
                        Some(Ir3Instruction::InitBinding {
                            name_pool_index,
                            src: initialized,
                        }) if *initialized == src => Some(*name_pool_index),
                        _ => None,
                    };
                    if let Some(local) = local
                        && let Some(specifier) = self.current_module_specifier.clone()
                    {
                        let local = Self::scoped_constant_name(module, local);
                        let cell = self
                            .scope_chain
                            .resolve(local.as_ref())
                            .map(|(_, binding)| Rc::clone(&binding.state));
                        if let Some(cell) = cell {
                            self.track_live_export(&cell, specifier, export_name)?;
                        }
                    }
                    self.ip += 1;
                }
                Ir3Instruction::GetProperty { obj, key, dst } => {
                    let obj_val = self.read_reg(obj)?;
                    let key_val = self.read_reg(key)?;
                    // ES2022 `o.#x` (PrivateGet): never a property lookup, so
                    // no prototype walk, Proxy trap or property hook.
                    if let Some(name) = self.class_private_name_key(&key_val) {
                        let (value, value_label) = self.private_get(module, &obj_val, name)?;
                        let mut label = self.binary_operation_label(obj, key)?;
                        label = self.join_owned_label_with_temporary_budget(label, &value_label)?;
                        if let Value::Closure(closure_id) = &value
                            && let Some(method) = self.closure_method_metadata.get(closure_id)
                        {
                            label = self.join_owned_label_with_temporary_budget(
                                label,
                                &method.definition_label,
                            )?;
                        }
                        if let Some(seeded) = self.seeded_register_label(dst).cloned() {
                            label = self.join_owned_label_with_temporary_budget(label, &seeded)?;
                        }
                        self.write_reg_with_label(dst, value, label)?;
                        self.ip += 1;
                        continue;
                    }
                    self.clear_pending_hostcall_result_label();
                    let key_val = self.member_key_primitive(module, &obj_val, key_val)?;
                    let property_key = self.executable_property_key_from_value(&key_val);
                    let object_id = match &obj_val {
                        Value::Object(object_id) => Some(*object_id),
                        _ => None,
                    };
                    let mut ordinary_own_property_read = object_id.and_then(|object_id| {
                        self.ordinary_own_property_fast_read(object_id, &property_key)
                    });
                    let ordinary_own_property_fast_path = ordinary_own_property_read.is_some();
                    // A data property's stored label from the fast read, for
                    // the owner-label join below (bd-9vouw.504).
                    let mut ordinary_own_property_label = None;
                    let has_hook_target = object_id.is_some()
                        || matches!(
                            &obj_val,
                            Value::BuiltinFunction(builtin)
                                if Self::builtin_function_property_object(builtin).is_some()
                        );
                    if !has_hook_target {
                        self.preflight_legacy_property_key_for_hook(&property_key)?;
                    }

                    self.legacy_regexp_read_label = None;
                    let mut result_label = self.binary_operation_label(obj, key)?;
                    if property_key.as_str() == Some("prototype")
                        && let Some((_, label)) =
                            self.constructor_prototype_override(module, &obj_val)?
                    {
                        result_label =
                            self.join_owned_label_with_temporary_budget(result_label, &label)?;
                    }
                    if let Value::Closure(closure_id) = &obj_val
                        && let Some(method) = self.closure_method_metadata.get(closure_id)
                    {
                        result_label = self.join_owned_label_with_temporary_budget(
                            result_label,
                            &method.definition_label,
                        )?;
                    }
                    if !ordinary_own_property_fast_path {
                        if let Some(binary_storage_label) =
                            object_id.and_then(|id| self.binary_storage_label_ref(id))
                        {
                            result_label = self.join_owned_label_with_temporary_budget(
                                result_label,
                                binary_storage_label,
                            )?;
                        }
                        if let Some(url_state_label) =
                            object_id.and_then(|id| self.url_state_label_ref(id))
                        {
                            result_label = self.join_owned_label_with_temporary_budget(
                                result_label,
                                url_state_label,
                            )?;
                        }
                        if let Some(cluster_state_label) =
                            object_id.and_then(|id| self.cluster_state_label_ref(id))
                        {
                            result_label = self.join_owned_label_with_temporary_budget(
                                result_label,
                                cluster_state_label,
                            )?;
                        }
                        let stream_state_label = if let Some(object_id) = object_id {
                            self.stream_state_label_with_temporary_budget(
                                object_id,
                                Self::estimate_label_bytes(&result_label),
                            )?
                        } else {
                            Label::Public
                        };
                        result_label = if result_label >= stream_state_label {
                            result_label
                        } else {
                            stream_state_label
                        };
                    }

                    // bd-9vouw.17: an own property stored on a user function's
                    // backing object (`F.x`, class statics) wins over the
                    // synthesized function members below. `prototype` keeps
                    // its dedicated path on a function with an intrinsic one;
                    // another function's (an arrow's, a bound function's) is
                    // an ordinary own property, as in function_own_get
                    // (bd-9vouw.277).
                    let authoritative_standard_backing = self
                        .authoritative_standard_constructor_backing(
                            module,
                            &obj_val,
                            &property_key,
                        )?;
                    let mut inherited_function_standard = None;
                    let function_backing = match &obj_val {
                        _ if authoritative_standard_backing.is_some() => {
                            authoritative_standard_backing
                        }
                        Value::Function(_)
                        | Value::Closure(_)
                        | Value::GeneratorFunction(_)
                        | Value::AsyncFunction(_)
                        | Value::AsyncGeneratorFunction(_)
                        | Value::BuiltinFunction(_)
                            if property_key.as_str() != Some("prototype")
                                || !self.function_has_intrinsic_prototype(&obj_val)
                                || self.function_backing_has_own_property(
                                    module,
                                    &obj_val,
                                    &property_key,
                                )? =>
                        {
                            match self.function_own_property_object(module, &obj_val)? {
                                // Own `name`/`length` are the function's (never
                                // inherited from a parent class). Once the
                                // backing object exists a deleted one reads
                                // Function.prototype's (`0`, `""`). Other keys
                                // may be statics inherited from the parent
                                // constructor (bd-9vouw.24).
                                Some(backing)
                                    if matches!(property_key.as_str(), Some("name" | "length")) =>
                                {
                                    if self.heap.get(backing.0 as usize).is_some_and(|object| {
                                        object.contains_own_runtime_property(&property_key)
                                    }) {
                                        Some(backing)
                                    } else {
                                        inherited_function_standard =
                                            Some(if property_key.as_str() == Some("length") {
                                                Value::Int(0)
                                            } else {
                                                Value::str("")
                                            });
                                        None
                                    }
                                }
                                Some(backing)
                                    if self.chain_contains_runtime_property(
                                        backing,
                                        &property_key,
                                    ) =>
                                {
                                    Some(backing)
                                }
                                _ => None,
                            }
                        }
                        _ => None,
                    };
                    // A function, generator object or iterator whose own
                    // properties lack the key continues its [[Get]] on its
                    // intrinsic prototype (after the match).
                    // A callable proxy's [[Get]] is its trap's (or its
                    // target's) answer, never continued here.
                    let inherited_base = if function_backing.is_none()
                        && !matches!(&obj_val, Value::BuiltinFunction(builtin)
                                if matches!(builtin.kind,
                                    BuiltinFunctionKind::CallableProxy
                                    | BuiltinFunctionKind::FunctionPrototype))
                    {
                        Self::function_intrinsic_prototype_name(&obj_val)
                            .or(self
                                .exotic_intrinsic_prototype_name(&obj_val)
                                .filter(|name| *name != "Promise"))
                            .map(|prototype| (prototype, obj_val.clone()))
                    } else {
                        None
                    };

                    // The prototype object a primitive base's property came
                    // from, for the stored-label join below.
                    let mut primitive_owner = None;
                    let prop = if let Some(value) = inherited_function_standard {
                        value
                    } else if let Some(backing) = function_backing {
                        self.run_pre_runtime_property_access_hook(module, backing, &property_key)?;
                        if authoritative_standard_backing.is_some() {
                            self.get_v(module, &obj_val, &property_key)?
                        } else {
                            self.proxy_aware_get_runtime_property(
                                Some(module),
                                backing,
                                &property_key,
                                obj_val.clone(),
                                0,
                            )?
                        }
                    } else {
                        match obj_val {
                            Value::Object(oid) => {
                                self.run_pre_runtime_property_access_hook(
                                    module,
                                    oid,
                                    &property_key,
                                )?;
                                if property_key.as_str() == Some("__proto__")
                                    && self.proto_key_reaches_accessor(oid)
                                {
                                    // `__proto__` reads the internal prototype link
                                    // (set by class `extends` and `o.__proto__ = p`),
                                    // not a data property (bd-ppfds). A function's
                                    // backing object reports as the function
                                    // (bd-9vouw.98). An own `__proto__` data
                                    // property or a null-prototype chain reads
                                    // as an ordinary property (bd-9vouw.318).
                                    let link = self.ordinary_get_prototype_of(oid)?;
                                    self.prototype_value_for_link(Some(module), link)
                                } else if let Some((value, stored_label)) =
                                    ordinary_own_property_read.take()
                                {
                                    ordinary_own_property_label = stored_label;
                                    // In a callback scope [[Get]] observes the
                                    // owner's shape label and the property's
                                    // stored label into the context, and
                                    // charges the step, before it resolves
                                    // (proxy_aware_get_runtime_property): the
                                    // same observation, at the same point
                                    // (bd-9vouw.505). A data property's stored
                                    // label is in hand (bd-9vouw.504).
                                    if self.active_inline_callback_context_label.is_some() {
                                        match &ordinary_own_property_label {
                                            Some(label) => {
                                                self.reflect_observe_own_data_property(oid, label)?
                                            }
                                            None => self.reflect_observe_selected_property(
                                                oid,
                                                &property_key,
                                            )?,
                                        }
                                    }
                                    self.capture_property_resolution_found(&property_key, oid, 0);
                                    self.resolve_accessor_get(
                                        Some(module),
                                        value,
                                        Value::Object(oid),
                                    )?
                                } else {
                                    self.proxy_aware_get_runtime_property(
                                        Some(module),
                                        oid,
                                        &property_key,
                                        Value::Object(oid),
                                        0,
                                    )?
                                }
                            }
                            Value::Iterator(iterator_handle) => {
                                match self.exotic_own_property_get(
                                    module,
                                    &Value::Iterator(iterator_handle),
                                    &property_key,
                                )? {
                                    // IFC: the backing object owns the stored label.
                                    Some((own, backing)) => {
                                        primitive_owner = Some(backing);
                                        own
                                    }
                                    None => self.iterator_runtime_property_value(
                                        iterator_handle,
                                        &property_key,
                                    ),
                                }
                            }
                            Value::Str(s) => {
                                if matches!(
                                    &property_key,
                                    RuntimePropertyKey::Symbol(symbol)
                                        if *symbol == WellKnownSymbol::Iterator.id()
                                ) {
                                    Value::BuiltinFunction(BuiltinFunction::string_iterator())
                                } else if let Some(own) = property_key
                                    .as_str()
                                    .and_then(|key| Self::string_own_property_value(&s, key))
                                {
                                    own
                                } else {
                                    let (value, owner) = self.primitive_prototype_get(
                                        module,
                                        "String",
                                        &property_key,
                                        Value::Str(s),
                                    )?;
                                    primitive_owner = owner;
                                    value
                                }
                            }
                            primitive @ (Value::Int(_)
                            | Value::Float(_)
                            | Value::Bool(_)
                            | Value::BigInt(_)) => {
                                let type_name = match primitive {
                                    Value::Bool(_) => "Boolean",
                                    Value::BigInt(_) => "BigInt",
                                    _ => "Number",
                                };
                                let (value, owner) = self.primitive_prototype_get(
                                    module,
                                    type_name,
                                    &property_key,
                                    primitive,
                                )?;
                                primitive_owner = owner;
                                value
                            }
                            // Functions are objects: reading `fn.prototype` returns the
                            // function's prototype object (where class instance methods
                            // live), matching what `Construct` links instances to so
                            // `new C().m()` resolves up the chain (bd-62un6).
                            Value::Closure(closure_id) => {
                                if let Some(key) = property_key.as_str() {
                                    let owner_module = self.foreign_closure_module(
                                        &Value::Closure(closure_id),
                                        module,
                                    )?;
                                    self.closure_property_value(
                                        owner_module.as_deref().unwrap_or(module),
                                        closure_id,
                                        key,
                                    )?
                                } else if Self::is_species_key(&property_key) {
                                    self.species_of_constructor(
                                        module,
                                        &Value::Closure(closure_id),
                                    )?
                                } else {
                                    Value::Undefined
                                }
                            }
                            Value::Function(idx) => {
                                if let Some(key) = property_key.as_str() {
                                    self.function_property_value(module, idx, key)?
                                } else if Self::is_species_key(&property_key) {
                                    self.species_of_constructor(module, &Value::Function(idx))?
                                } else {
                                    Value::Undefined
                                }
                            }
                            Value::BuiltinFunction(builtin) => {
                                if builtin.kind == BuiltinFunctionKind::GeneratedFunction
                                    && property_key.as_str() == Some("prototype")
                                {
                                    Value::Object(
                                        self.ensure_generated_function_prototype(&builtin)?,
                                    )
                                } else if builtin.kind == BuiltinFunctionKind::BoundFunction
                                    && let Some(key) = property_key.as_str()
                                    && let Some(value) =
                                        self.bound_function_property(&builtin, key)?
                                {
                                    value
                                } else if Self::is_species_key(&property_key)
                                    && let Some(species) = self.builtin_species_value(
                                        module,
                                        &builtin,
                                        Value::BuiltinFunction(builtin.clone()),
                                    )?
                                {
                                    // bd-9vouw.94, bd-9vouw.278: `get
                                    // [Symbol.species]() { return this }`
                                    // (ES2020 22.1.2.5 and the like).
                                    species
                                } else if property_key.as_str() == Some("prototype")
                                    && let Some(name) =
                                        Self::materialized_global_prototype_name(&builtin)
                                {
                                    // bd-9vouw.34: `Date.prototype` and
                                    // `Promise.prototype` are the realm's
                                    // intrinsics (non-writable in ES2020).
                                    self.builtin_prototype_value(name)?
                                } else if builtin.kind == BuiltinFunctionKind::Require
                                    && property_key.as_str() == Some("main")
                                {
                                    self.cjs_main_module()
                                } else if builtin.kind == BuiltinFunctionKind::Require
                                    && property_key.as_str() == Some("resolve")
                                {
                                    Value::BuiltinFunction(BuiltinFunction::require_resolve(
                                        &builtin,
                                    ))
                                } else if let Some(property_object) =
                                    Self::builtin_function_property_object(&builtin)
                                {
                                    self.run_pre_runtime_property_access_hook(
                                        module,
                                        property_object,
                                        &property_key,
                                    )?;
                                    self.proxy_aware_get_runtime_property(
                                        Some(module),
                                        property_object,
                                        &property_key,
                                        Value::BuiltinFunction(builtin),
                                        0,
                                    )?
                                } else if builtin.kind == BuiltinFunctionKind::StandardConstructor {
                                    let value = match property_key.as_str() {
                                        Some(key) => {
                                            self.standard_constructor_property(&builtin, key)?
                                        }
                                        None => Value::Undefined,
                                    };
                                    let constructor = Value::BuiltinFunction(builtin);
                                    match Self::native_error_constructor_parent(&constructor) {
                                        // A NativeError constructor inherits
                                        // Error's statics (ES2020 19.5.6.2):
                                        // `TypeError.captureStackTrace`.
                                        Some(parent) if matches!(value, Value::Undefined) => self
                                            .get_v_with_receiver(
                                            module,
                                            &parent,
                                            &property_key,
                                            constructor,
                                            1,
                                        )?,
                                        _ => value,
                                    }
                                } else {
                                    match property_key.as_str() {
                                        // bd-9vouw.17: a built-in's own `name`
                                        // and `length` (ES2020 17).
                                        Some(key @ ("name" | "length")) => self
                                            .function_standard_own_value(
                                                module,
                                                &Value::BuiltinFunction(builtin),
                                                key,
                                            )?
                                            .unwrap_or(Value::Undefined),
                                        key => key
                                            .and_then(Self::function_prototype_property)
                                            .unwrap_or(Value::Undefined),
                                    }
                                }
                            }
                            // Own `name` and `length` come from the function
                            // descriptor (or a concise method's name), like an
                            // ordinary closure's.
                            ref function @ (Value::GeneratorFunction(closure_id)
                            | Value::AsyncFunction(closure_id)
                            | Value::AsyncGeneratorFunction(closure_id)) => {
                                match property_key.as_str() {
                                    Some(key @ ("name" | "length")) => {
                                        if let (Some(metadata), "name") =
                                            (self.closure_method_metadata.get(&closure_id), key)
                                        {
                                            Value::Str(metadata.name.clone())
                                        } else {
                                            let owner_module =
                                                self.foreign_closure_module(function, module)?;
                                            let function_index =
                                                self.closure_function_index(closure_id)?;
                                            Self::function_name_or_length(
                                                owner_module.as_deref().unwrap_or(module),
                                                function_index,
                                                key,
                                            )
                                            .unwrap_or(Value::Undefined)
                                        }
                                    }
                                    // bd-9vouw.120: a generator function's
                                    // own `prototype` object.
                                    Some("prototype") => self
                                        .generator_function_prototype(module, function)?
                                        .unwrap_or(Value::Undefined),
                                    key => key
                                        .and_then(Self::function_prototype_property)
                                        .unwrap_or(Value::Undefined),
                                }
                            }
                            ref exotic @ (Value::Generator(_) | Value::AsyncGeneratorObject(_))
                                if self.exotic_has_own_property(
                                    module,
                                    exotic,
                                    &property_key,
                                )? =>
                            {
                                match self.exotic_own_property_get(module, exotic, &property_key)? {
                                    // IFC: the backing object owns the stored label.
                                    Some((own, backing)) => {
                                        primitive_owner = Some(backing);
                                        own
                                    }
                                    None => Value::Undefined,
                                }
                            }
                            Value::Generator(_) => match property_key {
                                RuntimePropertyKey::String(ref key) => match key.as_str() {
                                    Some("next") => {
                                        Value::BuiltinFunction(BuiltinFunction::new_kind(
                                            BuiltinFunctionKind::GeneratorNext,
                                        ))
                                    }
                                    Some("return") => {
                                        Value::BuiltinFunction(BuiltinFunction::new_kind(
                                            BuiltinFunctionKind::GeneratorReturn,
                                        ))
                                    }
                                    Some("throw") => {
                                        Value::BuiltinFunction(BuiltinFunction::new_kind(
                                            BuiltinFunctionKind::GeneratorThrow,
                                        ))
                                    }
                                    _ => Value::Undefined,
                                },
                                RuntimePropertyKey::Symbol(symbol)
                                    if symbol == WellKnownSymbol::Iterator.id() =>
                                {
                                    Value::BuiltinFunction(
                                        BuiltinFunction::generator_iterator_self(),
                                    )
                                }
                                _ => Value::Undefined,
                            },
                            Value::AsyncGeneratorObject(_) => match property_key {
                                RuntimePropertyKey::String(ref key) => match key.as_str() {
                                    Some("next") => {
                                        Value::BuiltinFunction(BuiltinFunction::new_kind(
                                            BuiltinFunctionKind::AsyncGeneratorNext,
                                        ))
                                    }
                                    Some("return") => {
                                        Value::BuiltinFunction(BuiltinFunction::new_kind(
                                            BuiltinFunctionKind::AsyncGeneratorReturn,
                                        ))
                                    }
                                    Some("throw") => {
                                        Value::BuiltinFunction(BuiltinFunction::new_kind(
                                            BuiltinFunctionKind::AsyncGeneratorThrow,
                                        ))
                                    }
                                    _ => Value::Undefined,
                                },
                                RuntimePropertyKey::Symbol(symbol)
                                    if symbol == WellKnownSymbol::AsyncIterator.id() =>
                                {
                                    Value::BuiltinFunction(BuiltinFunction::new_kind(
                                        BuiltinFunctionKind::AsyncGeneratorIteratorSelf,
                                    ))
                                }
                                _ => Value::Undefined,
                            },
                            // [[Get]] of a promise walks %Promise.prototype%
                            // (members a program adds, `constructor`, then
                            // Object.prototype), as for a primitive base.
                            // @@toStringTag is "Promise" (ES2020 25.6.5.5).
                            Value::Promise(promise) => {
                                if let Some((own, backing)) = self.exotic_own_property_get(
                                    module,
                                    &Value::Promise(promise),
                                    &property_key,
                                )? {
                                    // IFC: the backing object owns the stored label.
                                    primitive_owner = Some(backing);
                                    own
                                } else if let Some(prototype) = self
                                    .promise_prototype_override(module, &Value::Promise(promise))?
                                {
                                    // bd-9vouw.137: a subclass instance reads
                                    // through its subclass prototype, which
                                    // reaches %Promise.prototype%.
                                    primitive_owner = Some(prototype);
                                    let found = self.proxy_aware_get_runtime_property(
                                        Some(module),
                                        prototype,
                                        &property_key,
                                        Value::Promise(promise),
                                        0,
                                    )?;
                                    if matches!(found, Value::Undefined)
                                        && matches!(
                                            &property_key,
                                            RuntimePropertyKey::Symbol(symbol)
                                                if *symbol == WellKnownSymbol::ToStringTag.id()
                                        )
                                    {
                                        Value::str("Promise")
                                    } else {
                                        found
                                    }
                                } else if matches!(
                                    &property_key,
                                    RuntimePropertyKey::Symbol(symbol)
                                        if *symbol == WellKnownSymbol::ToStringTag.id()
                                ) {
                                    Value::str("Promise")
                                } else {
                                    let (value, owner) = self.primitive_prototype_get(
                                        module,
                                        "Promise",
                                        &property_key,
                                        Value::Promise(promise),
                                    )?;
                                    primitive_owner = owner;
                                    value
                                }
                            }
                            Value::Symbol(symbol) => match property_key.as_str() {
                                Some("description") => self
                                    .symbol_description(symbol)
                                    .map(Value::Str)
                                    .unwrap_or(Value::Undefined),
                                _ => {
                                    let (value, owner) = self.primitive_prototype_get(
                                        module,
                                        "Symbol",
                                        &property_key,
                                        Value::Symbol(symbol),
                                    )?;
                                    primitive_owner = owner;
                                    value
                                }
                            },
                            other => {
                                return Err(InterpreterError::TypeError {
                                    expected: "object".to_string(),
                                    got: self.nullish_access_subject(
                                        &other,
                                        &property_key,
                                        "reading",
                                    ),
                                });
                            }
                        }
                    };
                    // ES2020 19.2.3: a function's [[Prototype]] is
                    // %Function.prototype% (a generator, async or async
                    // generator function's is its kind's prototype, which
                    // inherits from it), so a key that neither its own
                    // properties nor its synthesized members supply is read
                    // there, then on Object.prototype: `fn.constructor` is
                    // Function (`g.constructor` GeneratorFunction), and
                    // `valueOf`, `__proto__` and members a program adds
                    // (`Function.prototype.method = ...`) reach every
                    // function. They read undefined. Generator objects and
                    // iterators reach %GeneratorPrototype% /
                    // %ArrayIteratorPrototype%, then Object.prototype, after
                    // their own methods (`it.toString`, `it[Symbol.toStringTag]`).
                    let prop = match inherited_base {
                        Some((prototype, base))
                            if matches!(prop, Value::Undefined) && primitive_owner.is_none() =>
                        {
                            if property_key.as_str() == Some("__proto__") && base.is_callable() {
                                self.function_value_prototype(Some(module), &base)?
                            } else if let Some(function_prototype) =
                                self.exotic_prototype_override(module, &base)?
                            {
                                // bd-9vouw.120: a generator inherits from its
                                // function's `prototype` (members a program
                                // adds there, then %GeneratorPrototype%).
                                primitive_owner = Some(function_prototype);
                                self.proxy_aware_get_runtime_property(
                                    Some(module),
                                    function_prototype,
                                    &property_key,
                                    base,
                                    0,
                                )?
                            } else {
                                // The kind prototypes exist once read, so
                                // Function.prototype's members are behind them.
                                if prototype != "Function" {
                                    self.ensure_builtin_prototype(prototype)?;
                                }
                                let (value, owner) = self.primitive_prototype_get(
                                    module,
                                    prototype,
                                    &property_key,
                                    base,
                                )?;
                                primitive_owner = owner;
                                value
                            }
                        }
                        _ => prop,
                    };
                    if let Value::Closure(closure_id) = &prop
                        && let Some(method) = self.closure_method_metadata.get(closure_id)
                    {
                        result_label = self.join_owned_label_with_temporary_budget(
                            result_label,
                            &method.definition_label,
                        )?;
                    }
                    // IFC: the read value's confidentiality is bounded below by
                    // the source object's label — a property of a Secret object
                    // is itself at least Secret. Join the object register's
                    // label onto dst (mirrors the BinaryOp/UnaryOp/HostCall
                    // propagation; without this, every property read under-taints
                    // and launders the object's label to the dst's stale prior
                    // value, enabling IFC confinement bypass — bd-0zybl, sibling
                    // of the HostCall gap bd-n2mjy). Conservative join (not bare
                    // overwrite) so a dst already carrying higher taint is never
                    // lowered by a property read. The seed join above covers the
                    // object and key operands; re-join the dst register's prior
                    // label here so the conservative (non-lowering) guarantee
                    // holds even after 1de697784/1e2abaff1 reseeded the join from
                    // (dst, obj) to (obj, key) — dropping (dst) alone would let a
                    // Public property read lower a dst that already held Secret
                    // (bd-0zybl regression).
                    // bd-ojvo1: join the value provenance recorded on the
                    // resolved property owner. This covers own/inherited exact
                    // string and Symbol keys while respecting shadowing.
                    // bd-9vouw.17: a function's backing object is the owner of
                    // its own properties, so their stored labels join too.
                    // The authoritative constructor path records the actual
                    // resolved owner's label during [[Get]]. Its storage's
                    // implicit Object.prototype chain is not the function's
                    // chain and must not override a Public shadow.
                    if let Some(owner) = object_id
                        .or(function_backing.filter(|_| authoritative_standard_backing.is_none()))
                        .or(primitive_owner)
                    {
                        // The fast read's owner is `object_id` itself, and a
                        // plain object never continues to an intrinsic
                        // prototype above (`inherited_base`).
                        let stored_label = match ordinary_own_property_label.take() {
                            Some(label) => label,
                            None => self.runtime_property_label(owner, &property_key),
                        };
                        result_label = self
                            .join_owned_label_with_temporary_budget(result_label, &stored_label)?;
                    }
                    // bd-9vouw.113: a legacy RegExp static carries its match's label.
                    if let Some(legacy_label) = self.legacy_regexp_read_label.take() {
                        result_label = self
                            .join_owned_label_with_temporary_budget(result_label, &legacy_label)?;
                    }
                    if let Some(seeded) = self.seeded_register_label(dst).cloned() {
                        result_label =
                            self.join_owned_label_with_temporary_budget(result_label, &seeded)?;
                    }
                    if let Some(observed_label) = self.take_pending_hostcall_result_label() {
                        result_label = self.join_owned_label_with_temporary_budget(
                            result_label,
                            &observed_label,
                        )?;
                    }
                    self.write_reg_with_label(dst, prop, result_label)?;
                    self.ip += 1;
                }
                Ir3Instruction::CreateDataProperty { obj, key, val } => {
                    let target = self.read_reg(obj)?;
                    let Value::Object(object_id) = target else {
                        return Err(InterpreterError::TypeError {
                            expected: "object for CreateDataProperty".to_string(),
                            got: target.type_name().to_string(),
                        });
                    };
                    // This opcode initializes ordinary literal allocations.
                    // Exotic definitions use the existing Reflect/Object
                    // intrinsic path, which owns trap and buffer IFC context.
                    if self.proxy_record(object_id)?.is_some()
                        || self.heap[object_id.0 as usize].typed_array.is_some()
                    {
                        return Err(InterpreterError::TypeError {
                            expected: "ordinary object or array literal target".to_string(),
                            got: "exotic object in CreateDataProperty".to_string(),
                        });
                    }
                    // Literal keys have already completed ToPropertyKey before
                    // their value expression runs. Defining them must not run
                    // that conversion again or invoke an inherited setter.
                    let key_value = self.read_reg(key)?;
                    let property_key = self.executable_property_key_from_value(&key_value);
                    self.run_pre_runtime_property_access_hook(module, object_id, &property_key)?;
                    let value = self.read_reg(val)?;
                    let value_label = self.get_register_label(val)?.clone();
                    let mutation_label = self
                        .get_register_label(obj)?
                        .join(self.get_register_label(key)?)
                        .join(&value_label);
                    self.join_object_mutation_label(object_id, &mutation_label)?;
                    let previous_label =
                        self.own_stored_runtime_property_label(object_id, &property_key);
                    self.set_own_runtime_property_label(object_id, &property_key, &value_label)?;
                    let fields = PropertyDescriptorFields {
                        value: Some(value),
                        writable: Some(true),
                        enumerable: Some(true),
                        configurable: Some(true),
                        ..PropertyDescriptorFields::default()
                    };
                    let result = self.define_own_property_from_descriptor(
                        object_id,
                        property_key.clone(),
                        fields,
                    );
                    match result {
                        Ok(true) => {}
                        refused => {
                            self.set_own_runtime_property_label(
                                object_id,
                                &property_key,
                                &previous_label,
                            )?;
                            match refused {
                                Err(error) => return Err(error),
                                Ok(false) => {
                                    return Err(InterpreterError::TypeError {
                                        expected: "permitted own data property definition"
                                            .to_string(),
                                        got: property_key.diagnostic(),
                                    });
                                }
                                Ok(true) => unreachable!(),
                            }
                        }
                    }
                    self.ip += 1;
                }
                set_instruction @ (Ir3Instruction::SetProperty { obj, key, val }
                | Ir3Instruction::SetPropertySloppy { obj, key, val }) => {
                    // bd-9vouw.146: PutValue throws for a write that [[Set]]
                    // rejects only in strict code (ES2020 6.2.4.9 step 6.d).
                    let strict = matches!(set_instruction, Ir3Instruction::SetProperty { .. });
                    let obj_val = self.read_reg(obj)?;
                    let key_val = self.read_reg(key)?;
                    // ES2022 `o.#x = v` (PrivateSet). The value keeps its own
                    // label; the write joins into the object's mutation
                    // label as an ordinary store does.
                    if let Some(name) = self.class_private_name_key(&key_val) {
                        let set_val = self.read_reg(val)?;
                        let value_label = self.get_register_label(val)?.clone();
                        if let Value::Object(oid) = &obj_val {
                            let mutation_label = self
                                .get_register_label(obj)?
                                .join(self.get_register_label(key)?)
                                .join(self.get_register_label(val)?);
                            self.join_object_mutation_label(*oid, &mutation_label)?;
                        }
                        self.private_set(module, &obj_val, name, set_val, value_label)?;
                        self.ip += 1;
                        continue;
                    }
                    let observation = self.begin_property_write_observation(obj, key, val)?;
                    let outcome = (|| {
                        let key_val = self.member_key_primitive(module, &obj_val, key_val)?;
                        let property_key = self.executable_property_key_from_value(&key_val);
                        let has_hook_target = matches!(&obj_val, Value::Object(_))
                            || matches!(
                                &obj_val,
                                Value::BuiltinFunction(builtin)
                                    if Self::builtin_function_property_object(builtin).is_some()
                            );
                        if !has_hook_target {
                            self.preflight_legacy_property_key_for_hook(&property_key)?;
                        }
                        let binary_object_id = match &obj_val {
                            Value::Object(object_id) => self
                                .array_buffer_id_for_object(*object_id)
                                .map(|_| *object_id),
                            _ => None,
                        };
                        let set_val = self.read_reg(val)?;
                        // An Array's writable `length` set to an object runs
                        // ArraySetLength's ToUint32 / ToNumber (its valueOf
                        // twice) before the write (bd-9vouw.338); a read-only
                        // `length` rejects the write without converting.
                        let set_val = match &obj_val {
                            Value::Object(oid)
                                if set_val.is_object_like()
                                    && property_key.as_str() == Some("length")
                                    && self.heap.get(oid.0 as usize).is_some_and(|object| {
                                        object.is_array
                                            && !object.is_frozen
                                            && object
                                                .own_property_attributes(&property_key)
                                                .writable
                                    }) =>
                            {
                                self.array_length_definition_value(Some(module), set_val)?
                            }
                            _ => set_val,
                        };

                        match obj_val {
                            Value::Object(oid) => {
                                self.run_pre_runtime_property_access_hook(
                                    module,
                                    oid,
                                    &property_key,
                                )?;
                                let mut mutation_label = self
                                    .get_register_label(obj)?
                                    .join(self.get_register_label(key)?)
                                    .join(self.get_register_label(val)?);
                                if let Some(ctx) = self.active_execution_context_label() {
                                    mutation_label = mutation_label.join(ctx);
                                }
                                self.join_object_mutation_label(oid, &mutation_label)?;
                                let handled_url = match property_key.as_str() {
                                    Some(key) => self.set_url_object_property(
                                        oid,
                                        key,
                                        &set_val,
                                        &mutation_label,
                                    )?,
                                    None => false,
                                };
                                if handled_url {
                                    // Native URL setter committed through its
                                    // authenticated side table; no guest-writable
                                    // mirror property is created.
                                } else if property_key.as_str() == Some("__proto__")
                                    && self.proto_key_reaches_accessor(oid)
                                {
                                    // Otherwise (an own `__proto__`, a null-prototype
                                    // chain) it is an ordinary data write below
                                    // (bd-9vouw.318).
                                    // `__proto__` sets the internal prototype link so
                                    // prototype-chain lookups (incl. class `extends`,
                                    // which lowers to `Child.prototype.__proto__ =
                                    // Parent.prototype`) traverse it — not a data
                                    // property (bd-ppfds). A non-object, non-null value
                                    // is a no-op per spec; a function links to its
                                    // own-property backing (bd-9vouw.98). The link
                                    // changes through [[SetPrototypeOf]] (Annex B
                                    // 2.2.1.2 steps 4-5), so a cycle, a
                                    // non-extensible object, Object.prototype and a
                                    // refusing proxy trap throw a TypeError; the
                                    // link was stored unconditionally (bd-9vouw.311).
                                    let proto_update =
                                        self.prototype_link_for_value(Some(module), &set_val)?;
                                    if let Some(new_proto) = proto_update
                                        && !self.object_set_prototype(
                                            Some(module),
                                            oid,
                                            new_proto,
                                            0,
                                        )?
                                    {
                                        return Err(InterpreterError::TypeError {
                                            expected: "a permitted __proto__ change".to_string(),
                                            got: "a cyclic or refused prototype".to_string(),
                                        });
                                    }
                                } else {
                                    // Precharge and stage the label before the value
                                    // write. The value mutation then sees the
                                    // combined retained size; failure restores the
                                    // old sparse label instead of committing an
                                    // unlabeled value under memory pressure.
                                    let mut value_label = self.get_register_label(val)?.clone();
                                    if let Some(ctx) = self.active_execution_context_label() {
                                        value_label = value_label.join(ctx);
                                    }
                                    let label_owner = self
                                        .proxy_set_receiver_object(&Value::Object(oid))?
                                        .unwrap_or(oid);
                                    let previous_label = self.own_stored_runtime_property_label(
                                        label_owner,
                                        &property_key,
                                    );
                                    // Namespace writes never replace an export,
                                    // including through a transparent Proxy. Preserve
                                    // export labels on refused writes; SameValue checks
                                    // belong to [[DefineOwnProperty]] and observe the
                                    // retained label there.
                                    let preserve_export_label =
                                        self.is_module_namespace(label_owner);
                                    if !preserve_export_label {
                                        self.set_own_runtime_property_label(
                                            label_owner,
                                            &property_key,
                                            &value_label,
                                        )?;
                                    }
                                    let set_result = self.proxy_aware_set_runtime_property(
                                        Some(module),
                                        oid,
                                        &property_key,
                                        set_val,
                                        Value::Object(oid),
                                        0,
                                    );
                                    let committed = match set_result {
                                        Ok(committed) => committed,
                                        Err(error) => {
                                            if !preserve_export_label {
                                                self.set_own_runtime_property_label(
                                                    label_owner,
                                                    &property_key,
                                                    &previous_label,
                                                )?;
                                            }
                                            return Err(error);
                                        }
                                    };
                                    if !committed && strict {
                                        if !preserve_export_label {
                                            self.set_own_runtime_property_label(
                                                label_owner,
                                                &property_key,
                                                &previous_label,
                                            )?;
                                        }
                                        return Err(
                                            self.rejected_strict_set_error(oid, &property_key)
                                        );
                                    }
                                    // A sloppy write that [[Set]] rejected left the
                                    // object as it was: restore the prior label.
                                    let owns_property = committed
                                        && self.heap.get(label_owner.0 as usize).is_some_and(
                                            |object| {
                                                object.contains_own_runtime_property(&property_key)
                                            },
                                        );
                                    // ([[Set]] itself grows an array's length.)
                                    if !owns_property && !preserve_export_label {
                                        // Prototype accessors and successful traps
                                        // need not create an own data property.
                                        self.set_own_runtime_property_label(
                                            label_owner,
                                            &property_key,
                                            &previous_label,
                                        )?;
                                    }
                                }
                            }
                            function @ (Value::Function(_)
                            | Value::Closure(_)
                            | Value::GeneratorFunction(_)
                            | Value::AsyncGeneratorFunction(_))
                                if property_key.as_str() == Some("prototype")
                                    && self.function_has_intrinsic_prototype(&function) =>
                            {
                                let writable = self
                                    .function_prototype_descriptor_fields(Some(module), &function)?
                                    .is_some_and(|fields| fields.writable == Some(true));
                                if writable {
                                    let mut label = self
                                        .get_register_label(obj)?
                                        .join(self.get_register_label(key)?)
                                        .join(self.get_register_label(val)?);
                                    if let Some(ctx) = self.active_execution_context_label() {
                                        label = label.join(ctx);
                                    }
                                    self.set_constructor_prototype_override(
                                        module, &function, set_val, label,
                                    )?;
                                } else if strict {
                                    return Err(Self::read_only_property_error(&property_key));
                                }
                            }
                            // bd-9vouw.17: a built-in's own `name` and `length`
                            // are non-writable too.
                            Value::BuiltinFunction(ref builtin)
                                if Self::builtin_function_property_object(builtin).is_none()
                                    && matches!(property_key.as_str(), Some("name" | "length")) =>
                            {
                                if strict {
                                    return Err(Self::read_only_property_error(&property_key));
                                }
                            }
                            // bd-9vouw.272: a built-in or bound function inherits
                            // Function.prototype's `caller` / `arguments`.
                            Value::BuiltinFunction(ref builtin)
                                if builtin.kind != BuiltinFunctionKind::CallableProxy
                                    && matches!(
                                        property_key.as_str(),
                                        Some("caller" | "arguments")
                                    )
                                    && self.restricted_function_property_set(
                                        module,
                                        &Value::BuiltinFunction(builtin.clone()),
                                        &property_key,
                                        &set_val,
                                        strict,
                                    )? => {}
                            Value::BuiltinFunction(builtin) => {
                                let property_object =
                                    match Self::builtin_function_property_object(&builtin) {
                                        Some(property_object) => property_object,
                                        // Other built-ins keep assigned properties
                                        // (`fn.displayName = ...`) on a backing object.
                                        None => self
                                            .own_property_holder(
                                                Some(module),
                                                &Value::BuiltinFunction(builtin.clone()),
                                                true,
                                            )?
                                            .ok_or_else(|| InterpreterError::TypeError {
                                                expected: "object with writable properties"
                                                    .to_string(),
                                                got: builtin.display_name().to_string(),
                                            })?,
                                    };
                                let mut mutation_label = self
                                    .get_register_label(obj)?
                                    .join(self.get_register_label(key)?)
                                    .join(self.get_register_label(val)?);
                                if let Some(ctx) = self.active_execution_context_label() {
                                    mutation_label = mutation_label.join(ctx);
                                }
                                self.join_object_mutation_label(property_object, &mutation_label)?;
                                self.set_backing_object_property(
                                    module,
                                    property_object,
                                    &property_key,
                                    val,
                                    Value::BuiltinFunction(builtin),
                                    strict,
                                )?;
                            }
                            // bd-9vouw.17: a function's own `name` and `length`
                            // are non-writable (ES2020 9.2.4 / 9.2.8), so [[Set]]
                            // rejects the write, unless the program redefined
                            // them on the backing object (a `static name()`
                            // method, Object.defineProperty).
                            ref function @ (Value::Function(_)
                            | Value::Closure(_)
                            | Value::GeneratorFunction(_)
                            | Value::AsyncFunction(_)
                            | Value::AsyncGeneratorFunction(_))
                                if matches!(property_key.as_str(), Some("name" | "length"))
                                    && !self.function_backing_has_own_property(
                                        module,
                                        function,
                                        &property_key,
                                    )? =>
                            {
                                if strict {
                                    return Err(Self::read_only_property_error(&property_key));
                                }
                            }
                            // bd-9vouw.216: `F.__proto__ = P` runs Object.prototype's
                            // `__proto__` setter (ES2020 B.2.2.1.2): an object, a
                            // function or null becomes F's [[Prototype]] (`F.s`
                            // then inherits P's statics), anything else is
                            // ignored, and a cycle is a TypeError. It stored an
                            // own property named `__proto__`.
                            ref function @ (Value::Function(_)
                            | Value::Closure(_)
                            | Value::GeneratorFunction(_)
                            | Value::AsyncFunction(_)
                            | Value::AsyncGeneratorFunction(_))
                                if property_key.as_str() == Some("__proto__")
                                    && !self.function_backing_has_own_property(
                                        module,
                                        function,
                                        &property_key,
                                    )? =>
                            {
                                if (set_val.is_object_like() || matches!(set_val, Value::Null))
                                    && !self.set_function_value_prototype(
                                        Some(module),
                                        function,
                                        &set_val,
                                    )?
                                {
                                    return Err(InterpreterError::TypeError {
                                        expected: "acyclic __proto__ value".to_string(),
                                        got: "a prototype chain that reaches the function"
                                            .to_string(),
                                    });
                                }
                            }
                            // bd-9vouw.272: `caller` / `arguments` the function
                            // does not define (Function.prototype's accessors, or
                            // a sloppy function's read-only own ones).
                            ref function @ (Value::Function(_)
                            | Value::Closure(_)
                            | Value::GeneratorFunction(_)
                            | Value::AsyncFunction(_)
                            | Value::AsyncGeneratorFunction(_))
                                if self.restricted_function_property_set(
                                    module,
                                    function,
                                    &property_key,
                                    &set_val,
                                    strict,
                                )? => {}
                            // Other own properties (`F.x = 1`,
                            // `Test262Error.thrower = ...`) live on the function's
                            // backing object.
                            ref function @ (Value::Function(_)
                            | Value::Closure(_)
                            | Value::GeneratorFunction(_)
                            | Value::AsyncFunction(_)
                            | Value::AsyncGeneratorFunction(_)) => {
                                let property_object = self
                                    .ensure_function_own_property_object(module, function)?
                                    .expect(
                                        "user function values always have a backing-object key",
                                    );
                                let mut mutation_label = self
                                    .get_register_label(obj)?
                                    .join(self.get_register_label(key)?)
                                    .join(self.get_register_label(val)?);
                                if let Some(ctx) = self.active_execution_context_label() {
                                    mutation_label = mutation_label.join(ctx);
                                }
                                self.join_object_mutation_label(property_object, &mutation_label)?;
                                self.set_backing_object_property(
                                    module,
                                    property_object,
                                    &property_key,
                                    val,
                                    function.clone(),
                                    strict,
                                )?;
                            }
                            // A promise, generator or async generator object keeps
                            // assigned properties (`p.cancel = fn`) on its backing
                            // object; the assignment threw "expected object".
                            ref exotic if Self::has_exotic_backing_object(exotic) => {
                                let property_object = self
                                    .ensure_function_own_property_object(module, exotic)?
                                    .expect(
                                        "promise and generator values have a backing-object key",
                                    );
                                let mut mutation_label = self
                                    .get_register_label(obj)?
                                    .join(self.get_register_label(key)?)
                                    .join(self.get_register_label(val)?);
                                if let Some(ctx) = self.active_execution_context_label() {
                                    mutation_label = mutation_label.join(ctx);
                                }
                                self.join_object_mutation_label(property_object, &mutation_label)?;
                                self.set_backing_object_property(
                                    module,
                                    property_object,
                                    &property_key,
                                    val,
                                    exotic.clone(),
                                    strict,
                                )?;
                            }
                            // bd-9vouw.146: [[Set]] with a primitive base creates
                            // no property (its receiver is not an object), so
                            // sloppy code ignores the write. undefined and null
                            // have no properties at all and throw in either mode.
                            Value::Bool(_)
                            | Value::Int(_)
                            | Value::Float(_)
                            | Value::BigInt(_)
                            | Value::Str(_)
                            | Value::Symbol(_)
                                if !strict => {}
                            _ => {
                                return Err(InterpreterError::TypeError {
                                    expected: "object".to_string(),
                                    got: self.nullish_access_subject(
                                        &obj_val,
                                        &property_key,
                                        "setting",
                                    ),
                                });
                            }
                        }
                        if let Some(object_id) = binary_object_id {
                            let mut mutation_label = self
                                .get_register_label(obj)?
                                .join(self.get_register_label(key)?)
                                .join(self.get_register_label(val)?);
                            if let Some(ctx) = self.active_execution_context_label() {
                                mutation_label = mutation_label.join(ctx);
                            }
                            self.join_binary_storage_label(object_id, &mutation_label)?;
                        }
                        Ok(())
                    })();
                    self.finish_property_write_observation(observation, outcome)?;
                    self.ip += 1;
                }
                Ir3Instruction::DefineAccessor {
                    obj,
                    key,
                    func,
                    kind,
                } => {
                    let obj_val = self.read_reg(obj)?;
                    let key_val = self.read_reg(key)?;
                    let func_val = self.read_reg(func)?;
                    let property_key = self.executable_property_key_from_value(&key_val);

                    match obj_val {
                        Value::Object(oid) => {
                            self.run_pre_runtime_property_access_hook(module, oid, &property_key)?;
                            let definition_label = self.get_register_label(obj)?.clone();
                            self.register_accessor_home_object(
                                &func_val,
                                oid,
                                &property_key,
                                kind,
                                definition_label,
                            )?;
                            self.define_accessor_property(oid, property_key, func_val, kind)?;
                        }
                        // bd-9vouw.17: class `static get x()` / `static set x()`.
                        // Like a static method (DefineMethod below), the
                        // accessor is a method of the constructor's own
                        // properties: named "get x" / "set x", without a
                        // `prototype`, not a constructor (bd-9vouw.266).
                        ref function @ (Value::Function(_)
                        | Value::Closure(_)
                        | Value::GeneratorFunction(_)
                        | Value::AsyncFunction(_)
                        | Value::AsyncGeneratorFunction(_)) => {
                            // A class's `prototype` is non-configurable, so
                            // `static get ['prototype']()` fails its
                            // DefinePropertyOrThrow (ES2020 14.6.13 step 21).
                            if property_key.as_str() == Some("prototype") {
                                return Err(InterpreterError::TypeError {
                                    expected: "a configurable property for a static class accessor"
                                        .to_string(),
                                    got: "the class's non-configurable `prototype`".to_string(),
                                });
                            }
                            let backing = self
                                .ensure_function_own_property_object(module, function)?
                                .expect("user function values always have a backing-object key");
                            self.run_pre_runtime_property_access_hook(
                                module,
                                backing,
                                &property_key,
                            )?;
                            let definition_label = self.get_register_label(obj)?.clone();
                            self.register_accessor_home_object(
                                &func_val,
                                backing,
                                &property_key,
                                kind,
                                definition_label,
                            )?;
                            self.define_accessor_property(backing, property_key, func_val, kind)?;
                        }
                        _ => {
                            return Err(InterpreterError::TypeError {
                                expected: "object".to_string(),
                                got: obj_val.type_name().to_string(),
                            });
                        }
                    }
                    self.ip += 1;
                }
                Ir3Instruction::DefineMethod { obj, key, func } => {
                    let obj_val = self.read_reg(obj)?;
                    let key_val = self.read_reg(key)?;
                    let func_val = self.read_reg(func)?;
                    let property_key = self.executable_property_key_from_value(&key_val);
                    let mut definition_label = self.get_register_label(obj)?;
                    for candidate in [
                        self.get_register_label(key)?,
                        self.get_register_label(func)?,
                    ] {
                        if candidate > definition_label {
                            definition_label = candidate;
                        }
                    }
                    self.check_temporary_memory_budget(Self::estimate_label_bytes(
                        definition_label,
                    ))?;
                    let definition_label = definition_label.clone();

                    match obj_val {
                        Value::Object(object_id) => {
                            self.run_pre_runtime_property_access_hook(
                                module,
                                object_id,
                                &property_key,
                            )?;
                            self.define_method_property(
                                object_id,
                                property_key,
                                func_val,
                                definition_label,
                            )?;
                        }
                        // bd-9vouw.17: class `static` methods install onto the
                        // constructor function's own properties.
                        ref function @ (Value::Function(_)
                        | Value::Closure(_)
                        | Value::GeneratorFunction(_)
                        | Value::AsyncFunction(_)
                        | Value::AsyncGeneratorFunction(_)) => {
                            // The class's `prototype` is neither writable nor
                            // configurable, so `static ['prototype']() {}`
                            // fails its DefinePropertyOrThrow (ES2020
                            // 14.3.8 step 8, bd-9vouw.266).
                            if property_key.as_str() == Some("prototype") {
                                return Err(InterpreterError::TypeError {
                                    expected: "a configurable property for a static class method"
                                        .to_string(),
                                    got: "the class's non-configurable `prototype`".to_string(),
                                });
                            }
                            let backing = self
                                .ensure_function_own_property_object(module, function)?
                                .expect("user function values always have a backing-object key");
                            self.run_pre_runtime_property_access_hook(
                                module,
                                backing,
                                &property_key,
                            )?;
                            self.define_method_property(
                                backing,
                                property_key,
                                func_val,
                                definition_label,
                            )?;
                        }
                        other => {
                            return Err(InterpreterError::TypeError {
                                expected: "object".to_string(),
                                got: other.type_name().to_string(),
                            });
                        }
                    }
                    self.ip += 1;
                }
                Ir3Instruction::DeleteProperty { obj, key, dst } => {
                    let obj_val = self.read_reg(obj)?;
                    let key_val = self.read_reg(key)?;
                    // `delete o.#x` is an early error; a private name that
                    // reaches here anyway deletes nothing.
                    if self.class_private_name_key(&key_val).is_some() {
                        return Err(InterpreterError::TypeError {
                            expected: "a deletable property key".to_string(),
                            got: "a class private name".to_string(),
                        });
                    }
                    let key_val = self.member_key_primitive(module, &obj_val, key_val)?;
                    let property_key = self.executable_property_key_from_value(&key_val);
                    let has_hook_target = matches!(&obj_val, Value::Object(_))
                        || matches!(
                            &obj_val,
                            Value::BuiltinFunction(builtin)
                                if Self::builtin_function_property_object(builtin).is_some()
                        );
                    if !has_hook_target {
                        self.preflight_legacy_property_key_for_hook(&property_key)?;
                    }

                    match obj_val {
                        Value::Object(oid) => {
                            self.run_pre_runtime_property_access_hook(module, oid, &property_key)?;
                            let deleted = self.proxy_aware_delete_runtime_property(
                                Some(module),
                                oid,
                                &property_key,
                                0,
                            )?;
                            if deleted && let Some(property_key) = property_key.string() {
                                self.mark_deleted_for_in_iterators(oid, property_key);
                            }
                            self.write_reg(dst, Value::Bool(deleted))?;
                        }
                        Value::BuiltinFunction(builtin)
                            if Self::builtin_function_property_object(&builtin).is_some() =>
                        {
                            let property_object = Self::builtin_function_property_object(&builtin)
                                .expect("guarded above");
                            self.run_pre_runtime_property_access_hook(
                                module,
                                property_object,
                                &property_key,
                            )?;
                            let deleted = self.proxy_aware_delete_runtime_property(
                                Some(module),
                                property_object,
                                &property_key,
                                0,
                            )?;
                            self.write_reg(dst, Value::Bool(deleted))?;
                        }
                        // bd-9vouw.17: a function's own properties (including
                        // its configurable `name` and `length`) live on its
                        // backing object. `prototype` is not configurable.
                        ref function @ (Value::Function(_)
                        | Value::Closure(_)
                        | Value::GeneratorFunction(_)
                        | Value::AsyncFunction(_)
                        | Value::AsyncGeneratorFunction(_)
                        | Value::BuiltinFunction(_)) => {
                            let deleted = if property_key.as_str() == Some("prototype") {
                                false
                            } else if let Some(backing) =
                                self.ensure_function_own_property_object(module, function)?
                            {
                                self.run_pre_runtime_property_access_hook(
                                    module,
                                    backing,
                                    &property_key,
                                )?;
                                self.proxy_aware_delete_runtime_property(
                                    Some(module),
                                    backing,
                                    &property_key,
                                    0,
                                )?
                            } else {
                                return Err(InterpreterError::TypeError {
                                    expected: "object with configurable properties".to_string(),
                                    got: function.type_name().to_string(),
                                });
                            };
                            self.write_reg(dst, Value::Bool(deleted))?;
                        }
                        ref exotic if Self::has_exotic_backing_object(exotic) => {
                            let deleted = if let Some(backing) =
                                self.function_own_property_object(module, exotic)?
                            {
                                self.run_pre_runtime_property_access_hook(
                                    module,
                                    backing,
                                    &property_key,
                                )?;
                                self.proxy_aware_delete_runtime_property(
                                    Some(module),
                                    backing,
                                    &property_key,
                                    0,
                                )?
                            } else {
                                true
                            };
                            self.write_reg(dst, Value::Bool(deleted))?;
                        }
                        _ => {
                            return Err(InterpreterError::TypeError {
                                expected: "object".to_string(),
                                got: obj_val.type_name().to_string(),
                            });
                        }
                    }
                    self.ip += 1;
                }
                Ir3Instruction::NewObject { dst } => {
                    self.run_pre_allocation_hook(module, AllocKind::Object, 0)?;
                    let id = self.alloc_object_with_prototype(None)?;
                    self.write_reg(dst, Value::Object(id))?;
                    self.ip += 1;
                }
                Ir3Instruction::NewArray { dst } => {
                    self.run_pre_allocation_hook(module, AllocKind::Array, 0)?;
                    let id = self.alloc_array_with_prototype(None)?;
                    self.write_reg(dst, Value::Object(id))?;
                    self.ip += 1;
                }
                Ir3Instruction::ArrayPush { array, element } => {
                    // Push a single element onto an array
                    let arr_val = self.read_reg(array)?;
                    let elem_val = self.read_reg(element)?;
                    let element_label = self.get_register_label(element)?.clone();
                    if let Value::Object(arr_id) = arr_val {
                        let mutation_label = self
                            .get_register_label(array)?
                            .join(self.get_register_label(element)?);
                        self.join_object_mutation_label(arr_id, &mutation_label)?;
                        let next_idx = self
                            .heap
                            .get(arr_id.0 as usize)
                            .map(|obj| {
                                // Fast path: use cached dense length if available
                                if let Some(cached_len) = obj.cached_dense_length {
                                    // Deterministic decision: fold, don't record (bd-9vouw.18).
                                    self.nondeterminism_trace.witness_deterministic(
                                        NondeterminismSource::ArrayCacheInvalidation,
                                        format!("cache_hit:{}", cached_len).as_bytes(),
                                    );
                                    cached_len
                                } else {
                                    // Sparse fallback: scan all properties (original slow path),
                                    // seeded with explicit `.length` so leading array holes (`[, x]`)
                                    // push at `length` instead of index 0.
                                    let explicit_len = match obj.properties.get("length") {
                                        Some(Value::Int(length)) => {
                                            u32::try_from((*length).max(0)).unwrap_or(u32::MAX)
                                        }
                                        Some(Value::Float(f)) if f.0.is_finite() && f.0 > 0.0 => {
                                            (f.0.trunc() as u64).min(u32::MAX as u64) as u32
                                        }
                                        _ => 0,
                                    };
                                    let sparse_len =
                                        obj.properties.keys().fold(explicit_len, |current, key| {
                                            key.parse::<u32>()
                                                .ok()
                                                // u32::MAX is not a valid array
                                                // index (see
                                                // canonical_array_index_property);
                                                // excluding it keeps `n + 1` from
                                                // overflowing. (bd-qsz8t)
                                                .filter(|&n| n != u32::MAX)
                                                .map_or(current, |n| current.max(n + 1))
                                        });
                                    // Deterministic decision: fold, don't record (bd-9vouw.18).
                                    self.nondeterminism_trace.witness_deterministic(
                                        NondeterminismSource::ArrayCacheInvalidation,
                                        format!("cache_miss:{}", sparse_len).as_bytes(),
                                    );
                                    sparse_len
                                }
                            })
                            .unwrap_or(0);
                        let next_len = next_idx.saturating_add(1);
                        let preserves_plain_moves = self
                            .heap
                            .slot(arr_id.0 as usize)
                            .is_some_and(|slot| slot.dense_moves_plain.get() == Some(true))
                            && self.array_cache_matches_visible_length(arr_id, next_idx as usize)
                            && !matches!(elem_val, Value::Accessor { .. })
                            && element_label == Label::Public;
                        let element_key =
                            RuntimePropertyKey::String(JsString::from(next_idx.to_string()));
                        let previous_label =
                            self.own_stored_runtime_property_label(arr_id, &element_key);
                        self.set_own_runtime_property_label(arr_id, &element_key, &element_label)?;
                        if let Err(error) =
                            self.set_object_property(arr_id, next_idx.to_string(), elem_val)
                        {
                            self.set_own_runtime_property_label(
                                arr_id,
                                &element_key,
                                &previous_label,
                            )?;
                            return Err(error);
                        }
                        self.set_object_property(
                            arr_id,
                            "length".to_string(),
                            Value::Int(i64::from(next_len)),
                        )?;
                        // Update cached dense length for arrays
                        let arr_index = arr_id.0 as usize;
                        self.mutate_heap(|heap| {
                            if let Some(obj) = heap.get_mut(arr_index) {
                                if obj.is_array && obj.cached_dense_length.is_some() {
                                    obj.cached_dense_length = Some(next_len);
                                }
                            }
                        });
                        if preserves_plain_moves
                            && self.array_cache_matches_visible_length(arr_id, next_len as usize)
                        {
                            self.heap
                                .slot(arr_index)
                                .expect("appended array remains live")
                                .dense_moves_plain
                                .set(Some(true));
                        }
                    }
                    self.ip += 1;
                }
                Ir3Instruction::ArraySlice { .. } | Ir3Instruction::SpreadIntoArray { .. } => {
                    return Ok(DispatchOutcome::ReentrantInstruction {
                        instruction_ip: self.ip,
                        profile_start,
                    });
                }
                Ir3Instruction::SpreadIntoObject { target, source } => {
                    let input_label = self.binary_operation_label(target, source)?;
                    let target_val = self.read_reg(target)?;
                    let source_val = self.read_reg(source)?;
                    let Value::Object(target_id) = target_val else {
                        return Err(InterpreterError::TypeError {
                            expected: "object spread target".to_string(),
                            got: target_val.type_name().to_string(),
                        });
                    };
                    self.clear_pending_hostcall_result_label();
                    self.join_object_mutation_label(target_id, &input_label)?;
                    let result = self.copy_data_properties(
                        Some(module),
                        target_id,
                        source_val,
                        &BTreeSet::new(),
                        false,
                    );
                    let callback_label = self
                        .pending_hostcall_result_label
                        .clone()
                        .unwrap_or(Label::Public);
                    self.clear_pending_hostcall_result_label();
                    match result {
                        Ok(()) => {
                            let label = input_label.join(&callback_label);
                            self.join_object_mutation_label(target_id, &label)?;
                            self.write_reg_with_label(target, Value::Object(target_id), label)?;
                            self.ip += 1;
                        }
                        Err(error) => {
                            if let Some(error) = self.route_iterator_close_failure(module, error)? {
                                return Err(error);
                            }
                        }
                    }
                }
                Ir3Instruction::Mod { dst, lhs, rhs } => {
                    let result_label = self.binary_operation_label(lhs, rhs)?;
                    let result = self.eval_mod(lhs, rhs)?;
                    self.write_reg_with_label(dst, result, result_label)?;
                    self.ip += 1;
                }
                Ir3Instruction::Exp { dst, lhs, rhs } => {
                    let result_label = self.binary_operation_label(lhs, rhs)?;
                    let result = self.eval_exp(lhs, rhs)?;
                    self.write_reg_with_label(dst, result, result_label)?;
                    self.ip += 1;
                }
                Ir3Instruction::UnaryNeg { dst, src } => {
                    let result_label = self.unary_operation_label(src)?;
                    let result = self.eval_unary_neg(src)?;
                    self.write_reg_with_label(dst, result, result_label)?;
                    self.ip += 1;
                }
                Ir3Instruction::UnaryPlus { dst, src } => {
                    let result_label = self.unary_operation_label(src)?;
                    let result = self.eval_unary_plus(src)?;
                    self.write_reg_with_label(dst, result, result_label)?;
                    self.ip += 1;
                }
                Ir3Instruction::Inc { dst, src } => {
                    let result_label = self.unary_operation_label(src)?;
                    let result = self.eval_step(src, 1)?;
                    self.write_reg_with_label(dst, result, result_label)?;
                    self.ip += 1;
                }
                Ir3Instruction::Dec { dst, src } => {
                    let result_label = self.unary_operation_label(src)?;
                    let result = self.eval_step(src, -1)?;
                    self.write_reg_with_label(dst, result, result_label)?;
                    self.ip += 1;
                }
                Ir3Instruction::LogicalNot { dst, src } => {
                    let result_label = self.unary_operation_label(src)?;
                    let val = self.read_reg(src)?;
                    self.write_reg_with_label(dst, Value::Bool(!val.is_truthy()), result_label)?;
                    self.ip += 1;
                }
                Ir3Instruction::BitNot { dst, src } => {
                    let result_label = self.unary_operation_label(src)?;
                    let result = self.eval_bit_not(src)?;
                    self.write_reg_with_label(dst, result, result_label)?;
                    self.ip += 1;
                }
                Ir3Instruction::TypeOf { dst, src } => {
                    let result_label = self.unary_operation_label(src)?;
                    let val = self.read_reg(src)?;
                    self.write_reg_with_label(dst, Value::str(val.typeof_name()), result_label)?;
                    self.ip += 1;
                }
                Ir3Instruction::Void { dst, src } => {
                    let result_label = self.unary_operation_label(src)?;
                    let _ = self.read_reg(src)?;
                    self.write_reg_with_label(dst, Value::Undefined, result_label)?;
                    self.ip += 1;
                }
                Ir3Instruction::Lt { dst, lhs, rhs } => {
                    let result_label = self.binary_operation_label(lhs, rhs)?;
                    let result = self.eval_relational(lhs, rhs, "<")?;
                    self.write_reg_with_label(dst, result, result_label)?;
                    self.ip += 1;
                }
                Ir3Instruction::Lte { dst, lhs, rhs } => {
                    let result_label = self.binary_operation_label(lhs, rhs)?;
                    let result = self.eval_relational(lhs, rhs, "<=")?;
                    self.write_reg_with_label(dst, result, result_label)?;
                    self.ip += 1;
                }
                Ir3Instruction::Gt { dst, lhs, rhs } => {
                    let result_label = self.binary_operation_label(lhs, rhs)?;
                    let result = self.eval_relational(lhs, rhs, ">")?;
                    self.write_reg_with_label(dst, result, result_label)?;
                    self.ip += 1;
                }
                Ir3Instruction::Gte { dst, lhs, rhs } => {
                    let result_label = self.binary_operation_label(lhs, rhs)?;
                    let result = self.eval_relational(lhs, rhs, ">=")?;
                    self.write_reg_with_label(dst, result, result_label)?;
                    self.ip += 1;
                }
                Ir3Instruction::Eq { dst, lhs, rhs } => {
                    let result_label = self.binary_operation_label(lhs, rhs)?;
                    let result = self.eval_equality(lhs, rhs, false, false)?;
                    self.write_reg_with_label(dst, result, result_label)?;
                    self.ip += 1;
                }
                Ir3Instruction::StrictEq { dst, lhs, rhs } => {
                    let result_label = self.binary_operation_label(lhs, rhs)?;
                    let result = self.eval_equality(lhs, rhs, true, false)?;
                    self.write_reg_with_label(dst, result, result_label)?;
                    self.ip += 1;
                }
                Ir3Instruction::NotEq { dst, lhs, rhs } => {
                    let result_label = self.binary_operation_label(lhs, rhs)?;
                    let result = self.eval_equality(lhs, rhs, false, true)?;
                    self.write_reg_with_label(dst, result, result_label)?;
                    self.ip += 1;
                }
                Ir3Instruction::StrictNotEq { dst, lhs, rhs } => {
                    let result_label = self.binary_operation_label(lhs, rhs)?;
                    let result = self.eval_equality(lhs, rhs, true, true)?;
                    self.write_reg_with_label(dst, result, result_label)?;
                    self.ip += 1;
                }
                Ir3Instruction::BitAnd { dst, lhs, rhs } => {
                    let result_label = self.binary_operation_label(lhs, rhs)?;
                    let result = self.eval_bitwise(lhs, rhs, "&")?;
                    self.write_reg_with_label(dst, result, result_label)?;
                    self.ip += 1;
                }
                Ir3Instruction::BitOr { dst, lhs, rhs } => {
                    let result_label = self.binary_operation_label(lhs, rhs)?;
                    let result = self.eval_bitwise(lhs, rhs, "|")?;
                    self.write_reg_with_label(dst, result, result_label)?;
                    self.ip += 1;
                }
                Ir3Instruction::BitXor { dst, lhs, rhs } => {
                    let result_label = self.binary_operation_label(lhs, rhs)?;
                    let result = self.eval_bitwise(lhs, rhs, "^")?;
                    self.write_reg_with_label(dst, result, result_label)?;
                    self.ip += 1;
                }
                Ir3Instruction::Shl { dst, lhs, rhs } => {
                    let result_label = self.binary_operation_label(lhs, rhs)?;
                    let result = self.eval_bitwise(lhs, rhs, "<<")?;
                    self.write_reg_with_label(dst, result, result_label)?;
                    self.ip += 1;
                }
                Ir3Instruction::Shr { dst, lhs, rhs } => {
                    let result_label = self.binary_operation_label(lhs, rhs)?;
                    let result = self.eval_bitwise(lhs, rhs, ">>")?;
                    self.write_reg_with_label(dst, result, result_label)?;
                    self.ip += 1;
                }
                Ir3Instruction::Ushr { dst, lhs, rhs } => {
                    let result_label = self.binary_operation_label(lhs, rhs)?;
                    let result = self.eval_bitwise(lhs, rhs, ">>>")?;
                    self.write_reg_with_label(dst, result, result_label)?;
                    self.ip += 1;
                }
                Ir3Instruction::InstanceOf { dst, lhs, rhs } => {
                    let mut result_label = self.binary_operation_label(lhs, rhs)?;
                    let constructor = self.read_reg(rhs)?;
                    if let Some((_, prototype_label)) =
                        self.constructor_prototype_override(module, &constructor)?
                    {
                        result_label = self.join_owned_label_with_temporary_budget(
                            result_label,
                            &prototype_label,
                        )?;
                    }
                    let (result, handler_label) = self.eval_instanceof(module, lhs, rhs)?;
                    if let Some(handler_label) = handler_label {
                        result_label = self
                            .join_owned_label_with_temporary_budget(result_label, &handler_label)?;
                    }
                    self.write_reg_with_label(dst, result, result_label)?;
                    self.ip += 1;
                }
                Ir3Instruction::InOp { dst, lhs, rhs } => {
                    let result_label = self.binary_operation_label(lhs, rhs)?;
                    // ES2022 `#x in o`: a brand check, not a property lookup.
                    let result = match self.class_private_name_key(&self.read_reg(lhs)?) {
                        Some(name) => {
                            let target = self.read_reg(rhs)?;
                            Value::Bool(self.private_in(module, &target, name)?)
                        }
                        None => self.eval_in_operator(module, lhs, rhs)?,
                    };
                    self.write_reg_with_label(dst, result, result_label)?;
                    self.ip += 1;
                }
                Ir3Instruction::RegisterDerivedConstructor {
                    constructor,
                    parent,
                    default_constructor,
                } => {
                    let constructor = self.read_reg(constructor)?;
                    let parent_value = self.read_reg(parent)?;
                    let parent_label = self.get_register_label(parent)?.clone();
                    self.register_derived_constructor_metadata(
                        module,
                        &constructor,
                        parent_value,
                        parent_label,
                        default_constructor,
                    )?;
                    self.ip += 1;
                }
                Ir3Instruction::ConstructSuper { args, dst } => {
                    let Some(frame) = self.call_stack.last() else {
                        return Err(InterpreterError::TypeError {
                            expected: "active derived constructor".to_string(),
                            got: "super() outside a constructor".to_string(),
                        });
                    };
                    if !frame.derived_constructor || frame.this_initialized {
                        // A second super() is a ReferenceError (ES2020
                        // 8.1.1.3.1 BindThisValue step 3).
                        let error = if frame.derived_constructor {
                            self.throw_js_error(
                                "ReferenceError",
                                "Super constructor may only be called once".to_string(),
                            )
                        } else {
                            InterpreterError::TypeError {
                                expected: "uninitialized derived-constructor this binding"
                                    .to_string(),
                                got: "super() in a base constructor".to_string(),
                            }
                        };
                        match self.route_isolated_explicit_throw(module, error)? {
                            None => continue,
                            Some(error) => return Err(error),
                        }
                    }
                    let parent = frame.super_value.clone();
                    let parent_label = frame.super_label.clone();
                    let new_target = frame.new_target_value.clone();
                    let new_target_label = frame.new_target_label.clone();
                    if let Err(error) = self.enter_constructor_call(
                        module,
                        parent,
                        parent_label,
                        args,
                        self.ip + 1,
                        dst,
                        new_target,
                        new_target_label,
                        true,
                        compact_tier1,
                    ) {
                        match self.route_isolated_explicit_throw(module, error)? {
                            None => continue,
                            Some(error) => return Err(error),
                        }
                    }
                }
                Ir3Instruction::ConstructWithNewTarget {
                    callee,
                    new_target,
                    args,
                    dst,
                } => {
                    let callee_value = self.read_reg(callee)?;
                    let callee_label = self.clone_register_label_with_temporary_budget(callee)?;
                    let new_target_value = self.read_reg(new_target)?;
                    let mut new_target_label =
                        self.clone_register_label_with_temporary_budget(new_target)?;

                    if let Some((_, label)) =
                        self.constructor_prototype_override(module, &new_target_value)?
                    {
                        new_target_label =
                            self.join_owned_label_with_temporary_budget(new_target_label, &label)?;
                    }

                    if !self.is_constructible_value(&callee_value) {
                        return Err(InterpreterError::TypeError {
                            expected: "constructible Reflect.construct target".to_string(),
                            got: callee_value.type_name().to_string(),
                        });
                    }
                    if !self.is_constructible_value(&new_target_value) {
                        return Err(InterpreterError::TypeError {
                            expected: "constructible Reflect.construct newTarget".to_string(),
                            got: new_target_value.type_name().to_string(),
                        });
                    }

                    if let Value::BuiltinFunction(builtin) = &callee_value
                        && builtin.kind == BuiltinFunctionKind::GeneratedFunction
                    {
                        let (result, result_label) = match self
                            .construct_generated_function_artifact(
                                module,
                                builtin,
                                args,
                                new_target_value,
                                new_target_label,
                            ) {
                            Ok(result) => result,
                            Err(error) => {
                                match self.route_isolated_explicit_throw(module, error)? {
                                    None => continue,
                                    Some(error) => return Err(error),
                                }
                            }
                        };
                        let result_label = self
                            .join_owned_label_with_temporary_budget(result_label, &callee_label)?;
                        self.write_reg_with_label(dst, result, result_label)?;
                        self.ip += 1;
                        continue;
                    }

                    if self
                        .foreign_closure_module(&callee_value, module)?
                        .is_some()
                    {
                        let call_labels =
                            self.clone_isolated_call_labels_from_registers(Some(callee), args)?;
                        let arguments = self.call_arguments(args)?;
                        let (result, result_label) = match self.invoke_inline_construct_with_labels(
                            Some(module),
                            callee_value,
                            arguments,
                            Some(call_labels),
                            Some((new_target_value, new_target_label)),
                        ) {
                            Ok(value) => value,
                            Err(error) => {
                                match self.route_isolated_explicit_throw(module, error)? {
                                    None => continue,
                                    Some(error) => return Err(error),
                                }
                            }
                        };
                        self.write_reg_with_label(dst, result, result_label)?;
                        self.ip += 1;
                        continue;
                    }

                    // Reflect.construct(proxy, args, newTarget) on a callable
                    // proxy (bd-9vouw.132): its construct trap or target, with
                    // that newTarget; the builtin path would call it.
                    if let Value::BuiltinFunction(builtin) = &callee_value
                        && builtin.kind == BuiltinFunctionKind::CallableProxy
                    {
                        let (result, result_label) = match self.construct_callable_proxy(
                            module,
                            builtin,
                            args,
                            Some(new_target_value.clone()),
                        ) {
                            Ok(value) => value,
                            Err(error) => {
                                match self.route_isolated_explicit_throw(module, error)? {
                                    None => continue,
                                    Some(error) => return Err(error),
                                }
                            }
                        };
                        let result_label = self
                            .join_owned_label_with_temporary_budget(result_label, &callee_label)?;
                        let result_label = self.join_owned_label_with_temporary_budget(
                            result_label,
                            &new_target_label,
                        )?;
                        self.write_reg_with_label(dst, result, result_label)?;
                        self.ip += 1;
                        continue;
                    }

                    // A bound function (ES2020 9.4.1.2) constructs its
                    // target with this newTarget, or with the target when
                    // the newTarget is the bound function itself.
                    if let Value::BuiltinFunction(builtin) = &callee_value
                        && builtin.kind == BuiltinFunctionKind::BoundFunction
                    {
                        let (result, result_label) = match self.construct_bound_function(
                            module,
                            builtin,
                            args,
                            Some((new_target_value.clone(), new_target_label.clone())),
                        ) {
                            Ok(value) => value,
                            Err(error) => {
                                match self.route_isolated_explicit_throw(module, error)? {
                                    None => continue,
                                    Some(error) => return Err(error),
                                }
                            }
                        };
                        let result_label = self
                            .join_owned_label_with_temporary_budget(result_label, &callee_label)?;
                        let result_label = self.join_owned_label_with_temporary_budget(
                            result_label,
                            &new_target_label,
                        )?;
                        self.write_reg_with_label(dst, result, result_label)?;
                        self.ip += 1;
                        continue;
                    }

                    if let Value::BuiltinFunction(builtin) = &callee_value {
                        let constructed = self.construct_builtin_with_new_target_and_labels(
                            module,
                            builtin,
                            args,
                            &new_target_value,
                            &callee_label,
                            &new_target_label,
                        )?;
                        let result_label = self.join_arg_range_label(args)?;
                        let result_label = self
                            .join_owned_label_with_temporary_budget(result_label, &callee_label)?;
                        let result_label = self.join_owned_label_with_temporary_budget(
                            result_label,
                            &new_target_label,
                        )?;
                        let result_label = if builtin.kind.observes_host_effect_selection() {
                            let observed = self
                                .take_pending_hostcall_result_label()
                                .unwrap_or(Label::Public);
                            self.join_owned_label_with_temporary_budget(observed, &result_label)?
                        } else {
                            result_label
                        };
                        self.write_reg_with_label(dst, constructed, result_label)?;
                        self.ip += 1;
                        continue;
                    }

                    if let Err(error) = self.enter_constructor_call(
                        module,
                        callee_value,
                        callee_label,
                        args,
                        self.ip + 1,
                        dst,
                        new_target_value,
                        new_target_label,
                        false,
                        compact_tier1,
                    ) {
                        match self.route_isolated_explicit_throw(module, error)? {
                            None => continue,
                            Some(error) => return Err(error),
                        }
                    }
                }
                Ir3Instruction::Construct { callee, args, dst } => {
                    let callee_val = self.read_reg(callee)?;
                    let callee_label = self.clone_register_label_with_temporary_budget(callee)?;

                    if matches!(&callee_val, Value::Closure(_))
                        && !self.is_constructible_value(&callee_val)
                    {
                        let error = InterpreterError::TypeError {
                            expected: "constructible function".to_string(),
                            got: "concise method".to_string(),
                        };
                        match self.route_isolated_explicit_throw(module, error)? {
                            None => continue,
                            Some(error) => return Err(error),
                        }
                    }

                    if let Value::BuiltinFunction(builtin) = &callee_val
                        && builtin.kind == BuiltinFunctionKind::GeneratedFunction
                    {
                        let (result, result_label) = match self
                            .construct_generated_function_artifact(
                                module,
                                builtin,
                                args,
                                callee_val.clone(),
                                callee_label.clone(),
                            ) {
                            Ok(result) => result,
                            Err(error) => {
                                match self.route_isolated_explicit_throw(module, error)? {
                                    None => continue,
                                    Some(error) => return Err(error),
                                }
                            }
                        };
                        self.write_reg_with_label(dst, result, result_label)?;
                        self.ip += 1;
                        continue;
                    }

                    if let Value::BuiltinFunction(builtin) = &callee_val
                        && builtin.kind == BuiltinFunctionKind::CallableProxy
                    {
                        let (result, result_label) = match self
                            .construct_callable_proxy(module, builtin, args, None)
                        {
                            Ok(value) => value,
                            Err(err) => match self.route_isolated_explicit_throw(module, err)? {
                                None => continue,
                                Some(err) => return Err(err),
                            },
                        };
                        self.write_reg_with_label(dst, result, result_label.join(&callee_label))?;
                        self.ip += 1;
                        continue;
                    }

                    if let Value::BuiltinFunction(builtin) = &callee_val
                        && builtin.kind == BuiltinFunctionKind::BoundFunction
                    {
                        let (result, result_label) = match self
                            .construct_bound_function(module, builtin, args, None)
                        {
                            Ok(value) => value,
                            Err(err) => match self.route_isolated_explicit_throw(module, err)? {
                                None => continue,
                                Some(err) => return Err(err),
                            },
                        };
                        self.write_reg_with_label(dst, result, result_label.join(&callee_label))?;
                        self.ip += 1;
                        continue;
                    }

                    if let Value::BuiltinFunction(builtin) = &callee_val {
                        if !builtin.kind.is_constructible() {
                            return Err(InterpreterError::TypeError {
                                expected: "constructible function".to_string(),
                                got: format!(
                                    "callable-only builtin function {}",
                                    builtin.display_name()
                                ),
                            });
                        }
                        let standard_name = (builtin.kind
                            == BuiltinFunctionKind::StandardConstructor)
                            .then(|| Self::standard_constructor_name(builtin).ok())
                            .flatten();
                        if let Some(name @ ("Symbol" | "BigInt")) = standard_name {
                            return Err(InterpreterError::TypeError {
                                expected: "constructor".to_string(),
                                got: format!("{name} is not a constructor"),
                            });
                        }
                        // ES2020 21.1.1.1 step 2: only a call turns a Symbol
                        // into its descriptive string; `new String(sym)` is
                        // ToString(sym), a TypeError.
                        if standard_name == Some("String")
                            && matches!(self.builtin_arg(args, 0)?, Some(Value::Symbol(_)))
                        {
                            return Err(Self::symbol_to_string_error());
                        }
                        // ES2025 27.1.3.1 step 1: NewTarget is Iterator itself.
                        if standard_name == Some("Iterator") {
                            return Err(self.abstract_iterator_construction_error());
                        }
                        if builtin.kind.observes_host_effect_selection() {
                            self.clear_pending_hostcall_result_label();
                        }
                        let mut result = match standard_name {
                            _ if builtin.kind
                                == BuiltinFunctionKind::NativeChildProcessFunction =>
                            {
                                self.construct_builtin_with_new_target_and_labels(
                                    module,
                                    builtin,
                                    args,
                                    &callee_val,
                                    &callee_label,
                                    &callee_label,
                                )?
                            }
                            _ if builtin.kind == BuiltinFunctionKind::DateConstructor => {
                                self.dispatch_builtin_hostcall("builtin:Date", args, Some(module))?
                            }
                            Some(name) if Self::buffer_family_constructor(name) => self
                                .dispatch_builtin_hostcall(
                                    &format!("builtin:{name}"),
                                    args,
                                    Some(module),
                                )?,
                            Some(name) if event_target::EVENT_TARGET_FAMILY.contains(&name) => {
                                self.construct_event_target_family(module, name, args)?
                            }
                            Some("Blob") => self.construct_blob(module, args)?,
                            Some("SharedArrayBuffer") => self.dispatch_builtin_hostcall(
                                "builtin:SharedArrayBuffer",
                                args,
                                Some(module),
                            )?,
                            // The collections construct through their
                            // hostcalls; called, they throw (ES2020 23.1.1.1).
                            Some(
                                name @ ("Proxy"
                                | "WeakRef"
                                | "FinalizationRegistry"
                                | "Map"
                                | "Set"
                                | "WeakMap"
                                | "WeakSet"),
                            ) => self.dispatch_builtin_hostcall(
                                &format!("builtin:{name}"),
                                args,
                                Some(module),
                            )?,
                            _ => self.dispatch_builtin_function_with_callee_register(
                                module, builtin, args, None, None, callee,
                            )?,
                        };
                        // ES2020 20.1.1.1, 21.1.1.1, 19.3.1.1: `new Number(x)`,
                        // `new String(x)` and `new Boolean(x)` wrap the converted
                        // primitive (bd-9vouw.48); called, they return it.
                        if builtin.kind == BuiltinFunctionKind::StandardConstructor
                            && matches!(
                                Self::standard_constructor_name(builtin),
                                Ok("Number" | "String" | "Boolean")
                            )
                            && !result.is_object_like()
                        {
                            result = Value::Object(self.alloc_primitive_wrapper(result)?);
                        }
                        // IFC: a `new Builtin(...)` result derives entirely from
                        // its argument registers, so the dst label is the join
                        // of the arg labels — same contract as the `Call`
                        // builtin arm. Without this, `new Array(secretLen)` /
                        // `new String(secret)` would read as Public and leak via
                        // a later egress hostcall (same under-tainting family as
                        // bd-n2mjy / bd-0zybl / bd-ooaka.1).
                        let args_label = self.join_arg_range_label(args)?;
                        let result_label = if builtin.kind.observes_host_effect_selection() {
                            let observed = self
                                .take_pending_hostcall_result_label()
                                .unwrap_or(Label::Public);
                            self.join_owned_label_with_temporary_budget(observed, &args_label)?
                        } else {
                            args_label
                        };
                        self.write_reg_with_label(dst, result, result_label.join(&callee_label))?;
                        self.ip += 1;
                        continue;
                    }

                    if self.foreign_closure_module(&callee_val, module)?.is_some() {
                        let call_labels =
                            self.clone_isolated_call_labels_from_registers(Some(callee), args)?;
                        let arguments = self.call_arguments(args)?;
                        let (result, result_label) = match self.invoke_inline_construct_with_labels(
                            Some(module),
                            callee_val.clone(),
                            arguments,
                            Some(call_labels),
                            None,
                        ) {
                            Ok(value) => value,
                            Err(err) => match self.route_isolated_explicit_throw(module, err)? {
                                None => continue,
                                Some(err) => return Err(err),
                            },
                        };
                        self.write_reg_with_label(dst, result, result_label)?;
                        self.ip += 1;
                        continue;
                    }

                    // The callee's default prototype object holds its
                    // constructor metadata, its instance field list and its
                    // HomeObject; resolve it once (bd-9vouw.504).
                    let default_prototype =
                        self.default_constructor_prototype_for_value(module, &callee_val)?;
                    let (is_derived, is_default_derived, _, _) =
                        self.derived_constructor_metadata_of_prototype(default_prototype)?;
                    if is_derived || is_default_derived {
                        if let Err(error) = self.enter_constructor_call(
                            module,
                            callee_val.clone(),
                            callee_label.clone(),
                            args,
                            self.ip + 1,
                            dst,
                            callee_val,
                            callee_label,
                            false,
                            compact_tier1,
                        ) {
                            match self.route_isolated_explicit_throw(module, error)? {
                                None => continue,
                                Some(error) => return Err(error),
                            }
                        }
                        continue;
                    }

                    // Resolve function index and optional captured environment.
                    let (func_idx, captured_env) = match &callee_val {
                        Value::Function(idx) => (*idx, None),
                        Value::Closure(closure_id) => {
                            let closure =
                                self.closures.get(*closure_id as usize).ok_or_else(|| {
                                    InterpreterError::TypeError {
                                        expected: "valid closure".to_string(),
                                        got: format!("closure#{closure_id} not found"),
                                    }
                                })?;
                            (
                                closure.function_index,
                                Some(self.clone_scope_frames_with_budget(&closure.captured_env)?),
                            )
                        }
                        _ => {
                            return Err(InterpreterError::TypeError {
                                expected: "function".to_string(),
                                got: callee_val.type_name().to_string(),
                            });
                        }
                    };

                    match &callee_val {
                        Value::Function(_) | Value::Closure(_) => {
                            let func = module.function_table.get(func_idx as usize).ok_or(
                                InterpreterError::FunctionNotFound {
                                    index: func_idx,
                                    table_size: module.function_table.len() as u32,
                                },
                            )?;

                            let effective_depth = self.effective_call_depth();
                            if effective_depth >= self.config.max_call_depth {
                                return Err(InterpreterError::StackOverflow {
                                    depth: effective_depth,
                                    max: self.config.max_call_depth,
                                });
                            }

                            // Allocate the `this` object for the constructor.
                            let prototype = self
                                .constructor_prototype_other_than_default(module, &callee_val)?
                                .unwrap_or(default_prototype);
                            let builtin_parent = self.builtin_subclass_ancestor_name(prototype)?;
                            // An ordinary object, never an Array exotic
                            // (OrdinaryCreateFromConstructor, bd-9vouw.152).
                            let this_id = self.alloc_object_with_prototype(Some(prototype))?;
                            let this_index = this_id.0 as usize;
                            self.mutate_heap(|heap| {
                                if let Some(this_obj) = heap.get_mut(this_index) {
                                    this_obj.constructor_function = Some(func_idx);
                                }
                            });
                            if let Some(builtin_name) = builtin_parent.as_deref() {
                                self.initialize_builtin_subclass_instance(
                                    Some(module),
                                    this_id,
                                    builtin_name,
                                    args,
                                )?;
                            }
                            let this_val = Value::Object(this_id);
                            // ES2022 [[Construct]] step 6.b: a base class's
                            // instance fields initialize on the new object
                            // before its constructor body and parameter
                            // initializers run (derived classes do this in
                            // `enter_constructor_call`, once super() returns).
                            let fields_initialized =
                                match self.class_instance_field_list(default_prototype) {
                                    Some(fields) => self.run_class_field_initializers(
                                        module,
                                        this_val.clone(),
                                        this_id,
                                        &fields,
                                    ),
                                    None => Ok(()),
                                };
                            if let Err(error) = fields_initialized {
                                match self.route_isolated_explicit_throw(module, error)? {
                                    None => continue,
                                    Some(error) => return Err(error),
                                }
                            }

                            let mut arg_vals = Vec::new();
                            let mut arg_labels = Vec::new();
                            for i in 0..args.count.min(func.arity) {
                                let reg = args.start.checked_add(i).ok_or(
                                    InterpreterError::RegisterOutOfBounds {
                                        register: args.start,
                                        max: self.config.max_registers,
                                    },
                                )?;
                                arg_vals.push(self.read_reg(reg)?);
                                arg_labels.push(self.get_register_label(reg)?.clone());
                            }
                            self.apply_rest_param(&mut arg_vals, func.rest_param_index, args)?;
                            self.apply_rest_param_labels(
                                &mut arg_labels,
                                func.rest_param_index,
                                args,
                            )?;
                            self.stage_arguments_object(module, func, func_idx, &callee_val, args)?;

                            self.run_pre_call_hook(module, &callee_val, func_idx, &arg_vals)?;
                            let super_home_object = self.constructor_super_home_object(
                                module,
                                func_idx,
                                default_prototype,
                            )?;

                            // Push constructor frame with `construct_this`.
                            let scope_depth = self.scope_chain.depth();
                            let captured_env_bytes = captured_env
                                .as_ref()
                                .map(|env| Self::estimate_scope_chain_bytes(env))
                                .unwrap_or(0);
                            let saved_chain = if captured_env.is_some() {
                                Some(self.snapshot_scope_chain_with_temporary_budget(
                                    captured_env_bytes,
                                )?)
                            } else {
                                None
                            };
                            let previous_scope_bytes = self.scope_chain_memory_bytes();
                            let previous_closure_bytes = self.closures_memory_bytes();
                            let previous_call_stack_bytes = self.call_stack_memory_bytes();
                            let construct_this_label = match self.active_execution_context_label() {
                                Some(active) => active.join(&callee_label),
                                None => callee_label.clone(),
                            };
                            if construct_this_label > Label::Public {
                                self.join_object_mutation_label(this_id, &construct_this_label)?;
                            }
                            let pushed_frame = CallFrame {
                                return_ip: self.ip + 1,
                                return_reg: dst,
                                register_base: self.register_base,
                                register_width: self.register_width,
                                function_index: Some(func_idx),
                                this_value: this_val.clone(),
                                this_label: construct_this_label.clone(),
                                new_target_value: callee_val.clone(),
                                new_target_label: callee_label,
                                super_value: Value::Undefined,
                                super_label: Label::Public,
                                super_home_object,
                                construct_this: Some(this_val.clone()),
                                derived_constructor: false,
                                this_initialized: true,
                                initialize_derived_this_on_return: false,
                                class_instance_fields: None,
                                saved_pending_exception: self.pending_exception.take(),
                                saved_pending_exception_label: std::mem::replace(
                                    &mut self.pending_exception_label,
                                    Label::Public,
                                ),
                                saved_pending_return: self.pending_return.take(),
                                saved_suspended_abrupt_depth: self
                                    .suspended_abrupt_completions
                                    .len(),
                                saved_finally_mode_depth: self.finally_frames.len(),
                                saved_scope_depth: scope_depth,
                                saved_scope_chain: saved_chain,
                                scope_inert_virtual_scope_bytes: 0,
                                async_function_id: None,
                                native_boundary: false,
                            };
                            self.call_stack
                                .push(pushed_frame, &mut self.closures.cold_cells);

                            // If calling a closure, restore its captured environment.
                            if let Some(env) = captured_env {
                                self.scope_chain.frames = env;
                            }
                            if let Err(err) = self.scope_chain.push(self.config.max_scope_depth) {
                                self.rollback_call_setup_state();
                                return Err(err);
                            }
                            if let Err(err) = self.apply_scope_closure_call_stack_memory_delta(
                                previous_scope_bytes,
                                previous_closure_bytes,
                                previous_call_stack_bytes,
                            ) {
                                self.rollback_call_setup_state();
                                return Err(err);
                            }

                            self.enter_stacked_register_frame_for_function(
                                module,
                                compact_tier1,
                                func_idx,
                            )?;
                            self.push_callee_pc_label(construct_this_label);

                            // Arguments occupy r0..rN-1, matching the IR3
                            // lowering's parameter-register allocation
                            // (lowering_pipeline.rs comment: "Allocate
                            // parameter registers r0..rN-1"). `this` is
                            // recovered through `LoadThis` reading
                            // `frame.this_value` and is not stored in a
                            // numbered register; writing it to register 0
                            // here used to clobber the first constructor
                            // parameter and silently corrupted
                            // `this.field = paramName` bodies (bd-a7kpw).
                            let _ = this_val;
                            for (i, (val, label)) in
                                arg_vals.into_iter().zip(arg_labels).enumerate()
                            {
                                let reg = i as u32;
                                if reg < self.config.max_registers {
                                    self.write_reg_with_label(reg, val, label)?;
                                }
                            }

                            self.ip = func.entry as usize;
                        }
                        _ => {
                            return Err(InterpreterError::TypeError {
                                expected: "function".to_string(),
                                got: callee_val.type_name().to_string(),
                            });
                        }
                    }
                }
                Ir3Instruction::TemplateLiteral { parts, dst } => {
                    // bd-9vouw.37: an object substitution is ToString(ToPrimitive
                    // (hint string)), which may run its toString/valueOf; only
                    // the reentrant path can run guest code.
                    if (0..parts.count).any(|i| {
                        parts
                            .start
                            .checked_add(i)
                            .is_some_and(|reg| self.register_needs_observable_to_primitive(reg))
                    }) {
                        return Ok(DispatchOutcome::ReentrantInstruction {
                            instruction_ip: self.ip,
                            profile_start,
                        });
                    }
                    // Concatenate over exact code units so string parts
                    // holding lone surrogates keep them (and heal across
                    // part boundaries) instead of collapsing to the lossy
                    // projection (bd-neika).
                    let mut result = JsString::empty();
                    for i in 0..parts.count {
                        let reg = parts.start.checked_add(i).ok_or(
                            InterpreterError::RegisterOutOfBounds {
                                register: parts.start,
                                max: self.config.max_registers,
                            },
                        )?;
                        let val = self.read_reg(reg)?;
                        let part_str = self.template_part_js_string(val)?;
                        self.check_string_limit(result.len().saturating_add(part_str.len()))?;
                        result = result.concat(&part_str);
                    }
                    // IFC: the concatenated string is derived from every part —
                    // `` `${secret}` `` must carry the secret's label, not the
                    // dst register's stale prior label (the bd-0zybl / bd-n2mjy
                    // under-tainting class). Same join contract as HostCall
                    // arguments: the new value depends exactly on the parts, so
                    // overwrite dst's label with the join of all part labels.
                    let parts_label = self.join_arg_range_label(parts)?;
                    self.write_reg_with_label(dst, Value::Str(result), parts_label)?;
                    self.ip += 1;
                }
                Ir3Instruction::Halt => {
                    return Err(InterpreterError::Halted);
                }
                Ir3Instruction::LoadThis { dst } => {
                    if self
                        .call_stack
                        .last()
                        .is_some_and(|frame| frame.derived_constructor && !frame.this_initialized)
                    {
                        let error = InterpreterError::UninitializedBinding {
                            name: "this".to_string(),
                        };
                        match self.route_isolated_explicit_throw(module, error)? {
                            None => continue,
                            Some(error) => return Err(error),
                        }
                    }
                    let (this_val, this_label) = self.current_this_binding()?;
                    self.write_reg_with_label(dst, this_val, this_label)?;
                    self.ip += 1;
                }
                Ir3Instruction::LoadNewTarget { dst } => {
                    let (new_target, new_target_label) =
                        self.call_stack
                            .last()
                            .map_or((Value::Undefined, Label::Public), |frame| {
                                (
                                    frame.new_target_value.clone(),
                                    frame.new_target_label.clone(),
                                )
                            });
                    self.write_reg_with_label(dst, new_target, new_target_label)?;
                    self.ip += 1;
                }
                Ir3Instruction::LoadSuper { dst } => {
                    let (mut super_value, mut super_label, super_home_object) =
                        if let Some(frame) = self.call_stack.last() {
                            self.check_temporary_memory_budget(Self::estimate_label_bytes(
                                &frame.super_label,
                            ))?;
                            (
                                frame.super_value.clone(),
                                frame.super_label.clone(),
                                frame.super_home_object,
                            )
                        } else {
                            (Value::Undefined, Label::Public, None)
                        };
                    if let Some(home_object) = super_home_object {
                        let home = self
                            .heap
                            .get(home_object.0 as usize)
                            .ok_or(InterpreterError::ObjectNotFound { id: home_object.0 })?;
                        // An unset [[Prototype]] link is the implicit one, not
                        // null: an object literal method's super base is
                        // Object.prototype, and a base class's static
                        // method's (its home is the constructor's backing
                        // object) is Function.prototype. Both read null, so
                        // `super.x = 1` and `super.toString` threw.
                        super_value = match (home.prototype, home.is_null_prototype) {
                            (Some(prototype), _) => Value::Object(prototype),
                            (None, true) => Value::Null,
                            (None, false)
                                if self
                                    .function_value_for_backing(module, home_object)
                                    .is_some() =>
                            {
                                self.builtin_prototype_value("Function")?
                            }
                            (None, false) => self
                                .ordinary_get_prototype_of(home_object)?
                                .map_or(Value::Null, Value::Object),
                        };
                        if let Some(home_label) = self.binary_storage_label_ref(home_object) {
                            super_label = self
                                .join_owned_label_with_temporary_budget(super_label, home_label)?;
                        }
                        if let Some(home_label) = self.object_mutation_labels.get(&home_object) {
                            super_label = self
                                .join_owned_label_with_temporary_budget(super_label, home_label)?;
                        }
                    }
                    self.write_reg_with_label(dst, super_value, super_label)?;
                    self.ip += 1;
                }
                // ---------------------------------------------------------
                // Exception handling — real unwinding semantics (RGC-313B).
                // ---------------------------------------------------------
                Ir3Instruction::BeginTry {
                    catch_target,
                    finally_target,
                } => {
                    self.catch_frames.push(CatchFrame {
                        catch_target: catch_target as usize,
                        finally_target: finally_target.map(|t| t as usize),
                        call_depth: self.call_stack.len(),
                        finally_frame_depth: self.finally_frames.len(),
                    });
                    self.ip += 1;
                }
                Ir3Instruction::EndTry => {
                    // Normal completion of the try block — pop the catch frame.
                    let _ = self.pop_current_try_frame();
                    self.ip += 1;
                }
                Ir3Instruction::Throw { value } => {
                    let thrown = self.read_reg(value)?;
                    // IFC: the thrown value's confidentiality travels with the
                    // exception (bd-l0d6z, fifth member of the bd-n2mjy /
                    // bd-0zybl under-tainting family). Capture the source
                    // register's label so `EnterCatch` re-establishes it on
                    // the catch binding instead of leaving a stale label.
                    let mut thrown_label =
                        self.clone_register_label_with_temporary_budget(value)?;
                    if let Some(context) = self.active_execution_context_label() {
                        thrown_label =
                            self.join_owned_label_with_temporary_budget(thrown_label, context)?;
                    }
                    self.pending_finally_entry = None;
                    self.suspend_current_abrupt_completion()?;
                    self.replace_pending_abrupt_slots(
                        Some((thrown.clone(), thrown_label.clone())),
                        None,
                    )?;
                    // Walk the catch frame stack to find the nearest valid handler.
                    // Use rposition to find the topmost matching frame by index,
                    // then truncate to remove it and any frames above it — but
                    // NOT frames below it (which belong to outer try blocks).
                    if let Some(frame) = self.pop_exception_target_frame()? {
                        self.select_exception_target(Some(module), frame);
                    } else {
                        // No catch handler found — uncaught exception.
                        if self.reject_nearest_async_boundary(thrown.clone(), thrown_label)? {
                            continue;
                        }
                        self.clear_suspended_abrupt_completions();
                        self.clear_finally_frames();
                        self.pending_finally_entry = None;
                        return Err(InterpreterError::UncaughtException {
                            value: self.uncaught_exception_description(&thrown),
                        });
                    }
                }
                Ir3Instruction::EnterCatch { dst } => {
                    // Load the pending exception into the catch binding register.
                    // Take the label BEFORE restoring a suspended completion,
                    // which may overwrite the shadow with an outer exception's
                    // label (bd-l0d6z).
                    let (exception, exception_label) = self
                        .take_pending_exception_slot()
                        .unwrap_or((Value::Undefined, Label::Public));
                    self.restore_suspended_abrupt_completion();
                    self.write_reg_with_label(dst, exception, exception_label)?;
                    self.ip += 1;
                }
                Ir3Instruction::EnterFinally => {
                    self.enter_finally_frame()?;
                    self.ip += 1;
                }
                Ir3Instruction::EndFinally => {
                    match self.take_finally_completion() {
                        Some(AbruptCompletion::Exception(thrown, thrown_label)) => {
                            self.clear_pending_abrupt_slots();
                            let desc = self.uncaught_exception_description(&thrown);
                            self.pending_exception = Some(thrown);
                            self.pending_exception_label = thrown_label;
                            if let Some(frame) = self.pop_exception_target_frame()? {
                                self.select_exception_target(Some(module), frame);
                            } else if self.nearest_async_call_depth().is_some() {
                                let (thrown, thrown_label) = self
                                    .take_pending_exception_slot()
                                    .expect("owned finally exception remained pending");
                                if self.reject_nearest_async_boundary(thrown, thrown_label)? {
                                    continue;
                                }
                                return Err(InterpreterError::InternalError {
                                    details: "async boundary disappeared while completing finally"
                                        .to_string(),
                                });
                            } else {
                                self.clear_suspended_abrupt_completions();
                                self.clear_finally_frames();
                                self.pending_finally_entry = None;
                                return Err(InterpreterError::UncaughtException { value: desc });
                            }
                        }
                        Some(AbruptCompletion::Return(pending_return)) => {
                            self.clear_pending_abrupt_slots();
                            if let Some(finally_target) = self.pop_current_finally_target() {
                                self.pending_return = Some(pending_return);
                                self.pending_finally_entry = Some(PendingFinallyEntry {
                                    target: finally_target,
                                    mode: FinallyMode::Return,
                                });
                                self.ip = finally_target;
                            } else {
                                self.estimated_memory_bytes =
                                    self.estimated_memory_bytes.saturating_sub(
                                        Self::estimate_labeled_return_bytes(&pending_return),
                                    );
                                match self.complete_return(
                                    Some(module),
                                    pending_return.value,
                                    pending_return.label,
                                ) {
                                    Ok(Some(completion)) => {
                                        return Ok(DispatchOutcome::Complete(completion));
                                    }
                                    Ok(None) => {}
                                    Err(error) => {
                                        match self.route_isolated_explicit_throw(module, error)? {
                                            None => continue,
                                            Some(error) => return Err(error),
                                        }
                                    }
                                }
                            }
                        }
                        None => {
                            // Normal completion — just continue.
                            self.ip += 1;
                        }
                    }
                }
                Ir3Instruction::DiscardAbruptCompletion => {
                    self.discard_current_finally_frame();
                    self.restore_suspended_abrupt_completion();
                    self.ip += 1;
                }

                // ���─ Closure / scope-chain instructions ────────────────
                Ir3Instruction::CreateClosure {
                    dst,
                    function_index,
                    capture_count,
                } => {
                    self.run_pre_allocation_hook(
                        module,
                        AllocKind::Closure,
                        capture_count as usize,
                    )?;
                    // Snapshot the current scope chain including any
                    // bindings declared so far. Pending captures were
                    // accumulated by prior PushCapture instructions but
                    // the scope chain snapshot already contains those
                    // bindings, so we just clear them.
                    let previous_estimated_memory_bytes = self.estimated_memory_bytes;
                    let previous_closure_bytes = self.closures_memory_bytes();
                    let lexical_super_metadata =
                        self.capture_current_lexical_super_metadata(module, function_index)?;
                    let lexical_super_temporary_bytes = lexical_super_metadata
                        .as_ref()
                        .map(Self::estimate_closure_lexical_super_metadata_entry_bytes)
                        .unwrap_or(0);
                    let captured_env = self.snapshot_scope_chain_with_temporary_budget(
                        lexical_super_temporary_bytes,
                    )?;
                    let closure_id = u32::try_from(self.closures.len()).map_err(|_| {
                        InterpreterError::TypeError {
                            expected: "closure table capacity".into(),
                            got: format!("exceeded u32::MAX ({})", self.closures.len()),
                        }
                    })?;
                    self.closures.push(ClosureValue {
                        function_index,
                        captured_env,
                    });
                    self.record_closure_program_provenance(closure_id, module);
                    if let Some(metadata) = lexical_super_metadata {
                        self.closure_lexical_super_metadata
                            .insert(closure_id, metadata);
                    }
                    if let Err(err) = self.apply_closures_memory_delta(previous_closure_bytes) {
                        self.closures.pop();
                        self.closure_lexical_super_metadata.remove(&closure_id);
                        self.remove_closure_program_provenance(closure_id);
                        return Err(err);
                    }
                    // Store the closure ID (not function_index) so Call can
                    // look up the correct closure instance.
                    if let Err(err) = self.write_reg(dst, Value::Closure(closure_id)) {
                        self.closures.pop();
                        self.closure_lexical_super_metadata.remove(&closure_id);
                        self.remove_closure_program_provenance(closure_id);
                        self.estimated_memory_bytes = previous_estimated_memory_bytes;
                        return Err(err);
                    }
                    self.pending_captures.clear();
                    self.ip += 1;
                }
                Ir3Instruction::CreateArrowClosure {
                    dst,
                    function_index,
                    capture_count,
                } => {
                    // bd-asw4m.3: identical to CreateClosure, plus the
                    // creating frame's lexical `this` is captured so later
                    // Call/CallMethod invocations bind it instead of the
                    // receiver. Top-level arrows capture `undefined`.
                    self.run_pre_allocation_hook(
                        module,
                        AllocKind::Closure,
                        capture_count as usize,
                    )?;
                    // Resolved before the accounting snapshot: a first
                    // top-level read allocates the top-level `this` object.
                    let lexical_this = self.current_this_binding()?;
                    let previous_estimated_memory_bytes = self.estimated_memory_bytes;
                    let previous_closure_bytes = self.closures_memory_bytes();
                    let lexical_super_metadata =
                        self.capture_current_lexical_super_metadata(module, function_index)?;
                    let lexical_super_temporary_bytes = lexical_super_metadata
                        .as_ref()
                        .map(Self::estimate_closure_lexical_super_metadata_entry_bytes)
                        .unwrap_or(0);
                    let lexical_this_temporary_bytes =
                        Self::estimate_arrow_lexical_this_entry_bytes(&lexical_this);
                    let captured_env = self.snapshot_scope_chain_with_temporary_budget(
                        lexical_super_temporary_bytes.saturating_add(lexical_this_temporary_bytes),
                    )?;
                    let closure_id = u32::try_from(self.closures.len()).map_err(|_| {
                        InterpreterError::TypeError {
                            expected: "closure table capacity".into(),
                            got: format!("exceeded u32::MAX ({})", self.closures.len()),
                        }
                    })?;
                    self.closures.push(ClosureValue {
                        function_index,
                        captured_env,
                    });
                    self.record_closure_program_provenance(closure_id, module);
                    if let Some(metadata) = lexical_super_metadata {
                        self.closure_lexical_super_metadata
                            .insert(closure_id, metadata);
                    }
                    self.arrow_lexical_this.insert(closure_id, lexical_this);
                    if let Err(err) = self.apply_closures_memory_delta(previous_closure_bytes) {
                        self.closures.pop();
                        self.closure_lexical_super_metadata.remove(&closure_id);
                        self.arrow_lexical_this.remove(&closure_id);
                        self.remove_closure_program_provenance(closure_id);
                        return Err(err);
                    }
                    if let Err(err) = self.write_reg(dst, Value::Closure(closure_id)) {
                        self.closures.pop();
                        self.closure_lexical_super_metadata.remove(&closure_id);
                        self.arrow_lexical_this.remove(&closure_id);
                        self.remove_closure_program_provenance(closure_id);
                        self.estimated_memory_bytes = previous_estimated_memory_bytes;
                        return Err(err);
                    }
                    self.pending_captures.clear();
                    self.ip += 1;
                }
                Ir3Instruction::CreateGenerator {
                    dst,
                    function_index,
                    capture_count,
                } => {
                    self.run_pre_allocation_hook(
                        module,
                        AllocKind::Closure,
                        capture_count as usize,
                    )?;
                    let previous_estimated_memory_bytes = self.estimated_memory_bytes;
                    let captured_env = self.snapshot_scope_chain()?;
                    let closure_id = u32::try_from(self.closures.len()).map_err(|_| {
                        InterpreterError::TypeError {
                            expected: "closure table capacity".into(),
                            got: format!("exceeded u32::MAX ({})", self.closures.len()),
                        }
                    })?;
                    let previous_closure_bytes = self.closures_memory_bytes();
                    self.closures.push(ClosureValue {
                        function_index,
                        captured_env,
                    });
                    self.record_closure_program_provenance(closure_id, module);
                    if let Err(err) = self.apply_closures_memory_delta(previous_closure_bytes) {
                        self.closures.pop();
                        self.remove_closure_program_provenance(closure_id);
                        return Err(err);
                    }
                    if let Err(err) = self.write_reg(dst, Value::GeneratorFunction(closure_id)) {
                        self.closures.pop();
                        self.remove_closure_program_provenance(closure_id);
                        self.estimated_memory_bytes = previous_estimated_memory_bytes;
                        return Err(err);
                    }
                    self.pending_captures.clear();
                    self.ip += 1;
                }
                Ir3Instruction::CreateAsyncFunction {
                    dst,
                    function_index,
                    capture_count,
                } => {
                    self.run_pre_allocation_hook(
                        module,
                        AllocKind::Closure,
                        capture_count as usize,
                    )?;
                    let previous_estimated_memory_bytes = self.estimated_memory_bytes;
                    let lexical_super_metadata =
                        self.capture_current_lexical_super_metadata(module, function_index)?;
                    let lexical_super_temporary_bytes = lexical_super_metadata
                        .as_ref()
                        .map(Self::estimate_closure_lexical_super_metadata_entry_bytes)
                        .unwrap_or(0);
                    let captured_env = self.snapshot_scope_chain_with_temporary_budget(
                        lexical_super_temporary_bytes,
                    )?;
                    let closure_id = u32::try_from(self.closures.len()).map_err(|_| {
                        InterpreterError::TypeError {
                            expected: "closure table capacity".into(),
                            got: format!("exceeded u32::MAX ({})", self.closures.len()),
                        }
                    })?;
                    let previous_closure_bytes = self.closures_memory_bytes();
                    self.closures.push(ClosureValue {
                        function_index,
                        captured_env,
                    });
                    self.record_closure_program_provenance(closure_id, module);
                    if let Some(metadata) = lexical_super_metadata {
                        self.closure_lexical_super_metadata
                            .insert(closure_id, metadata);
                    }
                    if let Err(err) = self.apply_closures_memory_delta(previous_closure_bytes) {
                        self.closures.pop();
                        self.closure_lexical_super_metadata.remove(&closure_id);
                        self.remove_closure_program_provenance(closure_id);
                        return Err(err);
                    }
                    if let Err(err) = self.write_reg(dst, Value::AsyncFunction(closure_id)) {
                        self.closures.pop();
                        self.closure_lexical_super_metadata.remove(&closure_id);
                        self.remove_closure_program_provenance(closure_id);
                        self.estimated_memory_bytes = previous_estimated_memory_bytes;
                        return Err(err);
                    }
                    self.pending_captures.clear();
                    self.ip += 1;
                }
                Ir3Instruction::CreateAsyncArrowClosure {
                    dst,
                    function_index,
                    capture_count,
                } => {
                    // bd-asw4m.3: identical to CreateAsyncFunction, plus the
                    // creating frame's lexical `this` is captured (see
                    // CreateArrowClosure).
                    self.run_pre_allocation_hook(
                        module,
                        AllocKind::Closure,
                        capture_count as usize,
                    )?;
                    // Resolved before the accounting snapshot: a first
                    // top-level read allocates the top-level `this` object.
                    let lexical_this = self.current_this_binding()?;
                    let previous_estimated_memory_bytes = self.estimated_memory_bytes;
                    let lexical_super_metadata =
                        self.capture_current_lexical_super_metadata(module, function_index)?;
                    let lexical_super_temporary_bytes = lexical_super_metadata
                        .as_ref()
                        .map(Self::estimate_closure_lexical_super_metadata_entry_bytes)
                        .unwrap_or(0);
                    let lexical_this_temporary_bytes =
                        Self::estimate_arrow_lexical_this_entry_bytes(&lexical_this);
                    let captured_env = self.snapshot_scope_chain_with_temporary_budget(
                        lexical_super_temporary_bytes.saturating_add(lexical_this_temporary_bytes),
                    )?;
                    let closure_id = u32::try_from(self.closures.len()).map_err(|_| {
                        InterpreterError::TypeError {
                            expected: "closure table capacity".into(),
                            got: format!("exceeded u32::MAX ({})", self.closures.len()),
                        }
                    })?;
                    let previous_closure_bytes = self.closures_memory_bytes();
                    self.closures.push(ClosureValue {
                        function_index,
                        captured_env,
                    });
                    self.record_closure_program_provenance(closure_id, module);
                    if let Some(metadata) = lexical_super_metadata {
                        self.closure_lexical_super_metadata
                            .insert(closure_id, metadata);
                    }
                    self.arrow_lexical_this.insert(closure_id, lexical_this);
                    if let Err(err) = self.apply_closures_memory_delta(previous_closure_bytes) {
                        self.closures.pop();
                        self.closure_lexical_super_metadata.remove(&closure_id);
                        self.arrow_lexical_this.remove(&closure_id);
                        self.remove_closure_program_provenance(closure_id);
                        return Err(err);
                    }
                    if let Err(err) = self.write_reg(dst, Value::AsyncFunction(closure_id)) {
                        self.closures.pop();
                        self.closure_lexical_super_metadata.remove(&closure_id);
                        self.arrow_lexical_this.remove(&closure_id);
                        self.remove_closure_program_provenance(closure_id);
                        self.estimated_memory_bytes = previous_estimated_memory_bytes;
                        return Err(err);
                    }
                    self.pending_captures.clear();
                    self.ip += 1;
                }
                Ir3Instruction::CreateAsyncGenerator {
                    dst,
                    function_index,
                    capture_count,
                } => {
                    self.run_pre_allocation_hook(
                        module,
                        AllocKind::Closure,
                        capture_count as usize,
                    )?;
                    let previous_estimated_memory_bytes = self.estimated_memory_bytes;
                    let captured_env = self.snapshot_scope_chain()?;
                    let closure_id = u32::try_from(self.closures.len()).map_err(|_| {
                        InterpreterError::TypeError {
                            expected: "closure table capacity".into(),
                            got: format!("exceeded u32::MAX ({})", self.closures.len()),
                        }
                    })?;
                    let previous_closure_bytes = self.closures_memory_bytes();
                    self.closures.push(ClosureValue {
                        function_index,
                        captured_env,
                    });
                    self.record_closure_program_provenance(closure_id, module);
                    if let Err(err) = self.apply_closures_memory_delta(previous_closure_bytes) {
                        self.closures.pop();
                        self.remove_closure_program_provenance(closure_id);
                        return Err(err);
                    }
                    if let Err(err) = self.write_reg(dst, Value::AsyncGeneratorFunction(closure_id))
                    {
                        self.closures.pop();
                        self.remove_closure_program_provenance(closure_id);
                        self.estimated_memory_bytes = previous_estimated_memory_bytes;
                        return Err(err);
                    }
                    self.pending_captures.clear();
                    self.ip += 1;
                }
                Ir3Instruction::Yield {
                    value,
                    delegate,
                    resume_dst,
                } => {
                    if delegate {
                        return Ok(DispatchOutcome::GeneratorDelegate {
                            source: value,
                            resume_dst,
                        });
                    }
                    let yielded = self.read_reg(value)?;
                    let yielded_label = self.clone_register_label_with_temporary_budget(value)?;
                    let mut yielded_label =
                        if let Some(context) = self.active_execution_context_label().cloned() {
                            self.join_owned_label_with_temporary_budget(yielded_label, &context)?
                        } else {
                            yielded_label
                        };
                    if let Some(artifact_label) = self.active_generated_artifact_source_label() {
                        yielded_label = self.join_owned_label_with_temporary_budget(
                            yielded_label,
                            &artifact_label,
                        )?;
                    }
                    let result_id = self.alloc_object_with_prototype(None)?;
                    {
                        self.set_object_property(result_id, "value".to_string(), yielded)?;
                        if yielded_label != Label::Public {
                            self.set_own_runtime_property_label(
                                result_id,
                                &RuntimePropertyKey::String(JsString::from("value")),
                                &yielded_label,
                            )?;
                        }
                        self.set_object_property(
                            result_id,
                            "done".to_string(),
                            Value::Bool(false),
                        )?;
                    }
                    self.ip += 1;
                    self.write_reg(resume_dst, Value::Undefined)?;
                    // bd-hoplz: mark this `run_loop` exit as a yield-suspension so
                    // `generator_next` does not mistake it for a completion-by-return.
                    self.generator_yielded = true;
                    self.generator_resume_dst = Some(resume_dst);
                    self.generator_result_label = yielded_label;
                    return Ok(DispatchOutcome::Complete(LabeledReturn {
                        value: Value::Object(result_id),
                        label: self.generator_result_label.clone(),
                    }));
                }
                await_instruction @ (Ir3Instruction::AwaitValue { promise_reg }
                | Ir3Instruction::ModuleAwaitValue { promise_reg }) => {
                    let is_module_await =
                        matches!(await_instruction, Ir3Instruction::ModuleAwaitValue { .. });
                    if !is_module_await
                        && self.nearest_async_call_depth().is_none()
                        && let Some(id) = self.async_generator_runtime.active
                    {
                        self.suspend_async_generator_await(id, promise_reg)?;
                        return Ok(DispatchOutcome::Complete(LabeledReturn {
                            value: Value::Undefined,
                            label: Label::Public,
                        }));
                    }
                    if is_module_await {
                        let current = self.current_module_specifier.as_deref();
                        if !self.call_stack.is_empty() {
                            return Err(InterpreterError::ModuleEvaluationFailed {
                                specifier: current.unwrap_or("<unknown>").to_string(),
                                reason: "module await executed with an active function frame"
                                    .to_string(),
                            });
                        }
                    }

                    let awaited_value = self.read_reg(promise_reg)?;
                    let mut awaited_label = self.get_register_label(promise_reg)?.clone();

                    // Convert the awaited value to a Promise if it's not already one
                    let promise_handle = match awaited_value {
                        Value::Promise(h) => {
                            // PromiseResolve reads its `constructor`
                            // (bd-9vouw.352); what the read observes labels
                            // the await, and a pending HostCall result label
                            // is set aside.
                            let saved_result_label = self.take_pending_hostcall_result_label();
                            let keeps = self.await_keeps_promise(module, h);
                            let observed = self.take_pending_hostcall_result_label();
                            if let Some(saved) = saved_result_label {
                                self.replace_pending_hostcall_result_label(Some(saved))?;
                            }
                            if let Some(observed) = observed {
                                awaited_label = awaited_label.join(&observed);
                            }
                            if keeps? {
                                crate::promise_model::PromiseHandle(h)
                            } else {
                                let handle = self.create_promise()?;
                                self.resolve_promise_with_value(
                                    Some(module),
                                    handle,
                                    Value::Promise(h),
                                    awaited_label.clone(),
                                )?;
                                handle
                            }
                        }
                        // PromiseResolve observes then on every object-like
                        // representation, including callable and iterator
                        // values, before queuing a thenable job.
                        value if value.is_object_like() => {
                            let handle = self.create_promise()?;
                            self.resolve_promise_with_value(
                                Some(module),
                                handle,
                                value,
                                awaited_label.clone(),
                            )?;
                            handle
                        }
                        _ => {
                            // await non-promise: create a resolved promise with the value
                            let js_val = self.promise_value(&awaited_value)?;
                            self.create_fulfilled_promise(js_val, awaited_label.clone())?
                        }
                    };

                    // Check if the promise is already settled
                    let promise_record = self.promise_store.get(promise_handle).map_err(|e| {
                        InterpreterError::TypeError {
                            expected: "valid promise".to_string(),
                            got: e.to_string(),
                        }
                    })?;
                    let promise_label = promise_record.label.clone();
                    let effective_label = awaited_label.join(&promise_label);

                    // Await always crosses a Promise-reaction microtask
                    // boundary, including for non-Promise and already-settled
                    // operands (ES2020 25.7.5.3; bd-9vouw.26). An async
                    // function runs in its own isolated activation, so only
                    // that activation is parked and its caller continues.
                    if is_module_await {
                        self.suspend_top_level_await(promise_handle, promise_reg, effective_label)?;
                    } else {
                        self.suspend_async_function_for_await(
                            promise_handle,
                            promise_reg,
                            effective_label,
                        )?;
                    }
                    // Suspension marker, not program data: the resumed
                    // completion carries the real label.
                    return Ok(DispatchOutcome::Complete(LabeledReturn {
                        value: Value::Undefined,
                        label: Label::Public,
                    }));
                }
                Ir3Instruction::AsyncReturn { value_reg } => {
                    let return_value = self.read_reg(value_reg)?;
                    let mut return_label = self.get_register_label(value_reg)?.clone();
                    if let Some(context) = self.active_execution_context_label().cloned() {
                        return_label =
                            self.join_owned_label_with_temporary_budget(return_label, &context)?;
                    }
                    if let Some(artifact_label) = self.active_generated_artifact_source_label() {
                        return_label = self.join_owned_label_with_temporary_budget(
                            return_label,
                            &artifact_label,
                        )?;
                    }
                    if let Some(completion) = self.complete_current_async_frame(
                        Some(module),
                        Ok(return_value),
                        return_label,
                    )? {
                        return Ok(DispatchOutcome::Complete(completion));
                    }
                    continue;
                }
                Ir3Instruction::AsyncThrow { error_reg } => {
                    let error_value = self.read_reg(error_reg)?;
                    let mut error_label = self.get_register_label(error_reg)?.clone();
                    if let Some(context) = self.active_execution_context_label().cloned() {
                        error_label =
                            self.join_owned_label_with_temporary_budget(error_label, &context)?;
                    }
                    if let Some(artifact_label) = self.active_generated_artifact_source_label() {
                        error_label = self
                            .join_owned_label_with_temporary_budget(error_label, &artifact_label)?;
                    }
                    if let Some(completion) = self.complete_current_async_frame(
                        Some(module),
                        Err(error_value),
                        error_label,
                    )? {
                        return Ok(DispatchOutcome::Complete(completion));
                    }
                    continue;
                }
                Ir3Instruction::PushCapture { name_pool_index } => {
                    self.pending_captures.push(name_pool_index);
                    self.ip += 1;
                }
                Ir3Instruction::PushScope => {
                    // bd-9vouw.31: an empty frame changes only structural
                    // bytes.
                    let previous_scope_bytes = self.scope_chain_structural_bytes();
                    #[cfg(debug_assertions)]
                    let walked_scope_before = self.scope_chain_memory_bytes();
                    self.scope_chain.push(self.config.max_scope_depth)?;
                    #[cfg(debug_assertions)]
                    self.debug_assert_scope_swap_delta(
                        walked_scope_before,
                        previous_scope_bytes,
                        0,
                    );
                    if let Err(err) = self.apply_memory_component_delta(
                        previous_scope_bytes,
                        self.scope_chain_structural_bytes(),
                    ) {
                        self.scope_chain.pop();
                        return Err(err);
                    }
                    if let Err(err) = self.inject_active_cjs_bindings() {
                        let previous_scope_bytes = self.scope_chain_memory_bytes();
                        self.scope_chain.pop();
                        self.apply_scope_chain_memory_delta(previous_scope_bytes)?;
                        return Err(err);
                    }
                    self.ip += 1;
                }
                Ir3Instruction::PopScope => {
                    // bd-9vouw.31: structural bytes plus the popped frame's
                    // own cells, which nothing else reaches unless captured
                    // (cold).
                    let previous_scope_bytes = self.scope_chain_structural_bytes();
                    #[cfg(debug_assertions)]
                    let walked_scope_before = self.scope_chain_memory_bytes();
                    let popped = self.scope_chain.pop();
                    if let Some(frame) = &popped {
                        let released_cell_bytes =
                            self.released_frame_cell_payload_bytes(std::slice::from_ref(frame));
                        #[cfg(debug_assertions)]
                        self.debug_assert_scope_swap_delta(
                            walked_scope_before,
                            previous_scope_bytes,
                            released_cell_bytes,
                        );
                        self.apply_memory_component_delta(
                            previous_scope_bytes.saturating_add(released_cell_bytes),
                            self.scope_chain_structural_bytes(),
                        )?;
                    }
                    debug_assert!(popped.is_some() || self.scope_chain.depth() == 1);
                    self.ip += 1;
                }
                Ir3Instruction::DeclareBinding {
                    name_pool_index,
                    kind,
                } => {
                    let name = Self::scoped_constant_name(module, name_pool_index);
                    if matches!(kind, GLOBAL_VAR_BINDING_KIND | GLOBAL_FUNCTION_BINDING_KIND) {
                        if self.ip == 0 {
                            self.validate_script_global_declarations(module)?;
                        }
                        self.instantiate_script_global_binding(name.as_ref(), kind)?;
                        self.ip += 1;
                        continue;
                    }
                    let binding_kind = BindingKind::from_u8(kind)?;
                    let existing = self.scope_chain.current()?.get(name.as_ref()).is_some();
                    // bd-9vouw.31: a new name adds its entry plus one fresh
                    // cell that nothing else reaches, and re-declaring an
                    // existing `var` changes nothing. Only replacing a
                    // lexical entry (rare) re-walks the live cells.
                    let local_delta = !existing || binding_kind == BindingKind::Var;
                    let previous_scope_bytes = if local_delta {
                        self.scope_chain_structural_bytes()
                    } else {
                        self.scope_chain_memory_bytes()
                    };
                    #[cfg(debug_assertions)]
                    let walked_scope_before = self.scope_chain_memory_bytes();
                    let checkpoint = self.scope_chain.current()?.bindings_checkpoint();
                    let replaced = self
                        .scope_chain
                        .current_mut()?
                        .declare(name.as_ref(), binding_kind);
                    let memory_result = if local_delta {
                        let added_cell_bytes = if existing {
                            0
                        } else {
                            self.scope_chain
                                .current()?
                                .get(name.as_ref())
                                .map_or(0, |binding| {
                                    Self::estimate_binding_cell_payload_bytes(&binding.state)
                                })
                        };
                        #[cfg(debug_assertions)]
                        debug_assert_eq!(
                            i128::from(self.scope_chain_memory_bytes())
                                - i128::from(walked_scope_before),
                            i128::from(self.scope_chain_structural_bytes())
                                - i128::from(previous_scope_bytes)
                                + i128::from(added_cell_bytes),
                            "a declaration must change scope memory by its entry and new cell"
                        );
                        self.apply_memory_component_delta(
                            previous_scope_bytes,
                            self.scope_chain_structural_bytes()
                                .saturating_add(added_cell_bytes),
                        )
                    } else {
                        self.apply_scope_chain_memory_delta(previous_scope_bytes)
                    };
                    if let Err(err) = memory_result {
                        if let Ok(current) = self.scope_chain.current_mut()
                            && !current.restore_copied_bindings(checkpoint)
                        {
                            if let Some(old) = replaced {
                                current.insert_binding(name.into_owned(), old);
                            } else {
                                current.remove_binding(name.as_ref());
                            }
                        }
                        return Err(err);
                    }
                    self.ip += 1;
                }
                Ir3Instruction::LoadScoped {
                    dst,
                    name_pool_index,
                } => {
                    let name = Self::scoped_constant_name(module, name_pool_index);
                    let (val, label) =
                        if let Some((_, binding)) = self.scope_chain.resolve(name.as_ref()) {
                            let state = binding.state()?;
                            if !state.initialized {
                                return Err(InterpreterError::UninitializedBinding {
                                    name: name.into_owned(),
                                });
                            }
                            (state.value.clone(), state.label.clone())
                        } else if let Some(context) = self.active_cjs_context.as_ref() {
                            let (filename, dirname) =
                                self.cjs_filename_dirname(Some(&context.module_specifier));
                            let value = match name.as_ref() {
                                "__filename" => filename,
                                "__dirname" => dirname,
                                _ => Value::Undefined,
                            };
                            (value, Label::Public)
                        } else {
                            (Value::Undefined, Label::Public)
                        };
                    self.write_reg_with_label(dst, val, label)?;
                    self.ip += 1;
                }
                Ir3Instruction::LoadName {
                    dst,
                    name_pool_index,
                    allow_missing,
                } => {
                    let name = Self::scoped_constant_name(module, name_pool_index);
                    match self.load_runtime_name_labeled(name.as_ref(), false) {
                        Err(InterpreterError::UndefinedBinding { .. }) => {
                            // A global binding performs a real property read:
                            // descriptor/prototype observations and a getter's
                            // return label belong to this instruction. The
                            // scope also seals catchable callback errors before
                            // returning to an enclosing native invocation.
                            self.clear_pending_hostcall_result_label();
                            let observation = self.begin_property_observation([])?;
                            let loaded =
                                match self.load_global_object_name(Some(module), name.as_ref()) {
                                    Ok(None) if !allow_missing => {
                                        Err(InterpreterError::UndefinedBinding {
                                            name: name.to_string(),
                                        })
                                    }
                                    loaded => loaded,
                                };
                            let loaded =
                                self.finish_property_read_observation(observation, loaded)?;
                            match loaded {
                                Some((val, label)) => {
                                    let label = if let Some(observed) =
                                        self.take_pending_hostcall_result_label()
                                    {
                                        self.join_owned_label_with_temporary_budget(
                                            label, &observed,
                                        )?
                                    } else {
                                        label
                                    };
                                    // Never lower a caller-seeded label on dst.
                                    let label = if let Some(seeded) =
                                        self.seeded_register_label(dst).cloned()
                                    {
                                        self.join_owned_label_with_temporary_budget(label, &seeded)?
                                    } else {
                                        label
                                    };
                                    self.write_reg_with_label(dst, val, label)?;
                                }
                                None => {
                                    debug_assert!(allow_missing);
                                    let label = self
                                        .take_pending_hostcall_result_label()
                                        .unwrap_or(Label::Public);
                                    let label = if let Some(seeded) =
                                        self.seeded_register_label(dst).cloned()
                                    {
                                        self.join_owned_label_with_temporary_budget(label, &seeded)?
                                    } else {
                                        label
                                    };
                                    self.write_reg_with_label(dst, Value::Undefined, label)?;
                                }
                            }
                        }
                        loaded => {
                            // A scope cell keeps its value's label (LoadScoped
                            // writes it); the read carries it, joined with any
                            // caller-seeded label on dst (bd-9vouw.487).
                            let (val, label) = loaded?;
                            let label =
                                if let Some(seeded) = self.seeded_register_label(dst).cloned() {
                                    self.join_owned_label_with_temporary_budget(label, &seeded)?
                                } else {
                                    label
                                };
                            self.write_reg_with_label(dst, val, label)?;
                        }
                    }
                    self.ip += 1;
                }
                Ir3Instruction::ResolveNameStatus {
                    dst,
                    name_pool_index,
                } => {
                    let name = Self::scoped_constant_name(module, name_pool_index);
                    let reference_token = self.capture_runtime_name_reference(name.as_ref())?;
                    self.write_reg(dst, Value::Int(i64::from(reference_token)))?;
                    self.ip += 1;
                }
                Ir3Instruction::DeleteName {
                    dst,
                    name_pool_index,
                } => {
                    let name = Self::scoped_constant_name(module, name_pool_index);
                    let result = self.delete_runtime_name(name.as_ref())?;
                    self.write_reg(dst, Value::Bool(result))?;
                    self.ip += 1;
                }
                Ir3Instruction::StoreScoped {
                    src,
                    name_pool_index,
                } => {
                    let name = Self::scoped_constant_name(module, name_pool_index);
                    let val = self.read_reg(src)?;
                    let mut label = self.get_register_label(src)?.clone();
                    if let Some(ctx) = self.active_execution_context_label() {
                        label = label.join(ctx);
                    }
                    #[cfg(debug_assertions)]
                    let walked_before = self.scope_closure_call_stack_memory_bytes();
                    let mut previous = None;
                    if let Some((_, binding)) = self.scope_chain.resolve(name.as_ref()) {
                        let previous_state = binding.snapshot_state()?;
                        if !previous_state.initialized {
                            return Err(InterpreterError::UninitializedBinding {
                                name: name.into_owned(),
                            });
                        }
                        if binding.kind.is_immutable() {
                            return Err(InterpreterError::ConstAssignment {
                                name: name.into_owned(),
                            });
                        }
                        let previous_payload =
                            Self::estimate_binding_cell_payload_bytes(&binding.state);
                        previous = Some((binding.clone(), previous_state, previous_payload));
                        {
                            let mut state = binding.state_mut()?;
                            state.value = val;
                            state.label = label;
                        }
                        self.closures.refresh_cell(&binding.state);
                    }
                    // Silently ignore stores to undeclared variables
                    // (strict mode would throw, but baseline is lenient).
                    if let Some((binding, old_state, previous_payload)) = previous {
                        #[cfg(debug_assertions)]
                        self.debug_assert_cell_write_delta(
                            walked_before,
                            previous_payload,
                            &binding.state,
                        );
                        if let Err(err) =
                            self.apply_scope_cell_write_delta(previous_payload, &binding.state)
                        {
                            binding.restore_state(old_state)?;
                            self.closures.refresh_cell(&binding.state);
                            return Err(err);
                        }
                        // bd-1lsy.4.10.1: a module binding that backs exports
                        // republishes them (namespace object and importers).
                        let live_export = binding.state()?.live_export;
                        if let Some(live_export) = live_export {
                            self.publish_live_export(&binding.state, live_export)?;
                        }
                    }
                    self.ip += 1;
                }
                Ir3Instruction::PutName {
                    src,
                    name_pool_index,
                    strict,
                } => {
                    let name = Self::scoped_constant_name(module, name_pool_index);
                    let val = self.read_reg(src)?;
                    let mut label = self.get_register_label(src)?.clone();
                    if let Some(ctx) = self.active_execution_context_label() {
                        label = label.join(ctx);
                    }
                    self.put_runtime_name_labeled(
                        Some(module),
                        name.as_ref(),
                        val,
                        &label,
                        strict,
                    )?;
                    self.ip += 1;
                }
                Ir3Instruction::PutNameWithStatus {
                    src,
                    status,
                    name_pool_index,
                    strict,
                } => {
                    let name = Self::scoped_constant_name(module, name_pool_index);
                    let val = self.read_reg(src)?;
                    let reference_token =
                        Self::runtime_name_reference_token(self.read_reg(status)?)?;
                    let mut label = self.get_register_label(src)?.clone();
                    if let Some(ctx) = self.active_execution_context_label() {
                        label = label.join(ctx);
                    }
                    self.put_runtime_name_with_status_labeled(
                        Some(module),
                        name.as_ref(),
                        val,
                        &label,
                        strict,
                        reference_token,
                    )?;
                    self.ip += 1;
                }
                Ir3Instruction::InitBinding {
                    name_pool_index,
                    src,
                } => {
                    let name = Self::scoped_constant_name(module, name_pool_index);
                    let val = self.read_reg(src)?;
                    let mut label = self.get_register_label(src)?.clone();
                    if let Some(ctx) = self.active_execution_context_label() {
                        label = label.join(ctx);
                    }
                    #[cfg(debug_assertions)]
                    let walked_before = self.scope_closure_call_stack_memory_bytes();
                    let mut previous = None;
                    if let Some((_, binding)) = self.scope_chain.resolve(name.as_ref()) {
                        let previous_payload =
                            Self::estimate_binding_cell_payload_bytes(&binding.state);
                        previous =
                            Some((binding.clone(), binding.snapshot_state()?, previous_payload));
                        {
                            let mut state = binding.state_mut()?;
                            state.value = val;
                            state.label = label;
                            state.initialized = true;
                        }
                        self.closures.refresh_cell(&binding.state);
                    }
                    if let Some((binding, old_state, previous_payload)) = &previous {
                        #[cfg(debug_assertions)]
                        self.debug_assert_cell_write_delta(
                            walked_before,
                            *previous_payload,
                            &binding.state,
                        );
                        if let Err(err) =
                            self.apply_scope_cell_write_delta(*previous_payload, &binding.state)
                        {
                            binding.restore_state(old_state.clone())?;
                            self.closures.refresh_cell(&binding.state);
                            return Err(err);
                        }
                    }
                    // bd-1lsy.4.10.1: a module binding that backs exports is
                    // initialized by its declaration (`export var v = 2` after
                    // the export was published undefined): republish it.
                    if let Some((binding, _, _)) = previous.as_ref() {
                        let live_export = binding.state()?.live_export;
                        if let Some(live_export) = live_export {
                            let cell = Rc::clone(&binding.state);
                            self.publish_live_export(&cell, live_export)?;
                        }
                    }
                    // bd-1lsy.4.10.1: an import binding initialized from its
                    // namespace read (the instruction just before) watches that
                    // export, so every later publication writes it: the import
                    // is a live view of the exporting module's binding. In a
                    // cycle the export may not be published yet; its
                    // publication initializes the binding then.
                    if let Some((binding, _, _)) = previous.as_ref()
                        && binding.kind == BindingKind::Import
                        && let Some(Ir3Instruction::GetProperty { obj, key, dst }) = self
                            .ip
                            .checked_sub(1)
                            .and_then(|read| module.instructions.get(read))
                        && *dst == src
                        && let Value::Object(namespace_object) = self.read_reg(*obj)?
                        && let Value::Str(export_name) = self.read_reg(*key)?
                    {
                        let cell = Rc::clone(&binding.state);
                        self.watch_module_export(namespace_object, export_name, &cell)?;
                    }
                    self.ip += 1;
                }
                Ir3Instruction::CreatePerIterationBinding {
                    name_pool_index,
                    kind,
                    preserve_state,
                } => {
                    let name = Self::scoped_constant_name(module, name_pool_index);
                    let binding_kind = BindingKind::from_u8(kind)?;
                    let previous_scope_bytes = self.scope_chain_memory_bytes();
                    let previous_closure_bytes = self.closures_memory_bytes();
                    let previous_call_stack_bytes = self.call_stack_memory_bytes();
                    let (frame_index, previous_binding) = self
                        .scope_chain
                        .resolve(name.as_ref())
                        .map(|(frame_index, binding)| (frame_index, binding.clone()))
                        .ok_or_else(|| InterpreterError::InternalError {
                            details: format!(
                                "per-iteration binding '{}' is not present in the scope chain",
                                name
                            ),
                        })?;
                    let next_binding = if preserve_state {
                        previous_binding.detached_clone()?
                    } else {
                        ScopeBinding::new(binding_kind)
                    };
                    self.scope_chain.frames[frame_index]
                        .insert_binding(name.to_string(), next_binding);
                    if let Err(err) = self.apply_scope_closure_call_stack_memory_delta(
                        previous_scope_bytes,
                        previous_closure_bytes,
                        previous_call_stack_bytes,
                    ) {
                        self.scope_chain.frames[frame_index]
                            .insert_binding(name.into_owned(), previous_binding);
                        return Err(err);
                    }
                    self.ip += 1;
                }
            }

            // Record profiling data for this instruction
            if let (Some(profiler), Some(profile_start)) = (&mut self.profiling_data, profile_start)
            {
                profiler.record_instruction(instr_ref);
                profiler.record_instruction_time(instr_ref, profile_start.elapsed());
            }
        }
    }
}
