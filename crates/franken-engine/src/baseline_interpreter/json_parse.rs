//! Native JSON.parse: coercion, transactional parsing, and reviver execution.
//!
//! The UTF-16 token parser lives in the parent module. No guest callback runs
//! while its unpublished heap suffix is transactional: input coercion happens
//! before the checkpoint, and revivers run only after the complete text parses.

use super::*;

impl InterpreterCore {
    pub(super) fn json_parse_builtin(
        &mut self,
        module: Option<&Ir3Module>,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let input = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
        let reviver = self.builtin_arg(args, 1)?.unwrap_or(Value::Undefined);
        let mut context = self.join_arg_range_label(args)?;
        for value in [&input, &reviver] {
            if let Some(label) = self.process_dynamic_value_label_ref(value, &mut BTreeSet::new()) {
                context = self.join_owned_label_with_temporary_budget(context, label)?;
            }
        }
        // Keep the caller's context accounted while it is moved out. Coercion
        // hooks and revivers inherit the input provenance, including zero-arg
        // effects performed from a callback. Restore it on every exit path.
        let context_bytes = Self::estimate_label_bytes(&context);
        let previous_context_bytes = self
            .active_inline_callback_context_label
            .as_ref()
            .map(Self::estimate_label_bytes)
            .unwrap_or(0);
        self.json_reserve_temporary(previous_context_bytes)?;
        if let Err(error) = self.apply_memory_component_delta(previous_context_bytes, context_bytes)
        {
            self.json_release_temporary(previous_context_bytes);
            return Err(error);
        }
        let previous_context = self.active_inline_callback_context_label.replace(context);
        let mut outcome = self.json_parse_builtin_inner(module, input, reviver);
        let context = self
            .active_inline_callback_context_label
            .take()
            .expect("JSON callback context must be restored by nested calls");
        if outcome.is_ok() {
            let joined = self.clone_dominant_label_with_temporary_budget(
                &context,
                self.pending_hostcall_result_label
                    .as_ref()
                    .unwrap_or(&Label::Public),
                0,
            );
            if let Err(error) =
                joined.and_then(|label| self.replace_pending_hostcall_result_label(Some(label)))
            {
                outcome = Err(error);
            }
        } else if matches!(outcome, Err(InterpreterError::UncaughtException { .. }))
            && let Err(error) = self.join_pending_exception_label(&context)
        {
            outcome = Err(error);
        }
        self.active_inline_callback_context_label = previous_context;
        let context_bytes = Self::estimate_label_bytes(&context);
        drop(context);
        self.estimated_memory_bytes = self
            .estimated_memory_bytes
            .saturating_sub(context_bytes)
            .saturating_add(previous_context_bytes);
        self.json_release_temporary(previous_context_bytes);
        outcome
    }

    fn json_parse_builtin_inner(
        &mut self,
        module: Option<&Ir3Module>,
        input: Value,
        reviver: Value,
    ) -> Result<Value, InterpreterError> {
        // ToString, not String(): a Symbol must throw even though String(symbol)
        // can produce a descriptive string. Observable object hooks run once.
        self.json_charge_work()?;
        let primitive = self.coerce_runtime_primitive(module, input, true)?;
        let coercion_label = self.json_parse_context_label()?;
        self.json_observe_label(coercion_label)?;
        let text = match primitive {
            Value::Str(text) => text,
            Value::Symbol(_) => {
                return Err(InterpreterError::TypeError {
                    expected: "JSON text convertible to a String".to_string(),
                    got: "Symbol".to_string(),
                });
            }
            Value::Float(number) if number.inner().is_finite() => {
                JsString::from(ryu_js::Buffer::new().format(number.inner()))
            }
            other => JsString::from(self.value_to_string(&other)),
        };
        self.check_string_limit(text.len())?;
        let unit_count = text.utf16_len();
        let unit_bytes = u64::try_from(unit_count)
            .unwrap_or(u64::MAX)
            .saturating_mul(2);
        self.json_reserve_temporary(unit_bytes)?;
        let units = text.code_units_vec();
        let outcome = self.json_parse_document(&units);
        drop(units);
        self.json_release_temporary(unit_bytes);
        let value = outcome?;
        if !reviver.is_callable() {
            return Ok(value);
        }
        let prototype = self.ensure_builtin_prototype("Object")?;
        let holder = self.alloc_object_with_prototype(Some(prototype))?;
        self.json_store_parsed_property(holder, JsString::from(""), value)?;
        // Parsing is committed before user code begins. A reviver can retain a
        // reference to the holder or any descendant and then throw; none of its
        // effects or escaped objects may be rolled back as syntax scratch.
        self.json_internalize_property(module, holder, JsString::from(""), &reviver, 0)
    }

    fn json_parse_document(&mut self, units: &[u16]) -> Result<Value, InterpreterError> {
        let mut pos = 0;
        Self::json_skip_ws(units, &mut pos);
        if matches!(units.get(pos), Some(0x7B | 0x5B)) {
            // Intrinsics outlive the parse transaction. Initializing them inside
            // it and then rolling back would leave dangling cached object ids.
            self.ensure_builtin_prototype("Object")?;
            self.ensure_builtin_prototype("Array")?;
        }
        let heap_checkpoint = self.heap.len();
        let memory_checkpoint = self.estimated_memory_bytes;
        let parsed = self.json_parse_value(units, &mut pos, 0);
        match parsed {
            Ok(Some(value)) => {
                Self::json_skip_ws(units, &mut pos);
                if pos == units.len() {
                    // Empty-container shape is provenance too. Publish labels
                    // only after parsing commits, so a syntax rollback cannot
                    // leave an ObjectId-keyed sidecar pointing into discarded
                    // heap storage. No guest callbacks have run in this suffix.
                    let label = self.json_parse_context_label()?;
                    if label != Label::Public {
                        let label_bytes = Self::estimate_label_bytes(&label);
                        self.json_reserve_temporary(label_bytes)?;
                        let outcome = (|| {
                            for index in heap_checkpoint..self.heap.len() {
                                let id = ObjectId(u32::try_from(index).map_err(|_| {
                                    InterpreterError::RangeError {
                                        message: "JSON object id exceeds heap index range"
                                            .to_string(),
                                    }
                                })?);
                                self.join_direct_object_mutation_label(id, &label)?;
                            }
                            Ok::<(), InterpreterError>(())
                        })();
                        drop(label);
                        self.json_release_temporary(label_bytes);
                        outcome?;
                    }
                    return Ok(value);
                }
            }
            Ok(None) => {}
            Err(error) => {
                self.rollback_json_parse(heap_checkpoint, memory_checkpoint);
                return Err(error);
            }
        }
        self.rollback_json_parse(heap_checkpoint, memory_checkpoint);
        self.json_syntax_error(pos)
    }

    fn json_syntax_error(&mut self, position: usize) -> Result<Value, InterpreterError> {
        let prototype = self.ensure_builtin_prototype("SyntaxError")?;
        let object = self.alloc_object_with_prototype(Some(prototype))?;
        self.initialize_error_like_object(
            object,
            "SyntaxError",
            format!("Invalid JSON at UTF-16 position {position}"),
        )?;
        let label = self.json_parse_context_label()?;
        let thrown = Value::Object(object);
        self.replace_pending_abrupt_slots(Some((thrown.clone(), label)), None)?;
        Err(InterpreterError::UncaughtException {
            value: self.uncaught_exception_description(&thrown),
        })
    }

    pub(super) fn json_parse_context_label(&self) -> Result<Label, InterpreterError> {
        self.clone_dominant_label_with_temporary_budget(
            self.active_execution_context_label()
                .unwrap_or(&Label::Public),
            self.pending_hostcall_result_label
                .as_ref()
                .unwrap_or(&Label::Public),
            0,
        )
    }

    pub(super) fn json_store_parsed_property(
        &mut self,
        holder: ObjectId,
        key: JsString,
        value: Value,
    ) -> Result<(), InterpreterError> {
        let key = RuntimePropertyKey::String(key);
        self.set_object_runtime_property(holder, key.clone(), value)?;
        let label = self.json_parse_context_label()?;
        let label_bytes = Self::estimate_label_bytes(&label);
        self.json_reserve_temporary(label_bytes)?;
        let outcome = self.set_own_runtime_property_label(holder, &key, &label);
        drop(label);
        self.json_release_temporary(label_bytes);
        outcome
    }

    pub(super) fn json_reserve_temporary(&mut self, bytes: u64) -> Result<(), InterpreterError> {
        self.check_temporary_memory_budget(bytes)?;
        self.json_parse_temporary_bytes = self
            .json_parse_temporary_bytes
            .checked_add(bytes)
            .ok_or_else(|| self.memory_budget_error(u64::MAX, self.heap_object_count_u32()))?;
        Ok(())
    }

    pub(super) fn json_release_temporary(&mut self, bytes: u64) {
        debug_assert!(self.json_parse_temporary_bytes >= bytes);
        self.json_parse_temporary_bytes = self.json_parse_temporary_bytes.saturating_sub(bytes);
    }

    pub(super) fn json_charge_work(&mut self) -> Result<(), InterpreterError> {
        if self
            .config
            .cancellation_token
            .as_ref()
            .is_some_and(CancellationToken::is_cancelled)
        {
            return Err(InterpreterError::Cancelled);
        }
        self.charge_property_copy_work()
    }

    /// Preserve observations across reentrant calls, whose own builtin
    /// dispatches may clear the pending-result slot. The operation context is
    /// a monotone provenance floor, not a replacement for per-property labels.
    pub(super) fn json_observe_label(&mut self, label: Label) -> Result<(), InterpreterError> {
        let current = self.active_inline_callback_context_label.as_ref();
        if current.is_some_and(|current| current >= &label) {
            return Ok(());
        }
        let previous_bytes = current.map(Self::estimate_label_bytes).unwrap_or(0);
        self.apply_memory_component_delta(previous_bytes, Self::estimate_label_bytes(&label))?;
        self.active_inline_callback_context_label = Some(label);
        Ok(())
    }

    fn json_internalize_property(
        &mut self,
        module: Option<&Ir3Module>,
        holder: ObjectId,
        name: JsString,
        reviver: &Value,
        depth: usize,
    ) -> Result<Value, InterpreterError> {
        // Guest mutations can introduce cycles after lexical parsing. Use an
        // explicit work stack: a Rust-recursive walk can overflow the native
        // test/worker stack before reaching the interpreter's depth guard.
        enum Children {
            None,
            Array {
                object: ObjectId,
                length: u64,
                next: u64,
            },
            Object {
                object: ObjectId,
                keys: Vec<JsString>,
                next: usize,
            },
        }
        struct Frame {
            holder: ObjectId,
            name: JsString,
            value: Value,
            children: Children,
            charged: u64,
        }
        let mut frames = Vec::<Frame>::new();
        let mut next = Some((holder, name));
        let mut retained = 0_u64;
        let outcome = (|| {
            loop {
                if let Some((holder, name)) = next.take() {
                    let current_depth = depth.saturating_add(frames.len());
                    if current_depth > 200 {
                        return Err(InterpreterError::StackOverflow {
                            depth: current_depth,
                            max: 200,
                        });
                    }
                    self.json_charge_work()?;
                    let key = RuntimePropertyKey::String(name.clone());
                    if let Some(module) = module {
                        self.run_pre_runtime_property_access_hook(module, holder, &key)?;
                    }
                    let label = self.runtime_property_label(holder, &key);
                    self.json_observe_label(label)?;
                    let value = self.proxy_aware_get_runtime_property(
                        module,
                        holder,
                        &key,
                        Value::Object(holder),
                        0,
                    )?;
                    let label = self.json_parse_context_label()?;
                    self.json_observe_label(label)?;
                    if let Some(label) =
                        self.process_dynamic_value_label_ref(&value, &mut BTreeSet::new())
                    {
                        self.check_temporary_memory_budget(Self::estimate_label_bytes(label))?;
                        let label = label.clone();
                        self.json_observe_label(label)?;
                    }
                    let charged = (std::mem::size_of::<Frame>() as u64)
                        .saturating_add(Self::estimate_js_string_bytes(&name))
                        .saturating_add(Self::estimate_value_bytes(&value));
                    self.json_reserve_temporary(charged)?;
                    retained += charged;
                    frames.try_reserve(1).map_err(|_| {
                        self.memory_budget_error(u64::MAX, self.heap_object_count_u32())
                    })?;
                    frames.push(Frame {
                        holder,
                        name,
                        value,
                        children: Children::None,
                        charged,
                    });
                    let frame = frames.last_mut().expect("pushed reviver frame");
                    if frame.value.is_object_like()
                        && let Some(object) =
                            self.iterator_carrier_backing_id(&frame.value, "JSON reviver object")?
                    {
                        let target = self
                            .proxy_set_receiver_object(&Value::Object(object))?
                            .unwrap_or(object);
                        if self.heap[target.0 as usize].is_array {
                            let length = self.json_reviver_array_length(
                                module,
                                object,
                                frame.value.clone(),
                            )?;
                            frame.children = Children::Array {
                                object,
                                length,
                                next: 0,
                            };
                        } else {
                            self.check_temporary_memory_budget(
                                Self::estimate_ordered_property_map_bytes_nonalloc(
                                    &self.heap[target.0 as usize].properties,
                                ),
                            )?;
                            let keys = self.proxy_own_enumerable_string_keys(module, object)?;
                            let observed = self.json_parse_context_label()?;
                            self.json_observe_label(observed)?;
                            let bytes = keys.iter().fold(0_u64, |bytes, key| {
                                bytes
                                    .saturating_add(Self::estimate_js_string_bytes(key))
                                    .saturating_add(std::mem::size_of::<JsString>() as u64)
                            });
                            self.json_reserve_temporary(bytes)?;
                            retained += bytes;
                            frame.charged += bytes;
                            frame.children = Children::Object {
                                object,
                                keys,
                                next: 0,
                            };
                        }
                    }
                }
                let frame = frames.last_mut().expect("active reviver frame");
                match &mut frame.children {
                    Children::Array {
                        object,
                        length,
                        next: index,
                    } if *index < *length => {
                        next = Some((*object, JsString::from(index.to_string())));
                        *index += 1;
                        continue;
                    }
                    Children::Object {
                        object,
                        keys,
                        next: index,
                    } if *index < keys.len() => {
                        next = Some((*object, keys[*index].clone()));
                        *index += 1;
                        continue;
                    }
                    _ => {}
                }
                let frame = frames.pop().expect("completed reviver frame");
                // Keep the popped frame charged until its callback returns,
                // even when it recursively parses or retains the original value.
                let context = self.json_parse_context_label()?;
                let (result, label) = self.invoke_inline_method_call_with_argument_label(
                    module,
                    reviver.clone(),
                    Value::Object(frame.holder),
                    vec![Value::Str(frame.name.clone()), frame.value],
                    Some(context),
                )?;
                self.json_observe_label(label)?;
                if frames.is_empty() {
                    return Ok(result);
                }
                self.json_apply_revived_property(module, frame.holder, frame.name, result, 0)?;
                self.json_release_temporary(frame.charged);
                retained -= frame.charged;
            }
        })();
        drop(frames);
        self.json_release_temporary(retained);
        outcome
    }

    pub(super) fn json_reviver_array_length(
        &mut self,
        module: Option<&Ir3Module>,
        object: ObjectId,
        receiver: Value,
    ) -> Result<u64, InterpreterError> {
        let key = RuntimePropertyKey::String(JsString::from("length"));
        let label = self.runtime_property_label(object, &key);
        self.json_observe_label(label)?;
        let value = self.proxy_aware_get_runtime_property(module, object, &key, receiver, 0)?;
        let observed = self.json_parse_context_label()?;
        self.json_observe_label(observed)?;
        let value = self.coerce_runtime_primitive(module, value, false)?;
        let observed = self.json_parse_context_label()?;
        self.json_observe_label(observed)?;
        let number = match value {
            Value::Int(number) => number as f64,
            Value::Float(number) => number.inner(),
            Value::Str(text) => Self::array_like_length_string_number(&text),
            Value::Undefined => f64::NAN,
            Value::Null | Value::Bool(false) => 0.0,
            Value::Bool(true) => 1.0,
            other => {
                return Err(InterpreterError::TypeError {
                    expected: "Number-convertible array length".to_string(),
                    got: other.type_name().to_string(),
                });
            }
        };
        Ok(if number.is_nan() || number <= 0.0 {
            0
        } else {
            number.min(9_007_199_254_740_991.0).trunc() as u64
        })
    }

    fn json_apply_revived_property(
        &mut self,
        module: Option<&Ir3Module>,
        object: ObjectId,
        name: JsString,
        value: Value,
        depth: u32,
    ) -> Result<(), InterpreterError> {
        if depth >= MAX_PROTOTYPE_CHAIN_DEPTH {
            return Err(InterpreterError::StackOverflow {
                depth: depth as usize,
                max: MAX_PROTOTYPE_CHAIN_DEPTH as usize,
            });
        }
        let key = RuntimePropertyKey::String(name.clone());
        if matches!(value, Value::Undefined) {
            // InternalizeJSONProperty ignores a false [[Delete]] result.
            self.proxy_aware_delete_runtime_property(module, object, &key, 0)?;
            let observed = self.json_parse_context_label()?;
            self.json_observe_label(observed)?;
            return Ok(());
        }
        if let Some((target, handler)) = self.active_proxy_record(object)? {
            // CreateDataProperty is [[DefineOwnProperty]], not [[Set]]. Never
            // invoke an inherited setter when replacing a revived value.
            let trap = self.proxy_trap_value(module, handler, "defineProperty")?;
            let observed = self.json_parse_context_label()?;
            self.json_observe_label(observed)?;
            if let Some(trap) = trap {
                let descriptor = self.alloc_object_with_properties(&[
                    ("value", value),
                    ("writable", Value::Bool(true)),
                    ("enumerable", Value::Bool(true)),
                    ("configurable", Value::Bool(true)),
                ])?;
                let context = self.json_parse_context_label()?;
                let (_, label) = self.invoke_inline_method_call_with_argument_label(
                    module,
                    trap,
                    Value::Object(handler),
                    vec![
                        Value::Object(target),
                        key.value(),
                        Value::Object(descriptor),
                    ],
                    Some(context),
                )?;
                self.json_observe_label(label)?;
                return Ok(());
            }
            return self.json_apply_revived_property(module, target, name, value, depth + 1);
        }
        if self.heap[object.0 as usize].is_frozen {
            // Likewise, a refused CreateDataProperty must not become a throw.
            return Ok(());
        }
        let index = name.as_str().and_then(Self::canonical_array_index_key);
        self.json_store_parsed_property(object, name, value)?;
        if let Some(index) = index {
            self.maintain_array_index_assignment(object, index)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn core() -> InterpreterCore {
        let mut config = InterpreterConfig::quickjs_defaults();
        config.granted_capabilities = [
            RuntimeCapability::VmDispatch,
            RuntimeCapability::HeapAllocate,
            RuntimeCapability::Builtin,
        ]
        .into_iter()
        .collect();
        InterpreterCore::new(config, "json-parse-test")
    }

    fn parse(core: &mut InterpreterCore, input: Value) -> Result<Value, InterpreterError> {
        core.set_register(0, input)?;
        core.dispatch_builtin_hostcall("builtin:JsonParse", RegRange { start: 0, count: 1 }, None)
    }

    #[test]
    fn primitive_inputs_follow_to_string() {
        for (input, expected) in [
            (Value::Bool(true), Value::Bool(true)),
            (Value::Null, Value::Null),
            (Value::Int(123), Value::Int(123)),
            (Value::Float(Float64::new(-0.0)), Value::Int(0)),
        ] {
            let mut core = core();
            assert_eq!(parse(&mut core, input).unwrap(), expected);
            assert_eq!(
                core.estimated_memory_bytes(),
                core.recompute_estimated_memory_bytes()
            );
        }
    }

    #[test]
    fn numbers_outside_safe_integer_range_round_as_binary64() {
        let mut core = core();
        for (text, expected) in [
            ("9007199254740993", 9007199254740992.0),
            ("-9007199254740993", -9007199254740992.0),
            ("9223372036854775807", 9223372036854775808.0),
            ("1e400", f64::INFINITY),
            ("-1e400", f64::NEG_INFINITY),
        ] {
            let Value::Float(actual) = parse(&mut core, Value::str(text)).unwrap() else {
                panic!("{text} must use the binary64 carrier");
            };
            assert_eq!(actual.inner().to_bits(), expected.to_bits());
        }
        let Value::Float(zero) = parse(&mut core, Value::str("-0")).unwrap() else {
            panic!("JSON -0 must retain its sign");
        };
        assert_eq!(zero.inner().to_bits(), (-0.0f64).to_bits());
    }

    #[test]
    fn malformed_utf16_keys_stay_distinct_and_duplicates_replace_in_place() {
        let mut core = core();
        let Value::Object(id) = parse(
            &mut core,
            Value::str(r#"{"\ud800":1,"\ud801":2,"\ufffd":3,"\ud800":4}"#),
        )
        .unwrap() else {
            panic!("object expected");
        };
        let object = &core.heap[id.0 as usize];
        assert_eq!(object.properties.exact_keys().len(), 3);
        for (unit, expected) in [(0xD800, 4), (0xD801, 2), (0xFFFD, 3)] {
            assert_eq!(
                object
                    .properties
                    .get_exact(&JsString::from_code_units(&[unit])),
                Some(&Value::Int(expected))
            );
        }
        assert_eq!(object.properties.exact_keys()[0].code_units_vec(), [0xD800]);
    }

    #[test]
    fn parsed_containers_have_intrinsic_prototypes_and_proto_is_data() {
        let mut core = core();
        let Value::Object(id) =
            parse(&mut core, Value::str(r#"{"__proto__":{"x":1},"a":[]}"#)).unwrap()
        else {
            panic!("object expected");
        };
        let object_proto = core.ensure_builtin_prototype("Object").unwrap();
        let array_proto = core.ensure_builtin_prototype("Array").unwrap();
        assert_eq!(core.heap[id.0 as usize].prototype, Some(object_proto));
        assert!(
            core.heap[id.0 as usize]
                .properties
                .contains_key("__proto__")
        );
        let Some(Value::Object(array)) = core.heap[id.0 as usize].properties.get("a") else {
            panic!("array expected");
        };
        assert_eq!(core.heap[array.0 as usize].prototype, Some(array_proto));
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }

    #[test]
    fn invalid_json_throws_real_syntax_error_and_releases_scratch() {
        let mut core = core();
        for text in [
            "",
            "undefined",
            "01",
            "1.",
            "[1,]",
            "{\"a\":1,}",
            "true false",
            "\"\u{1f}\"",
        ] {
            assert!(matches!(
                parse(&mut core, Value::str(text)),
                Err(InterpreterError::UncaughtException { .. })
            ));
            let Some(Value::Object(id)) = core.pending_exception.as_ref() else {
                panic!("exception expected");
            };
            assert_eq!(
                core.heap[id.0 as usize].properties.get("name"),
                Some(&Value::str("SyntaxError"))
            );
            assert!(core.active_inline_callback_context_label.is_none());
            assert_eq!(
                core.estimated_memory_bytes(),
                core.recompute_estimated_memory_bytes()
            );
            core.replace_pending_abrupt_slots(None, None).unwrap();
        }
    }

    #[test]
    fn depth_and_instruction_exhaustion_are_not_syntax_errors() {
        let mut core = core();
        let nested = format!("{}0{}", "[".repeat(202), "]".repeat(202));
        assert!(matches!(
            parse(&mut core, Value::str(nested)),
            Err(InterpreterError::StackOverflow { .. })
        ));
        assert!(core.pending_exception.is_none());
        assert!(core.active_inline_callback_context_label.is_none());
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
        core.config.instruction_budget = core.instructions_executed;
        assert!(matches!(
            parse(&mut core, Value::str("[1]")),
            Err(InterpreterError::BudgetExhausted { .. })
        ));
        assert!(core.pending_exception.is_none());
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }

    #[test]
    fn exact_input_provenance_covers_empty_containers_and_restores_caller_context() {
        let mut core = core();
        let caller = Label::Custom {
            name: "outer-context".repeat(8),
            level: 7,
        };
        let input_label = Label::Custom {
            name: "json-input".repeat(16),
            level: 8,
        };
        core.active_inline_callback_context_label = Some(caller.clone());
        core.sync_estimated_memory_bytes().unwrap();
        core.set_register(0, Value::str(r#"{"empty":{},"items":[]}"#))
            .unwrap();
        core.set_register_label(0, input_label.clone()).unwrap();
        let Value::Object(root) = core
            .dispatch_builtin_hostcall("builtin:JsonParse", RegRange { start: 0, count: 1 }, None)
            .unwrap()
        else {
            panic!("object expected");
        };
        for name in ["empty", "items"] {
            assert_eq!(core.own_property_label(root, name), input_label);
            let Some(Value::Object(child)) = core.heap[root.0 as usize].properties.get(name) else {
                panic!("nested container expected");
            };
            assert_eq!(core.object_mutation_labels.get(child), Some(&input_label));
            if name == "items" {
                assert_eq!(core.own_property_label(*child, "length"), input_label);
            }
        }
        assert_eq!(core.object_mutation_labels.get(&root), Some(&input_label));
        assert_eq!(core.pending_hostcall_result_label, Some(input_label));
        assert_eq!(core.active_inline_callback_context_label, Some(caller));
        assert_eq!(core.json_parse_temporary_bytes, 0);
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }

    #[test]
    fn syntax_error_carries_input_provenance_without_dangling_parse_metadata() {
        let mut core = core();
        core.set_register(0, Value::str(r#"{"empty":{},"items":[1]} invalid"#))
            .unwrap();
        core.set_register_label(0, Label::Secret).unwrap();
        assert!(matches!(
            core.dispatch_builtin_hostcall(
                "builtin:JsonParse",
                RegRange { start: 0, count: 1 },
                None,
            ),
            Err(InterpreterError::UncaughtException { .. })
        ));
        assert_eq!(core.pending_exception_label, Label::Secret);
        assert!(
            core.object_mutation_labels
                .keys()
                .all(|id| (id.0 as usize) < core.heap.len())
        );
        assert_eq!(core.json_parse_temporary_bytes, 0);
        assert!(core.active_inline_callback_context_label.is_none());
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }

    #[test]
    fn callback_scratch_remains_charged_across_accounting_resynchronization() {
        let mut core = core();
        let baseline = core.estimated_memory_bytes();
        core.config.max_total_memory_bytes = baseline + 2048;
        core.json_reserve_temporary(2048).unwrap();
        assert_eq!(core.sync_estimated_memory_bytes().unwrap(), baseline + 2048);
        assert!(matches!(
            core.json_reserve_temporary(1),
            Err(InterpreterError::MemoryBudgetExceeded { .. })
        ));
        assert_eq!(core.json_parse_temporary_bytes, 2048);
        core.json_release_temporary(2048);
        assert!(matches!(
            core.json_reserve_temporary(u64::MAX),
            Err(InterpreterError::MemoryBudgetExceeded { .. })
        ));
        assert_eq!(core.json_parse_temporary_bytes, 0);
        assert_eq!(core.estimated_memory_bytes(), baseline);
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }

    #[test]
    fn cancelled_json_dispatch_is_a_host_fault_not_a_catchable_syntax_error() {
        let mut core = core();
        let token = CancellationToken::new();
        token.cancel();
        core.config.cancellation_token = Some(token);
        let heap_before = core.heap_size();
        assert_eq!(
            parse(&mut core, Value::str("[1,2]")),
            Err(InterpreterError::Cancelled)
        );
        assert_eq!(core.heap_size(), heap_before);
        assert!(core.pending_exception.is_none());
        assert_eq!(core.json_parse_temporary_bytes, 0);
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }

    #[test]
    fn configured_string_limit_applies_after_primitive_to_string_coercion() {
        let mut core = core();
        core.set_register(0, Value::Int(1234)).unwrap();
        core.config.max_string_size = 3;
        assert!(matches!(
            core.dispatch_builtin_hostcall(
                "builtin:JsonParse",
                RegRange { start: 0, count: 1 },
                None,
            ),
            Err(InterpreterError::StringLimitExceeded { length: 4, max: 3 })
        ));
        assert!(core.pending_exception.is_none());
        assert_eq!(core.json_parse_temporary_bytes, 0);
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }
}
