//! Observable, bounded JSON serialization on the native interpreter.
//!
//! The traversal is an explicit work stack. Property selection is snapshotted,
//! but Get, toJSON and replacer calls stay live and ordered. Only ancestors
//! participate in cycle detection, and no guest mutation is rolled back on an
//! exception. Scratch remains charged across reentrant guest calls.

use super::*;

const MAX_STRINGIFY_DEPTH: usize = 200;

#[derive(Default)]
struct StringifyState {
    output: Vec<u16>,
    projection_bytes: usize,
    gap: Vec<u16>,
    property_list: Option<Vec<JsString>>,
    frames: Vec<StringifyFrame>,
    ancestors: BTreeSet<ObjectId>,
    charged: u64,
}

struct StringifyFrame {
    receiver: Value,
    object: ObjectId,
    children: StringifyChildren,
    next: u64,
    emitted: bool,
    charged: u64,
}

enum StringifyChildren {
    Array(u64),
    Object(Vec<JsString>),
    PropertyList,
}

impl StringifyState {
    fn reserve(&mut self, core: &mut InterpreterCore, bytes: u64) -> Result<(), InterpreterError> {
        core.json_reserve_temporary(bytes)?;
        self.charged += bytes;
        Ok(())
    }

    fn release(&mut self, core: &mut InterpreterCore, bytes: u64) {
        core.json_release_temporary(bytes);
        self.charged -= bytes;
    }

    fn push(&mut self, core: &mut InterpreterCore, unit: u16) -> Result<(), InterpreterError> {
        if self.output.len().is_multiple_of(256) {
            core.json_charge_work()?;
        }
        // The projection uses U+FFFD for a lone surrogate, but adjacent halves
        // heal to one four-byte scalar. Indentation may itself be ill-formed.
        let added = match unit {
            0..=0x7f => 1,
            0x80..=0x7ff => 2,
            0xdc00..=0xdfff
                if self
                    .output
                    .last()
                    .is_some_and(|u| (0xd800..=0xdbff).contains(u)) =>
            {
                1
            }
            _ => 3,
        };
        let bytes = self
            .projection_bytes
            .checked_add(added)
            .ok_or_else(|| core.memory_budget_error(u64::MAX, core.heap_object_count_u32()))?;
        core.check_string_limit(bytes)?;
        if self.output.len() == self.output.capacity() {
            let capacity = self.output.capacity();
            let desired = capacity
                .saturating_mul(2)
                .max(64)
                .min(core.config.max_string_size);
            let additional = desired.saturating_sub(capacity).max(1);
            self.reserve(core, (additional as u64).saturating_mul(2))?;
            self.output
                .try_reserve_exact(additional)
                .map_err(|_| core.memory_budget_error(u64::MAX, core.heap_object_count_u32()))?;
        }
        self.output.push(unit);
        self.projection_bytes = bytes;
        Ok(())
    }

    fn text(&mut self, core: &mut InterpreterCore, text: &str) -> Result<(), InterpreterError> {
        for unit in text.encode_utf16() {
            self.push(core, unit)?;
        }
        Ok(())
    }

    fn quote(
        &mut self,
        core: &mut InterpreterCore,
        text: &JsString,
    ) -> Result<(), InterpreterError> {
        self.push(core, u16::from(b'"'))?;
        for decoded in char::decode_utf16(text.encode_utf16()) {
            match decoded {
                Ok('"') => self.text(core, "\\\"")?,
                Ok('\\') => self.text(core, "\\\\")?,
                Ok('\u{0008}') => self.text(core, "\\b")?,
                Ok('\u{000c}') => self.text(core, "\\f")?,
                Ok('\n') => self.text(core, "\\n")?,
                Ok('\r') => self.text(core, "\\r")?,
                Ok('\t') => self.text(core, "\\t")?,
                Ok(c) if c <= '\u{001f}' => self.text(core, &format!("\\u{:04x}", c as u32))?,
                Ok(c) => {
                    for unit in c.encode_utf16(&mut [0_u16; 2]) {
                        self.push(core, *unit)?;
                    }
                }
                Err(error) => self.text(core, &format!("\\u{:04x}", error.unpaired_surrogate()))?,
            }
        }
        self.push(core, u16::from(b'"'))
    }

    fn indent(&mut self, core: &mut InterpreterCore, depth: usize) -> Result<(), InterpreterError> {
        if !self.gap.is_empty() {
            self.push(core, u16::from(b'\n'))?;
            for _ in 0..depth {
                for index in 0..self.gap.len() {
                    self.push(core, self.gap[index])?;
                }
            }
        }
        Ok(())
    }

    fn prefix(
        &mut self,
        core: &mut InterpreterCore,
        key: &JsString,
    ) -> Result<(), InterpreterError> {
        let Some(frame) = self.frames.last_mut() else {
            return Ok(());
        };
        let comma = frame.emitted;
        let array = matches!(frame.children, StringifyChildren::Array(_));
        frame.emitted = true;
        if comma {
            self.push(core, u16::from(b','))?;
        }
        self.indent(core, self.frames.len())?;
        if !array {
            self.quote(core, key)?;
            self.push(core, u16::from(b':'))?;
            if !self.gap.is_empty() {
                self.push(core, u16::from(b' '))?;
            }
        }
        Ok(())
    }

    fn push_frame(
        &mut self,
        core: &mut InterpreterCore,
        frame: StringifyFrame,
    ) -> Result<(), InterpreterError> {
        if self.frames.len() == self.frames.capacity() {
            let additional = self.frames.capacity().max(8);
            self.reserve(
                core,
                (additional * std::mem::size_of::<StringifyFrame>()) as u64,
            )?;
            self.frames
                .try_reserve_exact(additional)
                .map_err(|_| core.memory_budget_error(u64::MAX, core.heap_object_count_u32()))?;
        }
        self.frames.push(frame);
        Ok(())
    }
}

impl InterpreterCore {
    pub(super) fn json_stringify_builtin(
        &mut self,
        module: Option<&Ir3Module>,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let input = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
        let replacer = self.builtin_arg(args, 1)?.unwrap_or(Value::Undefined);
        let space = self.builtin_arg(args, 2)?.unwrap_or(Value::Undefined);
        let context = self.join_arg_range_label(args)?;
        let context_bytes = Self::estimate_label_bytes(&context);
        let previous_bytes = self
            .active_inline_callback_context_label
            .as_ref()
            .map(Self::estimate_label_bytes)
            .unwrap_or(0);
        self.json_reserve_temporary(previous_bytes)?;
        if let Err(error) = self.apply_memory_component_delta(previous_bytes, context_bytes) {
            self.json_release_temporary(previous_bytes);
            return Err(error);
        }
        let previous = self.active_inline_callback_context_label.replace(context);
        let mut outcome = (|| {
            for value in [&input, &replacer, &space] {
                self.json_observe_reachable_value(value)?;
            }
            self.json_stringify_document(module, input, replacer, space)
        })();
        // BigInt, cycles and invalid Proxy results produce native TypeErrors.
        // Materialize them while the monotone observation context is still
        // live: a later public callback may have replaced the pending-result
        // label, but must not declassify the exception seen by catch.
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
            .expect("nested JSON calls restore the operation context");
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
        self.active_inline_callback_context_label = previous;
        self.estimated_memory_bytes = self
            .estimated_memory_bytes
            .saturating_sub(Self::estimate_label_bytes(&context))
            .saturating_add(previous_bytes);
        self.json_release_temporary(previous_bytes);
        outcome
    }

    /// Shared Get path: preserve both the receiver and every observation made
    /// before a callback can reenter JSON or clear the pending-result slot.
    fn json_stringify_get(
        &mut self,
        module: Option<&Ir3Module>,
        object: ObjectId,
        receiver: Value,
        key: &JsString,
    ) -> Result<Value, InterpreterError> {
        self.json_charge_work()?;
        let property = RuntimePropertyKey::String(key.clone());
        let label = self.runtime_property_label(object, &property);
        self.json_observe_label(label)?;
        let value = self.iterator_protocol_property(module, object, &property, receiver)?;
        let label = self.json_parse_context_label()?;
        self.json_observe_label(label)?;
        self.json_observe_reachable_value(&value)?;
        Ok(value)
    }

    fn json_stringify_array_id(&self, value: &Value) -> Result<Option<ObjectId>, InterpreterError> {
        let Some(object) = self.proxy_set_receiver_object(value)? else {
            return Ok(None);
        };
        Ok(self
            .heap
            .get(object.0 as usize)
            .filter(|o| o.is_array)
            .map(|_| object))
    }

    fn json_stringify_property(
        &mut self,
        module: Option<&Ir3Module>,
        object: ObjectId,
        holder: Value,
        key: &JsString,
        replacer: &Value,
    ) -> Result<Value, InterpreterError> {
        let mut value = self.json_stringify_get(module, object, holder.clone(), key)?;
        let backing = if matches!(value, Value::BigInt(_)) {
            Some(self.ensure_builtin_prototype("BigInt")?)
        } else if value.is_object_like() {
            self.iterator_carrier_backing_id(&value, "JSON object")?
        } else {
            None
        };
        if let Some(backing) = backing {
            let method =
                self.json_stringify_get(module, backing, value.clone(), &JsString::from("toJSON"))?;
            if method.is_callable() {
                let context = self.json_parse_context_label()?;
                let (result, label) = self.invoke_inline_method_call_with_argument_label(
                    module,
                    method,
                    value,
                    vec![Value::Str(key.clone())],
                    Some(context),
                )?;
                self.json_observe_label(label)?;
                self.json_observe_reachable_value(&result)?;
                value = result;
            }
        }
        if replacer.is_callable() {
            let context = self.json_parse_context_label()?;
            let (result, label) = self.invoke_inline_method_call_with_argument_label(
                module,
                replacer.clone(),
                holder,
                vec![Value::Str(key.clone()), value],
                Some(context),
            )?;
            self.json_observe_label(label)?;
            self.json_observe_reachable_value(&result)?;
            value = result;
        }
        Ok(value)
    }

    fn json_stringify_options(
        &mut self,
        module: Option<&Ir3Module>,
        replacer: &Value,
        space: Value,
        state: &mut StringifyState,
    ) -> Result<(), InterpreterError> {
        // Only real arrays participate. A Proxy's target determines IsArray,
        // but indexed reads and length still go through that Proxy's traps.
        if !replacer.is_callable() && self.json_stringify_array_id(replacer)?.is_some() {
            let Value::Object(object) = replacer else {
                unreachable!("array has object storage")
            };
            let length = self.json_reviver_array_length(module, *object, replacer.clone())?;
            let mut list = Vec::new();
            let mut seen = BTreeSet::new();
            let mut seen_bytes = 0_u64;
            for index in 0..length {
                let value = self.json_stringify_get(
                    module,
                    *object,
                    replacer.clone(),
                    &JsString::from(index.to_string()),
                )?;
                let key = match value {
                    Value::Str(key) => Some(key),
                    Value::Int(number) => {
                        Some(JsString::from(ryu_js::Buffer::new().format(number as f64)))
                    }
                    Value::Float(number) => {
                        Some(JsString::from(ryu_js::Buffer::new().format(number.inner())))
                    }
                    _ => None,
                };
                if let Some(key) = key
                    && !seen.contains(&key)
                {
                    let bytes = Self::estimate_js_string_bytes(&key)
                        .saturating_add(std::mem::size_of::<JsString>() as u64);
                    // Charge the list and the deduplication set before insertion.
                    state.reserve(self, bytes.saturating_mul(2).saturating_add(64))?;
                    seen_bytes = seen_bytes.saturating_add(bytes).saturating_add(64);
                    list.try_reserve_exact(1).map_err(|_| {
                        self.memory_budget_error(u64::MAX, self.heap_object_count_u32())
                    })?;
                    seen.insert(key.clone());
                    list.push(key);
                }
            }
            drop(seen);
            state.release(self, seen_bytes);
            state.property_list = Some(list);
        }
        // The runtime has no authenticated NumberData/StringData wrapper slot.
        // Never infer one from guest-spoofable __type/__value properties. Plain
        // objects (including such spoofs) are ignored, as the JSON contract says.
        let gap = match space {
            Value::Str(text) => text.encode_utf16().take(10).collect::<Vec<_>>(),
            Value::Int(number) => vec![u16::from(b' '); number.clamp(0, 10) as usize],
            Value::Float(number) => {
                let n = number.inner();
                let count = if n.is_nan() || n <= 0.0 {
                    0
                } else {
                    n.min(10.0).floor() as usize
                };
                vec![u16::from(b' '); count]
            }
            _ => Vec::new(),
        };
        state.reserve(self, (gap.len() * 2) as u64)?;
        state.gap = gap;
        Ok(())
    }

    fn json_stringify_keys(
        &mut self,
        module: Option<&Ir3Module>,
        object: ObjectId,
        state: &mut StringifyState,
    ) -> Result<(Vec<JsString>, u64), InterpreterError> {
        let keys = self.proxy_aware_own_property_keys(module, object, 0)?;
        let observed = self.json_parse_context_label()?;
        self.json_observe_label(observed)?;
        let key_bytes = keys.iter().fold(0_u64, |sum, key| {
            sum.saturating_add(std::mem::size_of::<Value>() as u64)
                .saturating_add(Self::estimate_value_bytes(key))
        });
        state.reserve(self, key_bytes)?;
        let mut selected = Vec::new();
        let mut retained = 0_u64;
        for value in &keys {
            if let Value::Str(key) = value {
                self.json_charge_work()?;
                let enumerable = self.own_string_key_is_enumerable(module, object, key, 0)?;
                let observed = self.json_parse_context_label()?;
                self.json_observe_label(observed)?;
                if enumerable {
                    let bytes = (std::mem::size_of::<JsString>() as u64)
                        .saturating_add(Self::estimate_js_string_bytes(key));
                    state.reserve(self, bytes)?;
                    retained += bytes;
                    selected.try_reserve_exact(1).map_err(|_| {
                        self.memory_budget_error(u64::MAX, self.heap_object_count_u32())
                    })?;
                    selected.push(key.clone());
                }
            }
        }
        drop(keys);
        state.release(self, key_bytes);
        Ok((selected, retained))
    }

    fn json_stringify_document(
        &mut self,
        module: Option<&Ir3Module>,
        input: Value,
        replacer: Value,
        space: Value,
    ) -> Result<Value, InterpreterError> {
        let mut state = StringifyState::default();
        let outcome = (|| {
            self.json_charge_work()?;
            self.json_stringify_options(module, &replacer, space, &mut state)?;
            let prototype = self.ensure_builtin_prototype("Object")?;
            let holder = self.alloc_object_with_prototype(Some(prototype))?;
            self.json_store_parsed_property(holder, JsString::from(""), input)?;
            let mut next = Some((holder, Value::Object(holder), JsString::from("")));
            loop {
                if let Some((object, receiver, key)) = next.take() {
                    let value =
                        self.json_stringify_property(module, object, receiver, &key, &replacer)?;
                    let omitted =
                        matches!(value, Value::Undefined | Value::Symbol(_)) || value.is_callable();
                    if omitted {
                        if state.frames.is_empty() {
                            return Ok(Value::Undefined);
                        }
                        if state
                            .frames
                            .last()
                            .is_some_and(|f| matches!(f.children, StringifyChildren::Array(_)))
                        {
                            state.prefix(self, &key)?;
                            state.text(self, "null")?;
                        }
                    } else {
                        if matches!(value, Value::BigInt(_)) {
                            return Err(InterpreterError::TypeError {
                                expected:
                                    "JSON-serializable value (BigInt needs toJSON or a replacer)"
                                        .into(),
                                got: "BigInt".into(),
                            });
                        }
                        state.prefix(self, &key)?;
                        match value {
                            Value::Null => state.text(self, "null")?,
                            Value::Bool(value) => {
                                state.text(self, if value { "true" } else { "false" })?
                            }
                            Value::Int(value) => {
                                state.text(self, ryu_js::Buffer::new().format(value as f64))?
                            }
                            Value::Float(value) => {
                                if value.inner().is_finite() {
                                    state
                                        .text(self, ryu_js::Buffer::new().format(value.inner()))?;
                                } else {
                                    state.text(self, "null")?;
                                }
                            }
                            Value::Str(value) => state.quote(self, &value)?,
                            value if value.is_object_like() => {
                                let backing =
                                    self.iterator_carrier_backing_id(&value, "JSON object")?;
                                if let Some(object) = backing {
                                    if state.ancestors.contains(&object) {
                                        return Err(InterpreterError::TypeError {
                                            expected: "acyclic JSON value".into(),
                                            got: "circular structure".into(),
                                        });
                                    }
                                    if state.frames.len() >= MAX_STRINGIFY_DEPTH {
                                        return Err(InterpreterError::StackOverflow {
                                            depth: state.frames.len() + 1,
                                            max: MAX_STRINGIFY_DEPTH,
                                        });
                                    }
                                    self.join_pending_hostcall_stream_label(object)?;
                                    let observed = self.json_parse_context_label()?;
                                    self.json_observe_label(observed)?;
                                    let (children, key_bytes, open) =
                                        if self.json_stringify_array_id(&value)?.is_some() {
                                            (
                                                StringifyChildren::Array(
                                                    self.json_reviver_array_length(
                                                        module,
                                                        object,
                                                        value.clone(),
                                                    )?,
                                                ),
                                                0,
                                                b'[',
                                            )
                                        } else if state.property_list.is_some() {
                                            (StringifyChildren::PropertyList, 0, b'{')
                                        } else {
                                            let (keys, bytes) = self
                                                .json_stringify_keys(module, object, &mut state)?;
                                            (StringifyChildren::Object(keys), bytes, b'{')
                                        };
                                    let charged = 64 + Self::estimate_value_bytes(&value);
                                    state.reserve(self, charged)?;
                                    state.ancestors.insert(object);
                                    state.push(self, u16::from(open))?;
                                    state.push_frame(
                                        self,
                                        StringifyFrame {
                                            receiver: value,
                                            object,
                                            children,
                                            next: 0,
                                            emitted: false,
                                            charged: charged + key_bytes,
                                        },
                                    )?;
                                } else {
                                    state.text(self, "{}")?;
                                }
                            }
                            _ => {
                                return Err(InterpreterError::TypeError {
                                    expected: "guest JSON value".into(),
                                    got: value.type_name().into(),
                                });
                            }
                        }
                    }
                }
                loop {
                    let Some(frame) = state.frames.last_mut() else {
                        // Account for normalization scratch and the returned Arc
                        // backing before converting exact output code units.
                        let bytes = (state.output.len() as u64)
                            .saturating_mul(4)
                            .saturating_add((state.projection_bytes as u64).saturating_mul(2));
                        state.reserve(self, bytes)?;
                        return Ok(Value::Str(JsString::from_code_units(&state.output)));
                    };
                    let key = match &frame.children {
                        StringifyChildren::Array(length) if frame.next < *length => {
                            Some(JsString::from(frame.next.to_string()))
                        }
                        StringifyChildren::Object(keys) => usize::try_from(frame.next)
                            .ok()
                            .and_then(|index| keys.get(index))
                            .cloned(),
                        StringifyChildren::PropertyList => usize::try_from(frame.next)
                            .ok()
                            .and_then(|index| {
                                state
                                    .property_list
                                    .as_ref()
                                    .and_then(|keys| keys.get(index))
                            })
                            .cloned(),
                        _ => None,
                    };
                    if let Some(key) = key {
                        frame.next += 1;
                        next = Some((frame.object, frame.receiver.clone(), key));
                        break;
                    }
                    let frame = state.frames.pop().expect("completed frame");
                    if frame.emitted {
                        state.indent(self, state.frames.len())?;
                    }
                    let close = if matches!(frame.children, StringifyChildren::Array(_)) {
                        b']'
                    } else {
                        b'}'
                    };
                    state.push(self, u16::from(close))?;
                    state.ancestors.remove(&frame.object);
                    let charged = frame.charged;
                    drop(frame);
                    state.release(self, charged);
                }
            }
        })();
        let charged = state.charged;
        drop(state);
        self.json_release_temporary(charged);
        outcome
    }

    // Existing low-level tests exercise the same serializer, not a second
    // snapshot-only implementation. The public builtin retains exact UTF-16.
    #[cfg(test)]
    pub(super) fn json_stringify_value(
        &mut self,
        module: Option<&Ir3Module>,
        value: &Value,
        _visited: &mut Vec<ObjectId>,
    ) -> Result<Option<String>, InterpreterError> {
        match self.json_stringify_document(
            module,
            value.clone(),
            Value::Undefined,
            Value::Undefined,
        )? {
            Value::Undefined => Ok(None),
            Value::Str(text) => Ok(Some(text.to_string())),
            _ => unreachable!("JSON result is String or undefined"),
        }
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
        InterpreterCore::new(config, "json-stringify-abrupt-provenance")
    }

    fn stringify(core: &mut InterpreterCore) -> Result<Value, InterpreterError> {
        core.dispatch_builtin_hostcall(
            "builtin:JsonStringify",
            RegRange { start: 0, count: 1 },
            None,
        )
    }

    fn assert_accounted(core: &InterpreterCore) {
        assert_eq!(core.json_parse_temporary_bytes, 0);
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }

    fn assert_type_error(core: &InterpreterCore, label: &Label) {
        let Some(Value::Object(error)) = core.pending_exception.as_ref() else {
            panic!("native JSON failure must materialize a guest error object");
        };
        assert_eq!(
            core.heap[error.0 as usize].properties.get("name"),
            Some(&Value::str("TypeError"))
        );
        assert_eq!(&core.pending_exception_label, label);
        assert_accounted(core);
    }

    #[test]
    fn bigint_failure_retains_selected_property_label_and_caller_context() {
        let mut core = core();
        let object = core
            .alloc_object_with_properties(&[("payload", Value::BigInt("1".into()))])
            .unwrap();
        let observed = Label::Custom {
            name: "secret-property".repeat(16),
            level: 9,
        };
        core.set_own_property_label(object, "payload", &observed)
            .unwrap();
        let caller = Label::Custom {
            name: "outer-json-caller".repeat(8),
            level: 7,
        };
        core.active_inline_callback_context_label = Some(caller.clone());
        core.sync_estimated_memory_bytes().unwrap();
        core.set_register(0, Value::Object(object)).unwrap();
        assert!(matches!(
            stringify(&mut core),
            Err(InterpreterError::UncaughtException { .. })
        ));
        assert_eq!(core.active_inline_callback_context_label, Some(caller));
        assert_type_error(&core, &observed);
        assert_eq!(
            core.heap[object.0 as usize].properties.get("payload"),
            Some(&Value::BigInt("1".into()))
        );
    }

    #[test]
    fn circular_failure_preserves_secret_shape_and_live_heap() {
        let mut core = core();
        let object = core.alloc_object_with_prototype(None).unwrap();
        core.set_object_property(object, "self".into(), Value::Object(object))
            .unwrap();
        core.join_direct_object_mutation_label(object, &Label::Secret)
            .unwrap();
        core.set_register(0, Value::Object(object)).unwrap();
        assert!(matches!(
            stringify(&mut core),
            Err(InterpreterError::UncaughtException { .. })
        ));
        assert!(core.active_inline_callback_context_label.is_none());
        assert_type_error(&core, &Label::Secret);
        assert_eq!(
            core.heap[object.0 as usize].properties.get("self"),
            Some(&Value::Object(object))
        );
        assert_eq!(core.object_mutation_labels.get(&object), Some(&Label::Secret));
    }

    #[test]
    fn public_native_failure_does_not_poison_the_next_serialization() {
        let mut core = core();
        core.set_register(0, Value::BigInt("1".into())).unwrap();
        assert!(matches!(
            stringify(&mut core),
            Err(InterpreterError::UncaughtException { .. })
        ));
        assert_type_error(&core, &Label::Public);
        core.replace_pending_abrupt_slots(None, None).unwrap();
        core.set_register(0, Value::str("public")).unwrap();
        assert_eq!(stringify(&mut core).unwrap(), Value::str("\"public\""));
        assert!(core.pending_exception.is_none());
        assert!(core.active_inline_callback_context_label.is_none());
        assert_eq!(core.pending_hostcall_result_label, Some(Label::Public));
        assert_accounted(&core);
    }

    #[test]
    fn instruction_refusal_is_not_materialized_as_a_language_error() {
        let mut core = core();
        core.set_register(0, Value::BigInt("1".into())).unwrap();
        core.set_register_label(0, Label::Secret).unwrap();
        core.config.instruction_budget = core.instructions_executed;
        assert!(matches!(
            stringify(&mut core),
            Err(InterpreterError::BudgetExhausted { .. })
        ));
        assert!(core.pending_exception.is_none());
        assert!(core.active_inline_callback_context_label.is_none());
        assert_accounted(&core);
    }
}
