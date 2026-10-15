//! Observable, bounded JSON serialization on the native interpreter.
//!
//! The traversal is an explicit work stack. Property selection is snapshotted,
//! but Get, toJSON and replacer calls stay live and ordered. Only ancestors
//! participate in cycle detection, and no guest mutation is rolled back on an
//! exception. Scratch remains charged across reentrant guest calls.

use super::*;

mod output;

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

    /// Append an exact key with amortized linear copying. Charge the complete
    /// capacity increment, including unused slots, before native allocation.
    /// The returned charge belongs to this vector and must live until it drops,
    /// even when a nested frame or guest callback allocates more scratch.
    fn push_key(
        &mut self,
        core: &mut InterpreterCore,
        keys: &mut Vec<JsString>,
        key: &JsString,
    ) -> Result<u64, InterpreterError> {
        let additional = if keys.len() == keys.capacity() {
            keys.capacity().max(8)
        } else {
            0
        };
        let slots = (additional as u64).saturating_mul(std::mem::size_of::<JsString>() as u64);
        let bytes = slots.saturating_add(InterpreterCore::estimate_js_string_bytes(key));
        self.reserve(core, bytes)?;
        if additional != 0 && keys.try_reserve_exact(additional).is_err() {
            self.release(core, bytes);
            return Err(core.memory_budget_error(u64::MAX, core.heap_object_count_u32()));
        }
        keys.push(key.clone());
        Ok(bytes)
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

    /// Append ASCII into already charged capacity. A normal push starts each
    /// batch, so allocation, cancellation/work and size-limit boundaries keep
    /// the scalar writer's exact order. The bulk suffix crosses none of them.
    fn ascii(
        &mut self,
        core: &mut InterpreterCore,
        mut bytes: &[u8],
    ) -> Result<(), InterpreterError> {
        debug_assert!(bytes.is_ascii());
        while let Some((&first, rest)) = bytes.split_first() {
            self.push(core, u16::from(first))?;
            bytes = rest;
            let remainder = self.output.len() % 256;
            let until_checkpoint = if remainder == 0 { 0 } else { 256 - remainder };
            let available = self.output.capacity() - self.output.len();
            let below_limit = core
                .config
                .max_string_size
                .saturating_sub(self.projection_bytes);
            let count = bytes
                .len()
                .min(available)
                .min(until_checkpoint)
                .min(below_limit);
            // ASCII contributes exactly one projected byte, even following a
            // high surrogate. No reserve occurs: these slots are already paid.
            for &byte in &bytes[..count] {
                self.output.push(u16::from(byte));
            }
            self.projection_bytes += count;
            bytes = &bytes[count..];
        }
        Ok(())
    }

    fn text(&mut self, core: &mut InterpreterCore, text: &str) -> Result<(), InterpreterError> {
        // Literals, numbers and escape spellings are short. Bound the ASCII
        // probe so a long text never introduces an unbounded checkpoint delay.
        if text.len() <= 256 && text.is_ascii() {
            return self.ascii(core, text.as_bytes());
        }
        self.units(core, text.encode_utf16())
    }

    /// Quote an ASCII payload between the caller's opening/closing quotes.
    /// Inspect at most one checkpoint interval before appending a span; a
    /// large unescaped string never needs an uncharged whole-string scan.
    fn quote_ascii(
        &mut self,
        core: &mut InterpreterCore,
        mut bytes: &[u8],
    ) -> Result<(), InterpreterError> {
        while !bytes.is_empty() {
            let window = bytes.len().min(256);
            let plain = bytes[..window]
                .iter()
                .position(|&byte| byte < 0x20 || byte == b'"' || byte == b'\\')
                .unwrap_or(window);
            if plain != 0 {
                self.ascii(core, &bytes[..plain])?;
                bytes = &bytes[plain..];
                continue;
            }
            match bytes[0] {
                b'"' => self.text(core, "\\\"")?,
                b'\\' => self.text(core, "\\\\")?,
                0x08 => self.text(core, "\\b")?,
                0x0c => self.text(core, "\\f")?,
                b'\n' => self.text(core, "\\n")?,
                b'\r' => self.text(core, "\\r")?,
                b'\t' => self.text(core, "\\t")?,
                byte => self.hex_escape(core, u16::from(byte))?,
            }
            bytes = &bytes[1..];
        }
        Ok(())
    }

    /// Emit a JSON Unicode escape without a temporary formatted String. Each
    /// output unit still uses push, preserving work, size and allocation gates.
    fn hex_escape(
        &mut self,
        core: &mut InterpreterCore,
        unit: u16,
    ) -> Result<(), InterpreterError> {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        self.push(core, u16::from(b'\\'))?;
        self.push(core, u16::from(b'u'))?;
        for shift in [12, 8, 4, 0] {
            self.push(core, u16::from(HEX[usize::from((unit >> shift) & 0xf)]))?;
        }
        Ok(())
    }

    fn quote(
        &mut self,
        core: &mut InterpreterCore,
        text: &JsString,
    ) -> Result<(), InterpreterError> {
        self.push(core, u16::from(b'"'))?;
        self.quote_contents(core, text)?;
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
        // ES2020 24.5.2.2 step 4: a Number, String, Boolean or BigInt wrapper
        // serializes as its primitive (bd-9vouw.73). A Number wrapper goes
        // through ToNumber and a String wrapper through ToString, so their
        // valueOf / toString run (and may throw).
        if let Value::Object(object_id) = &value {
            value = match self.primitive_wrapper_value(*object_id).cloned() {
                Some(Value::Int(_) | Value::Float(_)) => {
                    js_number_to_value(self.conversion_to_number(module, value, false)?)
                }
                Some(Value::Str(_)) => Value::Str(self.conversion_to_string(module, value)?),
                Some(primitive @ (Value::Bool(_) | Value::BigInt(_))) => primitive,
                _ => value,
            };
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
                // ES2020 24.5.2 step 4.b.iii.5.e: a Number or String wrapper
                // item is ToString'd (its toString runs).
                let value = match &value {
                    Value::Object(object_id)
                        if matches!(
                            self.primitive_wrapper_value(*object_id),
                            Some(Value::Int(_) | Value::Float(_) | Value::Str(_))
                        ) =>
                    {
                        Value::Str(self.conversion_to_string(module, value)?)
                    }
                    _ => value,
                };
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
                        .saturating_add(std::mem::size_of::<JsString>() as u64)
                        .saturating_add(64);
                    // The set dies after option collection; the list's backing
                    // capacity stays charged until the whole document finishes.
                    state.reserve(self, bytes)?;
                    seen_bytes = seen_bytes.saturating_add(bytes);
                    state.push_key(self, &mut list, &key)?;
                    seen.insert(key);
                }
            }
            drop(seen);
            state.release(self, seen_bytes);
            state.property_list = Some(list);
        }
        // ES2020 24.5.2 step 5: a Number wrapper space is ToNumber'd and a
        // String wrapper ToString'd (their valueOf / toString run). A wrapper
        // is recognized by its heap object's primitive_value slot
        // (bd-9vouw.73), never by guest-spoofable __type / __value
        // properties; any other object space is ignored.
        let space = match &space {
            Value::Object(object_id) => match self.primitive_wrapper_value(*object_id) {
                Some(Value::Int(_) | Value::Float(_)) => {
                    js_number_to_value(self.conversion_to_number(module, space, false)?)
                }
                Some(Value::Str(_)) => Value::Str(self.conversion_to_string(module, space)?),
                _ => space,
            },
            _ => space,
        };
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
                    retained = retained.saturating_add(state.push_key(self, &mut selected, key)?);
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
                            // A JSON.rawJSON result is its text (bd-9vouw.380).
                            Value::Object(object) if self.is_raw_json_object(object) => {
                                let raw = match self.json_stringify_get(
                                    module,
                                    object,
                                    Value::Object(object),
                                    &JsString::from("rawJSON"),
                                )? {
                                    Value::Str(raw) => raw,
                                    other => {
                                        return Err(InterpreterError::TypeError {
                                            expected: "raw JSON text".into(),
                                            got: other.type_name().into(),
                                        });
                                    }
                                };
                                if raw.is_ascii() {
                                    state.ascii(self, raw.as_bytes())?;
                                } else {
                                    state.units(self, raw.encode_utf16())?;
                                }
                            }
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

    mod rope_output;
    mod unicode_batches;

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
            core.chain_data_property(*error, "name"),
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
        core.seed_register(0, Value::Object(object)).unwrap();
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
        core.seed_register(0, Value::Object(object)).unwrap();
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
        assert_eq!(
            core.object_mutation_labels.get(&object),
            Some(&Label::Secret)
        );
    }

    #[test]
    fn public_native_failure_does_not_poison_the_next_serialization() {
        let mut core = core();
        core.seed_register(0, Value::BigInt("1".into())).unwrap();
        assert!(matches!(
            stringify(&mut core),
            Err(InterpreterError::UncaughtException { .. })
        ));
        assert_type_error(&core, &Label::Public);
        core.replace_pending_abrupt_slots(None, None).unwrap();
        core.seed_register(0, Value::str("public")).unwrap();
        assert_eq!(stringify(&mut core).unwrap(), Value::str("\"public\""));
        assert!(core.pending_exception.is_none());
        assert!(core.active_inline_callback_context_label.is_none());
        assert_eq!(core.pending_hostcall_result_label, Some(Label::Public));
        assert_accounted(&core);
    }

    #[test]
    fn instruction_refusal_is_not_materialized_as_a_language_error() {
        let mut core = core();
        core.seed_register(0, Value::BigInt("1".into())).unwrap();
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

    #[test]
    fn key_scratch_growth_is_logarithmic_and_capacity_is_charged() {
        let mut core = core();
        let mut state = StringifyState::default();
        let mut keys = Vec::new();
        let mut growths = 0;
        let mut moved = 0;
        let mut retained = 0_u64;
        let mut payload = 0_u64;
        for index in 0..16_384 {
            let key = JsString::from(index.to_string());
            let capacity = keys.capacity();
            let length = keys.len();
            payload += InterpreterCore::estimate_js_string_bytes(&key);
            retained += state.push_key(&mut core, &mut keys, &key).unwrap();
            if keys.capacity() != capacity {
                growths += 1;
                moved += length;
            }
            assert_eq!(state.charged, retained);
            assert_eq!(core.json_parse_temporary_bytes, retained);
            assert!(retained >= payload + (keys.len() * std::mem::size_of::<JsString>()) as u64);
        }
        assert!(growths <= 12, "reallocated {growths} times");
        assert!(moved < 2 * keys.len(), "copied {moved} key slots");
        assert_eq!(keys[0], JsString::from("0"));
        assert_eq!(keys[16_383], JsString::from("16383"));
        drop(keys);
        state.release(&mut core, retained);
        assert_eq!(state.charged, 0);
        assert_accounted(&core);
    }

    #[test]
    fn key_scratch_preserves_exact_units_duplicates_and_order() {
        let mut core = core();
        let mut state = StringifyState::default();
        let mut keys = Vec::new();
        let expected = [
            JsString::from_code_units(&[0xd800]),
            JsString::from("\u{fffd}"),
            JsString::from_code_units(&[0xd801]),
            JsString::from_code_units(&[0xdc00]),
            JsString::from("plain"),
            JsString::from_code_units(&[0xd800]),
        ];
        for key in &expected {
            state.push_key(&mut core, &mut keys, key).unwrap();
        }
        assert_eq!(keys.as_slice(), expected.as_slice());
        assert_ne!(keys[0], keys[1]);
        assert_ne!(keys[0], keys[2]);
        let charged = state.charged;
        drop(keys);
        state.release(&mut core, charged);
        assert_accounted(&core);
    }

    #[test]
    fn releasing_one_key_snapshot_keeps_other_scratch_charged() {
        let mut core = core();
        let mut state = StringifyState::default();
        let mut outer = Vec::new();
        let mut inner = Vec::new();
        let mut outer_bytes = 0;
        let mut inner_bytes = 0;
        for index in 0..17 {
            outer_bytes += state
                .push_key(&mut core, &mut outer, &JsString::from(index.to_string()))
                .unwrap();
        }
        for key in ["a", "b", "c"] {
            inner_bytes += state
                .push_key(&mut core, &mut inner, &JsString::from(key))
                .unwrap();
        }
        assert_eq!(state.charged, outer_bytes + inner_bytes);
        drop(inner);
        state.release(&mut core, inner_bytes);
        assert_eq!(state.charged, outer_bytes);
        assert_eq!(core.json_parse_temporary_bytes, outer_bytes);
        assert_eq!(outer.len(), 17);
        drop(outer);
        state.release(&mut core, outer_bytes);
        assert_accounted(&core);
    }

    #[test]
    fn large_object_serialization_preserves_keys_and_releases_snapshot_capacity() {
        let mut core = core();
        let object = core.alloc_object_with_prototype(None).unwrap();
        let mut expected = String::from("{");
        for index in 0..256 {
            let key = format!("key{index:04}");
            core.set_object_property(object, key.clone(), Value::Int(index))
                .unwrap();
            if index != 0 {
                expected.push(',');
            }
            expected.push_str(&format!("\"{key}\":{index}"));
        }
        expected.push('}');
        core.seed_register(0, Value::Object(object)).unwrap();
        assert_eq!(
            stringify(&mut core).unwrap(),
            Value::Str(JsString::from(expected))
        );
        assert!(core.pending_exception.is_none());
        assert!(core.active_inline_callback_context_label.is_none());
        assert_accounted(&core);
    }

    // Independent pre-optimization oracle: retain the scalar codec and
    // formatted escapes, and never delegate text to the optimized writer.
    fn reference_text(
        state: &mut StringifyState,
        core: &mut InterpreterCore,
        text: &str,
    ) -> Result<(), InterpreterError> {
        for unit in text.encode_utf16() {
            state.push(core, unit)?;
        }
        Ok(())
    }

    fn reference_quote(
        state: &mut StringifyState,
        core: &mut InterpreterCore,
        text: &JsString,
    ) -> Result<(), InterpreterError> {
        state.push(core, u16::from(b'"'))?;
        for decoded in char::decode_utf16(text.encode_utf16()) {
            match decoded {
                Ok('"') => reference_text(state, core, "\\\"")?,
                Ok('\\') => reference_text(state, core, "\\\\")?,
                Ok('\u{0008}') => reference_text(state, core, "\\b")?,
                Ok('\u{000c}') => reference_text(state, core, "\\f")?,
                Ok('\n') => reference_text(state, core, "\\n")?,
                Ok('\r') => reference_text(state, core, "\\r")?,
                Ok('\t') => reference_text(state, core, "\\t")?,
                Ok(c) if c <= '\u{001f}' => {
                    reference_text(state, core, &format!("\\u{:04x}", c as u32))?;
                }
                Ok(c) => {
                    for unit in c.encode_utf16(&mut [0_u16; 2]) {
                        state.push(core, *unit)?;
                    }
                }
                Err(error) => {
                    reference_text(state, core, &format!("\\u{:04x}", error.unpaired_surrogate()))?;
                }
            }
        }
        state.push(core, u16::from(b'"'))
    }

    fn release_test_state(core: &mut InterpreterCore, state: StringifyState) {
        let charged = state.charged;
        drop(state);
        core.json_release_temporary(charged);
        assert_accounted(core);
    }

    fn compare_quote(
        text: &JsString,
        prefix: &[u16],
        string_limit: usize,
        work_budget: u64,
        scratch_budget: Option<u64>,
    ) {
        let mut actual_core = core();
        let mut expected_core = core();
        let mut actual = StringifyState::default();
        let mut expected = StringifyState::default();
        for &unit in prefix {
            actual.push(&mut actual_core, unit).unwrap();
            expected.push(&mut expected_core, unit).unwrap();
        }
        for core in [&mut actual_core, &mut expected_core] {
            core.config.max_string_size = string_limit;
            core.config.instruction_budget = core.instructions_executed + work_budget;
            if let Some(bytes) = scratch_budget {
                core.config.max_total_memory_bytes = core.estimated_memory_bytes() + bytes;
            }
        }
        let got = actual.quote(&mut actual_core, text);
        let want = reference_quote(&mut expected, &mut expected_core, text);
        assert_eq!(format!("{got:?}"), format!("{want:?}"));
        assert_eq!(actual.output, expected.output);
        assert_eq!(actual.projection_bytes, expected.projection_bytes);
        assert_eq!(actual.output.capacity(), expected.output.capacity());
        assert_eq!(actual.charged, expected.charged);
        assert_eq!(
            actual_core.instructions_executed,
            expected_core.instructions_executed
        );
        assert_eq!(
            actual_core.json_parse_temporary_bytes,
            expected_core.json_parse_temporary_bytes
        );
        assert_eq!(
            actual_core.estimated_memory_bytes(),
            expected_core.estimated_memory_bytes()
        );
        release_test_state(&mut actual_core, actual);
        release_test_state(&mut expected_core, expected);
    }

    #[test]
    fn quote_code_units_matches_scalar_oracle_for_every_bmp_unit() {
        let text = JsString::from_code_units(&(0..=u16::MAX).collect::<Vec<_>>());
        compare_quote(&text, &[], 1_048_576, 100_000, None);
    }

    #[test]
    fn quote_code_units_preserves_pairs_and_short_escapes() {
        let text = JsString::from_code_units(&[
            0, 8, 9, 10, 12, 13, 34, 92, 47, 0xd800, 65, 0xdc00, 0xd83d, 0xde00,
        ]);
        let mut core = core();
        let mut state = StringifyState::default();
        state.quote(&mut core, &text).unwrap();
        assert_eq!(
            state.output,
            "\"\\u0000\\b\\t\\n\\f\\r\\\"\\\\/\\ud800A\\udc00😀\""
                .encode_utf16()
                .collect::<Vec<_>>()
        );
        release_test_state(&mut core, state);
    }

    #[test]
    fn quote_code_units_matches_scalar_oracle_at_surrogate_boundaries() {
        let boundaries = [
            0, 0x1f, 0x20, 0x22, 0x5c, 0x7f, 0xd7ff, 0xd800, 0xdbff, 0xdc00, 0xdfff, 0xe000, 0xffff,
        ];
        for left in boundaries {
            for right in boundaries {
                let text = JsString::from_code_units(&[left, right, left]);
                compare_quote(&text, &[], 1_048_576, 100_000, None);
            }
        }
    }

    #[test]
    fn quote_code_units_matches_scalar_oracle_for_seeded_exact_strings() {
        let mut seed = 0x71a3_49c5_u32;
        for length in 0..256 {
            let units = (0..length)
                .map(|_| {
                    seed ^= seed << 13;
                    seed ^= seed >> 17;
                    seed ^= seed << 5;
                    seed as u16
                })
                .collect::<Vec<_>>();
            compare_quote(
                &JsString::from_code_units(&units),
                &[],
                1_048_576,
                100_000,
                None,
            );
        }
    }

    #[test]
    fn quote_code_units_preserves_refusal_prefixes_and_scratch_charges() {
        let texts = [
            JsString::from("a".repeat(700)),
            JsString::from_code_units(&[0, 34, 0xd800, 0xdc00, 0xdfff, 65, 8, 92]),
            JsString::from_code_units(&vec![0xd800; 128]),
        ];
        let prefixes = [vec![], vec![65; 255], vec![0xd800]];
        for text in &texts {
            for prefix in &prefixes {
                for limit in [0, 1, 2, 5, 6, 7, 63, 64, 65, 255, 256, 257, 511, 1024] {
                    for work in [0, 1, 2, 8] {
                        compare_quote(text, prefix, limit, work, None);
                    }
                }
                for scratch in [0, 1, 127, 128, 129, 255, 256, 257, 1024] {
                    compare_quote(text, prefix, 4096, 100_000, Some(scratch));
                }
            }
        }
    }

    #[test]
    fn quoted_string_builtin_keeps_secret_provenance_and_exact_units() {
        let mut core = core();
        core.seed_register(
            0,
            Value::Str(JsString::from_code_units(&[0xd800, 65, 0xdc00])),
        )
        .unwrap();
        core.set_register_label(0, Label::Secret).unwrap();
        assert_eq!(
            stringify(&mut core).unwrap(),
            Value::str("\"\\ud800A\\udc00\"")
        );
        assert_eq!(core.pending_hostcall_result_label, Some(Label::Secret));
        assert_accounted(&core);
    }

    fn compare_text(
        text: &str,
        prefix: &[u16],
        string_limit: usize,
        work_budget: u64,
        scratch_budget: Option<u64>,
    ) {
        let mut actual_core = core();
        let mut expected_core = core();
        let mut actual = StringifyState::default();
        let mut expected = StringifyState::default();
        for &unit in prefix {
            actual.push(&mut actual_core, unit).unwrap();
            expected.push(&mut expected_core, unit).unwrap();
        }
        for core in [&mut actual_core, &mut expected_core] {
            core.config.max_string_size = string_limit;
            core.config.instruction_budget = core.instructions_executed + work_budget;
            if let Some(bytes) = scratch_budget {
                core.config.max_total_memory_bytes = core.estimated_memory_bytes() + bytes;
            }
        }
        let got = actual.text(&mut actual_core, text);
        let want = reference_text(&mut expected, &mut expected_core, text);
        assert_eq!(format!("{got:?}"), format!("{want:?}"));
        assert_eq!(actual.output, expected.output);
        assert_eq!(actual.projection_bytes, expected.projection_bytes);
        assert_eq!(actual.output.capacity(), expected.output.capacity());
        assert_eq!(actual.charged, expected.charged);
        assert_eq!(
            actual_core.instructions_executed,
            expected_core.instructions_executed
        );
        assert_eq!(
            actual_core.json_parse_temporary_bytes,
            expected_core.json_parse_temporary_bytes
        );
        assert_eq!(
            actual_core.estimated_memory_bytes(),
            expected_core.estimated_memory_bytes()
        );
        release_test_state(&mut actual_core, actual);
        release_test_state(&mut expected_core, expected);
    }

    #[test]
    fn ascii_text_keeps_checkpoint_capacity_and_refusal_boundaries() {
        for prefix_len in [0, 1, 63, 64, 127, 128, 254, 255, 256, 511] {
            let prefix = vec![u16::from(b'p'); prefix_len];
            for length in [0, 1, 2, 63, 64, 65, 127, 128, 255, 256, 257, 1024] {
                let text = "a".repeat(length);
                for limit in [0, 1, 63, 64, 65, 255, 256, 257, 511, 1024, 4096] {
                    compare_text(&text, &prefix, limit, 100_000, None);
                }
                for work in [0, 1, 2, 8] {
                    compare_text(&text, &prefix, 4096, work, None);
                }
                for scratch in [0, 1, 127, 128, 129, 255, 256, 257, 1024] {
                    compare_text(&text, &prefix, 4096, 100_000, Some(scratch));
                }
            }
        }
    }

    #[test]
    fn ascii_quote_batches_keep_every_escape_and_boundary_position() {
        for position in [0, 1, 62, 63, 64, 126, 127, 128, 254, 255, 256, 511] {
            let mut units = vec![u16::from(b'a'); position];
            units.extend(0..128);
            units.extend(std::iter::repeat_n(u16::from(b'z'), 513));
            let text = JsString::from_code_units(&units);
            assert!(text.is_ascii());
            compare_quote(&text, &[], 4096, 100_000, None);
            for limit in [position, position + 1, position + 2, position + 64] {
                compare_quote(&text, &[], limit, 100_000, None);
            }
            for work in [0, 1, 2, 8] {
                compare_quote(&text, &[], 4096, work, None);
            }
        }
    }

    #[test]
    fn text_batching_keeps_utf16_projection_and_unicode_fallback() {
        let high_surrogate = [0xd800];
        for text in [
            "",
            "ascii",
            "\0\n\t",
            "é",
            "€",
            "😀",
            "a😀b",
            "\u{2028}\u{2029}",
        ] {
            for prefix in [&high_surrogate[..], &[][..]] {
                for limit in 0..24 {
                    compare_text(text, prefix, limit, 100_000, None);
                }
            }
        }
        // Both sides of the bounded text probe, followed by the non-ASCII
        // fallback: no whole-input ASCII scan is needed for long text.
        for length in [255, 256, 257, 2048] {
            let text = format!("{}😀", "a".repeat(length));
            compare_text(&text, &high_surrogate, 4096, 100_000, None);
        }
    }

    #[test]
    fn ascii_batches_do_not_allocate_when_paid_capacity_is_available() {
        let mut core = core();
        let mut state = StringifyState::default();
        state.push(&mut core, u16::from(b'x')).unwrap();
        let capacity = state.output.capacity();
        let charged = state.charged;
        core.config.max_total_memory_bytes = core.estimated_memory_bytes();
        state.ascii(&mut core, &vec![b'a'; capacity - 1]).unwrap();
        assert_eq!(state.output.len(), capacity);
        assert_eq!(state.output.capacity(), capacity);
        assert_eq!(state.charged, charged);
        assert!(state.ascii(&mut core, b"!").is_err());
        assert_eq!(state.output.len(), capacity);
        assert_eq!(state.output.capacity(), capacity);
        assert_eq!(state.charged, charged);
        release_test_state(&mut core, state);
    }

    #[test]
    fn long_ascii_builtin_quotes_keep_secret_result_provenance() {
        let mut core = core();
        let payload = "0123456789abcdef".repeat(256);
        core.seed_register(0, Value::str(payload.clone())).unwrap();
        core.set_register_label(0, Label::Secret).unwrap();
        assert_eq!(
            stringify(&mut core).unwrap(),
            Value::str(format!("\"{payload}\""))
        );
        assert_eq!(core.pending_hostcall_result_label, Some(Label::Secret));
        assert_accounted(&core);
    }

    #[test]
    fn ascii_batches_observe_cancellation_at_the_scalar_checkpoint() {
        for prefix_len in [0, 1, 63, 64, 255, 256, 257] {
            let mut actual_core = core();
            let mut expected_core = core();
            let mut actual = StringifyState::default();
            let mut expected = StringifyState::default();
            for _ in 0..prefix_len {
                actual.push(&mut actual_core, 65).unwrap();
                expected.push(&mut expected_core, 65).unwrap();
            }
            let token = CancellationToken::new();
            token.cancel();
            actual_core.config.cancellation_token = Some(token.clone());
            expected_core.config.cancellation_token = Some(token);
            let text = "z".repeat(768);
            assert!(matches!(
                actual.quote(&mut actual_core, &JsString::from(text.clone())),
                Err(InterpreterError::Cancelled)
            ));
            assert!(matches!(
                reference_quote(&mut expected, &mut expected_core, &JsString::from(text)),
                Err(InterpreterError::Cancelled)
            ));
            assert_eq!(actual.output, expected.output);
            assert_eq!(actual.projection_bytes, expected.projection_bytes);
            assert_eq!(actual.output.capacity(), expected.output.capacity());
            assert_eq!(actual.charged, expected.charged);
            assert_eq!(
                actual_core.instructions_executed,
                expected_core.instructions_executed
            );
            release_test_state(&mut actual_core, actual);
            release_test_state(&mut expected_core, expected);
        }
    }
}
