//! Public buffered Fetch objects over the same native slots as network responses.
//!
//! Headers keeps an authenticated mutable list; its iterators project that list
//! at each step, so callbacks and mutations cannot freeze stale values or labels.
//! Response construction is pure computation. It confers no network authority.

use super::*;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(in crate::baseline_interpreter) struct FetchHeadersIteratorSlots {
    pub headers: ObjectId,
    pub next_index: usize,
    pub kind: RuntimeTypedArrayIteratorKind,
}

fn header_pair_error() -> InterpreterError {
    fetch_type_error("a two-item iterable header pair")
}

fn normalize_header_pair(name: &mut String, value: &mut String) -> Result<(), InterpreterError> {
    if !http_token(name) {
        return Err(fetch_type_error("a valid HTTP header name"));
    }
    if value.chars().any(|ch| matches!(ch, '\0' | '\r' | '\n')) {
        return Err(fetch_type_error(
            "an HTTP header value without NUL or line breaks",
        ));
    }
    name.make_ascii_lowercase();
    *value = value.trim_matches([' ', '\t']).to_string();
    Ok(())
}

fn append_header_field(fields: &mut Vec<(String, String)>, name: String, value: String) {
    if name != "set-cookie"
        && let Some((_, existing)) = fields.iter_mut().find(|(key, _)| *key == name)
    {
        // Node's server Fetch profile combines Cookie fields as cookie pairs.
        existing.push_str(if name == "cookie" { "; " } else { ", " });
        existing.push_str(&value);
    } else {
        fields.push((name, value));
    }
}

fn response_status(number: f64) -> u16 {
    // Web IDL unsigned short, without EnforceRange. Range validation belongs
    // to Response initialization, after dictionary conversion.
    if !number.is_finite() || number == 0.0 {
        0
    } else {
        number.trunc().rem_euclid(65_536.0) as u16
    }
}

fn valid_status_text(value: &str) -> bool {
    value
        .chars()
        .all(|ch| ch == '\t' || matches!(ch as u32, 0x20..=0x7e | 0x80..=0xff))
}

struct ResponseInit {
    fields: Vec<(String, String)>,
    status: u16,
    status_text: String,
}

impl InterpreterCore {
    /// Preserve observations while native exceptions become guest values.
    /// The generic conversion scope publishes only successful results; Fetch
    /// object algorithms also expose failure after observable conversions.
    pub(in crate::baseline_interpreter) fn finish_fetch_object_result<T>(
        &mut self,
        mut outcome: Result<T, InterpreterError>,
    ) -> Result<T, InterpreterError> {
        if let Err(error) = &outcome
            && Self::js_catchable_error_name(error).is_none()
            && !matches!(error, InterpreterError::UncaughtException { .. })
        {
            // Budget, cancellation and capability refusals stay host failures.
            return outcome;
        }
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
        if matches!(outcome, Err(InterpreterError::UncaughtException { .. })) {
            let observed = self
                .json_parse_context_label()
                .and_then(|context| self.join_pending_exception_label(&context));
            if let Err(error) = observed {
                outcome = Err(error);
            }
        }
        outcome
    }

    /// Stream identity belongs to the private native module state. The carrier
    /// predicate is captured before exports escape; guest prototypes and public
    /// module exports never participate in this check.
    pub(in crate::baseline_interpreter) fn is_authenticated_readable_stream_body(
        &mut self,
        module: Option<&Ir3Module>,
        body: &Value,
    ) -> Result<bool, InterpreterError> {
        if !body.is_object_like() {
            return Ok(false);
        }
        let Some(predicate) = self.cached_readable_stream_brand_predicate()? else {
            return Ok(false);
        };
        self.json_observe_reachable_value(body)?;
        let label = self.json_parse_context_label()?;
        self.preflight_inline_method_call_with_argument_label(module, &predicate, 1, Some(&label))?;
        let (result, result_label) =
            self.with_gc_nested_request(vec![body.clone(), predicate.clone()], |core| {
                core.invoke_inline_method_call_with_argument_label_preflighted(
                    module,
                    predicate,
                    Value::Undefined,
                    vec![body.clone()],
                    Some(label),
                )
            })?;
        self.json_observe_label(result_label)?;
        self.observe_scoped_callback_result()?;
        match result {
            Value::Bool(branded) => Ok(branded),
            _ => Err(InterpreterError::InternalError {
                details: "private ReadableStream brand predicate returned a non-boolean"
                    .to_string(),
            }),
        }
    }

    /// Web IDL ByteString keeps Latin-1 without replacing lone surrogates.
    /// HTTP transmission retains its separate, narrower ASCII wire contract.
    pub(in crate::baseline_interpreter) fn fetch_object_byte_string(
        &mut self,
        module: &Ir3Module,
        value: Value,
        scratch: &mut u64,
    ) -> Result<String, InterpreterError> {
        self.json_observe_reachable_value(&value)?;
        let text = self.conversion_to_string(Some(module), value)?;
        self.fetch_reserve(
            scratch,
            (text.len() as u64)
                .saturating_add(MEMORY_ESTIMATE_STRING_BASE_BYTES)
                .saturating_mul(2),
        )?;
        self.fetch_charge_bytes(text.len())?;
        if text.encode_utf16().any(|unit| unit > 255) {
            return Err(fetch_type_error(
                "a ByteString containing only Latin-1 code units",
            ));
        }
        Ok(text.as_utf8_projection().to_string())
    }

    pub(in crate::baseline_interpreter) fn fetch_stage_header_pair(
        &mut self,
        fields: &mut Vec<(String, String)>,
        name: String,
        value: String,
        scratch: &mut u64,
    ) -> Result<(), InterpreterError> {
        self.fetch_reserve(scratch, 2 * std::mem::size_of::<(String, String)>() as u64)?;
        fields
            .try_reserve(1)
            .map_err(|_| self.memory_budget_error(u64::MAX, self.heap_object_count_u32()))?;
        fields.push((name, value));
        Ok(())
    }

    /// Convert HeadersInit once, before validating or filling a header list.
    /// The same conversion is shared by Headers, ResponseInit and fetch init.
    pub(in crate::baseline_interpreter) fn fetch_convert_headers_init(
        &mut self,
        module: &Ir3Module,
        input: Value,
        scratch: &mut u64,
    ) -> Result<Vec<(String, String)>, InterpreterError> {
        if matches!(input, Value::Undefined) {
            return Ok(Vec::new());
        }
        if !input.is_object_like() {
            return Err(fetch_type_error(
                "a header record or iterable of header pairs",
            ));
        }
        self.json_observe_reachable_value(&input)?;
        let pins = self.gc_pin_network_values([input.clone()]);
        let result = (|| {
            let mut fields = Vec::new();
            if let Some(initial) = self.prepare_custom_for_of_state(module, &input)? {
                let iterator =
                    self.init_iterator_from_state(input.clone(), initial, IterationKind::ForOf)?;
                self.gc_pin_network_values([iterator.clone()]);
                let mut invalid_length = false;
                loop {
                    self.json_charge_work()?;
                    let pair = self.advance_for_of_iterator(Some(module), iterator.clone())?;
                    self.observe_scoped_callback_result()?;
                    let Some(pair) = pair else {
                        break;
                    };
                    let pair_pins = self.gc_pin_network_values([pair.clone()]);
                    let converted = self.fetch_convert_header_pair(module, pair, scratch);
                    self.gc_unpin_network_values(pair_pins);
                    let (name, value, valid_length) = match converted {
                        Ok(pair) => pair,
                        Err(error) => {
                            return self.array_from_close_after_error(
                                Some(module),
                                iterator,
                                error,
                            );
                        }
                    };
                    invalid_length |= !valid_length;
                    self.fetch_stage_header_pair(&mut fields, name, value, scratch)?;
                }
                // Sequence conversion observes every pair before Headers.fill
                // rejects a pair whose converted sequence has the wrong length.
                if invalid_length {
                    return Err(header_pair_error());
                }
                return Ok(fields);
            }
            let Some(id) = self.own_property_holder(Some(module), &input, false)? else {
                return Ok(fields);
            };
            let keys = self.proxy_aware_own_property_keys(Some(module), id, 0)?;
            let key_bytes = keys.iter().fold(0u64, |bytes, key| {
                bytes.saturating_add(Self::estimate_value_bytes(key))
            });
            self.fetch_reserve(scratch, key_bytes)?;
            self.gc_pin_network_values(keys.iter().cloned());
            for key_value in keys {
                self.json_charge_work()?;
                let key = self.executable_property_key_from_value(&key_value);
                let descriptor = self.proxy_target_descriptor_fields(Some(module), id, &key, 0)?;
                if !descriptor.is_some_and(|fields| fields.enumerable == Some(true)) {
                    continue;
                }
                let Value::Str(key_text) = key_value else {
                    return Err(fetch_type_error("a string header record key"));
                };
                let name = self.fetch_object_byte_string(module, Value::Str(key_text), scratch)?;
                let value = self.get_v(module, &input, &key)?;
                let value_pins = self.gc_pin_network_values([value.clone()]);
                let converted = self.fetch_object_byte_string(module, value, scratch);
                self.gc_unpin_network_values(value_pins);
                self.fetch_stage_header_pair(&mut fields, name, converted?, scratch)?;
            }
            Ok(fields)
        })();
        self.gc_unpin_network_values(pins);
        result
    }

    fn fetch_convert_header_pair(
        &mut self,
        module: &Ir3Module,
        pair: Value,
        scratch: &mut u64,
    ) -> Result<(String, String, bool), InterpreterError> {
        if !pair.is_object_like() {
            return Err(header_pair_error());
        }
        let initial = self
            .prepare_custom_for_of_state(module, &pair)?
            .ok_or_else(header_pair_error)?;
        let iterator = self.init_iterator_from_state(pair, initial, IterationKind::ForOf)?;
        let pins = self.gc_pin_network_values([iterator.clone()]);
        let result = (|| {
            let mut name = String::new();
            let mut value = String::new();
            let mut count = 0usize;
            loop {
                self.json_charge_work()?;
                let item = self.advance_for_of_iterator(Some(module), iterator.clone())?;
                self.observe_scoped_callback_result()?;
                let Some(item) = item else {
                    break;
                };
                let item_pins = self.gc_pin_network_values([item.clone()]);
                let converted = self.fetch_object_byte_string(module, item, scratch);
                self.gc_unpin_network_values(item_pins);
                let text = match converted {
                    Ok(text) => text,
                    Err(error) => {
                        return self.array_from_close_after_error(Some(module), iterator, error);
                    }
                };
                match count {
                    0 => name = text,
                    1 => value = text,
                    _ => {}
                }
                count = count.saturating_add(1);
            }
            Ok((name, value, count == 2))
        })();
        self.gc_unpin_network_values(pins);
        result
    }

    pub(in crate::baseline_interpreter) fn fetch_fill_header_fields(
        &mut self,
        fields: Vec<(String, String)>,
        scratch: &mut u64,
    ) -> Result<Vec<(String, String)>, InterpreterError> {
        let size = fields.iter().fold(0u64, |total, (name, value)| {
            total
                .saturating_add(Self::estimate_string_bytes(name))
                .saturating_add(Self::estimate_string_bytes(value))
                .saturating_add(2 + std::mem::size_of::<(String, String)>() as u64)
        });
        // Normalization and combining can retain the old and new strings.
        self.fetch_reserve(scratch, size.saturating_mul(3))?;
        let mut normalized: Vec<(String, String)> = Vec::with_capacity(fields.len());
        for (mut name, mut value) in fields {
            self.fetch_charge_bytes(name.len().saturating_add(value.len()))?;
            normalize_header_pair(&mut name, &mut value)?;
            if name != "set-cookie" {
                // Combining is a linear search; charge every possible string
                // comparison before it runs, including long common prefixes.
                for (existing, _) in &normalized {
                    self.fetch_charge_bytes(name.len().min(existing.len()))?;
                }
            }
            append_header_field(&mut normalized, name, value);
        }
        Ok(normalized)
    }

    pub(in crate::baseline_interpreter) fn construct_fetch_headers(
        &mut self,
        module: &Ir3Module,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let input = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
        let label = self.join_arg_range_label(args)?;
        self.scoped_conversion(|core| {
            core.json_observe_label(label)?;
            let mut scratch = 0;
            let result = (|| {
                let fields = core.fetch_convert_headers_init(module, input, &mut scratch)?;
                let fields = core.fetch_fill_header_fields(fields, &mut scratch)?;
                let prototype = core.ensure_builtin_prototype("Headers")?;
                let id = core.alloc_object_with_prototype(Some(prototype))?;
                core.set_host_slots(
                    id,
                    HostObjectSlots::FetchHeaders(FetchHeadersSlots {
                        fields,
                        immutable: false,
                    }),
                )?;
                let label = core.json_parse_context_label()?;
                core.join_object_mutation_label(id, &label)?;
                core.join_into_pending_hostcall_result_label(Some(label))?;
                Ok(Value::Object(id))
            })();
            let result = core.finish_fetch_object_result(result);
            core.json_release_temporary(scratch);
            result
        })
    }

    fn fetch_headers_receiver(&self, receiver: &Value) -> Result<ObjectId, InterpreterError> {
        match receiver {
            Value::Object(id)
                if self
                    .heap
                    .get(id.0 as usize)
                    .and_then(HeapObject::fetch_headers_slots)
                    .is_some() =>
            {
                Ok(*id)
            }
            _ => Err(fetch_type_error("a Headers receiver")),
        }
    }

    pub(in crate::baseline_interpreter) fn dispatch_public_fetch_headers_method(
        &mut self,
        module: &Ir3Module,
        builtin: &BuiltinFunction,
        args: RegRange,
        receiver: Option<Value>,
        receiver_register: Option<u32>,
    ) -> Result<Value, InterpreterError> {
        let method = builtin.display_name();
        let receiver = receiver.unwrap_or(Value::Undefined);
        let id = self.fetch_headers_receiver(&receiver)?;
        let required = match method {
            "append" | "set" => 2,
            "get" | "has" | "delete" | "forEach" => 1,
            _ => 0,
        };
        if args.count < required {
            return Err(fetch_type_error("the required Headers method arguments"));
        }
        if matches!(method, "get" | "has" | "getSetCookie") {
            return self.dispatch_fetch_headers_method(
                module,
                builtin,
                args,
                Some(receiver),
                receiver_register,
            );
        }
        let label = self.fetch_receiver_label(id, args, receiver_register)?;
        self.scoped_conversion(|core| {
            core.json_observe_label(label)?;
            let result = (|| match method {
                "entries" | "keys" | "values" => {
                    let kind = match method {
                        "keys" => RuntimeTypedArrayIteratorKind::Keys,
                        "values" => RuntimeTypedArrayIteratorKind::Values,
                        _ => RuntimeTypedArrayIteratorKind::Entries,
                    };
                    let prototype = core.ensure_builtin_prototype("Headers Iterator")?;
                    let iterator = core.alloc_object_with_prototype(Some(prototype))?;
                    core.set_host_slots(
                        iterator,
                        HostObjectSlots::FetchHeadersIterator(FetchHeadersIteratorSlots {
                            headers: id,
                            next_index: 0,
                            kind,
                        }),
                    )?;
                    let label = core.json_parse_context_label()?;
                    core.join_object_mutation_label(iterator, &label)?;
                    core.join_into_pending_hostcall_result_label(Some(label))?;
                    Ok(Value::Object(iterator))
                }
                "forEach" => core.fetch_headers_for_each(module, id, args),
                "append" | "set" | "delete" => core.mutate_fetch_headers(module, id, method, args),
                _ => Err(fetch_type_error("a known Headers method")),
            })();
            core.finish_fetch_object_result(result)
        })
    }

    fn mutate_fetch_headers(
        &mut self,
        module: &Ir3Module,
        id: ObjectId,
        method: &str,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let mut scratch = 0;
        let result = (|| {
            let name = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
            let mut name = self.fetch_object_byte_string(module, name, &mut scratch)?;
            let mut value = if method == "delete" {
                String::new()
            } else {
                let value = self.builtin_arg(args, 1)?.unwrap_or(Value::Undefined);
                self.fetch_object_byte_string(module, value, &mut scratch)?
            };
            normalize_header_pair(&mut name, &mut value)?;
            let slots = self.heap[id.0 as usize]
                .fetch_headers_slots()
                .expect("checked receiver");
            if slots.immutable {
                return Err(fetch_type_error("mutable Headers"));
            }
            let retained = Self::estimate_host_object_slots_bytes(
                self.heap[id.0 as usize]
                    .host_slots
                    .as_deref()
                    .expect("header slots"),
            );
            self.fetch_reserve(
                &mut scratch,
                retained
                    .saturating_add(name.len() as u64)
                    .saturating_add(value.len() as u64)
                    .saturating_add(128)
                    .saturating_mul(3),
            )?;
            self.fetch_charge_bytes(usize::try_from(retained).unwrap_or(usize::MAX))?;
            let mut fields = self.heap[id.0 as usize]
                .fetch_headers_slots()
                .expect("checked receiver")
                .fields
                .clone();
            match method {
                "append" => append_header_field(&mut fields, name, value),
                "delete" => fields.retain(|(key, _)| *key != name),
                "set" => {
                    if let Some(first) = fields.iter().position(|(key, _)| *key == name) {
                        fields[first].1 = value;
                        let mut index = 0;
                        fields.retain(|(key, _)| {
                            let keep = *key != name || index == first;
                            index += 1;
                            keep
                        });
                    } else {
                        fields.push((name, value));
                    }
                }
                _ => unreachable!("closed Headers mutation table"),
            }
            let label = self.json_parse_context_label()?;
            self.join_object_mutation_label(id, &label)?;
            self.set_host_slots(
                id,
                HostObjectSlots::FetchHeaders(FetchHeadersSlots {
                    fields,
                    immutable: false,
                }),
            )?;
            self.join_into_pending_hostcall_result_label(Some(label))?;
            Ok(Value::Undefined)
        })();
        self.json_release_temporary(scratch);
        result
    }

    /// Project one row from the current sorted-and-combined list. Only the
    /// selected row is copied; no immutable iteration snapshot is retained.
    fn fetch_headers_row(
        &mut self,
        id: ObjectId,
        row: usize,
        scratch: &mut u64,
    ) -> Result<Option<(String, String)>, InterpreterError> {
        self.json_observe_reachable_value(&Value::Object(id))?;
        let fields = &self.heap[id.0 as usize]
            .fetch_headers_slots()
            .expect("checked headers")
            .fields;
        let count = fields.len();
        self.fetch_reserve(
            scratch,
            (count as u64).saturating_mul(2 * std::mem::size_of::<usize>() as u64),
        )?;
        // Sorting and scanning is bounded even for adversarial header counts.
        let rounds = usize::BITS - count.max(1).leading_zeros();
        let comparisons = count.saturating_mul(rounds as usize);
        let maximum_name_bytes = self.heap[id.0 as usize]
            .fetch_headers_slots()
            .expect("checked headers")
            .fields
            .iter()
            .map(|(name, _)| name.len())
            .max()
            .unwrap_or(0);
        for _ in 0..comparisons {
            self.fetch_charge_bytes(maximum_name_bytes)?;
        }
        let fields = &self.heap[id.0 as usize]
            .fetch_headers_slots()
            .expect("checked headers")
            .fields;
        let mut order: Vec<usize> = (0..count).collect();
        order.sort_by(|left, right| fields[*left].0.cmp(&fields[*right].0));
        let mut start = 0;
        let mut current = 0;
        while start < order.len() {
            let name = &fields[order[start]].0;
            let mut end = start + 1;
            if name != "set-cookie" {
                while end < order.len() && fields[order[end]].0 == *name {
                    end += 1;
                }
            }
            if current == row {
                let bytes =
                    order[start..end]
                        .iter()
                        .fold(name.len().saturating_add(2), |total, index| {
                            total
                                .saturating_add(fields[*index].1.len())
                                .saturating_add(2)
                        });
                self.fetch_reserve(
                    scratch,
                    (bytes as u64).saturating_mul(3).saturating_add(128),
                )?;
                self.fetch_charge_bytes(bytes)?;
                let fields = &self.heap[id.0 as usize]
                    .fetch_headers_slots()
                    .expect("checked headers")
                    .fields;
                let name = fields[order[start]].0.clone();
                let mut value = String::new();
                for (offset, index) in order[start..end].iter().enumerate() {
                    if offset != 0 {
                        // Empty header values still contribute a separator.
                        value.push_str(", ");
                    }
                    value.push_str(&fields[*index].1);
                }
                self.check_string_limit(name.encode_utf16().count())?;
                self.check_string_limit(value.encode_utf16().count())?;
                return Ok(Some((name, value)));
            }
            current += 1;
            start = end;
        }
        Ok(None)
    }

    pub(in crate::baseline_interpreter) fn dispatch_fetch_headers_iterator_next(
        &mut self,
        args: RegRange,
        receiver: Option<Value>,
        receiver_register: Option<u32>,
    ) -> Result<Value, InterpreterError> {
        let Some(Value::Object(id)) = receiver else {
            return Err(fetch_type_error("a Headers Iterator receiver"));
        };
        let slots = match self
            .heap
            .get(id.0 as usize)
            .and_then(|object| object.host_slots.as_deref())
        {
            Some(HostObjectSlots::FetchHeadersIterator(slots)) => slots.clone(),
            _ => return Err(fetch_type_error("a Headers Iterator receiver")),
        };
        let label = self.fetch_receiver_label(id, args, receiver_register)?;
        self.scoped_conversion(|core| {
            core.json_observe_label(label)?;
            let mut scratch = 0;
            let result = (|| {
                let row = core.fetch_headers_row(slots.headers, slots.next_index, &mut scratch)?;
                let label = core.json_parse_context_label()?;
                let value = match row {
                    Some((name, value)) => {
                        let value = match slots.kind {
                            RuntimeTypedArrayIteratorKind::Keys => Value::str(name),
                            RuntimeTypedArrayIteratorKind::Values => Value::str(value),
                            RuntimeTypedArrayIteratorKind::Entries => {
                                let pair = core.alloc_array_from_values(&[
                                    Value::str(name),
                                    Value::str(value),
                                ])?;
                                core.join_object_mutation_label(pair, &label)?;
                                Value::Object(pair)
                            }
                        };
                        core.join_object_mutation_label(id, &label)?;
                        core.mutate_heap(|heap| {
                            if let Some(HostObjectSlots::FetchHeadersIterator(state)) =
                                heap[id.0 as usize].host_slots.as_deref_mut()
                            {
                                state.next_index = state.next_index.saturating_add(1);
                            }
                        });
                        Some(value)
                    }
                    None => None,
                };
                // Web IDL does not latch exhaustion: a later mutation can add
                // another current-list row at this same cursor. The GC-traced
                // iterator owns the source until the iterator itself dies.
                let result = core.alloc_iterator_result_object(value)?;
                if let Value::Object(result) = &result {
                    core.join_object_mutation_label(*result, &label)?;
                }
                core.join_into_pending_hostcall_result_label(Some(label))?;
                Ok(result)
            })();
            let result = core.finish_fetch_object_result(result);
            core.json_release_temporary(scratch);
            result
        })
    }

    fn fetch_headers_for_each(
        &mut self,
        module: &Ir3Module,
        id: ObjectId,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let callback = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
        if !callback.is_callable() {
            return Err(fetch_type_error("a callable Headers.forEach callback"));
        }
        let this_arg = self.builtin_arg(args, 1)?.unwrap_or(Value::Undefined);
        let receiver = Value::Object(id);
        let mut index = 0usize;
        loop {
            let mut scratch = 0;
            let result = (|| {
                let Some((name, value)) = self.fetch_headers_row(id, index, &mut scratch)? else {
                    return Ok(false);
                };
                let label = self.json_parse_context_label()?;
                self.preflight_inline_method_call_with_argument_label(
                    Some(module),
                    &callback,
                    3,
                    Some(&label),
                )?;
                let (_, callback_label) =
                    self.with_gc_nested_request(vec![receiver.clone()], |core| {
                        core.invoke_inline_method_call_with_argument_label_preflighted(
                            Some(module),
                            callback.clone(),
                            this_arg.clone(),
                            vec![Value::str(value), Value::str(name), receiver.clone()],
                            Some(label),
                        )
                    })?;
                self.json_observe_label(callback_label)?;
                self.observe_scoped_callback_result()?;
                self.json_observe_reachable_value(&receiver)?;
                Ok(true)
            })();
            self.json_release_temporary(scratch);
            if !result? {
                break;
            }
            index = index.saturating_add(1);
        }
        let label = self.json_parse_context_label()?;
        self.join_into_pending_hostcall_result_label(Some(label))?;
        Ok(Value::Undefined)
    }
}

impl InterpreterCore {
    fn fetch_response_init(
        &mut self,
        module: &Ir3Module,
        init: Value,
        scratch: &mut u64,
    ) -> Result<ResponseInit, InterpreterError> {
        if !matches!(init, Value::Undefined | Value::Null) && !init.is_object_like() {
            return Err(fetch_type_error("a Response init dictionary"));
        }
        self.json_observe_reachable_value(&init)?;
        let pins = self.gc_pin_network_values([init.clone()]);
        let result = (|| {
            // Web IDL dictionary members convert immediately after Get, in
            // lexicographic order. Header filling is a later operation.
            let headers = self.fetch_property(Some(module), &init, "headers")?;
            let fields = self.fetch_convert_headers_init(module, headers, scratch)?;
            let status = self.fetch_property(Some(module), &init, "status")?;
            let status = if matches!(status, Value::Undefined) {
                200
            } else {
                let mut observed = None;
                let number =
                    self.builtin_argument_to_number(Some(module), status, &mut observed)?;
                if let Some(observed) = observed {
                    self.json_observe_label(observed)?;
                }
                response_status(number)
            };
            let status_text = self.fetch_property(Some(module), &init, "statusText")?;
            let status_text = if matches!(status_text, Value::Undefined) {
                String::new()
            } else {
                self.fetch_object_byte_string(module, status_text, scratch)?
            };
            Ok(ResponseInit {
                fields,
                status,
                status_text,
            })
        })();
        self.gc_unpin_network_values(pins);
        result
    }

    fn finish_constructed_fetch_response(
        &mut self,
        init: ResponseInit,
        body: Option<Vec<u8>>,
        content_type: Option<String>,
        scratch: &mut u64,
    ) -> Result<Value, InterpreterError> {
        if !(200..=599).contains(&init.status) {
            return Err(self.throw_js_error(
                "RangeError",
                "Response status must be between 200 and 599".to_string(),
            ));
        }
        if !valid_status_text(&init.status_text) {
            return Err(fetch_type_error("a valid HTTP status message"));
        }
        let mut fields = self.fetch_fill_header_fields(init.fields, scratch)?;
        if body.is_some() && matches!(init.status, 204 | 205 | 304) {
            return Err(fetch_type_error(
                "a null body for a null-body response status",
            ));
        }
        if let Some(content_type) = content_type
            && !fields.iter().any(|(name, _)| name == "content-type")
        {
            self.fetch_stage_header_pair(
                &mut fields,
                "content-type".to_string(),
                content_type,
                scratch,
            )?;
        }
        let label = self.json_parse_context_label()?;
        let id = self.alloc_fetch_response(
            FetchResponseSlots {
                status: init.status,
                status_text: init.status_text,
                url: String::new(),
                headers: ObjectId(0),
                body,
                body_used: false,
                redirected: false,
                response_type: "default".to_string(),
            },
            fields,
            false,
            &label,
        )?;
        self.join_into_pending_hostcall_result_label(Some(label))?;
        Ok(Value::Object(id))
    }

    pub(in crate::baseline_interpreter) fn construct_fetch_response(
        &mut self,
        module: &Ir3Module,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let body = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
        let init = self.builtin_arg(args, 1)?.unwrap_or(Value::Undefined);
        let label = self.join_arg_range_label(args)?;
        self.scoped_conversion(|core| {
            core.json_observe_label(label)?;
            let pins = core.gc_pin_network_values([body.clone(), init.clone()]);
            let mut scratch = 0;
            let result = (|| {
                let body = core.normalize_fetch_body(Some(module), body, &mut scratch)?;
                core.gc_pin_network_values([body.clone()]);
                let init = core.fetch_response_init(module, init, &mut scratch)?;
                // Extract native buffer/Blob/URLSearchParams data after init
                // conversion, just as Request does. Getter mutations are real.
                let (body, content_type) =
                    core.fetch_request_body(Some(module), body, &mut scratch)?;
                core.finish_constructed_fetch_response(init, body, content_type, &mut scratch)
            })();
            let result = core.finish_fetch_object_result(result);
            core.json_release_temporary(scratch);
            core.gc_unpin_network_values(pins);
            result
        })
    }

    pub(in crate::baseline_interpreter) fn dispatch_fetch_response_static(
        &mut self,
        module: &Ir3Module,
        builtin: &BuiltinFunction,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let method = builtin.display_name();
        if matches!(method, "json" | "redirect") && args.count == 0 {
            return Err(fetch_type_error("the required Response factory argument"));
        }
        let label = self.join_arg_range_label(args)?;
        self.scoped_conversion(|core| {
            core.json_observe_label(label)?;
            let mut scratch = 0;
            let pins = core.gc_pin_network_values(std::iter::empty::<Value>());
            let result = (|| {
                match method {
                    "json" => {
                        let data = core.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
                        let init = core.builtin_arg(args, 1)?.unwrap_or(Value::Undefined);
                        core.gc_pin_network_values([data.clone(), init.clone()]);
                        // Dictionary conversion precedes the factory algorithm
                        // (including toJSON/getters on data).
                        let init = core.fetch_response_init(module, init, &mut scratch)?;
                        core.json_observe_reachable_value(&data)?;
                        let serialized = core.json_stringify_document(
                            Some(module),
                            data,
                            Value::Undefined,
                            Value::Undefined,
                        )?;
                        let Value::Str(text) = serialized else {
                            return Err(fetch_type_error("a JSON-serializable Response value"));
                        };
                        core.fetch_reserve(
                            &mut scratch,
                            (text.len() as u64).saturating_mul(2).saturating_add(128),
                        )?;
                        core.fetch_charge_bytes(text.len())?;
                        let bytes = text.as_utf8_projection().as_bytes().to_vec();
                        core.finish_constructed_fetch_response(
                            init,
                            Some(bytes),
                            Some("application/json".to_string()),
                            &mut scratch,
                        )
                    }
                    "error" | "redirect" => {
                        let mut status = 0;
                        let mut fields = Vec::new();
                        let response_type = if method == "error" {
                            "error"
                        } else {
                            "default"
                        };
                        if method == "redirect" {
                            let input = core.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
                            let url = core.fetch_string(Some(module), input, &mut scratch)?;
                            let status_value =
                                core.builtin_arg(args, 1)?.unwrap_or(Value::Undefined);
                            status = if matches!(status_value, Value::Undefined) {
                                302
                            } else {
                                let mut observed = None;
                                let number = core.builtin_argument_to_number(
                                    Some(module),
                                    status_value,
                                    &mut observed,
                                )?;
                                if let Some(observed) = observed {
                                    core.json_observe_label(observed)?;
                                }
                                response_status(number)
                            };
                            core.fetch_reserve(
                                &mut scratch,
                                (url.len() as u64).saturating_mul(6).saturating_add(1024),
                            )?;
                            let url = Url::parse(&url)
                                .map_err(|_| fetch_type_error("an absolute redirect URL"))?;
                            if !matches!(status, 301 | 302 | 303 | 307 | 308) {
                                return Err(core.throw_js_error(
                                    "RangeError",
                                    "Response.redirect status must be a redirect status"
                                        .to_string(),
                                ));
                            }
                            core.fetch_stage_header_pair(
                                &mut fields,
                                "location".to_string(),
                                url.to_string(),
                                &mut scratch,
                            )?;
                        }
                        let label = core.json_parse_context_label()?;
                        let id = core.alloc_fetch_response(
                            FetchResponseSlots {
                                status,
                                status_text: String::new(),
                                url: String::new(),
                                headers: ObjectId(0),
                                body: None,
                                body_used: false,
                                redirected: false,
                                response_type: response_type.to_string(),
                            },
                            fields,
                            true,
                            &label,
                        )?;
                        core.join_into_pending_hostcall_result_label(Some(label))?;
                        Ok(Value::Object(id))
                    }
                    _ => Err(fetch_type_error("a known Response factory")),
                }
            })();
            let result = core.finish_fetch_object_result(result);
            core.json_release_temporary(scratch);
            core.gc_unpin_network_values(pins);
            result
        })
    }

    pub(in crate::baseline_interpreter) fn install_public_fetch_prototype_members(
        &mut self,
        owner: &str,
        prototype: ObjectId,
    ) -> Result<(), InterpreterError> {
        if matches!(owner, "Headers" | "Response" | "Request") {
            let name = match owner {
                "Headers" => "Headers",
                "Request" => "Request",
                _ => "Response",
            };
            self.install_prototype_constructor(
                prototype,
                Value::BuiltinFunction(BuiltinFunction::standard_constructor(name)),
            )?;
        }
        let getters: &[&str] = match owner {
            "Response" => &[
                "type",
                "url",
                "redirected",
                "status",
                "ok",
                "statusText",
                "headers",
                "bodyUsed",
            ],
            "Request" => &[
                "url",
                "method",
                "headers",
                "bodyUsed",
                "redirect",
                "signal",
                "destination",
                "referrer",
                "referrerPolicy",
                "mode",
                "credentials",
                "cache",
                "integrity",
                "keepalive",
                "duplex",
            ],
            _ => &[],
        };
        for &name in getters {
            let key = RuntimePropertyKey::String(JsString::from(name));
            self.define_accessor_property(
                prototype,
                key.clone(),
                Value::BuiltinFunction(BuiltinFunction::prototype_getter(owner, name)),
                AccessorKind::Get,
            )?;
            self.set_own_property_attributes(
                prototype,
                &key,
                PropertyAttributes {
                    writable: false,
                    enumerable: true,
                    configurable: true,
                },
            )?;
        }
        if owner == "Headers" {
            let key = RuntimePropertyKey::Symbol(WellKnownSymbol::Iterator.id());
            self.set_object_runtime_property(
                prototype,
                key.clone(),
                Value::BuiltinFunction(
                    BuiltinFunction::fetch_headers_method("entries")
                        .expect("Headers entries method"),
                ),
            )?;
            self.set_own_property_attributes(prototype, &key, NON_ENUMERABLE_DATA_ATTRIBUTES)?;
        } else if owner == "Headers Iterator" {
            let key = RuntimePropertyKey::String(JsString::from("next"));
            self.set_object_runtime_property(
                prototype,
                key.clone(),
                Value::BuiltinFunction(BuiltinFunction::new_kind(
                    BuiltinFunctionKind::FetchHeadersIteratorNext,
                )),
            )?;
            self.set_own_property_attributes(
                prototype,
                &key,
                PropertyAttributes {
                    writable: true,
                    enumerable: true,
                    configurable: true,
                },
            )?;
            let tag = RuntimePropertyKey::Symbol(WellKnownSymbol::ToStringTag.id());
            self.set_object_runtime_property(
                prototype,
                tag.clone(),
                Value::str("Headers Iterator"),
            )?;
            self.set_own_property_attributes(
                prototype,
                &tag,
                PropertyAttributes {
                    writable: false,
                    enumerable: false,
                    configurable: true,
                },
            )?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_normalization_preserves_cookie_semantics_and_latin1() {
        let mut fields = Vec::new();
        for (name, value) in [
            ("X-Test", " one\t"),
            ("x-test", "two"),
            ("Set-Cookie", "a=1"),
            ("set-cookie", "b=2"),
            ("Cookie", "a=1"),
            ("cookie", "b=2"),
            ("x-latin", "\u{e9}"),
        ] {
            let mut name = name.to_string();
            let mut value = value.to_string();
            normalize_header_pair(&mut name, &mut value).unwrap();
            append_header_field(&mut fields, name, value);
        }
        assert_eq!(
            fields,
            vec![
                ("x-test".to_string(), "one, two".to_string()),
                ("set-cookie".to_string(), "a=1".to_string()),
                ("set-cookie".to_string(), "b=2".to_string()),
                ("cookie".to_string(), "a=1; b=2".to_string()),
                ("x-latin".to_string(), "\u{e9}".to_string()),
            ]
        );
        for (name, value) in [("", "a"), ("x y", "a"), ("x", "a\r\nb"), ("x", "\0")] {
            assert!(normalize_header_pair(&mut name.to_string(), &mut value.to_string()).is_err());
        }
    }

    #[test]
    fn response_status_uses_webidl_unsigned_short_before_semantic_range_checks() {
        assert_eq!(response_status(65737.0), 201);
        assert_eq!(response_status(-65335.0), 201);
        assert_eq!(response_status(200.9), 200);
        assert_eq!(response_status(f64::NAN), 0);
        assert_eq!(response_status(f64::INFINITY), 0);
        assert!(valid_status_text("OK\t\u{e9}"));
        for text in ["\0", "\n", "\r", "\u{7f}", "\u{100}"] {
            assert!(!valid_status_text(text));
        }
    }

    fn core() -> InterpreterCore {
        let mut config = InterpreterConfig::quickjs_defaults();
        config.granted_capabilities = [
            RuntimeCapability::VmDispatch,
            RuntimeCapability::HeapAllocate,
            RuntimeCapability::Builtin,
        ]
        .into_iter()
        .collect();
        InterpreterCore::new(config, "fetch-objects-private")
    }

    fn module() -> Ir3Module {
        use crate::ast::ParseGoal;
        use crate::ir_contract::Ir0Module;
        use crate::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
        use crate::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};
        let tree = CanonicalEs2020Parser
            .parse_with_options(
                ParserSource {
                    label: "fetch-objects-private.js".into(),
                    text: "0;".into(),
                },
                ParseGoal::Script,
                &ParserOptions::default(),
            )
            .unwrap();
        lower_ir0_to_ir3(
            &Ir0Module::from_syntax_tree(tree, "fetch-objects-private.js"),
            &LoweringContext::new("fetch-objects-private", "decision", "policy"),
        )
        .unwrap()
        .ir3
    }

    fn assert_balanced(core: &InterpreterCore) {
        assert_eq!(core.json_parse_temporary_bytes, 0);
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }

    #[test]
    fn constructed_response_preserves_input_labels_without_network_authority() {
        let mut core = core();
        core.seed_register(0, Value::str("private payload"))
            .unwrap();
        core.set_register_label(0, Label::Secret).unwrap();
        let Value::Object(response) = core
            .construct_fetch_response(&module(), RegRange { start: 0, count: 1 })
            .unwrap()
        else {
            panic!("Response instance");
        };
        let slots = core.heap[response.0 as usize]
            .fetch_response_slots()
            .unwrap();
        assert_eq!(slots.response_type, "default");
        let headers = slots.headers;
        assert!(
            !core.heap[headers.0 as usize]
                .fetch_headers_slots()
                .unwrap()
                .immutable
        );
        assert_eq!(
            core.object_mutation_labels.get(&response),
            Some(&Label::Secret)
        );
        assert_eq!(
            core.object_mutation_labels.get(&headers),
            Some(&Label::Secret)
        );
        let clone = core.clone_fetch_response(response, &Label::Secret).unwrap();
        assert_eq!(
            core.consume_fetch_body(response, "text", &Label::Secret)
                .unwrap(),
            Value::str("private payload"),
        );
        assert_eq!(
            core.fetch_response_getter(response, "bodyUsed").unwrap(),
            Value::Bool(true)
        );
        assert_eq!(
            core.fetch_response_getter(clone, "bodyUsed").unwrap(),
            Value::Bool(false)
        );
        assert_balanced(&core);
    }

    #[test]
    fn iterator_hidden_source_is_traced_labeled_and_restorable() {
        let mut core = core();
        let prototype = core.ensure_builtin_prototype("Headers").unwrap();
        let headers = core.alloc_object_with_prototype(Some(prototype)).unwrap();
        core.set_host_slots(
            headers,
            HostObjectSlots::FetchHeaders(FetchHeadersSlots {
                fields: vec![("x-secret".into(), "retained".into())],
                immutable: false,
            }),
        )
        .unwrap();
        let prototype = core.ensure_builtin_prototype("Headers Iterator").unwrap();
        let iterator = core.alloc_object_with_prototype(Some(prototype)).unwrap();
        core.set_host_slots(
            iterator,
            HostObjectSlots::FetchHeadersIterator(FetchHeadersIteratorSlots {
                headers,
                next_index: 0,
                kind: RuntimeTypedArrayIteratorKind::Entries,
            }),
        )
        .unwrap();
        core.seed_register(0, Value::Object(iterator)).unwrap();
        core.set_register_label(0, Label::Internal).unwrap();
        core.join_object_mutation_label(headers, &Label::Secret)
            .unwrap();
        assert_eq!(
            core.process_dynamic_value_label_ref(&Value::Object(iterator), &mut BTreeSet::new()),
            Some(&Label::Secret),
        );
        let sources = core.capture_heap_label_sources();
        assert_eq!(sources[headers.0 as usize], Some(0));
        let seed = core.capture_execution_seed().unwrap();
        core.gc_safe_point();
        assert_eq!(
            core.heap[headers.0 as usize]
                .fetch_headers_slots()
                .unwrap()
                .fields[0]
                .1,
            "retained",
        );
        let result = core
            .dispatch_fetch_headers_iterator_next(
                RegRange { start: 1, count: 0 },
                Some(Value::Object(iterator)),
                Some(0),
            )
            .unwrap();
        let Value::Object(result) = result else {
            panic!("iterator result");
        };
        assert_eq!(
            core.object_mutation_labels.get(&result),
            Some(&Label::Secret)
        );
        let Some(HostObjectSlots::FetchHeadersIterator(slots)) =
            core.heap[iterator.0 as usize].host_slots.as_deref()
        else {
            panic!("iterator slots");
        };
        assert_eq!(slots.next_index, 1);
        core.reset_execution_state_from_seed(&seed).unwrap();
        let Some(HostObjectSlots::FetchHeadersIterator(slots)) =
            core.heap[iterator.0 as usize].host_slots.as_deref()
        else {
            panic!("restored iterator slots");
        };
        assert_eq!(slots.next_index, 0);
        drop(seed);
        assert_balanced(&core);
    }

    #[test]
    fn refused_header_mutation_retains_fields_and_balances_memory() {
        for memory_limited in [true, false] {
            let mut core = core();
            let prototype = core.ensure_builtin_prototype("Headers").unwrap();
            let headers = core.alloc_object_with_prototype(Some(prototype)).unwrap();
            let fields = vec![("x-old".to_string(), "x".repeat(8192))];
            core.set_host_slots(
                headers,
                HostObjectSlots::FetchHeaders(FetchHeadersSlots {
                    fields: fields.clone(),
                    immutable: false,
                }),
            )
            .unwrap();
            core.seed_register(0, Value::str("x-new")).unwrap();
            core.seed_register(1, Value::str("replacement")).unwrap();
            core.seed_register(2, Value::Object(headers)).unwrap();
            if memory_limited {
                core.config.max_total_memory_bytes = core.estimated_memory_bytes() + 512;
            } else {
                core.config.instruction_budget = core.instructions_executed + 4;
            }
            let outcome = core.dispatch_public_fetch_headers_method(
                &module(),
                &BuiltinFunction::fetch_headers_method("set").unwrap(),
                RegRange { start: 0, count: 2 },
                Some(Value::Object(headers)),
                Some(2),
            );
            if memory_limited {
                assert!(
                    matches!(outcome, Err(InterpreterError::MemoryBudgetExceeded { .. })),
                    "{outcome:?}"
                );
            } else {
                assert!(
                    matches!(outcome, Err(InterpreterError::BudgetExhausted { .. })),
                    "{outcome:?}"
                );
            }
            assert_eq!(
                core.heap[headers.0 as usize]
                    .fetch_headers_slots()
                    .unwrap()
                    .fields,
                fields
            );
            assert_balanced(&core);
        }
    }

    #[test]
    fn response_clone_preserves_later_header_mutation_provenance() {
        let mut core = core();
        let response = core
            .alloc_fetch_response(
                FetchResponseSlots {
                    status: 200,
                    status_text: String::new(),
                    url: String::new(),
                    headers: ObjectId(0),
                    body: None,
                    body_used: false,
                    redirected: false,
                    response_type: "default".to_string(),
                },
                vec![("x-private".to_string(), "classified header".to_string())],
                false,
                &Label::Public,
            )
            .unwrap();
        let headers = core.heap[response.0 as usize]
            .fetch_response_slots()
            .unwrap()
            .headers;
        core.join_object_mutation_label(headers, &Label::Secret)
            .unwrap();
        core.take_pending_hostcall_result_label();
        let copy = core
            .dispatch_fetch_response_method(
                &module(),
                &BuiltinFunction::fetch_response_method("clone").unwrap(),
                RegRange { start: 0, count: 0 },
                Some(Value::Object(response)),
                None,
            )
            .unwrap();
        let Value::Object(copy) = copy else {
            panic!("native Response clone")
        };
        let copied_headers = core.heap[copy.0 as usize]
            .fetch_response_slots()
            .unwrap()
            .headers;
        assert_ne!(headers, copied_headers);
        assert_eq!(core.object_mutation_labels.get(&copy), Some(&Label::Secret));
        assert_eq!(
            core.object_mutation_labels.get(&copied_headers),
            Some(&Label::Secret)
        );
        assert_eq!(
            core.heap[copied_headers.0 as usize]
                .fetch_headers_slots()
                .unwrap()
                .fields,
            [("x-private".to_string(), "classified header".to_string())],
        );
        assert_balanced(&core);
    }

    #[test]
    fn response_clone_refusal_preserves_private_body_state() {
        let mut core = core();
        let response = core
            .alloc_fetch_response(
                FetchResponseSlots {
                    status: 200,
                    status_text: String::new(),
                    url: String::new(),
                    headers: ObjectId(0),
                    body: Some(Vec::new()),
                    body_used: true,
                    redirected: false,
                    response_type: "default".to_string(),
                },
                Vec::new(),
                false,
                &Label::Secret,
            )
            .unwrap();
        let result = core.dispatch_fetch_response_method(
            &module(),
            &BuiltinFunction::fetch_response_method("clone").unwrap(),
            RegRange { start: 0, count: 0 },
            Some(Value::Object(response)),
            None,
        );
        assert!(
            matches!(result, Err(InterpreterError::UncaughtException { .. })),
            "{result:?}"
        );
        assert_eq!(core.pending_exception_label, Label::Secret);
        assert_eq!(core.json_parse_context_label().unwrap(), Label::Public);
        assert!(
            core.heap[response.0 as usize]
                .fetch_response_slots()
                .unwrap()
                .body_used
        );
        assert_balanced(&core);
    }

    #[test]
    fn response_json_errors_preserve_observed_provenance_and_scope_ownership() {
        for nested in [false, true] {
            let mut core = core();
            let data = core
                .alloc_object_with_properties(&[("payload", Value::BigInt("1".into()))])
                .unwrap();
            let observed = Label::Custom {
                name: "response-private-property".repeat(8),
                level: 9,
            };
            core.set_own_property_label(data, "payload", &observed)
                .unwrap();
            core.active_inline_callback_context_label = nested.then_some(Label::Custom {
                name: "response-caller".repeat(8),
                level: 7,
            });
            core.sync_estimated_memory_bytes().unwrap();
            core.seed_register(0, Value::Object(data)).unwrap();
            let factory = BuiltinFunction {
                kind: BuiltinFunctionKind::FetchResponseStatic,
                module_specifier: BuiltinModuleSpecifier::from_nonempty("json"),
                iterator_handle: None,
                bound_object: None,
            };
            let result = core.dispatch_fetch_response_static(
                &module(),
                &factory,
                RegRange { start: 0, count: 1 },
            );
            assert!(
                matches!(result, Err(InterpreterError::UncaughtException { .. })),
                "{result:?}"
            );
            let Some(Value::Object(error)) = core.pending_exception.as_ref() else {
                panic!("native JSON failure materializes a guest error");
            };
            assert_eq!(
                core.chain_data_property(*error, "name"),
                Some(&Value::str("TypeError"))
            );
            assert_eq!(core.pending_exception_label, observed);
            // A top-level operation owns and restores its observation scope.
            // A nested operation contributes observations to its caller's scope.
            assert_eq!(
                core.active_inline_callback_context_label,
                nested.then_some(observed.clone()),
            );
            assert_eq!(
                core.heap[data.0 as usize].properties.get("payload"),
                Some(&Value::BigInt("1".into()))
            );
            assert_balanced(&core);
        }
    }
}
