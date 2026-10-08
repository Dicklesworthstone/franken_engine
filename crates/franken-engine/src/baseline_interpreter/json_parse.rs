//! Native JSON.parse: coercion, transactional parsing, and reviver execution.
//!
//! The UTF-16 token parser lives in the parent module. No guest callback runs
//! while its unpublished heap suffix is transactional: input coercion happens
//! before the checkpoint, and revivers run only after the complete text parses.

use super::*;

/// Which edges a reachable-label walk follows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReachableEdges {
    /// Data properties reached through `properties.values()`: what JSON
    /// serialization and the other data consumers read.
    Data,
    /// Everything `util.inspect` can print (console sinks).
    Inspect,
}

/// A JSON Parse Record (JSON.parse source text access, bd-9vouw.380): the
/// value one parse node produced, a primitive's source text, and the
/// records of an array's elements or an object's entries, each taken once
/// as the reviver walk reaches it.
struct JsonParseRecord {
    value: Value,
    source: Option<JsString>,
    elements: Vec<Option<JsonParseRecord>>,
    entries: Vec<(JsString, Option<JsonParseRecord>)>,
}

impl InterpreterCore {
    pub(super) fn json_parse_builtin(
        &mut self,
        module: Option<&Ir3Module>,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let input = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
        let reviver = self.builtin_arg(args, 1)?.unwrap_or(Value::Undefined);
        let context = self.join_arg_range_label(args)?;
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
        let mut outcome = (|| {
            for value in [&input, &reviver] {
                self.json_observe_reachable_value(value)?;
            }
            self.json_parse_builtin_inner(module, input, reviver)
        })();
        // Coercion and reviver traversal can fail with native TypeErrors as
        // well as guest throws. Materialize language errors before removing
        // the observation context; resource refusals must remain host faults.
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
        // A reviver sees each unmodified primitive's source text (JSON.parse
        // source text access, bd-9vouw.380): record the parse tree before
        // any guest code runs.
        let mut record_bytes = 0;
        let record = match &outcome {
            Ok(value) if reviver.is_callable() => {
                Some(self.json_parse_record(&units, &mut 0, value.clone(), &mut record_bytes))
            }
            _ => None,
        };
        drop(units);
        self.json_release_temporary(unit_bytes);
        let outcome = (|| {
            let value = outcome?;
            let Some(record) = record else {
                return Ok(value);
            };
            let record = record?;
            let prototype = self.ensure_builtin_prototype("Object")?;
            let holder = self.alloc_object_with_prototype(Some(prototype))?;
            self.json_store_parsed_property(holder, JsString::from(""), value)?;
            // Parsing is committed before user code begins. A reviver can
            // retain a reference to the holder or any descendant and then
            // throw; none of its effects or escaped objects may be rolled back
            // as syntax scratch.
            self.json_internalize_property(
                module,
                holder,
                JsString::from(""),
                &reviver,
                0,
                Some(record),
            )
        })();
        self.json_release_temporary(record_bytes);
        outcome
    }

    /// The JSON Parse Record of the validated text at `pos`, whose parse
    /// produced `value`; a container's children are read back from the
    /// parsed objects before any reviver runs. Each record is charged to
    /// `charged` as it is built.
    fn json_parse_record(
        &mut self,
        units: &[u16],
        pos: &mut usize,
        value: Value,
        charged: &mut u64,
    ) -> Result<JsonParseRecord, InterpreterError> {
        self.json_charge_work()?;
        let bytes = std::mem::size_of::<JsonParseRecord>() as u64;
        self.json_reserve_temporary(bytes)?;
        *charged += bytes;
        Self::json_skip_ws(units, pos);
        let start = *pos;
        let mut record = JsonParseRecord {
            value,
            source: None,
            elements: Vec::new(),
            entries: Vec::new(),
        };
        match units.get(*pos) {
            Some(0x7B) => {
                *pos += 1;
                loop {
                    Self::json_skip_ws(units, pos);
                    if units.get(*pos) == Some(&0x7D) {
                        *pos += 1;
                        break;
                    }
                    let Some(key) = Self::json_parse_string(units, pos) else {
                        break;
                    };
                    Self::json_skip_ws(units, pos);
                    *pos += 1;
                    let child = self.json_parsed_child(&record.value, &key);
                    let child = self.json_parse_record(units, pos, child, charged)?;
                    // A repeated key keeps its last entry, the one the object
                    // holds.
                    if let Some(entry) = record
                        .entries
                        .iter_mut()
                        .find(|(existing, _)| *existing == key)
                    {
                        entry.1 = Some(child);
                    } else {
                        let bytes = Self::estimate_js_string_bytes(&key).saturating_add(
                            std::mem::size_of::<(JsString, JsonParseRecord)>() as u64,
                        );
                        self.json_reserve_temporary(bytes)?;
                        *charged += bytes;
                        record.entries.push((key, Some(child)));
                    }
                    Self::json_skip_ws(units, pos);
                    if units.get(*pos) == Some(&0x2C) {
                        *pos += 1;
                    }
                }
            }
            Some(0x5B) => {
                *pos += 1;
                loop {
                    Self::json_skip_ws(units, pos);
                    if *pos >= units.len() {
                        break;
                    }
                    if units.get(*pos) == Some(&0x5D) {
                        *pos += 1;
                        break;
                    }
                    let key = JsString::from(record.elements.len().to_string());
                    let child = self.json_parsed_child(&record.value, &key);
                    let child = self.json_parse_record(units, pos, child, charged)?;
                    record.elements.push(Some(child));
                    Self::json_skip_ws(units, pos);
                    if units.get(*pos) == Some(&0x2C) {
                        *pos += 1;
                    }
                }
            }
            first => {
                match first {
                    Some(0x22) => {
                        Self::json_parse_string(units, pos);
                    }
                    Some(0x2D | 0x30..=0x39) => {
                        Self::json_parse_number(units, pos);
                    }
                    Some(0x74 | 0x6E) => *pos += 4,
                    Some(0x66) => *pos += 5,
                    _ => *pos = units.len(),
                }
                let end = (*pos).min(units.len());
                let source = JsString::from_code_units(&units[start.min(end)..end]);
                let bytes = Self::estimate_js_string_bytes(&source);
                self.json_reserve_temporary(bytes)?;
                *charged += bytes;
                record.source = Some(source);
            }
        }
        Ok(record)
    }

    /// The parsed value of `key` in the parsed container `parent`.
    fn json_parsed_child(&self, parent: &Value, key: &JsString) -> Value {
        let Value::Object(id) = parent else {
            return Value::Undefined;
        };
        self.heap
            .get(id.0 as usize)
            .and_then(|object| {
                object.own_runtime_property_value(&RuntimePropertyKey::String(key.clone()))
            })
            .unwrap_or(Value::Undefined)
    }

    /// `JSON.rawJSON(text)` (JSON.parse source text access, in Node v22;
    /// bd-9vouw.380): a frozen null-prototype object whose only property,
    /// `rawJSON`, is ToString(text), and which JSON.stringify emits
    /// verbatim. The text must be one JSON number, string, boolean or null
    /// with no whitespace around it; anything else is a SyntaxError.
    pub(super) fn json_raw_json_builtin(
        &mut self,
        module: Option<&Ir3Module>,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        if matches!(self.builtin_arg(args, 0)?, Some(Value::Symbol(_))) {
            return Err(InterpreterError::TypeError {
                expected: "JSON text convertible to a String".to_string(),
                got: "Symbol".to_string(),
            });
        }
        let text = if args.count == 0 {
            JsString::from("undefined")
        } else {
            match self.primitive_conversion_builtin(module, args, PrimitiveConversion::String)? {
                Value::Str(text) => text,
                other => {
                    return Err(InterpreterError::TypeError {
                        expected: "string conversion result".to_string(),
                        got: other.type_name().to_string(),
                    });
                }
            }
        };
        self.check_string_limit(text.len())?;
        let units = text.code_units_vec();
        let padded =
            |unit: Option<&u16>| unit.is_none_or(|unit| matches!(unit, 0x09 | 0x0A | 0x0D | 0x20));
        if padded(units.first())
            || padded(units.last())
            || matches!(units.first(), Some(0x7B | 0x5B))
        {
            return self.json_syntax_error(0);
        }
        self.json_parse_document(&units)?;
        drop(units);
        let label = self.clone_dominant_label_with_temporary_budget(
            &self.join_arg_range_label(args)?,
            &self.json_parse_context_label()?,
            0,
        )?;
        let object = self.alloc_object_with_properties(&[("rawJSON", Value::Str(text))])?;
        self.store_prototype_link(object, None);
        self.set_object_brand(object, RAW_JSON_BRAND)?;
        self.mutate_heap(|heap| heap[object.0 as usize].is_frozen = true);
        if label != Label::Public {
            let key = RuntimePropertyKey::String(JsString::from("rawJSON"));
            self.set_own_runtime_property_label(object, &key, &label)?;
            self.join_direct_object_mutation_label(object, &label)?;
        }
        Ok(Value::Object(object))
    }

    /// `JSON.isRawJSON(value)`: whether `value` is a JSON.rawJSON result.
    pub(super) fn json_is_raw_json_builtin(
        &mut self,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let raw = match self.builtin_arg(args, 0)? {
            Some(Value::Object(object)) => self.is_raw_json_object(object),
            _ => false,
        };
        Ok(Value::Bool(raw))
    }

    /// Whether `object` has [[IsRawJSON]] (a JSON.rawJSON result).
    pub(super) fn is_raw_json_object(&self, object: ObjectId) -> bool {
        self.heap
            .get(object.0 as usize)
            .is_some_and(|object| object.brand() == Some(RAW_JSON_BRAND))
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

    /// Match the runtime's conservative reachable-value provenance floor,
    /// without recursing on an attacker-controlled graph before the JSON depth
    /// guard. Both the visited set and pending edges are admission-accounted.
    /// This walk performs no guest Get and cannot change callback order.
    pub(super) fn json_observe_reachable_value(
        &mut self,
        value: &Value,
    ) -> Result<(), InterpreterError> {
        self.observe_reachable_value(value, ReachableEdges::Data)
    }

    /// The console sink's walk (bd-39iih): console output is `util.inspect`,
    /// which prints more than the data edges JSON follows.
    pub(super) fn console_observe_reachable_value(
        &mut self,
        value: &Value,
    ) -> Result<(), InterpreterError> {
        self.observe_reachable_value(value, ReachableEdges::Inspect)
    }

    /// Objects one step from `object` along `edges`.
    fn reachable_children(&self, object: ObjectId, edges: ReachableEdges) -> Vec<ObjectId> {
        let Some(heap_object) = self.heap.get(object.0 as usize) else {
            return Vec::new();
        };
        let object_id = |value: &Value| match value {
            Value::Object(id) => Some(*id),
            _ => None,
        };
        match edges {
            // The walk visits each reachable object once and joins labels,
            // so child order does not matter: no per-key lookup for creation
            // order (bd-9vouw.333).
            ReachableEdges::Data => heap_object
                .properties
                .values_unordered()
                .filter_map(object_id)
                .collect(),
            ReachableEdges::Inspect => {
                // Every property inspect can print: string-keyed data in both
                // key forms and Symbol-keyed data (a separate sidecar that
                // `values()` skips). Accessors print as [Getter]/[Setter].
                let mut children: Vec<ObjectId> = heap_object
                    .properties
                    .all_data_values()
                    .filter_map(object_id)
                    .collect();
                children.extend(
                    heap_object
                        .properties
                        .baseline_symbol_properties()
                        .filter_map(|(_, property)| match property {
                            BaselineSymbolProperty::Data(value) => object_id(value),
                            BaselineSymbolProperty::Accessor { .. } => None,
                        }),
                );
                // Map keys are storage-key reprs, not values
                // (`collection_key_repr`); inspect prints the key objects.
                if let Some(storage_id) = self.collection_storage_id(object, "Map", "__entries")
                    && let Some(storage) = self.heap.get(storage_id.0 as usize)
                {
                    children.extend(
                        storage
                            .properties
                            .keys()
                            .filter_map(|repr| object_id(&Self::collection_key_from_repr(repr))),
                    );
                }
                // An error's message and name print through the prototype
                // chain (`chain_data_property`).
                if self.inspect_is_error(object)
                    && let Some(prototype) = heap_object.prototype
                {
                    children.push(prototype);
                }
                children
            }
        }
    }

    fn observe_reachable_value(
        &mut self,
        value: &Value,
        edges: ReachableEdges,
    ) -> Result<(), InterpreterError> {
        let Value::Object(root) = value else {
            return Ok(());
        };
        let mut pending = Vec::new();
        let mut visited = BTreeSet::new();
        let mut charged = 0_u64;
        let outcome = (|| {
            self.json_reserve_temporary(std::mem::size_of::<ObjectId>() as u64)?;
            charged += std::mem::size_of::<ObjectId>() as u64;
            pending
                .try_reserve_exact(1)
                .map_err(|_| self.memory_budget_error(u64::MAX, self.heap_object_count_u32()))?;
            pending.push(*root);
            while let Some(object) = pending.pop() {
                self.json_charge_work()?;
                if visited.contains(&object) {
                    continue;
                }
                self.json_reserve_temporary(64)?;
                charged += 64;
                visited.insert(object);
                let label = self
                    .object_mutation_labels
                    .get(&object)
                    .into_iter()
                    .chain(self.binary_storage_label_ref(object))
                    .max();
                if let Some(label) = label {
                    self.check_temporary_memory_budget(Self::estimate_label_bytes(label))?;
                    let label = label.clone();
                    self.json_observe_label(label)?;
                }
                let children = self.reachable_children(object, edges);
                let bytes =
                    (children.len() as u64).saturating_mul(std::mem::size_of::<ObjectId>() as u64);
                self.json_reserve_temporary(bytes)?;
                charged += bytes;
                pending.try_reserve_exact(children.len()).map_err(|_| {
                    self.memory_budget_error(u64::MAX, self.heap_object_count_u32())
                })?;
                pending.extend(children);
            }
            Ok(())
        })();
        drop(pending);
        drop(visited);
        self.json_release_temporary(charged);
        outcome
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
        record: Option<JsonParseRecord>,
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
            /// The parse record when `value` is still the parsed one.
            record: Option<JsonParseRecord>,
        }
        let mut frames = Vec::<Frame>::new();
        let mut next = Some((holder, name, record));
        let mut retained = 0_u64;
        let outcome = (|| {
            loop {
                if let Some((holder, name, record)) = next.take() {
                    let current_depth = depth.saturating_add(frames.len());
                    if current_depth > 200 {
                        return Err(InterpreterError::StackOverflow {
                            depth: current_depth,
                            max: 200,
                        });
                    }
                    self.json_charge_work()?;
                    let key = RuntimePropertyKey::String(name.clone());
                    // Preserve inherited/Proxy selection provenance before
                    // Get can throw or reenter and replace the pending label.
                    let value = self.iterator_protocol_property(
                        module,
                        holder,
                        &key,
                        Value::Object(holder),
                    )?;
                    let label = self.json_parse_context_label()?;
                    self.json_observe_label(label)?;
                    self.json_observe_reachable_value(&value)?;
                    let charged = (std::mem::size_of::<Frame>() as u64)
                        .saturating_add(Self::estimate_js_string_bytes(&name))
                        .saturating_add(Self::estimate_value_bytes(&value));
                    self.json_reserve_temporary(charged)?;
                    retained += charged;
                    frames.try_reserve(1).map_err(|_| {
                        self.memory_budget_error(u64::MAX, self.heap_object_count_u32())
                    })?;
                    // A record describes the value only while it is the
                    // parsed one (SameValue): a reviver's replacement, or a
                    // value it added, has no source.
                    let record = record.filter(|record| Self::same_value(&record.value, &value));
                    frames.push(Frame {
                        holder,
                        name,
                        value,
                        children: Children::None,
                        charged,
                        record,
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
                        let child = frame
                            .record
                            .as_mut()
                            .and_then(|record| {
                                record.elements.get_mut(usize::try_from(*index).ok()?)
                            })
                            .and_then(Option::take);
                        next = Some((*object, JsString::from(index.to_string()), child));
                        *index += 1;
                        continue;
                    }
                    Children::Object {
                        object,
                        keys,
                        next: index,
                    } if *index < keys.len() => {
                        let key = keys[*index].clone();
                        let child = frame
                            .record
                            .as_mut()
                            .and_then(|record| {
                                record.entries.iter_mut().find(|(entry, _)| *entry == key)
                            })
                            .and_then(|(_, child)| child.take());
                        next = Some((*object, key, child));
                        *index += 1;
                        continue;
                    }
                    _ => {}
                }
                let frame = frames.pop().expect("completed reviver frame");
                // The reviver's third argument: a plain object with the
                // source text of a still-parsed primitive.
                let context_object = {
                    let prototype = self.ensure_builtin_prototype("Object")?;
                    let object = self.alloc_object_with_prototype(Some(prototype))?;
                    if !frame.value.is_object_like()
                        && let Some(source) = frame.record.as_ref().and_then(|r| r.source.clone())
                    {
                        self.json_store_parsed_property(
                            object,
                            JsString::from("source"),
                            Value::Str(source),
                        )?;
                    }
                    Value::Object(object)
                };
                // Keep the popped frame charged until its callback returns,
                // even when it recursively parses or retains the original value.
                let context = self.json_parse_context_label()?;
                let (result, label) = self.invoke_inline_method_call_with_argument_label(
                    module,
                    reviver.clone(),
                    Value::Object(frame.holder),
                    vec![Value::Str(frame.name.clone()), frame.value, context_object],
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
        // Shared with stringify and replacer-list extraction. Use the same
        // receiver-preserving Get as element reads, including the access hook
        // and the shape labels of an inherited or proxied length property.
        let value = self.iterator_protocol_property(module, object, &key, receiver)?;
        let observed = self.json_parse_context_label()?;
        self.json_observe_label(observed)?;
        self.json_observe_reachable_value(&value)?;
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
                        self.proxy_trap_target(object, target),
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
        if self.heap[object.0 as usize].is_frozen
            || (!self.heap[object.0 as usize].extensible()
                && !self.heap[object.0 as usize]
                    .properties
                    .contains_exact_key(&name))
        {
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
                core.chain_data_property(*id, "name"),
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

    #[test]
    fn symbol_input_type_error_retains_context_and_allows_subsequent_parse() {
        let mut core = core();
        // IDs 1..=13 are the runtime's reserved well-known Symbols.
        core.set_register(0, Value::Symbol(SymbolId(1))).unwrap();
        let input_label = Label::Custom {
            name: "json-symbol-input".repeat(16),
            level: 9,
        };
        let caller = Label::Custom {
            name: "outer-json-call".repeat(8),
            level: 7,
        };
        core.set_register_label(0, input_label.clone()).unwrap();
        core.active_inline_callback_context_label = Some(caller.clone());
        core.sync_estimated_memory_bytes().unwrap();
        assert!(matches!(
            core.dispatch_builtin_hostcall(
                "builtin:JsonParse",
                RegRange { start: 0, count: 1 },
                None,
            ),
            Err(InterpreterError::UncaughtException { .. })
        ));
        let Some(Value::Object(error)) = core.pending_exception.as_ref() else {
            panic!("coercion must create a guest TypeError, not a SyntaxError");
        };
        assert_eq!(
            core.chain_data_property(*error, "name"),
            Some(&Value::str("TypeError"))
        );
        assert_eq!(core.pending_exception_label, input_label);
        assert_eq!(core.active_inline_callback_context_label, Some(caller));
        assert_eq!(core.json_parse_temporary_bytes, 0);
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );

        core.replace_pending_abrupt_slots(None, None).unwrap();
        core.active_inline_callback_context_label = None;
        core.sync_estimated_memory_bytes().unwrap();
        core.set_register_label(0, Label::Public).unwrap();
        assert_eq!(
            parse(&mut core, Value::str("123")).unwrap(),
            Value::Int(123)
        );
        assert!(core.pending_exception.is_none());
        assert!(core.active_inline_callback_context_label.is_none());
        assert_eq!(core.pending_hostcall_result_label, Some(Label::Public));
        assert_eq!(core.json_parse_temporary_bytes, 0);
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }

    #[test]
    fn array_length_preserves_inherited_owner_shape_provenance() {
        let mut core = core();
        let owner = core
            .alloc_object_with_properties(&[("length", Value::Int(3))])
            .unwrap();
        let receiver = core.alloc_object_with_prototype(Some(owner)).unwrap();
        core.join_direct_object_mutation_label(owner, &Label::Secret)
            .unwrap();
        // The value is public; selection of its owner is the secret input.
        assert_eq!(core.own_property_label(owner, "length"), Label::Public);
        core.json_observe_label(Label::Public).unwrap();
        assert_eq!(
            core.json_reviver_array_length(None, receiver, Value::Object(receiver))
                .unwrap(),
            3
        );
        assert_eq!(
            core.active_inline_callback_context_label,
            Some(Label::Secret)
        );
        assert_eq!(core.json_parse_temporary_bytes, 0);
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }

    #[test]
    fn array_length_own_shadow_does_not_observe_unused_prototype() {
        let mut core = core();
        let prototype = core
            .alloc_object_with_properties(&[("length", Value::Int(99))])
            .unwrap();
        core.join_direct_object_mutation_label(prototype, &Label::Secret)
            .unwrap();
        let receiver = core.alloc_object_with_prototype(Some(prototype)).unwrap();
        core.set_object_property(receiver, "length".into(), Value::Int(2))
            .unwrap();
        core.json_observe_label(Label::Public).unwrap();
        assert_eq!(
            core.json_reviver_array_length(None, receiver, Value::Object(receiver))
                .unwrap(),
            2
        );
        assert_eq!(
            core.active_inline_callback_context_label,
            Some(Label::Public)
        );
        assert_eq!(core.json_parse_temporary_bytes, 0);
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }

    #[test]
    fn invalid_inherited_length_keeps_shape_label_on_abrupt_exit() {
        let mut core = core();
        let owner = core
            .alloc_object_with_properties(&[("length", Value::BigInt("1".into()))])
            .unwrap();
        let receiver = core.alloc_object_with_prototype(Some(owner)).unwrap();
        core.join_direct_object_mutation_label(owner, &Label::Secret)
            .unwrap();
        core.json_observe_label(Label::Public).unwrap();
        assert!(matches!(
            core.json_reviver_array_length(None, receiver, Value::Object(receiver)),
            Err(InterpreterError::TypeError { .. })
        ));
        // The owning JSON boundary materializes this error while the label
        // is still live. No guest heap mutation or scratch may be rolled back.
        assert_eq!(
            core.active_inline_callback_context_label,
            Some(Label::Secret)
        );
        assert_eq!(
            core.heap[owner.0 as usize].properties.get("length"),
            Some(&Value::BigInt("1".into()))
        );
        assert_eq!(core.json_parse_temporary_bytes, 0);
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }
}
