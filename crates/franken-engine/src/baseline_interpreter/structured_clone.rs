//! HTML `structuredClone(value)` (bd-9vouw.96).
//!
//! StructuredSerialize and StructuredDeserialize done as one walk: a memory
//! map from source objects to their clones keeps shared references shared
//! and cycles closed. Supported, as in Node:
//! - primitives, including -0, NaN and BigInt;
//! - plain objects and arrays: own enumerable string-keyed properties, read
//!   with [[Get]] (getters run), become data properties; the prototype is
//!   not kept, so a class instance clones to a plain object, and holes stay
//!   holes;
//! - Boolean/Number/String/BigInt wrapper objects;
//! - Date, RegExp (`lastIndex` restarts at 0), Map, Set;
//! - ArrayBuffer (bytes copied), typed arrays and DataView over a cloned
//!   buffer (a Node Buffer clones to a plain Uint8Array);
//! - Error objects: the standard constructor named by `name` (else Error),
//!   an own `message`, `stack` and `cause`.
//!
//! Functions, symbols, Promises, WeakMap/WeakSet, generators, iterators,
//! proxies and other engine objects throw a DataCloneError (`code` 25, with
//! Node's message). The engine has no DOMException, so that is an Error named
//! DataCloneError, like btoa's InvalidCharacterError. The `transfer` option
//! is ignored.
//!
//! The walk keeps its own task stack instead of recursing natively, so
//! nesting depth is bounded by the instruction and memory budgets, not by the
//! Rust stack. Each object's properties are read in the HTML algorithm's
//! depth-first order: a property's value is cloned completely before the next
//! property is read, so getters run in Node's order.

use super::*;

/// Node's DOMException code for DataCloneError.
const DATA_CLONE_ERR_CODE: i64 = 25;

/// Error constructors a cloned error keeps (HTML serializable errors).
const SERIALIZABLE_ERROR_NAMES: [&str; 7] = [
    "Error",
    "EvalError",
    "RangeError",
    "ReferenceError",
    "SyntaxError",
    "TypeError",
    "URIError",
];

struct CloneState {
    /// Source object -> its clone, so identity and cycles survive.
    memory: BTreeMap<ObjectId, ObjectId>,
    /// Join of every object and property label read, carried to the result.
    label: Label,
    /// Live snapshot/binary-copy charges and conservative memo-entry charges.
    /// The shared native scratch counter survives reentrant accounting syncs.
    charged: u64,
}

impl CloneState {
    fn reserve(&mut self, core: &mut InterpreterCore, bytes: u64) -> Result<(), InterpreterError> {
        let total = self.charged.checked_add(bytes).ok_or_else(|| {
            core.memory_budget_error(u64::MAX, core.heap_object_count_u32())
        })?;
        core.json_reserve_temporary(bytes)?;
        self.charged = total;
        Ok(())
    }

    fn release(&mut self, core: &mut InterpreterCore, bytes: u64) {
        debug_assert!(bytes <= self.charged);
        core.json_release_temporary(bytes);
        self.charged = self.charged.saturating_sub(bytes);
    }
}

/// A traversal snapshot owns its scratch charge until its last entry is used.
struct CloneSnapshot<T> {
    values: Vec<T>,
    charged: u64,
}

// Use the existing reachable-walk estimate for a BTree node, not a new quota.
const CLONE_MEMO_ENTRY_BYTES: u64 = 64;

/// One step of the walk. `Clone` pushes exactly one value onto the results
/// stack; the steps after it pop what they need.
enum CloneTask {
    Clone(Value),
    /// Copy own enumerable string-keyed properties of `source`, from `next`.
    Properties {
        source: ObjectId,
        target: ObjectId,
        keys: CloneSnapshot<Value>,
        next: usize,
    },
    /// Pop a cloned value and define it on `target`.
    Define {
        target: ObjectId,
        key: RuntimePropertyKey,
        label: Label,
    },
    MapEntries {
        target: ObjectId,
        entries: CloneSnapshot<(Value, Value)>,
        next: usize,
    },
    /// Pop a cloned value, then its cloned key, into the Map.
    MapSet {
        target: ObjectId,
    },
    SetValues {
        target: ObjectId,
        values: CloneSnapshot<(Value, Value)>,
        next: usize,
    },
    SetAdd {
        target: ObjectId,
    },
    /// Pop the cloned buffer and make the clone of view `source` over it.
    View {
        source: ObjectId,
    },
    /// Pop a cloned `cause` and define it on the error clone.
    Cause {
        target: ObjectId,
    },
}

impl InterpreterCore {
    pub(super) fn structured_clone_builtin(
        &mut self,
        module: Option<&Ir3Module>,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        if args.count == 0 {
            return Err(self.throw_buffer_node_error(
                "TypeError",
                "ERR_MISSING_ARGS",
                "The value argument must be specified".to_string(),
            ));
        }
        let value = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
        let mut state = CloneState {
            memory: BTreeMap::new(),
            label: Label::Public,
            charged: 0,
        };
        let outcome = self.structured_clone_walk(module, value, &mut state);
        // Tasks and their snapshots have dropped on either return path. Drop
        // memo nodes too before releasing this invocation's remaining charge;
        // a caller's reentrant scratch reservation must remain untouched.
        state.memory.clear();
        self.json_release_temporary(state.charged);
        let clone = outcome?;
        // The clone holds everything reachable from the argument: its label
        // is the join of what the walk read, on top of the argument's own.
        let label = state.label.join(
            self.pending_hostcall_result_label
                .as_ref()
                .unwrap_or(&Label::Public),
        );
        self.replace_pending_hostcall_result_label(Some(label))?;
        Ok(clone)
    }

    fn structured_clone_walk(
        &mut self,
        module: Option<&Ir3Module>,
        value: Value,
        state: &mut CloneState,
    ) -> Result<Value, InterpreterError> {
        let mut tasks = vec![CloneTask::Clone(value)];
        let mut results: Vec<Value> = Vec::new();
        while let Some(task) = tasks.pop() {
            // Every edge costs work, including primitive values and references
            // already in memory. A large Map/Set must not hide an unbounded
            // native loop behind a single guest instruction. This shared check
            // also observes host cancellation; neither refusal becomes a guest
            // DataCloneError.
            self.json_charge_work()?;
            match task {
                CloneTask::Clone(value) => {
                    let clone = self.structured_clone_step(module, value, state, &mut tasks)?;
                    if let Some(clone) = clone {
                        results.push(clone);
                    }
                }
                CloneTask::Properties {
                    source,
                    target,
                    keys,
                    next,
                } => {
                    let Some(key_value) = keys.values.get(next).cloned() else {
                        let charged = keys.charged;
                        drop(keys);
                        state.release(self, charged);
                        continue;
                    };
                    tasks.push(CloneTask::Properties {
                        source,
                        target,
                        keys,
                        next: next + 1,
                    });
                    self.charge_property_copy_work()?;
                    let key = self.executable_property_key_from_value(&key_value);
                    // EnumerableOwnProperties is snapshotted before any value
                    // getter runs. Later deletion skips the key, but changing
                    // enumerability must not change that snapshot. Do not read
                    // an inherited replacement for a deleted own property.
                    let present = self
                        .heap
                        .get(source.0 as usize)
                        .ok_or(InterpreterError::ObjectNotFound { id: source.0 })?
                        .own_runtime_property_value(&key)
                        .is_some();
                    if !present {
                        continue;
                    }
                    let label = self.runtime_property_label(source, &key);
                    let value = self.proxy_aware_get_runtime_property(
                        module,
                        source,
                        &key,
                        Value::Object(source),
                        0,
                    )?;
                    state.label = state.label.join(&label);
                    tasks.push(CloneTask::Define { target, key, label });
                    tasks.push(CloneTask::Clone(value));
                }
                CloneTask::Define { target, key, label } => {
                    let value = Self::structured_clone_pop(&mut results)?;
                    self.copy_data_property_write(module, target, key, value, false, label)?;
                }
                CloneTask::MapEntries {
                    target,
                    entries,
                    next,
                } => {
                    let Some((key, value)) = entries.values.get(next).cloned() else {
                        let charged = entries.charged;
                        drop(entries);
                        state.release(self, charged);
                        continue;
                    };
                    tasks.push(CloneTask::MapEntries {
                        target,
                        entries,
                        next: next + 1,
                    });
                    tasks.push(CloneTask::MapSet { target });
                    tasks.push(CloneTask::Clone(value));
                    tasks.push(CloneTask::Clone(key));
                }
                CloneTask::MapSet { target } => {
                    let value = Self::structured_clone_pop(&mut results)?;
                    let key = Self::structured_clone_pop(&mut results)?;
                    self.map_collection_set(target, key, value)?;
                }
                CloneTask::SetValues {
                    target,
                    values,
                    next,
                } => {
                    let Some((_, value)) = values.values.get(next).cloned() else {
                        let charged = values.charged;
                        drop(values);
                        state.release(self, charged);
                        continue;
                    };
                    tasks.push(CloneTask::SetValues {
                        target,
                        values,
                        next: next + 1,
                    });
                    tasks.push(CloneTask::SetAdd { target });
                    tasks.push(CloneTask::Clone(value));
                }
                CloneTask::SetAdd { target } => {
                    let value = Self::structured_clone_pop(&mut results)?;
                    self.set_collection_add(target, value)?;
                }
                CloneTask::View { source } => {
                    let Value::Object(buffer) = Self::structured_clone_pop(&mut results)? else {
                        return Err(InterpreterError::InternalError {
                            details: "cloned view buffer is not an object".to_string(),
                        });
                    };
                    let object = self
                        .heap
                        .get(source.0 as usize)
                        .ok_or(InterpreterError::ObjectNotFound { id: source.0 })?;
                    let clone = match (object.typed_array.clone(), object.data_view.clone()) {
                        (Some(view), _) => self.alloc_typed_array_view_object(
                            view.kind,
                            buffer,
                            view.byte_offset,
                            view.byte_length,
                            view.length,
                        )?,
                        (None, Some(view)) => {
                            self.alloc_data_view_object(buffer, view.byte_offset, view.byte_length)?
                        }
                        (None, None) => {
                            return Err(InterpreterError::InternalError {
                                details: "cloned view source is not a view".to_string(),
                            });
                        }
                    };
                    state.memory.insert(source, clone);
                    results.push(Value::Object(clone));
                }
                CloneTask::Cause { target } => {
                    let cause = Self::structured_clone_pop(&mut results)?;
                    self.set_object_property(target, "cause".to_string(), cause)?;
                    self.set_own_property_attributes(
                        target,
                        &RuntimePropertyKey::String(JsString::from("cause")),
                        NON_ENUMERABLE_DATA_ATTRIBUTES,
                    )?;
                }
            }
        }
        match (results.pop(), results.is_empty()) {
            (Some(clone), true) => Ok(clone),
            _ => Err(InterpreterError::InternalError {
                details: "structuredClone walk left an unbalanced result stack".to_string(),
            }),
        }
    }

    fn structured_clone_pop(results: &mut Vec<Value>) -> Result<Value, InterpreterError> {
        results
            .pop()
            .ok_or_else(|| InterpreterError::InternalError {
                details: "structuredClone walk popped an empty result stack".to_string(),
            })
    }

    /// Clone one value: a primitive or a remembered object directly, a leaf
    /// object (Date, RegExp, wrapper, ArrayBuffer) at once, a container as an
    /// empty shell whose contents `tasks` fills next. Returns `None` only for
    /// a view, whose `View` task pushes the clone once its buffer is cloned.
    fn structured_clone_step(
        &mut self,
        module: Option<&Ir3Module>,
        value: Value,
        state: &mut CloneState,
        tasks: &mut Vec<CloneTask>,
    ) -> Result<Option<Value>, InterpreterError> {
        let id = match &value {
            Value::Undefined
            | Value::Null
            | Value::Bool(_)
            | Value::Int(_)
            | Value::Float(_)
            | Value::Str(_)
            | Value::BigInt(_) => return Ok(Some(value)),
            // Only a property's stored accessor pair has this shape; reads
            // through [[Get]] never return it.
            Value::Accessor { .. } => return Ok(Some(Value::Undefined)),
            Value::Object(id) => *id,
            Value::Symbol(symbol) => {
                let text = self.symbol_display_string(*symbol);
                return Err(self.throw_data_clone_error(&text, &state.label));
            }
            Value::Promise(_) | Value::AsyncFunctionObject(_) => {
                return Err(self.throw_data_clone_error("#<Promise>", &state.label));
            }
            Value::Generator(_) => {
                return Err(self.throw_data_clone_error("[object Generator]", &state.label));
            }
            Value::AsyncGeneratorObject(_) => {
                return Err(self.throw_data_clone_error("[object AsyncGenerator]", &state.label));
            }
            Value::Iterator(_) => {
                return Err(self.throw_data_clone_error("[object Array Iterator]", &state.label));
            }
            Value::Function(_)
            | Value::Closure(_)
            | Value::GeneratorFunction(_)
            | Value::AsyncFunction(_)
            | Value::AsyncGeneratorFunction(_)
            | Value::BuiltinFunction(_) => {
                let text = self.function_native_source_text(module, &value);
                return Err(self.throw_data_clone_error(&text, &state.label));
            }
        };
        if let Some(clone) = state.memory.get(&id) {
            return Ok(Some(Value::Object(*clone)));
        }
        self.charge_property_copy_work()?;
        if self.proxy_record(id)?.is_some() {
            return Err(self.throw_data_clone_error("#<Object>", &state.label));
        }
        state.label = state.label.join(&self.structured_clone_object_label(id));
        state.reserve(self, CLONE_MEMO_ENTRY_BYTES)?;
        let object = self
            .heap
            .get(id.0 as usize)
            .ok_or(InterpreterError::ObjectNotFound { id: id.0 })?;
        let is_array = object.is_array;
        // HTML serializes an array's length before traversing its properties.
        // A getter may grow or shrink the source, but not the clone's shape.
        let array_length = if is_array {
            object.properties.get("length").cloned()
        } else {
            None
        };
        let view_buffer = object
            .typed_array
            .as_ref()
            .map(|view| view.buffer)
            .or_else(|| object.data_view.as_ref().map(|view| view.buffer));
        let array_buffer = object.array_buffer.is_some();
        let primitive = object.primitive_value.clone();

        if let Some(primitive) = primitive {
            if matches!(primitive, Value::Symbol(_)) {
                return Err(self.throw_data_clone_error("[object Symbol]", &state.label));
            }
            let clone = self.alloc_primitive_wrapper(primitive)?;
            state.memory.insert(id, clone);
            return Ok(Some(Value::Object(clone)));
        }
        if let Some(buffer) = view_buffer {
            tasks.push(CloneTask::View { source: id });
            tasks.push(CloneTask::Clone(Value::Object(buffer)));
            return Ok(None);
        }
        if array_buffer {
            let length = self.with_array_buffer_bytes(id, <[u8]>::len)?;
            let charged = length as u64;
            state.reserve(self, charged)?;
            let outcome = (|| -> Result<ObjectId, InterpreterError> {
                let mut bytes = Vec::new();
                bytes.try_reserve_exact(length).map_err(|_| {
                    self.memory_budget_error(u64::MAX, self.heap_object_count_u32())
                })?;
                self.with_array_buffer_bytes(id, |source| bytes.extend_from_slice(source))?;
                let label = self.binary_storage_label(id);
                let clone = self.alloc_array_buffer_object(length)?;
                self.with_array_buffer_bytes_mut(clone, |target| target.copy_from_slice(&bytes))?;
                self.join_binary_storage_label(clone, &label)?;
                Ok(clone)
            })();
            state.release(self, charged);
            let clone = outcome?;
            state.memory.insert(id, clone);
            return Ok(Some(Value::Object(clone)));
        }
        match self.inspect_internal_type(id).as_deref() {
            Some("Date") => {
                let time = self
                    .heap
                    .get(id.0 as usize)
                    .and_then(|object| object.properties.get("__timestamp").cloned())
                    .unwrap_or(Value::Float(Float64::new(f64::NAN)));
                let prototype = self.ensure_builtin_prototype("Date")?;
                let clone = self.alloc_object_with_prototype(Some(prototype))?;
                self.set_object_brand(clone, "Date")?;
                self.set_object_property(clone, "__timestamp".to_string(), time)?;
                self.hide_internal_slots(clone, &["__timestamp"])?;
                state.memory.insert(id, clone);
                return Ok(Some(Value::Object(clone)));
            }
            Some("RegExp") => {
                let (source, flags) = self.regexp_source_flags_from_object(id).unwrap_or_default();
                let clone = self.alloc_regexp_object(source, flags)?;
                state.memory.insert(id, clone);
                return Ok(Some(Value::Object(clone)));
            }
            Some("Map") => {
                let (clone, _) = self.alloc_empty_map()?;
                state.memory.insert(id, clone);
                let entries =
                    self.structured_clone_collection_entries(id, "Map", "__entries", state)?;
                tasks.push(CloneTask::MapEntries {
                    target: clone,
                    entries,
                    next: 0,
                });
                return Ok(Some(Value::Object(clone)));
            }
            Some("Set") => {
                let clone = self.alloc_empty_set()?;
                state.memory.insert(id, clone);
                let values =
                    self.structured_clone_collection_entries(id, "Set", "__values", state)?;
                tasks.push(CloneTask::SetValues {
                    target: clone,
                    values,
                    next: 0,
                });
                return Ok(Some(Value::Object(clone)));
            }
            Some(other) => {
                let name = if other == PROXY_TYPE_TAG {
                    "Object"
                } else {
                    other
                };
                return Err(self.throw_data_clone_error(&format!("#<{name}>"), &state.label));
            }
            None => {}
        }
        if self.inspect_is_error(id) {
            return self.structured_clone_error(id, state, tasks).map(Some);
        }

        let clone = if is_array {
            self.alloc_array_with_prototype(None)?
        } else {
            self.alloc_object_with_prototype(None)?
        };
        if let Some(length) = array_length {
            self.set_object_property(clone, "length".to_string(), length)?;
        }
        state.memory.insert(id, clone);
        let mut keys = self.proxy_aware_own_property_keys(module, id, 0)?;
        let key_bytes = Self::estimate_value_vec_bytes(&keys);
        state.reserve(self, key_bytes)?;
        // Snapshot enumerable string keys, without reading their values. Use
        // the existing vector so filtering does not allocate a second list.
        let mut kept = 0;
        for index in 0..keys.len() {
            self.json_charge_work()?;
            let key = self.executable_property_key_from_value(&keys[index]);
            if !matches!(key, RuntimePropertyKey::Symbol(_))
                && self.copy_own_key_is_enumerable(module, id, &key, 0)?
            {
                keys.swap(kept, index);
                kept += 1;
            }
        }
        keys.truncate(kept);
        tasks.push(CloneTask::Properties {
            source: id,
            target: clone,
            keys: CloneSnapshot {
                values: keys,
                charged: key_bytes,
            },
            next: 0,
        });
        Ok(Some(Value::Object(clone)))
    }

    /// What an object's own storage carries: its mutation label and, for
    /// binary data, its bytes' label.
    fn structured_clone_object_label(&self, id: ObjectId) -> Label {
        self.object_mutation_labels
            .get(&id)
            .cloned()
            .unwrap_or(Label::Public)
            .join(&self.binary_storage_label(id))
    }

    /// Snapshot collection entries before visiting getters. Admission precedes
    /// decoding storage keys or copying values; sizing itself consumes work.
    /// Set keys are unused and need not be decoded or copied a second time.
    fn structured_clone_collection_entries(
        &mut self,
        id: ObjectId,
        type_tag: &str,
        storage_prop: &str,
        state: &mut CloneState,
    ) -> Result<CloneSnapshot<(Value, Value)>, InterpreterError> {
        let Some(storage_id) = self.collection_storage_id(id, type_tag, storage_prop) else {
            return Ok(CloneSnapshot {
                values: Vec::new(),
                charged: 0,
            });
        };
        state.label = state
            .label
            .join(&self.structured_clone_object_label(storage_id));
        let count = self
            .heap
            .get(storage_id.0 as usize)
            .map_or(0, |storage| storage.properties.len());
        for _ in 0..count {
            self.json_charge_work()?;
        }
        let is_map = type_tag == "Map";
        let charged = self.heap.get(storage_id.0 as usize).map_or(0, |storage| {
            storage.properties.iter().fold(0_u64, |bytes, (repr, value)| {
                // A decoded key's UTF-16 payload fits within twice its stored
                // representation length. The pair includes its Value headers.
                let key_bytes = if is_map {
                    (repr.len() as u64).saturating_mul(2)
                } else {
                    0
                };
                bytes.saturating_add(std::mem::size_of::<(Value, Value)>() as u64)
                    .saturating_add(key_bytes)
                    .saturating_add(Self::estimate_value_bytes(value))
            })
        });
        state.reserve(self, charged)?;
        let mut entries = Vec::new();
        entries.try_reserve_exact(count).map_err(|_| {
            self.memory_budget_error(u64::MAX, self.heap_object_count_u32())
        })?;
        if let Some(storage) = self.heap.get(storage_id.0 as usize) {
            for (repr, value) in storage.properties.iter() {
                let key = if is_map {
                    Self::collection_key_from_repr(repr)
                } else {
                    Value::Undefined
                };
                entries.push((key, value.clone()));
            }
        }
        Ok(CloneSnapshot {
            values: entries,
            charged,
        })
    }

    /// V8's error serialization: the prototype of the standard constructor
    /// that `name` names (else Error), then an own `message`, `stack` and
    /// `cause`. Other own properties are not kept.
    fn structured_clone_error(
        &mut self,
        id: ObjectId,
        state: &mut CloneState,
        tasks: &mut Vec<CloneTask>,
    ) -> Result<Value, InterpreterError> {
        let name = match self.chain_data_property(id, "name") {
            Some(Value::Str(name)) => SERIALIZABLE_ERROR_NAMES
                .into_iter()
                .find(|candidate| name.as_ref() == *candidate)
                .unwrap_or("Error"),
            _ => "Error",
        };
        let own = |core: &Self, key: &str| {
            core.heap
                .get(id.0 as usize)
                .and_then(|object| object.properties.get(key).cloned())
                .filter(|value| !matches!(value, Value::Accessor { .. }))
        };
        let message = own(self, "message").map(|message| self.value_to_string(&message));
        let stack = own(self, "stack");
        let cause = own(self, "cause");
        let prototype = self.ensure_builtin_prototype(name)?;
        let clone = self.alloc_object_with_prototype(Some(prototype))?;
        state.memory.insert(id, clone);
        self.initialize_error_object(clone, message)?;
        if let Some(stack @ Value::Str(_)) = stack {
            self.set_object_property(clone, "stack".to_string(), stack)?;
        }
        if let Some(cause) = cause {
            tasks.push(CloneTask::Cause { target: clone });
            tasks.push(CloneTask::Clone(cause));
        }
        Ok(Value::Object(clone))
    }

    /// A new empty Set: the object and its value storage, as `new Set()`
    /// makes them.
    pub(super) fn alloc_empty_set(&mut self) -> Result<ObjectId, InterpreterError> {
        let prototype = self.ensure_builtin_prototype("Set")?;
        let set_id = self.alloc_object_with_prototype(Some(prototype))?;
        let values_id = self.alloc_object_with_prototype(None)?;
        self.set_object_brand(set_id, "Set")?;
        self.set_object_property(set_id, "__values".to_string(), Value::Object(values_id))?;
        self.set_object_property(set_id, COLLECTION_SIZE_SLOT.to_string(), Value::Int(0))?;
        self.hide_internal_slots(set_id, &["__values", COLLECTION_SIZE_SLOT])?;
        Ok(set_id)
    }

    /// Node throws a DOMException named DataCloneError (legacy code 25). The
    /// engine has no DOMException, so the thrown value is an Error with that
    /// `name`, Node's message and `code` 25. The message can quote the
    /// value (a function's source, a symbol's description), so the exception
    /// carries the walk's label.
    fn throw_data_clone_error(&mut self, what: &str, label: &Label) -> InterpreterError {
        let thrown = (|| -> Result<Value, InterpreterError> {
            let prototype = self.ensure_builtin_prototype("Error")?;
            let error_id = self.alloc_object_with_prototype(Some(prototype))?;
            self.initialize_error_like_object(
                error_id,
                "DataCloneError",
                format!("{what} could not be cloned."),
            )?;
            self.set_object_property(
                error_id,
                "code".to_string(),
                Value::Int(DATA_CLONE_ERR_CODE),
            )?;
            Ok(Value::Object(error_id))
        })();
        let thrown = match thrown {
            Ok(value) => value,
            Err(err) => return err,
        };
        self.pending_exception = Some(thrown.clone());
        self.pending_exception_label = label.clone();
        InterpreterError::UncaughtException {
            value: self.uncaught_exception_description(&thrown),
        }
    }
}

#[cfg(test)]
mod resource_tests {
    use super::*;

    fn runtime() -> InterpreterCore {
        InterpreterCore::new(InterpreterConfig::quickjs_defaults(), "clone-resource")
    }

    fn state() -> CloneState {
        CloneState {
            memory: BTreeMap::new(),
            label: Label::Public,
            charged: 0,
        }
    }

    fn collection(core: &mut InterpreterCore, is_map: bool, count: i64) -> ObjectId {
        let target = if is_map {
            core.alloc_empty_map().unwrap().0
        } else {
            core.alloc_empty_set().unwrap()
        };
        for value in 0..count {
            if is_map {
                core.map_collection_set(target, Value::Int(value), Value::Int(value + 1))
                    .unwrap();
            } else {
                core.set_collection_add(target, Value::Int(value)).unwrap();
            }
        }
        target
    }

    fn clone_value(core: &mut InterpreterCore, value: Value) -> Result<Value, InterpreterError> {
        core.set_register(0, value).unwrap();
        core.structured_clone_builtin(None, RegRange { start: 0, count: 1 })
    }

    #[test]
    fn primitive_collections_cannot_bypass_the_instruction_budget() {
        for is_map in [false, true] {
            let mut core = runtime();
            let source = collection(&mut core, is_map, 128);
            // Construction is not part of the budget under test. The native
            // clone gets only eight more work units, far less than 128 edges.
            core.config.instruction_budget = core.instructions_executed + 8;
            assert!(matches!(
                clone_value(&mut core, Value::Object(source)),
                Err(InterpreterError::BudgetExhausted { .. })
            ));
            assert!(core.pending_exception.is_none(), "not a guest clone error");
            assert_eq!(core.json_parse_temporary_bytes, 0);
            assert_eq!(core.estimated_memory_bytes(), core.recompute_estimated_memory_bytes());
            core.config.instruction_budget = 1_000_000;
            assert!(matches!(
                clone_value(&mut core, Value::Object(source)),
                Ok(Value::Object(_))
            ));
            assert_eq!(core.json_parse_temporary_bytes, 0);
        }
    }

    #[test]
    fn collection_snapshot_is_admitted_before_allocation() {
        for is_map in [false, true] {
            let mut core = runtime();
            let source = collection(&mut core, is_map, 32);
            let before = core.estimated_memory_bytes();
            core.config.max_total_memory_bytes = before;
            let mut state = state();
            let (tag, slot) = if is_map { ("Map", "__entries") } else { ("Set", "__values") };
            let result = core.structured_clone_collection_entries(source, tag, slot, &mut state);
            assert!(matches!(result, Err(InterpreterError::MemoryBudgetExceeded { .. })));
            assert_eq!(state.charged, 0, "a refused snapshot owns no charge");
            assert_eq!(core.json_parse_temporary_bytes, 0);
            assert_eq!(core.estimated_memory_bytes(), before);
            assert_eq!(core.estimated_memory_bytes(), core.recompute_estimated_memory_bytes());
        }
    }

    #[test]
    fn snapshot_charge_survives_resynchronization_and_preserves_caller_scratch() {
        let mut core = runtime();
        let source = collection(&mut core, true, 16);
        core.json_reserve_temporary(37).unwrap();
        let mut state = state();
        let snapshot = core
            .structured_clone_collection_entries(source, "Map", "__entries", &mut state)
            .unwrap();
        assert_eq!(snapshot.values.len(), 16);
        assert!(snapshot.charged >= 16 * std::mem::size_of::<(Value, Value)>() as u64);
        assert_eq!(core.json_parse_temporary_bytes, snapshot.charged + 37);
        let expected_memory = core.estimated_memory_bytes();
        assert_eq!(core.sync_estimated_memory_bytes().unwrap(), expected_memory);
        let charged = snapshot.charged;
        drop(snapshot);
        state.release(&mut core, charged);
        assert_eq!(state.charged, 0);
        assert_eq!(core.json_parse_temporary_bytes, 37);
        assert!(clone_value(&mut core, Value::Object(source)).is_ok());
        assert_eq!(core.json_parse_temporary_bytes, 37);
        core.json_release_temporary(37);
        assert_eq!(core.estimated_memory_bytes(), core.recompute_estimated_memory_bytes());
    }

    #[test]
    fn completed_snapshots_are_released_before_memo_entries() {
        let mut core = runtime();
        let map = collection(&mut core, true, 64);
        let set = collection(&mut core, false, 64);
        let source = core.alloc_array_from_values(&[Value::Object(map), Value::Object(set)]).unwrap();
        let mut state = state();
        assert!(core.structured_clone_walk(None, Value::Object(source), &mut state).is_ok());
        assert_eq!(state.memory.len(), 3);
        assert_eq!(state.charged, 3 * CLONE_MEMO_ENTRY_BYTES);
        assert_eq!(core.estimated_memory_bytes(), core.recompute_estimated_memory_bytes());
        state.memory.clear();
        let charged = state.charged;
        state.release(&mut core, charged);
        assert_eq!(core.json_parse_temporary_bytes, 0);
        assert_eq!(core.estimated_memory_bytes(), core.recompute_estimated_memory_bytes());
    }

    #[test]
    fn shared_objects_are_memoized_and_charged_once() {
        let mut core = runtime();
        let shared = core.alloc_object_with_properties(&[("n", Value::Int(7))]).unwrap();
        let source = core.alloc_empty_map().unwrap().0;
        for n in 0..32 {
            core.map_collection_set(source, Value::Int(n), Value::Object(shared)).unwrap();
        }
        let mut state = state();
        assert!(core.structured_clone_walk(None, Value::Object(source), &mut state).is_ok());
        assert_eq!(state.memory.len(), 2);
        assert_eq!(state.charged, 2 * CLONE_MEMO_ENTRY_BYTES);
        state.memory.clear();
        let charged = state.charged;
        state.release(&mut core, charged);
        assert_eq!(core.json_parse_temporary_bytes, 0);
    }

    #[test]
    fn binary_copy_refusal_does_not_allocate_an_unbudgeted_payload() {
        let mut core = runtime();
        let source = core.alloc_array_buffer_object(1024).unwrap();
        core.with_array_buffer_bytes_mut(source, |bytes| bytes.fill(0xA5)).unwrap();
        core.set_register(0, Value::Object(source)).unwrap();
        let heap_before = core.heap_size();
        let before = core.estimated_memory_bytes();
        core.config.max_total_memory_bytes = before + CLONE_MEMO_ENTRY_BYTES + 1023;
        assert!(matches!(
            core.structured_clone_builtin(None, RegRange { start: 0, count: 1 }),
            Err(InterpreterError::MemoryBudgetExceeded { .. })
        ));
        assert_eq!(core.heap_size(), heap_before);
        assert!(core.with_array_buffer_bytes(source, |bytes| bytes.iter().all(|byte| *byte == 0xA5)).unwrap());
        assert!(core.pending_exception.is_none());
        assert_eq!(core.json_parse_temporary_bytes, 0);
        assert_eq!(core.estimated_memory_bytes(), before);
        assert_eq!(core.estimated_memory_bytes(), core.recompute_estimated_memory_bytes());
    }

    #[test]
    fn failed_clone_drops_snapshots_without_releasing_an_outer_reservation() {
        let mut core = runtime();
        let source = core.alloc_empty_map().unwrap().0;
        core.map_collection_set(source, Value::Int(1), Value::Symbol(SymbolId(1))).unwrap();
        core.json_reserve_temporary(37).unwrap();
        assert!(matches!(
            clone_value(&mut core, Value::Object(source)),
            Err(InterpreterError::UncaughtException { .. })
        ));
        assert!(core.pending_exception.is_some());
        assert_eq!(core.json_parse_temporary_bytes, 37);
        core.json_release_temporary(37);
        assert_eq!(core.estimated_memory_bytes(), core.recompute_estimated_memory_bytes());
    }

    #[test]
    fn cancellation_stops_native_clone_before_allocating_output() {
        let mut core = runtime();
        let source = collection(&mut core, true, 32);
        let token = CancellationToken::new();
        token.cancel();
        core.config.cancellation_token = Some(token);
        let before = core.heap_size();
        assert_eq!(clone_value(&mut core, Value::Object(source)), Err(InterpreterError::Cancelled));
        assert_eq!(core.heap_size(), before);
        assert!(core.pending_exception.is_none());
        assert_eq!(core.json_parse_temporary_bytes, 0);
        assert_eq!(core.estimated_memory_bytes(), core.recompute_estimated_memory_bytes());
    }
}
