//! ES2025 Set methods: `union`, `intersection`, `difference`,
//! `symmetricDifference`, `isSubsetOf`, `isSupersetOf` and `isDisjointFrom`
//! (ECMA-262 2025 24.2.4), as Node v22 ships them.
//!
//! The receiver is a Set; the argument is any set-like object, read once
//! through GetSetRecord: a numeric `size` and callable `has` and `keys`. Each
//! method picks, by the two sizes, whether it walks the receiver and asks
//! `other.has`, or walks `other.keys()`; those calls are guest code and their
//! order is observable. Intersection and the predicates walk live storage;
//! difference walks its private copy. Union and symmetricDifference initialize
//! the keys iterator before copying, including its observable `next` getter.

use super::*;

/// The Set.prototype methods this module answers, by name.
pub(super) const SET_ALGEBRA_METHODS: [&str; 7] = [
    "union",
    "intersection",
    "difference",
    "symmetricDifference",
    "isSubsetOf",
    "isSupersetOf",
    "isDisjointFrom",
];

/// GetSetRecord (24.2.1.2): the set-like argument's size, `has` and `keys`.
struct SetRecord {
    object: Value,
    size: f64,
    has: Value,
    keys: Value,
}

/// GetIteratorFromMethod captures `next` once, before iteration starts.
struct SetRecordKeys {
    iterator: Value,
    next: Value,
    // IteratorStep reads these on every element. Build their exact string
    // carriers once per iterator instead of allocating two JsStrings per step.
    done_key: RuntimePropertyKey,
    value_key: RuntimePropertyKey,
}

impl InterpreterCore {
    /// `Set.prototype[method](other)` for a Set receiver.
    pub(super) fn set_algebra_method(
        &mut self,
        module: &Ir3Module,
        method: &str,
        receiver: Value,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let this_id = match &receiver {
            Value::Object(id) if self.collection_storage_id(*id, "Set", "__values").is_some() => {
                *id
            }
            other => {
                return Err(InterpreterError::TypeError {
                    expected: format!("Set receiver for Set.prototype.{method}"),
                    got: other.type_name().to_string(),
                });
            }
        };
        let other = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
        let mut label = self.join_arg_range_label(args)?;
        if let Some(collection_label) = self.object_mutation_labels.get(&this_id) {
            label = label.join(collection_label);
        }
        let record = self.get_set_record(module, other, &mut label)?;
        let this_size = self.set_data_size(this_id) as f64;
        let result = match method {
            "union" => {
                let keys = self.set_record_keys(module, &record)?;
                let result = self.copy_set_data(this_id)?;
                self.for_each_set_record_key(module, keys, |core, value| {
                    core.set_collection_add(result, value)?;
                    Ok(true)
                })?;
                Value::Object(result)
            }
            "intersection" => {
                let result = self.alloc_empty_set()?;
                if this_size <= record.size {
                    self.for_each_live_set_value(this_id, |core, value| {
                        if core.set_record_has(module, &record, &value)? {
                            core.set_collection_add(result, value)?;
                        }
                        Ok(true)
                    })?;
                } else {
                    let keys = self.set_record_keys(module, &record)?;
                    self.for_each_set_record_key(module, keys, |core, value| {
                        if core.collection_has(this_id, "Set", "__values", &value) {
                            core.set_collection_add(result, value)?;
                        }
                        Ok(true)
                    })?;
                }
                Value::Object(result)
            }
            "difference" => {
                let result = self.copy_set_data(this_id)?;
                if this_size <= record.size {
                    // Unlike intersection, difference visits the original
                    // copied entries even if `has` clears the receiver.
                    self.for_each_live_set_value(result, |core, value| {
                        if core.set_record_has(module, &record, &value)? {
                            core.collection_delete(result, "Set", "__values", &value)?;
                        }
                        Ok(true)
                    })?;
                } else {
                    let keys = self.set_record_keys(module, &record)?;
                    self.for_each_set_record_key(module, keys, |core, value| {
                        core.collection_delete(result, "Set", "__values", &value)?;
                        Ok(true)
                    })?;
                }
                Value::Object(result)
            }
            "symmetricDifference" => {
                let keys = self.set_record_keys(module, &record)?;
                let result = self.copy_set_data(this_id)?;
                self.for_each_set_record_key(module, keys, |core, value| {
                    if core.collection_has(this_id, "Set", "__values", &value) {
                        core.collection_delete(result, "Set", "__values", &value)?;
                    } else {
                        core.set_collection_add(result, value)?;
                    }
                    Ok(true)
                })?;
                Value::Object(result)
            }
            "isSubsetOf" => {
                let mut subset = this_size <= record.size;
                if subset {
                    self.for_each_live_set_value(this_id, |core, value| {
                        subset = core.set_record_has(module, &record, &value)?;
                        Ok(subset)
                    })?;
                }
                Value::Bool(subset)
            }
            "isSupersetOf" => {
                let mut superset = this_size >= record.size;
                if superset {
                    let keys = self.set_record_keys(module, &record)?;
                    self.for_each_set_record_key(module, keys, |core, value| {
                        superset = core.collection_has(this_id, "Set", "__values", &value);
                        Ok(superset)
                    })?;
                }
                Value::Bool(superset)
            }
            "isDisjointFrom" => {
                let mut disjoint = true;
                if this_size <= record.size {
                    self.for_each_live_set_value(this_id, |core, value| {
                        disjoint = !core.set_record_has(module, &record, &value)?;
                        Ok(disjoint)
                    })?;
                } else {
                    let keys = self.set_record_keys(module, &record)?;
                    self.for_each_set_record_key(module, keys, |core, value| {
                        disjoint = !core.collection_has(this_id, "Set", "__values", &value);
                        Ok(disjoint)
                    })?;
                }
                Value::Bool(disjoint)
            }
            other => {
                return Err(InterpreterError::InternalError {
                    details: format!("unknown Set method {other}"),
                });
            }
        };
        self.replace_pending_hostcall_result_label(Some(label))?;
        Ok(result)
    }

    /// GetSetRecord (24.2.1.2): `size` is read and converted first (NaN is a
    /// TypeError, a negative integer a RangeError), then `has` and `keys`,
    /// which must be callable.
    fn get_set_record(
        &mut self,
        module: &Ir3Module,
        object: Value,
        label: &mut Label,
    ) -> Result<SetRecord, InterpreterError> {
        if !object.is_object_like() {
            return Err(InterpreterError::TypeError {
                expected: "set-like object argument".to_string(),
                got: object.type_name().to_string(),
            });
        }
        let raw_size = self.get_v(module, &object, &Self::set_record_key("size"))?;
        let mut size_label = None;
        let number = self.builtin_argument_to_number(Some(module), raw_size, &mut size_label)?;
        if let Some(size_label) = size_label {
            *label = label.join(&size_label);
        }
        if number.is_nan() {
            return Err(InterpreterError::TypeError {
                expected: "set-like object with a numeric size".to_string(),
                got: "NaN".to_string(),
            });
        }
        let size = number.trunc();
        if size < 0.0 {
            return Err(InterpreterError::RangeError {
                message: "set-like object size must not be negative".to_string(),
            });
        }
        // Read in spec order without a temporary Vec. These are only two
        // values and both remain live in the returned record.
        let has = self.get_v(module, &object, &Self::set_record_key("has"))?;
        if !has.is_callable() {
            return Err(InterpreterError::TypeError {
                expected: "set-like object with a callable has".to_string(),
                got: has.type_name().to_string(),
            });
        }
        let keys = self.get_v(module, &object, &Self::set_record_key("keys"))?;
        if !keys.is_callable() {
            return Err(InterpreterError::TypeError {
                expected: "set-like object with a callable keys".to_string(),
                got: keys.type_name().to_string(),
            });
        }
        Ok(SetRecord {
            object,
            size,
            has,
            keys,
        })
    }

    /// ToBoolean(Call(other.has, other, « value »)).
    fn set_record_has(
        &mut self,
        module: &Ir3Module,
        record: &SetRecord,
        value: &Value,
    ) -> Result<bool, InterpreterError> {
        Ok(self
            .invoke_inline_method_call(
                Some(module),
                record.has.clone(),
                record.object.clone(),
                vec![value.clone()],
            )?
            .is_truthy())
    }

    /// Acquire both parts of the iterator record before copying receiver data.
    /// Calling `keys` and reading `next` may each mutate that receiver.
    fn set_record_keys(
        &mut self,
        module: &Ir3Module,
        record: &SetRecord,
    ) -> Result<SetRecordKeys, InterpreterError> {
        let iterator = self.invoke_inline_method_call(
            Some(module),
            record.keys.clone(),
            record.object.clone(),
            Vec::new(),
        )?;
        if !iterator.is_object_like() {
            return Err(InterpreterError::TypeError {
                expected: "iterator object from the set-like keys()".to_string(),
                got: iterator.type_name().to_string(),
            });
        }
        let next = self.get_v(module, &iterator, &Self::set_record_key("next"))?;
        Ok(SetRecordKeys {
            iterator,
            next,
            done_key: Self::set_record_key("done"),
            value_key: Self::set_record_key("value"),
        })
    }

    /// IteratorStepValue over an already acquired record. An early normal
    /// completion closes the iterator; a failed `next`/`done`/`value` does not.
    fn for_each_set_record_key(
        &mut self,
        module: &Ir3Module,
        keys: SetRecordKeys,
        mut visit: impl FnMut(&mut Self, Value) -> Result<bool, InterpreterError>,
    ) -> Result<(), InterpreterError> {
        loop {
            self.json_charge_work()?;
            let step = self.invoke_inline_method_call(
                Some(module),
                keys.next.clone(),
                keys.iterator.clone(),
                Vec::new(),
            )?;
            if !step.is_object_like() {
                return Err(InterpreterError::TypeError {
                    expected: "iterator result object".to_string(),
                    got: step.type_name().to_string(),
                });
            }
            if self.get_v(module, &step, &keys.done_key)?.is_truthy() {
                return Ok(());
            }
            let value = self.get_v(module, &step, &keys.value_key)?;
            if !visit(self, Self::collection_canonical_member(value))? {
                return self.close_set_record_keys(module, keys);
            }
        }
    }

    /// IteratorClose with a normal completion: call the iterator's `return`
    /// if it has one; its result must be an object.
    fn close_set_record_keys(
        &mut self,
        module: &Ir3Module,
        keys: SetRecordKeys,
    ) -> Result<(), InterpreterError> {
        let iterator = keys.iterator;
        let return_method = self.get_v(module, &iterator, &Self::set_record_key("return"))?;
        if matches!(return_method, Value::Undefined | Value::Null) {
            return Ok(());
        }
        if !return_method.is_callable() {
            return Err(InterpreterError::TypeError {
                expected: "callable iterator return".to_string(),
                got: return_method.type_name().to_string(),
            });
        }
        let result =
            self.invoke_inline_method_call(Some(module), return_method, iterator, Vec::new())?;
        if !result.is_object_like() {
            return Err(InterpreterError::TypeError {
                expected: "iterator return result object".to_string(),
                got: result.type_name().to_string(),
            });
        }
        Ok(())
    }

    fn set_record_key(name: &str) -> RuntimePropertyKey {
        RuntimePropertyKey::String(JsString::from(name))
    }

    /// Size comes from internal storage, never an overridable `size` getter.
    fn set_data_size(&self, set_id: ObjectId) -> usize {
        self.collection_storage_id(set_id, "Set", "__values")
            .and_then(|storage| self.heap.get(storage.0 as usize))
            .map_or(0, |storage| storage.properties.len())
    }

    /// Copy directly into charged heap storage instead of building an
    /// unmetered, full-size temporary Vec before allocating the result.
    fn copy_set_data(&mut self, source: ObjectId) -> Result<ObjectId, InterpreterError> {
        let result = self.alloc_empty_set()?;
        self.for_each_live_set_value(source, |core, value| {
            core.set_collection_add(result, value)?;
            Ok(true)
        })?;
        Ok(result)
    }

    /// Share forEach's mutation-aware cursor protocol. Deletion compacts
    /// storage and moves cursors back; clear resets them; appended and
    /// deleted-then-reinserted entries remain visible. No guest iterator or
    /// overridden Set method is consulted. Nested walks own distinct slots.
    fn for_each_live_set_value(
        &mut self,
        set_id: ObjectId,
        mut visit: impl FnMut(&mut Self, Value) -> Result<bool, InterpreterError>,
    ) -> Result<(), InterpreterError> {
        let storage = self
            .collection_storage_id(set_id, "Set", "__values")
            .ok_or_else(|| InterpreterError::InternalError {
                details: "Set algebra lost its internal storage".to_string(),
            })?;
        let depth = self.collection_for_each_cursors.len();
        self.collection_for_each_cursors.push((storage, 0));
        let outcome = (|| {
            loop {
                self.json_charge_work()?;
                let index = self.collection_for_each_cursors[depth].1;
                let Some((_, value)) = self.collection_entry_at(storage, index) else {
                    return Ok(());
                };
                self.collection_for_each_cursors[depth].1 = index.saturating_add(1);
                if !visit(self, value)? {
                    return Ok(());
                }
            }
        })();
        // Also remove the cursor after callback throws, cancellation and
        // budget refusal, without rolling back guest-visible mutations.
        self.collection_for_each_cursors.truncate(depth);
        outcome
    }
}
