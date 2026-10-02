//! ES2025 Set methods: `union`, `intersection`, `difference`,
//! `symmetricDifference`, `isSubsetOf`, `isSupersetOf` and `isDisjointFrom`
//! (ECMA-262 2025 24.2.4), as Node v22 ships them.
//!
//! The receiver is a Set; the argument is any set-like object, read once
//! through GetSetRecord: a numeric `size` and callable `has` and `keys`. Each
//! method picks, by the two sizes, whether it walks the receiver and asks
//! `other.has`, or walks `other.keys()`; those calls are guest code and their
//! order is observable. The receiver's elements are walked from a snapshot
//! taken when the method starts.

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
        let this_values = self.set_values_snapshot(this_id);
        let this_size = this_values.len() as f64;
        let result = match method {
            "union" => {
                let result = self.new_set_from(&this_values)?;
                self.for_each_set_record_key(module, &record, |core, value| {
                    core.set_collection_add(result, value)?;
                    Ok(true)
                })?;
                Value::Object(result)
            }
            "intersection" => {
                let result = self.new_set_from(&[])?;
                if this_size <= record.size {
                    for value in this_values {
                        if self.set_record_has(module, &record, &value)? {
                            self.set_collection_add(result, value)?;
                        }
                    }
                } else {
                    self.for_each_set_record_key(module, &record, |core, value| {
                        if core.collection_has(this_id, "Set", "__values", &value) {
                            core.set_collection_add(result, value)?;
                        }
                        Ok(true)
                    })?;
                }
                Value::Object(result)
            }
            "difference" => {
                let result = self.new_set_from(&this_values)?;
                if this_size <= record.size {
                    for value in this_values {
                        if self.set_record_has(module, &record, &value)? {
                            self.collection_delete(result, "Set", "__values", &value)?;
                        }
                    }
                } else {
                    self.for_each_set_record_key(module, &record, |core, value| {
                        core.collection_delete(result, "Set", "__values", &value)?;
                        Ok(true)
                    })?;
                }
                Value::Object(result)
            }
            "symmetricDifference" => {
                let result = self.new_set_from(&this_values)?;
                self.for_each_set_record_key(module, &record, |core, value| {
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
                    for value in this_values {
                        if !self.set_record_has(module, &record, &value)? {
                            subset = false;
                            break;
                        }
                    }
                }
                Value::Bool(subset)
            }
            "isSupersetOf" => {
                let mut superset = this_size >= record.size;
                if superset {
                    self.for_each_set_record_key(module, &record, |core, value| {
                        superset = core.collection_has(this_id, "Set", "__values", &value);
                        Ok(superset)
                    })?;
                }
                Value::Bool(superset)
            }
            "isDisjointFrom" => {
                let mut disjoint = true;
                if this_size <= record.size {
                    for value in this_values {
                        if self.set_record_has(module, &record, &value)? {
                            disjoint = false;
                            break;
                        }
                    }
                } else {
                    self.for_each_set_record_key(module, &record, |core, value| {
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
        let mut members = Vec::with_capacity(2);
        for name in ["has", "keys"] {
            let member = self.get_v(module, &object, &Self::set_record_key(name))?;
            if !member.is_callable() {
                return Err(InterpreterError::TypeError {
                    expected: format!("set-like object with a callable {name}"),
                    got: member.type_name().to_string(),
                });
            }
            members.push(member);
        }
        let keys = members.pop().expect("two members were read");
        let has = members.pop().expect("two members were read");
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

    /// Walk `other.keys()` (GetIteratorFromMethod, then IteratorStepValue),
    /// handing each value (-0 canonicalized to +0) to `visit` until it
    /// returns false or the iterator is done. Stopping early closes the
    /// iterator (its `return`), as IteratorClose does.
    fn for_each_set_record_key(
        &mut self,
        module: &Ir3Module,
        record: &SetRecord,
        mut visit: impl FnMut(&mut Self, Value) -> Result<bool, InterpreterError>,
    ) -> Result<(), InterpreterError> {
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
        loop {
            let step = self.invoke_inline_method_call(
                Some(module),
                next.clone(),
                iterator.clone(),
                Vec::new(),
            )?;
            if !step.is_object_like() {
                return Err(InterpreterError::TypeError {
                    expected: "iterator result object".to_string(),
                    got: step.type_name().to_string(),
                });
            }
            if self
                .get_v(module, &step, &Self::set_record_key("done"))?
                .is_truthy()
            {
                return Ok(());
            }
            let value = self.get_v(module, &step, &Self::set_record_key("value"))?;
            if !visit(self, Self::collection_canonical_member(value))? {
                return self.close_set_record_keys(module, iterator);
            }
        }
    }

    /// IteratorClose with a normal completion: call the iterator's `return`
    /// if it has one; its result must be an object.
    fn close_set_record_keys(
        &mut self,
        module: &Ir3Module,
        iterator: Value,
    ) -> Result<(), InterpreterError> {
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

    /// The Set's elements in insertion order.
    fn set_values_snapshot(&self, set_id: ObjectId) -> Vec<Value> {
        let Some(storage) = self.collection_storage_id(set_id, "Set", "__values") else {
            return Vec::new();
        };
        let mut values = Vec::new();
        while let Some((_, value)) = self.collection_entry_at(storage, values.len()) {
            values.push(value);
        }
        values
    }

    /// A new Set (with %Set.prototype%) holding `values` in order.
    fn new_set_from(&mut self, values: &[Value]) -> Result<ObjectId, InterpreterError> {
        let set_id = self.alloc_empty_set()?;
        for value in values {
            self.set_collection_add(set_id, value.clone())?;
        }
        Ok(set_id)
    }
}
