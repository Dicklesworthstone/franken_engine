//! Executable ordinary property descriptors on the existing baseline carrier.
//!
//! These algorithms follow the engine's `core_objects_and_descriptors` path;
//! getters, coercion, exact keys and abrupt completions use core's existing
//! native-call machinery rather than introducing a second object heap.

use super::*;
use crate::ifc_artifacts::Label;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct PropertyAttributes {
    pub(super) writable: bool,
    pub(super) enumerable: bool,
    pub(super) configurable: bool,
}

impl PropertyAttributes {
    pub(super) const DEFAULT: Self = Self {
        writable: true,
        enumerable: true,
        configurable: true,
    };
    const ARRAY_LENGTH: Self = Self {
        writable: true,
        enumerable: false,
        configurable: false,
    };
}

/// Absent fields differ from present fields whose value is `undefined`.
#[derive(Debug, Clone, Default)]
pub(super) struct PropertyDescriptorFields {
    pub(super) value: Option<Value>,
    pub(super) writable: Option<bool>,
    pub(super) get: Option<Value>,
    pub(super) set: Option<Value>,
    pub(super) enumerable: Option<bool>,
    pub(super) configurable: Option<bool>,
}

impl PropertyDescriptorFields {
    fn is_accessor(&self) -> bool {
        self.get.is_some() || self.set.is_some()
    }
    fn is_data(&self) -> bool {
        self.value.is_some() || self.writable.is_some()
    }
    fn retained_bytes(&self) -> u64 {
        [&self.value, &self.get, &self.set]
            .into_iter()
            .flatten()
            .map(InterpreterCore::estimate_value_bytes)
            .sum()
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PropertyAttributesWire {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    key: Option<JsString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    symbol_id: Option<u32>,
    writable: bool,
    enumerable: bool,
    configurable: bool,
}

impl PropertyAttributesWire {
    pub(super) fn from_entry(key: &RuntimePropertyKey, attributes: PropertyAttributes) -> Self {
        Self {
            key: match key {
                RuntimePropertyKey::String(key) => Some(key.clone()),
                _ => None,
            },
            symbol_id: match key {
                RuntimePropertyKey::Symbol(id) => Some(id.0),
                _ => None,
            },
            writable: attributes.writable,
            enumerable: attributes.enumerable,
            configurable: attributes.configurable,
        }
    }
    pub(super) fn into_entry(
        self,
    ) -> Result<(RuntimePropertyKey, PropertyAttributes), &'static str> {
        let key = match (self.key, self.symbol_id) {
            (Some(key), None) => RuntimePropertyKey::String(key),
            (None, Some(id)) if id != 0 => RuntimePropertyKey::Symbol(SymbolId(id)),
            _ => return Err("property attributes require exactly one valid string or Symbol key"),
        };
        Ok((
            key,
            PropertyAttributes {
                writable: self.writable,
                enumerable: self.enumerable,
                configurable: self.configurable,
            },
        ))
    }
}

impl HeapObject {
    pub(super) fn own_property_attributes(&self, key: &RuntimePropertyKey) -> PropertyAttributes {
        self.property_attributes.get(key).copied().unwrap_or_else(|| {
            if self.is_array && matches!(key, RuntimePropertyKey::String(key) if key.as_str() == Some("length")) {
                PropertyAttributes::ARRAY_LENGTH
            } else {
                PropertyAttributes::DEFAULT
            }
        })
    }

    pub(super) fn own_runtime_property(&self, key: &RuntimePropertyKey) -> Option<RuntimeProperty> {
        match key {
            RuntimePropertyKey::String(key) => self
                .exact_accessor(key)
                .map(RuntimeProperty::Accessor)
                .or_else(|| {
                    self.properties
                        .get_exact(key)
                        .cloned()
                        .map(RuntimeProperty::Data)
                }),
            RuntimePropertyKey::Symbol(symbol) => self
                .properties
                .baseline_symbol_property(*symbol)
                .map(|property| match property {
                    BaselineSymbolProperty::Data(value) => RuntimeProperty::Data(value.clone()),
                    BaselineSymbolProperty::Accessor { get, set } => {
                        RuntimeProperty::Accessor(AccessorProperty {
                            get: get.clone(),
                            set: set.clone(),
                        })
                    }
                }),
        }
    }

    fn install_runtime_property(&mut self, key: &RuntimePropertyKey, property: RuntimeProperty) {
        match key {
            RuntimePropertyKey::String(key) => {
                let existed =
                    self.contains_own_runtime_property(&RuntimePropertyKey::String(key.clone()));
                self.record_property_definition(key, existed);
                match property {
                    RuntimeProperty::Data(value) => {
                        self.remove_exact_accessor(key);
                        self.properties.insert_exact(key.clone(), value);
                    }
                    RuntimeProperty::Accessor(accessor) => {
                        self.properties.remove_exact_preserving_baseline_order(key);
                        self.insert_exact_accessor(key.clone(), accessor);
                    }
                }
            }
            RuntimePropertyKey::Symbol(symbol) => {
                self.properties.insert_baseline_symbol_property(
                    *symbol,
                    match property {
                        RuntimeProperty::Data(value) => BaselineSymbolProperty::Data(value),
                        RuntimeProperty::Accessor(accessor) => BaselineSymbolProperty::Accessor {
                            get: accessor.get,
                            set: accessor.set,
                        },
                    },
                );
            }
        }
    }

    fn install_property_attributes(
        &mut self,
        key: RuntimePropertyKey,
        attributes: PropertyAttributes,
    ) {
        let default = if self.is_array
            && matches!(&key, RuntimePropertyKey::String(key) if key.as_str() == Some("length"))
        {
            PropertyAttributes::ARRAY_LENGTH
        } else {
            PropertyAttributes::DEFAULT
        };
        if attributes == default {
            self.property_attributes.remove(&key);
        } else {
            self.property_attributes.insert(key, attributes);
        }
    }
}

impl InterpreterCore {
    pub(super) fn is_descriptor_enumeration(capability: &str) -> bool {
        matches!(
            capability,
            "builtin:ObjectKeys"
                | "builtin:ObjectValues"
                | "builtin:ObjectEntries"
                | "builtin:ObjectGetOwnPropertyNames"
                | "builtin:ObjectGetOwnPropertySymbols"
                | "builtin:ReflectOwnKeys"
                | "builtin:JsonStringify"
        )
    }

    pub(super) fn dispatch_descriptor_enumeration(
        &mut self,
        module: &Ir3Module,
        capability: &str,
        args: RegRange,
    ) -> Result<(Value, Label), InterpreterError> {
        let source = self.optional_arg(args, 0)?.unwrap_or(Value::Undefined);
        let mut label = if args.count == 0 {
            Label::Public
        } else {
            self.read_reg_label(args.start)?
        };
        let result = (|| {
            if capability == "builtin:JsonStringify" {
                return self
                    .json_stringify_with_descriptors(module, &source, &mut Vec::new(), &mut label)
                    .map(|text| text.map_or(Value::Undefined, Value::str));
            }
            if let Some(object) = self.copy_data_properties_object_id(&source) {
                label = label.join(&self.observe_property_structure(object, false));
            }
            if !matches!(capability, "builtin:ObjectValues" | "builtin:ObjectEntries") {
                return self.dispatch_builtin_hostcall(capability, args);
            }
            let keys = self.copy_data_properties_keys(&source)?;
            let keys_bytes = keys.iter().map(Self::estimate_property_key_bytes).sum();
            self.with_array_method_temporary(keys_bytes, |core| {
                let result = core.alloc_array_from_values(&[])?;
                let string_units = match &source {
                    Value::Str(text) => Some(text.code_units_vec()),
                    _ => None,
                };
                let mut length = 0u32;
                for key in keys {
                    core.charge_array_method_step()?;
                    let RuntimePropertyKey::String(name) = &key else {
                        continue;
                    };
                    if core
                        .copy_data_properties_own_property(&source, &key, string_units.as_deref())?
                        .is_none()
                    {
                        continue;
                    }
                    let value = if let Some(units) = &string_units {
                        let index = name
                            .as_str()
                            .and_then(|key| key.parse::<usize>().ok())
                            .expect("string index");
                        Value::Str(JsString::from_code_units(&[units[index]]))
                    } else {
                        core.read_iterator_property(module, &source, &key, &mut label)?
                    };
                    let value = if capability == "builtin:ObjectEntries" {
                        let entry =
                            core.alloc_array_from_values(&[Value::Str(name.clone()), value])?;
                        Value::Object(entry)
                    } else {
                        value
                    };
                    core.create_data_property_or_throw(
                        result,
                        RuntimePropertyKey::String(length.to_string().into()),
                        value,
                        &label,
                    )?;
                    length = length.saturating_add(1);
                }
                Ok(Value::Object(result))
            })
        })();
        self.finish_native_builtin_call(result, label)
    }

    fn json_stringify_with_descriptors(
        &mut self,
        module: &Ir3Module,
        value: &Value,
        visited: &mut Vec<ObjectId>,
        label: &mut Label,
    ) -> Result<Option<String>, InterpreterError> {
        let Value::Object(object) = value else {
            return Ok(self.json_stringify_value(value, &mut Vec::new()));
        };
        if visited.contains(object) {
            return Err(InterpreterError::TypeError {
                expected: "acyclic JSON value".into(),
                got: "cyclic object".into(),
            });
        }
        if visited.len() >= self.config.max_call_depth {
            return Err(InterpreterError::StackOverflow {
                depth: visited.len(),
                max: self.config.max_call_depth,
            });
        }
        *label = label.join(&self.observe_property_structure(*object, false));
        let is_array = self.heap[object.0 as usize].is_array;
        let keys = if is_array {
            let length = self.array_like_length(*object)?;
            self.check_temporary_memory_budget(
                u64::from(length)
                    .saturating_mul(std::mem::size_of::<RuntimePropertyKey>() as u64 + 10),
            )?;
            (0..length)
                .map(|index| RuntimePropertyKey::String(index.to_string().into()))
                .collect::<Vec<_>>()
        } else {
            self.own_enumerable_keys(*object)?
                .into_iter()
                .map(RuntimePropertyKey::String)
                .collect()
        };
        let keys_bytes = keys.iter().map(Self::estimate_property_key_bytes).sum();
        visited.push(*object);
        let result = self.with_array_method_temporary(keys_bytes, |core| {
            let mut pieces = Vec::new();
            let mut retained = 0u64;
            for key in keys {
                core.charge_array_method_step()?;
                let piece = core.with_array_method_temporary(retained, |core| {
                    let member = core.read_iterator_property(module, value, &key, label)?;
                    core.with_array_method_temporary(Self::estimate_value_bytes(&member), |core| {
                        core.json_stringify_with_descriptors(module, &member, visited, label)
                    })
                })?;
                let piece = if is_array {
                    piece.unwrap_or_else(|| "null".into())
                } else {
                    let Some(piece) = piece else { continue };
                    let RuntimePropertyKey::String(name) = key else {
                        unreachable!()
                    };
                    core.check_temporary_memory_budget(
                        retained
                            .saturating_add(piece.len() as u64)
                            .saturating_add((name.utf16_len() as u64).saturating_mul(6))
                            .saturating_add(4),
                    )?;
                    format!("{}:{piece}", Self::json_quote_js_string(&name))
                };
                retained = retained
                    .saturating_add(piece.len() as u64)
                    .saturating_add(std::mem::size_of::<String>() as u64);
                core.check_temporary_memory_budget(retained)?;
                pieces.push(piece);
            }
            core.check_temporary_memory_budget(retained.saturating_mul(2).saturating_add(2))?;
            Ok(Some(if is_array {
                format!("[{}]", pieces.join(","))
            } else {
                format!("{{{}}}", pieces.join(","))
            }))
        });
        visited.pop();
        result
    }

    pub(super) fn descriptor_builtin_kind(capability: &str) -> Option<BuiltinFunctionKind> {
        match capability {
            "builtin:ObjectDefineProperty" => Some(BuiltinFunctionKind::ObjectDefineProperty),
            "builtin:ObjectGetOwnPropertyDescriptor" => {
                Some(BuiltinFunctionKind::ObjectGetOwnPropertyDescriptor)
            }
            "builtin:ReflectDefineProperty" => Some(BuiltinFunctionKind::ReflectDefineProperty),
            _ => None,
        }
    }

    pub(super) fn descriptor_factory_value(capability: &str) -> Option<Value> {
        let kind = match capability {
            "builtin:ObjectDefinePropertyFunction" => BuiltinFunctionKind::ObjectDefineProperty,
            "builtin:ObjectGetOwnPropertyDescriptorFunction" => {
                BuiltinFunctionKind::ObjectGetOwnPropertyDescriptor
            }
            "builtin:ReflectDefinePropertyFunction" => BuiltinFunctionKind::ReflectDefineProperty,
            _ => return None,
        };
        Some(Value::BuiltinFunction(BuiltinFunction {
            kind,
            module_specifier: String::new(),
            bound_object: None,
        }))
    }

    fn property_descriptor_target(&mut self, value: &Value) -> Result<ObjectId, InterpreterError> {
        match value {
            Value::Object(id) => {
                self.heap
                    .get(id.0 as usize)
                    .ok_or(InterpreterError::ObjectNotFound { id: id.0 })?;
                Ok(*id)
            }
            function if Self::function_object_key(function).is_some() => self
                .ensure_function_object(function)?
                .ok_or_else(|| InterpreterError::TypeError {
                    expected: "object property target".into(),
                    got: function.type_name().into(),
                }),
            other => Err(InterpreterError::TypeError {
                expected: "object property target".into(),
                got: other.type_name().into(),
            }),
        }
    }

    pub(super) fn descriptor_structure_label(&self, object: ObjectId) -> Label {
        self.heap
            .get(object.0 as usize)
            .and_then(|object| object.property_structure_label.clone())
            .unwrap_or(Label::Public)
    }

    pub(super) fn join_descriptor_structure_label(
        &mut self,
        object: ObjectId,
        label: &Label,
    ) -> Result<(), InterpreterError> {
        let previous = self.descriptor_structure_label(object);
        let next = previous.join(label);
        if next == previous {
            return Ok(());
        }
        let previous_bytes = Self::estimate_label_bytes(&previous);
        let next_bytes = Self::estimate_label_bytes(&next);
        self.check_temporary_memory_budget(next_bytes)?;
        self.heap[object.0 as usize].property_structure_label = Some(next);
        self.estimated_memory_bytes = self
            .estimated_memory_bytes
            .saturating_sub(previous_bytes)
            .saturating_add(next_bytes);
        Ok(())
    }

    pub(super) fn observe_property_structure(
        &self,
        object: ObjectId,
        include_prototypes: bool,
    ) -> Label {
        let mut label = Label::Public;
        let mut current = Some(object);
        let mut visited = BTreeSet::new();
        for _ in 0..MAX_PROTOTYPE_CHAIN_DEPTH {
            let Some(id) = current else { break };
            if !visited.insert(id) {
                break;
            }
            let Some(object) = self.heap.get(id.0 as usize) else {
                break;
            };
            if let Some(structure) = &object.property_structure_label {
                label = label.join(structure);
            }
            // Joining provenance does not need an own-key snapshot. Borrow
            // the sparse label carrier so observing a large object cannot
            // allocate an unbudgeted second copy of every property name.
            for property_label in object.property_labels.all_data_values() {
                label = label.join(property_label);
            }
            for (_, property) in object.property_labels.baseline_symbol_properties() {
                if let BaselineSymbolProperty::Data(property_label) = property {
                    label = label.join(property_label);
                }
            }
            current = if include_prototypes {
                object.prototype
            } else {
                None
            };
        }
        label
    }

    /// ES2020 ToPropertyKey, sharing observable native-method coercion.
    pub(super) fn descriptor_property_key(
        &mut self,
        module: &Ir3Module,
        value: Value,
        label: &mut Label,
    ) -> Result<RuntimePropertyKey, InterpreterError> {
        let primitive = self.array_method_to_primitive(module, value, true, label)?;
        let key = match primitive {
            Value::Symbol(symbol) => RuntimePropertyKey::Symbol(symbol),
            Value::Str(key) => RuntimePropertyKey::String(key),
            other => RuntimePropertyKey::String(JsString::from(self.value_to_string(&other))),
        };
        self.validate_executable_property_key(&key)?;
        Ok(key)
    }

    fn descriptor_field(
        &mut self,
        module: &Ir3Module,
        receiver: &Value,
        key: &str,
        label: &mut Label,
    ) -> Result<Option<Value>, InterpreterError> {
        let holder = self.property_descriptor_target(receiver)?;
        let key = RuntimePropertyKey::String(key.into());
        *label = label.join(&self.runtime_property_label(holder, &key));
        if self
            .prototype_chain_lookup_runtime_property(holder, &key)?
            .is_none()
        {
            return Ok(None);
        }
        self.read_iterator_property(module, receiver, &key, label)
            .map(Some)
    }

    /// ES2020 6.2.5.5 reads inherited fields in observable specification order.
    fn read_property_descriptor(
        &mut self,
        module: &Ir3Module,
        receiver: &Value,
        label: &mut Label,
    ) -> Result<PropertyDescriptorFields, InterpreterError> {
        self.property_descriptor_target(receiver)?;
        let mut fields = PropertyDescriptorFields::default();
        for name in [
            "enumerable",
            "configurable",
            "value",
            "writable",
            "get",
            "set",
        ] {
            self.charge_array_method_step()?;
            let value = self.with_array_method_temporary(fields.retained_bytes(), |core| {
                core.descriptor_field(module, receiver, name, label)
            })?;
            match name {
                "enumerable" => fields.enumerable = value.map(|value| value.is_truthy()),
                "configurable" => fields.configurable = value.map(|value| value.is_truthy()),
                "value" => fields.value = value,
                "writable" => fields.writable = value.map(|value| value.is_truthy()),
                "get" | "set" => {
                    if let Some(value) = &value
                        && !matches!(value, Value::Undefined)
                        && !Self::is_sync_callable(value)
                    {
                        return Err(InterpreterError::TypeError {
                            expected: format!("callable or undefined descriptor.{name}"),
                            got: value.type_name().into(),
                        });
                    }
                    if name == "get" {
                        fields.get = value;
                    } else {
                        fields.set = value;
                    }
                }
                _ => unreachable!(),
            }
        }
        if fields.is_accessor() && fields.is_data() {
            return Err(InterpreterError::TypeError {
                expected: "either data or accessor descriptor".into(),
                got: "descriptor mixes value/writable with get/set".into(),
            });
        }
        Ok(fields)
    }

    fn descriptor_same_value(left: &Value, right: &Value) -> bool {
        if matches!(left, Value::Int(_) | Value::Float(_))
            && matches!(right, Value::Int(_) | Value::Float(_))
        {
            let left = Self::coerce_to_float(left).expect("numeric value");
            let right = Self::coerce_to_float(right).expect("numeric value");
            return (left.is_nan() && right.is_nan())
                || (left == right
                    && (left != 0.0 || left.is_sign_negative() == right.is_sign_negative()));
        }
        left == right
    }

    fn descriptor_endpoint(value: Option<Value>) -> Option<Value> {
        value.filter(|value| !matches!(value, Value::Undefined))
    }

    /// ValidateAndApplyPropertyDescriptor compatibility, matching the engine
    /// and ordinary object_model invariants without converting runtime values.
    fn resolve_property_descriptor(
        current: Option<RuntimeProperty>,
        mut attributes: PropertyAttributes,
        fields: PropertyDescriptorFields,
    ) -> Option<(RuntimeProperty, PropertyAttributes)> {
        let Some(current) = current else {
            let property = if fields.is_accessor() {
                RuntimeProperty::Accessor(AccessorProperty {
                    get: Self::descriptor_endpoint(fields.get),
                    set: Self::descriptor_endpoint(fields.set),
                })
            } else {
                RuntimeProperty::Data(fields.value.unwrap_or(Value::Undefined))
            };
            return Some((
                property,
                PropertyAttributes {
                    writable: fields.writable.unwrap_or(false),
                    enumerable: fields.enumerable.unwrap_or(false),
                    configurable: fields.configurable.unwrap_or(false),
                },
            ));
        };
        if !attributes.configurable
            && (fields.configurable == Some(true)
                || fields
                    .enumerable
                    .is_some_and(|value| value != attributes.enumerable))
        {
            return None;
        }
        let property = match current {
            current if !fields.is_data() && !fields.is_accessor() => current,
            RuntimeProperty::Data(value) if fields.is_data() => {
                if !attributes.configurable
                    && !attributes.writable
                    && (fields.writable == Some(true)
                        || fields
                            .value
                            .as_ref()
                            .is_some_and(|new| !Self::descriptor_same_value(new, &value)))
                {
                    return None;
                }
                if let Some(writable) = fields.writable {
                    attributes.writable = writable;
                }
                RuntimeProperty::Data(fields.value.unwrap_or(value))
            }
            RuntimeProperty::Accessor(accessor) if fields.is_accessor() => {
                if !attributes.configurable {
                    let changed = |next: &Option<Value>, current: &Option<Value>| {
                        next.as_ref().is_some_and(|next| {
                            !Self::descriptor_same_value(
                                next,
                                current.as_ref().unwrap_or(&Value::Undefined),
                            )
                        })
                    };
                    if changed(&fields.get, &accessor.get) || changed(&fields.set, &accessor.set) {
                        return None;
                    }
                }
                RuntimeProperty::Accessor(AccessorProperty {
                    get: fields
                        .get
                        .map_or(accessor.get, |value| Self::descriptor_endpoint(Some(value))),
                    set: fields
                        .set
                        .map_or(accessor.set, |value| Self::descriptor_endpoint(Some(value))),
                })
            }
            _ => {
                if !attributes.configurable {
                    return None;
                }
                if fields.is_accessor() {
                    attributes.writable = false;
                    RuntimeProperty::Accessor(AccessorProperty {
                        get: Self::descriptor_endpoint(fields.get),
                        set: Self::descriptor_endpoint(fields.set),
                    })
                } else {
                    attributes.writable = fields.writable.unwrap_or(false);
                    RuntimeProperty::Data(fields.value.unwrap_or(Value::Undefined))
                }
            }
        };
        if let Some(enumerable) = fields.enumerable {
            attributes.enumerable = enumerable;
        }
        if let Some(configurable) = fields.configurable {
            attributes.configurable = configurable;
        }
        Some((property, attributes))
    }

    fn install_resolved_descriptor(
        &mut self,
        object: ObjectId,
        key: RuntimePropertyKey,
        property: RuntimeProperty,
        attributes: PropertyAttributes,
        label: &Label,
    ) -> Result<(), InterpreterError> {
        let default_attributes = if self.heap[object.0 as usize].is_array
            && matches!(&key, RuntimePropertyKey::String(key) if key.as_str() == Some("length"))
        {
            PropertyAttributes::ARRAY_LENGTH
        } else {
            PropertyAttributes::DEFAULT
        };
        if attributes == default_attributes
            && self.descriptor_structure_label(object) == Label::Public
            && *label == Label::Public
            && self.own_stored_runtime_property_label(object, &key) == Label::Public
            && let RuntimeProperty::Data(value) = &property
        {
            self.set_plain_data_runtime_property(object, key.clone(), value.clone())?;
            self.heap[object.0 as usize]
                .property_attributes
                .remove(&key);
            self.estimated_memory_bytes = self.recompute_estimated_memory_bytes();
            return Ok(());
        }
        let current = &self.heap[object.0 as usize];
        let current_bytes = Self::estimate_heap_object_bytes(current);
        self.check_temporary_memory_budget(current_bytes)?;
        let mut projected = current.clone();
        projected.install_runtime_property(&key, property);
        projected.install_property_attributes(key.clone(), attributes);
        let label = label
            .join(&self.own_stored_runtime_property_label(object, &key))
            .join(&self.descriptor_structure_label(object));
        if !matches!(label, Label::Public) {
            projected.property_structure_label = Some(label.clone());
            match &key {
                RuntimePropertyKey::String(key) => {
                    projected.property_labels.insert_exact(key.clone(), label);
                }
                RuntimePropertyKey::Symbol(symbol) => {
                    projected.property_labels.insert_baseline_symbol_property(
                        *symbol,
                        BaselineSymbolProperty::Data(label),
                    );
                }
            }
        }
        let projected_bytes = Self::estimate_heap_object_bytes(&projected);
        self.check_temporary_memory_budget(projected_bytes)?;
        let requested = self
            .estimated_memory_bytes
            .saturating_sub(current_bytes)
            .saturating_add(projected_bytes);
        if requested > self.config.max_total_memory_bytes {
            return Err(self.memory_budget_error(requested, self.heap_object_count_u32()));
        }
        self.heap[object.0 as usize] = projected;
        self.estimated_memory_bytes = requested;
        Ok(())
    }

    pub(super) fn set_own_property_attributes(
        &mut self,
        object: ObjectId,
        key: &RuntimePropertyKey,
        attributes: PropertyAttributes,
    ) -> Result<(), InterpreterError> {
        let property = self.heap[object.0 as usize]
            .own_runtime_property(key)
            .ok_or_else(|| InterpreterError::TypeError {
                expected: "existing own property".into(),
                got: "missing property".into(),
            })?;
        self.install_resolved_descriptor(object, key.clone(), property, attributes, &Label::Public)
    }

    pub(super) fn define_own_property_from_descriptor(
        &mut self,
        object: ObjectId,
        key: RuntimePropertyKey,
        fields: PropertyDescriptorFields,
        label: &Label,
    ) -> Result<bool, InterpreterError> {
        self.validate_executable_property_key(&key)?;
        let current = self
            .heap
            .get(object.0 as usize)
            .ok_or(InterpreterError::ObjectNotFound { id: object.0 })?;
        if current.is_array
            && matches!(&key, RuntimePropertyKey::String(key) if key.as_str() == Some("length"))
            && fields.value.is_some()
        {
            return self.array_length_from_descriptor(object, fields, label);
        }
        let index = match &key {
            RuntimePropertyKey::String(key) => key.as_str().and_then(canonical_array_index),
            _ => None,
        };
        if current.is_array
            && let Some(index) = index
        {
            let length_key = RuntimePropertyKey::String("length".into());
            if u64::from(index) >= u64::from(self.array_like_length(object)?)
                && !current.own_property_attributes(&length_key).writable
            {
                return Ok(false);
            }
        }
        let Some((property, attributes)) = Self::resolve_property_descriptor(
            current.own_runtime_property(&key),
            current.own_property_attributes(&key),
            fields,
        ) else {
            return Ok(false);
        };
        self.install_resolved_descriptor(object, key.clone(), property, attributes, label)?;
        self.grow_array_length_after_own_index_write(object, &key, label)?;
        Ok(true)
    }

    pub(super) fn create_data_property_or_throw(
        &mut self,
        object: ObjectId,
        key: RuntimePropertyKey,
        value: Value,
        label: &Label,
    ) -> Result<(), InterpreterError> {
        if self.define_own_data_runtime_property(object, key, value, label.clone(), true)? {
            Ok(())
        } else {
            Err(Self::property_definition_error())
        }
    }

    pub(super) fn define_own_data_runtime_property(
        &mut self,
        object: ObjectId,
        key: RuntimePropertyKey,
        value: Value,
        label: Label,
        enumerable: bool,
    ) -> Result<bool, InterpreterError> {
        let fields = PropertyDescriptorFields {
            value: Some(value),
            writable: Some(true),
            enumerable: Some(enumerable),
            configurable: Some(true),
            ..Default::default()
        };
        self.define_own_property_from_descriptor(object, key, fields, &label)
    }

    pub(super) fn define_own_accessor_runtime_property(
        &mut self,
        object: ObjectId,
        key: RuntimePropertyKey,
        function: Value,
        kind: AccessorKind,
        label: Label,
        enumerable: bool,
    ) -> Result<bool, InterpreterError> {
        let fields = PropertyDescriptorFields {
            get: (kind == AccessorKind::Get).then(|| function.clone()),
            set: (kind == AccessorKind::Set).then(|| function.clone()),
            enumerable: Some(enumerable),
            configurable: Some(true),
            ..Default::default()
        };
        let current = &self.heap[object.0 as usize];
        let Some((_, attributes)) = Self::resolve_property_descriptor(
            current.own_runtime_property(&key),
            current.own_property_attributes(&key),
            fields,
        ) else {
            return Ok(false);
        };
        self.define_accessor_property(object, key.clone(), function, kind, label)?;
        self.set_own_property_attributes(object, &key, attributes)?;
        Ok(true)
    }

    pub(super) fn set_function_name_from_property_key(
        &mut self,
        function: &Value,
        key: &RuntimePropertyKey,
    ) -> Result<(), InterpreterError> {
        let object = self.property_descriptor_target(function)?;
        self.install_resolved_descriptor(
            object,
            RuntimePropertyKey::String("name".into()),
            RuntimeProperty::Data(Value::Str(self.inferred_method_name(key))),
            PropertyAttributes {
                writable: false,
                enumerable: false,
                configurable: true,
            },
            &Label::Public,
        )
    }

    fn lookup_property_attributes(
        &self,
        object: ObjectId,
        key: &RuntimePropertyKey,
    ) -> Option<PropertyAttributes> {
        let mut current = Some(object);
        let mut visited = BTreeSet::new();
        for _ in 0..MAX_PROTOTYPE_CHAIN_DEPTH {
            let id = current?;
            if !visited.insert(id) {
                return None;
            }
            let object = self.heap.get(id.0 as usize)?;
            if object.contains_own_runtime_property(key) {
                return Some(object.own_property_attributes(key));
            }
            current = object.prototype;
        }
        None
    }

    /// OrdinarySetWithOwnDescriptor. Guest calls complete through the same
    /// isolated, labeled activation used by native array methods. `false`
    /// leaves the strict/sloppy decision to the instruction or builtin caller.
    pub(super) fn set_runtime_property_with_receiver(
        &mut self,
        module: &Ir3Module,
        receiver: Value,
        lookup_object: ObjectId,
        key: RuntimePropertyKey,
        value: Value,
        mut label: Label,
    ) -> Result<bool, InterpreterError> {
        self.run_pre_runtime_property_access_hook(module, lookup_object, &key)?;
        label = label.join(&self.runtime_property_label(lookup_object, &key));
        let property = self.prototype_chain_lookup_runtime_property(lookup_object, &key)?;
        if let Some(RuntimeProperty::Accessor(accessor)) = property {
            let Some(setter) = accessor.set else {
                return Ok(false);
            };
            let (completion, _) = self.invoke_inline_method_call_with_receiver_label(
                module,
                setter,
                receiver,
                label.clone(),
                &[(value, label)],
            )?;
            self.complete_inline_call(completion)?;
            return Ok(true);
        }
        if self
            .lookup_property_attributes(lookup_object, &key)
            .is_some_and(|attributes| !attributes.writable)
        {
            return Ok(false);
        }
        if !receiver.is_object_like() {
            return Ok(false);
        }
        let target = self.property_descriptor_target(&receiver)?;
        // The baseline represents the default Object.prototype.__proto__
        // accessor implicitly. A real own/inherited data property shadows it.
        if property.is_none()
            && matches!(&key, RuntimePropertyKey::String(key) if key.as_str() == Some("__proto__"))
        {
            let prototype = match value {
                Value::Object(id) => Some(id),
                Value::Null => None,
                _ => return Ok(true),
            };
            self.set_array_prototype_metadata(target, prototype)?;
            self.set_function_prototype_metadata(&receiver, target, prototype)?;
            self.heap[target.0 as usize].prototype = prototype;
            self.sync_estimated_memory_bytes()?;
            return Ok(true);
        }
        let current = self.heap[target.0 as usize].own_runtime_property(&key);
        if matches!(current, Some(RuntimeProperty::Accessor(_)))
            || current.is_some()
                && !self.heap[target.0 as usize]
                    .own_property_attributes(&key)
                    .writable
        {
            return Ok(false);
        }
        let mut fields = PropertyDescriptorFields {
            value: Some(value),
            ..Default::default()
        };
        if current.is_none() {
            fields.writable = Some(true);
            fields.enumerable = Some(true);
            fields.configurable = Some(true);
        }
        self.normalize_descriptor_array_length(module, target, &key, &mut fields, &mut label)?;
        let accepted =
            self.define_own_property_from_descriptor(target, key.clone(), fields, &label)?;
        if accepted {
            self.update_defined_function_prototype(&receiver, target, &key)?;
        }
        Ok(accepted)
    }

    pub(super) fn delete_own_runtime_property(
        &mut self,
        object: ObjectId,
        key: &RuntimePropertyKey,
    ) -> Result<bool, InterpreterError> {
        let current = self
            .heap
            .get(object.0 as usize)
            .ok_or(InterpreterError::ObjectNotFound { id: object.0 })?;
        if !current.contains_own_runtime_property(key) {
            return Ok(true);
        }
        if !current.own_property_attributes(key).configurable {
            return Ok(false);
        }
        self.remove_object_runtime_property(object, key)?;
        if let RuntimePropertyKey::String(key) = key {
            self.mark_deleted_for_in_iterators(object, key);
        }
        Ok(true)
    }

    pub(super) fn materialize_function_descriptor(
        &mut self,
        target: &Value,
        holder: ObjectId,
        key: &RuntimePropertyKey,
    ) -> Result<(), InterpreterError> {
        if self.heap[holder.0 as usize].contains_own_runtime_property(key) {
            return Ok(());
        }
        if matches!(key, RuntimePropertyKey::String(key) if key.as_str() == Some("prototype"))
            && let Some(prototype) = self.function_prototype_for_value(target)?
        {
            self.install_resolved_descriptor(
                holder,
                key.clone(),
                RuntimeProperty::Data(Value::Object(prototype)),
                PropertyAttributes {
                    writable: true,
                    enumerable: false,
                    configurable: false,
                },
                &Label::Public,
            )?;
        }
        Ok(())
    }

    fn update_defined_function_prototype(
        &mut self,
        target: &Value,
        holder: ObjectId,
        key: &RuntimePropertyKey,
    ) -> Result<(), InterpreterError> {
        if matches!(key, RuntimePropertyKey::String(key) if key.as_str() == Some("prototype"))
            && let Some(function_key) = self.function_prototype_key_for_value(target)?
            && let Some(RuntimeProperty::Data(Value::Object(prototype))) =
                self.heap[holder.0 as usize].own_runtime_property(key)
        {
            self.function_prototypes.insert(function_key, prototype);
        }
        Ok(())
    }

    pub(super) fn property_definition_error() -> InterpreterError {
        InterpreterError::TypeError {
            expected: "compatible property descriptor".into(),
            got: "non-configurable or non-writable property".into(),
        }
    }

    fn array_length_from_descriptor(
        &mut self,
        object: ObjectId,
        fields: PropertyDescriptorFields,
        label: &Label,
    ) -> Result<bool, InterpreterError> {
        let value = fields.value.as_ref().expect("array length value");
        let number = Self::coerce_to_float(value).unwrap_or(f64::NAN);
        if !number.is_finite()
            || number < 0.0
            || number > f64::from(u32::MAX)
            || number.fract() != 0.0
        {
            return Err(InterpreterError::RangeError {
                message: "Invalid array length".into(),
            });
        }
        let new_length = number as u32;
        let key = RuntimePropertyKey::String("length".into());
        let current = &self.heap[object.0 as usize];
        let attributes = current.own_property_attributes(&key);
        let old_length = self.array_like_length(object)?;
        if fields.is_accessor()
            || fields.configurable == Some(true)
            || fields.enumerable == Some(true)
        {
            return Ok(false);
        }
        if !attributes.writable {
            return Ok(new_length == old_length && fields.writable != Some(true));
        }
        let mut final_length = new_length;
        let mut accepted = true;
        if new_length < old_length {
            self.check_temporary_memory_budget(Self::estimate_heap_object_bytes(current))?;
            let mut keys = current
                .own_exact_property_keys()
                .into_iter()
                .filter_map(|key| {
                    key.as_str()
                        .and_then(canonical_array_index)
                        .map(|index| (index, key))
                })
                .filter(|(index, _)| *index >= new_length)
                .collect::<Vec<_>>();
            keys.sort_by_key(|entry| std::cmp::Reverse(entry.0));
            let bytes = keys
                .iter()
                .map(|(_, key)| {
                    Self::estimate_js_string_bytes(key).saturating_add(std::mem::size_of::<(
                        u32,
                        JsString,
                    )>()
                        as u64)
                })
                .sum();
            self.with_array_method_temporary(bytes, |core| {
                for (index, key) in keys {
                    core.charge_array_method_step()?;
                    let key = RuntimePropertyKey::String(key);
                    if !core.heap[object.0 as usize]
                        .own_property_attributes(&key)
                        .configurable
                    {
                        final_length = index + 1;
                        accepted = false;
                        break;
                    }
                    core.delete_own_runtime_property(object, &key)?;
                }
                Ok(())
            })?;
        }
        self.install_resolved_descriptor(
            object,
            key,
            RuntimeProperty::Data(Value::Int(i64::from(final_length))),
            PropertyAttributes {
                writable: fields.writable.unwrap_or(attributes.writable),
                ..attributes
            },
            label,
        )?;
        Ok(accepted)
    }

    fn normalize_descriptor_array_length(
        &mut self,
        module: &Ir3Module,
        object: ObjectId,
        key: &RuntimePropertyKey,
        fields: &mut PropertyDescriptorFields,
        label: &mut Label,
    ) -> Result<(), InterpreterError> {
        if self.heap[object.0 as usize].is_array
            && matches!(key, RuntimePropertyKey::String(key) if key.as_str() == Some("length"))
            && let Some(value) = fields.value.take()
        {
            let first = self.native_method_to_number(module, value.clone(), label)?;
            let as_uint32 = Self::js_to_int32(first) as u32;
            let second = self.native_method_to_number(module, value, label)?;
            if f64::from(as_uint32) != second {
                return Err(InterpreterError::RangeError {
                    message: "Invalid array length".into(),
                });
            }
            fields.value = Some(Value::Int(i64::from(as_uint32)));
        }
        Ok(())
    }

    pub(super) fn dispatch_descriptor_builtin(
        &mut self,
        module: &Ir3Module,
        kind: BuiltinFunctionKind,
        args: RegRange,
        mut label: Label,
    ) -> Result<(Value, Label), InterpreterError> {
        let value = self.optional_arg(args, 0)?.unwrap_or(Value::Undefined);
        let property_key = self.optional_arg(args, 1)?.unwrap_or(Value::Undefined);
        let descriptor = self.optional_arg(args, 2)?.unwrap_or(Value::Undefined);
        for offset in 0..args.count.min(3) {
            label = label.join(&self.read_reg_label(args.start + offset)?);
        }
        let bytes = [&value, &property_key, &descriptor]
            .into_iter()
            .map(Self::estimate_value_bytes)
            .sum();
        let result = self.with_array_method_temporary(bytes, |core| {
            if kind == BuiltinFunctionKind::ObjectGetOwnPropertyDescriptor
                && !value.is_object_like()
            {
                if value.is_nullish() {
                    return Err(InterpreterError::TypeError {
                        expected: "object-coercible descriptor target".into(),
                        got: value.type_name().into(),
                    });
                }
                let key = core.descriptor_property_key(module, property_key, &mut label)?;
                let property = if let Value::Str(text) = &value {
                    match &key {
                        RuntimePropertyKey::String(key) if key.as_str() == Some("length") => {
                            Some((Value::Int(text.utf16_len() as i64), false))
                        }
                        RuntimePropertyKey::String(key) => key
                            .as_str()
                            .and_then(canonical_array_index)
                            .and_then(|index| text.code_unit_at(index as usize))
                            .map(|unit| (Value::Str(JsString::from_code_units(&[unit])), true)),
                        _ => None,
                    }
                } else {
                    None
                };
                return match property {
                    Some((value, enumerable)) => core.descriptor_object(
                        RuntimeProperty::Data(value),
                        PropertyAttributes {
                            writable: false,
                            enumerable,
                            configurable: false,
                        },
                        &label,
                    ),
                    None => Ok(Value::Undefined),
                };
            }
            // Target validation precedes ToPropertyKey and descriptor getters.
            let object = core.property_descriptor_target(&value)?;
            let key = core.descriptor_property_key(module, property_key, &mut label)?;
            core.run_pre_runtime_property_access_hook(module, object, &key)?;
            core.materialize_function_descriptor(&value, object, &key)?;
            label = label.join(&core.runtime_property_label(object, &key));
            if kind == BuiltinFunctionKind::ObjectGetOwnPropertyDescriptor {
                return match core.heap[object.0 as usize].own_runtime_property(&key) {
                    Some(property) => core.descriptor_object(
                        property,
                        core.heap[object.0 as usize].own_property_attributes(&key),
                        &label,
                    ),
                    None => Ok(Value::Undefined),
                };
            }
            let mut fields = core.read_property_descriptor(module, &descriptor, &mut label)?;
            let retained = fields
                .retained_bytes()
                .saturating_add(Self::estimate_property_key_bytes(&key));
            core.with_array_method_temporary(retained, |core| {
                core.normalize_descriptor_array_length(
                    module,
                    object,
                    &key,
                    &mut fields,
                    &mut label,
                )?;
                let accepted =
                    core.define_own_property_from_descriptor(object, key.clone(), fields, &label)?;
                if accepted {
                    core.update_defined_function_prototype(&value, object, &key)?;
                }
                if kind == BuiltinFunctionKind::ReflectDefineProperty {
                    return Ok(Value::Bool(accepted));
                }
                if !accepted {
                    return Err(Self::property_definition_error());
                }
                Ok(value)
            })
        });
        self.finish_native_builtin_call(result, label)
    }

    fn descriptor_object(
        &mut self,
        property: RuntimeProperty,
        attributes: PropertyAttributes,
        label: &Label,
    ) -> Result<Value, InterpreterError> {
        let object = self.alloc_object_with_prototype(None)?;
        let fields = match property {
            RuntimeProperty::Data(value) => vec![
                ("value", value),
                ("writable", Value::Bool(attributes.writable)),
                ("enumerable", Value::Bool(attributes.enumerable)),
                ("configurable", Value::Bool(attributes.configurable)),
            ],
            RuntimeProperty::Accessor(accessor) => vec![
                ("get", accessor.get.unwrap_or(Value::Undefined)),
                ("set", accessor.set.unwrap_or(Value::Undefined)),
                ("enumerable", Value::Bool(attributes.enumerable)),
                ("configurable", Value::Bool(attributes.configurable)),
            ],
        };
        for (key, value) in fields {
            self.set_plain_data_property(object, key.into(), value)?;
            self.set_own_runtime_property_label(
                object,
                &RuntimePropertyKey::String(key.into()),
                label,
            )?;
        }
        Ok(Value::Object(object))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::Es2020Parser;

    #[test]
    fn descriptor_attribute_budget_refusal_preserves_existing_heap() {
        let mut config = InterpreterConfig::quickjs_defaults();
        config
            .granted_capabilities
            .insert(RuntimeCapability::HeapAllocate);
        let mut core = InterpreterCore::new(config, "descriptor-budget");
        let object = core.alloc_object_with_prototype(None).unwrap();
        core.set_plain_data_property(object, "x".into(), Value::Int(7))
            .unwrap();
        let before = core.heap[object.0 as usize].clone();
        let before_bytes = core.estimated_memory_bytes;
        core.config.max_total_memory_bytes = before_bytes;
        let result = core.define_own_property_from_descriptor(
            object,
            RuntimePropertyKey::String("x".into()),
            PropertyDescriptorFields {
                writable: Some(false),
                ..Default::default()
            },
            &Label::Public,
        );
        assert!(matches!(
            result,
            Err(InterpreterError::MemoryBudgetExceeded { .. })
        ));
        assert_eq!(core.heap[object.0 as usize], before);
        assert_eq!(core.estimated_memory_bytes, before_bytes);
        assert_eq!(
            core.estimated_memory_bytes,
            core.recompute_estimated_memory_bytes()
        );
    }

    #[test]
    fn ordinary_guest_keys_cannot_use_class_accessor_carrier_to_replace_frozen_data() {
        let source = "const object = {}; Object.defineProperty(object, 'x', {value: 1}); object['__franken_ir_accessor_get__:x'] = function() { return 2; }; console.log(object.x, typeof object['__franken_ir_accessor_get__:x']);";
        let tree = CanonicalEs2020Parser
            .parse(source, ParseGoal::Script)
            .unwrap();
        let module = lower_ir0_to_ir3(
            &Ir0Module::from_syntax_tree(tree, "descriptor-prefix"),
            &LoweringContext::new("descriptor", "descriptor", "descriptor"),
        )
        .unwrap()
        .ir3;
        for mut config in [
            InterpreterConfig::quickjs_defaults(),
            InterpreterConfig::v8_defaults(),
        ] {
            config.granted_capabilities.extend([
                RuntimeCapability::VmDispatch,
                RuntimeCapability::HeapAllocate,
            ]);
            let result = InterpreterCore::new(config, "descriptor-prefix")
                .execute(&module)
                .unwrap();
            assert_eq!(result.console_output[0].message, "1 function");
        }
    }
}
