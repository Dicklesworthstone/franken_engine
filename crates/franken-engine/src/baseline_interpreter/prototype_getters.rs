//! Built-in prototype accessors (bd-9vouw.129): `Map.prototype.size`,
//! `ArrayBuffer.prototype.byteLength`, `RegExp.prototype.flags`, ... are
//! accessor properties (ES2020 23.1.3.10, 24.1.4.1, 21.2.5.3, ...). The
//! engine serves the values from each instance, so `map.size` reads, but
//! `Object.getOwnPropertyDescriptor(Map.prototype, 'size')` was undefined.
//! Libraries read these getters to tell built-in types apart; object-inspect
//! takes `Object.getOwnPropertyDescriptor(Map.prototype, 'size').get` and
//! calls it on a candidate Map.
//!
//! Each accessor is described with a getter, a `PrototypeGetter` builtin
//! whose specifier names it (`"Map.size"`). The getter checks its receiver's
//! brand, throwing a TypeError as the spec's internal-slot checks do, and
//! reads the value from the instance.

use super::*;

/// (prototype owner, property key, getter name). A key starting with `@@`
/// names a well-known symbol ([`TYPED_ARRAY_TO_STRING_TAG`]); those accessors
/// are real own properties of the prototype, installed when it is created.
/// The [`SPECIES_GETTER_KEY`] rows are the constructors' own
/// `get [Symbol.species]` (bd-9vouw.278), installed on the constructor.
pub(super) const PROTOTYPE_GETTERS: [(&str, &str, &str); 55] = [
    // Annex B.2.2.1 (bd-9vouw.284): the one accessor here with a setter
    // ([`InterpreterCore::prototype_accessor_setter`]). Ordinary `o.__proto__`
    // reads and writes keep their direct path while they reach it.
    ("Object", "__proto__", "get __proto__"),
    ("Map", "size", "get size"),
    ("Set", "size", "get size"),
    ("ArrayBuffer", "byteLength", "get byteLength"),
    // ES2024 25.1.6 (bd-9vouw.244, bd-9vouw.256); webidl-conversions (under
    // whatwg-url) reads `resizable` when it loads.
    ("ArrayBuffer", "detached", "get detached"),
    ("ArrayBuffer", "maxByteLength", "get maxByteLength"),
    ("ArrayBuffer", "resizable", "get resizable"),
    // ES2020 24.2.4.1, ES2024 25.2.5 (bd-9vouw.244).
    ("SharedArrayBuffer", "byteLength", "get byteLength"),
    ("SharedArrayBuffer", "growable", "get growable"),
    ("SharedArrayBuffer", "maxByteLength", "get maxByteLength"),
    ("DataView", "buffer", "get buffer"),
    ("DataView", "byteLength", "get byteLength"),
    ("DataView", "byteOffset", "get byteOffset"),
    ("TypedArray", "buffer", "get buffer"),
    ("TypedArray", "byteLength", "get byteLength"),
    ("TypedArray", "byteOffset", "get byteOffset"),
    ("TypedArray", "length", "get length"),
    // ES2020 22.2.3.32 (bd-9vouw.155).
    (
        "TypedArray",
        TYPED_ARRAY_TO_STRING_TAG,
        "get [Symbol.toStringTag]",
    ),
    ("RegExp", "dotAll", "get dotAll"),
    ("RegExp", "flags", "get flags"),
    ("RegExp", "global", "get global"),
    ("RegExp", "hasIndices", "get hasIndices"),
    ("RegExp", "ignoreCase", "get ignoreCase"),
    ("RegExp", "multiline", "get multiline"),
    ("RegExp", "source", "get source"),
    ("RegExp", "sticky", "get sticky"),
    ("RegExp", "unicode", "get unicode"),
    ("RegExp", "unicodeSets", "get unicodeSets"),
    ("Symbol", "description", "get description"),
    // DOM events and aborting (bd-9vouw.170).
    ("Event", "type", "get type"),
    ("Event", "bubbles", "get bubbles"),
    ("Event", "cancelable", "get cancelable"),
    ("Event", "composed", "get composed"),
    ("Event", "defaultPrevented", "get defaultPrevented"),
    ("Event", "eventPhase", "get eventPhase"),
    ("Event", "target", "get target"),
    ("Event", "currentTarget", "get currentTarget"),
    ("Event", "srcElement", "get srcElement"),
    ("Event", "timeStamp", "get timeStamp"),
    ("Event", "returnValue", "get returnValue"),
    ("Event", "cancelBubble", "get cancelBubble"),
    ("CustomEvent", "detail", "get detail"),
    ("AbortController", "signal", "get signal"),
    ("AbortSignal", "aborted", "get aborted"),
    ("AbortSignal", "reason", "get reason"),
    // WHATWG File API (bd-9vouw.226).
    ("Blob", "size", "get size"),
    ("Blob", "type", "get type"),
    // `get [Symbol.species]() { return this }` (ES2020 22.1.2.5, 22.2.2.4,
    // 23.1.2.2, 23.2.2.2, 24.1.3.3, 24.2.3.2, 25.6.4.6, 21.2.4.2), owned by
    // the constructor, not its prototype. The concrete typed array
    // constructors inherit %TypedArray%'s.
    ("Array", SPECIES_GETTER_KEY, "get [Symbol.species]"),
    ("ArrayBuffer", SPECIES_GETTER_KEY, "get [Symbol.species]"),
    ("Map", SPECIES_GETTER_KEY, "get [Symbol.species]"),
    ("Promise", SPECIES_GETTER_KEY, "get [Symbol.species]"),
    ("RegExp", SPECIES_GETTER_KEY, "get [Symbol.species]"),
    ("Set", SPECIES_GETTER_KEY, "get [Symbol.species]"),
    (
        "SharedArrayBuffer",
        SPECIES_GETTER_KEY,
        "get [Symbol.species]",
    ),
    ("TypedArray", SPECIES_GETTER_KEY, "get [Symbol.species]"),
];

/// The key of %TypedArray%.prototype[@@toStringTag] in [`PROTOTYPE_GETTERS`].
pub(super) const TYPED_ARRAY_TO_STRING_TAG: &str = "@@toStringTag";

/// The key of a constructor's own `get [Symbol.species]` in
/// [`PROTOTYPE_GETTERS`] (bd-9vouw.278).
pub(super) const SPECIES_GETTER_KEY: &str = "@@species";

/// The table entry a getter's specifier (`"Map.size"`) names.
pub(super) fn prototype_getter_entry(
    specifier: &str,
) -> Option<&'static (&'static str, &'static str, &'static str)> {
    let (owner, key) = specifier.split_once('.')?;
    PROTOTYPE_GETTERS
        .iter()
        .find(|(entry_owner, entry_key, _)| *entry_owner == owner && *entry_key == key)
}

impl BuiltinFunction {
    pub(super) fn prototype_getter(owner: &str, key: &str) -> Self {
        Self {
            kind: BuiltinFunctionKind::PrototypeGetter,
            module_specifier: BuiltinModuleSpecifier::from_nonempty(&format!("{owner}.{key}")),
            iterator_handle: None,
            bound_object: None,
        }
    }
}

impl InterpreterCore {
    /// The getter of accessor `key` when `object` is the prototype of an
    /// owner in PROTOTYPE_GETTERS: [[Get]] and [[HasProperty]] find these
    /// accessors there (`/a/g.global`, `'global' in re`), bd-9vouw.162.
    /// An accessor `delete` removed is gone (bd-9vouw.249).
    pub(super) fn prototype_getter_at(
        &self,
        object: ObjectId,
        key: &RuntimePropertyKey,
    ) -> Option<BuiltinFunction> {
        if self.virtual_own_property_deleted(object, key) {
            return None;
        }
        let RuntimePropertyKey::String(key) = key else {
            return None;
        };
        let key = key.as_str()?;
        PROTOTYPE_GETTERS
            .iter()
            .find(|(owner, entry_key, _)| {
                *entry_key == key
                    && !entry_key.starts_with("@@")
                    && self.builtin_prototypes.get(*owner) == Some(&object)
            })
            .map(|(owner, key, _)| BuiltinFunction::prototype_getter(owner, key))
    }

    /// `{ get, set: undefined, enumerable: false, configurable: true }` when
    /// `object` is the prototype of an owner in PROTOTYPE_GETTERS and `key`
    /// one of its accessors, unless `delete` removed it or a stored property
    /// (a redefinition, bd-9vouw.379) shadows it.
    pub(super) fn prototype_getter_descriptor(
        &mut self,
        object: ObjectId,
        key: &RuntimePropertyKey,
    ) -> Result<Option<Value>, InterpreterError> {
        if self.virtual_own_property_deleted(object, key)
            || self
                .heap
                .get(object.0 as usize)
                .is_some_and(|stored| stored.contains_own_runtime_property(key))
        {
            return Ok(None);
        }
        let RuntimePropertyKey::String(key) = key else {
            return Ok(None);
        };
        let Some(key) = key.as_str() else {
            return Ok(None);
        };
        let Some((owner, key, _)) = PROTOTYPE_GETTERS.iter().find(|(owner, entry_key, _)| {
            *entry_key == key
                && !entry_key.starts_with("@@")
                && self.builtin_prototypes.get(*owner) == Some(&object)
        }) else {
            return Ok(None);
        };
        let getter = Value::BuiltinFunction(BuiltinFunction::prototype_getter(owner, key));
        let setter = Self::prototype_accessor_setter(owner, key).unwrap_or(Value::Undefined);
        let descriptor = self.alloc_object_with_properties(&[
            ("get", getter),
            ("set", setter),
            ("enumerable", Value::Bool(false)),
            ("configurable", Value::Bool(true)),
        ])?;
        Ok(Some(Value::Object(descriptor)))
    }

    /// A `PrototypeGetter` called on `receiver`.
    pub(super) fn call_prototype_getter(
        &mut self,
        module: &Ir3Module,
        builtin: &BuiltinFunction,
        receiver: Value,
    ) -> Result<Value, InterpreterError> {
        let Some(&(owner, key, _)) = builtin
            .module_specifier
            .0
            .as_deref()
            .and_then(prototype_getter_entry)
        else {
            return Err(InterpreterError::TypeError {
                expected: "a known built-in accessor".to_string(),
                got: "unknown accessor".to_string(),
            });
        };
        // `get [Symbol.species]() { return this }`, whatever `this` is.
        if key == SPECIES_GETTER_KEY {
            return Ok(receiver);
        }
        if owner == "Object" {
            return self.object_proto_getter(module, receiver);
        }
        // ES2020 22.2.3.32: the receiver's [[TypedArrayName]], and undefined
        // (never a TypeError) for anything else (bd-9vouw.155).
        if key == TYPED_ARRAY_TO_STRING_TAG {
            return Ok(match receiver {
                Value::Object(id) => self
                    .heap
                    .get(id.0 as usize)
                    .and_then(|object| object.typed_array.as_deref())
                    .map_or(Value::Undefined, |view| Value::str(view.kind.type_name())),
                _ => Value::Undefined,
            });
        }
        let incompatible = || InterpreterError::TypeError {
            expected: format!("{owner} receiver for get {owner}.prototype.{key}"),
            got: receiver.type_name().to_string(),
        };
        if owner == "Symbol" {
            let symbol = match &receiver {
                Value::Symbol(symbol) => *symbol,
                Value::Object(id) => match self
                    .heap
                    .get(id.0 as usize)
                    .and_then(|object| object.primitive_value.as_deref())
                {
                    Some(Value::Symbol(symbol)) => *symbol,
                    _ => return Err(incompatible()),
                },
                _ => return Err(incompatible()),
            };
            return Ok(self
                .symbol_description(symbol)
                .map_or(Value::Undefined, Value::Str));
        }
        // ES2020 21.2.5.3 ff.: on %RegExp.prototype% itself the flag
        // accessors answer undefined, `source` "(?:)" and `flags` "".
        if owner == "RegExp"
            && let Value::Object(id) = &receiver
            && self.builtin_prototypes.get("RegExp") == Some(id)
        {
            return Ok(match key {
                "source" => Value::str("(?:)"),
                "flags" => Value::str(""),
                _ => Value::Undefined,
            });
        }
        let Value::Object(id) = receiver else {
            return Err(incompatible());
        };
        let unbranded =
            self.proxy_record(id)?.is_some() || !self.has_prototype_getter_brand(id, owner);
        // ES2020 21.2.5.4: `flags` is generic. Any object answers through
        // its boolean flag properties, read in this order; the
        // regexp.prototype.flags polyfill (under deep-equal) feature-tests
        // the native getter on a plain object and checks the order
        // (bd-9vouw.208). A RegExp too: an own or prototype override of a
        // flag getter shows in `flags` (bd-9vouw.150 phase 2).
        if owner == "RegExp" && key == "flags" {
            let mut flags = String::new();
            for (letter, name) in [
                ('d', "hasIndices"),
                ('g', "global"),
                ('i', "ignoreCase"),
                ('m', "multiline"),
                ('s', "dotAll"),
                ('u', "unicode"),
                ('v', "unicodeSets"),
                ('y', "sticky"),
            ] {
                let value = self.get_v(
                    module,
                    &Value::Object(id),
                    &RuntimePropertyKey::String(JsString::from(name)),
                )?;
                if value.is_truthy() {
                    flags.push(letter);
                }
            }
            return Ok(Value::str(flags));
        }
        if unbranded {
            return Err(incompatible());
        }
        // A RegExp keeps `source` and `flags`; each boolean flag getter
        // reads its letter from `flags` (ES2020 21.2.5.4, ...).
        let flag = match key {
            "dotAll" => Some('s'),
            "global" => Some('g'),
            "hasIndices" => Some('d'),
            "ignoreCase" => Some('i'),
            "multiline" => Some('m'),
            "sticky" => Some('y'),
            "unicode" => Some('u'),
            "unicodeSets" => Some('v'),
            _ => None,
        };
        // The pattern and flags are engine-private slots (bd-9vouw.150 phase
        // 2).
        if owner == "RegExp" {
            let (source, flags) = self.regexp_source_flags_from_object(id).unwrap_or_default();
            if let Some(flag) = flag {
                return Ok(Value::Bool(flags.contains(flag)));
            }
            if key == "source" {
                return Ok(Value::str(source));
            }
        }
        // A Map's or Set's count is an internal slot (bd-9vouw.140); reading
        // `size` through [[Get]] would come back to this getter.
        if matches!(owner, "Map" | "Set") && key == "size" {
            return Ok(self
                .heap
                .get(id.0 as usize)
                .and_then(|object| object.properties.get(COLLECTION_SIZE_SLOT).cloned())
                .unwrap_or(Value::Int(0)));
        }
        if let Some(value) = self.event_family_getter(owner, key, id) {
            return Ok(value);
        }
        if owner == "Blob"
            && let Some(value) = self.blob_getter(id, key)
        {
            return Ok(value);
        }
        // ES2024 25.1.6.2-4, 25.2.5.2-5 (bd-9vouw.256). A detached buffer's
        // byteLength slot reads 0, which maxByteLength then answers too.
        if matches!(owner, "ArrayBuffer" | "SharedArrayBuffer") {
            let backing = self
                .heap
                .get(id.0 as usize)
                .and_then(|object| object.array_buffer.as_ref());
            let detached = backing.is_some_and(|backing| backing.detached);
            let max_byte_length = backing.and_then(|backing| backing.max_byte_length);
            match key {
                "detached" => return Ok(Value::Bool(detached)),
                "resizable" | "growable" => return Ok(Value::Bool(max_byte_length.is_some())),
                "maxByteLength" => {
                    if let Some(max) = max_byte_length.filter(|_| !detached) {
                        return Ok(Value::Int(i64::try_from(max).unwrap_or(i64::MAX)));
                    }
                    return self.prototype_getter_own_slot(module, id, "byteLength", receiver);
                }
                _ => {}
            }
        }
        // ES2024 25.3.4.2-3: an out-of-bounds DataView's byteLength and
        // byteOffset are a TypeError (a typed array's read 0).
        if owner == "DataView"
            && matches!(key, "byteLength" | "byteOffset")
            && let Some(view) = self
                .heap
                .get(id.0 as usize)
                .and_then(|object| object.data_view.as_ref())
        {
            Self::reject_out_of_bounds_data_view(view, key)?;
        }
        if let Some(value) = self.view_internal_slot(id, owner, key) {
            return Ok(value);
        }
        self.prototype_getter_own_slot(module, id, key, receiver)
    }

    /// A typed array's or DataView's [[ViewedArrayBuffer]], [[ByteOffset]],
    /// [[ByteLength]] and [[ArrayLength]], from the view itself: a program
    /// can redefine the own properties of those names, which the getters
    /// read before, so `get buffer.call(view)` returned the redefinition
    /// (bd-9vouw.320). An out-of-bounds typed array reads 0 for the three
    /// numbers (ES2024 23.2.3); an out-of-bounds DataView was refused above.
    fn view_internal_slot(&self, id: ObjectId, owner: &str, key: &str) -> Option<Value> {
        let object = self.heap.get(id.0 as usize)?;
        let int = |value: usize| Value::Int(i64::try_from(value).unwrap_or(i64::MAX));
        match owner {
            "TypedArray" => {
                let view = object.typed_array.as_ref()?;
                let in_bounds = !view.bounds.is_some_and(|bounds| bounds.out_of_bounds);
                let number = |value: usize| int(if in_bounds { value } else { 0 });
                match key {
                    "buffer" => Some(Value::Object(view.buffer)),
                    "byteLength" => Some(number(view.byte_length)),
                    "byteOffset" => Some(number(view.byte_offset)),
                    "length" => Some(number(view.length)),
                    _ => None,
                }
            }
            "DataView" => {
                let view = object.data_view.as_ref()?;
                match key {
                    "buffer" => Some(Value::Object(view.buffer)),
                    "byteLength" => Some(int(view.byte_length)),
                    "byteOffset" => Some(int(view.byte_offset)),
                    _ => None,
                }
            }
            _ => None,
        }
    }

    /// The receiver's own `key` slot (`flags`, `source`, `byteLength`, ...).
    /// Not its prototype chain: the accessor is found there, so a chain read
    /// of a deleted slot would call this getter again.
    fn prototype_getter_own_slot(
        &mut self,
        module: &Ir3Module,
        id: ObjectId,
        key: &str,
        receiver: Value,
    ) -> Result<Value, InterpreterError> {
        let slot = self
            .heap
            .get(id.0 as usize)
            .ok_or(InterpreterError::ObjectNotFound { id: id.0 })?
            .own_runtime_property_value(&RuntimePropertyKey::String(key.into()));
        match slot {
            Some(value) => self.resolve_accessor_get(Some(module), value, receiver),
            None => Ok(Value::Undefined),
        }
    }

    /// The internal slot each owner's accessors require of their receiver.
    fn has_prototype_getter_brand(&self, id: ObjectId, owner: &str) -> bool {
        let Some(object) = self.heap.get(id.0 as usize) else {
            return false;
        };
        match owner {
            "Map" => self.collection_storage_id(id, "Map", "__entries").is_some(),
            "Set" => self.collection_storage_id(id, "Set", "__values").is_some(),
            "ArrayBuffer" | "SharedArrayBuffer" => {
                object.array_buffer.is_some()
                    && (object.brand() == Some("SharedArrayBuffer"))
                        == (owner == "SharedArrayBuffer")
            }
            "DataView" => object.data_view.is_some(),
            "TypedArray" => object.typed_array.is_some(),
            "RegExp" => self.inspect_internal_type(id).as_deref() == Some("RegExp"),
            "Event" | "CustomEvent" | "AbortController" | "AbortSignal" => {
                self.has_event_family_brand(id, owner)
            }
            "Blob" => object.blob.is_some(),
            _ => false,
        }
    }

    /// The setter of the PROTOTYPE_GETTERS accessor `owner.key`, if it has
    /// one: only `Object.prototype.__proto__` (bd-9vouw.284).
    pub(super) fn prototype_accessor_setter(owner: &str, key: &str) -> Option<Value> {
        (owner == "Object" && key == "__proto__")
            .then(|| Value::BuiltinFunction(BuiltinFunction::object_proto_setter()))
    }

    /// `get Object.prototype.__proto__` (Annex B.2.2.1.1): the
    /// [[GetPrototypeOf]] of ToObject(this). A primitive answers its
    /// intrinsic prototype without allocating a wrapper; undefined and null
    /// are a TypeError (bd-9vouw.284).
    fn object_proto_getter(
        &mut self,
        module: &Ir3Module,
        receiver: Value,
    ) -> Result<Value, InterpreterError> {
        if receiver.is_callable()
            && self
                .iterator_carrier_backing_id(&receiver, "object target")?
                .is_none()
        {
            return self.function_value_prototype(Some(module), &receiver);
        }
        if let Some(name) = self.exotic_intrinsic_prototype_name(&receiver) {
            if let Some(prototype) = self.exotic_prototype_override(module, &receiver)? {
                return Ok(Value::Object(prototype));
            }
            return Ok(Value::Object(self.ensure_builtin_prototype(name)?));
        }
        if receiver.is_object_like() {
            let id = self.reflection_target_object(&receiver)?;
            return Ok(match self.object_get_prototype(Some(module), id, 0)? {
                Value::Object(link) => self.prototype_value_for_link(Some(module), Some(link)),
                other => other,
            });
        }
        let name = match receiver {
            Value::Str(_) => "String",
            Value::Int(_) | Value::Float(_) => "Number",
            Value::Bool(_) => "Boolean",
            Value::BigInt(_) => "BigInt",
            Value::Symbol(_) => "Symbol",
            other => {
                return Err(InterpreterError::TypeError {
                    expected: "an object-coercible this for Object.prototype.__proto__".to_string(),
                    got: other.type_name().to_string(),
                });
            }
        };
        Ok(Value::Object(self.ensure_builtin_prototype(name)?))
    }

    /// `set Object.prototype.__proto__` (Annex B.2.2.1.2): undefined and
    /// null receivers are a TypeError; a proposed value that is neither an
    /// object nor null, or a primitive receiver, changes nothing; otherwise
    /// [[SetPrototypeOf]], whose refusal (a cycle, a non-extensible object,
    /// Object.prototype's immutable prototype) is a TypeError
    /// (bd-9vouw.284).
    pub(super) fn object_proto_setter_call(
        &mut self,
        module: Option<&Ir3Module>,
        receiver: Value,
        proto: Value,
    ) -> Result<Value, InterpreterError> {
        if matches!(receiver, Value::Undefined | Value::Null) {
            return Err(InterpreterError::TypeError {
                expected: "an object-coercible this for Object.prototype.__proto__".to_string(),
                got: receiver.type_name().to_string(),
            });
        }
        let Some(link) = self.prototype_link_for_value(module, &proto)? else {
            return Ok(Value::Undefined);
        };
        if !receiver.is_object_like() {
            return Ok(Value::Undefined);
        }
        let accepted = if receiver.is_callable()
            && self
                .iterator_carrier_backing_id(&receiver, "object target")?
                .is_none()
        {
            self.set_function_value_prototype(module, &receiver, &proto)?
        } else {
            let id = self.reflection_target_object(&receiver)?;
            self.object_set_prototype(module, id, link, 0)?
        };
        if !accepted {
            return Err(InterpreterError::TypeError {
                expected: "a permitted __proto__ change".to_string(),
                got: "a cyclic or refused prototype".to_string(),
            });
        }
        Ok(Value::Undefined)
    }
}
