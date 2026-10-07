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
pub(super) const PROTOTYPE_GETTERS: [(&str, &str, &str); 40] = [
    ("Map", "size", "get size"),
    ("Set", "size", "get size"),
    ("ArrayBuffer", "byteLength", "get byteLength"),
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
];

/// The key of %TypedArray%.prototype[@@toStringTag] in [`PROTOTYPE_GETTERS`].
pub(super) const TYPED_ARRAY_TO_STRING_TAG: &str = "@@toStringTag";

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
    pub(super) fn prototype_getter_at(
        &self,
        object: ObjectId,
        key: &RuntimePropertyKey,
    ) -> Option<BuiltinFunction> {
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
    /// one of its accessors.
    pub(super) fn prototype_getter_descriptor(
        &mut self,
        object: ObjectId,
        key: &RuntimePropertyKey,
    ) -> Result<Option<Value>, InterpreterError> {
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
        let descriptor = self.alloc_object_with_properties(&[
            ("get", getter),
            ("set", Value::Undefined),
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
        // ES2020 22.2.3.32: the receiver's [[TypedArrayName]], and undefined
        // (never a TypeError) for anything else (bd-9vouw.155).
        if key == TYPED_ARRAY_TO_STRING_TAG {
            return Ok(match receiver {
                Value::Object(id) => self
                    .heap
                    .get(id.0 as usize)
                    .and_then(|object| object.typed_array.as_ref())
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
                    .and_then(|object| object.primitive_value.as_ref())
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
        // (bd-9vouw.208).
        if owner == "RegExp" && key == "flags" && unbranded {
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
        if owner == "RegExp"
            && let Some(flag) = flag
        {
            let flags = self.prototype_getter_own_slot(module, id, "flags", receiver)?;
            return Ok(Value::Bool(
                matches!(flags, Value::Str(flags) if flags.to_string().contains(flag)),
            ));
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
        self.prototype_getter_own_slot(module, id, key, receiver)
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
            "ArrayBuffer" => object.array_buffer.is_some(),
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
}
