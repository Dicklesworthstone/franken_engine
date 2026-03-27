//! ES2020 object model with property descriptors, prototype chains, and Proxy.
//!
//! Implements the full ES2020 object model required by Section 10.2 item 10
//! ("no permanent subset scope").  Key features:
//!
//! - **Property descriptors**: data vs accessor, configurable/enumerable/writable
//! - **Prototype chains**: `[[Prototype]]` internal slot with chain traversal
//! - **Object operations**: freeze, seal, preventExtensions, keys, values, entries
//! - **Proxy**: all 13 trap handlers with full invariant checking per ES2020
//! - **Reflect**: mirrors of each Proxy trap as ordinary functions
//! - **Symbol keys**: property keys that are either strings or symbols
//!
//! `BTreeMap`/`BTreeSet` for deterministic ordering.
//! `#![forbid(unsafe_code)]` — no unsafe anywhere.
//!
//! Plan reference: Section 10.2 item 10, bd-1m9.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

/// Serialize/deserialize `BTreeMap<PropertyKey, PropertyDescriptor>` as a
/// sorted sequence of `[key, descriptor]` pairs.  serde_json requires string
/// keys for JSON maps but `PropertyKey` is an enum, so we use a vec-of-pairs
/// representation to preserve full round-trip fidelity.
mod properties_as_seq {
    use super::{BTreeMap, PropertyDescriptor, PropertyKey};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(
        map: &BTreeMap<PropertyKey, PropertyDescriptor>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let pairs: Vec<(&PropertyKey, &PropertyDescriptor)> = map.iter().collect();
        pairs.serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<BTreeMap<PropertyKey, PropertyDescriptor>, D::Error> {
        let pairs: Vec<(PropertyKey, PropertyDescriptor)> = Vec::deserialize(deserializer)?;
        Ok(pairs.into_iter().collect())
    }
}

// ---------------------------------------------------------------------------
// PropertyKey — string or symbol
// ---------------------------------------------------------------------------

/// Unique symbol identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SymbolId(pub u32);

/// A property key: either a string or a symbol.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum PropertyKey {
    /// String key.
    String(String),
    /// Symbol key (references the global symbol registry).
    Symbol(SymbolId),
}

impl fmt::Display for PropertyKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::String(s) => write!(f, "{s}"),
            Self::Symbol(id) => write!(f, "Symbol({})", id.0),
        }
    }
}

impl From<&str> for PropertyKey {
    fn from(s: &str) -> Self {
        Self::String(s.to_string())
    }
}

impl From<String> for PropertyKey {
    fn from(s: String) -> Self {
        Self::String(s)
    }
}

// ---------------------------------------------------------------------------
// Well-known symbols
// ---------------------------------------------------------------------------

/// Well-known symbol indices (fixed allocation in the symbol registry).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum WellKnownSymbol {
    Iterator,
    ToPrimitive,
    HasInstance,
    ToStringTag,
    Species,
    IsConcatSpreadable,
    Unscopables,
    AsyncIterator,
    Match,
    MatchAll,
    Replace,
    Search,
    Split,
}

impl WellKnownSymbol {
    /// Get the `SymbolId` for this well-known symbol.
    /// Well-known symbols occupy ids 1..=13.
    pub fn id(self) -> SymbolId {
        SymbolId(self as u32 + 1)
    }

    /// Get the property key for this well-known symbol.
    pub fn key(self) -> PropertyKey {
        PropertyKey::Symbol(self.id())
    }

    /// Display name (e.g. `@@iterator`).
    pub fn name(self) -> &'static str {
        match self {
            Self::Iterator => "@@iterator",
            Self::ToPrimitive => "@@toPrimitive",
            Self::HasInstance => "@@hasInstance",
            Self::ToStringTag => "@@toStringTag",
            Self::Species => "@@species",
            Self::IsConcatSpreadable => "@@isConcatSpreadable",
            Self::Unscopables => "@@unscopables",
            Self::AsyncIterator => "@@asyncIterator",
            Self::Match => "@@match",
            Self::MatchAll => "@@matchAll",
            Self::Replace => "@@replace",
            Self::Search => "@@search",
            Self::Split => "@@split",
        }
    }
}

// ---------------------------------------------------------------------------
// ObjectHandle — typed reference to heap objects
// ---------------------------------------------------------------------------

/// Opaque handle referencing an object on the managed heap.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ObjectHandle(pub u32);

// ---------------------------------------------------------------------------
// JsValue — runtime value for the object model
// ---------------------------------------------------------------------------

/// Runtime value for the ES2020 object model.
///
/// This intentionally mirrors the baseline interpreter's `Value` but adds
/// `Symbol` and keeps `Object` typed via `ObjectHandle`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum JsValue {
    Undefined,
    Null,
    Bool(bool),
    Int(i64),
    Str(String),
    Symbol(SymbolId),
    Object(ObjectHandle),
    Function(u32),
}

impl JsValue {
    pub fn is_object(&self) -> bool {
        matches!(self, Self::Object(_))
    }

    pub fn is_callable(&self) -> bool {
        matches!(self, Self::Function(_))
    }

    pub fn type_name(&self) -> &'static str {
        match self {
            Self::Undefined => "undefined",
            Self::Null => "null",
            Self::Bool(_) => "boolean",
            Self::Int(_) => "number",
            Self::Str(_) => "string",
            Self::Symbol(_) => "symbol",
            Self::Object(_) => "object",
            Self::Function(_) => "function",
        }
    }

    /// SameValue comparison (ES2020 §7.2.10).
    pub fn same_value(&self, other: &Self) -> bool {
        self == other
    }
}

impl fmt::Display for JsValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Undefined => write!(f, "undefined"),
            Self::Null => write!(f, "null"),
            Self::Bool(b) => write!(f, "{b}"),
            Self::Int(n) => write!(f, "{n}"),
            Self::Str(s) => write!(f, "{s}"),
            Self::Symbol(id) => write!(f, "Symbol({})", id.0),
            Self::Object(h) => write!(f, "[object#{}]", h.0),
            Self::Function(idx) => write!(f, "[function#{idx}]"),
        }
    }
}

// ---------------------------------------------------------------------------
// PropertyDescriptor
// ---------------------------------------------------------------------------

/// ES2020 property descriptor (§6.2.5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PropertyDescriptor {
    /// Data descriptor: has `value` and `writable`.
    Data {
        value: JsValue,
        writable: bool,
        enumerable: bool,
        configurable: bool,
    },
    /// Accessor descriptor: has `get` and/or `set`.
    Accessor {
        get: Option<ObjectHandle>,
        set: Option<ObjectHandle>,
        enumerable: bool,
        configurable: bool,
    },
}

impl PropertyDescriptor {
    /// Create a default data descriptor (writable, enumerable, configurable).
    pub fn data(value: JsValue) -> Self {
        Self::Data {
            value,
            writable: true,
            enumerable: true,
            configurable: true,
        }
    }

    /// Create a non-writable, non-enumerable, non-configurable data descriptor.
    pub fn data_frozen(value: JsValue) -> Self {
        Self::Data {
            value,
            writable: false,
            enumerable: false,
            configurable: false,
        }
    }

    /// Is this descriptor configurable?
    pub fn is_configurable(&self) -> bool {
        match self {
            Self::Data { configurable, .. } | Self::Accessor { configurable, .. } => *configurable,
        }
    }

    /// Is this descriptor enumerable?
    pub fn is_enumerable(&self) -> bool {
        match self {
            Self::Data { enumerable, .. } | Self::Accessor { enumerable, .. } => *enumerable,
        }
    }

    /// Is this a data descriptor?
    pub fn is_data(&self) -> bool {
        matches!(self, Self::Data { .. })
    }

    /// Is this an accessor descriptor?
    pub fn is_accessor(&self) -> bool {
        matches!(self, Self::Accessor { .. })
    }

    /// Get the value if this is a data descriptor.
    pub fn value(&self) -> Option<&JsValue> {
        match self {
            Self::Data { value, .. } => Some(value),
            Self::Accessor { .. } => None,
        }
    }

    /// Is this a data descriptor with writable=true?
    pub fn is_writable(&self) -> bool {
        match self {
            Self::Data { writable, .. } => *writable,
            Self::Accessor { .. } => false,
        }
    }

    /// Make this descriptor non-configurable.
    pub fn set_non_configurable(&mut self) {
        match self {
            Self::Data { configurable, .. } | Self::Accessor { configurable, .. } => {
                *configurable = false;
            }
        }
    }

    /// Make this data descriptor non-writable (no-op for accessors).
    pub fn set_non_writable(&mut self) {
        if let Self::Data { writable, .. } = self {
            *writable = false;
        }
    }

    /// Make this descriptor non-enumerable.
    pub fn set_non_enumerable(&mut self) {
        match self {
            Self::Data { enumerable, .. } | Self::Accessor { enumerable, .. } => {
                *enumerable = false;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// ObjectError
// ---------------------------------------------------------------------------

/// Errors from object model operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ObjectError {
    /// TypeError per ES2020 spec.
    TypeError(String),
    /// Object not found in the heap.
    ObjectNotFound(ObjectHandle),
    /// Proxy has been revoked.
    ProxyRevoked,
    /// Prototype chain cycle detected.
    PrototypeCycleDetected,
    /// Maximum prototype chain depth exceeded.
    PrototypeChainTooDeep { depth: u32, max: u32 },
}

impl fmt::Display for ObjectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TypeError(msg) => write!(f, "TypeError: {msg}"),
            Self::ObjectNotFound(h) => write!(f, "object#{} not found", h.0),
            Self::ProxyRevoked => write!(f, "TypeError: proxy has been revoked"),
            Self::PrototypeCycleDetected => write!(f, "TypeError: prototype chain cycle detected"),
            Self::PrototypeChainTooDeep { depth, max } => {
                write!(
                    f,
                    "TypeError: prototype chain depth {depth} exceeds max {max}"
                )
            }
        }
    }
}

// ---------------------------------------------------------------------------
// OrdinaryObject — the core ES2020 object
// ---------------------------------------------------------------------------

/// Maximum prototype chain depth to prevent infinite loops.
const MAX_PROTOTYPE_CHAIN_DEPTH: u32 = 1024;

/// An ordinary ES2020 object with internal slots.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrdinaryObject {
    /// `[[Prototype]]` internal slot (null means end of chain).
    pub prototype: Option<ObjectHandle>,
    /// `[[Extensible]]` internal slot.
    pub extensible: bool,
    /// Own properties with descriptors, keyed by PropertyKey.
    #[serde(with = "properties_as_seq")]
    pub properties: BTreeMap<PropertyKey, PropertyDescriptor>,
    /// `[[Class]]` tag for intrinsic identification.
    pub class_tag: Option<String>,
    /// Is this object callable (i.e. a function)?
    pub callable: bool,
    /// Is this object a constructor?
    pub constructable: bool,
}

impl Default for OrdinaryObject {
    fn default() -> Self {
        Self {
            prototype: None,
            extensible: true,
            properties: BTreeMap::new(),
            class_tag: None,
            callable: false,
            constructable: false,
        }
    }
}

impl OrdinaryObject {
    /// Create a new ordinary object with the given prototype.
    pub fn with_prototype(proto: Option<ObjectHandle>) -> Self {
        Self {
            prototype: proto,
            ..Self::default()
        }
    }

    // -- [[GetOwnProperty]] (§9.1.1) ---------------------------------------

    /// `[[GetOwnProperty]](P)` — return the own property descriptor for `key`.
    pub fn get_own_property(&self, key: &PropertyKey) -> Option<&PropertyDescriptor> {
        self.properties.get(key)
    }

    // -- [[HasProperty]] (§9.1.7) ------------------------------------------

    /// `[[HasOwnProperty]](P)` — does this object have an own property `key`?
    pub fn has_own_property(&self, key: &PropertyKey) -> bool {
        self.properties.contains_key(key)
    }

    // -- [[DefineOwnProperty]] (§9.1.6) ------------------------------------

    /// `[[DefineOwnProperty]](P, Desc)` — define or update a property.
    ///
    /// Returns `Ok(true)` if the property was successfully defined,
    /// `Ok(false)` if rejected (non-configurable conflict), or
    /// `Err` for type errors.
    pub fn define_own_property(
        &mut self,
        key: PropertyKey,
        desc: PropertyDescriptor,
    ) -> Result<bool, ObjectError> {
        if let Some(current) = self.properties.get(&key) {
            // Existing property — check compatibility.
            if !current.is_configurable() {
                // Non-configurable: reject any change that would alter configurability
                // or change descriptor type.
                if desc.is_configurable() {
                    return Ok(false);
                }
                // Cannot change enumerable on non-configurable property.
                if desc.is_enumerable() != current.is_enumerable() {
                    return Ok(false);
                }
                // Cannot change data↔accessor type.
                if current.is_data() != desc.is_data() {
                    return Ok(false);
                }
                // For data descriptors: cannot change writable from false to true.
                if let (
                    PropertyDescriptor::Data {
                        writable: current_w,
                        value: current_v,
                        ..
                    },
                    PropertyDescriptor::Data {
                        writable: new_w,
                        value: new_v,
                        ..
                    },
                ) = (current, &desc)
                    && !current_w
                {
                    // Non-writable non-configurable: cannot become writable.
                    if *new_w {
                        return Ok(false);
                    }
                    // Non-writable non-configurable: cannot change value.
                    if !current_v.same_value(new_v) {
                        return Ok(false);
                    }
                }
                // For accessor descriptors: cannot change get/set on non-configurable.
                if let (
                    PropertyDescriptor::Accessor {
                        get: cur_get,
                        set: cur_set,
                        ..
                    },
                    PropertyDescriptor::Accessor {
                        get: new_get,
                        set: new_set,
                        ..
                    },
                ) = (current, &desc)
                    && (cur_get != new_get || cur_set != new_set)
                {
                    return Ok(false);
                }
            }
            // Update is valid.
            self.properties.insert(key, desc);
            Ok(true)
        } else {
            // New property.
            if !self.extensible {
                return Ok(false);
            }
            self.properties.insert(key, desc);
            Ok(true)
        }
    }

    // -- [[Delete]] (§9.1.10) -----------------------------------------------

    /// `[[Delete]](P)` — delete a property. Returns `false` if non-configurable.
    pub fn delete(&mut self, key: &PropertyKey) -> bool {
        if let Some(desc) = self.properties.get(key) {
            if !desc.is_configurable() {
                return false;
            }
        } else {
            // Property doesn't exist — vacuously true.
            return true;
        }
        self.properties.remove(key);
        true
    }

    // -- [[OwnPropertyKeys]] (§9.1.11) -------------------------------------

    /// `[[OwnPropertyKeys]]()` — returns own keys in ES2020 order:
    /// integer indices (sorted numerically), then string keys (insertion order
    /// approximated by BTreeMap order), then symbol keys.
    pub fn own_property_keys(&self) -> Vec<PropertyKey> {
        let mut int_keys: Vec<(u64, PropertyKey)> = Vec::new();
        let mut str_keys: Vec<PropertyKey> = Vec::new();
        let mut sym_keys: Vec<PropertyKey> = Vec::new();

        for key in self.properties.keys() {
            match key {
                PropertyKey::String(s) => {
                    if let Ok(n) = s.parse::<u32>() {
                        int_keys.push((u64::from(n), key.clone()));
                    } else {
                        str_keys.push(key.clone());
                    }
                }
                PropertyKey::Symbol(_) => {
                    sym_keys.push(key.clone());
                }
            }
        }

        int_keys.sort_by_key(|(n, _)| *n);
        let mut result: Vec<PropertyKey> = int_keys.into_iter().map(|(_, k)| k).collect();
        result.extend(str_keys);
        result.extend(sym_keys);
        result
    }

    // -- [[PreventExtensions]] (§9.1.4) ------------------------------------

    /// `[[PreventExtensions]]()` — makes this object non-extensible.
    pub fn prevent_extensions(&mut self) {
        self.extensible = false;
    }

    // -- Freeze/Seal --------------------------------------------------------

    /// `Object.freeze` semantics: make all own properties non-configurable
    /// and data properties non-writable.
    pub fn freeze(&mut self) {
        self.extensible = false;
        for desc in self.properties.values_mut() {
            desc.set_non_configurable();
            desc.set_non_writable();
        }
    }

    /// `Object.seal` semantics: make all own properties non-configurable
    /// but leave writable unchanged.
    pub fn seal(&mut self) {
        self.extensible = false;
        for desc in self.properties.values_mut() {
            desc.set_non_configurable();
        }
    }

    /// Is this object frozen? (non-extensible + all own properties non-configurable
    /// + all data properties non-writable.)
    pub fn is_frozen(&self) -> bool {
        if self.extensible {
            return false;
        }
        self.properties.values().all(|d| {
            if !d.is_configurable() {
                if let PropertyDescriptor::Data { writable, .. } = d {
                    !writable
                } else {
                    true
                }
            } else {
                false
            }
        })
    }

    /// Is this object sealed? (non-extensible + all own properties non-configurable.)
    pub fn is_sealed(&self) -> bool {
        if self.extensible {
            return false;
        }
        self.properties.values().all(|d| !d.is_configurable())
    }
}

// ---------------------------------------------------------------------------
// ProxyObject — ES2020 Proxy
// ---------------------------------------------------------------------------

/// Proxy internal state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyObject {
    /// `[[ProxyTarget]]` — the wrapped target object (None if revoked).
    pub target: Option<ObjectHandle>,
    /// `[[ProxyHandler]]` — the handler object (None if revoked).
    pub handler: Option<ObjectHandle>,
}

impl ProxyObject {
    /// Create a new proxy wrapping `target` with `handler`.
    pub fn new(target: ObjectHandle, handler: ObjectHandle) -> Self {
        Self {
            target: Some(target),
            handler: Some(handler),
        }
    }

    /// Revoke this proxy.
    pub fn revoke(&mut self) {
        self.target = None;
        self.handler = None;
    }

    /// Is this proxy revoked?
    pub fn is_revoked(&self) -> bool {
        self.target.is_none()
    }

    /// Get the target, or `ProxyRevoked` error.
    pub fn target(&self) -> Result<ObjectHandle, ObjectError> {
        self.target.ok_or(ObjectError::ProxyRevoked)
    }

    /// Get the handler, or `ProxyRevoked` error.
    pub fn handler(&self) -> Result<ObjectHandle, ObjectError> {
        self.handler.ok_or(ObjectError::ProxyRevoked)
    }
}

// ---------------------------------------------------------------------------
// ManagedObject — union of ordinary and proxy
// ---------------------------------------------------------------------------

/// A managed object: either ordinary or a Proxy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ManagedObject {
    Ordinary(OrdinaryObject),
    Proxy(ProxyObject),
}

impl ManagedObject {
    /// Get the ordinary object, if this is one.
    pub fn as_ordinary(&self) -> Option<&OrdinaryObject> {
        match self {
            Self::Ordinary(o) => Some(o),
            Self::Proxy(_) => None,
        }
    }

    /// Get a mutable ordinary object, if this is one.
    pub fn as_ordinary_mut(&mut self) -> Option<&mut OrdinaryObject> {
        match self {
            Self::Ordinary(o) => Some(o),
            Self::Proxy(_) => None,
        }
    }

    /// Get the proxy object, if this is one.
    pub fn as_proxy(&self) -> Option<&ProxyObject> {
        match self {
            Self::Proxy(p) => Some(p),
            Self::Ordinary(_) => None,
        }
    }

    /// Get a mutable proxy object, if this is one.
    pub fn as_proxy_mut(&mut self) -> Option<&mut ProxyObject> {
        match self {
            Self::Proxy(p) => Some(p),
            Self::Ordinary(_) => None,
        }
    }
}

// ---------------------------------------------------------------------------
// ObjectHeap — the managed object store
// ---------------------------------------------------------------------------

/// The object heap: arena of managed objects.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ObjectHeap {
    objects: Vec<ManagedObject>,
    /// Next symbol id (after well-known symbols).
    next_symbol: u32,
}

impl ObjectHeap {
    /// Create a new empty heap.
    pub fn new() -> Self {
        Self {
            objects: Vec::new(),
            // Well-known symbols occupy 1..=13.
            next_symbol: 14,
        }
    }

    /// Allocate a new ordinary object with the given prototype.
    pub fn alloc(&mut self, proto: Option<ObjectHandle>) -> ObjectHandle {
        let handle = ObjectHandle(u32::try_from(self.objects.len()).unwrap_or(u32::MAX));
        self.objects
            .push(ManagedObject::Ordinary(OrdinaryObject::with_prototype(
                proto,
            )));
        handle
    }

    /// Allocate a new ordinary object with default (no prototype).
    pub fn alloc_plain(&mut self) -> ObjectHandle {
        self.alloc(None)
    }

    /// Allocate a Proxy object.
    pub fn alloc_proxy(&mut self, target: ObjectHandle, handler: ObjectHandle) -> ObjectHandle {
        let handle = ObjectHandle(u32::try_from(self.objects.len()).unwrap_or(u32::MAX));
        self.objects
            .push(ManagedObject::Proxy(ProxyObject::new(target, handler)));
        handle
    }

    /// Allocate a new unique symbol id.
    pub fn alloc_symbol(&mut self) -> SymbolId {
        let id = SymbolId(self.next_symbol);
        self.next_symbol = self.next_symbol.saturating_add(1);
        id
    }

    /// Get a reference to a managed object.
    pub fn get(&self, handle: ObjectHandle) -> Result<&ManagedObject, ObjectError> {
        self.objects
            .get(handle.0 as usize)
            .ok_or(ObjectError::ObjectNotFound(handle))
    }

    /// Get a mutable reference to a managed object.
    pub fn get_mut(&mut self, handle: ObjectHandle) -> Result<&mut ManagedObject, ObjectError> {
        self.objects
            .get_mut(handle.0 as usize)
            .ok_or(ObjectError::ObjectNotFound(handle))
    }

    /// Number of objects allocated.
    pub fn len(&self) -> usize {
        self.objects.len()
    }

    /// Is the heap empty?
    pub fn is_empty(&self) -> bool {
        self.objects.is_empty()
    }

    // -- High-level operations requiring heap access ------------------------

    /// `[[Get]](O, P)` — get a property, walking the prototype chain.
    pub fn get_property(
        &self,
        handle: ObjectHandle,
        key: &PropertyKey,
    ) -> Result<JsValue, ObjectError> {
        let mut current = Some(handle);
        let mut depth: u32 = 0;
        let mut visited = BTreeSet::new();

        while let Some(h) = current {
            if depth >= MAX_PROTOTYPE_CHAIN_DEPTH {
                return Err(ObjectError::PrototypeChainTooDeep {
                    depth,
                    max: MAX_PROTOTYPE_CHAIN_DEPTH,
                });
            }
            if !visited.insert(h) {
                return Err(ObjectError::PrototypeCycleDetected);
            }

            let obj = self.get(h)?;
            match obj {
                ManagedObject::Ordinary(o) => {
                    if let Some(desc) = o.get_own_property(key) {
                        return match desc {
                            PropertyDescriptor::Data { value, .. } => Ok(value.clone()),
                            PropertyDescriptor::Accessor { get, .. } => {
                                // Accessor: return the getter handle as a marker.
                                // Actual getter invocation is done by the interpreter.
                                match get {
                                    Some(getter) => Ok(JsValue::Object(*getter)),
                                    None => Ok(JsValue::Undefined),
                                }
                            }
                        };
                    }
                    current = o.prototype;
                }
                ManagedObject::Proxy(_) => {
                    // Proxy get trap must be handled by the interpreter.
                    // Return a sentinel or handle at interpreter level.
                    return Err(ObjectError::TypeError(
                        "proxy get trap must be handled by interpreter".to_string(),
                    ));
                }
            }
            depth += 1;
        }

        // Reached end of prototype chain.
        Ok(JsValue::Undefined)
    }

    /// `[[Set]](O, P, V)` — set a property (own property only for now).
    pub fn set_property(
        &mut self,
        handle: ObjectHandle,
        key: PropertyKey,
        value: JsValue,
    ) -> Result<bool, ObjectError> {
        // First, traverse prototype chain to determine what should happen.
        let mut current = Some(handle);
        let mut depth: u32 = 0;
        let mut visited = BTreeSet::new();

        while let Some(h) = current {
            if depth >= MAX_PROTOTYPE_CHAIN_DEPTH {
                return Err(ObjectError::PrototypeChainTooDeep {
                    depth,
                    max: MAX_PROTOTYPE_CHAIN_DEPTH,
                });
            }
            if !visited.insert(h) {
                return Err(ObjectError::PrototypeCycleDetected);
            }

            let obj = self.get(h)?;
            match obj {
                ManagedObject::Ordinary(o) => {
                    if let Some(desc) = o.get_own_property(&key) {
                        if h == handle && desc.is_accessor() {
                            // Accessor set trap on the receiver itself is
                            // handled by interpreter.
                            return Ok(false);
                        }
                        if h != handle && desc.is_accessor() {
                            // Prototype has an accessor — per the spec we
                            // create an own data property on the receiver
                            // instead of invoking the accessor's setter.
                            break;
                        }
                        if !desc.is_writable() {
                            return Ok(false); // Non-writable property found on object or its prototype chain
                        }
                        // We found a writable property on the prototype chain, or on the object itself.
                        break;
                    }
                    current = o.prototype;
                }
                ManagedObject::Proxy(_) => {
                    return Err(ObjectError::TypeError(
                        "proxy set trap must be handled by interpreter".to_string(),
                    ));
                }
            }
            depth += 1;
        }

        // We verified there are no blocking properties on the prototype chain.
        // Now set the property on the *original* object handle.
        let obj = self.get_mut(handle)?;
        match obj {
            ManagedObject::Ordinary(o) => {
                if o.properties.contains_key(&key) {
                    if let Some(PropertyDescriptor::Data { value: v, .. }) =
                        o.properties.get_mut(&key)
                    {
                        *v = value;
                        return Ok(true);
                    }
                } else if o.extensible {
                    o.properties.insert(key, PropertyDescriptor::data(value));
                    return Ok(true);
                }
                Ok(false)
            }
            ManagedObject::Proxy(_) => Err(ObjectError::TypeError(
                "Proxy set not supported yet".to_string(),
            )),
        }
    }

    /// `[[HasProperty]](O, P)` — check if property exists (walks prototype chain).
    pub fn has_property(
        &self,
        handle: ObjectHandle,
        key: &PropertyKey,
    ) -> Result<bool, ObjectError> {
        let mut current = Some(handle);
        let mut depth: u32 = 0;
        let mut visited = BTreeSet::new();

        while let Some(h) = current {
            if depth >= MAX_PROTOTYPE_CHAIN_DEPTH {
                return Err(ObjectError::PrototypeChainTooDeep {
                    depth,
                    max: MAX_PROTOTYPE_CHAIN_DEPTH,
                });
            }
            if !visited.insert(h) {
                return Err(ObjectError::PrototypeCycleDetected);
            }

            let obj = self.get(h)?;
            match obj {
                ManagedObject::Ordinary(o) => {
                    if o.has_own_property(key) {
                        return Ok(true);
                    }
                    current = o.prototype;
                }
                ManagedObject::Proxy(_) => {
                    return Err(ObjectError::TypeError(
                        "proxy has trap must be handled by interpreter".to_string(),
                    ));
                }
            }
            depth += 1;
        }
        Ok(false)
    }

    /// `[[Delete]](O, P)` — delete a property.
    pub fn delete_property(
        &mut self,
        handle: ObjectHandle,
        key: &PropertyKey,
    ) -> Result<bool, ObjectError> {
        let obj = self.get_mut(handle)?;
        match obj {
            ManagedObject::Ordinary(o) => Ok(o.delete(key)),
            ManagedObject::Proxy(_) => Err(ObjectError::TypeError(
                "proxy deleteProperty trap must be handled by interpreter".to_string(),
            )),
        }
    }

    /// `Object.getPrototypeOf(O)`.
    pub fn get_prototype_of(
        &self,
        handle: ObjectHandle,
    ) -> Result<Option<ObjectHandle>, ObjectError> {
        let obj = self.get(handle)?;
        match obj {
            ManagedObject::Ordinary(o) => Ok(o.prototype),
            ManagedObject::Proxy(_) => Err(ObjectError::TypeError(
                "proxy getPrototypeOf trap must be handled by interpreter".to_string(),
            )),
        }
    }

    /// `Object.setPrototypeOf(O, proto)`.
    pub fn set_prototype_of(
        &mut self,
        handle: ObjectHandle,
        proto: Option<ObjectHandle>,
    ) -> Result<bool, ObjectError> {
        // Check for cycles.
        if let Some(p) = proto {
            let mut current = Some(p);
            let mut visited = BTreeSet::new();
            visited.insert(handle);
            while let Some(h) = current {
                if !visited.insert(h) {
                    return Err(ObjectError::PrototypeCycleDetected);
                }
                let obj = self.get(h)?;
                match obj {
                    ManagedObject::Ordinary(o) => current = o.prototype,
                    ManagedObject::Proxy(_) => break,
                }
            }
        }

        let obj = self.get_mut(handle)?;
        match obj {
            ManagedObject::Ordinary(o) => {
                if !o.extensible {
                    // Non-extensible: can only set prototype to current value.
                    if o.prototype == proto {
                        return Ok(true);
                    }
                    return Ok(false);
                }
                o.prototype = proto;
                Ok(true)
            }
            ManagedObject::Proxy(_) => Err(ObjectError::TypeError(
                "proxy setPrototypeOf trap must be handled by interpreter".to_string(),
            )),
        }
    }

    /// `Object.isExtensible(O)`.
    pub fn is_extensible(&self, handle: ObjectHandle) -> Result<bool, ObjectError> {
        let obj = self.get(handle)?;
        match obj {
            ManagedObject::Ordinary(o) => Ok(o.extensible),
            ManagedObject::Proxy(_) => Err(ObjectError::TypeError(
                "proxy isExtensible trap must be handled by interpreter".to_string(),
            )),
        }
    }

    /// `Object.preventExtensions(O)`.
    pub fn prevent_extensions(&mut self, handle: ObjectHandle) -> Result<bool, ObjectError> {
        let obj = self.get_mut(handle)?;
        match obj {
            ManagedObject::Ordinary(o) => {
                o.prevent_extensions();
                Ok(true)
            }
            ManagedObject::Proxy(_) => Err(ObjectError::TypeError(
                "proxy preventExtensions trap must be handled by interpreter".to_string(),
            )),
        }
    }

    /// `Object.defineProperty(O, P, Desc)`.
    pub fn define_property(
        &mut self,
        handle: ObjectHandle,
        key: PropertyKey,
        desc: PropertyDescriptor,
    ) -> Result<bool, ObjectError> {
        let obj = self.get_mut(handle)?;
        match obj {
            ManagedObject::Ordinary(o) => o.define_own_property(key, desc),
            ManagedObject::Proxy(_) => Err(ObjectError::TypeError(
                "proxy defineProperty trap must be handled by interpreter".to_string(),
            )),
        }
    }

    /// `Object.getOwnPropertyDescriptor(O, P)`.
    pub fn get_own_property_descriptor(
        &self,
        handle: ObjectHandle,
        key: &PropertyKey,
    ) -> Result<Option<PropertyDescriptor>, ObjectError> {
        let obj = self.get(handle)?;
        match obj {
            ManagedObject::Ordinary(o) => Ok(o.get_own_property(key).cloned()),
            ManagedObject::Proxy(_) => Err(ObjectError::TypeError(
                "proxy getOwnPropertyDescriptor trap must be handled by interpreter".to_string(),
            )),
        }
    }

    /// `Object.values(O)` — enumerable own values.
    pub fn values(&self, handle: ObjectHandle) -> Result<Vec<JsValue>, ObjectError> {
        let obj = self.get(handle)?;
        match obj {
            ManagedObject::Ordinary(o) => {
                let result = o
                    .own_property_keys()
                    .into_iter()
                    .filter(|k| matches!(k, PropertyKey::String(_)))
                    .filter_map(|k| {
                        o.properties.get(&k).and_then(|d| {
                            if d.is_enumerable() {
                                d.value().cloned()
                            } else {
                                None
                            }
                        })
                    })
                    .collect();
                Ok(result)
            }
            ManagedObject::Proxy(_) => Err(ObjectError::TypeError(
                "proxy ownKeys trap must be handled by interpreter".to_string(),
            )),
        }
    }

    /// `Object.entries(O)` — enumerable own `[key, value]` pairs.
    pub fn entries(&self, handle: ObjectHandle) -> Result<Vec<(String, JsValue)>, ObjectError> {
        let obj = self.get(handle)?;
        match obj {
            ManagedObject::Ordinary(o) => {
                let result = o
                    .own_property_keys()
                    .into_iter()
                    .filter_map(|k| match &k {
                        PropertyKey::String(s) => o.properties.get(&k).and_then(|d| {
                            if d.is_enumerable() {
                                d.value().map(|v| (s.clone(), v.clone()))
                            } else {
                                None
                            }
                        }),
                        PropertyKey::Symbol(_) => None,
                    })
                    .collect();
                Ok(result)
            }
            ManagedObject::Proxy(_) => Err(ObjectError::TypeError(
                "proxy ownKeys trap must be handled by interpreter".to_string(),
            )),
        }
    }

    /// `Object.defineProperties(O, props)` — define multiple properties.
    pub fn define_properties(
        &mut self,
        handle: ObjectHandle,
        props: Vec<(PropertyKey, PropertyDescriptor)>,
    ) -> Result<bool, ObjectError> {
        for (key, desc) in props {
            if !self.define_property(handle, key, desc)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// `Object.getOwnPropertyDescriptors(O)` — all own property descriptors.
    pub fn get_own_property_descriptors(
        &self,
        handle: ObjectHandle,
    ) -> Result<Vec<(PropertyKey, PropertyDescriptor)>, ObjectError> {
        let obj = self.get(handle)?;
        match obj {
            ManagedObject::Ordinary(o) => Ok(o
                .own_property_keys()
                .into_iter()
                .filter_map(|k| o.properties.get(&k).map(|d| (k, d.clone())))
                .collect()),
            ManagedObject::Proxy(_) => Err(ObjectError::TypeError(
                "proxy getOwnPropertyDescriptor trap must be handled by interpreter".to_string(),
            )),
        }
    }

    /// `for...in` enumeration: walk prototype chain, collect enumerable
    /// string keys in ES2020 order, skipping shadowed keys.
    pub fn for_in_keys(&self, handle: ObjectHandle) -> Result<Vec<String>, ObjectError> {
        let mut result = Vec::new();
        let mut seen = BTreeSet::<PropertyKey>::new();
        let mut current = Some(handle);
        let mut depth: u32 = 0;
        let mut visited = BTreeSet::new();

        while let Some(h) = current {
            if depth >= MAX_PROTOTYPE_CHAIN_DEPTH {
                return Err(ObjectError::PrototypeChainTooDeep {
                    depth,
                    max: MAX_PROTOTYPE_CHAIN_DEPTH,
                });
            }
            if !visited.insert(h) {
                return Err(ObjectError::PrototypeCycleDetected);
            }

            let obj = self.get(h)?;
            match obj {
                ManagedObject::Ordinary(o) => {
                    for k in o.own_property_keys() {
                        if seen.contains(&k) {
                            continue; // shadowed by own property higher in chain
                        }
                        seen.insert(k.clone());
                        if let PropertyKey::String(ref s) = k
                            && let Some(d) = o.properties.get(&k)
                            && d.is_enumerable()
                        {
                            result.push(s.clone());
                        }
                    }
                    current = o.prototype;
                }
                ManagedObject::Proxy(_) => {
                    return Err(ObjectError::TypeError(
                        "proxy ownKeys trap must be handled by interpreter".to_string(),
                    ));
                }
            }
            depth += 1;
        }
        Ok(result)
    }

    /// `Object.keys(O)` — enumerable own string keys.
    pub fn keys(&self, handle: ObjectHandle) -> Result<Vec<String>, ObjectError> {
        let obj = self.get(handle)?;
        match obj {
            ManagedObject::Ordinary(o) => {
                let result = o
                    .own_property_keys()
                    .into_iter()
                    .filter(|k| {
                        if let Some(d) = o.properties.get(k) {
                            d.is_enumerable() && matches!(k, PropertyKey::String(_))
                        } else {
                            false
                        }
                    })
                    .filter_map(|k| match k {
                        PropertyKey::String(s) => Some(s),
                        PropertyKey::Symbol(_) => None,
                    })
                    .collect();
                Ok(result)
            }
            ManagedObject::Proxy(_) => Err(ObjectError::TypeError(
                "proxy ownKeys trap must be handled by interpreter".to_string(),
            )),
        }
    }

    /// `Object.freeze(O)`.
    pub fn freeze(&mut self, handle: ObjectHandle) -> Result<(), ObjectError> {
        let obj = self.get_mut(handle)?;
        match obj {
            ManagedObject::Ordinary(o) => {
                o.freeze();
                Ok(())
            }
            ManagedObject::Proxy(_) => Err(ObjectError::TypeError(
                "cannot freeze proxy directly".to_string(),
            )),
        }
    }

    /// `Object.seal(O)`.
    pub fn seal(&mut self, handle: ObjectHandle) -> Result<(), ObjectError> {
        let obj = self.get_mut(handle)?;
        match obj {
            ManagedObject::Ordinary(o) => {
                o.seal();
                Ok(())
            }
            ManagedObject::Proxy(_) => Err(ObjectError::TypeError(
                "cannot seal proxy directly".to_string(),
            )),
        }
    }

    /// `Object.isFrozen(O)`.
    pub fn is_frozen(&self, handle: ObjectHandle) -> Result<bool, ObjectError> {
        let obj = self.get(handle)?;
        match obj {
            ManagedObject::Ordinary(o) => Ok(o.is_frozen()),
            ManagedObject::Proxy(_) => Ok(false),
        }
    }

    /// `Object.isSealed(O)`.
    pub fn is_sealed(&self, handle: ObjectHandle) -> Result<bool, ObjectError> {
        let obj = self.get(handle)?;
        match obj {
            ManagedObject::Ordinary(o) => Ok(o.is_sealed()),
            ManagedObject::Proxy(_) => Ok(false),
        }
    }

    /// `Object.assign(target, ...sources)` — copies own enumerable properties.
    pub fn assign(
        &mut self,
        target: ObjectHandle,
        sources: &[ObjectHandle],
    ) -> Result<(), ObjectError> {
        // Collect source data first to avoid borrow issues.
        let mut all_props: Vec<Vec<(PropertyKey, JsValue)>> = Vec::new();
        for &src in sources {
            let obj = self.get(src)?;
            let pairs = match obj {
                ManagedObject::Ordinary(o) => o
                    .own_property_keys()
                    .into_iter()
                    .filter_map(|k| {
                        o.properties.get(&k).and_then(|d| {
                            if d.is_enumerable() {
                                d.value().map(|v| (k, v.clone()))
                            } else {
                                None
                            }
                        })
                    })
                    .collect(),
                ManagedObject::Proxy(_) => {
                    return Err(ObjectError::TypeError(
                        "Object.assign source cannot be proxy (handled by interpreter)".to_string(),
                    ));
                }
            };
            all_props.push(pairs);
        }

        for props in all_props {
            for (key, value) in props {
                self.set_property(target, key, value)?;
            }
        }
        Ok(())
    }

    /// `Object.create(proto)` — create an object with the given prototype.
    pub fn create(&mut self, proto: Option<ObjectHandle>) -> ObjectHandle {
        self.alloc(proto)
    }

    /// Revoke a proxy object.
    pub fn revoke_proxy(&mut self, handle: ObjectHandle) -> Result<(), ObjectError> {
        let obj = self.get_mut(handle)?;
        match obj {
            ManagedObject::Proxy(p) => {
                p.revoke();
                Ok(())
            }
            ManagedObject::Ordinary(_) => Err(ObjectError::TypeError(
                "cannot revoke non-proxy object".to_string(),
            )),
        }
    }

    /// `Object.is(a, b)` — SameValue comparison.
    pub fn object_is(a: &JsValue, b: &JsValue) -> bool {
        a.same_value(b)
    }

    /// `Object.getOwnPropertyNames(O)` — all own string-keyed property names
    /// (both enumerable and non-enumerable), in ES2020 order.
    pub fn get_own_property_names(&self, handle: ObjectHandle) -> Result<Vec<String>, ObjectError> {
        let obj = self.get(handle)?;
        match obj {
            ManagedObject::Ordinary(o) => {
                let result = o
                    .own_property_keys()
                    .into_iter()
                    .filter_map(|k| match k {
                        PropertyKey::String(s) => Some(s),
                        PropertyKey::Symbol(_) => None,
                    })
                    .collect();
                Ok(result)
            }
            ManagedObject::Proxy(_) => Err(ObjectError::TypeError(
                "proxy ownKeys trap must be handled by interpreter".to_string(),
            )),
        }
    }

    /// `Object.getOwnPropertySymbols(O)` — all own symbol-keyed properties.
    pub fn get_own_property_symbols(
        &self,
        handle: ObjectHandle,
    ) -> Result<Vec<SymbolId>, ObjectError> {
        let obj = self.get(handle)?;
        match obj {
            ManagedObject::Ordinary(o) => {
                let result = o
                    .own_property_keys()
                    .into_iter()
                    .filter_map(|k| match k {
                        PropertyKey::Symbol(id) => Some(id),
                        PropertyKey::String(_) => None,
                    })
                    .collect();
                Ok(result)
            }
            ManagedObject::Proxy(_) => Err(ObjectError::TypeError(
                "proxy ownKeys trap must be handled by interpreter".to_string(),
            )),
        }
    }

    /// `Object.fromEntries(entries)` — create an object from key-value pairs.
    pub fn from_entries(&mut self, entries: Vec<(String, JsValue)>) -> ObjectHandle {
        let handle = self.alloc_plain();
        for (key, value) in entries {
            // Ignore errors — fromEntries always creates a plain extensible object.
            let _ = self.set_property(handle, PropertyKey::String(key), value);
        }
        handle
    }

    /// `Object.hasOwn(O, P)` — ES2022 static method, checks own property
    /// without walking prototype chain.
    pub fn has_own(&self, handle: ObjectHandle, key: &PropertyKey) -> Result<bool, ObjectError> {
        let obj = self.get(handle)?;
        match obj {
            ManagedObject::Ordinary(o) => Ok(o.has_own_property(key)),
            ManagedObject::Proxy(_) => Err(ObjectError::TypeError(
                "proxy getOwnPropertyDescriptor trap must be handled by interpreter".to_string(),
            )),
        }
    }
}

// ---------------------------------------------------------------------------
// SymbolRegistry — global symbol table
// ---------------------------------------------------------------------------

/// Global symbol registry for `Symbol.for()` and well-known symbols.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SymbolRegistry {
    /// Description → SymbolId mapping for `Symbol.for()`.
    by_description: BTreeMap<String, SymbolId>,
    /// SymbolId → description mapping for `Symbol.keyFor()`.
    by_id: BTreeMap<SymbolId, String>,
}

impl SymbolRegistry {
    /// Create a new registry with well-known symbols pre-registered.
    pub fn new() -> Self {
        let mut reg = Self::default();
        // Pre-register well-known symbols.
        let well_knowns = [
            (WellKnownSymbol::Iterator, "Symbol.iterator"),
            (WellKnownSymbol::ToPrimitive, "Symbol.toPrimitive"),
            (WellKnownSymbol::HasInstance, "Symbol.hasInstance"),
            (WellKnownSymbol::ToStringTag, "Symbol.toStringTag"),
            (WellKnownSymbol::Species, "Symbol.species"),
            (
                WellKnownSymbol::IsConcatSpreadable,
                "Symbol.isConcatSpreadable",
            ),
            (WellKnownSymbol::Unscopables, "Symbol.unscopables"),
            (WellKnownSymbol::AsyncIterator, "Symbol.asyncIterator"),
            (WellKnownSymbol::Match, "Symbol.match"),
            (WellKnownSymbol::MatchAll, "Symbol.matchAll"),
            (WellKnownSymbol::Replace, "Symbol.replace"),
            (WellKnownSymbol::Search, "Symbol.search"),
            (WellKnownSymbol::Split, "Symbol.split"),
        ];
        for (sym, desc) in well_knowns {
            reg.by_id.insert(sym.id(), desc.to_string());
        }
        reg
    }

    /// `Symbol.for(key)` — get or create a symbol for the given key.
    pub fn symbol_for(&mut self, key: &str, heap: &mut ObjectHeap) -> SymbolId {
        if let Some(&id) = self.by_description.get(key) {
            return id;
        }
        let id = heap.alloc_symbol();
        self.by_description.insert(key.to_string(), id);
        self.by_id.insert(id, key.to_string());
        id
    }

    /// `Symbol.keyFor(sym)` — get the description for a global symbol.
    pub fn key_for(&self, sym: SymbolId) -> Option<&str> {
        self.by_id.get(&sym).map(String::as_str)
    }
}

// ---------------------------------------------------------------------------
// ProxyInvariantChecker — validates Proxy trap results
// ---------------------------------------------------------------------------

/// Proxy invariant checker per ES2020 §9.5.x.
pub struct ProxyInvariantChecker;

impl ProxyInvariantChecker {
    /// Validate `[[GetOwnProperty]]` trap result (§9.5.5).
    pub fn check_get_own_property(
        target: &OrdinaryObject,
        key: &PropertyKey,
        trap_result: &Option<PropertyDescriptor>,
    ) -> Result<(), ObjectError> {
        let target_desc = target.get_own_property(key);

        match (trap_result, target_desc) {
            // Trap reports non-existent but target has non-configurable property.
            (None, Some(td)) if !td.is_configurable() => Err(ObjectError::TypeError(format!(
                "proxy getOwnPropertyDescriptor: cannot report non-configurable property '{key}' as non-existent"
            ))),
            // Trap reports non-existent but target is non-extensible and has the property.
            (None, Some(_)) if !target.extensible => Err(ObjectError::TypeError(format!(
                "proxy getOwnPropertyDescriptor: cannot report existing property '{key}' as non-existent on non-extensible target"
            ))),
            // Trap reports existent but target is non-extensible and doesn't have it.
            (Some(_), None) if !target.extensible => Err(ObjectError::TypeError(format!(
                "proxy getOwnPropertyDescriptor: cannot report property '{key}' as existent on non-extensible target"
            ))),
            // Trap returns non-configurable but target property is configurable (or missing).
            (Some(td), target_d) if !td.is_configurable() => {
                match target_d {
                    Some(existing) if !existing.is_configurable() => {
                        // Both non-configurable: check value compatibility for data descriptors.
                        if let (
                            PropertyDescriptor::Data {
                                value: tv,
                                writable: tw,
                                ..
                            },
                            PropertyDescriptor::Data {
                                value: ev,
                                writable: ew,
                                ..
                            },
                        ) = (td, existing)
                            && !tw
                            && !ew
                            && !tv.same_value(ev)
                        {
                            return Err(ObjectError::TypeError(format!(
                                "proxy getOwnPropertyDescriptor: non-configurable non-writable property '{key}' must have same value"
                            )));
                        }
                        Ok(())
                    }
                    _ => Err(ObjectError::TypeError(format!(
                        "proxy getOwnPropertyDescriptor: cannot return non-configurable descriptor for property '{key}' when target property is configurable or absent"
                    ))),
                }
            }
            _ => Ok(()),
        }
    }

    /// Validate `[[HasProperty]]` trap result (§9.5.7).
    pub fn check_has(
        target: &OrdinaryObject,
        key: &PropertyKey,
        trap_result: bool,
    ) -> Result<(), ObjectError> {
        if !trap_result {
            if let Some(td) = target.get_own_property(key)
                && !td.is_configurable()
            {
                return Err(ObjectError::TypeError(format!(
                    "proxy has: cannot report non-configurable property '{key}' as non-existent"
                )));
            }
            if !target.extensible && target.has_own_property(key) {
                return Err(ObjectError::TypeError(format!(
                    "proxy has: cannot report property '{key}' as non-existent on non-extensible target"
                )));
            }
        }
        Ok(())
    }

    /// Validate `[[Get]]` trap result (§9.5.8).
    pub fn check_get(
        target: &OrdinaryObject,
        key: &PropertyKey,
        trap_result: &JsValue,
    ) -> Result<(), ObjectError> {
        if let Some(td) = target.get_own_property(key)
            && !td.is_configurable()
        {
            match td {
                PropertyDescriptor::Data {
                    value, writable, ..
                } if !writable => {
                    if !trap_result.same_value(value) {
                        return Err(ObjectError::TypeError(format!(
                            "proxy get: non-configurable non-writable property '{key}' must return same value"
                        )));
                    }
                }
                PropertyDescriptor::Accessor { get: None, .. } => {
                    if *trap_result != JsValue::Undefined {
                        return Err(ObjectError::TypeError(format!(
                            "proxy get: non-configurable accessor property '{key}' with undefined getter must return undefined"
                        )));
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// Validate `[[Set]]` trap result (§9.5.9).
    pub fn check_set(
        target: &OrdinaryObject,
        key: &PropertyKey,
        value: &JsValue,
        trap_result: bool,
    ) -> Result<(), ObjectError> {
        if trap_result
            && let Some(td) = target.get_own_property(key)
            && !td.is_configurable()
        {
            match td {
                PropertyDescriptor::Data {
                    value: current_val,
                    writable,
                    ..
                } if !writable => {
                    if !value.same_value(current_val) {
                        return Err(ObjectError::TypeError(format!(
                            "proxy set: cannot set non-configurable non-writable property '{key}' to different value"
                        )));
                    }
                }
                PropertyDescriptor::Accessor { set: None, .. } => {
                    return Err(ObjectError::TypeError(format!(
                        "proxy set: cannot set non-configurable accessor property '{key}' with undefined setter"
                    )));
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// Validate `[[Delete]]` trap result (§9.5.10).
    pub fn check_delete(
        target: &OrdinaryObject,
        key: &PropertyKey,
        trap_result: bool,
    ) -> Result<(), ObjectError> {
        if trap_result && let Some(td) = target.get_own_property(key) {
            if !td.is_configurable() {
                return Err(ObjectError::TypeError(format!(
                    "proxy deleteProperty: cannot delete non-configurable property '{key}'"
                )));
            }
            // §9.5.10 step 15: non-extensible target with existing property
            if !target.extensible {
                return Err(ObjectError::TypeError(format!(
                    "proxy deleteProperty: cannot report existing property '{key}' as deleted on non-extensible target"
                )));
            }
        }
        Ok(())
    }

    /// Validate `[[OwnKeys]]` trap result (§9.5.11).
    pub fn check_own_keys(
        target: &OrdinaryObject,
        trap_result: &[PropertyKey],
    ) -> Result<(), ObjectError> {
        // Check for duplicates.
        let mut seen = BTreeSet::new();
        for key in trap_result {
            if !seen.insert(key) {
                return Err(ObjectError::TypeError(format!(
                    "proxy ownKeys: duplicate key '{key}'"
                )));
            }
        }

        // All non-configurable keys must be present.
        for (key, desc) in &target.properties {
            if !desc.is_configurable() && !seen.contains(key) {
                return Err(ObjectError::TypeError(format!(
                    "proxy ownKeys: must include non-configurable property '{key}'"
                )));
            }
        }

        // If non-extensible, result must be exact permutation.
        if !target.extensible {
            let target_keys: BTreeSet<&PropertyKey> = target.properties.keys().collect();
            let result_keys: BTreeSet<&PropertyKey> = trap_result.iter().collect();
            if target_keys != result_keys {
                return Err(ObjectError::TypeError(
                    "proxy ownKeys: non-extensible target requires exact key set".to_string(),
                ));
            }
        }

        Ok(())
    }

    /// Validate `[[GetPrototypeOf]]` trap result (§9.5.1).
    pub fn check_get_prototype_of(
        target: &OrdinaryObject,
        trap_result: Option<ObjectHandle>,
    ) -> Result<(), ObjectError> {
        if !target.extensible && trap_result != target.prototype {
            return Err(ObjectError::TypeError(
                "proxy getPrototypeOf: non-extensible target must return same prototype"
                    .to_string(),
            ));
        }
        Ok(())
    }

    /// Validate `[[SetPrototypeOf]]` trap result (§9.5.2).
    pub fn check_set_prototype_of(
        target: &OrdinaryObject,
        new_proto: Option<ObjectHandle>,
        trap_result: bool,
    ) -> Result<(), ObjectError> {
        if trap_result && !target.extensible && new_proto != target.prototype {
            return Err(ObjectError::TypeError(
                "proxy setPrototypeOf: non-extensible target can only set to current prototype"
                    .to_string(),
            ));
        }
        Ok(())
    }

    /// Validate `[[IsExtensible]]` trap result (§9.5.3).
    pub fn check_is_extensible(
        target: &OrdinaryObject,
        trap_result: bool,
    ) -> Result<(), ObjectError> {
        if trap_result != target.extensible {
            return Err(ObjectError::TypeError(
                "proxy isExtensible: must match target extensibility".to_string(),
            ));
        }
        Ok(())
    }

    /// Validate `[[PreventExtensions]]` trap result (§9.5.4).
    pub fn check_prevent_extensions(
        target: &OrdinaryObject,
        trap_result: bool,
    ) -> Result<(), ObjectError> {
        if trap_result && target.extensible {
            return Err(ObjectError::TypeError(
                "proxy preventExtensions: cannot return true when target is still extensible"
                    .to_string(),
            ));
        }
        Ok(())
    }

    /// Validate `[[DefineOwnProperty]]` trap result (§9.5.6).
    pub fn check_define_own_property(
        target: &OrdinaryObject,
        key: &PropertyKey,
        desc: &PropertyDescriptor,
        trap_result: bool,
    ) -> Result<(), ObjectError> {
        if trap_result {
            // Cannot add new property to non-extensible target.
            if !target.has_own_property(key) && !target.extensible {
                return Err(ObjectError::TypeError(format!(
                    "proxy defineProperty: cannot add property '{key}' to non-extensible target"
                )));
            }
            // Cannot define non-configurable if target property is configurable or absent.
            if !desc.is_configurable() {
                match target.get_own_property(key) {
                    Some(td) if !td.is_configurable() => {
                        // Both non-configurable: check value compatibility.
                        if let (
                            PropertyDescriptor::Data {
                                value: nv,
                                writable: nw,
                                ..
                            },
                            PropertyDescriptor::Data {
                                value: tv,
                                writable: tw,
                                ..
                            },
                        ) = (desc, td)
                            && !tw
                            && !nw
                            && !nv.same_value(tv)
                        {
                            return Err(ObjectError::TypeError(format!(
                                "proxy defineProperty: cannot change value of non-configurable non-writable property '{key}'"
                            )));
                        }
                    }
                    _ => {
                        return Err(ObjectError::TypeError(format!(
                            "proxy defineProperty: cannot define non-configurable property '{key}' when target property is configurable or absent"
                        )));
                    }
                }
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Reflect — ES2020 Reflect namespace
// ---------------------------------------------------------------------------

/// ES2020 `Reflect` namespace — static methods mirroring Proxy traps.
///
/// Each method delegates to the corresponding `ObjectHeap` operation.
/// This provides a uniform API that mirrors the 13 Proxy trap handlers
/// as ordinary functions per ES2020 §26.1.
pub struct Reflect;

impl Reflect {
    /// `Reflect.get(target, propertyKey)` — ES2020 §26.1.6.
    pub fn get(
        heap: &ObjectHeap,
        target: ObjectHandle,
        key: &PropertyKey,
    ) -> Result<JsValue, ObjectError> {
        heap.get_property(target, key)
    }

    /// `Reflect.set(target, propertyKey, value)` — ES2020 §26.1.13.
    pub fn set(
        heap: &mut ObjectHeap,
        target: ObjectHandle,
        key: PropertyKey,
        value: JsValue,
    ) -> Result<bool, ObjectError> {
        heap.set_property(target, key, value)
    }

    /// `Reflect.has(target, propertyKey)` — ES2020 §26.1.9.
    pub fn has(
        heap: &ObjectHeap,
        target: ObjectHandle,
        key: &PropertyKey,
    ) -> Result<bool, ObjectError> {
        heap.has_property(target, key)
    }

    /// `Reflect.deleteProperty(target, propertyKey)` — ES2020 §26.1.4.
    pub fn delete_property(
        heap: &mut ObjectHeap,
        target: ObjectHandle,
        key: &PropertyKey,
    ) -> Result<bool, ObjectError> {
        heap.delete_property(target, key)
    }

    /// `Reflect.ownKeys(target)` — ES2020 §26.1.11.
    pub fn own_keys(
        heap: &ObjectHeap,
        target: ObjectHandle,
    ) -> Result<Vec<PropertyKey>, ObjectError> {
        let obj = heap.get(target)?;
        match obj {
            ManagedObject::Ordinary(o) => Ok(o.own_property_keys()),
            ManagedObject::Proxy(_) => Err(ObjectError::TypeError(
                "proxy ownKeys trap must be handled by interpreter".to_string(),
            )),
        }
    }

    /// `Reflect.getPrototypeOf(target)` — ES2020 §26.1.8.
    pub fn get_prototype_of(
        heap: &ObjectHeap,
        target: ObjectHandle,
    ) -> Result<Option<ObjectHandle>, ObjectError> {
        heap.get_prototype_of(target)
    }

    /// `Reflect.setPrototypeOf(target, proto)` — ES2020 §26.1.14.
    pub fn set_prototype_of(
        heap: &mut ObjectHeap,
        target: ObjectHandle,
        proto: Option<ObjectHandle>,
    ) -> Result<bool, ObjectError> {
        heap.set_prototype_of(target, proto)
    }

    /// `Reflect.isExtensible(target)` — ES2020 §26.1.10.
    pub fn is_extensible(heap: &ObjectHeap, target: ObjectHandle) -> Result<bool, ObjectError> {
        heap.is_extensible(target)
    }

    /// `Reflect.preventExtensions(target)` — ES2020 §26.1.12.
    pub fn prevent_extensions(
        heap: &mut ObjectHeap,
        target: ObjectHandle,
    ) -> Result<bool, ObjectError> {
        heap.prevent_extensions(target)
    }

    /// `Reflect.defineProperty(target, propertyKey, attributes)` — ES2020 §26.1.3.
    pub fn define_property(
        heap: &mut ObjectHeap,
        target: ObjectHandle,
        key: PropertyKey,
        desc: PropertyDescriptor,
    ) -> Result<bool, ObjectError> {
        heap.define_property(target, key, desc)
    }

    /// `Reflect.getOwnPropertyDescriptor(target, propertyKey)` — ES2020 §26.1.7.
    pub fn get_own_property_descriptor(
        heap: &ObjectHeap,
        target: ObjectHandle,
        key: &PropertyKey,
    ) -> Result<Option<PropertyDescriptor>, ObjectError> {
        heap.get_own_property_descriptor(target, key)
    }

    /// `Reflect.apply(target, thisArgument, argumentsList)` — ES2020 §26.1.1.
    ///
    /// Returns the function index and arguments for the interpreter to dispatch.
    /// The actual call is performed by the execution pipeline; this method
    /// validates that the target is callable and returns the components.
    pub fn apply(
        heap: &ObjectHeap,
        target: ObjectHandle,
        this_arg: JsValue,
        args: Vec<JsValue>,
    ) -> Result<ReflectApplyRequest, ObjectError> {
        let obj = heap.get(target)?;
        match obj {
            ManagedObject::Ordinary(o) => {
                if !o.callable {
                    return Err(ObjectError::TypeError(
                        "Reflect.apply: target is not callable".to_string(),
                    ));
                }
                Ok(ReflectApplyRequest {
                    target,
                    this_arg,
                    arguments: args,
                })
            }
            ManagedObject::Proxy(_) => {
                // Proxy apply trap: interpreter must resolve handler.apply trap.
                Ok(ReflectApplyRequest {
                    target,
                    this_arg,
                    arguments: args,
                })
            }
        }
    }

    /// `Reflect.construct(target, argumentsList[, newTarget])` — ES2020 §26.1.2.
    ///
    /// Returns the constructor call request for the interpreter to dispatch.
    /// Validates that target and optional newTarget are constructors.
    pub fn construct(
        heap: &ObjectHeap,
        target: ObjectHandle,
        args: Vec<JsValue>,
        new_target: Option<ObjectHandle>,
    ) -> Result<ReflectConstructRequest, ObjectError> {
        let obj = heap.get(target)?;
        match obj {
            ManagedObject::Ordinary(o) => {
                if !o.constructable {
                    return Err(ObjectError::TypeError(
                        "Reflect.construct: target is not a constructor".to_string(),
                    ));
                }
            }
            ManagedObject::Proxy(_) => {
                // Proxy construct trap: handled by interpreter.
            }
        }

        // Validate newTarget if provided.
        let effective_new_target = if let Some(nt) = new_target {
            let nt_obj = heap.get(nt)?;
            match nt_obj {
                ManagedObject::Ordinary(o) => {
                    if !o.constructable {
                        return Err(ObjectError::TypeError(
                            "Reflect.construct: newTarget is not a constructor".to_string(),
                        ));
                    }
                }
                ManagedObject::Proxy(_) => {
                    // Proxy newTarget: handled by interpreter.
                }
            }
            nt
        } else {
            target
        };

        Ok(ReflectConstructRequest {
            target,
            arguments: args,
            new_target: effective_new_target,
        })
    }
}

// ---------------------------------------------------------------------------
// ReflectApplyRequest / ReflectConstructRequest
// ---------------------------------------------------------------------------

/// Request produced by `Reflect.apply` for the interpreter to execute.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReflectApplyRequest {
    /// The callable target object.
    pub target: ObjectHandle,
    /// The `this` argument.
    pub this_arg: JsValue,
    /// The arguments list.
    pub arguments: Vec<JsValue>,
}

/// Request produced by `Reflect.construct` for the interpreter to execute.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReflectConstructRequest {
    /// The constructor target.
    pub target: ObjectHandle,
    /// The arguments list.
    pub arguments: Vec<JsValue>,
    /// The effective newTarget (defaults to target if not specified).
    pub new_target: ObjectHandle,
}

// ---------------------------------------------------------------------------
// ObjectHeap — additional creation helpers
// ---------------------------------------------------------------------------

impl ObjectHeap {
    /// `Object.create(proto, propertiesObject)` — create with prototype and
    /// define properties atomically.
    pub fn create_with_properties(
        &mut self,
        proto: Option<ObjectHandle>,
        properties: Vec<(PropertyKey, PropertyDescriptor)>,
    ) -> Result<ObjectHandle, ObjectError> {
        let handle = self.alloc(proto);
        for (key, desc) in properties {
            self.define_property(handle, key, desc)?;
        }
        Ok(handle)
    }

    /// Allocate a callable (function) object with the given prototype.
    pub fn alloc_callable(&mut self, proto: Option<ObjectHandle>) -> ObjectHandle {
        let handle = ObjectHandle(u32::try_from(self.objects.len()).unwrap_or(u32::MAX));
        let mut obj = OrdinaryObject::with_prototype(proto);
        obj.callable = true;
        self.objects.push(ManagedObject::Ordinary(obj));
        handle
    }

    /// Allocate a constructor object with the given prototype.
    pub fn alloc_constructor(&mut self, proto: Option<ObjectHandle>) -> ObjectHandle {
        let handle = ObjectHandle(u32::try_from(self.objects.len()).unwrap_or(u32::MAX));
        let mut obj = OrdinaryObject::with_prototype(proto);
        obj.callable = true;
        obj.constructable = true;
        self.objects.push(ManagedObject::Ordinary(obj));
        handle
    }

    /// `instanceof` operator check: walks the prototype chain of `obj`
    /// looking for `proto_target`.
    pub fn instance_of(
        &self,
        obj: ObjectHandle,
        proto_target: ObjectHandle,
    ) -> Result<bool, ObjectError> {
        let mut current = self.get_prototype_of(obj)?;
        let mut depth: u32 = 0;
        let mut visited = BTreeSet::new();
        visited.insert(obj);

        while let Some(h) = current {
            if depth >= MAX_PROTOTYPE_CHAIN_DEPTH {
                return Err(ObjectError::PrototypeChainTooDeep {
                    depth,
                    max: MAX_PROTOTYPE_CHAIN_DEPTH,
                });
            }
            if !visited.insert(h) {
                return Err(ObjectError::PrototypeCycleDetected);
            }
            if h == proto_target {
                return Ok(true);
            }
            current = self.get_prototype_of(h)?;
            depth += 1;
        }
        Ok(false)
    }

    /// Shallow copy of an ordinary object's own enumerable properties
    /// using the spread syntax semantics (`{...source}`).
    pub fn spread_into(
        &mut self,
        target: ObjectHandle,
        source: ObjectHandle,
    ) -> Result<(), ObjectError> {
        // Collect source properties first to avoid borrow conflicts.
        let props: Vec<(PropertyKey, JsValue)> = {
            let obj = self.get(source)?;
            match obj {
                ManagedObject::Ordinary(o) => o
                    .own_property_keys()
                    .into_iter()
                    .filter_map(|k| {
                        o.properties.get(&k).and_then(|d| {
                            if d.is_enumerable() {
                                d.value().map(|v| (k, v.clone()))
                            } else {
                                None
                            }
                        })
                    })
                    .collect(),
                ManagedObject::Proxy(_) => {
                    return Err(ObjectError::TypeError(
                        "spread source cannot be proxy (handled by interpreter)".to_string(),
                    ));
                }
            }
        };

        for (key, value) in props {
            self.set_property(target, key, value)?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- helpers --------------------------------------------------------

    fn str_key(s: &str) -> PropertyKey {
        PropertyKey::String(s.to_string())
    }

    fn int_val(n: i64) -> JsValue {
        JsValue::Int(n)
    }

    fn str_val(s: &str) -> JsValue {
        JsValue::Str(s.to_string())
    }

    // -----------------------------------------------------------------------
    // 1. PropertyKey
    // -----------------------------------------------------------------------

    #[test]
    fn property_key_from_str() {
        let k: PropertyKey = "foo".into();
        assert_eq!(k, PropertyKey::String("foo".to_string()));
    }

    #[test]
    fn property_key_display() {
        assert_eq!(str_key("foo").to_string(), "foo");
        assert_eq!(PropertyKey::Symbol(SymbolId(42)).to_string(), "Symbol(42)");
    }

    // -----------------------------------------------------------------------
    // 2. PropertyDescriptor basics
    // -----------------------------------------------------------------------

    #[test]
    fn data_descriptor_defaults() {
        let d = PropertyDescriptor::data(int_val(42));
        assert!(d.is_data());
        assert!(!d.is_accessor());
        assert!(d.is_configurable());
        assert!(d.is_enumerable());
        assert!(d.is_writable());
        assert_eq!(d.value(), Some(&int_val(42)));
    }

    #[test]
    fn data_descriptor_frozen() {
        let d = PropertyDescriptor::data_frozen(int_val(1));
        assert!(!d.is_configurable());
        assert!(!d.is_enumerable());
        assert!(!d.is_writable());
    }

    #[test]
    fn accessor_descriptor() {
        let d = PropertyDescriptor::Accessor {
            get: Some(ObjectHandle(1)),
            set: None,
            enumerable: true,
            configurable: true,
        };
        assert!(d.is_accessor());
        assert!(!d.is_data());
        assert!(d.is_configurable());
        assert!(d.is_enumerable());
        assert!(!d.is_writable());
        assert_eq!(d.value(), None);
    }

    #[test]
    fn descriptor_mutators() {
        let mut d = PropertyDescriptor::data(int_val(1));
        d.set_non_configurable();
        assert!(!d.is_configurable());
        d.set_non_writable();
        assert!(!d.is_writable());
        d.set_non_enumerable();
        assert!(!d.is_enumerable());
    }

    // -----------------------------------------------------------------------
    // 3. OrdinaryObject basics
    // -----------------------------------------------------------------------

    #[test]
    fn ordinary_object_defaults() {
        let obj = OrdinaryObject::default();
        assert!(obj.extensible);
        assert_eq!(obj.prototype, None);
        assert!(obj.properties.is_empty());
    }

    #[test]
    fn define_own_property_new() {
        let mut obj = OrdinaryObject::default();
        let result = obj
            .define_own_property(str_key("x"), PropertyDescriptor::data(int_val(42)))
            .unwrap();
        assert!(result);
        assert!(obj.has_own_property(&str_key("x")));
        assert_eq!(
            obj.get_own_property(&str_key("x")).unwrap().value(),
            Some(&int_val(42))
        );
    }

    #[test]
    fn define_own_property_non_extensible_rejects() {
        let mut obj = OrdinaryObject {
            extensible: false,
            ..Default::default()
        };
        let result = obj
            .define_own_property(str_key("x"), PropertyDescriptor::data(int_val(1)))
            .unwrap();
        assert!(!result);
    }

    #[test]
    fn define_own_property_non_configurable_rejects_reconfig() {
        let mut obj = OrdinaryObject::default();
        obj.define_own_property(
            str_key("x"),
            PropertyDescriptor::Data {
                value: int_val(1),
                writable: false,
                enumerable: true,
                configurable: false,
            },
        )
        .unwrap();

        // Try to make it configurable again — rejected.
        let result = obj
            .define_own_property(str_key("x"), PropertyDescriptor::data(int_val(2)))
            .unwrap();
        assert!(!result);
    }

    #[test]
    fn define_own_property_non_configurable_allows_same_value() {
        let mut obj = OrdinaryObject::default();
        obj.define_own_property(
            str_key("x"),
            PropertyDescriptor::Data {
                value: int_val(1),
                writable: false,
                enumerable: true,
                configurable: false,
            },
        )
        .unwrap();

        // Same value, same attributes — allowed.
        let result = obj
            .define_own_property(
                str_key("x"),
                PropertyDescriptor::Data {
                    value: int_val(1),
                    writable: false,
                    enumerable: true,
                    configurable: false,
                },
            )
            .unwrap();
        assert!(result);
    }

    // -----------------------------------------------------------------------
    // 4. Delete
    // -----------------------------------------------------------------------

    #[test]
    fn delete_configurable_property() {
        let mut obj = OrdinaryObject::default();
        obj.define_own_property(str_key("x"), PropertyDescriptor::data(int_val(1)))
            .unwrap();
        assert!(obj.delete(&str_key("x")));
        assert!(!obj.has_own_property(&str_key("x")));
    }

    #[test]
    fn delete_non_configurable_rejected() {
        let mut obj = OrdinaryObject::default();
        obj.define_own_property(
            str_key("x"),
            PropertyDescriptor::Data {
                value: int_val(1),
                writable: true,
                enumerable: true,
                configurable: false,
            },
        )
        .unwrap();
        assert!(!obj.delete(&str_key("x")));
        assert!(obj.has_own_property(&str_key("x")));
    }

    #[test]
    fn delete_nonexistent_succeeds() {
        let mut obj = OrdinaryObject::default();
        assert!(obj.delete(&str_key("nope")));
    }

    // -----------------------------------------------------------------------
    // 5. Own property keys ordering
    // -----------------------------------------------------------------------

    #[test]
    fn own_property_keys_order() {
        let mut obj = OrdinaryObject::default();
        obj.define_own_property(str_key("b"), PropertyDescriptor::data(int_val(1)))
            .unwrap();
        obj.define_own_property(str_key("2"), PropertyDescriptor::data(int_val(2)))
            .unwrap();
        obj.define_own_property(str_key("0"), PropertyDescriptor::data(int_val(3)))
            .unwrap();
        obj.define_own_property(str_key("a"), PropertyDescriptor::data(int_val(4)))
            .unwrap();
        obj.define_own_property(
            PropertyKey::Symbol(SymbolId(100)),
            PropertyDescriptor::data(int_val(5)),
        )
        .unwrap();
        obj.define_own_property(str_key("10"), PropertyDescriptor::data(int_val(6)))
            .unwrap();

        let keys = obj.own_property_keys();
        // Integer indices first (sorted numerically), then strings, then symbols.
        assert_eq!(keys[0], str_key("0"));
        assert_eq!(keys[1], str_key("2"));
        assert_eq!(keys[2], str_key("10"));
        assert_eq!(keys[3], str_key("a"));
        assert_eq!(keys[4], str_key("b"));
        assert_eq!(keys[5], PropertyKey::Symbol(SymbolId(100)));
    }

    // -----------------------------------------------------------------------
    // 6. Freeze / Seal
    // -----------------------------------------------------------------------

    #[test]
    fn freeze_makes_non_writable_non_configurable() {
        let mut obj = OrdinaryObject::default();
        obj.define_own_property(str_key("x"), PropertyDescriptor::data(int_val(1)))
            .unwrap();
        obj.freeze();
        assert!(!obj.extensible);
        assert!(obj.is_frozen());
        assert!(obj.is_sealed());
        let d = obj.get_own_property(&str_key("x")).unwrap();
        assert!(!d.is_configurable());
        assert!(!d.is_writable());
    }

    #[test]
    fn seal_makes_non_configurable_keeps_writable() {
        let mut obj = OrdinaryObject::default();
        obj.define_own_property(str_key("x"), PropertyDescriptor::data(int_val(1)))
            .unwrap();
        obj.seal();
        assert!(!obj.extensible);
        assert!(obj.is_sealed());
        assert!(!obj.is_frozen()); // writable data property remains writable
        let d = obj.get_own_property(&str_key("x")).unwrap();
        assert!(!d.is_configurable());
        assert!(d.is_writable());
    }

    // -----------------------------------------------------------------------
    // 7. ObjectHeap basics
    // -----------------------------------------------------------------------

    #[test]
    fn heap_alloc_and_get() {
        let mut heap = ObjectHeap::new();
        let h = heap.alloc_plain();
        assert_eq!(h, ObjectHandle(0));
        assert_eq!(heap.len(), 1);
        assert!(heap.get(h).is_ok());
    }

    #[test]
    fn heap_get_invalid_handle() {
        let heap = ObjectHeap::new();
        assert!(heap.get(ObjectHandle(99)).is_err());
    }

    #[test]
    fn heap_set_and_get_property() {
        let mut heap = ObjectHeap::new();
        let h = heap.alloc_plain();
        heap.set_property(h, str_key("x"), int_val(42)).unwrap();
        let val = heap.get_property(h, &str_key("x")).unwrap();
        assert_eq!(val, int_val(42));
    }

    // -----------------------------------------------------------------------
    // 8. Prototype chain traversal
    // -----------------------------------------------------------------------

    #[test]
    fn prototype_chain_get() {
        let mut heap = ObjectHeap::new();
        let proto = heap.alloc_plain();
        heap.set_property(proto, str_key("inherited"), int_val(99))
            .unwrap();

        let child = heap.alloc(Some(proto));
        let val = heap.get_property(child, &str_key("inherited")).unwrap();
        assert_eq!(val, int_val(99));
    }

    #[test]
    fn prototype_chain_own_shadows() {
        let mut heap = ObjectHeap::new();
        let proto = heap.alloc_plain();
        heap.set_property(proto, str_key("x"), int_val(1)).unwrap();

        let child = heap.alloc(Some(proto));
        heap.set_property(child, str_key("x"), int_val(2)).unwrap();

        let val = heap.get_property(child, &str_key("x")).unwrap();
        assert_eq!(val, int_val(2)); // own shadows prototype
    }

    #[test]
    fn prototype_chain_undefined_at_end() {
        let mut heap = ObjectHeap::new();
        let h = heap.alloc_plain();
        let val = heap.get_property(h, &str_key("nonexistent")).unwrap();
        assert_eq!(val, JsValue::Undefined);
    }

    #[test]
    fn prototype_chain_has_property() {
        let mut heap = ObjectHeap::new();
        let proto = heap.alloc_plain();
        heap.set_property(proto, str_key("y"), int_val(1)).unwrap();
        let child = heap.alloc(Some(proto));

        assert!(heap.has_property(child, &str_key("y")).unwrap());
        assert!(!heap.has_property(child, &str_key("z")).unwrap());
    }

    // -----------------------------------------------------------------------
    // 9. Set prototype / cycle detection
    // -----------------------------------------------------------------------

    #[test]
    fn set_prototype_cycle_detection() {
        let mut heap = ObjectHeap::new();
        let a = heap.alloc_plain();
        let b = heap.alloc(Some(a));
        // Try to set a's prototype to b (would create cycle: a -> b -> a).
        let result = heap.set_prototype_of(a, Some(b));
        assert!(result.is_err());
    }

    #[test]
    fn set_prototype_non_extensible_rejects() {
        let mut heap = ObjectHeap::new();
        let a = heap.alloc_plain();
        let b = heap.alloc_plain();
        heap.prevent_extensions(a).unwrap();
        let result = heap.set_prototype_of(a, Some(b)).unwrap();
        assert!(!result); // non-extensible, different prototype
    }

    #[test]
    fn set_prototype_non_extensible_allows_same() {
        let mut heap = ObjectHeap::new();
        let proto = heap.alloc_plain();
        let obj = heap.alloc(Some(proto));
        heap.prevent_extensions(obj).unwrap();
        let result = heap.set_prototype_of(obj, Some(proto)).unwrap();
        assert!(result); // same prototype is ok
    }

    // -----------------------------------------------------------------------
    // 10. Object.keys
    // -----------------------------------------------------------------------

    #[test]
    fn object_keys_only_enumerable_strings() {
        let mut heap = ObjectHeap::new();
        let h = heap.alloc_plain();
        heap.set_property(h, str_key("a"), int_val(1)).unwrap();
        heap.define_property(
            h,
            str_key("hidden"),
            PropertyDescriptor::Data {
                value: int_val(2),
                writable: true,
                enumerable: false,
                configurable: true,
            },
        )
        .unwrap();
        heap.define_property(
            h,
            PropertyKey::Symbol(SymbolId(100)),
            PropertyDescriptor::data(int_val(3)),
        )
        .unwrap();

        let keys = heap.keys(h).unwrap();
        assert_eq!(keys, vec!["a".to_string()]);
    }

    // -----------------------------------------------------------------------
    // 11. Object.freeze / seal on heap
    // -----------------------------------------------------------------------

    #[test]
    fn heap_freeze() {
        let mut heap = ObjectHeap::new();
        let h = heap.alloc_plain();
        heap.set_property(h, str_key("x"), int_val(1)).unwrap();
        heap.freeze(h).unwrap();

        assert!(heap.is_frozen(h).unwrap());
        // Cannot modify frozen property.
        let result = heap.set_property(h, str_key("x"), int_val(2)).unwrap();
        assert!(!result);
        // Cannot add new property.
        let result = heap.set_property(h, str_key("y"), int_val(3)).unwrap();
        assert!(!result);
    }

    #[test]
    fn heap_seal() {
        let mut heap = ObjectHeap::new();
        let h = heap.alloc_plain();
        heap.set_property(h, str_key("x"), int_val(1)).unwrap();
        heap.seal(h).unwrap();

        assert!(heap.is_sealed(h).unwrap());
        assert!(!heap.is_frozen(h).unwrap());
        // Can modify value of writable property on sealed object.
        let result = heap.set_property(h, str_key("x"), int_val(2)).unwrap();
        assert!(result);
        // Cannot add new property.
        let result = heap.set_property(h, str_key("y"), int_val(3)).unwrap();
        assert!(!result);
    }

    // -----------------------------------------------------------------------
    // 12. Object.assign
    // -----------------------------------------------------------------------

    #[test]
    fn object_assign_copies_enumerable() {
        let mut heap = ObjectHeap::new();
        let src = heap.alloc_plain();
        heap.set_property(src, str_key("a"), int_val(1)).unwrap();
        heap.set_property(src, str_key("b"), int_val(2)).unwrap();

        let target = heap.alloc_plain();
        heap.assign(target, &[src]).unwrap();

        assert_eq!(
            heap.get_property(target, &str_key("a")).unwrap(),
            int_val(1)
        );
        assert_eq!(
            heap.get_property(target, &str_key("b")).unwrap(),
            int_val(2)
        );
    }

    // -----------------------------------------------------------------------
    // 13. Proxy creation and revocation
    // -----------------------------------------------------------------------

    #[test]
    fn proxy_create_and_revoke() {
        let mut heap = ObjectHeap::new();
        let target = heap.alloc_plain();
        let handler = heap.alloc_plain();
        let proxy = heap.alloc_proxy(target, handler);

        let obj = heap.get(proxy).unwrap();
        assert!(obj.as_proxy().is_some());
        assert!(!obj.as_proxy().unwrap().is_revoked());

        heap.revoke_proxy(proxy).unwrap();
        let obj = heap.get(proxy).unwrap();
        assert!(obj.as_proxy().unwrap().is_revoked());
    }

    #[test]
    fn proxy_revoked_target_errors() {
        let mut heap = ObjectHeap::new();
        let target = heap.alloc_plain();
        let handler = heap.alloc_plain();
        let proxy = heap.alloc_proxy(target, handler);
        heap.revoke_proxy(proxy).unwrap();

        let p = heap.get(proxy).unwrap().as_proxy().unwrap();
        assert_eq!(p.target(), Err(ObjectError::ProxyRevoked));
        assert_eq!(p.handler(), Err(ObjectError::ProxyRevoked));
    }

    // -----------------------------------------------------------------------
    // 14. Proxy invariant: [[Get]] non-configurable non-writable
    // -----------------------------------------------------------------------

    #[test]
    fn proxy_invariant_get_non_configurable_non_writable() {
        let mut obj = OrdinaryObject::default();
        obj.define_own_property(
            str_key("x"),
            PropertyDescriptor::Data {
                value: int_val(42),
                writable: false,
                enumerable: true,
                configurable: false,
            },
        )
        .unwrap();

        // Trap returns correct value — ok.
        assert!(ProxyInvariantChecker::check_get(&obj, &str_key("x"), &int_val(42)).is_ok());

        // Trap returns different value — error.
        assert!(ProxyInvariantChecker::check_get(&obj, &str_key("x"), &int_val(99)).is_err());
    }

    // -----------------------------------------------------------------------
    // 15. Proxy invariant: [[Has]] non-configurable
    // -----------------------------------------------------------------------

    #[test]
    fn proxy_invariant_has_non_configurable() {
        let mut obj = OrdinaryObject::default();
        obj.define_own_property(
            str_key("x"),
            PropertyDescriptor::Data {
                value: int_val(1),
                writable: true,
                enumerable: true,
                configurable: false,
            },
        )
        .unwrap();

        // Cannot report non-configurable as non-existent.
        assert!(ProxyInvariantChecker::check_has(&obj, &str_key("x"), false).is_err());
        assert!(ProxyInvariantChecker::check_has(&obj, &str_key("x"), true).is_ok());
    }

    // -----------------------------------------------------------------------
    // 16. Proxy invariant: [[Delete]] non-configurable
    // -----------------------------------------------------------------------

    #[test]
    fn proxy_invariant_delete_non_configurable() {
        let mut obj = OrdinaryObject::default();
        obj.define_own_property(
            str_key("x"),
            PropertyDescriptor::Data {
                value: int_val(1),
                writable: true,
                enumerable: true,
                configurable: false,
            },
        )
        .unwrap();

        assert!(ProxyInvariantChecker::check_delete(&obj, &str_key("x"), true).is_err());
        assert!(ProxyInvariantChecker::check_delete(&obj, &str_key("x"), false).is_ok());
    }

    // -----------------------------------------------------------------------
    // 17. Proxy invariant: [[OwnKeys]] completeness
    // -----------------------------------------------------------------------

    #[test]
    fn proxy_invariant_own_keys_must_include_non_configurable() {
        let mut obj = OrdinaryObject::default();
        obj.define_own_property(
            str_key("required"),
            PropertyDescriptor::Data {
                value: int_val(1),
                writable: true,
                enumerable: true,
                configurable: false,
            },
        )
        .unwrap();

        // Missing non-configurable key — error.
        assert!(ProxyInvariantChecker::check_own_keys(&obj, &[]).is_err());

        // Includes the key — ok.
        assert!(ProxyInvariantChecker::check_own_keys(&obj, &[str_key("required")]).is_ok());
    }

    #[test]
    fn proxy_invariant_own_keys_no_duplicates() {
        let obj = OrdinaryObject::default();
        let result = ProxyInvariantChecker::check_own_keys(&obj, &[str_key("a"), str_key("a")]);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // 18. Proxy invariant: [[IsExtensible]] match
    // -----------------------------------------------------------------------

    #[test]
    fn proxy_invariant_is_extensible_must_match() {
        let obj = OrdinaryObject::default(); // extensible = true
        assert!(ProxyInvariantChecker::check_is_extensible(&obj, true).is_ok());
        assert!(ProxyInvariantChecker::check_is_extensible(&obj, false).is_err());
    }

    // -----------------------------------------------------------------------
    // 19. Proxy invariant: [[PreventExtensions]]
    // -----------------------------------------------------------------------

    #[test]
    fn proxy_invariant_prevent_extensions() {
        let obj = OrdinaryObject::default(); // extensible = true
        // Cannot return true while target is extensible.
        assert!(ProxyInvariantChecker::check_prevent_extensions(&obj, true).is_err());
        assert!(ProxyInvariantChecker::check_prevent_extensions(&obj, false).is_ok());
    }

    // -----------------------------------------------------------------------
    // 20. Proxy invariant: [[GetPrototypeOf]] non-extensible
    // -----------------------------------------------------------------------

    #[test]
    fn proxy_invariant_get_prototype_of_non_extensible() {
        let obj = OrdinaryObject {
            prototype: Some(ObjectHandle(5)),
            extensible: false,
            ..Default::default()
        };

        // Must return same prototype.
        assert!(ProxyInvariantChecker::check_get_prototype_of(&obj, Some(ObjectHandle(5))).is_ok());
        assert!(
            ProxyInvariantChecker::check_get_prototype_of(&obj, Some(ObjectHandle(6))).is_err()
        );
    }

    // -----------------------------------------------------------------------
    // 21. Symbol registry
    // -----------------------------------------------------------------------

    #[test]
    fn symbol_registry_basics() {
        let mut heap = ObjectHeap::new();
        let mut reg = SymbolRegistry::new();

        let s1 = reg.symbol_for("shared", &mut heap);
        let s2 = reg.symbol_for("shared", &mut heap);
        assert_eq!(s1, s2); // Same key → same symbol.

        let s3 = reg.symbol_for("other", &mut heap);
        assert_ne!(s1, s3);

        assert_eq!(reg.key_for(s1), Some("shared"));
        assert_eq!(reg.key_for(s3), Some("other"));
    }

    #[test]
    fn well_known_symbol_ids() {
        let reg = SymbolRegistry::new();
        assert_eq!(
            reg.key_for(WellKnownSymbol::Iterator.id()),
            Some("Symbol.iterator")
        );
        assert_eq!(
            reg.key_for(WellKnownSymbol::ToPrimitive.id()),
            Some("Symbol.toPrimitive")
        );
    }

    // -----------------------------------------------------------------------
    // 22. JsValue basics
    // -----------------------------------------------------------------------

    #[test]
    fn js_value_same_value() {
        assert!(int_val(42).same_value(&int_val(42)));
        assert!(!int_val(42).same_value(&int_val(43)));
        assert!(JsValue::Undefined.same_value(&JsValue::Undefined));
        assert!(!JsValue::Null.same_value(&JsValue::Undefined));
    }

    #[test]
    fn js_value_type_name() {
        assert_eq!(JsValue::Undefined.type_name(), "undefined");
        assert_eq!(JsValue::Null.type_name(), "null");
        assert_eq!(JsValue::Bool(true).type_name(), "boolean");
        assert_eq!(int_val(1).type_name(), "number");
        assert_eq!(str_val("hi").type_name(), "string");
        assert_eq!(JsValue::Symbol(SymbolId(1)).type_name(), "symbol");
        assert_eq!(JsValue::Object(ObjectHandle(0)).type_name(), "object");
        assert_eq!(JsValue::Function(0).type_name(), "function");
    }

    #[test]
    fn js_value_display() {
        assert_eq!(int_val(42).to_string(), "42");
        assert_eq!(str_val("hello").to_string(), "hello");
        assert_eq!(JsValue::Null.to_string(), "null");
    }

    // -----------------------------------------------------------------------
    // 23. Object.is
    // -----------------------------------------------------------------------

    #[test]
    fn object_is() {
        assert!(ObjectHeap::object_is(&int_val(0), &int_val(0)));
        // In fixed-point integer model, 0 and -0 are identical (no IEEE 754 +0/-0 distinction)
        assert!(ObjectHeap::object_is(&int_val(0), &int_val(-0)));
        assert!(!ObjectHeap::object_is(&int_val(0), &int_val(1)));
        assert!(ObjectHeap::object_is(&JsValue::Null, &JsValue::Null));
    }

    // -----------------------------------------------------------------------
    // 24. ManagedObject variants
    // -----------------------------------------------------------------------

    #[test]
    fn managed_object_ordinary() {
        let obj = ManagedObject::Ordinary(OrdinaryObject::default());
        assert!(obj.as_ordinary().is_some());
        assert!(obj.as_proxy().is_none());
    }

    #[test]
    fn managed_object_proxy() {
        let obj = ManagedObject::Proxy(ProxyObject::new(ObjectHandle(0), ObjectHandle(1)));
        assert!(obj.as_proxy().is_some());
        assert!(obj.as_ordinary().is_none());
    }

    // -----------------------------------------------------------------------
    // 25. Delete property on heap
    // -----------------------------------------------------------------------

    #[test]
    fn heap_delete_property() {
        let mut heap = ObjectHeap::new();
        let h = heap.alloc_plain();
        heap.set_property(h, str_key("x"), int_val(1)).unwrap();
        assert!(heap.delete_property(h, &str_key("x")).unwrap());
        assert_eq!(
            heap.get_property(h, &str_key("x")).unwrap(),
            JsValue::Undefined
        );
    }

    // -----------------------------------------------------------------------
    // 26. Three-level prototype chain
    // -----------------------------------------------------------------------

    #[test]
    fn three_level_prototype_chain() {
        let mut heap = ObjectHeap::new();
        let grandparent = heap.alloc_plain();
        heap.set_property(grandparent, str_key("g"), int_val(1))
            .unwrap();

        let parent = heap.alloc(Some(grandparent));
        heap.set_property(parent, str_key("p"), int_val(2)).unwrap();

        let child = heap.alloc(Some(parent));
        heap.set_property(child, str_key("c"), int_val(3)).unwrap();

        assert_eq!(heap.get_property(child, &str_key("g")).unwrap(), int_val(1));
        assert_eq!(heap.get_property(child, &str_key("p")).unwrap(), int_val(2));
        assert_eq!(heap.get_property(child, &str_key("c")).unwrap(), int_val(3));
    }

    // -----------------------------------------------------------------------
    // 27. Serde round-trips
    // -----------------------------------------------------------------------

    #[test]
    fn property_key_serde_roundtrip() {
        for key in [str_key("foo"), PropertyKey::Symbol(SymbolId(42))] {
            let json = serde_json::to_string(&key).unwrap();
            let deser: PropertyKey = serde_json::from_str(&json).unwrap();
            assert_eq!(key, deser);
        }
    }

    #[test]
    fn js_value_serde_roundtrip() {
        for val in [
            JsValue::Undefined,
            JsValue::Null,
            JsValue::Bool(true),
            int_val(42),
            str_val("hello"),
            JsValue::Symbol(SymbolId(7)),
            JsValue::Object(ObjectHandle(3)),
            JsValue::Function(5),
        ] {
            let json = serde_json::to_string(&val).unwrap();
            let deser: JsValue = serde_json::from_str(&json).unwrap();
            assert_eq!(val, deser);
        }
    }

    #[test]
    fn property_descriptor_serde_roundtrip() {
        let descs = [
            PropertyDescriptor::data(int_val(42)),
            PropertyDescriptor::data_frozen(str_val("frozen")),
            PropertyDescriptor::Accessor {
                get: Some(ObjectHandle(1)),
                set: Some(ObjectHandle(2)),
                enumerable: true,
                configurable: false,
            },
        ];
        for desc in descs {
            let json = serde_json::to_string(&desc).unwrap();
            let deser: PropertyDescriptor = serde_json::from_str(&json).unwrap();
            assert_eq!(desc, deser);
        }
    }

    #[test]
    fn object_error_serde_roundtrip() {
        let errors = [
            ObjectError::TypeError("test".to_string()),
            ObjectError::ObjectNotFound(ObjectHandle(99)),
            ObjectError::ProxyRevoked,
            ObjectError::PrototypeCycleDetected,
            ObjectError::PrototypeChainTooDeep { depth: 10, max: 5 },
        ];
        for err in errors {
            let json = serde_json::to_string(&err).unwrap();
            let deser: ObjectError = serde_json::from_str(&json).unwrap();
            assert_eq!(err, deser);
        }
    }

    // -----------------------------------------------------------------------
    // 28. Error display coverage
    // -----------------------------------------------------------------------

    #[test]
    fn error_display_coverage() {
        let errors = [
            ObjectError::TypeError("test".to_string()),
            ObjectError::ObjectNotFound(ObjectHandle(99)),
            ObjectError::ProxyRevoked,
            ObjectError::PrototypeCycleDetected,
            ObjectError::PrototypeChainTooDeep { depth: 10, max: 5 },
        ];
        for e in errors {
            let s = e.to_string();
            assert!(!s.is_empty());
        }
    }

    // -----------------------------------------------------------------------
    // 29. Object.create with prototype
    // -----------------------------------------------------------------------

    #[test]
    fn object_create_with_proto() {
        let mut heap = ObjectHeap::new();
        let proto = heap.alloc_plain();
        heap.set_property(proto, str_key("shared"), int_val(100))
            .unwrap();

        let child = heap.create(Some(proto));
        assert_eq!(
            heap.get_property(child, &str_key("shared")).unwrap(),
            int_val(100)
        );
        assert_eq!(heap.get_prototype_of(child).unwrap(), Some(proto));
    }

    // -----------------------------------------------------------------------
    // 30. Proxy invariant: [[Set]] non-configurable non-writable
    // -----------------------------------------------------------------------

    #[test]
    fn proxy_invariant_set_non_configurable_non_writable() {
        let mut obj = OrdinaryObject::default();
        obj.define_own_property(
            str_key("x"),
            PropertyDescriptor::Data {
                value: int_val(42),
                writable: false,
                enumerable: true,
                configurable: false,
            },
        )
        .unwrap();

        // Cannot set to different value.
        assert!(ProxyInvariantChecker::check_set(&obj, &str_key("x"), &int_val(99), true).is_err());
        // Same value — ok.
        assert!(ProxyInvariantChecker::check_set(&obj, &str_key("x"), &int_val(42), true).is_ok());
    }

    // -----------------------------------------------------------------------
    // 31. Proxy invariant: [[Set]] accessor with no setter
    // -----------------------------------------------------------------------

    #[test]
    fn proxy_invariant_set_accessor_no_setter() {
        let mut obj = OrdinaryObject::default();
        obj.define_own_property(
            str_key("x"),
            PropertyDescriptor::Accessor {
                get: Some(ObjectHandle(1)),
                set: None,
                enumerable: true,
                configurable: false,
            },
        )
        .unwrap();

        assert!(ProxyInvariantChecker::check_set(&obj, &str_key("x"), &int_val(1), true).is_err());
    }

    // -----------------------------------------------------------------------
    // 32. Proxy invariant: [[OwnKeys]] non-extensible exact permutation
    // -----------------------------------------------------------------------

    #[test]
    #[allow(clippy::field_reassign_with_default)]
    fn proxy_invariant_own_keys_non_extensible_exact() {
        let mut obj = OrdinaryObject::default();
        obj.define_own_property(str_key("a"), PropertyDescriptor::data(int_val(1)))
            .unwrap();
        obj.define_own_property(str_key("b"), PropertyDescriptor::data(int_val(2)))
            .unwrap();
        obj.extensible = false;

        // Exact permutation — ok.
        assert!(ProxyInvariantChecker::check_own_keys(&obj, &[str_key("b"), str_key("a")]).is_ok());

        // Extra key — error.
        assert!(
            ProxyInvariantChecker::check_own_keys(
                &obj,
                &[str_key("a"), str_key("b"), str_key("c")]
            )
            .is_err()
        );

        // Missing key — error.
        assert!(ProxyInvariantChecker::check_own_keys(&obj, &[str_key("a")]).is_err());
    }

    // -----------------------------------------------------------------------
    // 33. Proxy invariant: [[SetPrototypeOf]] non-extensible
    // -----------------------------------------------------------------------

    #[test]
    fn proxy_invariant_set_prototype_of_non_extensible() {
        let obj = OrdinaryObject {
            prototype: Some(ObjectHandle(5)),
            extensible: false,
            ..Default::default()
        };

        // Same prototype — ok.
        assert!(
            ProxyInvariantChecker::check_set_prototype_of(&obj, Some(ObjectHandle(5)), true)
                .is_ok()
        );

        // Different prototype — error.
        assert!(
            ProxyInvariantChecker::check_set_prototype_of(&obj, Some(ObjectHandle(6)), true)
                .is_err()
        );
    }

    // -----------------------------------------------------------------------
    // 34. Proxy invariant: [[GetOwnProperty]] non-existent on non-extensible
    // -----------------------------------------------------------------------

    #[test]
    #[allow(clippy::field_reassign_with_default)]
    fn proxy_invariant_get_own_property_non_extensible() {
        let mut obj = OrdinaryObject::default();
        obj.define_own_property(str_key("x"), PropertyDescriptor::data(int_val(1)))
            .unwrap();
        obj.extensible = false;

        // Cannot report existing property as non-existent.
        assert!(ProxyInvariantChecker::check_get_own_property(&obj, &str_key("x"), &None).is_err());

        // Cannot report new property as existent.
        let fake_desc = Some(PropertyDescriptor::data(int_val(2)));
        assert!(
            ProxyInvariantChecker::check_get_own_property(&obj, &str_key("y"), &fake_desc).is_err()
        );
    }

    // -----------------------------------------------------------------------
    // 35. Proxy invariant: [[DefineOwnProperty]] non-extensible add
    // -----------------------------------------------------------------------

    #[test]
    fn proxy_invariant_define_property_non_extensible_add() {
        let obj = OrdinaryObject {
            extensible: false,
            ..Default::default()
        };

        let desc = PropertyDescriptor::data(int_val(1));
        assert!(
            ProxyInvariantChecker::check_define_own_property(
                &obj,
                &str_key("new_prop"),
                &desc,
                true
            )
            .is_err()
        );
    }

    // -----------------------------------------------------------------------
    // 36. Heap is_empty
    // -----------------------------------------------------------------------

    #[test]
    fn heap_is_empty() {
        let heap = ObjectHeap::new();
        assert!(heap.is_empty());
        assert_eq!(heap.len(), 0);
    }

    // -----------------------------------------------------------------------
    // 37. Symbol allocation
    // -----------------------------------------------------------------------

    #[test]
    fn heap_alloc_symbol() {
        let mut heap = ObjectHeap::new();
        let s1 = heap.alloc_symbol();
        let s2 = heap.alloc_symbol();
        assert_ne!(s1, s2);
        assert!(s1.0 >= 14); // after well-known symbols
    }

    // -----------------------------------------------------------------------
    // 38. Accessor property get returns getter handle
    // -----------------------------------------------------------------------

    #[test]
    fn accessor_get_returns_getter() {
        let mut heap = ObjectHeap::new();
        let h = heap.alloc_plain();
        let getter_handle = ObjectHandle(99);
        heap.define_property(
            h,
            str_key("x"),
            PropertyDescriptor::Accessor {
                get: Some(getter_handle),
                set: None,
                enumerable: true,
                configurable: true,
            },
        )
        .unwrap();

        // get_property returns the getter handle as an Object value.
        let val = heap.get_property(h, &str_key("x")).unwrap();
        assert_eq!(val, JsValue::Object(getter_handle));
    }

    // -----------------------------------------------------------------------
    // 39. Accessor property without getter returns undefined
    // -----------------------------------------------------------------------

    #[test]
    fn accessor_no_getter_returns_undefined() {
        let mut heap = ObjectHeap::new();
        let h = heap.alloc_plain();
        heap.define_property(
            h,
            str_key("x"),
            PropertyDescriptor::Accessor {
                get: None,
                set: Some(ObjectHandle(1)),
                enumerable: true,
                configurable: true,
            },
        )
        .unwrap();

        let val = heap.get_property(h, &str_key("x")).unwrap();
        assert_eq!(val, JsValue::Undefined);
    }

    // -----------------------------------------------------------------------
    // 40. Proxy invariant: [[Get]] accessor without getter
    // -----------------------------------------------------------------------

    #[test]
    fn proxy_invariant_get_accessor_no_getter() {
        let mut obj = OrdinaryObject::default();
        obj.define_own_property(
            str_key("x"),
            PropertyDescriptor::Accessor {
                get: None,
                set: None,
                enumerable: true,
                configurable: false,
            },
        )
        .unwrap();

        // Must return undefined.
        assert!(ProxyInvariantChecker::check_get(&obj, &str_key("x"), &JsValue::Undefined).is_ok());
        assert!(ProxyInvariantChecker::check_get(&obj, &str_key("x"), &int_val(42)).is_err());
    }

    // -----------------------------------------------------------------------
    // 41. Revoke non-proxy is error
    // -----------------------------------------------------------------------

    #[test]
    fn revoke_non_proxy_is_error() {
        let mut heap = ObjectHeap::new();
        let h = heap.alloc_plain();
        assert!(heap.revoke_proxy(h).is_err());
    }

    // -----------------------------------------------------------------------
    // 42. WellKnownSymbol name coverage
    // -----------------------------------------------------------------------

    #[test]
    fn well_known_symbol_names() {
        let syms = [
            (WellKnownSymbol::Iterator, "@@iterator"),
            (WellKnownSymbol::ToPrimitive, "@@toPrimitive"),
            (WellKnownSymbol::HasInstance, "@@hasInstance"),
            (WellKnownSymbol::ToStringTag, "@@toStringTag"),
            (WellKnownSymbol::Species, "@@species"),
            (WellKnownSymbol::IsConcatSpreadable, "@@isConcatSpreadable"),
            (WellKnownSymbol::Unscopables, "@@unscopables"),
            (WellKnownSymbol::AsyncIterator, "@@asyncIterator"),
            (WellKnownSymbol::Match, "@@match"),
            (WellKnownSymbol::MatchAll, "@@matchAll"),
            (WellKnownSymbol::Replace, "@@replace"),
            (WellKnownSymbol::Search, "@@search"),
            (WellKnownSymbol::Split, "@@split"),
        ];
        for (sym, expected) in syms {
            assert_eq!(sym.name(), expected);
        }
    }

    // -----------------------------------------------------------------------
    // 43. WellKnownSymbol key
    // -----------------------------------------------------------------------

    #[test]
    fn well_known_symbol_key() {
        let k = WellKnownSymbol::Iterator.key();
        assert_eq!(k, PropertyKey::Symbol(WellKnownSymbol::Iterator.id()));
    }

    // -----------------------------------------------------------------------
    // 44. Define data→data type change blocked on non-configurable
    // -----------------------------------------------------------------------

    #[test]
    fn define_data_to_accessor_blocked_on_non_configurable() {
        let mut obj = OrdinaryObject::default();
        obj.define_own_property(
            str_key("x"),
            PropertyDescriptor::Data {
                value: int_val(1),
                writable: true,
                enumerable: true,
                configurable: false,
            },
        )
        .unwrap();

        // Cannot change to accessor.
        let result = obj
            .define_own_property(
                str_key("x"),
                PropertyDescriptor::Accessor {
                    get: None,
                    set: None,
                    enumerable: true,
                    configurable: false,
                },
            )
            .unwrap();
        assert!(!result);
    }

    // -----------------------------------------------------------------------
    // 45. Non-configurable data: writable=false cannot become writable=true
    // -----------------------------------------------------------------------

    #[test]
    fn non_configurable_non_writable_cannot_become_writable() {
        let mut obj = OrdinaryObject::default();
        obj.define_own_property(
            str_key("x"),
            PropertyDescriptor::Data {
                value: int_val(1),
                writable: false,
                enumerable: true,
                configurable: false,
            },
        )
        .unwrap();

        let result = obj
            .define_own_property(
                str_key("x"),
                PropertyDescriptor::Data {
                    value: int_val(1),
                    writable: true,
                    enumerable: true,
                    configurable: false,
                },
            )
            .unwrap();
        assert!(!result);
    }

    // -----------------------------------------------------------------------
    // 46. Non-configurable accessor: cannot change get/set
    // -----------------------------------------------------------------------

    #[test]
    fn non_configurable_accessor_cannot_change_getset() {
        let mut obj = OrdinaryObject::default();
        obj.define_own_property(
            str_key("x"),
            PropertyDescriptor::Accessor {
                get: Some(ObjectHandle(1)),
                set: None,
                enumerable: true,
                configurable: false,
            },
        )
        .unwrap();

        // Change getter — rejected.
        let result = obj
            .define_own_property(
                str_key("x"),
                PropertyDescriptor::Accessor {
                    get: Some(ObjectHandle(2)),
                    set: None,
                    enumerable: true,
                    configurable: false,
                },
            )
            .unwrap();
        assert!(!result);
    }

    // -----------------------------------------------------------------------
    // 47. Configurable property can change type
    // -----------------------------------------------------------------------

    #[test]
    fn configurable_property_can_change_type() {
        let mut obj = OrdinaryObject::default();
        obj.define_own_property(str_key("x"), PropertyDescriptor::data(int_val(1)))
            .unwrap();

        let result = obj
            .define_own_property(
                str_key("x"),
                PropertyDescriptor::Accessor {
                    get: Some(ObjectHandle(1)),
                    set: None,
                    enumerable: true,
                    configurable: true,
                },
            )
            .unwrap();
        assert!(result);
        assert!(obj.get_own_property(&str_key("x")).unwrap().is_accessor());
    }

    // -----------------------------------------------------------------------
    // 48. Proxy invariant: [[DefineOwnProperty]] non-configurable on absent
    // -----------------------------------------------------------------------

    #[test]
    fn proxy_invariant_define_non_configurable_absent_target() {
        let obj = OrdinaryObject::default();
        let desc = PropertyDescriptor::Data {
            value: int_val(1),
            writable: true,
            enumerable: true,
            configurable: false,
        };

        // Cannot define non-configurable when target doesn't have the property.
        assert!(
            ProxyInvariantChecker::check_define_own_property(&obj, &str_key("x"), &desc, true)
                .is_err()
        );
    }

    // -----------------------------------------------------------------------
    // 49. JsValue is_object / is_callable
    // -----------------------------------------------------------------------

    #[test]
    fn js_value_predicates() {
        assert!(JsValue::Object(ObjectHandle(0)).is_object());
        assert!(!int_val(1).is_object());
        assert!(JsValue::Function(0).is_callable());
        assert!(!int_val(1).is_callable());
    }

    // -----------------------------------------------------------------------
    // 50. Object.assign multiple sources
    // -----------------------------------------------------------------------

    #[test]
    fn object_assign_multiple_sources() {
        let mut heap = ObjectHeap::new();
        let s1 = heap.alloc_plain();
        heap.set_property(s1, str_key("a"), int_val(1)).unwrap();
        let s2 = heap.alloc_plain();
        heap.set_property(s2, str_key("b"), int_val(2)).unwrap();
        heap.set_property(s2, str_key("a"), int_val(3)).unwrap(); // overrides s1.a

        let target = heap.alloc_plain();
        heap.assign(target, &[s1, s2]).unwrap();

        assert_eq!(
            heap.get_property(target, &str_key("a")).unwrap(),
            int_val(3)
        );
        assert_eq!(
            heap.get_property(target, &str_key("b")).unwrap(),
            int_val(2)
        );
    }

    // -----------------------------------------------------------------------
    // 51. Object.values
    // -----------------------------------------------------------------------

    #[test]
    fn object_values_enumerable_only() {
        let mut heap = ObjectHeap::new();
        let h = heap.alloc_plain();
        heap.set_property(h, str_key("a"), int_val(1)).unwrap();
        heap.set_property(h, str_key("b"), int_val(2)).unwrap();
        heap.define_property(
            h,
            str_key("hidden"),
            PropertyDescriptor::Data {
                value: int_val(3),
                writable: true,
                enumerable: false,
                configurable: true,
            },
        )
        .unwrap();
        // Symbol keys excluded from values.
        heap.define_property(
            h,
            PropertyKey::Symbol(SymbolId(100)),
            PropertyDescriptor::data(int_val(4)),
        )
        .unwrap();

        let vals = heap.values(h).unwrap();
        assert_eq!(vals, vec![int_val(1), int_val(2)]);
    }

    // -----------------------------------------------------------------------
    // 52. Object.entries
    // -----------------------------------------------------------------------

    #[test]
    fn object_entries_enumerable_string_keys_only() {
        let mut heap = ObjectHeap::new();
        let h = heap.alloc_plain();
        heap.set_property(h, str_key("x"), int_val(10)).unwrap();
        heap.set_property(h, str_key("y"), int_val(20)).unwrap();
        heap.define_property(
            h,
            str_key("secret"),
            PropertyDescriptor::Data {
                value: int_val(99),
                writable: true,
                enumerable: false,
                configurable: true,
            },
        )
        .unwrap();

        let entries = heap.entries(h).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0], ("x".to_string(), int_val(10)));
        assert_eq!(entries[1], ("y".to_string(), int_val(20)));
    }

    // -----------------------------------------------------------------------
    // 53. Object.defineProperties
    // -----------------------------------------------------------------------

    #[test]
    fn define_properties_multi() {
        let mut heap = ObjectHeap::new();
        let h = heap.alloc_plain();
        let props = vec![
            (str_key("a"), PropertyDescriptor::data(int_val(1))),
            (str_key("b"), PropertyDescriptor::data(int_val(2))),
            (str_key("c"), PropertyDescriptor::data(int_val(3))),
        ];
        assert!(heap.define_properties(h, props).unwrap());
        assert_eq!(heap.get_property(h, &str_key("a")).unwrap(), int_val(1));
        assert_eq!(heap.get_property(h, &str_key("b")).unwrap(), int_val(2));
        assert_eq!(heap.get_property(h, &str_key("c")).unwrap(), int_val(3));
    }

    #[test]
    fn define_properties_fails_on_non_extensible() {
        let mut heap = ObjectHeap::new();
        let h = heap.alloc_plain();
        heap.prevent_extensions(h).unwrap();
        let props = vec![(str_key("a"), PropertyDescriptor::data(int_val(1)))];
        assert!(!heap.define_properties(h, props).unwrap());
    }

    // -----------------------------------------------------------------------
    // 54. Object.getOwnPropertyDescriptors
    // -----------------------------------------------------------------------

    #[test]
    fn get_own_property_descriptors() {
        let mut heap = ObjectHeap::new();
        let h = heap.alloc_plain();
        heap.set_property(h, str_key("x"), int_val(1)).unwrap();
        heap.set_property(h, str_key("y"), int_val(2)).unwrap();

        let descs = heap.get_own_property_descriptors(h).unwrap();
        assert_eq!(descs.len(), 2);
        // Keys are in own_property_keys order.
        assert_eq!(descs[0].0, str_key("x"));
        assert_eq!(descs[1].0, str_key("y"));
    }

    // -----------------------------------------------------------------------
    // 55. for_in_keys (prototype chain enumeration)
    // -----------------------------------------------------------------------

    #[test]
    fn for_in_keys_walks_prototype_chain() {
        let mut heap = ObjectHeap::new();
        let proto = heap.alloc_plain();
        heap.set_property(proto, str_key("inherited"), int_val(1))
            .unwrap();

        let child = heap.alloc(Some(proto));
        heap.set_property(child, str_key("own"), int_val(2))
            .unwrap();

        let keys = heap.for_in_keys(child).unwrap();
        assert_eq!(keys, vec!["own".to_string(), "inherited".to_string()]);
    }

    #[test]
    fn for_in_keys_shadows_inherited() {
        let mut heap = ObjectHeap::new();
        let proto = heap.alloc_plain();
        heap.set_property(proto, str_key("x"), int_val(1)).unwrap();
        heap.set_property(proto, str_key("y"), int_val(2)).unwrap();

        let child = heap.alloc(Some(proto));
        heap.set_property(child, str_key("x"), int_val(3)).unwrap();

        let keys = heap.for_in_keys(child).unwrap();
        // "x" from child shadows proto's "x"; "y" is inherited
        assert_eq!(keys, vec!["x".to_string(), "y".to_string()]);
    }

    #[test]
    fn for_in_keys_skips_non_enumerable() {
        let mut heap = ObjectHeap::new();
        let proto = heap.alloc_plain();
        heap.define_property(
            proto,
            str_key("hidden"),
            PropertyDescriptor::Data {
                value: int_val(1),
                writable: true,
                enumerable: false,
                configurable: true,
            },
        )
        .unwrap();
        heap.set_property(proto, str_key("visible"), int_val(2))
            .unwrap();

        let child = heap.alloc(Some(proto));
        let keys = heap.for_in_keys(child).unwrap();
        assert_eq!(keys, vec!["visible".to_string()]);
    }

    #[test]
    fn for_in_keys_skips_symbols() {
        let mut heap = ObjectHeap::new();
        let h = heap.alloc_plain();
        heap.set_property(h, str_key("a"), int_val(1)).unwrap();
        heap.define_property(
            h,
            PropertyKey::Symbol(SymbolId(100)),
            PropertyDescriptor::data(int_val(2)),
        )
        .unwrap();

        let keys = heap.for_in_keys(h).unwrap();
        assert_eq!(keys, vec!["a".to_string()]);
    }

    #[test]
    fn for_in_keys_three_level_chain() {
        let mut heap = ObjectHeap::new();
        let gp = heap.alloc_plain();
        heap.set_property(gp, str_key("g"), int_val(1)).unwrap();
        let parent = heap.alloc(Some(gp));
        heap.set_property(parent, str_key("p"), int_val(2)).unwrap();
        let child = heap.alloc(Some(parent));
        heap.set_property(child, str_key("c"), int_val(3)).unwrap();

        let keys = heap.for_in_keys(child).unwrap();
        assert_eq!(
            keys,
            vec!["c".to_string(), "p".to_string(), "g".to_string()]
        );
    }

    // -----------------------------------------------------------------------
    // 56. Reflect API
    // -----------------------------------------------------------------------

    #[test]
    fn reflect_get_set() {
        let mut heap = ObjectHeap::new();
        let h = heap.alloc_plain();
        assert!(Reflect::set(&mut heap, h, str_key("x"), int_val(42)).unwrap());
        assert_eq!(Reflect::get(&heap, h, &str_key("x")).unwrap(), int_val(42));
    }

    #[test]
    fn reflect_has() {
        let mut heap = ObjectHeap::new();
        let h = heap.alloc_plain();
        Reflect::set(&mut heap, h, str_key("x"), int_val(1)).unwrap();
        assert!(Reflect::has(&heap, h, &str_key("x")).unwrap());
        assert!(!Reflect::has(&heap, h, &str_key("y")).unwrap());
    }

    #[test]
    fn reflect_delete_property() {
        let mut heap = ObjectHeap::new();
        let h = heap.alloc_plain();
        Reflect::set(&mut heap, h, str_key("x"), int_val(1)).unwrap();
        assert!(Reflect::delete_property(&mut heap, h, &str_key("x")).unwrap());
        assert!(!Reflect::has(&heap, h, &str_key("x")).unwrap());
    }

    #[test]
    fn reflect_own_keys() {
        let mut heap = ObjectHeap::new();
        let h = heap.alloc_plain();
        Reflect::set(&mut heap, h, str_key("a"), int_val(1)).unwrap();
        Reflect::set(&mut heap, h, str_key("b"), int_val(2)).unwrap();
        let keys = Reflect::own_keys(&heap, h).unwrap();
        assert_eq!(keys, vec![str_key("a"), str_key("b")]);
    }

    #[test]
    fn reflect_prototype_of() {
        let mut heap = ObjectHeap::new();
        let proto = heap.alloc_plain();
        let obj = heap.alloc(Some(proto));
        assert_eq!(Reflect::get_prototype_of(&heap, obj).unwrap(), Some(proto));
    }

    #[test]
    fn reflect_set_prototype_of() {
        let mut heap = ObjectHeap::new();
        let h = heap.alloc_plain();
        let new_proto = heap.alloc_plain();
        assert!(Reflect::set_prototype_of(&mut heap, h, Some(new_proto)).unwrap());
        assert_eq!(
            Reflect::get_prototype_of(&heap, h).unwrap(),
            Some(new_proto)
        );
    }

    #[test]
    fn reflect_is_extensible_and_prevent() {
        let mut heap = ObjectHeap::new();
        let h = heap.alloc_plain();
        assert!(Reflect::is_extensible(&heap, h).unwrap());
        assert!(Reflect::prevent_extensions(&mut heap, h).unwrap());
        assert!(!Reflect::is_extensible(&heap, h).unwrap());
    }

    #[test]
    fn reflect_define_and_get_own_property_descriptor() {
        let mut heap = ObjectHeap::new();
        let h = heap.alloc_plain();
        let desc = PropertyDescriptor::data(int_val(42));
        assert!(Reflect::define_property(&mut heap, h, str_key("x"), desc.clone()).unwrap());
        let got = Reflect::get_own_property_descriptor(&heap, h, &str_key("x")).unwrap();
        assert_eq!(got, Some(desc));
    }

    // -----------------------------------------------------------------------
    // 57. Edge: empty object operations
    // -----------------------------------------------------------------------

    #[test]
    fn empty_object_values_entries_keys() {
        let mut heap = ObjectHeap::new();
        let h = heap.alloc_plain();
        assert!(heap.keys(h).unwrap().is_empty());
        assert!(heap.values(h).unwrap().is_empty());
        assert!(heap.entries(h).unwrap().is_empty());
        assert!(heap.for_in_keys(h).unwrap().is_empty());
    }

    // -----------------------------------------------------------------------
    // 58. Edge: Object.assign with empty source
    // -----------------------------------------------------------------------

    #[test]
    fn object_assign_empty_sources() {
        let mut heap = ObjectHeap::new();
        let target = heap.alloc_plain();
        heap.set_property(target, str_key("x"), int_val(1)).unwrap();
        heap.assign(target, &[]).unwrap();
        assert_eq!(
            heap.get_property(target, &str_key("x")).unwrap(),
            int_val(1)
        );
    }

    // -----------------------------------------------------------------------
    // 59. Edge: frozen object rejects define_property
    // -----------------------------------------------------------------------

    #[test]
    fn frozen_object_rejects_define() {
        let mut heap = ObjectHeap::new();
        let h = heap.alloc_plain();
        heap.set_property(h, str_key("x"), int_val(1)).unwrap();
        heap.freeze(h).unwrap();

        // Cannot redefine existing frozen property to different value.
        let result = heap
            .define_property(
                h,
                str_key("x"),
                PropertyDescriptor::Data {
                    value: int_val(2),
                    writable: false,
                    enumerable: true,
                    configurable: false,
                },
            )
            .unwrap();
        assert!(!result);

        // Cannot add new property.
        let result = heap
            .define_property(h, str_key("y"), PropertyDescriptor::data(int_val(3)))
            .unwrap();
        assert!(!result);
    }

    // -----------------------------------------------------------------------
    // 60. Edge: sealed object allows value change on writable property
    // -----------------------------------------------------------------------

    #[test]
    fn sealed_object_allows_value_change() {
        let mut heap = ObjectHeap::new();
        let h = heap.alloc_plain();
        heap.set_property(h, str_key("x"), int_val(1)).unwrap();
        heap.seal(h).unwrap();

        // Data property is sealed (non-configurable) but writable.
        // Define with same attributes but different value should succeed.
        let result = heap
            .define_property(
                h,
                str_key("x"),
                PropertyDescriptor::Data {
                    value: int_val(2),
                    writable: true,
                    enumerable: true,
                    configurable: false,
                },
            )
            .unwrap();
        assert!(result);
    }

    // -----------------------------------------------------------------------
    // 61. Object.create(null) — no prototype
    // -----------------------------------------------------------------------

    #[test]
    fn object_create_null_prototype() {
        let mut heap = ObjectHeap::new();
        let h = heap.create(None);
        assert_eq!(heap.get_prototype_of(h).unwrap(), None);
        // Property lookup with no prototype returns undefined.
        assert_eq!(
            heap.get_property(h, &str_key("anything")).unwrap(),
            JsValue::Undefined
        );
    }

    // -----------------------------------------------------------------------
    // 62. Proxy wrapping proxy
    // -----------------------------------------------------------------------

    #[test]
    fn proxy_wrapping_proxy() {
        let mut heap = ObjectHeap::new();
        let target = heap.alloc_plain();
        let handler1 = heap.alloc_plain();
        let inner_proxy = heap.alloc_proxy(target, handler1);

        let handler2 = heap.alloc_plain();
        let outer_proxy = heap.alloc_proxy(inner_proxy, handler2);

        // Outer is a proxy wrapping inner proxy.
        let outer = heap.get(outer_proxy).unwrap();
        let proxy = outer.as_proxy().unwrap();
        assert_eq!(proxy.target().unwrap(), inner_proxy);

        // Inner is a proxy wrapping target.
        let inner = heap.get(inner_proxy).unwrap();
        let inner_p = inner.as_proxy().unwrap();
        assert_eq!(inner_p.target().unwrap(), target);
    }

    // -----------------------------------------------------------------------
    // 63. Revocable proxy — double revoke is idempotent
    // -----------------------------------------------------------------------

    #[test]
    fn proxy_double_revoke_idempotent() {
        let mut heap = ObjectHeap::new();
        let target = heap.alloc_plain();
        let handler = heap.alloc_plain();
        let proxy = heap.alloc_proxy(target, handler);

        heap.revoke_proxy(proxy).unwrap();
        heap.revoke_proxy(proxy).unwrap(); // second revoke succeeds

        let p = heap.get(proxy).unwrap().as_proxy().unwrap();
        assert!(p.is_revoked());
    }

    // -----------------------------------------------------------------------
    // 64. Proxy invariant: [[GetOwnProperty]] non-configurable must match
    // -----------------------------------------------------------------------

    #[test]
    fn proxy_invariant_get_own_property_non_configurable() {
        let mut obj = OrdinaryObject::default();
        obj.define_own_property(
            str_key("x"),
            PropertyDescriptor::Data {
                value: int_val(42),
                writable: false,
                enumerable: true,
                configurable: false,
            },
        )
        .unwrap();

        // Trap returns non-configurable with different value — error.
        let bad_desc = Some(PropertyDescriptor::Data {
            value: int_val(99),
            writable: false,
            enumerable: true,
            configurable: false,
        });
        assert!(
            ProxyInvariantChecker::check_get_own_property(&obj, &str_key("x"), &bad_desc).is_err()
        );

        // Trap returns non-configurable with same value — ok.
        let good_desc = Some(PropertyDescriptor::Data {
            value: int_val(42),
            writable: false,
            enumerable: true,
            configurable: false,
        });
        assert!(
            ProxyInvariantChecker::check_get_own_property(&obj, &str_key("x"), &good_desc).is_ok()
        );
    }

    // -----------------------------------------------------------------------
    // 65. Proxy invariant: [[DefineOwnProperty]] non-configurable value match
    // -----------------------------------------------------------------------

    #[test]
    fn proxy_invariant_define_non_configurable_value_mismatch() {
        let mut obj = OrdinaryObject::default();
        obj.define_own_property(
            str_key("x"),
            PropertyDescriptor::Data {
                value: int_val(42),
                writable: false,
                enumerable: true,
                configurable: false,
            },
        )
        .unwrap();

        // Trap defines non-configurable non-writable with different value.
        let desc = PropertyDescriptor::Data {
            value: int_val(99),
            writable: false,
            enumerable: true,
            configurable: false,
        };
        assert!(
            ProxyInvariantChecker::check_define_own_property(&obj, &str_key("x"), &desc, true)
                .is_err()
        );
    }

    // -----------------------------------------------------------------------
    // 66. Proxy invariant: [[Delete]] non-extensible any own property
    // -----------------------------------------------------------------------

    #[test]
    #[allow(clippy::field_reassign_with_default)]
    fn proxy_invariant_delete_non_extensible_own_property() {
        let mut obj = OrdinaryObject::default();
        obj.define_own_property(str_key("x"), PropertyDescriptor::data_frozen(int_val(1)))
            .unwrap();
        obj.extensible = false;

        // Cannot delete non-configurable own property on non-extensible target.
        assert!(ProxyInvariantChecker::check_delete(&obj, &str_key("x"), true).is_err());
    }

    // -----------------------------------------------------------------------
    // 67. Integer index ordering in own_property_keys
    // -----------------------------------------------------------------------

    #[test]
    fn own_property_keys_integer_order() {
        let mut obj = OrdinaryObject::default();
        // Insert in non-sorted order.
        for key in ["100", "3", "10", "1", "0"] {
            obj.define_own_property(str_key(key), PropertyDescriptor::data(int_val(0)))
                .unwrap();
        }
        let keys = obj.own_property_keys();
        let strs: Vec<&str> = keys
            .iter()
            .filter_map(|k| match k {
                PropertyKey::String(s) => Some(s.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(strs, vec!["0", "1", "3", "10", "100"]);
    }

    // -----------------------------------------------------------------------
    // 68. Non-configurable enumerable change blocked
    // -----------------------------------------------------------------------

    #[test]
    fn non_configurable_enumerable_change_blocked() {
        let mut obj = OrdinaryObject::default();
        obj.define_own_property(
            str_key("x"),
            PropertyDescriptor::Data {
                value: int_val(1),
                writable: true,
                enumerable: true,
                configurable: false,
            },
        )
        .unwrap();

        // Try to change enumerable — rejected.
        let result = obj
            .define_own_property(
                str_key("x"),
                PropertyDescriptor::Data {
                    value: int_val(1),
                    writable: true,
                    enumerable: false,
                    configurable: false,
                },
            )
            .unwrap();
        assert!(!result);
    }

    // -----------------------------------------------------------------------
    // 69. Symbol property key serde with well-known
    // -----------------------------------------------------------------------

    #[test]
    fn symbol_property_with_well_known() {
        let mut heap = ObjectHeap::new();
        let h = heap.alloc_plain();
        let iter_key = WellKnownSymbol::Iterator.key();
        heap.define_property(h, iter_key.clone(), PropertyDescriptor::data(int_val(1)))
            .unwrap();

        let desc = heap.get_own_property_descriptor(h, &iter_key).unwrap();
        assert!(desc.is_some());
        assert_eq!(desc.unwrap().value(), Some(&int_val(1)));
    }

    // -----------------------------------------------------------------------
    // 70. OrdinaryObject class_tag and callable/constructable
    // -----------------------------------------------------------------------

    #[test]
    fn ordinary_object_class_tag_callable() {
        let mut obj = OrdinaryObject::default();
        assert!(!obj.callable);
        assert!(!obj.constructable);
        assert!(obj.class_tag.is_none());

        obj.callable = true;
        obj.constructable = true;
        obj.class_tag = Some("Function".to_string());
        assert!(obj.callable);
        assert!(obj.constructable);
        assert_eq!(obj.class_tag.as_deref(), Some("Function"));
    }

    // -----------------------------------------------------------------------
    // 71. Serde round-trip for OrdinaryObject
    // -----------------------------------------------------------------------

    #[test]
    #[allow(clippy::field_reassign_with_default)]
    fn ordinary_object_serde_roundtrip() {
        let mut obj = OrdinaryObject::default();
        obj.define_own_property(str_key("x"), PropertyDescriptor::data(int_val(42)))
            .unwrap();
        obj.prototype = Some(ObjectHandle(5));
        obj.class_tag = Some("TestObj".to_string());

        let json = serde_json::to_string(&obj).unwrap();
        let deser: OrdinaryObject = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.prototype, Some(ObjectHandle(5)));
        assert_eq!(deser.class_tag.as_deref(), Some("TestObj"));
        assert!(deser.has_own_property(&str_key("x")));
    }

    // -----------------------------------------------------------------------
    // 72. Serde round-trip for ObjectHeap
    // -----------------------------------------------------------------------

    #[test]
    fn object_heap_serde_roundtrip() {
        let mut heap = ObjectHeap::new();
        let h = heap.alloc_plain();
        heap.set_property(h, str_key("key"), str_val("value"))
            .unwrap();

        let json = serde_json::to_string(&heap).unwrap();
        let deser: ObjectHeap = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.len(), 1);
        assert_eq!(
            deser
                .get_property(ObjectHandle(0), &str_key("key"))
                .unwrap(),
            str_val("value")
        );
    }

    // -----------------------------------------------------------------------
    // 73. Serde round-trip for SymbolRegistry
    // -----------------------------------------------------------------------

    #[test]
    fn symbol_registry_serde_roundtrip() {
        let mut heap = ObjectHeap::new();
        let mut reg = SymbolRegistry::new();
        let sym = reg.symbol_for("test_key", &mut heap);

        let json = serde_json::to_string(&reg).unwrap();
        let deser: SymbolRegistry = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.key_for(sym), Some("test_key"));
    }

    // -----------------------------------------------------------------------
    // 74. Proxy invariant: [[Has]] non-extensible existing property
    // -----------------------------------------------------------------------

    #[test]
    #[allow(clippy::field_reassign_with_default)]
    fn proxy_invariant_has_non_extensible_existing() {
        let mut obj = OrdinaryObject::default();
        obj.define_own_property(str_key("x"), PropertyDescriptor::data(int_val(1)))
            .unwrap();
        obj.extensible = false;

        // Cannot report existing property as non-existent on non-extensible.
        assert!(ProxyInvariantChecker::check_has(&obj, &str_key("x"), false).is_err());
        assert!(ProxyInvariantChecker::check_has(&obj, &str_key("x"), true).is_ok());
    }

    // -----------------------------------------------------------------------
    // 75. Proxy invariant: [[GetOwnProperty]] non-configurable on configurable target
    // -----------------------------------------------------------------------

    #[test]
    fn proxy_invariant_get_own_property_non_config_on_config_target() {
        let mut obj = OrdinaryObject::default();
        obj.define_own_property(str_key("x"), PropertyDescriptor::data(int_val(1)))
            .unwrap(); // configurable=true

        // Trap returns non-configurable — error because target's property is configurable.
        let trap_desc = Some(PropertyDescriptor::Data {
            value: int_val(1),
            writable: true,
            enumerable: true,
            configurable: false,
        });
        assert!(
            ProxyInvariantChecker::check_get_own_property(&obj, &str_key("x"), &trap_desc).is_err()
        );
    }

    // -----------------------------------------------------------------------
    // 76. Reflect mirrors heap operations exactly
    // -----------------------------------------------------------------------

    #[test]
    fn reflect_matches_heap_semantics() {
        let mut heap = ObjectHeap::new();
        let proto = heap.alloc_plain();
        Reflect::set(&mut heap, proto, str_key("inherited"), int_val(100)).unwrap();

        let child = heap.alloc(Some(proto));

        // Reflect.get walks prototype chain just like heap.get_property.
        assert_eq!(
            Reflect::get(&heap, child, &str_key("inherited")).unwrap(),
            int_val(100)
        );

        // Reflect.has walks prototype chain.
        assert!(Reflect::has(&heap, child, &str_key("inherited")).unwrap());

        // Reflect.getOwnPropertyDescriptor does NOT walk prototype chain.
        assert_eq!(
            Reflect::get_own_property_descriptor(&heap, child, &str_key("inherited")).unwrap(),
            None
        );
    }

    // -----------------------------------------------------------------------
    // 77. Proxy invariant: [[Set]] on configurable writable allows different value
    // -----------------------------------------------------------------------

    #[test]
    fn proxy_invariant_set_configurable_writable_allows_different() {
        let mut obj = OrdinaryObject::default();
        obj.define_own_property(str_key("x"), PropertyDescriptor::data(int_val(1)))
            .unwrap(); // configurable=true, writable=true

        // Setting different value should be allowed.
        assert!(ProxyInvariantChecker::check_set(&obj, &str_key("x"), &int_val(99), true).is_ok());
    }

    // -----------------------------------------------------------------------
    // 78. for_in_keys: non-enumerable prototype property is excluded
    // -----------------------------------------------------------------------

    #[test]
    fn for_in_keys_non_enumerable_proto_excluded() {
        let mut heap = ObjectHeap::new();
        let proto = heap.alloc_plain();
        heap.define_property(
            proto,
            str_key("hidden"),
            PropertyDescriptor::Data {
                value: int_val(1),
                writable: true,
                enumerable: false,
                configurable: true,
            },
        )
        .unwrap();

        let child = heap.alloc(Some(proto));
        heap.set_property(child, str_key("own"), int_val(2))
            .unwrap();

        let keys = heap.for_in_keys(child).unwrap();
        assert_eq!(keys, vec!["own".to_string()]);
    }

    // -----------------------------------------------------------------------
    // 79. Object.values on frozen object
    // -----------------------------------------------------------------------

    #[test]
    fn values_on_frozen_object() {
        let mut heap = ObjectHeap::new();
        let h = heap.alloc_plain();
        heap.set_property(h, str_key("a"), int_val(1)).unwrap();
        heap.set_property(h, str_key("b"), int_val(2)).unwrap();
        heap.freeze(h).unwrap();

        // Frozen properties are non-enumerable per our freeze impl? No — freeze only
        // sets non-configurable and non-writable but keeps enumerable unchanged.
        // Actually, freeze doesn't change enumerable. Let me verify:
        // Our freeze() calls set_non_configurable() and set_non_writable().
        // It does NOT call set_non_enumerable().
        // So frozen values are still enumerable and should appear.
        let vals = heap.values(h).unwrap();
        assert_eq!(vals, vec![int_val(1), int_val(2)]);
    }

    // -----------------------------------------------------------------------
    // 80. Reflect.set on frozen property returns false
    // -----------------------------------------------------------------------

    #[test]
    fn reflect_set_frozen_returns_false() {
        let mut heap = ObjectHeap::new();
        let h = heap.alloc_plain();
        Reflect::set(&mut heap, h, str_key("x"), int_val(1)).unwrap();
        heap.freeze(h).unwrap();

        let result = Reflect::set(&mut heap, h, str_key("x"), int_val(2)).unwrap();
        assert!(!result);
        // Value unchanged.
        assert_eq!(Reflect::get(&heap, h, &str_key("x")).unwrap(), int_val(1));
    }

    // -----------------------------------------------------------------------
    // 81. Object.getOwnPropertyNames — all own string keys including non-enumerable
    // -----------------------------------------------------------------------

    #[test]
    fn get_own_property_names_includes_non_enumerable() {
        let mut heap = ObjectHeap::new();
        let h = heap.alloc_plain();
        heap.set_property(h, str_key("visible"), int_val(1))
            .unwrap();
        heap.define_property(
            h,
            str_key("hidden"),
            PropertyDescriptor::Data {
                value: int_val(2),
                writable: true,
                enumerable: false,
                configurable: true,
            },
        )
        .unwrap();

        let names = heap.get_own_property_names(h).unwrap();
        assert!(names.contains(&"visible".to_string()));
        assert!(names.contains(&"hidden".to_string()));
        assert_eq!(names.len(), 2);
    }

    // -----------------------------------------------------------------------
    // 82. Object.getOwnPropertyNames excludes symbol keys
    // -----------------------------------------------------------------------

    #[test]
    fn get_own_property_names_excludes_symbols() {
        let mut heap = ObjectHeap::new();
        let h = heap.alloc_plain();
        heap.set_property(h, str_key("a"), int_val(1)).unwrap();
        heap.define_property(
            h,
            WellKnownSymbol::Iterator.key(),
            PropertyDescriptor::data(int_val(99)),
        )
        .unwrap();

        let names = heap.get_own_property_names(h).unwrap();
        assert_eq!(names, vec!["a".to_string()]);
    }

    // -----------------------------------------------------------------------
    // 83. Object.getOwnPropertySymbols — returns only symbol keys
    // -----------------------------------------------------------------------

    #[test]
    fn get_own_property_symbols_basic() {
        let mut heap = ObjectHeap::new();
        let h = heap.alloc_plain();
        heap.set_property(h, str_key("a"), int_val(1)).unwrap();
        let sym = WellKnownSymbol::ToStringTag.id();
        heap.define_property(
            h,
            PropertyKey::Symbol(sym),
            PropertyDescriptor::data(str_val("MyClass")),
        )
        .unwrap();

        let syms = heap.get_own_property_symbols(h).unwrap();
        assert_eq!(syms, vec![sym]);
    }

    // -----------------------------------------------------------------------
    // 84. Object.fromEntries — creates object from key-value pairs
    // -----------------------------------------------------------------------

    #[test]
    fn from_entries_basic() {
        let mut heap = ObjectHeap::new();
        let entries = vec![("x".to_string(), int_val(1)), ("y".to_string(), int_val(2))];
        let h = heap.from_entries(entries);

        assert_eq!(heap.get_property(h, &str_key("x")).unwrap(), int_val(1));
        assert_eq!(heap.get_property(h, &str_key("y")).unwrap(), int_val(2));
    }

    // -----------------------------------------------------------------------
    // 85. Object.fromEntries — later entries overwrite earlier for same key
    // -----------------------------------------------------------------------

    #[test]
    fn from_entries_overwrite() {
        let mut heap = ObjectHeap::new();
        let entries = vec![
            ("x".to_string(), int_val(1)),
            ("x".to_string(), int_val(99)),
        ];
        let h = heap.from_entries(entries);
        assert_eq!(heap.get_property(h, &str_key("x")).unwrap(), int_val(99));
    }

    // -----------------------------------------------------------------------
    // 86. Object.fromEntries — empty input produces empty object
    // -----------------------------------------------------------------------

    #[test]
    fn from_entries_empty() {
        let mut heap = ObjectHeap::new();
        let h = heap.from_entries(vec![]);
        assert_eq!(heap.keys(h).unwrap().len(), 0);
    }

    // -----------------------------------------------------------------------
    // 87. Object.hasOwn — detects own property without prototype walk
    // -----------------------------------------------------------------------

    #[test]
    fn has_own_true_for_own_property() {
        let mut heap = ObjectHeap::new();
        let h = heap.alloc_plain();
        heap.set_property(h, str_key("x"), int_val(1)).unwrap();
        assert!(heap.has_own(h, &str_key("x")).unwrap());
    }

    #[test]
    fn has_own_false_for_inherited() {
        let mut heap = ObjectHeap::new();
        let proto = heap.alloc_plain();
        heap.set_property(proto, str_key("inherited"), int_val(1))
            .unwrap();
        let child = heap.alloc(Some(proto));
        assert!(!heap.has_own(child, &str_key("inherited")).unwrap());
        // But has_property should find it.
        assert!(heap.has_property(child, &str_key("inherited")).unwrap());
    }

    // -----------------------------------------------------------------------
    // 89. Proxy invariant: nested proxy (3 levels) with non-configurable property
    // -----------------------------------------------------------------------

    #[test]
    fn proxy_nested_three_levels_alloc() {
        let mut heap = ObjectHeap::new();
        let target = heap.alloc_plain();
        let h1 = heap.alloc_plain();
        let h2 = heap.alloc_plain();
        let h3 = heap.alloc_plain();

        let proxy1 = heap.alloc_proxy(target, h1);
        let proxy2 = heap.alloc_proxy(proxy1, h2);
        let proxy3 = heap.alloc_proxy(proxy2, h3);

        // All three should be proxy objects.
        assert!(heap.get(proxy1).unwrap().as_proxy().is_some());
        assert!(heap.get(proxy2).unwrap().as_proxy().is_some());
        assert!(heap.get(proxy3).unwrap().as_proxy().is_some());

        // Outermost proxy's target is proxy2.
        let p3 = heap.get(proxy3).unwrap().as_proxy().unwrap();
        assert_eq!(p3.target().unwrap(), proxy2);
    }

    // -----------------------------------------------------------------------
    // 90. Revocable proxy: double revoke is idempotent
    // -----------------------------------------------------------------------

    #[test]
    fn proxy_revoke_idempotent() {
        let mut heap = ObjectHeap::new();
        let target = heap.alloc_plain();
        let handler = heap.alloc_plain();
        let proxy = heap.alloc_proxy(target, handler);

        heap.revoke_proxy(proxy).unwrap();
        // Second revoke should also succeed.
        heap.revoke_proxy(proxy).unwrap();

        let p = heap.get(proxy).unwrap().as_proxy().unwrap();
        assert!(p.is_revoked());
    }

    // -----------------------------------------------------------------------
    // 91. Proxy invariant: revoked proxy target() and handler() return errors
    // -----------------------------------------------------------------------

    #[test]
    fn proxy_revoked_target_handler_error() {
        let mut heap = ObjectHeap::new();
        let target = heap.alloc_plain();
        let handler = heap.alloc_plain();
        let proxy = heap.alloc_proxy(target, handler);
        heap.revoke_proxy(proxy).unwrap();

        let p = heap.get(proxy).unwrap().as_proxy().unwrap();
        assert_eq!(p.target().unwrap_err(), ObjectError::ProxyRevoked);
        assert_eq!(p.handler().unwrap_err(), ObjectError::ProxyRevoked);
    }

    // -----------------------------------------------------------------------
    // 92. Proxy invariant: check_get on non-configurable accessor with undefined getter
    // -----------------------------------------------------------------------

    #[test]
    fn proxy_check_get_non_configurable_accessor_undefined_getter() {
        let mut target = OrdinaryObject::default();
        target
            .define_own_property(
                str_key("prop"),
                PropertyDescriptor::Accessor {
                    get: None,
                    set: Some(ObjectHandle(99)),
                    enumerable: true,
                    configurable: false,
                },
            )
            .unwrap();

        // Must return undefined.
        assert!(
            ProxyInvariantChecker::check_get(&target, &str_key("prop"), &JsValue::Undefined)
                .is_ok()
        );
        // Returning anything else is a violation.
        assert!(ProxyInvariantChecker::check_get(&target, &str_key("prop"), &int_val(42)).is_err());
    }

    // -----------------------------------------------------------------------
    // 93. Proxy invariant: check_delete on non-extensible target
    // -----------------------------------------------------------------------

    #[test]
    fn proxy_check_delete_non_extensible_own_property() {
        let mut target = OrdinaryObject::default();
        target
            .define_own_property(str_key("x"), PropertyDescriptor::data_frozen(int_val(1)))
            .unwrap();
        target.prevent_extensions();

        // Non-extensible target: cannot delete non-configurable own property.
        assert!(ProxyInvariantChecker::check_delete(&target, &str_key("x"), true).is_err());
    }

    // -----------------------------------------------------------------------
    // 94. Proxy invariant: check_own_keys duplicate detection
    // -----------------------------------------------------------------------

    #[test]
    fn proxy_check_own_keys_rejects_duplicates() {
        let target = OrdinaryObject::default();
        let keys = vec![str_key("a"), str_key("a")];
        assert!(ProxyInvariantChecker::check_own_keys(&target, &keys).is_err());
    }

    // -----------------------------------------------------------------------
    // 95. Proxy invariant: check_own_keys non-extensible exact permutation
    // -----------------------------------------------------------------------

    #[test]
    fn proxy_check_own_keys_non_extensible_exact() {
        let mut target = OrdinaryObject::default();
        target
            .define_own_property(str_key("a"), PropertyDescriptor::data(int_val(1)))
            .unwrap();
        target
            .define_own_property(str_key("b"), PropertyDescriptor::data(int_val(2)))
            .unwrap();
        target.prevent_extensions();

        // Exact set: ok.
        assert!(
            ProxyInvariantChecker::check_own_keys(&target, &[str_key("a"), str_key("b")]).is_ok()
        );
        // Reversed order also ok (permutation).
        assert!(
            ProxyInvariantChecker::check_own_keys(&target, &[str_key("b"), str_key("a")]).is_ok()
        );
        // Missing key: error.
        assert!(ProxyInvariantChecker::check_own_keys(&target, &[str_key("a")]).is_err());
        // Extra key: error.
        assert!(
            ProxyInvariantChecker::check_own_keys(
                &target,
                &[str_key("a"), str_key("b"), str_key("c")]
            )
            .is_err()
        );
    }

    // -----------------------------------------------------------------------
    // 96. Proxy invariant: check_is_extensible must match target
    // -----------------------------------------------------------------------

    #[test]
    fn proxy_check_is_extensible_mismatch() {
        let target = OrdinaryObject::default(); // extensible=true
        assert!(ProxyInvariantChecker::check_is_extensible(&target, true).is_ok());
        assert!(ProxyInvariantChecker::check_is_extensible(&target, false).is_err());

        let mut non_ext = OrdinaryObject::default();
        non_ext.prevent_extensions();
        assert!(ProxyInvariantChecker::check_is_extensible(&non_ext, false).is_ok());
        assert!(ProxyInvariantChecker::check_is_extensible(&non_ext, true).is_err());
    }

    // -----------------------------------------------------------------------
    // 97. Proxy invariant: check_prevent_extensions target must be non-extensible
    // -----------------------------------------------------------------------

    #[test]
    fn proxy_check_prevent_extensions_target_still_extensible() {
        let target = OrdinaryObject::default(); // extensible=true
        // Trap says it succeeded, but target is still extensible → error.
        assert!(ProxyInvariantChecker::check_prevent_extensions(&target, true).is_err());
        // Trap returns false → ok (no-op).
        assert!(ProxyInvariantChecker::check_prevent_extensions(&target, false).is_ok());
    }

    // -----------------------------------------------------------------------
    // 98. Proxy invariant: check_set_prototype_of non-extensible different proto
    // -----------------------------------------------------------------------

    #[test]
    fn proxy_check_set_prototype_of_non_extensible() {
        let mut target = OrdinaryObject::with_prototype(Some(ObjectHandle(5)));
        target.prevent_extensions();

        // Setting to current proto → ok.
        assert!(
            ProxyInvariantChecker::check_set_prototype_of(&target, Some(ObjectHandle(5)), true)
                .is_ok()
        );
        // Setting to different proto → error.
        assert!(
            ProxyInvariantChecker::check_set_prototype_of(&target, Some(ObjectHandle(6)), true)
                .is_err()
        );
        // Trap returns false (didn't set) → ok regardless.
        assert!(
            ProxyInvariantChecker::check_set_prototype_of(&target, Some(ObjectHandle(6)), false)
                .is_ok()
        );
    }

    // -----------------------------------------------------------------------
    // 99. Proxy invariant: check_define_own_property non-extensible new property
    // -----------------------------------------------------------------------

    #[test]
    fn proxy_check_define_property_non_extensible_new() {
        let mut target = OrdinaryObject::default();
        target.prevent_extensions();

        // Trap claims it added a new property to non-extensible target → error.
        assert!(
            ProxyInvariantChecker::check_define_own_property(
                &target,
                &str_key("new_prop"),
                &PropertyDescriptor::data(int_val(1)),
                true,
            )
            .is_err()
        );
    }

    // -----------------------------------------------------------------------
    // 100. Property descriptor: data↔accessor type change on non-configurable
    // -----------------------------------------------------------------------

    #[test]
    fn define_own_property_rejects_data_to_accessor_non_configurable() {
        let mut obj = OrdinaryObject::default();
        obj.define_own_property(
            str_key("x"),
            PropertyDescriptor::Data {
                value: int_val(1),
                writable: true,
                enumerable: true,
                configurable: false,
            },
        )
        .unwrap();

        // Try to redefine as accessor → rejected.
        let result = obj
            .define_own_property(
                str_key("x"),
                PropertyDescriptor::Accessor {
                    get: Some(ObjectHandle(1)),
                    set: None,
                    enumerable: true,
                    configurable: false,
                },
            )
            .unwrap();
        assert!(!result);
    }

    // -----------------------------------------------------------------------
    // 101. Object.assign copies symbol-keyed enumerable properties
    // -----------------------------------------------------------------------

    #[test]
    fn assign_copies_symbol_properties() {
        let mut heap = ObjectHeap::new();
        let src = heap.alloc_plain();
        let sym = WellKnownSymbol::ToStringTag.id();
        heap.define_property(
            src,
            PropertyKey::Symbol(sym),
            PropertyDescriptor::data(str_val("Source")),
        )
        .unwrap();

        let target = heap.alloc_plain();
        // Object.assign copies ALL enumerable own properties including symbols.
        heap.assign(target, &[src]).unwrap();

        // Verify via get_own_property_descriptor.
        let desc = heap
            .get_own_property_descriptor(target, &PropertyKey::Symbol(sym))
            .unwrap();
        assert!(desc.is_some());
        assert_eq!(desc.unwrap().value(), Some(&str_val("Source")));
    }

    // -----------------------------------------------------------------------
    // 102. Sealed object: properties are writable but not deletable/reconfigurable
    // -----------------------------------------------------------------------

    #[test]
    fn sealed_object_writable_but_not_deletable() {
        let mut heap = ObjectHeap::new();
        let h = heap.alloc_plain();
        heap.set_property(h, str_key("x"), int_val(1)).unwrap();
        heap.seal(h).unwrap();

        // Can update existing property.
        assert!(heap.set_property(h, str_key("x"), int_val(2)).unwrap());
        assert_eq!(heap.get_property(h, &str_key("x")).unwrap(), int_val(2));

        // Cannot add new property.
        assert!(!heap.set_property(h, str_key("new"), int_val(3)).unwrap());

        // Cannot delete.
        assert!(!heap.delete_property(h, &str_key("x")).unwrap());
    }

    // -----------------------------------------------------------------------
    // 103. Prototype chain: property shadowing with accessor descriptor
    // -----------------------------------------------------------------------

    #[test]
    fn prototype_shadowing_accessor() {
        let mut heap = ObjectHeap::new();
        let proto = heap.alloc_plain();
        // Prototype has accessor property.
        heap.define_property(
            proto,
            str_key("x"),
            PropertyDescriptor::Accessor {
                get: Some(ObjectHandle(77)),
                set: None,
                enumerable: true,
                configurable: true,
            },
        )
        .unwrap();

        let child = heap.alloc(Some(proto));
        // Child shadows with data property.
        heap.set_property(child, str_key("x"), int_val(42)).unwrap();

        // Child's own property takes precedence.
        assert_eq!(
            heap.get_property(child, &str_key("x")).unwrap(),
            int_val(42)
        );
    }

    // -----------------------------------------------------------------------
    // 104. Integer key ordering in own_property_keys
    // -----------------------------------------------------------------------

    #[test]
    fn own_property_keys_integer_ordering() {
        let mut obj = OrdinaryObject::default();
        // Insert in non-numeric order.
        obj.define_own_property(str_key("10"), PropertyDescriptor::data(int_val(10)))
            .unwrap();
        obj.define_own_property(str_key("2"), PropertyDescriptor::data(int_val(2)))
            .unwrap();
        obj.define_own_property(str_key("1"), PropertyDescriptor::data(int_val(1)))
            .unwrap();
        obj.define_own_property(str_key("foo"), PropertyDescriptor::data(str_val("bar")))
            .unwrap();

        let keys = obj.own_property_keys();
        // Integer keys sorted numerically first, then string keys.
        assert_eq!(keys[0], str_key("1"));
        assert_eq!(keys[1], str_key("2"));
        assert_eq!(keys[2], str_key("10"));
        assert_eq!(keys[3], str_key("foo"));
    }

    // -----------------------------------------------------------------------
    // 105. Symbol registry: keyFor returns None for non-global symbols
    // -----------------------------------------------------------------------

    #[test]
    fn symbol_key_for_non_global_returns_none() {
        let mut heap = ObjectHeap::new();
        let reg = SymbolRegistry::new();
        let private_sym = heap.alloc_symbol();
        assert!(reg.key_for(private_sym).is_none());
    }

    // -----------------------------------------------------------------------
    // 106. Symbol registry: symbol_for is idempotent
    // -----------------------------------------------------------------------

    #[test]
    fn symbol_for_idempotent() {
        let mut heap = ObjectHeap::new();
        let mut reg = SymbolRegistry::new();
        let id1 = reg.symbol_for("shared_key", &mut heap);
        let id2 = reg.symbol_for("shared_key", &mut heap);
        assert_eq!(id1, id2);
    }

    // -----------------------------------------------------------------------
    // 107. JsValue::same_value distinguishes types
    // -----------------------------------------------------------------------

    #[test]
    fn same_value_type_distinctions() {
        assert!(!int_val(0).same_value(&JsValue::Null));
        assert!(!JsValue::Undefined.same_value(&JsValue::Null));
        assert!(!JsValue::Bool(false).same_value(&int_val(0)));
        assert!(!str_val("0").same_value(&int_val(0)));
    }

    // -----------------------------------------------------------------------
    // 108. OrdinaryObject::is_sealed and is_frozen with no properties
    // -----------------------------------------------------------------------

    #[test]
    fn is_sealed_frozen_empty_non_extensible() {
        let mut obj = OrdinaryObject::default();
        obj.prevent_extensions();
        // Non-extensible with no properties is both sealed and frozen.
        assert!(obj.is_sealed());
        assert!(obj.is_frozen());
    }

    // -----------------------------------------------------------------------
    // 109. Proxy invariant: check_get_own_property — trap returns existent
    //      on non-extensible target that doesn't have the property
    // -----------------------------------------------------------------------

    #[test]
    fn proxy_check_get_own_prop_existent_on_non_extensible_missing() {
        let mut target = OrdinaryObject::default();
        target.prevent_extensions();

        let trap_desc = Some(PropertyDescriptor::data(int_val(42)));
        assert!(
            ProxyInvariantChecker::check_get_own_property(&target, &str_key("x"), &trap_desc)
                .is_err()
        );
    }

    // -----------------------------------------------------------------------
    // 110. Proxy invariant: check_has — non-extensible target has the property
    //      but trap says false
    // -----------------------------------------------------------------------

    #[test]
    fn proxy_check_has_non_extensible_denies_existing() {
        let mut target = OrdinaryObject::default();
        target
            .define_own_property(str_key("x"), PropertyDescriptor::data(int_val(1)))
            .unwrap();
        target.prevent_extensions();

        // Property is configurable, target is non-extensible, trap says false → error.
        assert!(ProxyInvariantChecker::check_has(&target, &str_key("x"), false).is_err());
    }

    // -----------------------------------------------------------------------
    // 111. Multiple prototype levels: 3-level chain with has_property
    // -----------------------------------------------------------------------

    #[test]
    fn three_level_prototype_chain_has_property() {
        let mut heap = ObjectHeap::new();
        let grandparent = heap.alloc_plain();
        heap.set_property(grandparent, str_key("gp_prop"), int_val(1))
            .unwrap();

        let parent = heap.alloc(Some(grandparent));
        heap.set_property(parent, str_key("p_prop"), int_val(2))
            .unwrap();

        let child = heap.alloc(Some(parent));
        heap.set_property(child, str_key("c_prop"), int_val(3))
            .unwrap();

        // has_property traverses entire chain.
        assert!(heap.has_property(child, &str_key("gp_prop")).unwrap());
        assert!(heap.has_property(child, &str_key("p_prop")).unwrap());
        assert!(heap.has_property(child, &str_key("c_prop")).unwrap());
        assert!(!heap.has_property(child, &str_key("missing")).unwrap());
    }

    // -----------------------------------------------------------------------
    // 112. defineOwnProperty: reject writable false→true on non-configurable
    // -----------------------------------------------------------------------

    #[test]
    fn define_own_prop_reject_writable_upgrade_non_configurable() {
        let mut obj = OrdinaryObject::default();
        obj.define_own_property(
            str_key("x"),
            PropertyDescriptor::Data {
                value: int_val(1),
                writable: false,
                enumerable: true,
                configurable: false,
            },
        )
        .unwrap();

        // Try to make writable → rejected.
        let result = obj
            .define_own_property(
                str_key("x"),
                PropertyDescriptor::Data {
                    value: int_val(1),
                    writable: true,
                    enumerable: true,
                    configurable: false,
                },
            )
            .unwrap();
        assert!(!result);
    }

    // -----------------------------------------------------------------------
    // 113. defineOwnProperty: non-extensible object rejects new property
    // -----------------------------------------------------------------------

    #[test]
    fn define_own_prop_non_extensible_rejects_new() {
        let mut obj = OrdinaryObject::default();
        obj.prevent_extensions();

        let result = obj
            .define_own_property(str_key("x"), PropertyDescriptor::data(int_val(1)))
            .unwrap();
        assert!(!result);
    }

    // -----------------------------------------------------------------------
    // 114. Object.getOwnPropertyDescriptors on object with mixed descriptors
    // -----------------------------------------------------------------------

    #[test]
    fn get_own_property_descriptors_mixed() {
        let mut heap = ObjectHeap::new();
        let h = heap.alloc_plain();
        heap.define_property(h, str_key("data"), PropertyDescriptor::data(int_val(1)))
            .unwrap();
        heap.define_property(
            h,
            str_key("accessor"),
            PropertyDescriptor::Accessor {
                get: Some(ObjectHandle(10)),
                set: None,
                enumerable: true,
                configurable: true,
            },
        )
        .unwrap();

        let descs = heap.get_own_property_descriptors(h).unwrap();
        assert_eq!(descs.len(), 2);
        // Find the accessor.
        let accessor = descs
            .iter()
            .find(|(k, _)| *k == str_key("accessor"))
            .unwrap();
        assert!(accessor.1.is_accessor());
    }

    // -----------------------------------------------------------------------
    // 115. Proxy invariant: check_get_prototype_of non-extensible must match
    // -----------------------------------------------------------------------

    #[test]
    fn proxy_check_get_prototype_of_non_extensible_match() {
        let mut target = OrdinaryObject::with_prototype(Some(ObjectHandle(3)));
        target.prevent_extensions();

        // Correct prototype → ok.
        assert!(
            ProxyInvariantChecker::check_get_prototype_of(&target, Some(ObjectHandle(3))).is_ok()
        );
        // Different prototype → error.
        assert!(
            ProxyInvariantChecker::check_get_prototype_of(&target, Some(ObjectHandle(4))).is_err()
        );
        // None when target has Some → error.
        assert!(ProxyInvariantChecker::check_get_prototype_of(&target, None).is_err());
    }

    // -----------------------------------------------------------------------
    // 116. Proxy invariant: check_set non-configurable accessor undefined setter
    // -----------------------------------------------------------------------

    #[test]
    fn proxy_check_set_non_configurable_accessor_no_setter() {
        let mut target = OrdinaryObject::default();
        target
            .define_own_property(
                str_key("prop"),
                PropertyDescriptor::Accessor {
                    get: Some(ObjectHandle(1)),
                    set: None,
                    enumerable: true,
                    configurable: false,
                },
            )
            .unwrap();

        // Cannot set on non-configurable accessor with undefined setter.
        assert!(
            ProxyInvariantChecker::check_set(&target, &str_key("prop"), &int_val(1), true).is_err()
        );
    }

    // -----------------------------------------------------------------------
    // 117. for_in_keys: integer-like keys come first
    // -----------------------------------------------------------------------

    #[test]
    fn for_in_keys_integer_keys_first() {
        let mut heap = ObjectHeap::new();
        let h = heap.alloc_plain();
        heap.set_property(h, str_key("b"), str_val("b")).unwrap();
        heap.set_property(h, str_key("2"), str_val("two")).unwrap();
        heap.set_property(h, str_key("0"), str_val("zero")).unwrap();

        let keys = heap.for_in_keys(h).unwrap();
        // Integer indices first (0, 2), then string keys.
        assert_eq!(keys[0], "0");
        assert_eq!(keys[1], "2");
        assert_eq!(keys[2], "b");
    }

    // -----------------------------------------------------------------------
    // 118. Object.assign with multiple sources
    // -----------------------------------------------------------------------

    #[test]
    fn assign_multiple_sources_later_wins() {
        let mut heap = ObjectHeap::new();
        let s1 = heap.alloc_plain();
        heap.set_property(s1, str_key("x"), int_val(1)).unwrap();
        heap.set_property(s1, str_key("y"), int_val(2)).unwrap();

        let s2 = heap.alloc_plain();
        heap.set_property(s2, str_key("x"), int_val(10)).unwrap();
        heap.set_property(s2, str_key("z"), int_val(3)).unwrap();

        let target = heap.alloc_plain();
        heap.assign(target, &[s1, s2]).unwrap();

        assert_eq!(
            heap.get_property(target, &str_key("x")).unwrap(),
            int_val(10)
        );
        assert_eq!(
            heap.get_property(target, &str_key("y")).unwrap(),
            int_val(2)
        );
        assert_eq!(
            heap.get_property(target, &str_key("z")).unwrap(),
            int_val(3)
        );
    }

    // -----------------------------------------------------------------------
    // 119. ManagedObject: as_ordinary/as_proxy correct discrimination
    // -----------------------------------------------------------------------

    #[test]
    fn managed_object_discrimination() {
        let mut heap = ObjectHeap::new();
        let ord = heap.alloc_plain();
        let target = heap.alloc_plain();
        let handler = heap.alloc_plain();
        let prx = heap.alloc_proxy(target, handler);

        assert!(heap.get(ord).unwrap().as_ordinary().is_some());
        assert!(heap.get(ord).unwrap().as_proxy().is_none());
        assert!(heap.get(prx).unwrap().as_proxy().is_some());
        assert!(heap.get(prx).unwrap().as_ordinary().is_none());
    }

    // -----------------------------------------------------------------------
    // 120. Object.entries skips non-enumerable and symbol properties
    // -----------------------------------------------------------------------

    #[test]
    fn entries_skips_non_enumerable_and_symbols() {
        let mut heap = ObjectHeap::new();
        let h = heap.alloc_plain();
        heap.set_property(h, str_key("visible"), int_val(1))
            .unwrap();
        heap.define_property(
            h,
            str_key("hidden"),
            PropertyDescriptor::Data {
                value: int_val(2),
                writable: true,
                enumerable: false,
                configurable: true,
            },
        )
        .unwrap();
        heap.define_property(
            h,
            WellKnownSymbol::Iterator.key(),
            PropertyDescriptor::data(int_val(99)),
        )
        .unwrap();

        let entries = heap.entries(h).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0], ("visible".to_string(), int_val(1)));
    }

    // -----------------------------------------------------------------------
    // 121. Serde round-trip for ObjectHeap with proxy
    // -----------------------------------------------------------------------

    #[test]
    fn serde_roundtrip_heap_with_proxy() {
        let mut heap = ObjectHeap::new();
        let target = heap.alloc_plain();
        heap.set_property(target, str_key("a"), int_val(1)).unwrap();
        let handler = heap.alloc_plain();
        let _proxy = heap.alloc_proxy(target, handler);

        let json = serde_json::to_string(&heap).unwrap();
        let restored: ObjectHeap = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.len(), heap.len());
    }

    // -----------------------------------------------------------------------
    // 122. Well-known symbol ids are contiguous 1..=13
    // -----------------------------------------------------------------------

    #[test]
    fn well_known_symbol_ids_contiguous() {
        let symbols = [
            WellKnownSymbol::Iterator,
            WellKnownSymbol::ToPrimitive,
            WellKnownSymbol::HasInstance,
            WellKnownSymbol::ToStringTag,
            WellKnownSymbol::Species,
            WellKnownSymbol::IsConcatSpreadable,
            WellKnownSymbol::Unscopables,
            WellKnownSymbol::AsyncIterator,
            WellKnownSymbol::Match,
            WellKnownSymbol::MatchAll,
            WellKnownSymbol::Replace,
            WellKnownSymbol::Search,
            WellKnownSymbol::Split,
        ];
        for (i, sym) in symbols.iter().enumerate() {
            assert_eq!(sym.id().0, (i as u32) + 1);
        }
    }

    // -----------------------------------------------------------------------
    // 123. PropertyKey ordering: String < Symbol
    // -----------------------------------------------------------------------

    #[test]
    fn property_key_ordering() {
        let string_key = str_key("z");
        let symbol_key = PropertyKey::Symbol(SymbolId(1));
        // In BTreeMap, String comes before Symbol due to enum discriminant ordering.
        assert!(string_key < symbol_key);
    }

    // -----------------------------------------------------------------------
    // 124. Object.getOwnPropertyNames with integer-like keys
    // -----------------------------------------------------------------------

    #[test]
    fn get_own_property_names_integer_ordering() {
        let mut heap = ObjectHeap::new();
        let h = heap.alloc_plain();
        heap.set_property(h, str_key("10"), int_val(10)).unwrap();
        heap.set_property(h, str_key("2"), int_val(2)).unwrap();
        heap.set_property(h, str_key("abc"), int_val(0)).unwrap();

        let names = heap.get_own_property_names(h).unwrap();
        // Integer indices first (sorted), then strings.
        assert_eq!(names[0], "2");
        assert_eq!(names[1], "10");
        assert_eq!(names[2], "abc");
    }

    // -----------------------------------------------------------------------
    // 125. Proxy invariant: check_define_own_property non-configurable on
    //      non-configurable non-writable with different value
    // -----------------------------------------------------------------------

    #[test]
    fn proxy_check_define_own_prop_non_conf_non_writable_diff_value() {
        let mut target = OrdinaryObject::default();
        target
            .define_own_property(
                str_key("x"),
                PropertyDescriptor::Data {
                    value: int_val(1),
                    writable: false,
                    enumerable: true,
                    configurable: false,
                },
            )
            .unwrap();

        // Trap tries to define with different value → error.
        assert!(
            ProxyInvariantChecker::check_define_own_property(
                &target,
                &str_key("x"),
                &PropertyDescriptor::Data {
                    value: int_val(99),
                    writable: false,
                    enumerable: true,
                    configurable: false,
                },
                true,
            )
            .is_err()
        );

        // Same value → ok.
        assert!(
            ProxyInvariantChecker::check_define_own_property(
                &target,
                &str_key("x"),
                &PropertyDescriptor::Data {
                    value: int_val(1),
                    writable: false,
                    enumerable: true,
                    configurable: false,
                },
                true,
            )
            .is_ok()
        );
    }

    // -----------------------------------------------------------------------
    // 126. Proxy invariant: check_own_keys must include all non-configurable keys
    // -----------------------------------------------------------------------

    #[test]
    fn proxy_check_own_keys_missing_non_configurable() {
        let mut target = OrdinaryObject::default();
        target
            .define_own_property(
                str_key("locked"),
                PropertyDescriptor::Data {
                    value: int_val(1),
                    writable: true,
                    enumerable: true,
                    configurable: false,
                },
            )
            .unwrap();
        target
            .define_own_property(str_key("open"), PropertyDescriptor::data(int_val(2)))
            .unwrap();

        // Trap returns only "open" — missing non-configurable "locked" → error.
        assert!(ProxyInvariantChecker::check_own_keys(&target, &[str_key("open")]).is_err());

        // Including "locked" → ok.
        assert!(
            ProxyInvariantChecker::check_own_keys(&target, &[str_key("locked"), str_key("open")])
                .is_ok()
        );
    }

    // -----------------------------------------------------------------------
    // 127. Serde round-trip for SymbolRegistry
    // -----------------------------------------------------------------------

    #[test]
    fn serde_roundtrip_symbol_registry() {
        let mut heap = ObjectHeap::new();
        let mut reg = SymbolRegistry::new();
        let _sym = reg.symbol_for("my.symbol", &mut heap);

        let json = serde_json::to_string(&reg).unwrap();
        let restored: SymbolRegistry = serde_json::from_str(&json).unwrap();
        assert_eq!(
            restored.key_for(reg.by_description["my.symbol"]),
            Some("my.symbol")
        );
    }

    // -----------------------------------------------------------------------
    // 128. Revoke non-proxy returns error
    // -----------------------------------------------------------------------

    #[test]
    fn revoke_non_proxy_error() {
        let mut heap = ObjectHeap::new();
        let h = heap.alloc_plain();
        assert!(heap.revoke_proxy(h).is_err());
    }

    // -----------------------------------------------------------------------
    // 129. ObjectError equality
    // -----------------------------------------------------------------------

    #[test]
    fn object_error_equality() {
        let e1 = ObjectError::TypeError("same".to_string());
        let e2 = ObjectError::TypeError("same".to_string());
        let e3 = ObjectError::TypeError("different".to_string());
        assert_eq!(e1, e2);
        assert_ne!(e1, e3);
        assert_ne!(
            ObjectError::ProxyRevoked,
            ObjectError::PrototypeCycleDetected
        );
    }

    // -----------------------------------------------------------------------
    // 130. WellKnownSymbol key() produces correct PropertyKey
    // -----------------------------------------------------------------------

    #[test]
    fn well_known_symbol_key_produces_property_key() {
        let key = WellKnownSymbol::Iterator.key();
        assert_eq!(key, PropertyKey::Symbol(SymbolId(1)));
        let key2 = WellKnownSymbol::Split.key();
        assert_eq!(key2, PropertyKey::Symbol(SymbolId(13)));
    }

    // -----------------------------------------------------------------------
    // 131. defineProperties batch operation
    // -----------------------------------------------------------------------

    #[test]
    fn define_properties_batch() {
        let mut heap = ObjectHeap::new();
        let h = heap.alloc_plain();
        let props = vec![
            (str_key("a"), PropertyDescriptor::data(int_val(1))),
            (str_key("b"), PropertyDescriptor::data(int_val(2))),
            (str_key("c"), PropertyDescriptor::data(int_val(3))),
        ];
        assert!(heap.define_properties(h, props).unwrap());

        assert_eq!(heap.get_property(h, &str_key("a")).unwrap(), int_val(1));
        assert_eq!(heap.get_property(h, &str_key("b")).unwrap(), int_val(2));
        assert_eq!(heap.get_property(h, &str_key("c")).unwrap(), int_val(3));
    }

    // -----------------------------------------------------------------------
    // 138. set_prototype_of non-extensible with current prototype succeeds
    // -----------------------------------------------------------------------

    #[test]
    fn set_prototype_of_non_extensible_same_proto() {
        let mut heap = ObjectHeap::new();
        let proto = heap.alloc_plain();
        let h = heap.alloc(Some(proto));
        heap.prevent_extensions(h).unwrap();

        // Setting to same prototype → ok.
        assert!(heap.set_prototype_of(h, Some(proto)).unwrap());
        // Setting to different → rejected.
        let other = heap.alloc_plain();
        assert!(!heap.set_prototype_of(h, Some(other)).unwrap());
    }

    // -----------------------------------------------------------------------
    // 139. Proxy invariant: check_has allows true for any property
    // -----------------------------------------------------------------------

    #[test]
    fn proxy_check_has_true_always_ok() {
        let target = OrdinaryObject::default();
        // Trap says property exists even though target doesn't have it — ok.
        assert!(ProxyInvariantChecker::check_has(&target, &str_key("any"), true).is_ok());
    }

    // -----------------------------------------------------------------------
    // 140. Proxy invariant: check_get non-configurable non-writable same value ok
    // -----------------------------------------------------------------------

    #[test]
    fn proxy_check_get_same_value_ok() {
        let mut target = OrdinaryObject::default();
        target
            .define_own_property(
                str_key("x"),
                PropertyDescriptor::Data {
                    value: int_val(42),
                    writable: false,
                    enumerable: true,
                    configurable: false,
                },
            )
            .unwrap();

        // Same value → ok.
        assert!(ProxyInvariantChecker::check_get(&target, &str_key("x"), &int_val(42)).is_ok());
        // Different value → error.
        assert!(ProxyInvariantChecker::check_get(&target, &str_key("x"), &int_val(99)).is_err());
    }

    // -- Enrichment: serde roundtrips for untested types (PearlTower 2026-02-27) --

    #[test]
    fn symbol_id_serde_roundtrip() {
        let id = SymbolId(42);
        let json = serde_json::to_string(&id).unwrap();
        let back: SymbolId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, back);
    }

    #[test]
    fn well_known_symbol_serde_roundtrip_all() {
        let variants = [
            WellKnownSymbol::Iterator,
            WellKnownSymbol::ToPrimitive,
            WellKnownSymbol::HasInstance,
            WellKnownSymbol::ToStringTag,
            WellKnownSymbol::Species,
            WellKnownSymbol::IsConcatSpreadable,
            WellKnownSymbol::Unscopables,
            WellKnownSymbol::AsyncIterator,
            WellKnownSymbol::Match,
            WellKnownSymbol::MatchAll,
            WellKnownSymbol::Replace,
            WellKnownSymbol::Search,
            WellKnownSymbol::Split,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: WellKnownSymbol = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
        assert_eq!(variants.len(), 13);
    }

    #[test]
    fn object_handle_serde_roundtrip() {
        let h = ObjectHandle(99);
        let json = serde_json::to_string(&h).unwrap();
        let back: ObjectHandle = serde_json::from_str(&json).unwrap();
        assert_eq!(h, back);
    }

    #[test]
    fn proxy_object_serde_roundtrip() {
        let p = ProxyObject::new(ObjectHandle(1), ObjectHandle(2));
        let json = serde_json::to_string(&p).unwrap();
        let back: ProxyObject = serde_json::from_str(&json).unwrap();
        assert_eq!(back.target, Some(ObjectHandle(1)));
        assert_eq!(back.handler, Some(ObjectHandle(2)));
    }

    #[test]
    fn proxy_object_revoked_serde_roundtrip() {
        let mut p = ProxyObject::new(ObjectHandle(1), ObjectHandle(2));
        p.revoke();
        let json = serde_json::to_string(&p).unwrap();
        let back: ProxyObject = serde_json::from_str(&json).unwrap();
        assert!(back.is_revoked());
        assert_eq!(back.target, None);
    }

    #[test]
    fn managed_object_ordinary_serde_roundtrip() {
        let obj = OrdinaryObject::default();
        let m = ManagedObject::Ordinary(obj);
        let json = serde_json::to_string(&m).unwrap();
        let back: ManagedObject = serde_json::from_str(&json).unwrap();
        assert!(back.as_ordinary().is_some());
    }

    #[test]
    fn managed_object_proxy_serde_roundtrip() {
        let p = ProxyObject::new(ObjectHandle(5), ObjectHandle(6));
        let m = ManagedObject::Proxy(p);
        let json = serde_json::to_string(&m).unwrap();
        let back: ManagedObject = serde_json::from_str(&json).unwrap();
        assert!(back.as_ordinary().is_none());
    }

    // -----------------------------------------------------------------------
    // Reflect.apply
    // -----------------------------------------------------------------------

    #[test]
    fn reflect_apply_callable() {
        let mut heap = ObjectHeap::new();
        let func = heap.alloc_callable(None);
        let req = Reflect::apply(
            &heap,
            func,
            JsValue::Undefined,
            vec![int_val(1), int_val(2)],
        )
        .unwrap();
        assert_eq!(req.target, func);
        assert_eq!(req.this_arg, JsValue::Undefined);
        assert_eq!(req.arguments.len(), 2);
    }

    #[test]
    fn reflect_apply_not_callable() {
        let mut heap = ObjectHeap::new();
        let obj = heap.alloc_plain();
        let err = Reflect::apply(&heap, obj, JsValue::Null, vec![]).unwrap_err();
        assert!(matches!(err, ObjectError::TypeError(_)));
        assert!(err.to_string().contains("not callable"));
    }

    #[test]
    fn reflect_apply_with_this_arg() {
        let mut heap = ObjectHeap::new();
        let func = heap.alloc_callable(None);
        let this_obj = heap.alloc_plain();
        let req = Reflect::apply(
            &heap,
            func,
            JsValue::Object(this_obj),
            vec![str_val("hello")],
        )
        .unwrap();
        assert_eq!(req.this_arg, JsValue::Object(this_obj));
        assert_eq!(req.arguments, vec![str_val("hello")]);
    }

    #[test]
    fn reflect_apply_proxy_target() {
        let mut heap = ObjectHeap::new();
        let target = heap.alloc_callable(None);
        let handler = heap.alloc_plain();
        let proxy = heap.alloc_proxy(target, handler);
        // Proxy apply should succeed (interpreter handles the trap).
        let req = Reflect::apply(&heap, proxy, JsValue::Undefined, vec![]).unwrap();
        assert_eq!(req.target, proxy);
    }

    #[test]
    fn reflect_apply_empty_args() {
        let mut heap = ObjectHeap::new();
        let func = heap.alloc_callable(None);
        let req = Reflect::apply(&heap, func, JsValue::Undefined, vec![]).unwrap();
        assert!(req.arguments.is_empty());
    }

    #[test]
    fn reflect_apply_request_serde_roundtrip() {
        let req = ReflectApplyRequest {
            target: ObjectHandle(1),
            this_arg: JsValue::Int(42),
            arguments: vec![JsValue::Bool(true), JsValue::Str("x".into())],
        };
        let json = serde_json::to_string(&req).unwrap();
        let back: ReflectApplyRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(back.target, ObjectHandle(1));
        assert_eq!(back.this_arg, JsValue::Int(42));
        assert_eq!(back.arguments.len(), 2);
    }

    // -----------------------------------------------------------------------
    // Reflect.construct
    // -----------------------------------------------------------------------

    #[test]
    fn reflect_construct_basic() {
        let mut heap = ObjectHeap::new();
        let ctor = heap.alloc_constructor(None);
        let req = Reflect::construct(&heap, ctor, vec![int_val(10)], None).unwrap();
        assert_eq!(req.target, ctor);
        assert_eq!(req.new_target, ctor); // defaults to target
        assert_eq!(req.arguments, vec![int_val(10)]);
    }

    #[test]
    fn reflect_construct_with_new_target() {
        let mut heap = ObjectHeap::new();
        let ctor = heap.alloc_constructor(None);
        let new_target = heap.alloc_constructor(None);
        let req = Reflect::construct(&heap, ctor, vec![], Some(new_target)).unwrap();
        assert_eq!(req.target, ctor);
        assert_eq!(req.new_target, new_target);
    }

    #[test]
    fn reflect_construct_not_constructor() {
        let mut heap = ObjectHeap::new();
        let func = heap.alloc_callable(None); // callable but not constructable
        let err = Reflect::construct(&heap, func, vec![], None).unwrap_err();
        assert!(matches!(err, ObjectError::TypeError(_)));
        assert!(err.to_string().contains("not a constructor"));
    }

    #[test]
    fn reflect_construct_new_target_not_constructor() {
        let mut heap = ObjectHeap::new();
        let ctor = heap.alloc_constructor(None);
        let non_ctor = heap.alloc_callable(None);
        let err = Reflect::construct(&heap, ctor, vec![], Some(non_ctor)).unwrap_err();
        assert!(matches!(err, ObjectError::TypeError(_)));
        assert!(err.to_string().contains("newTarget is not a constructor"));
    }

    #[test]
    fn reflect_construct_proxy_target() {
        let mut heap = ObjectHeap::new();
        let target = heap.alloc_constructor(None);
        let handler = heap.alloc_plain();
        let proxy = heap.alloc_proxy(target, handler);
        let req = Reflect::construct(&heap, proxy, vec![int_val(1)], None).unwrap();
        assert_eq!(req.target, proxy);
    }

    #[test]
    fn reflect_construct_request_serde_roundtrip() {
        let req = ReflectConstructRequest {
            target: ObjectHandle(5),
            arguments: vec![JsValue::Null],
            new_target: ObjectHandle(5),
        };
        let json = serde_json::to_string(&req).unwrap();
        let back: ReflectConstructRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(back.target, ObjectHandle(5));
        assert_eq!(back.arguments, vec![JsValue::Null]);
        assert_eq!(back.new_target, ObjectHandle(5));
    }

    // -----------------------------------------------------------------------
    // ObjectHeap — create_with_properties
    // -----------------------------------------------------------------------

    #[test]
    fn create_with_properties_basic() {
        let mut heap = ObjectHeap::new();
        let handle = heap
            .create_with_properties(
                None,
                vec![
                    (str_key("a"), PropertyDescriptor::data(int_val(1))),
                    (str_key("b"), PropertyDescriptor::data(int_val(2))),
                ],
            )
            .unwrap();
        assert_eq!(
            heap.get_property(handle, &str_key("a")).unwrap(),
            int_val(1)
        );
        assert_eq!(
            heap.get_property(handle, &str_key("b")).unwrap(),
            int_val(2)
        );
    }

    #[test]
    fn create_with_properties_with_prototype() {
        let mut heap = ObjectHeap::new();
        let proto = heap.alloc_plain();
        heap.set_property(proto, str_key("inherited"), int_val(99))
            .unwrap();
        let child = heap
            .create_with_properties(
                Some(proto),
                vec![(str_key("own"), PropertyDescriptor::data(int_val(1)))],
            )
            .unwrap();
        assert_eq!(
            heap.get_property(child, &str_key("own")).unwrap(),
            int_val(1)
        );
        assert_eq!(
            heap.get_property(child, &str_key("inherited")).unwrap(),
            int_val(99)
        );
    }

    #[test]
    fn create_with_accessor_properties() {
        let mut heap = ObjectHeap::new();
        let getter = heap.alloc_callable(None);
        let handle = heap
            .create_with_properties(
                None,
                vec![(
                    str_key("x"),
                    PropertyDescriptor::Accessor {
                        get: Some(getter),
                        set: None,
                        enumerable: true,
                        configurable: true,
                    },
                )],
            )
            .unwrap();
        let desc = heap
            .get_own_property_descriptor(handle, &str_key("x"))
            .unwrap()
            .unwrap();
        assert!(desc.is_accessor());
    }

    // -----------------------------------------------------------------------
    // ObjectHeap — alloc_callable / alloc_constructor
    // -----------------------------------------------------------------------

    #[test]
    fn alloc_callable_creates_callable() {
        let mut heap = ObjectHeap::new();
        let func = heap.alloc_callable(None);
        let obj = heap.get(func).unwrap().as_ordinary().unwrap();
        assert!(obj.callable);
        assert!(!obj.constructable);
    }

    #[test]
    fn alloc_constructor_creates_constructor() {
        let mut heap = ObjectHeap::new();
        let ctor = heap.alloc_constructor(None);
        let obj = heap.get(ctor).unwrap().as_ordinary().unwrap();
        assert!(obj.callable);
        assert!(obj.constructable);
    }

    #[test]
    fn alloc_callable_with_prototype() {
        let mut heap = ObjectHeap::new();
        let proto = heap.alloc_plain();
        let func = heap.alloc_callable(Some(proto));
        let obj = heap.get(func).unwrap().as_ordinary().unwrap();
        assert_eq!(obj.prototype, Some(proto));
        assert!(obj.callable);
    }

    // -----------------------------------------------------------------------
    // ObjectHeap — instance_of
    // -----------------------------------------------------------------------

    #[test]
    fn instance_of_direct_prototype() {
        let mut heap = ObjectHeap::new();
        let proto = heap.alloc_plain();
        let obj = heap.alloc(Some(proto));
        assert!(heap.instance_of(obj, proto).unwrap());
    }

    #[test]
    fn instance_of_chain() {
        let mut heap = ObjectHeap::new();
        let grandproto = heap.alloc_plain();
        let proto = heap.alloc(Some(grandproto));
        let obj = heap.alloc(Some(proto));
        assert!(heap.instance_of(obj, grandproto).unwrap());
        assert!(heap.instance_of(obj, proto).unwrap());
    }

    #[test]
    fn instance_of_no_match() {
        let mut heap = ObjectHeap::new();
        let proto = heap.alloc_plain();
        let other = heap.alloc_plain();
        let obj = heap.alloc(Some(proto));
        assert!(!heap.instance_of(obj, other).unwrap());
    }

    #[test]
    fn instance_of_null_prototype() {
        let mut heap = ObjectHeap::new();
        let target = heap.alloc_plain();
        let obj = heap.alloc(None); // null prototype
        assert!(!heap.instance_of(obj, target).unwrap());
    }

    // -----------------------------------------------------------------------
    // ObjectHeap — spread_into
    // -----------------------------------------------------------------------

    #[test]
    fn spread_into_copies_enumerable() {
        let mut heap = ObjectHeap::new();
        let src = heap.alloc_plain();
        heap.set_property(src, str_key("a"), int_val(1)).unwrap();
        heap.set_property(src, str_key("b"), int_val(2)).unwrap();

        let dst = heap.alloc_plain();
        heap.spread_into(dst, src).unwrap();

        assert_eq!(heap.get_property(dst, &str_key("a")).unwrap(), int_val(1));
        assert_eq!(heap.get_property(dst, &str_key("b")).unwrap(), int_val(2));
    }

    #[test]
    fn spread_into_skips_non_enumerable() {
        let mut heap = ObjectHeap::new();
        let src = heap.alloc_plain();
        heap.define_property(
            src,
            str_key("visible"),
            PropertyDescriptor::data(int_val(1)),
        )
        .unwrap();
        heap.define_property(
            src,
            str_key("hidden"),
            PropertyDescriptor::Data {
                value: int_val(2),
                writable: true,
                enumerable: false,
                configurable: true,
            },
        )
        .unwrap();

        let dst = heap.alloc_plain();
        heap.spread_into(dst, src).unwrap();

        assert_eq!(
            heap.get_property(dst, &str_key("visible")).unwrap(),
            int_val(1)
        );
        assert_eq!(
            heap.get_property(dst, &str_key("hidden")).unwrap(),
            JsValue::Undefined
        );
    }

    #[test]
    fn spread_into_overwrites_target() {
        let mut heap = ObjectHeap::new();
        let src = heap.alloc_plain();
        heap.set_property(src, str_key("x"), int_val(99)).unwrap();

        let dst = heap.alloc_plain();
        heap.set_property(dst, str_key("x"), int_val(1)).unwrap();
        heap.spread_into(dst, src).unwrap();

        assert_eq!(heap.get_property(dst, &str_key("x")).unwrap(), int_val(99));
    }

    #[test]
    fn spread_into_proxy_source_error() {
        let mut heap = ObjectHeap::new();
        let target = heap.alloc_plain();
        let handler = heap.alloc_plain();
        let proxy = heap.alloc_proxy(target, handler);
        let dst = heap.alloc_plain();
        let err = heap.spread_into(dst, proxy).unwrap_err();
        assert!(matches!(err, ObjectError::TypeError(_)));
    }
}
